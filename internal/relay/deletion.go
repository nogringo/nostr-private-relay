package relay

import (
	"errors"
	"fmt"
	"log"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/eventstore"
)

const (
	deletionBlocked = "blocked: this event was deleted"

	deletionBatchSize = 500
	maxErasePasses    = 100_000

	// How often a long retroactive sweep says it is still running.
	progressInterval = 5 * time.Second
)

// DeletionRegistry remembers every NIP-09 deletion request this relay has seen,
// so that a deleted event can never be stored again: not by rebroadcasting it,
// not by publishing it before the request that covers it, not across restarts.
// It is safe for concurrent use.
type DeletionRegistry struct {
	store     eventstore.Store
	log       *log.Logger
	batchSize int

	mu sync.RWMutex
	// byID holds one requester per deleted event, which is all there ever is in
	// practice. Keeping it a plain array value leaves the map free of pointers,
	// so the garbage collector never has to walk it however large it grows.
	// The rare id claimed by a second requester spills into byIDAlso.
	byID     map[nostr.ID]nostr.PubKey
	byIDAlso map[nostr.ID][]nostr.PubKey
	byAddr   map[string]addressRecord
}

// addressRecord is a deletion request against an "a" coordinate. It covers every
// version of that coordinate up to cutoff, as NIP-09 requires.
type addressRecord struct {
	kind       nostr.Kind
	author     nostr.PubKey
	identifier string
	cutoff     nostr.Timestamp
}

// NewDeletionRegistry rebuilds the registry from the deletion requests already in
// the store, which is what makes deletions outlive a restart.
func NewDeletionRegistry(store eventstore.Store) *DeletionRegistry {
	registry := &DeletionRegistry{
		store:     store,
		log:       log.Default(),
		batchSize: deletionBatchSize,
		byID:      make(map[nostr.ID]nostr.PubKey),
		byIDAlso:  make(map[nostr.ID][]nostr.PubKey),
		byAddr:    make(map[string]addressRecord),
	}
	registry.rebuild()
	return registry
}

// erasable reports whether this relay is willing to delete a kind at all.
// NIP-09: publishing a deletion request against a deletion request has no
// effect, and letting one through would erase the very record that keeps the
// deleted event out. A NIP-62 request must stay replayable so an interrupted
// purge can run again.
func erasable(kind nostr.Kind) bool {
	return kind != nostr.KindDeletion && kind != KindRequestToVanish
}

func (r *DeletionRegistry) record(deletion nostr.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for tag := range deletion.Tags.FindAll("e") {
		id, err := nostr.IDFromHex(tag[1])
		if err != nil {
			continue
		}
		r.recordID(id, deletion.PubKey)
	}

	for tag := range deletion.Tags.FindAll("a") {
		record, ok := parseDeletableAddress(tag[1], deletion.PubKey)
		if !ok {
			continue
		}
		record.cutoff = deletion.CreatedAt
		coord := coordinate(record.kind, record.author, record.identifier)
		if existing, seen := r.byAddr[coord]; seen && existing.cutoff >= record.cutoff {
			continue
		}
		r.byAddr[coord] = record
	}
}

// recordID keeps every requester seen for an id. An event id already commits to
// its author, so a request signed by anyone else must never block the rightful
// one, and must not shadow it either whichever of the two is seen first.
// Callers hold r.mu.
func (r *DeletionRegistry) recordID(id nostr.ID, requester nostr.PubKey) {
	first, seen := r.byID[id]
	if !seen {
		r.byID[id] = requester
		return
	}
	if first == requester || slices.Contains(r.byIDAlso[id], requester) {
		return
	}
	r.byIDAlso[id] = append(r.byIDAlso[id], requester)
}

// deletedBy reports whether author asked for id to be deleted.
func (r *DeletionRegistry) deletedBy(id nostr.ID, author nostr.PubKey) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	first, seen := r.byID[id]
	if !seen {
		return false
	}
	return first == author || slices.Contains(r.byIDAlso[id], author)
}

// parseDeletableAddress accepts an "a" tag value only when it points at an event
// the requester may delete: their own, of a kind this relay agrees to erase.
func parseDeletableAddress(value string, requester nostr.PubKey) (addressRecord, bool) {
	spl := strings.SplitN(value, ":", 3)
	if len(spl) != 3 {
		return addressRecord{}, false
	}
	kind, err := strconv.ParseUint(spl[0], 10, 16)
	if err != nil {
		return addressRecord{}, false
	}
	author, err := nostr.PubKeyFromHex(spl[1])
	if err != nil || author != requester {
		return addressRecord{}, false
	}
	if !erasable(nostr.Kind(kind)) {
		return addressRecord{}, false
	}
	return addressRecord{kind: nostr.Kind(kind), author: author, identifier: spl[2]}, true
}

func coordinate(kind nostr.Kind, author nostr.PubKey, identifier string) string {
	return strconv.Itoa(int(kind)) + ":" + author.Hex() + ":" + identifier
}

// eventCoordinate returns the "a" coordinate an event can be deleted through,
// which only replaceable and addressable kinds have.
func eventCoordinate(event nostr.Event) (string, bool) {
	switch {
	case event.Kind.IsAddressable():
		return coordinate(event.Kind, event.PubKey, event.Tags.GetD()), true
	case event.Kind.IsReplaceable():
		return coordinate(event.Kind, event.PubKey, ""), true
	default:
		return "", false
	}
}

func (r *DeletionRegistry) blocks(event nostr.Event) bool {
	if !erasable(event.Kind) {
		return false
	}

	if r.deletedBy(event.ID, event.PubKey) {
		return true
	}

	coord, addressed := eventCoordinate(event)
	if !addressed {
		return false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	// A version newer than the request is a new event, not the deleted one.
	record, ok := r.byAddr[coord]
	return ok && record.cutoff >= event.CreatedAt
}

func (r *DeletionRegistry) onEvent(event nostr.Event) (bool, string) {
	if r.blocks(event) {
		return true, deletionBlocked
	}
	if event.Kind == nostr.KindDeletion {
		// Closing the door before the request is stored leaves no window for a
		// concurrent republication of its targets to slip in.
		r.record(event)
	}
	return false, ""
}

// Admit reports whether event may be stored, remembering it first when it is a
// deletion request. It never deletes anything: call EnforceAll once the batch is
// over.
func (r *DeletionRegistry) Admit(event nostr.Event) bool {
	if r.blocks(event) {
		return false
	}
	if event.Kind == nostr.KindDeletion {
		r.record(event)
	}
	return true
}

func (r *DeletionRegistry) rebuild() {
	filter := nostr.Filter{Kinds: []nostr.Kind{nostr.KindDeletion}}
	seen := make(map[nostr.ID]struct{})
	limit := r.batchSize

	for pass := 0; pass < maxErasePasses; pass++ {
		added, yielded := 0, 0
		oldest := nostr.Timestamp(0)

		for event := range r.store.QueryEvents(filter, limit) {
			yielded++
			if oldest == 0 || event.CreatedAt < oldest {
				oldest = event.CreatedAt
			}
			if _, duplicate := seen[event.ID]; duplicate {
				continue
			}
			seen[event.ID] = struct{}{}
			added++
			r.record(event)
		}

		if yielded < limit {
			return
		}
		if added == 0 {
			// Every event of this pass shares filter.Until, so moving Until can
			// never get past them: widen the window instead of dropping them.
			limit *= 2
			continue
		}
		limit = r.batchSize
		filter.Until = oldest
	}
}

// EnforceAll rebuilds the registry from the store and erases whatever the
// deletion requests still cover, which is how events deleted before this relay
// kept track of them finally go away. It is idempotent and nearly free once the
// store is clean.
func (r *DeletionRegistry) EnforceAll() error {
	r.rebuild()

	r.mu.RLock()
	ids := make([]nostr.ID, 0, len(r.byID))
	for id := range r.byID {
		ids = append(ids, id)
	}
	addresses := make([]addressRecord, 0, len(r.byAddr))
	for _, record := range r.byAddr {
		addresses = append(addresses, record)
	}
	r.mu.RUnlock()

	var errs []error
	erased := 0
	sweep := newProgressTicker(r.log)

	for start := 0; start < len(ids); start += r.batchSize {
		deleted, err := r.eraseIDBatch(ids[start:min(start+r.batchSize, len(ids))])
		erased += deleted
		if err != nil {
			errs = append(errs, err)
		}
		sweep.report(erased)
	}
	for _, record := range addresses {
		deleted, err := r.eraseAddress(record)
		erased += deleted
		if err != nil {
			errs = append(errs, err)
		}
		sweep.report(erased)
	}

	if erased > 0 {
		r.log.Printf("deletion requests: erased %d events that were in the store despite being deleted", erased)
	}
	return errors.Join(errs...)
}

func (r *DeletionRegistry) eraseIDBatch(batch []nostr.ID) (int, error) {
	// The store yields from inside an open read transaction, so collect the
	// batch before deleting anything.
	doomed := make([]nostr.ID, 0, len(batch))
	for event := range r.store.QueryEvents(nostr.Filter{IDs: batch}, len(batch)) {
		if erasable(event.Kind) && r.deletedBy(event.ID, event.PubKey) {
			doomed = append(doomed, event.ID)
		}
	}

	deleted := 0
	for _, id := range doomed {
		if err := r.store.DeleteEvent(id); err != nil {
			return deleted, fmt.Errorf("failed to delete %s: %w", id.Hex(), err)
		}
		deleted++
	}
	return deleted, nil
}

func (r *DeletionRegistry) eraseAddress(record addressRecord) (int, error) {
	filter := nostr.Filter{
		Kinds:   []nostr.Kind{record.kind},
		Authors: []nostr.PubKey{record.author},
		Until:   record.cutoff,
	}
	if record.kind.IsAddressable() {
		filter.Tags = nostr.TagMap{"d": []string{record.identifier}}
	}
	return eraseMatching(r.store, filter, r.batchSize, nostr.ID{})
}

// progressTicker turns a long sweep into a handful of log lines, so a first boot
// with a lot to erase does not look like a hang. It stays quiet when the sweep
// is quick, which is every boot after the first.
type progressTicker struct {
	log  *log.Logger
	next time.Time
}

func newProgressTicker(logger *log.Logger) *progressTicker {
	return &progressTicker{log: logger, next: time.Now().Add(progressInterval)}
}

func (p *progressTicker) report(erased int) {
	now := time.Now()
	if erased == 0 || now.Before(p.next) {
		return
	}
	p.next = now.Add(progressInterval)
	p.log.Printf("deletion requests: %d events erased so far, still sweeping", erased)
}

// eraseMatching drains filter in batches and deletes everything it yields except
// keep, until nothing is left.
func eraseMatching(store eventstore.Store, filter nostr.Filter, batchSize int, keep nostr.ID) (int, error) {
	deleted := 0
	ids := make([]nostr.ID, 0, batchSize)

	for pass := 0; pass < maxErasePasses; pass++ {
		// The store yields from inside an open read transaction, so drain the
		// batch before deleting anything.
		ids = ids[:0]
		for event := range store.QueryEvents(filter, batchSize) {
			if event.ID == keep {
				continue
			}
			ids = append(ids, event.ID)
		}
		if len(ids) == 0 {
			return deleted, nil
		}

		for _, id := range ids {
			if err := store.DeleteEvent(id); err != nil {
				return deleted, fmt.Errorf("failed to delete %s: %w", id.Hex(), err)
			}
			deleted++
		}
	}
	return deleted, fmt.Errorf("gave up purging after %d passes", maxErasePasses)
}
