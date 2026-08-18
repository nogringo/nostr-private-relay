package relay

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/eventstore"
)

// KindRequestToVanish is the NIP-62 request to vanish.
const KindRequestToVanish nostr.Kind = 62

const (
	vanishAllRelays = "ALL_RELAYS"

	// Deliberately says nothing about why: naming the request to vanish would
	// let a third party confirm that this pubkey ever used this relay.
	vanishBlocked     = "blocked: this event is not accepted by this relay"
	vanishInvalidTime = "invalid: request to vanish has an unusable created_at"

	vanishBatchSize = 500
	maxVanishPasses = 100_000

	maxVanishDrift nostr.Timestamp = 900
)

// VanishRegistry tracks the NIP-62 requests to vanish addressed to this relay and
// enforces them: it purges the author's events and refuses to let them come back.
// It is safe for concurrent use.
type VanishRegistry struct {
	store     eventstore.Store
	relayURL  string
	log       *log.Logger
	batchSize int

	mu         sync.RWMutex
	vanished   map[nostr.PubKey]vanishRecord
	unresolved bool
	wg         sync.WaitGroup
}

type vanishRecord struct {
	id     nostr.ID
	cutoff nostr.Timestamp
	purged bool
}

// NewVanishRegistry rebuilds the registry from the requests to vanish already in
// the store. Requests come back with purged=false, so a PurgeAll finishes any
// purge that a crash or a reboot interrupted.
func NewVanishRegistry(cfg Config, store eventstore.Store) *VanishRegistry {
	registry := &VanishRegistry{
		store:     store,
		relayURL:  nostr.NormalizeURL(cfg.RelayURL),
		log:       log.Default(),
		batchSize: vanishBatchSize,
		vanished:  make(map[nostr.PubKey]vanishRecord),
	}
	registry.rebuild()
	return registry
}

func (r *VanishRegistry) targetsThisRelay(event nostr.Event) bool {
	if event.Kind != KindRequestToVanish {
		return false
	}

	for tag := range event.Tags.FindAll("relay") {
		value := strings.TrimSpace(tag[1])
		if value == vanishAllRelays {
			return true
		}
		if r.relayURL == "" {
			continue
		}
		if nostr.NormalizeURL(value) == r.relayURL {
			return true
		}
	}
	return false
}

func (r *VanishRegistry) blocks(event nostr.Event) bool {
	r.mu.RLock()
	record, ok := r.vanished[event.PubKey]
	r.mu.RUnlock()

	if !ok || event.CreatedAt > record.cutoff {
		return false
	}
	// The only way back in is replaying the exact request whose purge never
	// completed, so that it can run again.
	return record.purged || event.ID != record.id
}

func (r *VanishRegistry) record(event nostr.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if existing, ok := r.vanished[event.PubKey]; ok && existing.cutoff >= event.CreatedAt {
		return
	}
	r.vanished[event.PubKey] = vanishRecord{id: event.ID, cutoff: event.CreatedAt}
}

func (r *VanishRegistry) markUnresolved() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.unresolved = true
}

// HasUnresolvedRequests reports whether the store holds requests to vanish that
// cannot be evaluated because RELAY_URL is not configured. Enforcing them is
// impossible until the operator says what this relay's URL is.
func (r *VanishRegistry) HasUnresolvedRequests() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.unresolved
}

func (r *VanishRegistry) markPurged(pubkey nostr.PubKey, cutoff nostr.Timestamp) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if record, ok := r.vanished[pubkey]; ok && record.cutoff == cutoff {
		record.purged = true
		r.vanished[pubkey] = record
	}
}

func (r *VanishRegistry) onEvent(event nostr.Event) (bool, string) {
	if r.blocks(event) {
		return true, vanishBlocked
	}
	if !r.targetsThisRelay(event) {
		return false, ""
	}
	// A zero Until means "unbounded" to nostr.Filter, and a future-dated request
	// would lock the pubkey out until that date with no way to undo it.
	if event.CreatedAt <= 0 || event.CreatedAt > nostr.Now()+maxVanishDrift {
		return true, vanishInvalidTime
	}

	// Closing the door before the event is stored leaves no window for a
	// concurrent publish from this pubkey to slip in during the purge.
	r.record(event)
	return false, ""
}

// onEventSaved runs once the request is persisted, so an interrupted purge is
// always recoverable from the store.
func (r *VanishRegistry) onEventSaved(_ context.Context, event nostr.Event) {
	if !r.targetsThisRelay(event) {
		return
	}
	r.purgeAsync(event)
}

func (r *VanishRegistry) purgeAsync(event nostr.Event) {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()

		deleted, err := r.purge(event.PubKey, event.CreatedAt, event.ID)
		if err != nil {
			r.log.Printf("request to vanish %s: purge failed after %d events: %v", event.ID.Hex(), deleted, err)
			return
		}
		r.markPurged(event.PubKey, event.CreatedAt)
		r.log.Printf("request to vanish %s: deleted %d events from %s", event.ID.Hex(), deleted, event.PubKey.Hex())
	}()
}

func (r *VanishRegistry) purge(pubkey nostr.PubKey, cutoff nostr.Timestamp, keep nostr.ID) (int, error) {
	filter := nostr.Filter{Authors: []nostr.PubKey{pubkey}, Until: cutoff}
	return r.purgeFilter(filter, keep)
}

func (r *VanishRegistry) purgeFilter(filter nostr.Filter, keep nostr.ID) (int, error) {
	deleted := 0
	ids := make([]nostr.ID, 0, r.batchSize)

	for pass := 0; pass < maxVanishPasses; pass++ {
		// The store yields from inside an open read transaction, so drain the
		// batch before deleting anything.
		ids = ids[:0]
		for event := range r.store.QueryEvents(filter, r.batchSize) {
			if event.ID == keep {
				continue
			}
			ids = append(ids, event.ID)
		}
		if len(ids) == 0 {
			return deleted, nil
		}

		for _, id := range ids {
			if err := r.store.DeleteEvent(id); err != nil {
				return deleted, fmt.Errorf("failed to delete %s: %w", id.Hex(), err)
			}
			deleted++
		}
	}
	return deleted, fmt.Errorf("gave up purging after %d passes", maxVanishPasses)
}

func (r *VanishRegistry) rebuild() {
	filter := nostr.Filter{Kinds: []nostr.Kind{KindRequestToVanish}}
	seen := make(map[nostr.ID]struct{})

	for pass := 0; pass < maxVanishPasses; pass++ {
		added := 0
		oldest := nostr.Timestamp(0)

		for event := range r.store.QueryEvents(filter, r.batchSize) {
			if _, duplicate := seen[event.ID]; duplicate {
				continue
			}
			seen[event.ID] = struct{}{}
			added++

			if oldest == 0 || event.CreatedAt < oldest {
				oldest = event.CreatedAt
			}
			if event.CreatedAt > 0 && r.targetsThisRelay(event) {
				r.record(event)
			} else if r.relayURL == "" {
				// Without RELAY_URL we cannot tell whether this request was
				// addressed to us, so we may be silently failing to enforce it.
				r.markUnresolved()
			}
		}

		if added == 0 || oldest == 0 {
			return
		}
		filter.Until = oldest
	}
}

func (r *VanishRegistry) allowDeleting(_ context.Context, target, deletion nostr.Event) bool {
	if r.targetsThisRelay(target) {
		return false // there is no unrequest vanish
	}
	return target.PubKey == deletion.PubKey
}

// Admit reports whether event may be stored, recording it first when it is a
// request to vanish addressed to this relay. It never deletes anything: call
// PurgeAll once the batch is over.
func (r *VanishRegistry) Admit(event nostr.Event) bool {
	if r.blocks(event) {
		return false
	}
	if event.CreatedAt > 0 && r.targetsThisRelay(event) {
		r.record(event)
	}
	return true
}

// PurgeAll re-runs the purge for every recorded request to vanish. It is
// idempotent and nearly free once the store is clean.
func (r *VanishRegistry) PurgeAll() error {
	type pending struct {
		id     nostr.ID
		cutoff nostr.Timestamp
	}

	r.mu.RLock()
	todo := make(map[nostr.PubKey]pending, len(r.vanished))
	for pubkey, record := range r.vanished {
		todo[pubkey] = pending{id: record.id, cutoff: record.cutoff}
	}
	r.mu.RUnlock()

	var errs []error
	for pubkey, p := range todo {
		if _, err := r.purge(pubkey, p.cutoff, p.id); err != nil {
			errs = append(errs, err)
			continue
		}
		r.markPurged(pubkey, p.cutoff)
	}
	return errors.Join(errs...)
}
