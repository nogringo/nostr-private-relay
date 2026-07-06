package relay

import (
	"context"
	"iter"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/eventstore"
	"fiatjaf.com/nostr/khatru"
	"fiatjaf.com/nostr/nip45/hyperloglog"
)

const authRequired = "auth-required: this relay requires NIP-42 authentication"

type hllCounter interface {
	CountEventsHLL(filter nostr.Filter, offset int) (uint32, *hyperloglog.HyperLogLog, error)
}

type privateStore struct {
	store    eventstore.Store
	hllStore hllCounter
	maxLimit int
}

func newPrivateStore(store eventstore.Store, maxLimit int) privateStore {
	ps := privateStore{store: store, maxLimit: maxLimit}
	if hll, ok := store.(hllCounter); ok {
		ps.hllStore = hll
	}
	return ps
}

func (ps privateStore) query(ctx context.Context, filter nostr.Filter) iter.Seq[nostr.Event] {
	if khatru.IsInternalCall(ctx) {
		return ps.store.QueryEvents(filter, ps.queryLimit(ctx))
	}

	restricted, ok := restrictFilterToAuthed(ctx, filter)
	if !ok {
		return emptySeq
	}
	return ps.store.QueryEvents(restricted, ps.queryLimit(ctx))
}

func (ps privateStore) count(ctx context.Context, filter nostr.Filter) (uint32, error) {
	if khatru.IsInternalCall(ctx) {
		return ps.store.CountEvents(filter)
	}

	restricted, ok := restrictFilterToAuthed(ctx, filter)
	if !ok {
		return 0, nil
	}
	return ps.store.CountEvents(restricted)
}

func (ps privateStore) countHLL(ctx context.Context, filter nostr.Filter, offset int) (uint32, *hyperloglog.HyperLogLog, error) {
	if ps.hllStore == nil {
		return 0, nil, nil
	}

	if khatru.IsInternalCall(ctx) {
		return ps.hllStore.CountEventsHLL(filter, offset)
	}

	restricted, ok := restrictFilterToAuthed(ctx, filter)
	if !ok {
		return 0, nil, nil
	}
	return ps.hllStore.CountEventsHLL(restricted, offset)
}

func (ps privateStore) queryLimit(ctx context.Context) int {
	if khatru.IsNegentropySession(ctx) {
		return ps.maxLimit * 20
	}
	return ps.maxLimit
}

func restrictFilterToAuthed(ctx context.Context, filter nostr.Filter) (nostr.Filter, bool) {
	return restrictFilterToPubKeys(filter, khatru.GetAllAuthed(ctx))
}

func restrictFilterToPubKeys(filter nostr.Filter, authed []nostr.PubKey) (nostr.Filter, bool) {
	if len(authed) == 0 {
		return nostr.Filter{}, false
	}

	restricted := filter
	if len(filter.Authors) == 0 {
		restricted.Authors = clonePubKeys(authed)
		return restricted, true
	}

	allowed := make([]nostr.PubKey, 0, min(len(filter.Authors), len(authed)))
	for _, author := range filter.Authors {
		if containsPubKey(authed, author) && !containsPubKey(allowed, author) {
			allowed = append(allowed, author)
		}
	}
	if len(allowed) == 0 {
		return nostr.Filter{}, false
	}

	restricted.Authors = allowed
	return restricted, true
}

func canReadEvent(authed []nostr.PubKey, event nostr.Event) bool {
	return containsPubKey(authed, event.PubKey)
}

func emptySeq(yield func(nostr.Event) bool) {}

func clonePubKeys(in []nostr.PubKey) []nostr.PubKey {
	out := make([]nostr.PubKey, len(in))
	copy(out, in)
	return out
}

func containsPubKey(haystack []nostr.PubKey, needle nostr.PubKey) bool {
	for _, candidate := range haystack {
		if candidate == needle {
			return true
		}
	}
	return false
}
