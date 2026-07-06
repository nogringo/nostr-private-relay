package relay

import (
	"context"
	"iter"
	"slices"
	"strings"
	"sync"
	"testing"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/khatru"
)

var (
	skA = nostr.MustSecretKeyFromHex("0000000000000000000000000000000000000000000000000000000000000001")
	skB = nostr.MustSecretKeyFromHex("0000000000000000000000000000000000000000000000000000000000000002")
	pkA = nostr.GetPublicKey(skA)
	pkB = nostr.GetPublicKey(skB)
)

func TestRestrictFilterToPubKeys(t *testing.T) {
	t.Run("unauthenticated", func(t *testing.T) {
		if _, ok := restrictFilterToPubKeys(nostr.Filter{}, nil); ok {
			t.Fatal("expected unauthenticated filter to be rejected")
		}
	})

	t.Run("without authors", func(t *testing.T) {
		filter, ok := restrictFilterToPubKeys(nostr.Filter{}, []nostr.PubKey{pkA})
		if !ok {
			t.Fatal("expected filter to be accepted")
		}
		assertAuthors(t, filter.Authors, pkA)
	})

	t.Run("other author only", func(t *testing.T) {
		_, ok := restrictFilterToPubKeys(nostr.Filter{Authors: []nostr.PubKey{pkB}}, []nostr.PubKey{pkA})
		if ok {
			t.Fatal("expected filter to be rejected")
		}
	})

	t.Run("intersect authors", func(t *testing.T) {
		filter, ok := restrictFilterToPubKeys(
			nostr.Filter{Authors: []nostr.PubKey{pkA, pkB}},
			[]nostr.PubKey{pkA},
		)
		if !ok {
			t.Fatal("expected filter to be accepted")
		}
		assertAuthors(t, filter.Authors, pkA)
	})

	t.Run("multiple authenticated pubkeys", func(t *testing.T) {
		filter, ok := restrictFilterToPubKeys(nostr.Filter{}, []nostr.PubKey{pkA, pkB})
		if !ok {
			t.Fatal("expected filter to be accepted")
		}
		assertAuthors(t, filter.Authors, pkA, pkB)
	})
}

func TestRelayRequiresAuthButAllowsPublishingDifferentAuthors(t *testing.T) {
	store := newMemoryStore()
	relay := NewWithStore(testConfig(), store)
	event := signedEvent(t, skB, nostr.KindTextNote, "published by B")

	if _, err := relay.AddEvent(context.Background(), event); err == nil {
		t.Fatal("expected unauthenticated EVENT to be rejected")
	}

	ctx := khatru.ForceSetAuthed(context.Background(), pkA)
	if _, err := relay.AddEvent(ctx, event); err != nil {
		t.Fatalf("expected authenticated publish by another author to be accepted: %v", err)
	}
}

func TestRelayQueriesAndCountsOnlyAuthenticatedAuthors(t *testing.T) {
	store := newMemoryStore()
	relay := NewWithStore(testConfig(), store)

	eventA := signedEvent(t, skA, nostr.KindTextNote, "A")
	eventB := signedEvent(t, skB, nostr.KindTextNote, "B")
	if err := store.SaveEvent(eventA); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveEvent(eventB); err != nil {
		t.Fatal(err)
	}

	ctx := khatru.ForceSetAuthed(context.Background(), pkA)
	events := collect(relay.QueryStored(ctx, nostr.Filter{}))
	if len(events) != 1 || events[0].PubKey != pkA {
		t.Fatalf("expected only A's event, got %#v", events)
	}

	events = collect(relay.QueryStored(ctx, nostr.Filter{Authors: []nostr.PubKey{pkB}}))
	if len(events) != 0 {
		t.Fatalf("expected no events for B query while authed as A, got %#v", events)
	}

	count, err := relay.Count(ctx, nostr.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected count 1, got %d", count)
	}
}

func TestPreventBroadcastBlocksOtherAuthors(t *testing.T) {
	relay := NewWithStore(testConfig(), newMemoryStore())
	ws := &khatru.WebSocket{AuthedPublicKeys: []nostr.PubKey{pkA}}

	eventA := signedEvent(t, skA, nostr.KindTextNote, "A")
	eventB := signedEvent(t, skB, nostr.KindTextNote, "B")

	if relay.PreventBroadcast(ws, nostr.Filter{}, eventA) {
		t.Fatal("expected event by authenticated author to be broadcast")
	}
	if !relay.PreventBroadcast(ws, nostr.Filter{}, eventB) {
		t.Fatal("expected event by another author to be blocked")
	}
}

func TestNewWithStorePublishesRelayMetadata(t *testing.T) {
	relay := NewWithStore(Config{
		Addr:        ":0",
		Name:        "test relay",
		Description: "test",
		Icon:        "https://example.com/icon.png",
		Contact:     "nostr@example.com",
		LMDBPath:    "unused",
		MaxLimit:    500,
	}, newMemoryStore())

	if relay.Info.Software != "nostr-private-relay" {
		t.Fatalf("expected software metadata to be set, got %q", relay.Info.Software)
	}
	if relay.Info.Icon != "https://example.com/icon.png" {
		t.Fatalf("expected icon metadata to be set, got %q", relay.Info.Icon)
	}
	if relay.Info.Contact != "nostr@example.com" {
		t.Fatalf("expected contact metadata to be set, got %q", relay.Info.Contact)
	}
}

func TestVersionIsLoadedFromVersionFile(t *testing.T) {
	got := version()
	if got == "" {
		t.Fatal("expected version from version.txt, got empty string")
	}
	if got != strings.TrimSpace(string(mustReadVersionFile(t))) {
		t.Fatalf("expected version to match version.txt contents, got %q", got)
	}
}

func testConfig() Config {
	return Config{
		Addr:        ":0",
		Name:        "test relay",
		Description: "test",
		LMDBPath:    "unused",
		MaxLimit:    500,
	}
}

func signedEvent(t *testing.T, sk nostr.SecretKey, kind nostr.Kind, content string) nostr.Event {
	t.Helper()
	event := nostr.Event{
		CreatedAt: nostr.Now(),
		Kind:      kind,
		Tags:      nostr.Tags{},
		Content:   content,
	}
	if err := event.Sign(sk); err != nil {
		t.Fatal(err)
	}
	return event
}

func assertAuthors(t *testing.T, got []nostr.PubKey, want ...nostr.PubKey) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("authors mismatch: got %v want %v", got, want)
	}
}

func mustReadVersionFile(t *testing.T) []byte {
	t.Helper()
	data, err := versionFile.ReadFile("version.txt")
	if err != nil {
		t.Fatalf("failed to read embedded version file: %v", err)
	}
	return data
}

func collect(seq iter.Seq[nostr.Event]) []nostr.Event {
	var events []nostr.Event
	for event := range seq {
		events = append(events, event)
	}
	return events
}

type memoryStore struct {
	mu     sync.Mutex
	events []nostr.Event
}

func newMemoryStore() *memoryStore {
	return &memoryStore{events: make([]nostr.Event, 0)}
}

func (s *memoryStore) Init() error { return nil }

func (s *memoryStore) Close() {}

func (s *memoryStore) QueryEvents(filter nostr.Filter, maxLimit int) iter.Seq[nostr.Event] {
	s.mu.Lock()
	events := slices.Clone(s.events)
	s.mu.Unlock()

	return func(yield func(nostr.Event) bool) {
		sent := 0
		for _, event := range events {
			if maxLimit > 0 && sent >= maxLimit {
				return
			}
			if filter.Matches(event) {
				sent++
				if !yield(event) {
					return
				}
			}
		}
	}
}

func (s *memoryStore) DeleteEvent(id nostr.ID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.events = slices.DeleteFunc(s.events, func(event nostr.Event) bool {
		return event.ID == id
	})
	return nil
}

func (s *memoryStore) SaveEvent(event nostr.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, existing := range s.events {
		if existing.ID == event.ID {
			return nil
		}
	}
	s.events = append(s.events, event)
	return nil
}

func (s *memoryStore) ReplaceEvent(event nostr.Event) ([]nostr.Event, error) {
	if event.Kind.IsRegular() {
		return nil, s.SaveEvent(event)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var deleted []nostr.Event
	kept := s.events[:0]
	for _, existing := range s.events {
		if existing.Kind == event.Kind && existing.PubKey == event.PubKey {
			deleted = append(deleted, existing)
			continue
		}
		kept = append(kept, existing)
	}
	s.events = append(kept, event)
	return deleted, nil
}

func (s *memoryStore) CountEvents(filter nostr.Filter) (uint32, error) {
	var count uint32
	for range s.QueryEvents(filter, 0) {
		count++
	}
	return count, nil
}
