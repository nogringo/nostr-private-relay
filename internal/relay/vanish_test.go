package relay

import (
	"context"
	"errors"
	"iter"
	"slices"
	"strings"
	"testing"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/khatru"
)

const testRelayURL = "wss://relay.example.com"

func TestVanishTargetsThisRelay(t *testing.T) {
	tests := []struct {
		name     string
		relayURL string
		kind     nostr.Kind
		tags     []nostr.Tag
		want     bool
	}{
		{name: "exact url", relayURL: testRelayURL, kind: KindRequestToVanish, tags: []nostr.Tag{{"relay", testRelayURL}}, want: true},
		{name: "normalized url", relayURL: testRelayURL, kind: KindRequestToVanish, tags: []nostr.Tag{{"relay", "https://Relay.Example.COM/"}}, want: true},
		{name: "all relays", relayURL: testRelayURL, kind: KindRequestToVanish, tags: []nostr.Tag{{"relay", vanishAllRelays}}, want: true},
		{name: "all relays lowercase", relayURL: testRelayURL, kind: KindRequestToVanish, tags: []nostr.Tag{{"relay", "all_relays"}}, want: false},
		{name: "second tag matches", relayURL: testRelayURL, kind: KindRequestToVanish, tags: []nostr.Tag{{"relay", "wss://other.example.com"}, {"relay", testRelayURL}}, want: true},
		{name: "other relay", relayURL: testRelayURL, kind: KindRequestToVanish, tags: []nostr.Tag{{"relay", "wss://other.example.com"}}, want: false},
		{name: "tag without value", relayURL: testRelayURL, kind: KindRequestToVanish, tags: []nostr.Tag{{"relay"}}, want: false},
		{name: "empty tag value", relayURL: testRelayURL, kind: KindRequestToVanish, tags: []nostr.Tag{{"relay", ""}}, want: false},
		{name: "no relay tag", relayURL: testRelayURL, kind: KindRequestToVanish, tags: nil, want: false},
		{name: "unconfigured relay url", relayURL: "", kind: KindRequestToVanish, tags: []nostr.Tag{{"relay", testRelayURL}}, want: false},
		{name: "unconfigured relay url with empty tag", relayURL: "", kind: KindRequestToVanish, tags: []nostr.Tag{{"relay", ""}}, want: false},
		{name: "unconfigured relay url with all relays", relayURL: "", kind: KindRequestToVanish, tags: []nostr.Tag{{"relay", vanishAllRelays}}, want: true},
		{name: "wrong kind", relayURL: testRelayURL, kind: nostr.KindTextNote, tags: []nostr.Tag{{"relay", testRelayURL}}, want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			registry := NewVanishRegistry(Config{RelayURL: test.relayURL}, newMemoryStore())
			event := signedEvent(t, skA, test.kind, "", test.tags...)

			if got := registry.targetsThisRelay(event); got != test.want {
				t.Fatalf("targetsThisRelay = %v, want %v", got, test.want)
			}
		})
	}
}

func TestVanishPurgesAuthorEventsUpToCreatedAt(t *testing.T) {
	store := newMemoryStore()
	relay, registry := newWithVanish(vanishConfig(), store)
	now := nostr.Now()

	older := signedEventAt(t, skA, nostr.KindTextNote, now-10, "A older")
	atCutoff := signedEventAt(t, skA, nostr.KindTextNote, now, "A at cutoff")
	newer := signedEventAt(t, skA, nostr.KindTextNote, now+10, "A newer")
	deletion := signedEventAt(t, skA, nostr.KindDeletion, now-5, "A deletion")
	byB := signedEventAt(t, skB, nostr.KindTextNote, now-10, "B older")
	for _, event := range []nostr.Event{older, atCutoff, newer, deletion, byB} {
		if err := store.SaveEvent(event); err != nil {
			t.Fatal(err)
		}
	}

	vanish := vanishEvent(t, skA, now, testRelayURL)
	if _, err := relay.AddEvent(context.Background(), vanish); err != nil {
		t.Fatalf("expected the request to vanish to be accepted: %v", err)
	}
	registry.wg.Wait()

	assertStoredIDs(t, store, newer, byB, vanish)
}

func TestVanishKeepsGiftWrapsAddressedToPubkey(t *testing.T) {
	store := newMemoryStore()
	relay, registry := newWithVanish(vanishConfig(), store)
	now := nostr.Now()

	wrap := signedEventAt(t, skB, nostr.KindGiftWrap, now-10, "wrap", nostr.Tag{"p", pkA.Hex()})
	if err := store.SaveEvent(wrap); err != nil {
		t.Fatal(err)
	}

	vanish := vanishEvent(t, skA, now, testRelayURL)
	if _, err := relay.AddEvent(context.Background(), vanish); err != nil {
		t.Fatal(err)
	}
	registry.wg.Wait()

	assertStoredIDs(t, store, wrap, vanish)
}

func TestVanishIgnoresRequestForAnotherRelay(t *testing.T) {
	store := newMemoryStore()
	relay, registry := newWithVanish(vanishConfig(), store)
	now := nostr.Now()

	older := signedEventAt(t, skA, nostr.KindTextNote, now-10, "A older")
	if err := store.SaveEvent(older); err != nil {
		t.Fatal(err)
	}

	vanish := vanishEvent(t, skA, now, "wss://other.example.com")
	if _, err := relay.AddEvent(context.Background(), vanish); err != nil {
		t.Fatal(err)
	}
	registry.wg.Wait()

	assertStoredIDs(t, store, older, vanish)
	if registry.blocks(older) {
		t.Fatal("expected a request for another relay not to arm the guard")
	}
}

func TestVanishPurgeSpansMultipleBatches(t *testing.T) {
	store := newMemoryStore()
	registry := NewVanishRegistry(vanishConfig(), store)
	registry.batchSize = 2
	now := nostr.Now()

	for i := range 5 {
		if err := store.SaveEvent(signedEventAt(t, skA, nostr.KindTextNote, now-nostr.Timestamp(i)-1, "note")); err != nil {
			t.Fatal(err)
		}
	}
	vanish := vanishEvent(t, skA, now, testRelayURL)
	if err := store.SaveEvent(vanish); err != nil {
		t.Fatal(err)
	}

	deleted, err := registry.purge(pkA, now, vanish.ID)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 5 {
		t.Fatalf("expected 5 deletions, got %d", deleted)
	}
	assertStoredIDs(t, store, vanish)
}

func TestVanishBlocksRepublishing(t *testing.T) {
	store := newMemoryStore()
	relay, registry := newWithVanish(vanishConfig(), store)
	now := nostr.Now()

	older := signedEventAt(t, skA, nostr.KindTextNote, now-10, "A older")
	vanish := vanishEvent(t, skA, now, testRelayURL)
	if _, err := relay.AddEvent(context.Background(), vanish); err != nil {
		t.Fatal(err)
	}
	registry.wg.Wait()

	ctx := khatru.ForceSetAuthed(context.Background(), pkA)
	_, err := relay.AddEvent(ctx, older)
	if err == nil {
		t.Fatal("expected the republished event to be blocked")
	}
	if !strings.Contains(err.Error(), vanishBlocked) {
		t.Fatalf("unexpected rejection reason: %v", err)
	}
	// The reason must stay generic so a third party cannot confirm the vanish.
	if strings.Contains(err.Error(), "vanish") {
		t.Fatalf("rejection reason leaks the request to vanish: %v", err)
	}

	newer := signedEventAt(t, skA, nostr.KindTextNote, now+1, "A newer")
	if _, err := relay.AddEvent(ctx, newer); err != nil {
		t.Fatalf("expected an event past the cutoff to be accepted: %v", err)
	}

	byB := signedEventAt(t, skB, nostr.KindTextNote, now-10, "B older")
	if _, err := relay.AddEvent(ctx, byB); err != nil {
		t.Fatalf("expected another pubkey to be unaffected: %v", err)
	}
}

func TestVanishBlocksReplayedAndOlderRequests(t *testing.T) {
	store := newMemoryStore()
	relay, registry := newWithVanish(vanishConfig(), store)
	now := nostr.Now()

	vanish := vanishEvent(t, skA, now, testRelayURL)
	if _, err := relay.AddEvent(context.Background(), vanish); err != nil {
		t.Fatal(err)
	}
	registry.wg.Wait()

	if _, err := relay.AddEvent(context.Background(), vanish); err == nil {
		t.Fatal("expected a replayed request to vanish to be blocked")
	}

	older := vanishEvent(t, skA, now-100, testRelayURL)
	if _, err := relay.AddEvent(context.Background(), older); err == nil {
		t.Fatal("expected an older request to vanish to be blocked")
	}
	if got := registry.cutoffOf(pkA); got != now {
		t.Fatalf("expected the cutoff to stay at %d, got %d", now, got)
	}
}

func TestVanishRejectsUnusableTimestamps(t *testing.T) {
	for _, createdAt := range []nostr.Timestamp{0, nostr.Now() + 3600} {
		store := newMemoryStore()
		relay, registry := newWithVanish(vanishConfig(), store)

		vanish := vanishEvent(t, skA, createdAt, testRelayURL)
		if _, err := relay.AddEvent(context.Background(), vanish); err == nil {
			t.Fatalf("expected created_at %d to be rejected", createdAt)
		}
		registry.wg.Wait()

		assertStoredIDs(t, store)
		if registry.blocks(signedEvent(t, skA, nostr.KindTextNote, "A")) {
			t.Fatalf("expected created_at %d not to arm the guard", createdAt)
		}
	}
}

func TestVanishRequestNeedsNoAuthentication(t *testing.T) {
	store := newMemoryStore()
	relay, registry := newWithVanish(vanishConfig(), store)
	now := nostr.Now()

	older := signedEventAt(t, skA, nostr.KindTextNote, now-10, "A older")
	if err := store.SaveEvent(older); err != nil {
		t.Fatal(err)
	}

	if _, err := relay.AddEvent(context.Background(), signedEvent(t, skA, nostr.KindTextNote, "A")); err == nil {
		t.Fatal("expected an unauthenticated text note to still be rejected")
	}

	vanish := vanishEvent(t, skA, now, testRelayURL)
	if _, err := relay.AddEvent(context.Background(), vanish); err != nil {
		t.Fatalf("expected an unauthenticated request to vanish to be accepted: %v", err)
	}
	registry.wg.Wait()

	assertStoredIDs(t, store, vanish)

	if reject, _ := relay.OnRequest(context.Background(), nostr.Filter{}); !reject {
		t.Fatal("expected reads to still require authentication")
	}
	if reject, _ := relay.OnCount(context.Background(), nostr.Filter{}); !reject {
		t.Fatal("expected counts to still require authentication")
	}
}

func TestVanishRequestCannotBeDeleted(t *testing.T) {
	relay, _ := newWithVanish(vanishConfig(), newMemoryStore())
	ctx := context.Background()
	now := nostr.Now()

	vanish := vanishEvent(t, skA, now, testRelayURL)
	deletionByA := signedEventAt(t, skA, nostr.KindDeletion, now+10, "")
	deletionByB := signedEventAt(t, skB, nostr.KindDeletion, now+10, "")
	noteByA := signedEventAt(t, skA, nostr.KindTextNote, now, "A")

	if relay.AllowDeleting(ctx, vanish, deletionByA) {
		t.Fatal("expected a request to vanish to be undeletable")
	}
	if !relay.AllowDeleting(ctx, noteByA, deletionByA) {
		t.Fatal("expected an author to still delete their own event")
	}
	if relay.AllowDeleting(ctx, noteByA, deletionByB) {
		t.Fatal("expected a non-author deletion to be refused")
	}
}

func TestVanishResumesInterruptedPurgeOnStartup(t *testing.T) {
	store := newMemoryStore()
	now := nostr.Now()

	// Exactly the state a crash mid-purge leaves behind.
	older := signedEventAt(t, skA, nostr.KindTextNote, now-10, "A older")
	newer := signedEventAt(t, skA, nostr.KindTextNote, now+10, "A newer")
	vanish := vanishEvent(t, skA, now, testRelayURL)
	for _, event := range []nostr.Event{older, newer, vanish} {
		if err := store.SaveEvent(event); err != nil {
			t.Fatal(err)
		}
	}

	relay, registry := newWithVanish(vanishConfig(), store)

	assertStoredIDs(t, store, newer, vanish)
	if _, err := relay.AddEvent(khatru.ForceSetAuthed(context.Background(), pkA), older); err == nil {
		t.Fatal("expected the rebuilt guard to block republishing")
	}
	if !registry.isPurged(pkA) {
		t.Fatal("expected the startup purge to mark the record as purged")
	}
}

func TestVanishRebuildLeavesRecordsUnpurged(t *testing.T) {
	store := newMemoryStore()
	now := nostr.Now()
	if err := store.SaveEvent(vanishEvent(t, skA, now, testRelayURL)); err != nil {
		t.Fatal(err)
	}

	registry := NewVanishRegistry(vanishConfig(), store)
	if registry.cutoffOf(pkA) != now {
		t.Fatal("expected the request to vanish to be rebuilt from the store")
	}
	if registry.isPurged(pkA) {
		t.Fatal("expected a rebuilt record to be unpurged so the purge resumes")
	}
}

func TestVanishFlagsRequestsItCannotEvaluate(t *testing.T) {
	store := newMemoryStore()
	if err := store.SaveEvent(vanishEvent(t, skA, nostr.Now(), testRelayURL)); err != nil {
		t.Fatal(err)
	}

	if NewVanishRegistry(Config{}, store).HasUnresolvedRequests() != true {
		t.Fatal("expected an unset RELAY_URL to flag the request as unresolved")
	}
	if NewVanishRegistry(vanishConfig(), store).HasUnresolvedRequests() {
		t.Fatal("expected a configured RELAY_URL to resolve the request")
	}

	global := newMemoryStore()
	if err := global.SaveEvent(vanishEvent(t, skA, nostr.Now(), vanishAllRelays)); err != nil {
		t.Fatal(err)
	}
	if NewVanishRegistry(Config{}, global).HasUnresolvedRequests() {
		t.Fatal("expected an ALL_RELAYS request to need no RELAY_URL")
	}
}

func TestVanishRebuildIgnoresRequestsForOtherRelays(t *testing.T) {
	store := newMemoryStore()
	if err := store.SaveEvent(vanishEvent(t, skA, nostr.Now(), "wss://other.example.com")); err != nil {
		t.Fatal(err)
	}

	registry := NewVanishRegistry(vanishConfig(), store)
	if registry.cutoffOf(pkA) != 0 {
		t.Fatal("expected a request for another relay to be ignored on rebuild")
	}
}

func TestVanishFailedPurgeCanBeRetriedByReplay(t *testing.T) {
	store := &failingStore{memoryStore: newMemoryStore(), failDeletes: 1}
	relay, registry := newWithVanish(vanishConfig(), store)
	now := nostr.Now()

	older := signedEventAt(t, skA, nostr.KindTextNote, now-10, "A older")
	if err := store.SaveEvent(older); err != nil {
		t.Fatal(err)
	}

	vanish := vanishEvent(t, skA, now, testRelayURL)
	if _, err := relay.AddEvent(context.Background(), vanish); err != nil {
		t.Fatal(err)
	}
	registry.wg.Wait()

	if registry.isPurged(pkA) {
		t.Fatal("expected a failed purge to leave the record unpurged")
	}
	if registry.blocks(vanish) {
		t.Fatal("expected the unpurged request to be replayable")
	}

	if _, err := relay.AddEvent(context.Background(), vanish); err != nil {
		t.Fatalf("expected the replay to be accepted: %v", err)
	}
	registry.wg.Wait()

	if !registry.isPurged(pkA) {
		t.Fatal("expected the replayed purge to succeed")
	}
	assertStoredIDs(t, store.memoryStore, vanish)
}

func TestVanishAdmitGuardsImports(t *testing.T) {
	store := newMemoryStore()
	now := nostr.Now()
	if err := store.SaveEvent(vanishEvent(t, skA, now, testRelayURL)); err != nil {
		t.Fatal(err)
	}

	registry := NewVanishRegistry(vanishConfig(), store)
	if registry.Admit(signedEventAt(t, skA, nostr.KindTextNote, now-10, "A older")) {
		t.Fatal("expected an event below the cutoff to be refused on import")
	}
	if !registry.Admit(signedEventAt(t, skA, nostr.KindTextNote, now+10, "A newer")) {
		t.Fatal("expected an event past the cutoff to be admitted on import")
	}
}

func TestVanishPurgeAllSweepsOutOfOrderImports(t *testing.T) {
	store := newMemoryStore()
	registry := NewVanishRegistry(vanishConfig(), store)
	now := nostr.Now()

	older := signedEventAt(t, skA, nostr.KindTextNote, now-10, "A older")
	vanish := vanishEvent(t, skA, now, testRelayURL)

	// The request to vanish comes after the events it covers, as it may in a dump.
	for _, event := range []nostr.Event{older, vanish} {
		if !registry.Admit(event) {
			continue
		}
		if err := store.SaveEvent(event); err != nil {
			t.Fatal(err)
		}
	}

	if err := registry.PurgeAll(); err != nil {
		t.Fatal(err)
	}
	assertStoredIDs(t, store, vanish)
}

func TestSupportedNIPsIncludeNIP62(t *testing.T) {
	relay := NewWithStore(vanishConfig(), newMemoryStore())
	if !slices.Contains(relay.Info.SupportedNIPs, any(62)) {
		t.Fatalf("expected NIP-62 to be advertised, got %v", relay.Info.SupportedNIPs)
	}
}

func vanishConfig() Config {
	cfg := testConfig()
	cfg.RelayURL = testRelayURL
	return cfg
}

func vanishEvent(t *testing.T, sk nostr.SecretKey, createdAt nostr.Timestamp, relayURL string) nostr.Event {
	t.Helper()
	return signedEventAt(t, sk, KindRequestToVanish, createdAt, "goodbye", nostr.Tag{"relay", relayURL})
}

func (r *VanishRegistry) cutoffOf(pubkey nostr.PubKey) nostr.Timestamp {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.vanished[pubkey].cutoff
}

func (r *VanishRegistry) isPurged(pubkey nostr.PubKey) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.vanished[pubkey].purged
}

func assertStoredIDs(t *testing.T, store *memoryStore, want ...nostr.Event) {
	t.Helper()

	stored := collect(store.QueryEvents(nostr.Filter{}, 0))
	got := make([]string, 0, len(stored))
	for _, event := range stored {
		got = append(got, event.ID.Hex())
	}
	expected := make([]string, 0, len(want))
	for _, event := range want {
		expected = append(expected, event.ID.Hex())
	}

	slices.Sort(got)
	slices.Sort(expected)
	if !slices.Equal(got, expected) {
		t.Fatalf("stored events mismatch:\n got  %v\n want %v", got, expected)
	}
}

// failingStore makes the first failDeletes deletions fail, to exercise the
// unpurged-record retry path.
type failingStore struct {
	*memoryStore
	failDeletes int
}

func (s *failingStore) DeleteEvent(id nostr.ID) error {
	if s.failDeletes > 0 {
		s.failDeletes--
		return errors.New("delete failed")
	}
	return s.memoryStore.DeleteEvent(id)
}

func (s *failingStore) QueryEvents(filter nostr.Filter, maxLimit int) iter.Seq[nostr.Event] {
	return s.memoryStore.QueryEvents(filter, maxLimit)
}
