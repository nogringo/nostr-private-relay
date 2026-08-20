package relay

import (
	"context"
	"strings"
	"testing"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/khatru"
)

func TestDeletedEventCannotBeRepublished(t *testing.T) {
	store := newMemoryStore()
	relay, _, deletions := newWithRegistries(testConfig(), store)
	ctx := authedContext(pkA)
	now := nostr.Now()

	note := signedEventAt(t, skA, nostr.KindTextNote, now-10, "A note")
	if _, err := relay.AddEvent(ctx, note); err != nil {
		t.Fatalf("expected the note to be accepted: %v", err)
	}

	deletion := deletionEvent(t, skA, now, nostr.Tag{"e", note.ID.Hex()})
	if _, err := relay.AddEvent(ctx, deletion); err != nil {
		t.Fatalf("expected the deletion request to be accepted: %v", err)
	}
	if err := deletions.EnforceAll(); err != nil {
		t.Fatal(err)
	}
	assertStoredIDs(t, store, deletion)

	assertRefusedAsDeleted(t, relay, ctx, note)
	assertStoredIDs(t, store, deletion)
}

func TestDeletionRequestBlocksAnEventItArrivesBefore(t *testing.T) {
	store := newMemoryStore()
	relay, _, _ := newWithRegistries(testConfig(), store)
	ctx := authedContext(pkA)
	now := nostr.Now()

	note := signedEventAt(t, skA, nostr.KindTextNote, now-10, "A note")
	deletion := deletionEvent(t, skA, now, nostr.Tag{"e", note.ID.Hex()})
	if _, err := relay.AddEvent(ctx, deletion); err != nil {
		t.Fatalf("expected the deletion request to be accepted: %v", err)
	}

	assertRefusedAsDeleted(t, relay, ctx, note)
	assertStoredIDs(t, store, deletion)
}

func TestDeletionRequestFromAnotherAuthorIsIgnored(t *testing.T) {
	store := newMemoryStore()
	relay, _, deletions := newWithRegistries(testConfig(), store)
	now := nostr.Now()

	note := signedEventAt(t, skA, nostr.KindTextNote, now-10, "A note")
	forged := deletionEvent(t, skB, now, nostr.Tag{"e", note.ID.Hex()})
	if _, err := relay.AddEvent(authedContext(pkB), forged); err != nil {
		t.Fatalf("expected the deletion request to be accepted: %v", err)
	}

	if _, err := relay.AddEvent(authedContext(pkA), note); err != nil {
		t.Fatalf("expected the note to stay publishable: %v", err)
	}
	if err := deletions.EnforceAll(); err != nil {
		t.Fatal(err)
	}
	assertStoredIDs(t, store, forged, note)
}

// Only one requester per id is kept inline, the rest spill over, so a forged
// request must not shadow the real one whichever of the two lands first.
func TestDeletionRequestFromAnotherAuthorDoesNotShadowTheRealOne(t *testing.T) {
	tests := []struct {
		name  string
		first nostr.SecretKey
	}{
		{name: "author first", first: skA},
		{name: "forgery first", first: skB},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newMemoryStore()
			relay, _, _ := newWithRegistries(testConfig(), store)
			now := nostr.Now()

			note := signedEventAt(t, skA, nostr.KindTextNote, now-10, "A note")
			second := skA
			if test.first == skA {
				second = skB
			}
			for _, sk := range []nostr.SecretKey{test.first, second} {
				deletion := deletionEvent(t, sk, now, nostr.Tag{"e", note.ID.Hex()})
				if _, err := relay.AddEvent(authedContext(deletion.PubKey), deletion); err != nil {
					t.Fatalf("expected the deletion request to be accepted: %v", err)
				}
			}

			assertRefusedAsDeleted(t, relay, authedContext(pkA), note)
		})
	}
}

func TestDeletionOfAddressableEventCoversVersionsUpToTheRequest(t *testing.T) {
	store := newMemoryStore()
	relay, _, _ := newWithRegistries(testConfig(), store)
	ctx := authedContext(pkA)
	now := nostr.Now()

	deletion := deletionEvent(t, skA, now, nostr.Tag{"a", "30023:" + pkA.Hex() + ":my-article"})
	if _, err := relay.AddEvent(ctx, deletion); err != nil {
		t.Fatalf("expected the deletion request to be accepted: %v", err)
	}

	older := signedEventAt(t, skA, nostr.KindArticle, now-10, "older", nostr.Tag{"d", "my-article"})
	atCutoff := signedEventAt(t, skA, nostr.KindArticle, now, "at cutoff", nostr.Tag{"d", "my-article"})
	for _, event := range []nostr.Event{older, atCutoff} {
		assertRefusedAsDeleted(t, relay, ctx, event)
	}

	newer := signedEventAt(t, skA, nostr.KindArticle, now+10, "newer", nostr.Tag{"d", "my-article"})
	otherArticle := signedEventAt(t, skA, nostr.KindArticle, now-10, "other", nostr.Tag{"d", "other-article"})
	for _, event := range []nostr.Event{newer, otherArticle} {
		if _, err := relay.AddEvent(ctx, event); err != nil {
			t.Fatalf("expected %q to be accepted: %v", event.Content, err)
		}
	}
}

func TestDeletionOfAddressableEventErasesStoredVersions(t *testing.T) {
	store := newMemoryStore()
	now := nostr.Now()

	article := signedEventAt(t, skA, nostr.KindArticle, now-10, "article", nostr.Tag{"d", "my-article"})
	deletion := deletionEvent(t, skA, now, nostr.Tag{"a", "30023:" + pkA.Hex() + ":my-article"})
	byB := signedEventAt(t, skB, nostr.KindArticle, now-10, "B article", nostr.Tag{"d", "my-article"})
	for _, event := range []nostr.Event{article, deletion, byB} {
		if err := store.SaveEvent(event); err != nil {
			t.Fatal(err)
		}
	}

	newWithRegistries(testConfig(), store)

	assertStoredIDs(t, store, deletion, byB)
}

func TestDeletionRequestCannotBeDeleted(t *testing.T) {
	store := newMemoryStore()
	relay, _, deletions := newWithRegistries(testConfig(), store)
	ctx := authedContext(pkA)
	now := nostr.Now()

	note := signedEventAt(t, skA, nostr.KindTextNote, now-20, "A note")
	deletion := deletionEvent(t, skA, now-10, nostr.Tag{"e", note.ID.Hex()})
	undo := deletionEvent(t, skA, now, nostr.Tag{"e", deletion.ID.Hex()})

	if relay.AllowDeleting(ctx, deletion, undo) {
		t.Fatal("expected a deletion request to be undeletable")
	}

	for _, event := range []nostr.Event{deletion, undo} {
		if _, err := relay.AddEvent(ctx, event); err != nil {
			t.Fatalf("expected the deletion request to be accepted: %v", err)
		}
	}
	if err := deletions.EnforceAll(); err != nil {
		t.Fatal(err)
	}

	assertStoredIDs(t, store, deletion, undo)
	assertRefusedAsDeleted(t, relay, ctx, note)
}

func TestDeletionDoesNotBlockRequestToVanish(t *testing.T) {
	store := newMemoryStore()
	relay, _, deletions := newWithRegistries(vanishConfig(), store)
	now := nostr.Now()

	vanish := vanishEvent(t, skA, now, testRelayURL)
	deletion := deletionEvent(t, skA, now, nostr.Tag{"e", vanish.ID.Hex()})
	if _, err := relay.AddEvent(authedContext(pkA), deletion); err != nil {
		t.Fatalf("expected the deletion request to be accepted: %v", err)
	}

	if deletions.blocks(vanish) {
		t.Fatal("expected a request to vanish to stay publishable, so an interrupted purge can be replayed")
	}
}

func TestDeletionSurvivesRestart(t *testing.T) {
	store := newMemoryStore()
	now := nostr.Now()

	note := signedEventAt(t, skA, nostr.KindTextNote, now-10, "A note")
	deletion := deletionEvent(t, skA, now, nostr.Tag{"e", note.ID.Hex()})
	byB := signedEventAt(t, skB, nostr.KindTextNote, now-10, "B note")
	// The note is back in the store, as a republication would have left it
	// before this relay kept a record of the deletion.
	for _, event := range []nostr.Event{note, deletion, byB} {
		if err := store.SaveEvent(event); err != nil {
			t.Fatal(err)
		}
	}

	relay, _, _ := newWithRegistries(testConfig(), store)

	assertStoredIDs(t, store, deletion, byB)
	assertRefusedAsDeleted(t, relay, authedContext(pkA), note)
}

// Paginating on created_at cannot get past a batch whose events all share it,
// which used to drop every request beyond the first batch.
func TestDeletionRebuildKeepsRequestsSharingACreatedAt(t *testing.T) {
	store := newMemoryStore()
	now := nostr.Timestamp(1750000000)
	const count = 3 * deletionBatchSize

	notes := make([]nostr.Event, count)
	for i := range notes {
		notes[i] = signedEventAt(t, skA, nostr.KindTextNote, now-nostr.Timestamp(i)-1, "note")
		deletion := deletionEvent(t, skA, now, nostr.Tag{"e", notes[i].ID.Hex()})
		for _, event := range []nostr.Event{notes[i], deletion} {
			if err := store.SaveEvent(event); err != nil {
				t.Fatal(err)
			}
		}
	}

	relay, _, _ := newWithRegistries(testConfig(), store)

	for _, note := range notes {
		assertRefusedAsDeleted(t, relay, authedContext(pkA), note)
	}
	if stored := collect(store.QueryEvents(nostr.Filter{Kinds: []nostr.Kind{nostr.KindTextNote}}, 0)); len(stored) != 0 {
		t.Fatalf("expected every deleted note to be erased, %d left", len(stored))
	}
}

func TestDeletionAdmitReportsDeletedEvents(t *testing.T) {
	store := newMemoryStore()
	registry := NewDeletionRegistry(store)
	now := nostr.Now()

	note := signedEventAt(t, skA, nostr.KindTextNote, now-10, "A note")
	deletion := deletionEvent(t, skA, now, nostr.Tag{"e", note.ID.Hex()})

	if !registry.Admit(deletion) {
		t.Fatal("expected the deletion request to be admitted")
	}
	if registry.Admit(note) {
		t.Fatal("expected the deleted note to be refused")
	}
}

func TestParseDeletableAddress(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "addressable", value: "30023:" + pkA.Hex() + ":my-article", want: true},
		{name: "replaceable without identifier", value: "10002:" + pkA.Hex() + ":", want: true},
		{name: "another author", value: "30023:" + pkB.Hex() + ":my-article", want: false},
		{name: "deletion request", value: "5:" + pkA.Hex() + ":", want: false},
		{name: "request to vanish", value: "62:" + pkA.Hex() + ":", want: false},
		{name: "missing identifier part", value: "30023:" + pkA.Hex(), want: false},
		{name: "unparseable kind", value: "notakind:" + pkA.Hex() + ":", want: false},
		{name: "unparseable pubkey", value: "30023:nothex:", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, got := parseDeletableAddress(test.value, pkA); got != test.want {
				t.Fatalf("parseDeletableAddress = %v, want %v", got, test.want)
			}
		})
	}
}

func deletionEvent(t *testing.T, sk nostr.SecretKey, createdAt nostr.Timestamp, tags ...nostr.Tag) nostr.Event {
	t.Helper()
	return signedEventAt(t, sk, nostr.KindDeletion, createdAt, "", tags...)
}

func authedContext(pubkey nostr.PubKey) context.Context {
	return khatru.ForceSetAuthed(context.Background(), pubkey)
}

func assertRefusedAsDeleted(t *testing.T, relay *khatru.Relay, ctx context.Context, event nostr.Event) {
	t.Helper()

	_, err := relay.AddEvent(ctx, event)
	if err == nil {
		t.Fatalf("expected %q to be refused as deleted", event.Content)
	}
	if !strings.Contains(err.Error(), deletionBlocked) {
		t.Fatalf("unexpected rejection reason for %q: %v", event.Content, err)
	}
}
