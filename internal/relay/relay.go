package relay

import (
	"context"
	"embed"
	"strings"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/eventstore"
	"fiatjaf.com/nostr/eventstore/lmdb"
	"fiatjaf.com/nostr/khatru"
	"fiatjaf.com/nostr/nip11"
)

func New(cfg Config) (*khatru.Relay, func(), error) {
	store := &lmdb.LMDBBackend{Path: cfg.LMDBPath}
	if err := store.Init(); err != nil {
		return nil, nil, err
	}

	relay := NewWithStore(cfg, store)
	return relay, store.Close, nil
}

func NewWithStore(cfg Config, store eventstore.Store) *khatru.Relay {
	relay, _, _ := newWithRegistries(cfg, store)
	return relay
}

func newWithRegistries(cfg Config, store eventstore.Store) (*khatru.Relay, *VanishRegistry, *DeletionRegistry) {
	relay := khatru.NewRelay()
	relay.Addr = cfg.Addr
	relay.ServiceURL = cfg.RelayURL
	relay.Negentropy = true

	relay.Info.Name = cfg.Name
	relay.Info.Description = cfg.Description
	relay.Info.Software = "https://github.com/nogringo/nostr-private-relay"
	relay.Info.Version = version()
	relay.Info.Icon = cfg.Icon
	relay.Info.Contact = cfg.Contact
	relay.Info.PubKey = cfg.PubKey
	relay.Info.Limitation = &nip11.RelayLimitationDocument{
		AuthRequired: true,
		MaxLimit:     cfg.MaxLimit,
		DefaultLimit: cfg.MaxLimit,
	}
	relay.Info.AddSupportedNIPs([]int{1, 9, 11, 37, 40, 42, 45, 51, 62, 70, 77})

	vanish := NewVanishRegistry(cfg, store)
	vanish.log = relay.Log
	// rebuild() marked nothing as purged, so this finishes a purge that a crash
	// or a reboot interrupted. Synchronous on purpose: serving before it is done
	// would make the deleted events readable again.
	if err := vanish.PurgeAll(); err != nil {
		relay.Log.Printf("failed to enforce stored requests to vanish: %v", err)
	}
	if vanish.HasUnresolvedRequests() {
		relay.Log.Printf("WARNING: stored NIP-62 requests to vanish cannot be evaluated without RELAY_URL and are NOT being enforced")
	}

	deletions := NewDeletionRegistry(store)
	deletions.log = relay.Log
	// Catches up on NIP-09 requests whose targets were republished back when the
	// relay kept no record of them. Synchronous for the same reason as above.
	if err := deletions.EnforceAll(); err != nil {
		relay.Log.Printf("failed to enforce stored deletion requests: %v", err)
	}

	relay.OnConnect = func(ctx context.Context) {
		khatru.RequestAuth(ctx)
	}
	relay.OnEvent = func(ctx context.Context, event nostr.Event) (bool, string) {
		if reject, msg := requireAuthForEvent(ctx, event); reject {
			return reject, msg
		}
		if reject, msg := vanish.onEvent(event); reject {
			return reject, msg
		}
		return deletions.onEvent(event)
	}
	relay.OnEventSaved = vanish.onEventSaved
	relay.AllowDeleting = func(ctx context.Context, target, deletion nostr.Event) bool {
		// NIP-09: there is no unrequest deletion, and erasing the request would
		// let the events it covers come back.
		if target.Kind == nostr.KindDeletion {
			return false
		}
		return vanish.allowDeleting(ctx, target, deletion)
	}
	relay.OnRequest = requireAuthForFilter
	relay.OnCount = requireAuthForFilter
	relay.PreventBroadcast = func(ws *khatru.WebSocket, _ nostr.Filter, event nostr.Event) bool {
		return !canReadEvent(ws.AuthedPublicKeys, event)
	}

	relay.UseEventstore(store, cfg.MaxLimit)
	private := newPrivateStore(store, cfg.MaxLimit)
	relay.QueryStored = private.query
	relay.Count = private.count
	relay.CountHLL = private.countHLL

	return relay, vanish, deletions
}

func requireAuthForEvent(ctx context.Context, event nostr.Event) (bool, string) {
	// NIP-62: a request to vanish must be honoured regardless of the user's status
	if event.Kind == KindRequestToVanish {
		return false, ""
	}

	if _, ok := khatru.GetAuthed(ctx); !ok {
		requestAuthIfConnected(ctx)
		return true, authRequired
	}
	return false, ""
}

func requireAuthForFilter(ctx context.Context, _ nostr.Filter) (bool, string) {
	if _, ok := khatru.GetAuthed(ctx); !ok {
		requestAuthIfConnected(ctx)
		return true, authRequired
	}
	return false, ""
}

func requestAuthIfConnected(ctx context.Context) {
	if khatru.GetConnection(ctx) != nil {
		khatru.RequestAuth(ctx)
	}
}

//go:embed version.txt
var versionFile embed.FS

func version() string {
	data, err := versionFile.ReadFile("version.txt")
	if err != nil {
		return ""
	}
	version := strings.TrimSpace(string(data))
	if version == "" {
		return ""
	}
	return version
}
