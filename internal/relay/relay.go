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
	relay, _ := newWithVanish(cfg, store)
	return relay
}

func newWithVanish(cfg Config, store eventstore.Store) (*khatru.Relay, *VanishRegistry) {
	relay := khatru.NewRelay()
	relay.Addr = cfg.Addr
	relay.ServiceURL = cfg.RelayURL
	relay.Negentropy = true

	relay.Info.Name = cfg.Name
	relay.Info.Description = cfg.Description
	relay.Info.Software = "nostr-private-relay"
	relay.Info.Version = version()
	relay.Info.Icon = cfg.Icon
	relay.Info.Contact = cfg.Contact
	relay.Info.PubKey = cfg.PubKey
	relay.Info.Limitation = &nip11.RelayLimitationDocument{
		AuthRequired: true,
		MaxLimit:     cfg.MaxLimit,
		DefaultLimit: cfg.MaxLimit,
	}
	relay.Info.AddSupportedNIPs([]int{37, 51, 62, 77})

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

	relay.OnConnect = func(ctx context.Context) {
		khatru.RequestAuth(ctx)
	}
	relay.OnEvent = func(ctx context.Context, event nostr.Event) (bool, string) {
		if reject, msg := requireAuthForEvent(ctx, event); reject {
			return reject, msg
		}
		return vanish.onEvent(event)
	}
	relay.OnEventSaved = vanish.onEventSaved
	relay.AllowDeleting = vanish.allowDeleting
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

	return relay, vanish
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
