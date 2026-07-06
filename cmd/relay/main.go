package main

import (
	"log"
	"net/http"

	privaterelay "nostr-private-relay/internal/relay"
)

func main() {
	cfg, err := privaterelay.LoadConfig()
	if err != nil {
		log.Fatalf("configuration error: %v", err)
	}

	relay, closeStore, err := privaterelay.New(cfg)
	if err != nil {
		log.Fatalf("relay setup error: %v", err)
	}
	defer closeStore()

	log.Printf("private nostr relay listening on %s", cfg.Addr)
	if cfg.RelayURL != "" {
		log.Printf("using relay URL %s for NIP-42 AUTH challenges", cfg.RelayURL)
	}

	if err := http.ListenAndServe(cfg.Addr, relay); err != nil {
		log.Fatalf("relay stopped: %v", err)
	}
}
