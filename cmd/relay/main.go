package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/eventstore/lmdb"
	privaterelay "nostr-private-relay/internal/relay"
)

func main() {
	exportFlag := flag.Bool("export", false, "Export all events as JSONL to stdout")
	exportFilter := flag.String("filter", "", "NIP-01 JSON filter for export (e.g. '{\"kinds\":[1,4]}'). Only used with --export.")
	importFlag := flag.Bool("import", false, "Import events as JSONL from stdin")
	flag.Parse()

	cfg, err := privaterelay.LoadConfig()
	if err != nil {
		log.Fatalf("configuration error: %v", err)
	}

	if *exportFlag {
		if err := runExport(cfg, *exportFilter); err != nil {
			log.Fatalf("export error: %v", err)
		}
		return
	}

	if *importFlag {
		if err := runImport(cfg); err != nil {
			log.Fatalf("import error: %v", err)
		}
		return
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

func runExport(cfg privaterelay.Config, filterJSON string) error {
	store := &lmdb.LMDBBackend{Path: cfg.LMDBPath}
	if err := store.Init(); err != nil {
		return err
	}
	defer store.Close()

	var filter nostr.Filter
	if filterJSON != "" {
		if err := json.Unmarshal([]byte(filterJSON), &filter); err != nil {
			return fmt.Errorf("invalid --filter JSON: %w", err)
		}
	}

	// Use a very high limit when none is set in the filter
	limit := 1_000_000_000
	if filter.Limit > 0 || filter.LimitZero {
		limit = filter.Limit
	}

	events := store.QueryEvents(filter, limit)

	encoder := json.NewEncoder(os.Stdout)
	for event := range events {
		if err := encoder.Encode(event); err != nil {
			return err
		}
	}
	return nil
}

func runImport(cfg privaterelay.Config) error {
	store := &lmdb.LMDBBackend{Path: cfg.LMDBPath}
	if err := store.Init(); err != nil {
		return err
	}
	defer store.Close()

	vanish := privaterelay.NewVanishRegistry(cfg, store)
	// Importing without knowing our own URL would silently reinject events a
	// request to vanish had deleted.
	if vanish.HasUnresolvedRequests() {
		return fmt.Errorf("this database holds NIP-62 requests to vanish that cannot be evaluated: set RELAY_URL before importing")
	}

	scanner := bufio.NewScanner(os.Stdin)
	// Nostr events can be large. Let's use a 16MB maximum line buffer capacity.
	const maxCapacity = 16 * 1024 * 1024
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, maxCapacity)

	count := 0
	skipped := 0
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var event nostr.Event
		if err := json.Unmarshal(line, &event); err != nil {
			return fmt.Errorf("error parsing event on line %d: %w", count+1, err)
		}

		// Validate structure and cryptographic signature
		if !event.CheckID() {
			return fmt.Errorf("invalid ID for event %s on line %d", event.ID, count+1)
		}
		if !event.VerifySignature() {
			return fmt.Errorf("invalid signature for event %s on line %d", event.ID, count+1)
		}

		if !vanish.Admit(event) {
			skipped++
			continue
		}

		if err := store.SaveEvent(event); err != nil {
			return fmt.Errorf("error saving event %s on line %d: %w", event.ID, count+1, err)
		}
		count++
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	// A request to vanish can appear anywhere in the file, including after the
	// events it covers, and stdin cannot be replayed: sweep once at the end.
	if err := vanish.PurgeAll(); err != nil {
		return fmt.Errorf("error enforcing requests to vanish after import: %w", err)
	}

	log.Printf("Successfully imported %d events (%d skipped for vanished pubkeys)", count, skipped)
	return nil
}
