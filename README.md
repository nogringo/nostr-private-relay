# nostr-private-relay

A private relay where only the author can read their own events.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `RELAY_ADDR` | `:3334` | HTTP/WebSocket listen address. |
| `RELAY_URL` | empty | Public relay URL used for NIP-42 challenge validation, for example `wss://relay.example.com/`. |
| `RELAY_NAME` | `Private relay` | NIP-11 relay name. |
| `RELAY_DESCRIPTION` | `A private relay where only the author can read their own events.` | NIP-11 relay description. |
| `RELAY_ICON` | empty | Optional NIP-11 icon URL. |
| `RELAY_CONTACT` | empty | Optional contact info for the relay operator. |
| `RELAY_PUBKEY` | empty | Optional relay operator pubkey in hex. |
| `RELAY_LMDB_PATH` | `./data/lmdb` | LMDB directory. |
| `RELAY_MAX_LIMIT` | `500` | Maximum query limit. |

Run:

```sh
go run ./cmd/relay
```

## Database Backups & Portability

This relay supports two types of backups:
1. **Physical LMDB Hot Backups (`.mdb`)**: Consistent byte-for-byte snapshots of the database state. Best for daily production backups and quick disaster recovery.
2. **Logical JSONL Exports/Imports (`.jsonl`)**: Standard, human-readable text exports of Nostr events. Best for auditing, archival, or migrating events to another relay implementation.

### Physical Backups (LMDB)

These backups copy and compact database pages at a consistent transaction state. They can be performed live while the relay is running.

* **To back up the database:**
  ```sh
  ./scripts/backup.sh
  ```
  This creates a compressed snapshot inside the `./backups` folder (e.g., `backup_20260706_162000.mdb.gz`) and automatically deletes backups older than 7 days.

* **To restore the database:**
  ```sh
  ./scripts/restore.sh backups/backup_20260706_162000.mdb.gz
  ```
  *Note: The restore script will stop the container, create a safety backup of your current database, extract the chosen backup, and restart the container.*

### Logical Backups (JSONL)

These exports write events in standard JSON format (one per line). They can be run on a live container without stopping the service.

* **To export all events to a compressed JSONL file:**
  ```sh
  ./scripts/export_jsonl.sh
  ```
  This creates `backups/export_20260706_162000.jsonl.gz`.

* **To export a filtered subset of events:**

  The `--export` flag accepts an optional `--filter` flag containing a [NIP-01](https://github.com/nostr-protocol/nostr/blob/master/01.md) JSON filter.

  ```sh
  # All events from a specific author
  go run ./cmd/relay --export --filter '{"authors":["<pubkey-hex>"]}'

  # Events within a time window (Unix timestamps)
  go run ./cmd/relay --export --filter '{"since":1700000000,"until":1750000000}'
  ```

  When `--filter` is omitted, all events are exported.

* **To import events from a JSONL file:**
  ```sh
  ./scripts/import_jsonl.sh backups/export_20260706_162000.jsonl.gz
  ```
  *Note: During import, the relay validates the IDs and cryptographic signatures of all events before storing them.*
