# nostr-private-relay

A private relay where only the author can read their own events.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `RELAY_ADDR` | `:3334` | HTTP/WebSocket listen address. |
| `RELAY_URL` | empty | Public relay URL used for NIP-42 challenge validation, for example `wss://relay.example.com/`. |
| `RELAY_NAME` | `Private relay` | NIP-11 relay name. |
| `RELAY_DESCRIPTION` | `A private relay where only the author can read their own events.` | NIP-11 relay description. |
| `RELAY_PUBKEY` | empty | Optional relay operator pubkey in hex. |
| `RELAY_LMDB_PATH` | `./data/lmdb` | LMDB directory. |
| `RELAY_MAX_LIMIT` | `500` | Maximum query limit. |

Run:

```sh
go run ./cmd/relay
```
