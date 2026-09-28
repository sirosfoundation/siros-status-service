# reassign-shard

Moves one issuer, or every issuer currently on one shard, to a different
shard (or shards) for all *future* allocations (docs/design.md §23).
Never touches an issuer's already-issued credentials — those keep the
shard recorded on their own list rows forever, from whenever they were
actually allocated.

A deliberate, infrequent, operator-driven action — a CLI against the
AS's own Postgres directly, not an admin API endpoint.

## Usage

```sh
# Move one issuer (rebalancing):
go run ./tools/reassign-shard -issuer some-issuer-id -to fra

# Empty a whole shard (region decommission), splitting its issuers
# round-robin across two targets so the emptied shard's traffic doesn't
# just pile onto one new hotspot:
go run ./tools/reassign-shard -from iad -to fra,syd

# Always dry-run first:
go run ./tools/reassign-shard -from iad -to fra,syd -dry-run
```

`-h` for the full flag list (`-postgres-dsn` to target a real deployment
instead of the local default).

## What happens after reassignment

- Existing access tokens keep routing to the *old* shard until they
  expire (`ACCESS_TOKEN_TTL`, default 1h) — no thundering herd, traffic
  drains on its own schedule as issuers naturally re-authenticate.
- `PATCH /status` against a credential issued before the reassignment
  still reaches the shard that actually holds it: `cmd/ingress-router`
  routes that request by the *list's own* embedded shard
  (`internal/listid`), not the caller's current token claim.
- To confirm a shard is actually emptying, watch
  `ingestion_allocate_total{shard_id=...}` and
  `ingestion_pool_active_lists{shard_id=...}` (docs/design.md §21) —
  both should flatline shortly after a bulk reassignment.
