# loadtest

Drives synthetic issuer traffic through a real deployment: mints N
synthetic issuer identities, gets each a real access token from `cmd/as`
(RFC 7523 client assertion, matching `internal/clientassertion`'s test
construction exactly — see `identity.go`), then generates concurrent
`POST /allocate` / `PATCH /status` / `GET /accounting/me` traffic through
`cmd/ingress-router` for a configured duration.

This is the issuer-facing **write** path (docs/design.md §15's "Track B"),
deliberately not `GET /lists/{id}` — that read path sits behind a CDN in
front of `cmd/verifier-service`, so its load profile is a CDN-sizing
question, not a question about this service's own code.

## Usage

```sh
# against the local walkthrough in the main README (make dev-up, then
# the four services running with their default local ports):
go run ./tools/loadtest -issuers 50 -duration 30s

# with the post-run invariant checks (needs the target's own postgres/redis):
go run ./tools/loadtest -issuers 50 -duration 30s -verify \
  -postgres-dsn "postgres://postgres:postgres@localhost:5432/statuslist?sslmode=disable" \
  -shard-redis-urls '{"default":"redis://localhost:6379"}'

# against the real test deployment (docs/design.md §18):
go run ./tools/loadtest -issuers 20 -duration 30s -rps 25 \
  -as-url https://auth.t.status.siros.org \
  -ingress-url https://api.t.status.siros.org
```

`-h` for the full flag list (endpoints, traffic mix weights, issuer count,
duration).

**`-rps` (default 25, total across every issuer)**: the two live shards'
Redis is billed pay-per-command (Upstash, ~$0.20/100K commands), and
every op here costs several Redis commands downstream, not one — an
uncapped `-issuers` fat-finger against the live deployment is a real
line item, not just a stress test. Raise this deliberately once you
know what a run will actually cost, never by removing the cap.

**`-verify` against the live deployment** needs a tunnel: `-postgres-dsn`
must reach the shared Postgres, which lives on Fly's private network
(`siros-status-service-db.flycast`) — not reachable directly from
outside Fly. Open one first:

```sh
fly proxy 5432:5432 -a siros-status-service-db
# then, in another terminal:
go run ./tools/loadtest ... -verify \
  -postgres-dsn "postgres://<user>:<password>@localhost:5432/siros_status_service_ingestion_iad?sslmode=disable" \
  -shard-redis-urls '{"iad":"<iad redis URL>","fra":"<fra redis URL>"}'
```

Each shard's Redis (Upstash) is reachable directly over the public
internet already — no tunnel needed for those, only for Postgres. Any
of the shared database's per-app users works for `-postgres-dsn` (they
all point at the same database — see docs/design.md §18); the database
name itself must be `siros_status_service_ingestion_iad` regardless of
which user connects, since that's the shared database's actual name.

## What `-verify` actually checks

Two things, both against the target's real Postgres/Redis, not just this
tool's own view of what it sent:

- **Pool balance** (docs/design.md §8.1): how evenly this run's own
  allocations landed across the ACTIVE list pool — a live check of the
  power-of-two-choices mixing property under real concurrent load, not
  just the synthetic unit test in `internal/pool`.
- **Decoy safety** (docs/design.md §17): for every index this run
  allocated or PATCHed, re-reads its *actual* current status straight
  from Redis and compares it against what this harness itself last wrote.
  A mismatch means something — most plausibly `internal/decoy` — silently
  overwrote a real credential's real status. This is the reason the tool
  exists: a race in `internal/decoy.sweepList` was found by re-reading the
  implementation (docs/design.md §17's "found and closed 2026-09-24"
  note) before this tool ever ran, and fixed first. Run this with
  `DECOY_NOISE_RATE` set aggressively on the target `ingestion-service`
  (e.g. `DECOY_NOISE_RATE=0.5 DECOY_CHECK_INTERVAL=2s`) to actually stress
  that fix — confirmed live: ~50,000 decoy flips landing concurrently with
  ~48,000 real allocations at ~3,200 req/s, 0 mismatches.

## Limitations

- `-rps` caps total request rate, not the read/write path deliberately
  left out of scope: `GET /lists/{id}` (docs/design.md §18 — that's a
  CDN-sizing question, not a question about this service's own code).
- Latencies are collected in memory per worker and merged after the run,
  so very long/very high-issuer-count runs use proportionally more
  memory — fine at the scale this was built and tested at (tens of
  issuers, tens of seconds), unverified beyond that.
