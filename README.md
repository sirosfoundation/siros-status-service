# siros-status-service

A standalone status list service for digital credentials, implementing
[draft-ietf-oauth-status-list-21](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html)
(Token Status List). See [`docs/design.md`](docs/design.md) for the full
design and rationale.

**Status:** prototype (docs/design.md §14). This validates the core
claims end to end: the keyed FPE index allocator, spec-conformant
bit-packing, the allocate/update/publish/cache loop, real rotation on
both fullness (N_max) and age (T_max), the §8.1 issuer-blind,
power-of-two-choices distribution pool across K concurrently-ACTIVE
lists, and the §7 point 4 GC/archival sweeper (archive on expiry +
grace, purge on retention, 410 after that). The finer §8.2/§8.3 controls
are deliberately not yet implemented; see "Known gaps" below.

## Architecture

- `internal/allocator` — the keyed format-preserving permutation from
  §5A: derives a pseudorandom, collision-free index for each new
  allocation without storing a permutation array.
- `internal/statuslist` — pure spec logic: bit-packing status values
  (§4.1), DEFLATE/zlib + base64url encoding (§4.2), and building/parsing
  the signed Status List Token (§5.1). Verified against the draft's own
  worked byte-array examples.
- `internal/store` — Postgres for list/allocation-ownership metadata,
  Redis for the hot status bitmap. See the package doc in
  `internal/store/redis.go` for why this does **not** use Redis's
  `BITFIELD` field-addressing directly (its bit numbering is MSB-first;
  the spec packs LSB-first) — it does an atomic whole-byte
  read-modify-write via a small Lua script instead.
- `internal/publisher` — rebuilds and signs a fresh StatusListToken when
  a list's live version has moved past what was last published. Publishes
  every ACTIVE and FROZEN list (§7 point 3: a frozen list still accepts
  status updates until it's archived).
- `internal/pool` — §8's distribution: keeps a pool of `PoolWidth` (K)
  concurrently-ACTIVE lists healthy (freezing any past `RotationMaxAge`
  — T_max — and topping the pool back up), and picks a target list for
  each allocation via issuer-blind power-of-two-choices (§8.1). Fullness
  rotation (N_max) is enforced atomically inside
  `store.ReserveCursorAndRecord`'s own `UPDATE`, so a list flips to
  FROZEN in the same statement that fills its last slot.
- `internal/api` — the issuer-facing `POST /allocate` / `PATCH /status`
  and the verifier-facing `GET /lists/{id}` (with ETag/conditional-GET
  support). `POST /allocate` retries against a freshly-queried pool if
  the list it picked got filled or frozen by a concurrent request first.
  `PATCH /status` rejects writes to an ARCHIVED list; `GET` keeps serving
  an ARCHIVED list's last-published token through its retention window,
  then returns `410`.
- `internal/gc` — the archive/purge sweep (§7 point 4): FROZEN lists past
  `max_exp + GCGracePeriod` become ARCHIVED; ARCHIVED lists past
  `archived_at + GCRetentionPeriod` have their Redis bitmap dropped. A
  separate background loop, like `internal/pool`'s rotation maintenance.

## Running locally

```sh
make dev-up                                                    # Redis + Postgres via docker compose
export SIGNING_KEY_PEM="$(openssl ecparam -name prime256v1 -genkey -noout)"
export ISSUER_API_KEYS='{"some-token":"issuer-a"}'
make run
```

Then:

```sh
curl -X POST localhost:8080/allocate \
  -H "Authorization: Bearer some-token" -H "Content-Type: application/json" \
  -d '{"exp":"2027-01-01T00:00:00Z"}'
# => {"list_url":"http://localhost:8080/lists/<id>","index":<n>}

curl -X PATCH localhost:8080/status/<id>/<n> \
  -H "Authorization: Bearer some-token" -H "Content-Type: application/json" \
  -d '{"status":"INVALID"}'

curl localhost:8080/lists/<id>   # the signed StatusListToken (JWT)
```

## Configuration (environment variables)

| Variable | Default | Notes |
|---|---|---|
| `HTTP_ADDR` | `:8080` | |
| `BASE_URL` | `http://localhost:8080` | used to build `list_url` values |
| `REDIS_ADDR` | `localhost:6379` | bare host:port, for unauthenticated/local Redis |
| `REDIS_URL` | *(unset)* | full `redis://`/`rediss://` URL; takes precedence over `REDIS_ADDR`, required for managed Redis (e.g. Fly's Upstash-backed offering) which needs password auth + TLS |
| `DATABASE_URL` | `postgres://postgres:postgres@localhost:5432/statuslist?sslmode=disable` | |
| `LIST_CAPACITY` | `100000` | N_max, per docs/design.md §7/§8.2 |
| `LIST_BITS` | `2` | 1, 2, 4, or 8 |
| `POOL_WIDTH` | `4` | K, per §8.1/§8.2 — concurrently-ACTIVE lists |
| `ROTATION_MAX_AGE` | `24h` | T_max, per §8.2 — 0 disables age-based rotation |
| `POOL_CHECK_INTERVAL` | `30s` | how often `internal/pool` checks for stale/missing lists |
| `GC_GRACE_PERIOD` | `24h` | buffer past a list's `max_exp` before archiving, per §7 point 4 |
| `GC_RETENTION_PERIOD` | `720h` (30d) | how long an archived list stays servable before `410`/purge |
| `GC_CHECK_INTERVAL` | `1h` | how often `internal/gc` sweeps for lists to archive/purge |
| `DEFAULT_TTL_SECONDS` | `3600` | see "Known gaps" re: per-issuer ttl |
| `SIGNING_KEY_PEM` | *(required)* | PEM-encoded EC (P-256) private key |
| `SIGNING_KEY_ID` | `prototype-1` | JWS `kid` header |
| `ISSUER_API_KEYS` | `{}` | JSON object mapping bearer token → issuer_id (prototype-only auth, see `internal/config`'s package doc). **Left empty, auth is skipped entirely** and every caller shares the `anonymous` issuer_id — convenient for a quick test deployment, not a real multi-tenancy boundary. |

## Known gaps vs. the full design

These are intentionally deferred, not oversights:

- **GC row cleanup**: `internal/gc` drops a list's Redis bitmap once past
  retention, but its Postgres row (metadata + ownership records) is kept
  indefinitely — needed to keep serving `410` correctly and for audit
  history. Revisit only if that metadata's own storage becomes worth
  reclaiming.
- **Expiry-bucketed pools (§8.3)**: not implemented — a single pool
  mixes credentials of any expiration horizon, so a long-lived outlier
  can drag out a list's effective anonymity-set decay the way §8.3
  describes. Needs real traffic data to size buckets sensibly.
- **Target-based rotation knob (§8.2)**: only the raw knobs
  (`LIST_CAPACITY`/`ROTATION_MAX_AGE`/`POOL_WIDTH`) exist; the
  throughput-derived "minimum anonymity set + max interval" surface
  decided as the eventual admin-facing knob is not built.
- **Per-issuer/credential-type `ttl`**: decided in §13, but only really
  meaningful once §8.3's expiry-bucketed pools exist, so each pool
  corresponds to a consistent population that could reasonably share a
  ttl policy. Right now there's one `ttl` for everyone
  (`DEFAULT_TTL_SECONDS`).
- **Debouncing**: the publisher polls on a fixed interval
  (`PublishInterval`, default 10s) rather than the "immediately if idle"
  behavior described in §9. See `internal/publisher`'s package doc.
- **Issuer authentication**: a static bearer-token map, not OAuth2
  client-credentials or mTLS. Fine for a prototype, not for onboarding
  real issuers.
- **Pool maintenance has no cross-process lock**: `internal/pool`'s
  "count ACTIVE lists, then create more if under Width" isn't wrapped in
  an advisory lock, so a transient overshoot above `POOL_WIDTH` is
  possible under a race. Harmless at prototype scale (see the package
  doc); worth hardening only if that stops being true.

## Verified against the spec

`internal/statuslist`'s bit-packing was checked against
draft-ietf-oauth-status-list-21 §4.1's own worked hex examples (fetched
directly from the IETF datatracker while building this, not recalled
from memory) rather than assumed from a general description — see
`bitmap_test.go`.
