# siros-status-service

A standalone status list service for digital credentials, implementing
[draft-ietf-oauth-status-list-21](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html)
(Token Status List). See [`docs/design.md`](docs/design.md) for the full
design and rationale.

**Status:** prototype (docs/design.md §14–§15). Core list mechanics are
proven end to end: the keyed FPE index allocator, spec-conformant
bit-packing, the allocate/update/publish/cache loop, real rotation on
both fullness and age, the issuer-blind power-of-two-choices distribution
pool, the GC/archival sweeper, and the debounced publisher. On top of
that, §15 splits the service into four cooperating binaries with real
issuer authentication (client-assertion + trust evaluation), offline
JWT verification, sharding, and JWT-based ingress routing — also proven
end to end against real Postgres/Redis with two live shards.

## Architecture

Four services (docs/design.md §15), each its own binary under `cmd/`:

- **`cmd/as`** (`internal/as`) — the Authorization Server. An issuer
  proves possession of their signing key via a self-signed client
  assertion (`internal/clientassertion`, RFC 7523-flavored, an embedded
  `jwk` header **or** an `x5c` certificate chain — no pre-registration
  needed either way; §20); a `trust.Evaluator`
  decides whether that key is trusted (`internal/trust`): if
  `TRUST_PDP_URL` is set, a real AuthZEN-wire-protocol
  `AuthZENEvaluator` against a go-trust PDP, **failing closed** on any
  PDP error; if unset, `AllowAllEvaluator` — **fail open**, dev/prototype
  only, `cmd/as` logs a warning. (An earlier Postgres-backed static
  allow-list evaluator was removed as pure duplication — go-trust's own
  PDP already has an equivalent whitelist-registry mode.) On success,
  mints an access token shaped as `go-tokenauth/claims.AccessTokenClaims`
  (`internal/accesstoken`), assigning the issuer to a shard on first
  request (`internal/as/shard.go`, sticky thereafter).
- **`cmd/ingestion-service`** (`internal/ingestion`) — issuer-facing:
  `POST /allocate`, `PATCH /status/{listID}/{idx}`,
  `GET /accounting/me`. One process = one shard. Verifies access tokens
  fully offline using **`go-tokenauth`'s real `validator`/`jwks`/
  `tokengin` packages** (not a local reimplementation — see design doc
  §15.2 for why), enforces per-route permissions via its `tac` claim,
  and rejects a token whose `tenant_id` (shard) doesn't match this
  instance's own as defense in depth.
- **`cmd/verifier-service`** (`internal/verifier`) — read-only,
  unauthenticated: `GET /lists/{id}`. A single instance can serve any
  shard's lists — it looks up `shard_id` from the shared Postgres row
  and holds one Redis client per shard (`SHARD_REDIS_URLS`).
- **`cmd/ingress-router`** (`internal/ingress`) — sits in front of the
  ingestion farm. Verifies the caller's token the same way (offline,
  `go-tokenauth`), reads its `tenant_id`, and reverse-proxies to that
  shard's configured backend. Issuers only ever see one router URL.

Shared packages:

- `internal/allocator` — the keyed format-preserving permutation
  (§5A): a pseudorandom, collision-free index per allocation, no stored
  permutation array.
- `internal/statuslist` — pure spec logic: bit-packing (§4.1),
  DEFLATE/zlib + base64url encoding (§4.2), the signed Status List
  Token (§5.1). Verified against the draft's own worked byte-array
  examples.
- `internal/store` — Postgres for list/allocation/accounting metadata
  (shared across shards, `shard_id`-scoped queries), Redis for the hot
  status bitmap (one instance per shard). See `internal/store/redis.go`
  for why this does **not** use Redis's `BITFIELD` field-addressing
  directly (its bit numbering is MSB-first; the spec packs LSB-first) —
  a small Lua script does an atomic whole-byte read-modify-write
  instead.
- `internal/publisher` — rebuilds and signs a fresh StatusListToken
  when a list's live version moves past what was cached. `MarkDirty`
  (called right after a write) implements the debounce described in §9
  literally: publish immediately if idle, coalesce a burst into one
  deferred publish otherwise; a periodic `Run` loop is a backstop.
  Shard-aware — takes a `shard_id -> BitmapStore` map, since
  `cmd/verifier-service` may need any shard's bitmap.
- `internal/pool` — the §8 distribution: keeps a shard's pool of
  `PoolWidth` (K) concurrently-ACTIVE lists healthy, picks a target via
  issuer-blind power-of-two-choices. Fullness rotation is atomic inside
  `store.ReserveCursorAndRecord`'s own `UPDATE`.
- `internal/gc` — the archive/purge sweep (§7 point 4).
- `internal/pgutil` — `ApplySchema`, an advisory-locked DDL helper.
  **Found live**: two `ingestion-service` shards sharing one Postgres
  and starting concurrently hit a genuine Postgres catalog race running
  the same `CREATE TABLE IF NOT EXISTS` at once; this closes it.

## Running locally

Needs Postgres, two Redis instances (one per shard, to exercise
sharding for real — a single shard works too), and three EC (P-256)
signing keys: one for the AS, one shared by ingestion+verifier for
StatusListTokens (they must match — both sides sign/verify the same
token type), and one for a test issuer.

```sh
make dev-up   # Postgres + Redis via docker compose (see compose.yaml for shard-b, add a second Redis for real sharding)

export AS_SIGNING_KEY_PEM="$(openssl ecparam -name prime256v1 -genkey -noout)"
export STATUSLIST_SIGNING_KEY_PEM="$(openssl ecparam -name prime256v1 -genkey -noout)"
export ISSUER_KEY_PEM="$(openssl ecparam -name prime256v1 -genkey -noout)"

# 1. AS — no TRUST_PDP_URL below means fail-open (AllowAllEvaluator):
# fine for this local walkthrough, never for a real deployment. Set
# TRUST_PDP_URL to a real go-trust PDP to get real (fail-closed) trust
# evaluation instead.
DATABASE_URL=... BASE_URL=http://localhost:8090 HTTP_ADDR=:8090 \
  AS_SIGNING_KEY_PEM="$AS_SIGNING_KEY_PEM" SHARDS=shard-a \
  go run ./cmd/as &

# 2. ingestion-service (shard-a)
DATABASE_URL=... BASE_URL=http://localhost:8080 HTTP_ADDR=:8091 \
  SHARD_ID=shard-a REDIS_ADDR=localhost:6379 SIGNING_KEY_PEM="$STATUSLIST_SIGNING_KEY_PEM" \
  AS_JWKS_URL=http://localhost:8090/.well-known/jwks.json ACCESS_TOKEN_ISSUER=http://localhost:8090 \
  go run ./cmd/ingestion-service &

# 3. verifier-service
DATABASE_URL=... BASE_URL=http://localhost:8080 HTTP_ADDR=:8093 \
  SIGNING_KEY_PEM="$STATUSLIST_SIGNING_KEY_PEM" \
  SHARD_REDIS_URLS='{"shard-a":"redis://localhost:6379"}' \
  go run ./cmd/verifier-service &

# 4. ingress-router
AS_JWKS_URL=http://localhost:8090/.well-known/jwks.json ACCESS_TOKEN_ISSUER=http://localhost:8090 \
  HTTP_ADDR=:8094 SHARD_BACKENDS='{"shard-a":"http://localhost:8091"}' \
  go run ./cmd/ingress-router &
```

Then, as an issuer: get a token (no separate registration step — in
fail-open mode any presented key is trusted; with a real PDP configured,
trust comes from whatever policy it enforces) and use it through the
router.

```sh
# A self-signed client assertion (embedded jwk header) — see
# internal/clientassertion's tests for the exact construction; any small
# script using go-jose + golang-jwt/v5 as shown there works.

curl -X POST localhost:8090/token \
  --data-urlencode grant_type=client_credentials \
  --data-urlencode client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  --data-urlencode "client_assertion=$ASSERTION"
# => {"access_token":"...","token_type":"Bearer","expires_in":3600}

curl -X POST localhost:8094/allocate -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" -d '{"exp":"2027-01-01T00:00:00Z"}'
# => {"list_url":"http://localhost:8080/lists/<id>","index":<n>,"exp":"2027-01-01T00:00:00Z"}
#    -- routed to shard-a automatically; rejected with 400 if exp is past MAX_EXPIRY (§19)

curl -X POST localhost:8094/allocate -H "Authorization: Bearer $ACCESS_TOKEN"
# => exp omitted entirely -> exp defaults to exactly the maximum allowed (now + MAX_EXPIRY)

curl -X PATCH "localhost:8094/status/<id>/<n>" -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" -d '{"status":"INVALID"}'

curl localhost:8093/lists/<id>   # verifier-service, no auth — the signed StatusListToken (JWT)
```

## Configuration (environment variables)

Common to every binary: `HTTP_ADDR`, `BASE_URL`, `DATABASE_URL`.

**`cmd/as`**

| Variable | Default | Notes |
|---|---|---|
| `AS_SIGNING_KEY_PEM` | *(required)* | the AS's own token-signing key — distinct from the StatusListToken key |
| `SIGNING_KEY_ID` | `as-prototype-1` | JWS `kid` for the AS's key |
| `SHARDS` | `default` | comma-separated shard IDs new issuers round-robin/hash-assign into (§15.5) |
| `ACCESS_TOKEN_TTL` | `1h` | |
| `ACCESS_TOKEN_AUDIENCE` | `siros-status-service` | |
| `TRUST_PDP_URL` | *(unset)* | if set, trust evaluation goes to a real AuthZEN PDP, **fail-closed** on any PDP error; if unset, `AllowAllEvaluator` — **fail-open**, dev/prototype only |
| `TRUST_ACTION_NAME` | *(unset)* | AuthZEN `action.name` sent with PDP evaluations |

**`cmd/ingestion-service`**

| Variable | Default | Notes |
|---|---|---|
| `SHARD_ID` | `default` | which shard this instance owns |
| `REDIS_ADDR` / `REDIS_URL` | `localhost:6379` / unset | this shard's Redis |
| `SIGNING_KEY_PEM` | *(required)* | StatusListToken key — must match `verifier-service`'s |
| `AS_JWKS_URL` | *(required)* | e.g. `http://as:8090/.well-known/jwks.json` |
| `ACCESS_TOKEN_ISSUER` | *(required)* | must equal the AS's `BASE_URL` |
| `ACCESS_TOKEN_AUDIENCE` | `siros-status-service` | |
| `LIST_CAPACITY` | `100000` | N_max (§7/§8.2) |
| `LIST_BITS` | `2` | 1, 2, 4, or 8 |
| `POOL_WIDTH` | `4` | K (§8.1/§8.2) |
| `ROTATION_MAX_AGE` | `24h` | T_max — 0 disables age-based rotation |
| `POOL_CHECK_INTERVAL` | `30s` | |
| `GC_GRACE_PERIOD` | `24h` | |
| `GC_RETENTION_PERIOD` | `720h` (30d) | |
| `GC_CHECK_INTERVAL` | `1h` | |
| `DEFAULT_TTL_SECONDS` | `3600` | see "Known gaps" re: per-issuer ttl |
| `PUBLISH_INTERVAL` | `10s` | backstop poll interval (§9) |
| `DECOY_NOISE_RATE` | `0` (disabled) | fraction of never-allocated capacity flipped per pass (§17 — "herd immunity" for real revocations); opt-in |
| `DECOY_CHECK_INTERVAL` | `15m` | how often the decoy sweep runs, when `DECOY_NOISE_RATE` > 0 |
| `MAX_EXPIRY` | `8760h` (365d) | §19: `POST /allocate`'s `exp` may not exceed now+this; omitting `exp` returns exactly this maximum. Tighten per deployment — the test deployment uses `24h` |

**`cmd/verifier-service`**

| Variable | Default | Notes |
|---|---|---|
| `SHARD_REDIS_URLS` | *(required)* | JSON object, `shard_id -> redis URL`, one entry per shard this instance can serve |
| `SIGNING_KEY_PEM` | *(required)* | must match `ingestion-service`'s |
| `DEFAULT_TTL_SECONDS` | `3600` | |
| `GC_RETENTION_PERIOD` | `720h` | must match ingestion's — governs the archived-list 410 cutoff |

**`cmd/ingress-router`**

| Variable | Default | Notes |
|---|---|---|
| `AS_JWKS_URL` | *(required)* | |
| `ACCESS_TOKEN_ISSUER` | *(required)* | |
| `ACCESS_TOKEN_AUDIENCE` | `siros-status-service` | |
| `SHARD_BACKENDS` | *(required)* | JSON object, `shard_id -> ingestion-service base URL` |

## Deploying to Fly

Five Fly apps (docs/design.md §18), each with its own `fly.*.toml` — this
org's convention for a standalone service is its own fly config rather
than being orchestrated through `sirosid-dev` (see
[go-zk-circuits](https://github.com/sirosfoundation/go-zk-circuits)'s
`fly.toml` for another example of the same pattern):

| app | file | region(s) | public? |
|---|---|---|---|
| `siros-status-service-as` | `fly.as.toml` | `iad` | **`auth.t.status.siros.org`** |
| `siros-status-service-ingestion-iad` | `fly.ingestion.iad.toml` | `iad` | internal only |
| `siros-status-service-ingestion-fra` | `fly.ingestion.fra.toml` | `fra` | internal only |
| `siros-status-service-verifier` | `fly.verifier.toml` | `iad` | **`lists.t.status.siros.org`** |
| `siros-status-service-ingress` | `fly.ingress.toml` | `iad` + `fra` | **`api.t.status.siros.org`** |

**One shard per region** (`iad`, `fra` to start): each `-ingestion-<region>`
app is a real, separate shard with its own Redis — that's genuine
physical isolation, not just geographic spread. `-ingress`, by contrast,
is one app deployed to *both* regions, because it's fully stateless
(every region's copy carries the identical `SHARD_BACKENDS` map): a
custom domain attaches to exactly one Fly app, and Fly's Anycast routes
each request to whichever of that app's regions is nearest — which only
works within one app, not across `-ingress-iad`/`-ingress-fra` as
separate apps. `-as` and `-verifier` stay single-instance in `iad`,
alongside the shared Postgres primary (docs/design.md §18 on why: token
issuance and shared metadata reads aren't worth splitting for v1).

One shared Postgres (metadata only — `-as`, every `-ingestion-<region>`,
and `-verifier` all point at it, single primary, no replicas for v1) and
one Redis per shard (`-ingestion-<region>` writes to its own; `-verifier`
needs every shard's Redis URL in `SHARD_REDIS_URLS`, since a verifier
request can name a list from any shard).

```sh
fly apps create siros-status-service-as
fly apps create siros-status-service-ingestion-iad
fly apps create siros-status-service-ingestion-fra
fly apps create siros-status-service-verifier
fly apps create siros-status-service-ingress

fly postgres create --name siros-status-service-db --region iad
fly postgres attach siros-status-service-db -a siros-status-service-as
fly postgres attach siros-status-service-db -a siros-status-service-ingestion-iad
fly postgres attach siros-status-service-db -a siros-status-service-ingestion-fra
fly postgres attach siros-status-service-db -a siros-status-service-verifier
# `attach` sets each app's DATABASE_URL secret directly — no manual copy needed.

fly redis create --name siros-status-service-redis-iad --region iad --no-replicas
fly redis create --name siros-status-service-redis-fra --region fra --no-replicas
# fly redis create prints each connection URL once, at creation time — save both.

fly certs add auth.t.status.siros.org -a siros-status-service-as
# fly.as.toml's BASE_URL must match this domain — it drives the `iss`
# claim on every issued access token and the required `aud` on incoming
# client assertions, and fly.ingress.toml / each fly.ingestion.<region>.toml
# hardcode this same domain as AS_JWKS_URL/ACCESS_TOKEN_ISSUER, so all four
# files agree before any of them are deployed.

STATUSLIST_SIGNING_KEY_PEM="$(openssl ecparam -name prime256v1 -genkey -noout)"
fly secrets set -a siros-status-service-as AS_SIGNING_KEY_PEM="$(openssl ecparam -name prime256v1 -genkey -noout)"
fly secrets set -a siros-status-service-ingestion-iad SIGNING_KEY_PEM="$STATUSLIST_SIGNING_KEY_PEM" REDIS_URL="<iad redis URL>"
fly secrets set -a siros-status-service-ingestion-fra SIGNING_KEY_PEM="$STATUSLIST_SIGNING_KEY_PEM" REDIS_URL="<fra redis URL>"
fly secrets set -a siros-status-service-verifier SIGNING_KEY_PEM="$STATUSLIST_SIGNING_KEY_PEM" \
  SHARD_REDIS_URLS='{"iad":"<iad redis URL>","fra":"<fra redis URL>"}'

# Deploy order matters only in that the AS should exist before issuers hit
# it — nothing blocks on anything else at startup (each only fetches the
# AS's JWKS lazily, on first token verification), so this order is a
# convenience, not a hard requirement.
fly deploy -c fly.as.toml
fly deploy -c fly.ingestion.iad.toml
fly deploy -c fly.ingestion.fra.toml
fly deploy -c fly.verifier.toml
fly deploy -c fly.ingress.toml

# -ingress starts single-region (primary_region above); `fly regions add`
# is deprecated — add the second region's machines directly:
fly scale count 2 -a siros-status-service-ingress --region fra

# Custom domains — one-time per app, then follow each command's printed
# DNS instructions (auth.t.status.siros.org is added earlier, above,
# since -as's BASE_URL must already match it before -as is deployed):
fly certs add api.t.status.siros.org -a siros-status-service-ingress
fly certs add lists.t.status.siros.org -a siros-status-service-verifier
```

`TRUST_PDP_URL` is deliberately left unset in `fly.as.toml` — see "Known
gaps" below before pointing this at a real deployment.

## Known gaps vs. the full design

These are intentionally deferred, not oversights:

- **GC row cleanup**: `internal/gc` drops a list's Redis bitmap once past
  retention, but its Postgres row (metadata + ownership records) is kept
  indefinitely — needed for `410` semantics and audit history. Revisit
  only if that metadata's own storage becomes worth reclaiming.
- **Expiry-bucketed pools (§8.3)**: not implemented — needs real
  traffic data to size buckets sensibly.
- **Target-based rotation knob (§8.2)**: only the raw knobs exist; the
  throughput-derived auto-tuning surface is not built.
- **Per-issuer/credential-type `ttl`**: still one config value per
  ingestion instance, not per issuer/type — only really meaningful once
  §8.3's expiry-bucketed pools exist.
- **AuthZEN trust evaluation is untested against a live PDP**: the wire
  client (`internal/trust.AuthZENEvaluator`) is real, but no go-trust
  PDP is deployed for this service yet (see design doc §15.2 for why
  importing go-trust's own Go client wasn't the right move either) — so
  today this only ever runs in `AllowAllEvaluator`'s fail-open mode.
  **Do not deploy without `TRUST_PDP_URL` set to a real PDP.**
- **Sharding is logical, not physical**: multiple processes/Redis
  instances, not separate infrastructure/regions.
- **AS key rotation**: a single static key, not a rotating set.
- **Pool maintenance has no cross-process lock**: `internal/pool`'s
  "count ACTIVE lists, then create more if under Width" can transiently
  overshoot `POOL_WIDTH` under a race. Harmless at prototype scale (see
  the package doc).
- **Decoy noise (§17) is a flat rate, not revocation-rate-adaptive**:
  `DECOY_NOISE_RATE` disguises real revocations with a constant fraction
  of a list's *remaining* capacity, not one scaled to that list's actual
  revocation rate or to how close it is to full — a list nearing
  `N_max` has proportionally less unallocated capacity left to hide
  behind. Off by default (`DECOY_NOISE_RATE=0`); the correctness guard
  it depends on (explicit VALID-reset at allocation) is real and tested,
  but the feature itself hasn't run against real traffic yet.

## Verified against the spec

`internal/statuslist`'s bit-packing was checked against
draft-ietf-oauth-status-list-21 §4.1's own worked hex examples (fetched
directly from the IETF datatracker while building this, not recalled
from memory) rather than assumed from a general description — see
`bitmap_test.go`.
