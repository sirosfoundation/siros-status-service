<!-- Regenerate with: go run ./tools/gen-config-docs -->

# Configuration Reference

Every field is set purely from environment variables (docs/design.md §12) — no YAML/config-file convention at this scale. `Required` fields with no default make the binary refuse to start rather than run with a guessed value.

## Table of Contents

- [cmd/as](#cmdas)
- [cmd/ingestion-service](#cmdingestion-service)
- [cmd/verifier-service](#cmdverifier-service)
- [cmd/ingress-router](#cmdingress-router)

---

## cmd/as

Config struct: `internal/config.ASConfig`

| Field | Env Variable | Default | Description |
|-------|-------------|---------|-------------|
| `HTTPAddr` | `HTTP_ADDR` | `:8082` | HTTPAddr is the address this service listens on (host:port, or just :port). |
| `BaseURL` | `BASE_URL` | `http://localhost:8082` | BaseURL is the AS's own public base URL — both the `iss` claim on minted tokens and the expected `aud` on inbound client assertions. |
| `PostgresDSN` | `DATABASE_URL` | `postgres://postgres:postgres@localhost:5432/statuslist?sslmode=disable` | PostgresDSN is the shared metadata Postgres connection string — the same database as every cmd/ingestion-service shard and cmd/verifier-service point at (docs/design.md §18). |
| `SigningKey` | `AS_SIGNING_KEY_PEM` | *(required)* (PEM-encoded EC private key) | SigningKey signs access tokens; deliberately distinct from the StatusListToken signing key (different service, different trust boundary — see docs/design.md §15.8). SigningKeyID is placed in the JWS `kid` header on minted access tokens. |
| `SigningKeyID` | `SIGNING_KEY_ID` | `as-prototype-1` |  |
| `AccessTokenTTL` | `ACCESS_TOKEN_TTL` | `1h0m0s` |  |
| `AccessTokenAudience` | `ACCESS_TOKEN_AUDIENCE` | `siros-status-service` | AccessTokenAudience is the `aud` claim minted access tokens carry, and what every consumer (cmd/ingress-router, cmd/ingestion-service) requires an inbound token to match. |
| `Shards` | `SHARDS` | `default` (comma-separated list) | Shards is the pool of shard IDs new issuers get round-robin assigned into on first token issuance (§15.5). |
| `TrustPDPURL` | `TRUST_PDP_URL` | — | TrustPDPURL selects the trust source (decided 2026-09-24): if set, evaluations go to a real go-trust PDP over AuthZEN, and a PDP error/unreachability fails closed (no token issued). If unset, the default is AllowAllEvaluator — fail *open* — so a prototype/dev deployment works without a PDP; never appropriate for production. |
| `TrustActionName` | `TRUST_ACTION_NAME` | — | TrustActionName is the AuthZEN action name sent to the PDP — only meaningful when TrustPDPURL is set. |

## cmd/ingestion-service

Config struct: `internal/config.IngestionConfig`

| Field | Env Variable | Default | Description |
|-------|-------------|---------|-------------|
| `HTTPAddr` | `HTTP_ADDR` | `:8080` | HTTPAddr is the address this service listens on (host:port, or just :port). |
| `BaseURL` | `BASE_URL` | `http://localhost:8080` | BaseURL is this service's own public base URL, used to build {list_url} values returned from POST /allocate. |
| `RedisAddr` | `REDIS_ADDR` | `localhost:6379` | RedisAddr is used only if RedisURL is unset. RedisURL (a full redis:// or rediss:// URL) takes priority when set, and is required for managed offerings needing auth/TLS (e.g. Fly's Upstash-backed Redis). |
| `RedisURL` | `REDIS_URL` | — |  |
| `PostgresDSN` | `DATABASE_URL` | `postgres://postgres:postgres@localhost:5432/statuslist?sslmode=disable` | PostgresDSN is the shared metadata Postgres connection string — the same database as cmd/as and cmd/verifier-service point at (docs/design.md §18). |
| `ShardID` | `SHARD_ID` | `default` | ShardID is which shard (docs/design.md §15.5) this instance owns — every list it creates, and every access token it will accept, belongs to this shard. |
| `ListCapacity` | `LIST_CAPACITY` | `100000` | ListCapacity is N_max (§7/§8.2): the per-list capacity internal/pool creates new lists with. |
| `ListBits` | `LIST_BITS` | `2` | ListBits is the per-entry bit width (1, 2, 4, or 8). |
| `PoolWidth` | `POOL_WIDTH` | `4` | PoolWidth is K (§8.1/§8.2): concurrently-ACTIVE lists that power-of-two-choices placement picks between. |
| `RotationMaxAge` | `ROTATION_MAX_AGE` | `24h0m0s` | RotationMaxAge is T_max (§8.2). Zero disables age-based rotation. |
| `PoolCheckInterval` | `POOL_CHECK_INTERVAL` | `30s` | PoolCheckInterval is how often internal/pool's background loop checks for lists past RotationMaxAge and tops the pool back up. |
| `DefaultTTLSeconds` | `DEFAULT_TTL_SECONDS` | `3600` | DefaultTTLSeconds is the fallback cache lifetime applied when an issuer doesn't set its own (§9/§13). |
| `PublishInterval` | `PUBLISH_INTERVAL` | `10s` | PublishInterval is the periodic-republish backstop interval (§9). |
| `DecoyNoiseRate` | `DECOY_NOISE_RATE` | `0` | DecoyNoiseRate is the fraction (0, 1] of a list's never-allocated capacity internal/decoy targets per check pass (§17). Zero (the default) disables decoy noising entirely. |
| `DecoyCheckInterval` | `DECOY_CHECK_INTERVAL` | `15m0s` | DecoyCheckInterval is how often internal/decoy sweeps this shard's lists for noise injection. |
| `MaxExpiry` | `MAX_EXPIRY` | `8760h0m0s` | MaxExpiry bounds how far in the future POST /allocate's `exp` may be set (docs/design.md §19): a request naming a later `exp` is rejected outright, and a request that omits `exp` gets exactly now+MaxExpiry — the maximum, not an arbitrary/short fallback. Real deployments are expected to tighten this well below the permissive default (e.g. the test deployment uses 24h). |
| `GCGracePeriod` | `GC_GRACE_PERIOD` | `24h0m0s` | GCGracePeriod, GCRetentionPeriod, and GCCheckInterval configure internal/gc's archive/purge sweep (§7 point 4) — see VerifierConfig.GCRetentionPeriod's own comment for why the verifier needs a copy of just that one value. |
| `GCRetentionPeriod` | `GC_RETENTION_PERIOD` | `720h0m0s` |  |
| `GCCheckInterval` | `GC_CHECK_INTERVAL` | `1h0m0s` |  |
| `SigningKey` | `SIGNING_KEY_PEM` | *(required)* (PEM-encoded EC private key) | SigningKey signs StatusListTokens; SigningKeyID is placed in the JWS `kid` header — must match across every ingestion shard and the verifier (one signing identity). |
| `SigningKeyID` | `SIGNING_KEY_ID` | `prototype-1` |  |
| `ASJWKSURL` | `AS_JWKS_URL` | *(required)* | ASJWKSURL, AccessTokenIssuer, and AccessTokenAudience configure offline access-token verification (§15.3) — the AS is never called on the request path, only its JWKS is fetched and cached. |
| `AccessTokenIssuer` | `ACCESS_TOKEN_ISSUER` | *(required)* |  |
| `AccessTokenAudience` | `ACCESS_TOKEN_AUDIENCE` | `siros-status-service` |  |
| `JWKSRefreshInterval` | `JWKS_REFRESH_INTERVAL` | `5m0s` | JWKSRefreshInterval is how often ASJWKSURL is re-fetched. |

## cmd/verifier-service

Config struct: `internal/config.VerifierConfig`

| Field | Env Variable | Default | Description |
|-------|-------------|---------|-------------|
| `HTTPAddr` | `HTTP_ADDR` | `:8081` | HTTPAddr is the address this service listens on (host:port, or just :port). |
| `BaseURL` | `BASE_URL` | `http://localhost:8081` | BaseURL is this service's own public base URL — signed into every published StatusListToken's `sub` claim, and what every ingestion shard's own BaseURL points POST /allocate's `list_url` response at (docs/design.md §18). |
| `PostgresDSN` | `DATABASE_URL` | `postgres://postgres:postgres@localhost:5432/statuslist?sslmode=disable` | PostgresDSN is the shared metadata Postgres connection string — the same database as cmd/as and every cmd/ingestion-service shard point at (docs/design.md §18). |
| `ShardRedisURLs` | `SHARD_REDIS_URLS` | *(required)* (JSON object) | ShardRedisURLs maps shard_id -> that shard's Redis connection string, since a verifier may need to read any shard's bitmap depending on which shard a requested list belongs to (§15.5). |
| `DefaultTTLSeconds` | `DEFAULT_TTL_SECONDS` | `3600` | DefaultTTLSeconds is the fallback cache lifetime applied when an issuer didn't set its own at allocation time (§9/§13). |
| `GCRetentionPeriod` | `GC_RETENTION_PERIOD` | `720h0m0s` | GCRetentionPeriod must match the ingestion shards' own setting — it's how the verifier decides whether an ARCHIVED list is still within its serve-the-last-token window or should now 410 (§7 point 4, §13). GC itself (archiving, purging) still runs only on the ingestion side (internal/gc); the verifier only reads this value. |
| `SigningKey` | `SIGNING_KEY_PEM` | *(required)* (PEM-encoded EC private key) | SigningKey signs StatusListTokens. |
| `SigningKeyID` | `SIGNING_KEY_ID` | `prototype-1` | SigningKeyID is placed in the JWS `kid` header on published StatusListTokens — must match every ingestion shard's own value (one signing identity). |

## cmd/ingress-router

Config struct: `internal/config.IngressConfig`

| Field | Env Variable | Default | Description |
|-------|-------------|---------|-------------|
| `HTTPAddr` | `HTTP_ADDR` | `:8083` | HTTPAddr is the address this service listens on (host:port, or just :port). |
| `ASJWKSURL` | `AS_JWKS_URL` | *(required)* | ASJWKSURL, AccessTokenIssuer, and AccessTokenAudience configure offline access-token verification (§15.3/§15.6) — the AS is never called on the request path, only its JWKS is fetched and cached. |
| `AccessTokenIssuer` | `ACCESS_TOKEN_ISSUER` | *(required)* |  |
| `AccessTokenAudience` | `ACCESS_TOKEN_AUDIENCE` | `siros-status-service` |  |
| `JWKSRefreshInterval` | `JWKS_REFRESH_INTERVAL` | `5m0s` | JWKSRefreshInterval is how often ASJWKSURL is re-fetched. |
| `ShardBackends` | `SHARD_BACKENDS` | *(required)* (JSON object) | ShardBackends maps shard_id -> that shard's ingestion-service base URL, read from the access token's shard claim per request. |

