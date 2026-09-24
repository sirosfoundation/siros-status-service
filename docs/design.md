# SIROS Status List Service — Design

**Status:** Draft, for prototype scoping
**Date:** 2026-09-23
**Author:** leifj@siros.org

## 1. Problem

We need a standalone service that maintains and publishes status lists for
digital credentials, compatible with the IETF OAuth WG Token Status List
draft. Unlike a naive per-issuer implementation, this service needs to:

- Maintain a potentially large number of status lists.
- Assign **randomized** indices within a list, so index order doesn't leak
  issuance order/volume.
- Spread issuers across a shared pool of lists rather than dedicating lists
  to individual issuers, with administrative control over how fast that
  pool rotates, so that fetching a list doesn't itself reveal which issuer
  (or holder population) a verifier is checking.
- Automatically rotate the "current" writable list as it fills, and
  garbage-collect list objects once every credential referencing them has
  expired.
- Offer issuers a minimal API: `POST` with just the credential's expiration,
  get back `{list_url, index}`.
- Store as little as possible per index — just a status value, default
  `VALID`.
- Make published lists efficiently cacheable by verifiers, with a cheap way
  to detect when a list has actually changed.

## 2. Fit with the spec

The Token Status List draft already anticipates this deployment model: a
Status List Token's `iss` does not have to match the credential issuer, and a
Referenced Token only carries `status.status_list = {idx, uri}`. Outsourced
status-list-as-a-service is a designed-for case, not a workaround.

The draft also defines a **Status List Aggregation** endpoint (an issuer
publishes the set of list URIs it uses). We should reuse that instead of
inventing a bespoke manifest for "what changed."

Spec facts that drive the design below:

- Per-entry status is 1/2/4/8 bits (`bits` param); values `0x00 VALID`,
  `0x01 INVALID`, `0x02 SUSPENDED`, `0x0B–0x0F` application-specific.
- `lst` = bit-packed array, entry 0 in the LSB of byte 0, DEFLATE-compressed,
  base64url-encoded.
- Status List Token (JWT `application/statuslist+jwt` or CWT) carries `sub`
  (the list URI), `iat`, optional `exp`, and `ttl` — an explicit "don't cache
  longer than this" hint, layered on top of ordinary HTTP caching.

## 3. Components

```
Issuer ──POST /allocate──▶  Allocation Service ──▶ Metadata store (Postgres)
                                   │                    (list_id, state, cursor,
                                   │                     bits, N, max_exp, fpe_key)
Issuer ──PATCH /status───▶  Update Service ──────▶ Bitmap store (Redis/KeyDB)
                                                        SETBIT / BITFIELD
                                                             │
                                                    Publisher (debounced)
                                                             │
                                              DEFLATE + sign → StatusListToken
                                                             │
                                                    CDN / object storage
                                                             │
Verifier ──GET /lists/{id}──(conditional GET, ETag)──▶ CDN ──▶ Bucket
                                                             │
                                              GC sweeper (checks max_exp)
```

Read traffic (verifiers) dominates by orders of magnitude over write traffic
(issuers, ~1 POST per credential). Split them: writes go through an
authenticated API in front of the fast bitmap store; reads are anonymous,
cacheable, and should never touch the write path — they hit a CDN in front
of periodically-republished tokens.

## 4. Data model

Per list, store only:

| field | purpose |
|---|---|
| `list_id` | opaque, **randomly generated** (a sequential list_id leaks issuance volume/rate the same way sequential indices would) |
| `bits` | 1/2/4/8, per spec |
| `size` (N) | capacity |
| `cursor` | next unallocated position, 0..N |
| `fpe_key` | per-list secret used to derive indices (§5) |
| `max_exp` | max of all `exp` values ever handed out from this list |
| `state` | `ACTIVE` / `FROZEN` / `ARCHIVED` |
| `version` | monotonic counter, bumped on every status write |

**No per-index expiry table is needed.** "Lists expire when all their
credentials expire" is satisfiable with a single scalar per list (`max_exp`),
not a per-credential expiry index. That's the key efficiency property:
allocation and GC both stay O(1) / O(lists), never O(credentials).

Per index: just the status value packed into a bitmap — nothing else. An
issuer may keep its own credential records for audit purposes, but that's
outside this service's responsibility.

## 5. Random index allocation without an O(N) structure

Two options, in preference order.

**A. Keyed format-preserving permutation (recommended).** For a list of size
N, derive `index = FPE(cursor, fpe_key)` using a small Feistel network over
`⌈log2 N⌉` bits with cycle-walking to fold results back into `[0, N)`.
Increment `cursor` on each allocation.

- O(1) time, O(1) space per list (just the key + a counter) — no permutation
  array, no "allocated" bitmap needed.
- Bijective ⇒ zero collisions, deterministic, trivially resumable/idempotent.
- Indistinguishable from random to anyone without `fpe_key`, which is the
  actual goal (unlinkability of issuance order), without the storage cost of
  a real shuffle.

**B. Inside-out Fisher-Yates draw array.** Keep `avail[0..N)`, swap-and-pop a
random remaining slot per allocation. O(1) amortized time but O(N) memory
*while the list is ACTIVE* (droppable once FROZEN). Simpler to reason about
if we'd rather not own a Feistel implementation; costs real memory for large
N.

Recommendation: build A for the prototype — it's the more efficient answer
and isn't much harder to implement correctly than B.

## 6. Status storage

Use `bits=2` by default (VALID/INVALID/SUSPENDED fit in 2 bits, matching the
spec's default semantics).

**Correction from the prototype build (2026-09-23):** this section originally
called for Redis's `BITFIELD` field-addressing (`BITFIELD key SET u2 #idx
value`) directly. That turned out not to be spec-conformant: Redis's own
SETBIT/BITFIELD bit numbering is MSB-first (offset 0 = most significant bit
of byte 0), while draft-ietf-oauth-status-list-21 §4.1 packs entries
LSB-first (index 0 in the least significant bit(s) of byte 0) — verified
against the draft's own worked hex examples. Using `#idx` addressing as
originally written would have silently produced a byte layout that doesn't
match what a verifier decoding `lst` expects.

The actual implementation (`internal/store/redis.go`) instead runs a small
Lua script that does an atomic whole-**byte** read-modify-write
(`GETRANGE`/`SETRANGE`), computing the LSB-first bit math itself rather than
relying on Redis's bit-numbering convention at all. Because every allowed
bit width (1, 2, 4, 8) divides 8 evenly, a field never spans a byte
boundary, so byte-level granularity is sufficient — this is still a single
atomic round trip per write, just not via `BITFIELD`'s automatic field
arithmetic.

Postgres `bytea` + `get_byte`/`set_byte` is a viable fallback for
lower-scale deployments that would rather not run a second stateful system,
at the cost of doing the bit math ourselves and coarser locking (byte-level
read-modify-write under concurrent writers to the same list).

The durable copy of each bitmap (for rebuild/audit) lives in Postgres or
object storage; Redis is the fast path, not the source of truth, if we need
durability guarantees stronger than AOF/RDB gives us.

## 7. List lifecycle

1. **Create**: no ACTIVE list, or the ACTIVE list's `cursor == N` → generate
   a random `list_id`, `fpe_key`, choose `bits`/`N`, state=ACTIVE. Rotation
   from full-to-new must be a single atomic swap (`SELECT ... FOR UPDATE` or
   compare-and-swap on a "current active list per pool" pointer) so
   concurrent allocators don't race-create two new lists.
2. **Allocate** (issuer `POST`, only `exp` needed): pick an ACTIVE list from
   the pool (§8), rotating/creating first if needed, derive an index via §5,
   `max_exp = max(max_exp, exp)`, return `{list_url, index}`. No bitmap
   write happens here — new entries default to VALID via the bitmap's
   zero-initialization, so allocation is metadata-only.
3. **Frozen**: once full or past its rotation window (§8.2), a list stops
   issuing new indices but keeps accepting status updates for its lifetime —
   a credential can be revoked any time up to its own expiry.
4. **Expire/GC**: a background sweeper scans FROZEN lists where
   `now > max_exp + grace_period` → ARCHIVED: stop accepting writes, keep
   serving the last-published (all-quiet) token for a retention window so
   late verifiers don't hit a dead link, then drop the bitmap from hot
   storage and respond **410 Gone** on the list URL from then on (decided —
   see §13). A short retention window (e.g. 30–90 days past the grace
   period) before the 410 kicks in is a reasonable default.

## 8. Issuer distribution across the list pool

The privacy goal isn't only about the index inside a list (§5) — it's also
about what the *choice of list* reveals. If a list were effectively
dedicated to one issuer (or a handful of low-volume issuers), an operator
watching verifier `GET`s would learn "this verifier just checked something
from issuer X" without ever looking inside the list — the mere fact of
fetching that URL is the leak. The service already knows the
issuer→list→index mapping from the `POST /allocate` call (that's
unavoidable, the same way a CA knows who it issued a certificate to); the
design goal is to keep that stored mapping from being *exploitable* by
anyone observing traffic to the published list, including the operator
itself.

### 8.1 Issuer-blind, load-balanced placement

Maintain a **pool of K concurrently ACTIVE lists** rather than a single
current list or one list per issuer. On each `POST /allocate`:

1. Pick two lists at random from the K currently ACTIVE lists in the
   relevant pool ("power of two choices").
2. Allocate into whichever of the two has more remaining capacity.
3. Derive the index within that list via the keyed FPE allocator (§5).

This is deliberately **issuer-blind**: the selection function takes no
issuer identity as input, only the current fill state of a couple of
randomly-sampled lists. That's what gives the mixing property — over time,
every list's membership is an unbiased sample of *all* recent issuance
traffic, not a function of which issuer happened to call the API.
Power-of-two-choices gives near-perfectly balanced fill across the pool with
O(1) work and no global lock or counter, which also keeps this compatible
with the sharded deployment in §12.

### 8.2 Administrative rotation controls

Expose two tiers of control — low-level for engineers, a target-based one
for the rest of the org:

- **Low-level knobs**: `N_max` (capacity per list), `T_max` (max time a
  list stays ACTIVE regardless of fill), `K` (pool width — number of
  concurrently ACTIVE lists). A list rotates out of ACTIVE (§7) on whichever
  of `N_max`/`T_max` is hit first.
- **`min_fill_before_time_rotate`**: don't let a quiet period rotate out a
  near-empty list purely on the `T_max` timer — a list with only a handful
  of members is itself a small-anonymity-set artifact. Extend the window
  (up to some hard ceiling) instead, until it has at least this many
  entries, or accept the small list only past the ceiling.
- **Target-based knob (recommended default surface)**: let an admin set a
  *target minimum anonymity set* and a *max rotation interval* instead of
  raw `N`. The service observes measured issuance throughput per pool and
  derives `N_max`/`K` to hit that target — this is the control an admin
  actually cares about ("lists should mix at least 10,000 credentials
  before rotating, and never stay open longer than 7 days"), without
  needing to know or track issuance volume by hand.

`N_max`↑ and `T_max`↑ are the same knob wearing two hats — both mean "let a
list accumulate more members before closing it," trading turnover speed for
anonymity-set size against fetch/GC cost (§13).

**Decided for the prototype (§13):** ship the low-level knobs only
(`N_max`/`T_max`/`K`, admin-configured directly). The target-based
auto-tune knob is worth keeping as the eventual admin-facing surface, but it
needs real throughput data to derive sane `N_max`/`K` from — defer it until
after the raw-knob version has run against actual issuance volume.

### 8.3 Expiry-bucketed pools

A list's *live* anonymity set — the number of still-unexpired credentials
sharing it — shrinks over the list's tail life as most of its members
expire, even though the bitmap itself never shrinks. A single long-lived
outlier credential (e.g. a 10-year credential mixed into a pool otherwise
full of 1-day credentials) drags out both the GC horizon (§7, `max_exp`) and
the point at which the list's *effective* anonymity set has collapsed to
almost nothing, long before the object is actually archived.

Mitigate by bucketing the allocation pools by requested `exp` horizon (e.g.
a small, configurable set of buckets like "≤1 day", "≤30 days", "≤1 year",
"other") and running the §8.1 distribution independently per bucket. This
keeps the credentials sharing a list roughly co-expiring, which:

- Keeps the anonymity set closer to its nominal size for most of the list's
  life, instead of decaying badly near the tail.
- Bounds GC lag from a single outlier `exp` to just its own bucket, instead
  of blocking reclamation of an otherwise fully-expired list.

This does mean `K` and the rotation knobs in §8.2 are set *per bucket*,
since each bucket sees different issuance volume and different natural
lifetimes.

## 9. Change detection / verifier caching

- **`version`**: increment on every write to a list (Redis `INCR` alongside
  the `BITFIELD SET`, in the same pipeline).
- Publishing is **decoupled from writes**: a debounced publisher job
  snapshots the bitmap, DEFLATE-compresses `lst`, signs a fresh
  StatusListToken, and pushes it to the CDN, at most every `ttl` seconds (or
  immediately if idle). This bounds resign/compress cost under bursty
  revocation traffic instead of doing it per write.
- Set `ETag = version` (or a hash of the compressed `lst`) and
  `Last-Modified`; support conditional `GET` → `304` for verifiers/CDN. This
  sits on top of the spec's own `ttl` claim, not instead of it — `ttl` tells
  the verifier the *policy* staleness bound; ETag/conditional-GET makes
  re-checks cheap.
- Use the spec's **Status List Aggregation** endpoint per issuer/pool so a
  verifier that cares about many lists can poll one small endpoint for
  "what changed" instead of polling every list individually.
- Because most entries stay VALID, DEFLATE compression ratios are large in
  the common case — a list with N=1,000,000 and `bits=2` is 250 KB raw but
  typically compresses to a small fraction of that when revocations are
  sparse, keeping CDN payloads and bandwidth low.
- **`ttl` is configurable per issuer/credential type (decided — see §13)**,
  with a conservative fallback (~1 hour) for issuers who don't set one.
  Letting high-value/high-risk credential types opt into a shorter `ttl`
  (more verifier traffic, faster revocation visibility) without forcing
  that cost onto every issuer is worth the extra config surface.
- Note the two rotation-like concepts stay independent: **list rotation**
  (§8.2 — when a new list starts accepting allocations) governs anonymity
  set size, while **`ttl`/republish frequency** here governs how fresh a
  given list's *content* looks to verifiers. Conflating them would tie
  privacy tuning to cache tuning for no reason.

## 10. Storage backend options

| Option | Fit |
|---|---|
| Redis/KeyDB (bitmaps) + Postgres (metadata) + object storage/CDN (published tokens) | Recommended. Native bit ops, cheap horizontal sharding by `list_id` hash, clean separation of hot-write vs. cold-read paths. |
| Postgres only (`bytea` + byte functions) | Simpler ops footprint for lower-scale deployments; loses native bitfield ops and needs app-level bit math plus care around concurrent RMW on the same row. |
| Cloud KV (DynamoDB, etc.) | Serverless-friendly, but no native bitwise primitive — bit-packing plus optimistic/conditional writes would need to be implemented ourselves. More app complexity for the same result. |

## 11. Scaling

- Verifier reads are anonymous and heavily cacheable — put a CDN in front of
  them; this is where a large number of lists actually costs money, and CDN
  caching neutralizes it almost entirely given `ttl`-bounded staleness is
  acceptable.
- Issuer writes are low-QPS relative to reads (one allocation per credential
  issued, occasional status flips) — a normal authenticated API tier in
  front of Redis handles this without special scaling work.
- Shard the bitmap store by `list_id` hash across a Redis cluster; lists are
  independent of each other by construction (no cross-list transactions, no
  shared counters beyond each list's own `cursor`/`max_exp`), so this is
  embarrassingly parallel — the same property that makes a single-node
  prototype trivial to build is what makes it safe to shard later without a
  redesign. The pool-based allocation in §8 is likewise per-pool state, so
  each pool can live on its own shard(s) without coordinating with others.
- For origin (CDN cache-miss) traffic at scale, route by `hash(list_id)` to
  the owning shard via a small shard-map lookup in the metadata store (not
  a fixed `mod N`, so shards can be added without a full rehash — use
  consistent hashing or an explicit shard-assignment table updated by a
  rebalancing job).

## 12. Deployment path: Fly prototype → sharded fleet

Two deployment targets are in scope, and the architecture above is meant to
support both without a rewrite in between:

**Phase 1 — quick deploy on Fly.** A single Fly app is enough for a
prototype and for early production traffic:

- One Fly app running the API (allocate/update/read) as stateless Fly
  Machines, autoscaled/autostopped the way `sirosid-dev` already does for
  other services (`fly-up`/`fly-down ENV=<name>` pattern).
- One Fly Redis (or Upstash) instance for the bitmap store, one Fly Postgres
  for metadata, tokens published to Fly's built-in edge cache or a thin
  Cloudflare/Fastly layer in front of the app for verifier `GET`s.
- Single region is fine to start; this validates the allocator, the
  publisher, and the API contract cheaply, and is the natural target for
  the prototype scope in §14.

**Phase 2 — scaling to thousands of status lists.** Nothing in the data
model requires a different architecture, only more of the same shape,
because lists don't interact with each other:

- Split the bitmap store into a **Redis cluster of shards**, each owning a
  disjoint hash range of `list_id`s; the metadata store's shard-assignment
  table is the only piece of state that needs to be globally consistent,
  and it changes rarely (on shard add/rebalance, not per request).
- Run multiple stateless API instances per region behind Fly's regional
  load balancing (or move the app tier to a small Kubernetes/Nomad fleet if
  Fly Machines autoscaling stops being the right fit at that volume) — the
  API layer itself has no local state, so it scales by adding instances.
- Verifier reads should mostly never reach the origin fleet at all: with
  thousands of lists each fronted by CDN caching on `ETag`/`ttl`, only
  cache-misses and the periodic republish-triggered purges hit Redis. This
  is the main lever for "very large deployment" — the origin fleet is sized
  for issuer writes plus cache-miss reads, not for total verifier traffic.
- Publisher jobs (§9) shard the same way as the bitmap store — one
  worker pool per Redis shard (or a queue-based fan-out keyed by
  `list_id`), so republish throughput scales with shard count instead of
  being a single bottleneck.
- Fly's own Redis/Postgres offerings are convenient for Phase 1 but are
  single-region-oriented; plan to swap the backing stores for a
  purpose-built managed Redis Cluster (e.g. self-hosted Redis Cluster,
  Elasticache, or Upstash's multi-region tier) once sharding is actually
  needed, while keeping the API tier and its interfaces unchanged — the
  storage backend is intentionally abstracted behind the allocator/status
  APIs (§10) for exactly this reason.
- GC sweepers (§7) and the shard-assignment rebalancer are the two pieces
  of genuinely global coordination in the system; keep both as separate,
  infrequent background jobs rather than folding them into the request
  path, so they don't become a scaling constraint on allocation or status
  updates.

## 13. Open questions / trade-offs

- **List size / rotation speed vs. herd privacy vs. fetch efficiency**:
  bigger lists (or a slower rotation, §8.2) mean a bigger anonymity set per
  list — the actual privacy goal — but a larger object to fetch and a
  longer tail before a single outlier `exp` allows GC (§8.3). The steady-
  state fetch cost is mostly absorbed by CDN caching and `ttl` (§9), so the
  real cost of a larger `N` is first-fetch bandwidth/parse time and CDN
  egress on cache misses, not ongoing per-request cost — which argues for
  erring toward larger anonymity sets over minimizing `N` for its own sake,
  and tuning `T_max`/`K` (§8.2) to bound worst-case object size instead.
- **Shared vs. per-issuer list pools**: resolved in favor of shared,
  issuer-blind pools (§8) for the privacy reasons above. The consequence is
  that an index-update request must be checked against index ownership, not
  just "does this issuer own any list at all" — needs an authorization
  check per index, not just per list.
- **Update authorization — decided**: `{list_url, index}` is not inherently
  secret, so updates go through the ordinary authenticated-issuer API with a
  server-side ownership lookup per index (one extra read per status write).
  Simpler than an opaque capability token, and avoids issuers having to
  manage a second secret alongside their normal API credentials.
- **`ttl` vs. revocation latency — decided**: configurable per
  issuer/credential type rather than a single global default, with a
  conservative fallback (~1 hour) for issuers who don't set one (§9). A
  push-invalidation channel (webhook, or a "recently changed" feed) is
  still a natural v2 for latency-sensitive relying parties who need faster
  than any polling `ttl` can offer, layered on top rather than replacing
  the polling model.
- **FPE key custody**: the unlinkability guarantee depends on `fpe_key`
  staying server-side; treat it like any other signing-adjacent secret
  (KMS-backed, rotated with the list, never logged).
- **Residual allocation-time correlation**: the operator inherently learns
  issuer→list→index at `POST /allocate` time. An observer who could also
  watch verifier `GET` timing might weakly correlate "issuer X allocated
  around time t" with "list L was fetched shortly after t" even with §8's
  mixing. Standard mitigations (delaying a newly-opened list's first
  publish, never exposing per-list fill counts or creation timestamps to
  verifiers) reduce this but don't eliminate it — flagged as a residual
  risk for v1, not solved by the distribution algorithm alone.
- **Dead-link policy on archive — decided**: 410 Gone once the retention
  window (§7) passes, rather than serving a frozen artifact indefinitely.
  Predictable storage reclamation won out over never showing a dead link;
  worth revisiting if a specific compliance/audit requirement surfaces that
  needs longer availability.

## 14. Suggested prototype scope

To validate the core claims cheaply before building the full service:

1. Implement the keyed FPE index allocator (§5A) standalone and verify O(1)
   allocation time and bijectivity across a range of N.
2. Implement the Redis `BITFIELD`-backed status store and the debounced
   publisher (§6, §9), producing a spec-conformant StatusListToken.
3. Wire up the minimal issuer API (`POST /allocate`, `PATCH /status` with
   server-side ownership-lookup authorization per §13) and a verifier-facing
   `GET` with conditional-request support and a per-issuer/type-configurable
   `ttl` (fallback ~1 hour).
4. Skip list rotation/GC (§7), the pool-based distribution algorithm and
   expiry bucketing (§8), for the first pass — confirm the allocator and
   publisher work end-to-end on a single ACTIVE list before adding
   lifecycle/pool management. (Rotation done in item 7 below; GC done in
   item 8.)
5. Ship it as a single Fly app (Phase 1 of §12) — this is enough to
   demonstrate the API contract and the caching behavior to the team without
   committing to any sharding infrastructure up front.
6. Keep the shard-map lookup (§11) as an interface from day one, even if
   Phase 1 only ever has one shard — it costs little to add now and avoids
   an API-layer rewrite when Phase 2 (§12) becomes necessary.
7. **Done (2026-09-23).** Power-of-two-choices pool selection (§8.1) behind
   a `K`-list pool, plus real rotation on both fullness (N_max, enforced
   atomically in the same `UPDATE` that fills a list's last slot) and age
   (T_max, enforced by `internal/pool`'s background loop per §8.2's
   raw-knob decision). Validated both with a synthetic multi-issuer load
   test (`internal/pool/pool_test.go`: fill balances within 10% across the
   pool, and no single issuer's share of any one list exceeds 3x the
   expected average — directly checking the §8.1 mixing property, not just
   load balancing) and live against real Redis/Postgres (age-based freeze,
   fill-triggered freeze, and pool top-up all observed firing correctly).
   Expiry bucketing (§8.3) and the target-based rotation knob (§8.2) remain
   deferred — see the repo's README "Known gaps."
8. **Done (2026-09-23).** The GC/archival sweeper (§7 point 4): a
   background job (`internal/gc`) transitions FROZEN lists to ARCHIVED
   once `now > max_exp + grace_period`, then drops a list's Redis bitmap
   once `now > archived_at + retention_period` — matching the decided
   410-after-retention policy from §13. Archived lists reject further
   status updates (there's nothing left to revoke once every credential
   has expired) but keep serving their last-published token for the
   full retention window, so a late verifier never sees a sudden dead
   link. Validated live: allocated an already-expired credential into a
   capacity-1 list (auto-freezing it immediately), watched it archive on
   the next GC tick, confirmed it still served `200` mid-retention-window
   and rejected a revoke attempt with `410`, then confirmed the bitmap
   was purged and the list itself started returning `410` once the
   window passed. Deferred: actually deleting the Postgres row itself
   (only the Redis bitmap is dropped; the row stays so 410 semantics and
   audit history remain available indefinitely) — revisit only if that
   metadata's own storage cost becomes worth reclaiming.
9. **Done (2026-09-23).** §9's debounced publisher, taken literally:
   `internal/publisher`'s `MarkDirty` is called right after a status
   write succeeds and publishes immediately if the list is idle (no
   publish within its own `ttl` window yet), or coalesces a burst of
   writes into a single deferred publish timed for exactly when that
   window reopens — via `leadingDebouncer` (`debounce.go`), a small
   pure/clock-injectable primitive kept separate from the store and
   signing dependencies specifically so its coalescing logic could be
   unit-tested deterministically (no real sleeps, no flakiness) rather
   than only exercised live. The periodic poll (`Run`) stays as a
   backstop rather than being removed, in case a restart loses
   `MarkDirty`'s in-memory debounce state mid-window. Validated live
   against real Redis/Postgres: a single idle write updated the served
   ETag in ~10ms despite a 60s poll interval configured (proving
   `MarkDirty`'s immediate path, not the backstop, did it), and a burst
   of 6 writes to one list produced exactly 2 rebuilds — one immediate,
   one coalesced — confirmed via a temporary rebuild log line rather than
   by polling `GET` (which has its own independent rebuild-if-stale check
   on every read and would have masked the coalescing behavior).

## 15. Multi-service architecture: AS, sharded ingestion, verifier tier, ingress routing

The single-binary prototype (§14) proved the core mechanics. This section
covers the next phase, requested directly: split issuer-facing and
verifier-facing traffic into separate services, add real (non-static-token)
issuer authentication backed by trust evaluation, meter per-issuer usage,
and shard the write path across a farm of ingestion nodes with JWT-based
ingress routing.

### 15.1 Why split now

§3 already argued reads and writes should never share a request path
because verifier traffic dominates by orders of magnitude. The
single-binary prototype didn't *violate* that (writes and reads still hit
different handlers, and reads never touch Postgres for writes), but it did
mean both traffic classes shared fate: one process, one deploy, one blast
radius. Splitting into `cmd/ingestion-service` (issuer-facing:
`POST /allocate`, `PATCH /status`) and `cmd/verifier-service`
(`GET /lists/{id}` only) makes that separation operational, not just
architectural — they scale, deploy, and fail independently, and only the
ingestion side needs to be shard-aware for writes.

### 15.2 Authorization Server: issuer authentication via signing-key possession

Replaces the prototype's static bearer-token map (§14, README "Known
gaps") with a real grant: an issuer proves possession of their own signing
key, the AS evaluates whether that key is trusted, and — if so — mints a
short-lived access token the issuer then presents to the ingestion tier.

**Grant shape (client-assertion, RFC 7523-flavored):** the issuer POSTs a
self-signed JWT to the AS's token endpoint (`iss`=`sub`=their claimed
issuer ID, `aud`=the AS's token endpoint URL, short `exp`, and either an
embedded `jwk` header param or an `x5c` chain proving the signature can be
checked without a prior registration step). The AS verifies the signature
against the key material the assertion itself carries — this is a proof of
possession, not yet a trust decision.

**Trust decision:** the AS then asks a `TrustEvaluator` whether that
specific name-to-key binding is trusted for the issuer role. Two
implementations, selected by whether `TRUST_PDP_URL` is configured
(decided 2026-09-24):

- `AllowAllEvaluator` — trusts everything, unconditionally. The default
  when `TRUST_PDP_URL` is unset: **fail open**, so a prototype/dev
  deployment works without standing up a PDP first. Never appropriate
  for production — `cmd/as` logs a warning on startup whenever this is
  selected. An earlier pass of this doc had a Postgres-backed
  `StaticRegistryEvaluator` (pre-registered `issuer_id -> JWK`, admin-
  managed) as the default instead; that was removed as pure duplication
  — go-trust's own PDP already has an equivalent whitelist-registry
  mode, so a second, divergent static allow-list living in this
  service's own database was never buying anything.
- `AuthZENEvaluator` — a real HTTP client speaking the actual AuthZEN wire
  protocol go-trust's PDP exposes (`POST {pdp}/evaluation` with
  `{subject:{type:"key",id}, resource:{type:"jwk"|"x5c",id,key}}`,
  response `{decision: bool, context: {...}}` — verified against
  `go-trust/pkg/authzen`'s actual JSON tags). **This deliberately does not
  import go-trust as a Go module dependency**: `go-trust`'s `go.mod`
  requires `go 1.27`, one major toolchain step ahead of this org's current
  1.26.6 pin (Dockerfiles, CI, every other repo) — importing it forces an
  automatic `go 1.26.6 → 1.27` bump in *this* module and a wide transitive
  dependency churn (verified empirically: `go get` on `authzenclient`
  did exactly this, reverted). A thin, dependency-free HTTP client
  implementing the same wire protocol gets the same real interoperability
  with a live PDP without that cost — appropriate for a standalone public
  service that shouldn't need to pull in an internal trust-framework
  library just to make one HTTP call. `TrustEvaluator` (the local
  interface both implementations satisfy) mirrors go-trust's own
  `pkg/trustapi.TrustEvaluator` shape for conceptual consistency, so
  swapping evaluators — or later vendoring the real client if the
  toolchain gap closes — is a drop-in, not a rewrite. Once
  `TRUST_PDP_URL` is set, this evaluator **fails closed**: a network
  error, non-200 response, or malformed body all return an error rather
  than a silent trust decision, so a merely-unreachable PDP is never
  indistinguishable from "everything is trusted" — the opposite failure
  mode from `AllowAllEvaluator`'s deliberate fail-open default above.

**`go-tokenauth` for verification, our own AS for issuance:**
`go-tokenauth` already implements exactly the JWKS-fetch-and-validate-
offline pattern §15.3 needs (`jwks.Fetcher` with background refresh,
`validator.Validate` fully offline against the cached key set,
`tokengin.TokenAuth`/`MustHaveTAC` gin middleware) and is the org's
established tool for it. An earlier pass of this doc reasoned that
standing guidance scoped `go-tokenauth` to wallet-infra consumers and
planned a local reimplementation of the same shape instead — the user
overrode that explicitly for this project: **ingestion nodes and the
ingress router import `go-tokenauth`'s `validator`/`jwks`/`tokengin`
packages directly** rather than a hand-rolled lookalike, since re-
verifying against the actual library used elsewhere in the org for this
exact purpose is strictly better than trusting a parallel implementation
to match it. `internal/accesstoken` accordingly narrowed to just the
AS-side issuance half (`KeyManager`: holds the signing key, mints tokens
shaped exactly like `go-tokenauth/claims.AccessTokenClaims`, serves the
JWKS) — verification itself is 100% `go-tokenauth` code, proven by an
integration test that mints with our `KeyManager` and validates with
`go-tokenauth`'s real `validator.Validator`, not a mock.

This deliberately does **not** mean reusing `go-wallet-backend`'s
existing AS instance — that AS's whole design is wallet-instance
authentication (WIA/PoP attestation, DPoP-bound keys), a different
client population and trust model than "a credential-issuing
organization proves possession of a signing key." `siros-status-service`
runs its own small AS (`cmd/as`), which happens to mint tokens in the
same *shape* `go-tokenauth` validates, and stays free of the wallet
AS's unrelated concerns. The claim mapping: this service's "shard"
(§15.5) rides in `go-tokenauth`'s `tenant_id` claim (a reasonable
semantic fit — both name which data partition a caller's traffic
belongs to), and per-route permissions use its `tac` (token access
control) claim: `i` for `POST /allocate` (insert), `w` for
`PATCH /status` (write), `r` for `GET /accounting/me` (read) —
`tokengin.MustHaveTAC` enforces these per route for free, a real
capability upgrade over the flat single-scope token an earlier pass of
this doc had planned.

### 15.3 Offline-verifiable access tokens

The AS signs an access token shaped as `go-tokenauth/claims.
AccessTokenClaims` — `iss` (the AS), `sub` (issuer ID), `aud` (this
service), `exp`/`iat`/`jti`, `tenant_id` (§15.5's shard), and `tac`
(§15.2's per-route permissions) — using `go-jose/go-jose/v4` (the same
library `go-tokenauth` and `go-wallet-backend` build these tokens with,
confirmed against `go-wallet-backend/internal/as/token.go`'s actual
signing code rather than assumed). It's signed with the AS's own key,
published as a JWK Set at `/.well-known/jwks.json`.

Every consumer (ingestion nodes, the ingress router) verifies this token
**fully offline** via `go-tokenauth`'s `validator.Validator`: fetch the
AS's JWKS once, cache it with a background refresh interval, and check
the JWT's signature against the cached key set locally on every request —
no synchronous call back to the AS. This is the literal meaning of "not
depending on authorization" per request: the AS is a dependency for
*minting* a token, never for *checking* one. An AS outage doesn't take
down request-serving; it only blocks new token issuance until it
recovers, and existing tokens keep working until they
expire.

### 15.4 Accounting: per-issuer index-position usage

A new Postgres table, `issuer_usage(issuer_id, shard_id, index_count,
updated_at)`, incremented inside the same transaction as
`ReserveCursorAndRecord` (§7) — accounting can never drift from actual
allocations, because it's the same commit. Exposed read-only via
`GET /accounting/me` on the ingestion service, scoped to the caller's own
`sub` claim from their access token (self-service; no separate admin auth
needed for a number an issuer already has every incentive to track
honestly themselves).

### 15.5 Sharding pools across ingestion farms

A **shard** = one `cmd/ingestion-service` process (or a small replica set
behind a load balancer), each configured with its own `SHARD_ID` and its
own Redis (`REDIS_URL`) for the hot bitmap store, but sharing the same
Postgres for metadata — the write-heavy, latency-sensitive part (bitmap
read-modify-write) is what actually benefits from physical isolation;
list/allocation metadata is comparatively small and fine to keep
centralized for now (matches §10's original recommendation: shard Redis
first).

- `lists.shard_id` (new column, idempotent `ALTER TABLE`) scopes every
  pool query (`ActiveLists`, `LiveLists`, etc.) to one shard — a shard's
  `pool.Manager` only ever sees and rotates its own lists.
- Issuer-to-shard assignment is decided once, at first token issuance, and
  is sticky thereafter (`issuer_shard(issuer_id PRIMARY KEY, shard_id)`,
  round-robin over the AS's configured `SHARDS` list) — an issuer's
  credentials should keep landing in the same shard's pools for their
  whole relationship with the service, not bounce around.
- The verifier tier doesn't shard the same way: `GET /lists/{id}` looks up
  `shard_id` from the (shared) Postgres row, then reads that shard's Redis
  for the bitmap — `cmd/verifier-service` holds a `shard_id -> Redis
  client` map (`SHARD_REDIS_URLS`) rather than being shard-pinned itself.

### 15.6 Ingress routing by JWT claim

`cmd/ingress-router` is a small reverse proxy in front of the ingestion
farm: it verifies the caller's access token the same way any other
consumer does (§15.3, `go-tokenauth`'s validator, fully offline against
the AS's JWKS), reads the `tenant_id` claim (this service's shard), and
forwards the request to that shard's configured backend URL
(`SHARD_BACKENDS`, a static `shard_id -> URL` map). A request with an
invalid/unverifiable token is rejected at the router (401) before it ever
reaches a shard; a valid token naming an unconfigured shard is a 502.
This keeps shard topology out of issuers' hands entirely — they only ever
see one router URL, and the token's `tenant_id` (not anything the issuer
supplies directly) decides where their traffic actually lands.

### 15.7 Updated component picture

```
Issuer ──(self-signed client-assertion JWT)──▶  AS (cmd/as)
                                                   │  verify assertion sig
                                                   │  TrustEvaluator.Evaluate (§15.2)
                                                   │  assign/lookup shard (§15.5)
                                                   ▼
                                  access token (go-tokenauth AccessTokenClaims:
                                          tenant_id=shard, tac=permissions)
                                                   │
Issuer ──(Bearer access token)──▶  cmd/ingress-router ──▶ shard N's cmd/ingestion-service
                                     verifies offline         │  verify offline (same JWKS,
                                     via AS's JWKS             │  go-tokenauth tokengin.TokenAuth)
                                     (§15.3), routes on         │  POST /allocate, PATCH /status
                                     `tenant_id`                 │  accounting increment (§15.4)
                                                                 ▼
                                                        shard N's Redis (bitmap)
                                                        shared Postgres (metadata, shard_id column)

Verifier ──GET /lists/{id}──▶  cmd/verifier-service ──▶ shared Postgres (look up shard_id)
                                (no auth, CDN-fronted)  ──▶ shard N's Redis (via shard_id -> URL map)
```

### 15.8 Prototype scope for this phase

Real, not stubbed: the client-assertion verification (actual signature
check against issuer-presented key material), the fail-open/fail-closed
trust decision (§15.2 — `AllowAllEvaluator` and `AuthZENEvaluator` are
both real, not placeholders; only whether a live PDP exists to point
`AuthZENEvaluator` at is the open item), offline JWT verification via
`go-tokenauth`'s real validator/jwks/tokengin (not a lookalike),
per-route TAC permission enforcement, the accounting table and its
transactional increment, the `shard_id`-scoped pool queries, and the
ingress router's routing logic. Also confirmed live: two
ingestion-service instances sharing one Postgres and starting
concurrently hit a genuine Postgres catalog race applying the same
`CREATE TABLE IF NOT EXISTS` schema at once (`duplicate key value
violates unique constraint pg_type_typname_nsp_index`) — fixed with
`internal/pgutil.ApplySchema`, an advisory lock serializing schema
application across every process sharing a schema, applied everywhere
this service does its own DDL (`internal/store`, `internal/as`).

Deliberately simplified: `AuthZENEvaluator` is real wire-protocol code but
untested against a live go-trust PDP (none is deployed for this service
yet — see §15.2 on why importing go-trust's Go client wasn't the right
move for standing one up quickly either, so until a PDP exists this
service can only run in `AllowAllEvaluator`'s fail-open mode); sharding
is logical/config-driven (multiple processes on one host or a
docker-compose, not physically separate infrastructure); and the AS's
own key is a single static key, not a rotating set.

Explicitly considered and rejected: extending `go-wallet-backend`'s
existing AS with this client-assertion grant, instead of running a
second one (`cmd/as`). Rejected because that AS's whole design targets
wallet-instance authentication (WIA/PoP attestation, DPoP-bound keys) —
a different client population and trust model than "a credential-issuing
organization proves possession of a signing key" — and extending a
shared, already-deployed production AS carries real blast radius for
unrelated consumers plus a deeper investigation of its existing
grant-type dispatch than a small, isolated, purpose-built AS needs.
`go-tokenauth`'s *validator* is still shared (§15.2); only issuance stays
separate.

## 16. Investigated: `cmd/ingress-router` on a platform-native edge runtime

`cmd/ingress-router` (§15.6) is a small, generic component — verify a
Bearer token offline, read one claim, proxy to a backend named by that
claim — that in principle any L7 platform with edge compute could run
instead of a container we operate. Surveyed Fly.io, Fastly, Google Cloud,
and AWS for a platform-native replacement:

- **Fly.io** has no matching primitive at all — `fly-proxy` does TLS
  termination and static host/path routing, no JWT verification, no
  claims-aware routing.
- **Google Cloud**'s Apigee is the one genuine declarative, no-code match
  (`VerifyJWT` + conditional routing on extracted claims), but is a
  heavyweight, expensive, enterprise API-management product — real
  overkill for a service this size. Google API Gateway (the lighter
  ESPv2-based product) validates JWTs natively but only routes on
  path/method, not claim value.
- **AWS** API Gateway HTTP APIs have a native JWT authorizer (JWKS URL +
  issuer + audience, no Lambda needed) for verification, but claim-based
  *routing* isn't declarative — it needs a Lambda authorizer plus either a
  Lambda integration or REST API VTL mapping templates, which is
  architecturally the same router, just moved to a different compute
  substrate.
- **Fastly** has no turnkey feature either, but a real substrate: Compute
  (formerly "Compute@Edge"), their WASM edge runtime, plus Dynamic
  Backends (proxy to an arbitrary, runtime-resolved origin) and a KV
  Store, compose into exactly this router's logic.

Conclusion: only GCP has a true no-code match, and it's disproportionate
for this service. Everywhere else — including Fastly — "platform-native"
really means rewriting the router's ~100 lines onto that platform's edge
runtime, which trades away the one thing `cmd/ingress-router` is
deliberately built for: running identically on any cloud, including Fly
itself, which has nothing native at all. **Decision: keep
`cmd/ingress-router` as the primary, portable implementation.**

Fastly's path was investigated further anyway (real edge PoPs are a
genuine latency argument, if this service ever needs it) and prototyped
as a real, compiling artifact rather than left as a paper conclusion —
see `rust/`, a separate Cargo workspace alongside this Go module:

- **`rust/token-format`** — decodes/validates this service's ES256 access
  tokens (the `go-tokenauth/claims.AccessTokenClaims` shape), tested
  against a real token minted by `internal/accesstoken.KeyManager`
  (`tools/gen-fixture`), not a token the crate constructed itself — the
  same "prove wire compatibility against the real thing" standard §15.3's
  Go-side test already holds. Confirmed compiling and passing all tests
  natively and building clean for `wasm32-wasip1` (Fastly Compute's
  target) with no code changes needed either way.
- **`rust/fastly-ingress-sample`** — a sample Fastly Compute service built
  on `token-format`, reimplementing the router's verify-then-route logic
  using real Fastly Dynamic Backends (routing) and a KV Store (cache-aside
  JWKS — Compute has no persistent memory between requests, so there's no
  analog of `go-tokenauth`'s background-refresh goroutine; a TTL-based
  cache-aside read replaces it). Builds clean to a ~1MB release `.wasm`.
  **Not deployed or CLI-validated** — no `fastly` CLI or account was
  available; see that crate's README for exactly what is and isn't
  proven.

Rust, not Go, for both crates: `go-tokenauth`'s validator is built around
a long-lived process with a background JWKS-refresh goroutine, which
doesn't transfer to Fastly's per-request, no-persistent-memory execution
model regardless of language — the logic has to be rewritten either way,
so staying in Go would buy no real code reuse. Given that, Rust is
Fastly's most mature Compute SDK (their own JWT tutorial is written in
Rust, not Go), and `serde`'s compile-time JSON handling is a better fit
for WASM than Go's reflection-based `encoding/json` — Go on Compute is
officially supported but the newer, less-proven path for this pattern.
