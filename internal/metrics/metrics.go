// Package metrics is this service's single Prometheus metric taxonomy,
// kept in one file deliberately (unlike this repo's usual per-concern
// package split) so the full set of signals meant for capacity planning
// across deployments is visible in one place, not scattered invisibly
// across a dozen files a reader would have to already know to check.
//
// Every metric here registers on prometheus.DefaultRegisterer via
// promauto, and every binary (cmd/as, cmd/ingestion-service,
// cmd/verifier-service, cmd/ingress-router) exposes it at GET /metrics
// via Handler(). Deployment identity (which app, which shard's process)
// is deliberately NOT a label on any metric here — Prometheus's own
// scrape-time job/instance labels already carry that, and a `cluster`
// label distinguishing one deployment from another belongs on the
// scraper/remote-write side (see fly.metrics.toml's Grafana Alloy
// config), not baked into the application. This keeps every metric name
// here identical across every future deployment, which is the whole
// point of cross-cluster capacity-planning dashboards.
package metrics

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
)

// Handler serves the process's current metrics in Prometheus text
// format. Mount at GET /metrics on every binary.
func Handler() http.Handler {
	return promhttp.Handler()
}

// GinMiddleware records HTTPRequestsTotal/HTTPRequestDuration for every
// request a gin-based service handles. Register before any route so it
// wraps every handler, /metrics itself included (its own request rate is
// a real, if uninteresting, signal — excluding it would need special-
// casing that isn't worth the code).
func GinMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		// c.FullPath() is gin's matched route pattern (e.g.
		// "/status/:listID/:idx"), empty only for a route that matched
		// nothing (a 404) — labeled explicitly so that case stays a
		// single bounded series rather than one per garbage path tried.
		route := c.FullPath()
		if route == "" {
			route = "(no match)"
		}
		HTTPRequestDuration.WithLabelValues(route, c.Request.Method).Observe(time.Since(start).Seconds())
		HTTPRequestsTotal.WithLabelValues(route, c.Request.Method, strconv.Itoa(c.Writer.Status())).Inc()
	}
}

// --- HTTP layer: every gin-based service's request-level throughput,
// latency, and error rate — the base signal for capacity planning
// regardless of what a route does internally. `route` is gin's own
// matched path pattern (e.g. "/status/:listID/:idx"), not the raw URL,
// so cardinality stays bounded regardless of traffic volume.

var (
	HTTPRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "HTTP requests handled, by route/method/status.",
	}, []string{"route", "method", "status"})

	HTTPRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "http_request_duration_seconds",
		Help:    "HTTP request handling latency, by route/method.",
		Buckets: prometheus.DefBuckets,
	}, []string{"route", "method"})
)

// --- cmd/as: token issuance is this service's only business operation.

var (
	// ASTokenIssuanceTotal breaks down /token's outcome beyond the raw
	// HTTP status: e.g. two different 401s (invalid_client vs a
	// malformed request) are different capacity/security signals, not
	// just "an error".
	ASTokenIssuanceTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "as_token_issuance_total",
		Help: "Access token issuance attempts, by outcome (success, invalid_client, invalid_request, unsupported_grant_type).",
	}, []string{"result"})

	// ASShardAssignmentsTotal counts issuer->shard assignment decisions
	// (internal/as/shard.go's AssignOrLookup): `new` distinguishes a
	// brand-new issuer's first assignment from an existing issuer's
	// lookup — the rate of the former is this service's real growth
	// signal, the latter just reflects token-refresh traffic.
	ASShardAssignmentsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "as_shard_assignments_total",
		Help: "Issuer shard assignment lookups, by shard and whether it was a new assignment.",
	}, []string{"shard_id", "new"})
)

// --- cmd/ingestion-service: the write path and its background loops.
// Every metric here that varies per shard carries a shard_id label
// because, unlike route/method, Prometheus's own job/instance labels
// can't distinguish "this ingestion-service process's own shard" from
// anything else — SHARD_ID is this process's own identity, not a
// property of one request.

var (
	IngestionAllocateTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ingestion_allocate_total",
		Help: "POST /allocate outcomes, by shard and result (success, error).",
	}, []string{"shard_id", "result"})

	// IngestionPoolActiveLists and IngestionPoolWidthTarget together give
	// headroom: how close a shard's pool is to needing more lists before
	// pool.Manager's own maintenance loop would create them anyway — the
	// single most direct "is this shard about to need more capacity"
	// signal this service has (docs/design.md §8.1).
	IngestionPoolActiveLists = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ingestion_pool_active_lists",
		Help: "Current count of ACTIVE lists in this shard's pool.",
	}, []string{"shard_id"})
	IngestionPoolWidthTarget = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ingestion_pool_width_target",
		Help: "This shard's configured POOL_WIDTH target.",
	}, []string{"shard_id"})

	IngestionRotationsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ingestion_rotations_total",
		Help: "Lists rotated out of ACTIVE, by shard and reason (age, full).",
	}, []string{"shard_id", "reason"})

	IngestionGCArchivedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ingestion_gc_archived_total",
		Help: "Lists moved FROZEN -> ARCHIVED by internal/gc, by shard.",
	}, []string{"shard_id"})
	IngestionGCPurgedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ingestion_gc_purged_total",
		Help: "List Redis bitmaps purged past retention by internal/gc, by shard.",
	}, []string{"shard_id"})

	IngestionDecoyFlipsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ingestion_decoy_flips_total",
		Help: "Decoy-noise status flips applied by internal/decoy, by shard (docs/design.md §17).",
	}, []string{"shard_id"})
)

// --- internal/publisher: shared by cmd/ingestion-service's periodic
// backstop and cmd/verifier-service's on-read PublishIfStale — a
// cache_hit vs rebuilt breakdown says how often a read actually costs a
// Redis snapshot + JWS sign, which is the real per-read cost driver.

var PublisherRebuildsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "publisher_rebuilds_total",
	Help: "StatusListToken publish attempts, by result (cache_hit, rebuilt).",
}, []string{"result"})

// --- cmd/ingress-router: proxy outcomes by shard, and the specific
// rejection reasons docs/design.md §15.6 and the RFC 6750 challenge
// logic already distinguish — reused here as metric labels rather than
// re-deriving them from response codes downstream.

var (
	IngressProxyTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ingress_proxy_total",
		Help: "Requests handled by ingress-router, by shard and result (proxied, missing_token, invalid_token, expired_token, unknown_shard).",
	}, []string{"shard_id", "result"})

	IngressProxyDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ingress_proxy_duration_seconds",
		Help:    "Round-trip latency of a proxied request, by shard.",
		Buckets: prometheus.DefBuckets,
	}, []string{"shard_id"})
)

// --- Backend saturation: Postgres and Redis connection pool state,
// polled periodically (see UpdatePostgresPoolStats/UpdateRedisPoolStats)
// rather than derived from request events, since pool occupancy is a
// point-in-time property, not something that happens once per request.

var (
	PostgresPoolAcquiredConns = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "postgres_pool_acquired_conns",
		Help: "Currently acquired (in-use) connections in this process's Postgres pool.",
	})
	PostgresPoolIdleConns = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "postgres_pool_idle_conns",
		Help: "Currently idle connections in this process's Postgres pool.",
	})
	PostgresPoolMaxConns = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "postgres_pool_max_conns",
		Help: "Configured maximum size of this process's Postgres pool.",
	})

	// Redis pool gauges carry a shard_id label because cmd/verifier-service
	// is a single process holding one Redis client per shard (unlike
	// Postgres, which is one shared pool per process) — without it,
	// verifier-service's per-shard pools would collide into one series.
	// cmd/ingestion-service (single-shard per process) labels with its own
	// SHARD_ID for consistency, even though its own job/instance scrape
	// label would already distinguish it.
	RedisPoolTotalConns = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "redis_pool_total_conns",
		Help: "Total connections (idle + in-use) in a Redis pool, by shard.",
	}, []string{"shard_id"})
	RedisPoolIdleConns = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "redis_pool_idle_conns",
		Help: "Currently idle connections in a Redis pool, by shard.",
	}, []string{"shard_id"})
	RedisPoolStaleConns = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "redis_pool_stale_conns",
		Help: "Connections closed for being idle too long, cumulative (go-redis PoolStats.StaleConns), by shard.",
	}, []string{"shard_id"})
)

// UpdatePostgresPoolStats sets the Postgres pool gauges from a snapshot
// (internal/store.MetaStore.Stat()). Call periodically (see
// WatchPostgresPool), not per-request.
func UpdatePostgresPoolStats(stat *pgxpool.Stat) {
	PostgresPoolAcquiredConns.Set(float64(stat.AcquiredConns()))
	PostgresPoolIdleConns.Set(float64(stat.IdleConns()))
	PostgresPoolMaxConns.Set(float64(stat.MaxConns()))
}

// UpdateRedisPoolStats sets shardID's Redis pool gauges from a snapshot
// (internal/store.BitmapStore.Stat()). Call periodically (see
// WatchRedisPool), not per-request.
func UpdateRedisPoolStats(shardID string, stat *redis.PoolStats) {
	RedisPoolTotalConns.WithLabelValues(shardID).Set(float64(stat.TotalConns))
	RedisPoolIdleConns.WithLabelValues(shardID).Set(float64(stat.IdleConns))
	RedisPoolStaleConns.WithLabelValues(shardID).Set(float64(stat.StaleConns))
}

// WatchPostgresPool polls stat on interval and updates the Postgres pool
// gauges until ctx is canceled — a small background loop each of
// cmd/as, cmd/ingestion-service, and cmd/verifier-service's main.go
// starts alongside their other periodic loops (pool/gc/decoy/publisher),
// since pool occupancy is a point-in-time property with nothing that
// would otherwise trigger an update.
func WatchPostgresPool(ctx context.Context, interval time.Duration, stat func() *pgxpool.Stat) {
	UpdatePostgresPoolStats(stat())
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			UpdatePostgresPoolStats(stat())
		}
	}
}

// WatchRedisPool is WatchPostgresPool's Redis-pool equivalent, started
// once per shard by cmd/ingestion-service (its own single shard) and
// cmd/verifier-service (once per configured SHARD_REDIS_URLS entry) —
// cmd/as has no Redis dependency.
func WatchRedisPool(ctx context.Context, interval time.Duration, shardID string, stat func() *redis.PoolStats) {
	UpdateRedisPoolStats(shardID, stat())
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			UpdateRedisPoolStats(shardID, stat())
		}
	}
}
