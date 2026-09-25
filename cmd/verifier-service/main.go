// Command verifier-service runs the read-only, unauthenticated half of
// the split described in docs/design.md §15.1. A single instance can
// serve lists belonging to any configured shard (§15.5) — it holds one
// Redis client per shard, chosen per-request by the list's own shard_id.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/sirosfoundation/siros-status-service/internal/config"
	"github.com/sirosfoundation/siros-status-service/internal/metrics"
	"github.com/sirosfoundation/siros-status-service/internal/publisher"
	"github.com/sirosfoundation/siros-status-service/internal/store"
	"github.com/sirosfoundation/siros-status-service/internal/verifier"
)

const (
	httpShutdownTimeout = 10 * time.Second
	poolStatsInterval   = 15 * time.Second
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.LoadVerifier()
	if err != nil {
		return err
	}

	bitmapsByShard := make(map[string]*store.BitmapStore, len(cfg.ShardRedisURLs))
	for shardID, url := range cfg.ShardRedisURLs {
		opts, err := redis.ParseURL(url)
		if err != nil {
			return err
		}
		rdb := redis.NewClient(opts)
		if err := rdb.Ping(ctx).Err(); err != nil {
			return err
		}
		defer func() { _ = rdb.Close() }()
		bs := store.NewBitmapStore(rdb)
		bitmapsByShard[shardID] = bs
		go metrics.WatchRedisPool(ctx, poolStatsInterval, shardID, bs.Stat)
	}
	if len(bitmapsByShard) == 0 {
		slog.Warn("verifier-service: no shards configured in SHARD_REDIS_URLS")
	}

	meta, err := store.NewMetaStore(ctx, cfg.PostgresDSN)
	if err != nil {
		return err
	}
	defer meta.Close()
	go metrics.WatchPostgresPool(ctx, poolStatsInterval, meta.Stat)

	pub := publisher.New(bitmapsByShard, meta, cfg.SigningKey, cfg.SigningKeyID, cfg.BaseURL)
	srv := verifier.New(cfg, meta, pub)

	httpSrv := &http.Server{Addr: cfg.HTTPAddr, Handler: srv.Router()}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), httpShutdownTimeout)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	shardIDs := make([]string, 0, len(bitmapsByShard))
	for id := range bitmapsByShard {
		shardIDs = append(shardIDs, id)
	}
	slog.Info("verifier-service listening", "addr", cfg.HTTPAddr, "shards", shardIDs, "base_url", cfg.BaseURL)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
