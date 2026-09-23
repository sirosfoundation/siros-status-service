// Command status-list-service runs the prototype status list service
// described in docs/design.md. See docs/design.md §14 for prototype
// scope and README.md for how to run it locally.
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

	"github.com/sirosfoundation/siros-status-service/internal/api"
	"github.com/sirosfoundation/siros-status-service/internal/config"
	"github.com/sirosfoundation/siros-status-service/internal/gc"
	"github.com/sirosfoundation/siros-status-service/internal/pool"
	"github.com/sirosfoundation/siros-status-service/internal/publisher"
	"github.com/sirosfoundation/siros-status-service/internal/store"
)

const httpShutdownTimeout = 10 * time.Second

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}

	redisOpts, err := redisOptions(cfg)
	if err != nil {
		return err
	}
	rdb := redis.NewClient(redisOpts)
	if err := rdb.Ping(ctx).Err(); err != nil {
		return err
	}
	defer func() { _ = rdb.Close() }()
	bitmaps := store.NewBitmapStore(rdb)

	meta, err := store.NewMetaStore(ctx, cfg.PostgresDSN)
	if err != nil {
		return err
	}
	defer meta.Close()

	pub := publisher.New(bitmaps, meta, cfg.SigningKey, cfg.SigningKeyID, cfg.BaseURL)
	pm := pool.NewManager(meta, bitmaps, cfg.PoolWidth, cfg.ListCapacity, cfg.ListBits, cfg.RotationMaxAge)
	sweeper := gc.NewSweeper(meta, bitmaps, cfg.GCGracePeriod, cfg.GCRetentionPeriod)

	srv := api.New(cfg, meta, bitmaps, pub, pm)
	go pub.Run(ctx, cfg.PublishInterval, srv.ListsForPublishing)
	go pm.Run(ctx, cfg.PoolCheckInterval)
	go sweeper.Run(ctx, cfg.GCCheckInterval)

	httpSrv := &http.Server{Addr: cfg.HTTPAddr, Handler: srv.Router()}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), httpShutdownTimeout)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	slog.Info("status-list-service listening", "addr", cfg.HTTPAddr, "base_url", cfg.BaseURL)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// redisOptions prefers a full REDIS_URL (redis:// or rediss://) when set,
// since that's the only way to express the password auth and TLS that
// managed offerings like Fly's Upstash-backed Redis require — a bare
// host:port can't carry either. REDIS_ADDR remains the simple path for
// local/unauthenticated Redis (e.g. docker compose).
func redisOptions(cfg *config.Config) (*redis.Options, error) {
	if cfg.RedisURL != "" {
		return redis.ParseURL(cfg.RedisURL)
	}
	return &redis.Options{Addr: cfg.RedisAddr}, nil
}
