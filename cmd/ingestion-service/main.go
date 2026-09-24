// Command ingestion-service runs the issuer-facing half of the split
// described in docs/design.md §15.1. One process = one shard (§15.5).
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
	tokenauthvalidator "github.com/sirosfoundation/go-tokenauth/validator"

	"github.com/sirosfoundation/siros-status-service/internal/config"
	"github.com/sirosfoundation/siros-status-service/internal/gc"
	"github.com/sirosfoundation/siros-status-service/internal/ingestion"
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

	cfg, err := config.LoadIngestion()
	if err != nil {
		return err
	}

	redisOpts, err := redisOptions(cfg.RedisURL, cfg.RedisAddr)
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

	// go-tokenauth's own validator + jwks.Fetcher (background-refreshed,
	// fully offline per request) — see docs/design.md §15.2/§15.3 for why
	// this service uses go-tokenauth directly for verification while
	// running its own AS for issuance.
	validator := tokenauthvalidator.New(tokenauthvalidator.Config{
		JWKSURL:     cfg.ASJWKSURL,
		JWKSRefresh: cfg.JWKSRefreshInterval,
		Issuer:      cfg.AccessTokenIssuer,
		Audiences:   []string{cfg.AccessTokenAudience},
	})
	validator.Start(ctx)

	pub := publisher.New(map[string]*store.BitmapStore{cfg.ShardID: bitmaps}, meta, cfg.SigningKey, cfg.SigningKeyID, cfg.BaseURL)
	pm := pool.NewManager(meta, bitmaps, cfg.ShardID, cfg.PoolWidth, cfg.ListCapacity, cfg.ListBits, cfg.RotationMaxAge)
	sweeper := gc.NewSweeper(meta, bitmaps, cfg.GCGracePeriod, cfg.GCRetentionPeriod)

	srv := ingestion.New(cfg, meta, bitmaps, pub, pm, validator)
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

	slog.Info("ingestion-service listening", "addr", cfg.HTTPAddr, "shard", cfg.ShardID, "base_url", cfg.BaseURL)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// redisOptions prefers a full REDIS_URL (redis:// or rediss://) when set,
// since that's the only way to express the password auth and TLS that
// managed offerings like Fly's Upstash-backed Redis require.
func redisOptions(redisURL, redisAddr string) (*redis.Options, error) {
	if redisURL != "" {
		return redis.ParseURL(redisURL)
	}
	return &redis.Options{Addr: redisAddr}, nil
}
