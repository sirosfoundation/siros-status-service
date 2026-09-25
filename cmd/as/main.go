// Command as runs the Authorization Server described in docs/design.md
// §15.2: issuer client-assertion verification, trust evaluation, and
// offline-verifiable access token issuance.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirosfoundation/siros-status-service/internal/accesstoken"
	"github.com/sirosfoundation/siros-status-service/internal/as"
	"github.com/sirosfoundation/siros-status-service/internal/config"
	"github.com/sirosfoundation/siros-status-service/internal/metrics"
	"github.com/sirosfoundation/siros-status-service/internal/trust"
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

	cfg, err := config.LoadAS()
	if err != nil {
		return err
	}

	// Trust source (decided 2026-09-24): a real PDP if configured (fails
	// closed on any error — see AuthZENEvaluator.Evaluate's doc comment),
	// otherwise AllowAllEvaluator (fails open) — never a static registry
	// in this service, since go-trust's own PDP already has an equivalent
	// whitelist-registry mode; duplicating that here would just be a
	// second, divergent source of truth for the same decision.
	var evaluator trust.Evaluator
	if cfg.TrustPDPURL != "" {
		evaluator = trust.NewAuthZENEvaluator(cfg.TrustPDPURL, cfg.TrustActionName, nil)
		slog.Info("as: AuthZEN trust evaluation enabled (fail-closed on PDP errors)", "pdp_url", cfg.TrustPDPURL)
	} else {
		evaluator = trust.AllowAllEvaluator{}
		slog.Warn("as: no TRUST_PDP_URL configured — running fail-open (allow-all); do not use this in production")
	}

	shards, err := as.NewShardAssigner(ctx, cfg.PostgresDSN, cfg.Shards)
	if err != nil {
		return err
	}
	defer shards.Close()
	go metrics.WatchPostgresPool(ctx, poolStatsInterval, shards.Stat)

	km := accesstoken.NewKeyManager(cfg.SigningKey, cfg.SigningKeyID)
	srv := as.New(cfg, km, evaluator, shards)

	httpSrv := &http.Server{Addr: cfg.HTTPAddr, Handler: srv.Router()}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), httpShutdownTimeout)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	slog.Info("as listening", "addr", cfg.HTTPAddr, "base_url", cfg.BaseURL, "shards", cfg.Shards)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
