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
	"github.com/sirosfoundation/siros-status-service/internal/trust"
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

	cfg, err := config.LoadAS()
	if err != nil {
		return err
	}

	registry, err := trust.NewStaticRegistryEvaluator(ctx, cfg.PostgresDSN)
	if err != nil {
		return err
	}
	defer registry.Close()

	var evaluator trust.Evaluator = registry
	if cfg.TrustPDPURL != "" {
		evaluator = trust.Any{registry, trust.NewAuthZENEvaluator(cfg.TrustPDPURL, cfg.TrustActionName, nil)}
		slog.Info("as: AuthZEN trust evaluation enabled", "pdp_url", cfg.TrustPDPURL)
	}

	shards, err := as.NewShardAssigner(ctx, cfg.PostgresDSN, cfg.Shards)
	if err != nil {
		return err
	}
	defer shards.Close()

	km := accesstoken.NewKeyManager(cfg.SigningKey, cfg.SigningKeyID)
	srv := as.New(cfg, km, evaluator, registry, shards)

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
