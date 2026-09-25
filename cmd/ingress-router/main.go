// Command ingress-router is the JWT-claim-based routing layer described
// in docs/design.md §15.6, sitting in front of the ingestion farm.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	tokenauthvalidator "github.com/sirosfoundation/go-tokenauth/validator"

	"github.com/sirosfoundation/siros-status-service/internal/config"
	"github.com/sirosfoundation/siros-status-service/internal/ingress"
	"github.com/sirosfoundation/siros-status-service/internal/metrics"
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

	cfg, err := config.LoadIngress()
	if err != nil {
		return err
	}

	validator := tokenauthvalidator.New(tokenauthvalidator.Config{
		JWKSURL:     cfg.ASJWKSURL,
		JWKSRefresh: cfg.JWKSRefreshInterval,
		Issuer:      cfg.AccessTokenIssuer,
		Audiences:   []string{cfg.AccessTokenAudience},
	})
	validator.Start(ctx)

	router, err := ingress.New(validator, cfg.ShardBackends)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.Handle("/metrics", metrics.Handler())
	mux.Handle("/", router)

	httpSrv := &http.Server{Addr: cfg.HTTPAddr, Handler: mux}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), httpShutdownTimeout)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	shards := make([]string, 0, len(cfg.ShardBackends))
	for id := range cfg.ShardBackends {
		shards = append(shards, id)
	}
	slog.Info("ingress-router listening", "addr", cfg.HTTPAddr, "shards", shards)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
