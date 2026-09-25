// Command loadtest drives synthetic issuer traffic through a real
// siros-status-service deployment — AS token issuance, then POST
// /allocate, PATCH /status, and GET /accounting/me through
// cmd/ingress-router — and optionally verifies two invariants directly
// against the shard's own Postgres/Redis afterward: docs/design.md
// §8.1's pool-balance mixing, and §17's decoy-noise safety guarantee
// (the reason this tool exists — see that section's "found and closed
// 2026-09-24" note for the bug this same reasoning caught before any
// load test ran).
//
// This drives the issuer-facing write path deliberately, not
// GET /lists/{id}: that read path is meant to sit behind a CDN (Fastly
// or otherwise) in front of cmd/verifier-service, so its load profile is
// a CDN-sizing question, not a question about this service's own code.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

func main() {
	var (
		asURL          = flag.String("as-url", "http://localhost:8090", "cmd/as base URL")
		ingressURL     = flag.String("ingress-url", "http://localhost:8094", "cmd/ingress-router base URL — every timed request goes here")
		numIssuers     = flag.Int("issuers", 50, "number of synthetic issuer identities, each its own goroutine")
		duration       = flag.Duration("duration", 30*time.Second, "how long to generate load after setup completes")
		allocWeight    = flag.Float64("allocate-weight", 80, "relative weight of POST /allocate in the traffic mix")
		statWeight     = flag.Float64("status-weight", 15, "relative weight of PATCH /status in the traffic mix")
		acctWeight     = flag.Float64("accounting-weight", 5, "relative weight of GET /accounting/me in the traffic mix")
		rps            = flag.Float64("rps", 25, "total requests/sec across every issuer, combined — a deliberately conservative default: a real shard's Redis is billed per command (docs/design.md §18), and every op here costs several Redis commands downstream, not one. Raise this deliberately, never by removing the cap.")
		verify         = flag.Bool("verify", false, "after the run, check pool balance and decoy-noise safety directly against postgres/redis")
		postgresDSN    = flag.String("postgres-dsn", "postgres://postgres:postgres@localhost:5432/statuslist?sslmode=disable", "used only with -verify")
		shardRedisURLs = flag.String("shard-redis-urls", `{"default":"redis://localhost:6379"}`, "used only with -verify; JSON object of shard_id -> that shard's own Redis URL, the same shape cmd/verifier-service's own SHARD_REDIS_URLS takes — must cover every shard an issuer could have been assigned to, or verify fails loudly rather than silently skipping that shard's allocations")
	)
	flag.Parse()

	var shardRedis map[string]string
	if err := json.Unmarshal([]byte(*shardRedisURLs), &shardRedis); err != nil {
		log.Fatalf("-shard-redis-urls: %v", err)
	}

	if err := run(runConfig{
		asURL:          *asURL,
		ingressURL:     *ingressURL,
		numIssuers:     *numIssuers,
		duration:       *duration,
		weights:        opWeights{allocate: *allocWeight, status: *statWeight, accounting: *acctWeight},
		rps:            *rps,
		verify:         *verify,
		postgresDSN:    *postgresDSN,
		shardRedisURLs: shardRedis,
	}); err != nil {
		log.Fatal(err)
	}
}

type runConfig struct {
	asURL, ingressURL string
	numIssuers        int
	duration          time.Duration
	weights           opWeights
	rps               float64
	verify            bool
	postgresDSN       string
	shardRedisURLs    map[string]string
}

func run(cfg runConfig) error {
	client := &http.Client{Timeout: 10 * time.Second}

	fmt.Printf("setting up %d issuer identities and fetching tokens from %s ...\n", cfg.numIssuers, cfg.asURL)
	type issuerAndToken struct {
		identity *issuerIdentity
		token    string
	}
	prepared := make([]issuerAndToken, cfg.numIssuers)
	for i := range cfg.numIssuers {
		ii, err := newIssuerIdentity(fmt.Sprintf("loadtest-issuer-%d", i))
		if err != nil {
			return err
		}
		token, err := fetchToken(client, cfg.asURL, ii)
		if err != nil {
			return fmt.Errorf("setup: %w", err)
		}
		prepared[i] = issuerAndToken{identity: ii, token: token}
	}

	fmt.Printf("generating load against %s for %s (mix: allocate=%.0f status=%.0f accounting=%.0f, capped at %.0f req/s total) ...\n",
		cfg.ingressURL, cfg.duration, cfg.weights.allocate, cfg.weights.status, cfg.weights.accounting, cfg.rps)

	// One limiter shared by every worker (not one per worker at rps/N):
	// the cap is meant to bound this run's total real-world cost, which
	// doesn't change with how many issuer goroutines happen to produce it.
	limiter := rate.NewLimiter(rate.Limit(cfg.rps), max(1, int(cfg.rps)))

	results := make([]*workerResult, cfg.numIssuers)
	deadline := time.Now().Add(cfg.duration)
	start := time.Now()

	var wg sync.WaitGroup
	for i := range cfg.numIssuers {
		result := newWorkerResult(prepared[i].identity.id)
		results[i] = result
		wg.Add(1)
		go func(token string, result *workerResult) {
			defer wg.Done()
			runWorker(client, cfg.ingressURL, token, cfg.weights, limiter, deadline, result)
		}(prepared[i].token, result)
	}
	wg.Wait()
	wallClock := time.Since(start)

	printReport(results, wallClock)
	printPoolBalance(results)

	if cfg.verify {
		fmt.Println("\nverifying against postgres/redis directly ...")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := verifyDecoySafety(ctx, cfg.postgresDSN, cfg.shardRedisURLs, results); err != nil {
			return err
		}
	}
	return nil
}
