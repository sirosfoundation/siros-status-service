// Package testsupport provides shared test-only infrastructure helpers —
// throwaway Postgres/Redis containers for integration tests that need
// the real thing, not a mock — for use across the module's test files.
// It is a regular (non-_test.go) package so its helpers can be imported
// by tests in other packages (docs/design.md §24).
//
// Same pattern SUNET/vc already uses for its own SQL/Mongo store tests
// (testcontainers-go, skipped gracefully when Docker isn't available,
// no special CI wiring needed since GitHub-hosted runners already have
// Docker preinstalled) — matched deliberately rather than inventing a
// different mechanism for this repo.
package testsupport

import (
	"context"
	"fmt"
	"os/exec"
	"testing"
	"time"

	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

// IsDockerAvailable reports whether a working Docker daemon is reachable.
func IsDockerAvailable() bool {
	dockerPath, err := exec.LookPath("docker")
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, dockerPath, "version").Run() == nil // #nosec G204
}

// StartPostgres spins up a throwaway Postgres container and returns its
// connection string and a cleanup function. Skips the calling test if
// Docker is not available. Deliberately hands back a bare DSN, not an
// already-open pool: every caller in this repo connects via
// store.NewMetaStore or as.NewShardAssigner, both of which apply their
// own schema on connect (internal/pgutil.ApplySchema) — there is no
// separate migration step to run first, unlike a store that expects its
// schema pre-applied.
func StartPostgres(t *testing.T) (dsn string, cleanup func()) {
	t.Helper()
	if !IsDockerAvailable() {
		t.Skip("skipping: Docker is not available")
	}
	ctx := t.Context()

	ctr, err := tcpostgres.Run(ctx, "postgres:16-alpine", tcpostgres.BasicWaitStrategies())
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}

	// context.Background(), not ctx (t.Context()), for teardown: ctx is
	// canceled once the test ends, and the whole point of Terminate is
	// to run reliably during cleanup — registering it against an
	// already-canceled context would make it fail immediately and leak
	// the container.
	cleanup = func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = ctr.Terminate(cleanupCtx)
	}

	connStr, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		cleanup()
		t.Fatalf("postgres connection string: %v", err)
	}
	return connStr, cleanup
}

// StartRedis spins up a throwaway Redis container and returns its
// addr (host:port, matching store.NewBitmapStore's expected
// redis.Options.Addr shape) and a cleanup function. Skips the calling
// test if Docker is not available.
func StartRedis(t *testing.T) (addr string, cleanup func()) {
	t.Helper()
	if !IsDockerAvailable() {
		t.Skip("skipping: Docker is not available")
	}
	ctx := t.Context()

	ctr, err := tcredis.Run(ctx, "redis:7-alpine")
	if err != nil {
		t.Fatalf("start redis container: %v", err)
	}

	cleanup = func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = ctr.Terminate(cleanupCtx)
	}

	host, err := ctr.Host(ctx)
	if err != nil {
		cleanup()
		t.Fatalf("redis host: %v", err)
	}
	port, err := ctr.MappedPort(ctx, "6379/tcp")
	if err != nil {
		cleanup()
		t.Fatalf("redis mapped port: %v", err)
	}
	return fmt.Sprintf("%s:%s", host, port.Port()), cleanup
}
