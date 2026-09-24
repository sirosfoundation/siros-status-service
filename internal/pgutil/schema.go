// Package pgutil holds small Postgres helpers shared across this
// service's stores.
package pgutil

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ApplySchema runs ddl under a Postgres advisory lock keyed by lockKey.
//
// Found live while smoke-testing docs/design.md §15.5's sharding: two
// ingestion-service instances starting at once and both running the same
// `CREATE TABLE IF NOT EXISTS ...` against shared Postgres can hit a real
// catalog-level race ("duplicate key value violates unique constraint
// pg_type_typname_nsp_index") — IF NOT EXISTS doesn't make concurrent DDL
// against the same objects safe. An advisory lock serializes schema
// application across every process that calls this with the same
// lockKey, so only one of them actually runs the DDL at a time; the
// lock+unlock happen on a single dedicated connection (advisory locks
// are session-scoped, so acquiring and releasing on different pooled
// connections would be a no-op release).
func ApplySchema(ctx context.Context, pool *pgxpool.Pool, lockKey, ddl string) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("pgutil: acquire connection: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(hashtext($1))`, lockKey); err != nil {
		return fmt.Errorf("pgutil: acquire advisory lock %q: %w", lockKey, err)
	}
	defer func() {
		_, _ = conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock(hashtext($1))`, lockKey)
	}()

	if _, err := conn.Exec(ctx, ddl); err != nil {
		return fmt.Errorf("pgutil: apply schema: %w", err)
	}
	return nil
}
