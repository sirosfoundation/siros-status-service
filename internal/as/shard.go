package as

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sirosfoundation/siros-status-service/internal/metrics"
	"github.com/sirosfoundation/siros-status-service/internal/pgutil"
)

const shardSchema = `
CREATE TABLE IF NOT EXISTS issuer_shard (
	issuer_id  text PRIMARY KEY,
	shard_id   text NOT NULL,
	created_at timestamptz NOT NULL DEFAULT now()
);
`

// ShardAssigner sticks each issuer to one shard for life (docs/design.md
// §15.5: "an issuer's credentials should keep landing in the same
// shard's pools for their whole relationship with the service").
type ShardAssigner struct {
	pool   *pgxpool.Pool
	shards []string
}

func NewShardAssigner(ctx context.Context, dsn string, shards []string) (*ShardAssigner, error) {
	if len(shards) == 0 {
		return nil, fmt.Errorf("as: at least one shard must be configured")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("as: connect postgres: %w", err)
	}
	if err := pgutil.ApplySchema(ctx, pool, "siros-status-service:as-shard-schema", shardSchema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("as: %w", err)
	}
	return &ShardAssigner{pool: pool, shards: shards}, nil
}

func (a *ShardAssigner) Close() { a.pool.Close() }

// Stat returns this assigner's underlying Postgres connection pool's
// current stats — a point-in-time snapshot for periodic metrics polling
// (see internal/metrics.UpdatePostgresPoolStats), not per-operation.
func (a *ShardAssigner) Stat() *pgxpool.Stat {
	return a.pool.Stat()
}

// AssignOrLookup returns issuerID's shard, assigning one on first call.
// The candidate for a brand-new issuer is a deterministic hash of their
// ID mod the configured shard count — not a shared round-robin counter —
// so concurrent first requests for the same new issuer compute the same
// candidate independently and never race each other for a counter.
func (a *ShardAssigner) AssignOrLookup(ctx context.Context, issuerID string) (string, error) {
	var shardID string
	err := a.pool.QueryRow(ctx, `SELECT shard_id FROM issuer_shard WHERE issuer_id = $1`, issuerID).Scan(&shardID)
	if err == nil {
		metrics.ASShardAssignmentsTotal.WithLabelValues(shardID, "false").Inc()
		return shardID, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("as: lookup shard for %s: %w", issuerID, err)
	}

	candidate := a.shards[hashIndex(issuerID, len(a.shards))]
	_, err = a.pool.Exec(ctx,
		`INSERT INTO issuer_shard (issuer_id, shard_id) VALUES ($1, $2) ON CONFLICT (issuer_id) DO NOTHING`,
		issuerID, candidate,
	)
	if err != nil {
		return "", fmt.Errorf("as: assign shard for %s: %w", issuerID, err)
	}

	// Re-select rather than trusting `candidate`: a genuine race against
	// another request for the same brand-new issuer would compute the
	// same candidate anyway (hashIndex is a pure function of issuerID),
	// but re-selecting is the only way to be certain which row actually
	// won, and costs one cheap indexed lookup.
	if err := a.pool.QueryRow(ctx, `SELECT shard_id FROM issuer_shard WHERE issuer_id = $1`, issuerID).Scan(&shardID); err != nil {
		return "", fmt.Errorf("as: read back assigned shard for %s: %w", issuerID, err)
	}
	metrics.ASShardAssignmentsTotal.WithLabelValues(shardID, "true").Inc()
	return shardID, nil
}

func hashIndex(s string, n int) int {
	sum := sha256.Sum256([]byte(s))
	return int(binary.BigEndian.Uint64(sum[:8]) % uint64(n))
}
