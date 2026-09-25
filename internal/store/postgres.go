package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sirosfoundation/siros-status-service/internal/metrics"
	"github.com/sirosfoundation/siros-status-service/internal/pgutil"
)

// ErrListFull is returned by ReserveCursorAndRecord when the targeted
// list has no remaining capacity (or is no longer ACTIVE) at the moment
// of reservation — e.g. a concurrent allocation filled its last slot
// first. Callers are expected to retry against a different pool member
// (internal/pool does this); it is not a terminal error for the request.
var ErrListFull = errors.New("store: list is full")

// ErrNotOwner is returned when an issuer attempts to update an index it
// did not allocate (docs/design.md §13, "Update authorization — decided":
// server-side ownership lookup per index).
var ErrNotOwner = errors.New("store: caller does not own this index")

const schema = `
CREATE TABLE IF NOT EXISTS lists (
	id          text PRIMARY KEY,
	bits        integer NOT NULL,
	size        bigint NOT NULL,
	cursor      bigint NOT NULL DEFAULT 0,
	fpe_key     bytea NOT NULL,
	max_exp     timestamptz,
	state       text NOT NULL DEFAULT 'ACTIVE',
	created_at  timestamptz NOT NULL DEFAULT now(),
	archived_at timestamptz,
	purged      boolean NOT NULL DEFAULT false,
	shard_id    text NOT NULL DEFAULT 'default'
);

-- Idempotent migrations for tables created before these columns existed
-- (e.g. the live Fly test instance) — CREATE TABLE IF NOT EXISTS above is
-- a no-op against an existing table, so new columns need adding here too.
ALTER TABLE lists ADD COLUMN IF NOT EXISTS archived_at timestamptz;
ALTER TABLE lists ADD COLUMN IF NOT EXISTS purged boolean NOT NULL DEFAULT false;
ALTER TABLE lists ADD COLUMN IF NOT EXISTS shard_id text NOT NULL DEFAULT 'default';
CREATE INDEX IF NOT EXISTS lists_shard_state_idx ON lists (shard_id, state);

CREATE TABLE IF NOT EXISTS allocations (
	list_id    text NOT NULL REFERENCES lists(id),
	idx        bigint NOT NULL,
	issuer_id  text NOT NULL,
	exp        timestamptz NOT NULL,
	created_at timestamptz NOT NULL DEFAULT now(),
	PRIMARY KEY (list_id, idx)
);

-- docs/design.md §15.4: per-issuer index-position accounting, incremented
-- in the same transaction as the allocation it counts (see
-- ReserveCursorAndRecord) so it can never drift from reality.
CREATE TABLE IF NOT EXISTS issuer_usage (
	issuer_id   text NOT NULL,
	shard_id    text NOT NULL,
	index_count bigint NOT NULL DEFAULT 0,
	updated_at  timestamptz NOT NULL DEFAULT now(),
	PRIMARY KEY (issuer_id, shard_id)
);
`

// ListMeta mirrors the per-list metadata fields from docs/design.md §4
// (minus `version`, which lives only in Redis — it is cache-control
// state, not durable structure).
type ListMeta struct {
	ID         string
	Bits       int
	Size       uint64
	Cursor     uint64
	FPEKey     []byte
	MaxExp     *time.Time
	State      string
	CreatedAt  time.Time
	ArchivedAt *time.Time
	// ShardID names which ingestion shard owns this list (docs/design.md
	// §15.5). Defaults to "default" for single-shard deployments.
	ShardID string
	// Purged is true once GC has dropped this list's Redis bitmap (docs/
	// design.md §7 point 4) — internal/decoy checks this before noising
	// an ARCHIVED list, since there's no bitmap left to write to.
	Purged bool
}

// Remaining returns how many unallocated slots this list has left.
func (lm *ListMeta) Remaining() uint64 {
	if lm.Cursor >= lm.Size {
		return 0
	}
	return lm.Size - lm.Cursor
}

// MetaStore is the Postgres-backed store for list and allocation-
// ownership metadata.
type MetaStore struct {
	pool *pgxpool.Pool
}

// NewMetaStore connects to Postgres and applies the (idempotent) schema.
// A prototype-scale service can get away with inline DDL instead of a
// separate migration tool; revisit if/when this grows real migrations.
func NewMetaStore(ctx context.Context, dsn string) (*MetaStore, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("store: connect postgres: %w", err)
	}
	// Advisory-locked: multiple ingestion-service instances (one per
	// shard, docs/design.md §15.5) share this Postgres and may start
	// concurrently, all applying this same schema — see pgutil.ApplySchema
	// for the real race this closes.
	if err := pgutil.ApplySchema(ctx, pool, "siros-status-service:store-schema", schema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: %w", err)
	}
	return &MetaStore{pool: pool}, nil
}

func (m *MetaStore) Close() { m.pool.Close() }

// Stat returns this store's underlying Postgres connection pool's
// current stats — a point-in-time snapshot for periodic metrics polling
// (see internal/metrics.UpdatePostgresPoolStats), not per-operation.
func (m *MetaStore) Stat() *pgxpool.Stat {
	return m.pool.Stat()
}

// CreateList inserts a new list row in ACTIVE state, owned by shardID
// (docs/design.md §15.5; pass "default" for single-shard deployments).
func (m *MetaStore) CreateList(ctx context.Context, id string, bits int, size uint64, fpeKey []byte, shardID string) (*ListMeta, error) {
	_, err := m.pool.Exec(ctx,
		`INSERT INTO lists (id, bits, size, fpe_key, shard_id) VALUES ($1, $2, $3, $4, $5)`,
		id, bits, int64(size), fpeKey, shardID,
	)
	if err != nil {
		return nil, fmt.Errorf("store: create list: %w", err)
	}
	return &ListMeta{ID: id, Bits: bits, Size: size, FPEKey: fpeKey, State: "ACTIVE", ShardID: shardID}, nil
}

const listColumns = `id, bits, size, cursor, fpe_key, max_exp, state, created_at, archived_at, shard_id, purged`

func scanListMeta(row pgx.Row) (*ListMeta, error) {
	var lm ListMeta
	var size, cursor int64
	if err := row.Scan(&lm.ID, &lm.Bits, &size, &cursor, &lm.FPEKey, &lm.MaxExp, &lm.State, &lm.CreatedAt, &lm.ArchivedAt, &lm.ShardID, &lm.Purged); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	lm.Size, lm.Cursor = uint64(size), uint64(cursor)
	return &lm, nil
}

// ActiveLists returns every list currently in ACTIVE state within
// shardID — the pool that internal/pool's power-of-two-choices
// distribution (§8.1) picks from. A shard's pool.Manager only ever sees
// and rotates its own shard's lists (docs/design.md §15.5). Ordered
// oldest-first, which has no correctness significance but keeps output
// deterministic for tests.
func (m *MetaStore) ActiveLists(ctx context.Context, shardID string) ([]*ListMeta, error) {
	return m.queryLists(ctx, `WHERE shard_id = $1 AND state = 'ACTIVE' ORDER BY created_at ASC`, shardID)
}

// LiveLists returns every list in shardID that the periodic publisher
// should keep republishing: ACTIVE ones (still accepting new
// allocations) and FROZEN ones (no longer accepting allocations, but
// still accepting status updates until GC archives them — §7 point 3).
// ARCHIVED lists are excluded deliberately, not because GC doesn't
// exist: once archived, a list accepts no further writes (internal/api
// enforces this), so its version can never change again — there's
// nothing for periodic republishing to do. internal/api's handleGetList
// still serves an ARCHIVED list on direct request (via the same
// PublishIfStale, which is a no-op cache hit after the one rebuild) for
// as long as it's within its retention window.
func (m *MetaStore) LiveLists(ctx context.Context, shardID string) ([]*ListMeta, error) {
	return m.queryLists(ctx, `WHERE shard_id = $1 AND state IN ('ACTIVE', 'FROZEN') ORDER BY created_at ASC`, shardID)
}

// NoiseLists returns every list in shardID that internal/decoy may inject
// camouflage noise into (docs/design.md §17): ACTIVE and FROZEN lists (the
// same population LiveLists returns, for the same reason — they still have
// a live bitmap and unallocated capacity worth disguising) plus ARCHIVED
// lists that GC hasn't purged yet. An ARCHIVED list's cursor is frozen
// (nothing beyond it will ever be allocated, since it no longer accepts
// new issuance), so noising its unallocated tail carries zero risk of ever
// colliding with a real future allocation — unlike ACTIVE/FROZEN, which
// only avoid that collision via the explicit VALID-reset internal/ingestion
// does at allocation time (see its handleAllocate).
func (m *MetaStore) NoiseLists(ctx context.Context, shardID string) ([]*ListMeta, error) {
	return m.queryLists(ctx, `WHERE shard_id = $1 AND state IN ('ACTIVE', 'FROZEN', 'ARCHIVED') AND purged = false ORDER BY created_at ASC`, shardID)
}

func (m *MetaStore) queryLists(ctx context.Context, whereOrderBy string, args ...any) ([]*ListMeta, error) {
	rows, err := m.pool.Query(ctx, `SELECT `+listColumns+` FROM lists `+whereOrderBy, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query lists: %w", err)
	}
	defer rows.Close()

	var out []*ListMeta
	for rows.Next() {
		lm, err := scanListMeta(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scan list: %w", err)
		}
		out = append(out, lm)
	}
	return out, rows.Err()
}

// GetList fetches a list by ID regardless of state.
func (m *MetaStore) GetList(ctx context.Context, id string) (*ListMeta, error) {
	row := m.pool.QueryRow(ctx, `SELECT `+listColumns+` FROM lists WHERE id = $1`, id)
	lm, err := scanListMeta(row)
	if err != nil {
		return nil, fmt.Errorf("store: get list %s: %w", id, err)
	}
	return lm, nil
}

// Freeze transitions a list out of ACTIVE (docs/design.md §8.2:
// rotation on hitting T_max, the age-based knob — the N_max/fullness
// case is handled inline by ReserveCursorAndRecord's UPDATE instead, so
// a list never has to round-trip through an ACTIVE state visible to
// another allocator between filling its last slot and freezing). A
// no-op if the list isn't ACTIVE (e.g. another caller already froze it),
// which callers rely on to make pool maintenance idempotent under races.
func (m *MetaStore) Freeze(ctx context.Context, listID string) error {
	_, err := m.pool.Exec(ctx, `UPDATE lists SET state = 'FROZEN' WHERE id = $1 AND state = 'ACTIVE'`, listID)
	if err != nil {
		return fmt.Errorf("store: freeze list %s: %w", listID, err)
	}
	return nil
}

// FrozenListsPastGrace returns FROZEN lists whose every credential
// expired at least `grace` ago — i.e. `max_exp <= cutoff` where cutoff
// is the caller's now-minus-grace (docs/design.md §7 point 4: "a
// background sweeper scans FROZEN lists where now > max_exp +
// grace_period"). A list with no allocations yet (max_exp IS NULL, only
// possible if it was frozen by age-based rotation before ever being
// used) is treated as immediately eligible — there's nothing to wait
// out.
func (m *MetaStore) FrozenListsPastGrace(ctx context.Context, cutoff time.Time) ([]*ListMeta, error) {
	rows, err := m.pool.Query(ctx,
		`SELECT `+listColumns+` FROM lists
		  WHERE state = 'FROZEN' AND (max_exp IS NULL OR max_exp <= $1)
		  ORDER BY created_at ASC`,
		cutoff,
	)
	if err != nil {
		return nil, fmt.Errorf("store: query frozen lists past grace: %w", err)
	}
	defer rows.Close()
	var out []*ListMeta
	for rows.Next() {
		lm, err := scanListMeta(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scan list: %w", err)
		}
		out = append(out, lm)
	}
	return out, rows.Err()
}

// Archive transitions a FROZEN list to ARCHIVED, recording when. A
// no-op if the list isn't FROZEN, for the same idempotency-under-races
// reason as Freeze. Archiving stops status updates too (docs/design.md
// §13's ownership check happens before this state is consulted, so
// internal/api must reject writes to ARCHIVED lists itself — see
// handleSetStatus).
func (m *MetaStore) Archive(ctx context.Context, listID string) error {
	_, err := m.pool.Exec(ctx,
		`UPDATE lists SET state = 'ARCHIVED', archived_at = now() WHERE id = $1 AND state = 'FROZEN'`,
		listID,
	)
	if err != nil {
		return fmt.Errorf("store: archive list %s: %w", listID, err)
	}
	return nil
}

// ArchivedListsPastRetention returns ARCHIVED, not-yet-purged lists
// whose retention window has elapsed (`archived_at <= cutoff`) — ready
// to have their Redis bitmap dropped (docs/design.md §7 point 4 /
// §13's decided 410 policy).
func (m *MetaStore) ArchivedListsPastRetention(ctx context.Context, cutoff time.Time) ([]*ListMeta, error) {
	rows, err := m.pool.Query(ctx,
		`SELECT `+listColumns+` FROM lists
		  WHERE state = 'ARCHIVED' AND purged = false AND archived_at <= $1
		  ORDER BY created_at ASC`,
		cutoff,
	)
	if err != nil {
		return nil, fmt.Errorf("store: query archived lists past retention: %w", err)
	}
	defer rows.Close()
	var out []*ListMeta
	for rows.Next() {
		lm, err := scanListMeta(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scan list: %w", err)
		}
		out = append(out, lm)
	}
	return out, rows.Err()
}

// MarkPurged records that a list's Redis bitmap has been dropped, so
// later GC sweeps don't keep re-issuing the (harmless but wasteful)
// delete against an already-purged key forever.
func (m *MetaStore) MarkPurged(ctx context.Context, listID string) error {
	_, err := m.pool.Exec(ctx, `UPDATE lists SET purged = true WHERE id = $1`, listID)
	if err != nil {
		return fmt.Errorf("store: mark list %s purged: %w", listID, err)
	}
	return nil
}

// ReserveCursorAndRecord atomically reserves the next cursor position in
// a list, bumps max_exp, records issuer ownership of the resulting
// index, and increments the issuer's accounting counter for shardID
// (docs/design.md §15.4 — in the same transaction as the allocation it
// counts, so it can never drift from reality) — the four writes an
// allocation needs, done as one transaction so a crash between them
// can't leave a partial result.
func (m *MetaStore) ReserveCursorAndRecord(ctx context.Context, listID, issuerID, shardID string, exp time.Time, deriveIndex func(cursor uint64) (uint64, error)) (index uint64, err error) {
	tx, err := m.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("store: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op if committed

	// The state = 'ACTIVE' guard matters once multiple pool members
	// exist (§8): a list picked by internal/pool a moment ago may have
	// since been frozen by an age-based rotation (Freeze) or by another
	// concurrent allocation filling its last slot (the CASE below) —
	// either way this must fail closed as ErrListFull rather than
	// allocating into a list no longer meant to accept new entries.
	var cursor, size int64
	err = tx.QueryRow(ctx,
		`UPDATE lists SET
		   cursor = cursor + 1,
		   state = CASE WHEN cursor + 1 >= size THEN 'FROZEN' ELSE state END
		   WHERE id = $1 AND cursor < size AND state = 'ACTIVE'
		 RETURNING cursor - 1, size`,
		listID,
	).Scan(&cursor, &size)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrListFull
		}
		return 0, fmt.Errorf("store: reserve cursor: %w", err)
	}
	if cursor+1 >= size {
		metrics.IngestionRotationsTotal.WithLabelValues(shardID, "full").Inc()
	}

	idx, err := deriveIndex(uint64(cursor))
	if err != nil {
		return 0, fmt.Errorf("store: derive index for cursor %d: %w", cursor, err)
	}

	if _, err := tx.Exec(ctx,
		`UPDATE lists SET max_exp = GREATEST(max_exp, $2) WHERE id = $1`,
		listID, exp,
	); err != nil {
		return 0, fmt.Errorf("store: bump max_exp: %w", err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO allocations (list_id, idx, issuer_id, exp) VALUES ($1, $2, $3, $4)`,
		listID, int64(idx), issuerID, exp,
	); err != nil {
		return 0, fmt.Errorf("store: record allocation: %w", err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO issuer_usage (issuer_id, shard_id, index_count) VALUES ($1, $2, 1)
		 ON CONFLICT (issuer_id, shard_id) DO UPDATE
		   SET index_count = issuer_usage.index_count + 1, updated_at = now()`,
		issuerID, shardID,
	); err != nil {
		return 0, fmt.Errorf("store: increment issuer usage: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("store: commit allocation: %w", err)
	}
	return idx, nil
}

// IsAllocated reports whether idx within listID has ever been given out
// to a real issuer, regardless of who owns it — internal/decoy's narrow
// pre-write check (docs/design.md §17) that a candidate position hasn't
// been consumed by a real allocation since the sweep read this list's
// cursor.
func (m *MetaStore) IsAllocated(ctx context.Context, listID string, idx uint64) (bool, error) {
	var exists bool
	err := m.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM allocations WHERE list_id = $1 AND idx = $2)`,
		listID, int64(idx),
	).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("store: check allocated: %w", err)
	}
	return exists, nil
}

// CheckOwnership returns nil if issuerID owns idx within listID, and
// ErrNotOwner (or the allocation-not-found variant of it) otherwise.
func (m *MetaStore) CheckOwnership(ctx context.Context, listID string, idx uint64, issuerID string) error {
	var owner string
	err := m.pool.QueryRow(ctx,
		`SELECT issuer_id FROM allocations WHERE list_id = $1 AND idx = $2`,
		listID, int64(idx),
	).Scan(&owner)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: no allocation at list %s index %d", ErrNotOwner, listID, idx)
		}
		return fmt.Errorf("store: check ownership: %w", err)
	}
	if owner != issuerID {
		return ErrNotOwner
	}
	return nil
}

// Usage is one issuer's index-position count within one shard
// (docs/design.md §15.4).
type Usage struct {
	IssuerID   string
	ShardID    string
	IndexCount int64
	UpdatedAt  time.Time
}

// GetUsage returns issuerID's accounting rows, one per shard it has ever
// allocated in.
func (m *MetaStore) GetUsage(ctx context.Context, issuerID string) ([]Usage, error) {
	rows, err := m.pool.Query(ctx,
		`SELECT issuer_id, shard_id, index_count, updated_at FROM issuer_usage WHERE issuer_id = $1 ORDER BY shard_id`,
		issuerID,
	)
	if err != nil {
		return nil, fmt.Errorf("store: query usage for %s: %w", issuerID, err)
	}
	defer rows.Close()

	var out []Usage
	for rows.Next() {
		var u Usage
		if err := rows.Scan(&u.IssuerID, &u.ShardID, &u.IndexCount, &u.UpdatedAt); err != nil {
			return nil, fmt.Errorf("store: scan usage row: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
