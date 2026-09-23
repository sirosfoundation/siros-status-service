package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
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
	id         text PRIMARY KEY,
	bits       integer NOT NULL,
	size       bigint NOT NULL,
	cursor     bigint NOT NULL DEFAULT 0,
	fpe_key    bytea NOT NULL,
	max_exp    timestamptz,
	state      text NOT NULL DEFAULT 'ACTIVE',
	created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS allocations (
	list_id    text NOT NULL REFERENCES lists(id),
	idx        bigint NOT NULL,
	issuer_id  text NOT NULL,
	exp        timestamptz NOT NULL,
	created_at timestamptz NOT NULL DEFAULT now(),
	PRIMARY KEY (list_id, idx)
);
`

// ListMeta mirrors the per-list metadata fields from docs/design.md §4
// (minus `version`, which lives only in Redis — it is cache-control
// state, not durable structure).
type ListMeta struct {
	ID        string
	Bits      int
	Size      uint64
	Cursor    uint64
	FPEKey    []byte
	MaxExp    *time.Time
	State     string
	CreatedAt time.Time
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
	if _, err := pool.Exec(ctx, schema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: apply schema: %w", err)
	}
	return &MetaStore{pool: pool}, nil
}

func (m *MetaStore) Close() { m.pool.Close() }

// CreateList inserts a new list row in ACTIVE state.
func (m *MetaStore) CreateList(ctx context.Context, id string, bits int, size uint64, fpeKey []byte) (*ListMeta, error) {
	_, err := m.pool.Exec(ctx,
		`INSERT INTO lists (id, bits, size, fpe_key) VALUES ($1, $2, $3, $4)`,
		id, bits, int64(size), fpeKey,
	)
	if err != nil {
		return nil, fmt.Errorf("store: create list: %w", err)
	}
	return &ListMeta{ID: id, Bits: bits, Size: size, FPEKey: fpeKey, State: "ACTIVE"}, nil
}

const listColumns = `id, bits, size, cursor, fpe_key, max_exp, state, created_at`

func scanListMeta(row pgx.Row) (*ListMeta, error) {
	var lm ListMeta
	var size, cursor int64
	if err := row.Scan(&lm.ID, &lm.Bits, &size, &cursor, &lm.FPEKey, &lm.MaxExp, &lm.State, &lm.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	lm.Size, lm.Cursor = uint64(size), uint64(cursor)
	return &lm, nil
}

// ActiveLists returns every list currently in ACTIVE state — the pool
// that internal/pool's power-of-two-choices distribution (§8.1) picks
// from. Ordered oldest-first, which has no correctness significance but
// keeps output deterministic for tests.
func (m *MetaStore) ActiveLists(ctx context.Context) ([]*ListMeta, error) {
	return m.queryLists(ctx, `WHERE state = 'ACTIVE' ORDER BY created_at ASC`)
}

// LiveLists returns every list that still needs publishing: ACTIVE ones
// (still accepting new allocations) and FROZEN ones (no longer accepting
// allocations, but still accepting status updates until GC archives
// them — §7 point 3). ARCHIVED lists are excluded; GC/archival itself is
// not yet implemented (README "Known gaps"), so nothing produces that
// state today.
func (m *MetaStore) LiveLists(ctx context.Context) ([]*ListMeta, error) {
	return m.queryLists(ctx, `WHERE state IN ('ACTIVE', 'FROZEN') ORDER BY created_at ASC`)
}

func (m *MetaStore) queryLists(ctx context.Context, whereOrderBy string) ([]*ListMeta, error) {
	rows, err := m.pool.Query(ctx, `SELECT `+listColumns+` FROM lists `+whereOrderBy)
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

// ReserveCursorAndRecord atomically reserves the next cursor position in
// a list, bumps max_exp, and records issuer ownership of the resulting
// index — the three writes an allocation needs, done as one transaction
// so a crash between them can't leave an orphaned reservation.
func (m *MetaStore) ReserveCursorAndRecord(ctx context.Context, listID string, issuerID string, exp time.Time, deriveIndex func(cursor uint64) (uint64, error)) (index uint64, err error) {
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

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("store: commit allocation: %w", err)
	}
	return idx, nil
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
