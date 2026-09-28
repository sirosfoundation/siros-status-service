package gc

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/sirosfoundation/siros-status-service/internal/allocator"
	"github.com/sirosfoundation/siros-status-service/internal/store"
	"github.com/sirosfoundation/siros-status-service/internal/testsupport"
)

// newTestStores spins up real Postgres+Redis containers and returns
// ready-to-use stores plus a cleanup. Every gc test needs both: the
// sweep's three phases touch Postgres (state transitions) and Redis
// (the actual bitmap purge).
func newTestStores(t *testing.T) (*store.MetaStore, *store.BitmapStore) {
	t.Helper()
	pgDSN, pgCleanup := testsupport.StartPostgres(t)
	t.Cleanup(pgCleanup)
	redisAddr, redisCleanup := testsupport.StartRedis(t)
	t.Cleanup(redisCleanup)

	meta, err := store.NewMetaStore(t.Context(), pgDSN)
	if err != nil {
		t.Fatalf("NewMetaStore: %v", err)
	}
	t.Cleanup(meta.Close)

	rdb := redis.NewClient(&redis.Options{Addr: redisAddr})
	t.Cleanup(func() { _ = rdb.Close() })
	if err := rdb.Ping(t.Context()).Err(); err != nil {
		t.Fatalf("ping redis: %v", err)
	}
	bitmaps := store.NewBitmapStore(rdb)

	return meta, bitmaps
}

// createAndFillOneSlotList creates a 1-entry list (so a single
// allocation fills and freezes it immediately — docs/design.md §7's
// N_max fullness transition, no age-based rotation needed to force
// FROZEN) with exp already in the past, so every grace/retention window
// this test uses can be zero and still deterministically match.
func createAndFillOneSlotList(t *testing.T, meta *store.MetaStore, bitmaps *store.BitmapStore, listID string) uint64 {
	t.Helper()
	key, err := allocator.NewKey(rand.Read)
	if err != nil {
		t.Fatalf("allocator.NewKey: %v", err)
	}
	lm, err := meta.CreateList(t.Context(), listID, 2, 1, key, "default")
	if err != nil {
		t.Fatalf("CreateList: %v", err)
	}
	if err := bitmaps.Init(t.Context(), lm.ID, int64((lm.Size*uint64(lm.Bits)+7)/8)); err != nil {
		t.Fatalf("bitmaps.Init: %v", err)
	}

	alloc, err := allocator.New(key, 1)
	if err != nil {
		t.Fatalf("allocator.New: %v", err)
	}
	// exp already in the past: every FrozenListsPastGrace/
	// ArchivedListsPastRetention/PurgedListsPastDBRetention check in this
	// test uses cutoff = now (grace/retention/dbRetention all 0), so this
	// list is eligible for every phase from the moment it's created —
	// no real-time sleeping needed to make a deterministic test.
	exp := time.Now().Add(-time.Hour)
	idx, err := meta.ReserveCursorAndRecord(t.Context(), listID, "test-issuer", "default", exp, alloc.Index)
	if err != nil {
		t.Fatalf("ReserveCursorAndRecord: %v", err)
	}
	return idx
}

func TestSweeper_FullLifecycle_ArchivePurgeDelete(t *testing.T) {
	meta, bitmaps := newTestStores(t)
	const listID = "sweeper-lifecycle-list"
	idx := createAndFillOneSlotList(t, meta, bitmaps, listID)

	lm, err := meta.GetList(t.Context(), listID)
	if err != nil {
		t.Fatalf("GetList: %v", err)
	}
	if lm.State != "FROZEN" {
		t.Fatalf("state after allocating the list's only slot = %q, want FROZEN", lm.State)
	}

	// Phase 1: archive. Grace=0, and exp is already in the past, so this
	// list is immediately eligible.
	sweeper := NewSweeper(meta, bitmaps, 0, 0, 0)
	if err := sweeper.Sweep(t.Context()); err != nil {
		t.Fatalf("Sweep (archive phase): %v", err)
	}
	lm, err = meta.GetList(t.Context(), listID)
	if err != nil {
		t.Fatalf("GetList: %v", err)
	}
	if lm.State != "ARCHIVED" {
		t.Fatalf("state after sweep 1 = %q, want ARCHIVED", lm.State)
	}
	if lm.ArchivedAt == nil {
		t.Error("ArchivedAt is nil after archiving")
	}

	// Phase 2: purge the Redis bitmap. Retention=0, archived_at already
	// set, so eligible on the very next sweep.
	if err := sweeper.Sweep(t.Context()); err != nil {
		t.Fatalf("Sweep (purge phase): %v", err)
	}
	lm, err = meta.GetList(t.Context(), listID)
	if err != nil {
		t.Fatalf("GetList: %v", err)
	}
	if !lm.Purged {
		t.Fatal("Purged is false after sweep 2, want true")
	}
	if lm.PurgedAt == nil {
		t.Error("PurgedAt is nil after purging")
	}
	if lm.State != "ARCHIVED" {
		t.Errorf("state after purge = %q, want still ARCHIVED (purge doesn't change state)", lm.State)
	}

	// Phase 3: hard-delete — deliberately NOT enabled yet (DBRetention
	// still 0 from NewSweeper above). This is the safe-by-default
	// property docs/design.md §22 exists for: a sweep must NOT delete
	// anything when DB_RETENTION_PERIOD is disabled, even though this
	// list is otherwise long past every other window.
	if err := sweeper.Sweep(t.Context()); err != nil {
		t.Fatalf("Sweep (disabled delete phase): %v", err)
	}
	lm, err = meta.GetList(t.Context(), listID)
	if err != nil {
		t.Fatalf("GetList: %v", err)
	}
	if lm == nil {
		t.Fatal("list row was deleted with DBRetention disabled (DB_RETENTION_PERIOD=0) — must never happen")
	}

	// Now enable DB retention and sweep again: the row and its
	// allocation must actually be gone.
	sweeper.DBRetention = time.Nanosecond
	if err := sweeper.Sweep(t.Context()); err != nil {
		t.Fatalf("Sweep (enabled delete phase): %v", err)
	}
	lm, err = meta.GetList(t.Context(), listID)
	if err != nil {
		t.Fatalf("GetList after delete: %v", err)
	}
	if lm != nil {
		t.Fatalf("list row still present after DBRetention enabled and a sweep past it: %+v", lm)
	}

	if err := meta.CheckOwnership(t.Context(), listID, idx, "test-issuer"); err == nil {
		t.Error("CheckOwnership succeeded for a deleted list's allocation — the allocations row should be gone too")
	}
}

func TestSweeper_NoOpWhenNothingIsEligible(t *testing.T) {
	meta, bitmaps := newTestStores(t)
	const listID = "sweeper-noop-list"
	key, err := allocator.NewKey(rand.Read)
	if err != nil {
		t.Fatalf("allocator.NewKey: %v", err)
	}
	// A list with real headroom left (size 10, only one slot taken) and
	// a future exp: nothing here should be touched by any phase, with
	// generous grace/retention windows that clearly haven't elapsed.
	lm, err := meta.CreateList(t.Context(), listID, 2, 10, key, "default")
	if err != nil {
		t.Fatalf("CreateList: %v", err)
	}
	if err := bitmaps.Init(t.Context(), lm.ID, int64((lm.Size*uint64(lm.Bits)+7)/8)); err != nil {
		t.Fatalf("bitmaps.Init: %v", err)
	}

	sweeper := NewSweeper(meta, bitmaps, time.Hour, 30*24*time.Hour, 30*24*time.Hour)
	if err := sweeper.Sweep(t.Context()); err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	got, err := meta.GetList(t.Context(), listID)
	if err != nil {
		t.Fatalf("GetList: %v", err)
	}
	if got == nil {
		t.Fatal("list was deleted — should still be ACTIVE and untouched")
	}
	if got.State != "ACTIVE" {
		t.Errorf("state = %q, want ACTIVE (nothing should have moved it)", got.State)
	}
	if got.Purged {
		t.Error("Purged = true, want false — nothing should have touched this list")
	}
}
