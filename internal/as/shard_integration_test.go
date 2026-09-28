package as

import (
	"testing"

	"github.com/sirosfoundation/siros-status-service/internal/testsupport"
)

func newTestShardAssigner(t *testing.T, shards []string) *ShardAssigner {
	t.Helper()
	dsn, cleanup := testsupport.StartPostgres(t)
	t.Cleanup(cleanup)

	assigner, err := NewShardAssigner(t.Context(), dsn, shards)
	if err != nil {
		t.Fatalf("NewShardAssigner: %v", err)
	}
	t.Cleanup(assigner.Close)
	return assigner
}

func TestShardAssigner_AssignOrLookup_StickyAcrossCalls(t *testing.T) {
	a := newTestShardAssigner(t, []string{"iad", "fra"})

	first, err := a.AssignOrLookup(t.Context(), "issuer-1")
	if err != nil {
		t.Fatalf("AssignOrLookup: %v", err)
	}
	if first != "iad" && first != "fra" {
		t.Fatalf("AssignOrLookup returned %q, want one of the configured shards", first)
	}

	// docs/design.md §15.5: sticky thereafter — repeated lookups for the
	// same issuer must keep returning the same shard, not re-roll it.
	for range 5 {
		got, err := a.AssignOrLookup(t.Context(), "issuer-1")
		if err != nil {
			t.Fatalf("AssignOrLookup (repeat): %v", err)
		}
		if got != first {
			t.Errorf("AssignOrLookup returned %q on a repeat call, want the original %q", got, first)
		}
	}
}

func TestShardAssigner_AssignOrLookup_DifferentIssuersCanLandDifferently(t *testing.T) {
	a := newTestShardAssigner(t, []string{"iad", "fra"})

	seen := map[string]bool{}
	for i := range 20 {
		shard, err := a.AssignOrLookup(t.Context(), issuerName(i))
		if err != nil {
			t.Fatalf("AssignOrLookup: %v", err)
		}
		seen[shard] = true
	}
	if len(seen) < 2 {
		t.Errorf("20 distinct issuers all landed on %v — hashIndex isn't actually distributing across shards", seen)
	}
}

func TestShardAssigner_Reassign_MovesFutureAllocationsOnly(t *testing.T) {
	a := newTestShardAssigner(t, []string{"iad", "fra", "syd"})

	original, err := a.AssignOrLookup(t.Context(), "issuer-1")
	if err != nil {
		t.Fatalf("AssignOrLookup: %v", err)
	}

	oldShard, err := a.Reassign(t.Context(), "issuer-1", "syd")
	if err != nil {
		t.Fatalf("Reassign: %v", err)
	}
	if oldShard != original {
		t.Errorf("Reassign returned old shard %q, want %q (the original assignment)", oldShard, original)
	}

	// docs/design.md §23: reassignment must actually take — a subsequent
	// lookup returns the new shard, not the old one.
	after, err := a.AssignOrLookup(t.Context(), "issuer-1")
	if err != nil {
		t.Fatalf("AssignOrLookup after reassign: %v", err)
	}
	if after != "syd" {
		t.Errorf("AssignOrLookup after Reassign = %q, want %q", after, "syd")
	}
}

func TestShardAssigner_Reassign_FirstAssignmentReturnsEmptyOldShard(t *testing.T) {
	a := newTestShardAssigner(t, []string{"iad"})

	oldShard, err := a.Reassign(t.Context(), "never-assigned-before", "iad")
	if err != nil {
		t.Fatalf("Reassign: %v", err)
	}
	if oldShard != "" {
		t.Errorf("Reassign for a never-before-assigned issuer returned old shard %q, want \"\"", oldShard)
	}

	got, err := a.AssignOrLookup(t.Context(), "never-assigned-before")
	if err != nil {
		t.Fatalf("AssignOrLookup: %v", err)
	}
	if got != "iad" {
		t.Errorf("AssignOrLookup after Reassign = %q, want %q", got, "iad")
	}
}

func TestShardAssigner_ListIssuersOnShard(t *testing.T) {
	a := newTestShardAssigner(t, []string{"iad", "fra"})

	if _, err := a.Reassign(t.Context(), "issuer-1", "iad"); err != nil {
		t.Fatalf("Reassign issuer-1: %v", err)
	}
	if _, err := a.Reassign(t.Context(), "issuer-2", "iad"); err != nil {
		t.Fatalf("Reassign issuer-2: %v", err)
	}
	if _, err := a.Reassign(t.Context(), "issuer-3", "fra"); err != nil {
		t.Fatalf("Reassign issuer-3: %v", err)
	}

	onIAD, err := a.ListIssuersOnShard(t.Context(), "iad")
	if err != nil {
		t.Fatalf("ListIssuersOnShard(iad): %v", err)
	}
	if len(onIAD) != 2 {
		t.Errorf("ListIssuersOnShard(iad) = %v, want 2 issuers", onIAD)
	}

	onEmpty, err := a.ListIssuersOnShard(t.Context(), "nonexistent-shard")
	if err != nil {
		t.Fatalf("ListIssuersOnShard(nonexistent): %v", err)
	}
	if len(onEmpty) != 0 {
		t.Errorf("ListIssuersOnShard(nonexistent-shard) = %v, want empty", onEmpty)
	}
}

func issuerName(i int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	return "issuer-" + string(letters[i%len(letters)]) + string(rune('0'+i/len(letters)))
}
