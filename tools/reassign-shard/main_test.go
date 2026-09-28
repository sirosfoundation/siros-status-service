package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sirosfoundation/siros-status-service/internal/as"
	"github.com/sirosfoundation/siros-status-service/internal/testsupport"
)

func newTestAssigner(t *testing.T, shards []string) *as.ShardAssigner {
	t.Helper()
	dsn, cleanup := testsupport.StartPostgres(t)
	t.Cleanup(cleanup)

	assigner, err := as.NewShardAssigner(t.Context(), dsn, shards)
	if err != nil {
		t.Fatalf("NewShardAssigner: %v", err)
	}
	t.Cleanup(assigner.Close)
	return assigner
}

func TestNewConfig_RequiresExactlyOneOfIssuerOrFrom(t *testing.T) {
	if _, err := newConfig("", "", "iad", false); err == nil {
		t.Error("newConfig with neither -issuer nor -from: want error, got nil")
	}
	if _, err := newConfig("issuer-1", "iad", "fra", false); err == nil {
		t.Error("newConfig with both -issuer and -from: want error, got nil")
	}
	if _, err := newConfig("issuer-1", "", "", false); err == nil {
		t.Error("newConfig with no -to: want error, got nil")
	}
	if _, err := newConfig("issuer-1", "", "fra,,syd", false); err == nil {
		t.Error("newConfig with an empty -to entry: want error, got nil")
	}
}

func TestReassign_SingleIssuer(t *testing.T) {
	assigner := newTestAssigner(t, []string{"iad", "fra"})
	if _, err := assigner.Reassign(t.Context(), "issuer-1", "iad"); err != nil {
		t.Fatalf("seed Reassign: %v", err)
	}

	cfg, err := newConfig("issuer-1", "", "fra", false)
	if err != nil {
		t.Fatalf("newConfig: %v", err)
	}
	var out bytes.Buffer
	moved, err := reassign(t.Context(), assigner, cfg, &out)
	if err != nil {
		t.Fatalf("reassign: %v", err)
	}
	if moved != 1 {
		t.Errorf("moved = %d, want 1", moved)
	}

	got, err := assigner.AssignOrLookup(t.Context(), "issuer-1")
	if err != nil {
		t.Fatalf("AssignOrLookup: %v", err)
	}
	if got != "fra" {
		t.Errorf("issuer-1's shard after reassign = %q, want %q", got, "fra")
	}
	if !strings.Contains(out.String(), "issuer-1: iad -> fra") {
		t.Errorf("output %q does not report the move", out.String())
	}
}

func TestReassign_DryRunChangesNothing(t *testing.T) {
	assigner := newTestAssigner(t, []string{"iad", "fra"})
	if _, err := assigner.Reassign(t.Context(), "issuer-1", "iad"); err != nil {
		t.Fatalf("seed Reassign: %v", err)
	}

	cfg, err := newConfig("issuer-1", "", "fra", true)
	if err != nil {
		t.Fatalf("newConfig: %v", err)
	}
	var out bytes.Buffer
	moved, err := reassign(t.Context(), assigner, cfg, &out)
	if err != nil {
		t.Fatalf("reassign: %v", err)
	}
	if moved != 0 {
		t.Errorf("moved = %d, want 0 (dry run must not write anything)", moved)
	}

	got, err := assigner.AssignOrLookup(t.Context(), "issuer-1")
	if err != nil {
		t.Fatalf("AssignOrLookup: %v", err)
	}
	if got != "iad" {
		t.Errorf("issuer-1's shard after a DRY-RUN reassign = %q, want unchanged %q", got, "iad")
	}
	if !strings.Contains(out.String(), "would move issuer-1 -> fra") {
		t.Errorf("output %q does not describe the dry-run move", out.String())
	}
}

func TestReassign_BulkSplitsRoundRobinAcrossTargets(t *testing.T) {
	assigner := newTestAssigner(t, []string{"iad", "fra", "syd"})
	for _, id := range []string{"issuer-1", "issuer-2", "issuer-3", "issuer-4"} {
		if _, err := assigner.Reassign(t.Context(), id, "iad"); err != nil {
			t.Fatalf("seed Reassign %s: %v", id, err)
		}
	}

	cfg, err := newConfig("", "iad", "fra,syd", false)
	if err != nil {
		t.Fatalf("newConfig: %v", err)
	}
	var out bytes.Buffer
	moved, err := reassign(t.Context(), assigner, cfg, &out)
	if err != nil {
		t.Fatalf("reassign: %v", err)
	}
	if moved != 4 {
		t.Errorf("moved = %d, want 4", moved)
	}

	counts := map[string]int{}
	for _, id := range []string{"issuer-1", "issuer-2", "issuer-3", "issuer-4"} {
		shard, err := assigner.AssignOrLookup(t.Context(), id)
		if err != nil {
			t.Fatalf("AssignOrLookup(%s): %v", id, err)
		}
		if shard == "iad" {
			t.Errorf("%s is still on iad after a bulk -from iad reassign", id)
		}
		counts[shard]++
	}
	if counts["fra"] != 2 || counts["syd"] != 2 {
		t.Errorf("round-robin split = %v, want 2 on fra and 2 on syd", counts)
	}
}

func TestReassign_EmptyShardIsANoOp(t *testing.T) {
	assigner := newTestAssigner(t, []string{"iad", "fra"})

	cfg, err := newConfig("", "nonexistent-shard", "fra", false)
	if err != nil {
		t.Fatalf("newConfig: %v", err)
	}
	var out bytes.Buffer
	moved, err := reassign(t.Context(), assigner, cfg, &out)
	if err != nil {
		t.Fatalf("reassign: %v", err)
	}
	if moved != 0 {
		t.Errorf("moved = %d, want 0", moved)
	}
	if !strings.Contains(out.String(), "nothing to do") {
		t.Errorf("output %q does not report the no-op", out.String())
	}
}

func TestReassign_FirstAssignmentShowsNoPreviousShard(t *testing.T) {
	assigner := newTestAssigner(t, []string{"iad"})

	cfg, err := newConfig("brand-new-issuer", "", "iad", false)
	if err != nil {
		t.Fatalf("newConfig: %v", err)
	}
	var out bytes.Buffer
	if _, err := reassign(t.Context(), assigner, cfg, &out); err != nil {
		t.Fatalf("reassign: %v", err)
	}
	if !strings.Contains(out.String(), "(none — first assignment) -> iad") {
		t.Errorf("output %q does not show the first-assignment display", out.String())
	}
}
