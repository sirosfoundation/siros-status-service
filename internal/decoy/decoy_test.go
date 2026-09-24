package decoy

import (
	"testing"

	"github.com/sirosfoundation/siros-status-service/internal/statuslist"
)

// nextDecoyStatus is randomized (which of two real states a VALID decoy
// moves to; whether a SUSPENDED decoy reverts), so these run many trials
// and assert on the *set* of outcomes rather than one fixed result —
// what actually matters for docs/design.md §17 is that both real
// transitions stay reachable and INVALID is truly a dead end.
const trials = 500

func TestNextDecoyStatus_ValidMovesToInvalidOrSuspended(t *testing.T) {
	seen := map[statuslist.Status]bool{}
	for range trials {
		next, changed := nextDecoyStatus(statuslist.StatusValid)
		if !changed {
			t.Fatal("expected a VALID decoy to always change on this pass")
		}
		if next != statuslist.StatusInvalid && next != statuslist.StatusSuspended {
			t.Fatalf("unexpected next status %v", next)
		}
		seen[next] = true
	}
	if !seen[statuslist.StatusInvalid] {
		t.Error("StatusInvalid never observed across trials — VALID->INVALID transition looks unreachable")
	}
	if !seen[statuslist.StatusSuspended] {
		t.Error("StatusSuspended never observed across trials — VALID->SUSPENDED transition looks unreachable")
	}
}

func TestNextDecoyStatus_SuspendedMayRevertOrStay(t *testing.T) {
	sawRevert := false
	sawStay := false
	for range trials {
		next, changed := nextDecoyStatus(statuslist.StatusSuspended)
		switch {
		case changed && next == statuslist.StatusValid:
			sawRevert = true
		case !changed && next == statuslist.StatusSuspended:
			sawStay = true
		default:
			t.Fatalf("unexpected result (next=%v, changed=%v) for a SUSPENDED decoy", next, changed)
		}
	}
	if !sawRevert {
		t.Error("SUSPENDED never reverted to VALID across trials — a real lifted suspension has no decoy analog")
	}
	if !sawStay {
		t.Error("SUSPENDED never stayed put across trials — decoys would always revert, unlike real suspensions")
	}
}

func TestNextDecoyStatus_InvalidNeverChanges(t *testing.T) {
	for range trials {
		next, changed := nextDecoyStatus(statuslist.StatusInvalid)
		if changed {
			t.Fatal("expected an INVALID decoy to never change — a real revocation is permanent")
		}
		if next != statuslist.StatusInvalid {
			t.Fatalf("expected next == StatusInvalid when unchanged, got %v", next)
		}
	}
}

func TestNextDecoyStatus_ApplicationSpecificValueLeftAlone(t *testing.T) {
	const appSpecific statuslist.Status = 0x0C
	next, changed := nextDecoyStatus(appSpecific)
	if changed {
		t.Fatal("expected an application-specific value to never be touched")
	}
	if next != appSpecific {
		t.Fatalf("expected next == %v when unchanged, got %v", appSpecific, next)
	}
}
