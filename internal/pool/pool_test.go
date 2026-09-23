package pool

import (
	"math/rand/v2"
	"testing"

	"github.com/sirosfoundation/siros-status-service/internal/store"
)

// loadResult is simulateLoad's output: each list's final fill count, and
// a [list][issuer] matrix of how many of that list's entries came from
// each issuer.
type loadResult struct {
	fills    []uint64
	byIssuer [][]int // byIssuer[listIdx][issuerIdx]
}

// simulateLoad runs n synthetic allocations from numIssuers distinct
// issuers against a pool of k lists, each of capacity `capacity`,
// choosing a target list via ChooseByPowerOfTwo each time and
// incrementing its cursor — a pure in-memory stand-in for what the real
// allocate handler does against Postgres.
//
// This exercises exactly what docs/design.md §14 item 7 asks for:
// "validate that fill balances evenly under a synthetic multi-issuer
// load." Issuer identity is recorded here only for the test's own
// bookkeeping (to check the §8.1 mixing property below) — it is
// deliberately never passed to ChooseByPowerOfTwo itself, matching
// §8.1's issuer-blind placement rule.
func simulateLoad(t *testing.T, k int, capacity uint64, n int, numIssuers int) loadResult {
	t.Helper()
	r := rand.New(rand.NewPCG(1, 2))
	issuerOf := rand.New(rand.NewPCG(7, 8)) // separate stream: which issuer places each request

	lists := make([]*store.ListMeta, k)
	byIssuer := make([][]int, k)
	for i := range k {
		lists[i] = &store.ListMeta{Size: capacity}
		byIssuer[i] = make([]int, numIssuers)
	}

	for i := range n {
		issuer := issuerOf.IntN(numIssuers)
		chosen := ChooseByPowerOfTwo(lists, r)
		if chosen == nil {
			t.Fatalf("ChooseByPowerOfTwo returned nil with a non-empty candidate list (allocation %d)", i)
		}
		chosen.Cursor++
		for li, lm := range lists {
			if lm == chosen {
				byIssuer[li][issuer]++
				break
			}
		}
	}

	fills := make([]uint64, k)
	for i, lm := range lists {
		fills[i] = lm.Cursor
	}
	return loadResult{fills: fills, byIssuer: byIssuer}
}

func TestChooseByPowerOfTwo_BalancesFillUnderMultiIssuerLoad(t *testing.T) {
	const (
		k          = 5
		capacity   = 1_000_000 // large relative to n so no list fills up mid-run
		n          = 200_000
		numIssuers = 37 // an awkward, non-divisor-of-k count on purpose
	)

	result := simulateLoad(t, k, capacity, n, numIssuers)
	fills := result.fills

	var total uint64
	minFill, maxFill := fills[0], fills[0]
	for _, f := range fills {
		total += f
		if f < minFill {
			minFill = f
		}
		if f > maxFill {
			maxFill = f
		}
	}
	if total != uint64(n) {
		t.Fatalf("fills sum to %d, want %d (allocations must land somewhere)", total, n)
	}

	mean := float64(total) / float64(k)
	spread := float64(maxFill-minFill) / mean
	// Power-of-two-choices is known to balance far tighter than pure
	// random placement (which would have a much wider spread at this n);
	// 10% of the mean is a generous bound that would fail fast if the
	// selection function regressed to "always pick index 0" or similar.
	if spread > 0.10 {
		t.Fatalf("fill spread too wide: min=%d max=%d mean=%.0f spread=%.3f (fills=%v)", minFill, maxFill, mean, spread, fills)
	}
	t.Logf("fills=%v mean=%.0f spread=%.4f", fills, mean, spread)

	// The privacy-relevant property from §8.1 isn't just balanced load —
	// it's that every list ends up mixed across many issuers, so
	// observing a fetch of any one list doesn't identify a single
	// issuer. Assert no issuer dominates any list: each issuer's share
	// of a list's entries should be near 1/numIssuers, not concentrated.
	expectedPerIssuerPerList := float64(n) / float64(k*numIssuers)
	for li, perIssuer := range result.byIssuer {
		for issuer, count := range perIssuer {
			// Generous bound (3x expected) — this only needs to catch a
			// real regression (e.g. selection secretly keying off issuer
			// identity), not assert tight statistical uniformity.
			if float64(count) > 3*expectedPerIssuerPerList {
				t.Fatalf("list %d: issuer %d contributed %d entries (expected ~%.0f) — mixing looks broken", li, issuer, count, expectedPerIssuerPerList)
			}
		}
	}
}

func TestChooseByPowerOfTwo_PrefersMoreRemainingCapacity(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	// One list nearly full, one nearly empty: over many draws, the
	// nearly-empty one should be chosen far more often, since
	// power-of-two-choices picks the candidate with more remaining
	// capacity whenever both are sampled.
	full := &store.ListMeta{Size: 1000, Cursor: 990}
	empty := &store.ListMeta{Size: 1000, Cursor: 10}
	candidates := []*store.ListMeta{full, empty}

	emptyChosen := 0
	const trials = 10_000
	for range trials {
		if ChooseByPowerOfTwo(candidates, r) == empty {
			emptyChosen++
		}
	}
	// With only 2 candidates, power-of-two-choices always samples both,
	// so this should deterministically favor `empty` every time.
	if emptyChosen != trials {
		t.Fatalf("expected the emptier list to be chosen every time with only 2 candidates, got %d/%d", emptyChosen, trials)
	}
}

func TestChooseByPowerOfTwo_EdgeCases(t *testing.T) {
	r := rand.New(rand.NewPCG(5, 6))
	if got := ChooseByPowerOfTwo(nil, r); got != nil {
		t.Fatalf("expected nil for empty candidate list, got %v", got)
	}
	only := &store.ListMeta{Size: 10, Cursor: 5}
	if got := ChooseByPowerOfTwo([]*store.ListMeta{only}, r); got != only {
		t.Fatalf("expected the sole candidate to be returned, got %v", got)
	}
}

func TestListMeta_Remaining(t *testing.T) {
	lm := &store.ListMeta{Size: 10, Cursor: 3}
	if lm.Remaining() != 7 {
		t.Fatalf("Remaining() = %d, want 7", lm.Remaining())
	}
	full := &store.ListMeta{Size: 10, Cursor: 10}
	if full.Remaining() != 0 {
		t.Fatalf("Remaining() on a full list = %d, want 0", full.Remaining())
	}
}
