package allocator

import (
	"crypto/rand"
	"testing"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key, err := NewKey(rand.Read)
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	return key
}

// assertBijective walks the full cursor range [0, n) and verifies every
// resulting index is distinct and within [0, n) — i.e. Index is a true
// permutation of the list's capacity, not just "looks random."
func assertBijective(t *testing.T, n uint64) {
	t.Helper()
	key := testKey(t)
	a, err := New(key, n)
	if err != nil {
		t.Fatalf("New(n=%d): %v", n, err)
	}

	seen := make(map[uint64]bool, n)
	for cursor := range n {
		idx, err := a.Index(cursor)
		if err != nil {
			t.Fatalf("Index(%d) for n=%d: %v", cursor, n, err)
		}
		if idx >= n {
			t.Fatalf("Index(%d) for n=%d returned out-of-range index %d", cursor, n, idx)
		}
		if seen[idx] {
			t.Fatalf("Index(%d) for n=%d returned duplicate index %d", cursor, n, idx)
		}
		seen[idx] = true
	}
	if uint64(len(seen)) != n {
		t.Fatalf("n=%d: expected %d distinct indices, got %d", n, n, len(seen))
	}
}

func TestBijective_SmallSizes(t *testing.T) {
	// Cover n==1, powers of two, odd bit-lengths, and small primes —
	// the odd-bit-length cases are exactly what the padded-even-Feistel
	// fix in permute() needs to get right.
	for _, n := range []uint64{1, 2, 3, 4, 5, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 100, 127, 128, 129, 200, 255, 256, 257, 1000} {
		t.Run("", func(t *testing.T) {
			assertBijective(t, n)
		})
	}
}

func TestBijective_LargeSize(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large bijectivity sweep in -short mode")
	}
	// Matches the design doc's stated target list capacity.
	assertBijective(t, 100_000)
}

func TestIndex_OutOfRangeCursor(t *testing.T) {
	a, err := New(testKey(t), 10)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := a.Index(10); err == nil {
		t.Fatal("expected error for cursor == n, got nil")
	}
	if _, err := a.Index(1000); err == nil {
		t.Fatal("expected error for cursor > n, got nil")
	}
}

func TestNew_RejectsBadInput(t *testing.T) {
	if _, err := New([]byte("too short"), 100); err == nil {
		t.Fatal("expected error for short key")
	}
	if _, err := New(testKey(t), 0); err == nil {
		t.Fatal("expected error for n == 0")
	}
}

func TestIndex_DifferentKeysDifferentPermutations(t *testing.T) {
	const n = 1000
	a1, err := New(testKey(t), n)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	a2, err := New(testKey(t), n)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	same := 0
	for cursor := range uint64(n) {
		i1, _ := a1.Index(cursor)
		i2, _ := a2.Index(cursor)
		if i1 == i2 {
			same++
		}
	}
	// Two independent keys should agree on only a tiny fraction of
	// positions by chance; a large overlap would mean the key isn't
	// actually influencing the permutation.
	if same > n/10 {
		t.Fatalf("two different keys agreed on %d/%d indices, expected near-zero overlap", same, n)
	}
}

func TestIndex_Deterministic(t *testing.T) {
	const n = 500
	key := testKey(t)
	a1, err := New(key, n)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	a2, err := New(key, n)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for cursor := range uint64(n) {
		i1, _ := a1.Index(cursor)
		i2, _ := a2.Index(cursor)
		if i1 != i2 {
			t.Fatalf("same key produced different index at cursor %d: %d vs %d", cursor, i1, i2)
		}
	}
}

func BenchmarkIndex(b *testing.B) {
	key, err := NewKey(rand.Read)
	if err != nil {
		b.Fatalf("NewKey: %v", err)
	}
	a, err := New(key, 1_000_000)
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		if _, err := a.Index(uint64(i) % 1_000_000); err != nil {
			b.Fatal(err)
		}
	}
}
