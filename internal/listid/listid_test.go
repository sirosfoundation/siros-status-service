package listid

import "testing"

func TestNewAndParseShard(t *testing.T) {
	for _, shard := range []string{"iad", "fra", "default", "a"} {
		id, err := New(shard)
		if err != nil {
			t.Fatalf("New(%q): %v", shard, err)
		}
		got, ok := ParseShard(id)
		if !ok {
			t.Fatalf("ParseShard(%q): ok = false, want true", id)
		}
		if got != shard {
			t.Errorf("ParseShard(%q) = %q, want %q", id, got, shard)
		}
	}
}

func TestNewRejectsShardContainingSeparator(t *testing.T) {
	if _, err := New("bad.shard"); err == nil {
		t.Error("New(\"bad.shard\"): want error, got nil")
	}
}

func TestNewProducesDistinctIDs(t *testing.T) {
	a, err := New("iad")
	if err != nil {
		t.Fatal(err)
	}
	b, err := New("iad")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Errorf("New(\"iad\") produced the same ID twice: %q", a)
	}
}

func TestParseShardRejectsLegacyIDs(t *testing.T) {
	// Pre-existing list IDs (this scheme's predecessor: pure random hex,
	// no separator) must report ok=false, not a garbage/empty shard —
	// callers fall back to a different routing signal for these, they
	// never treat them as an error.
	for _, id := range []string{
		"a1b2c3d4e5f60718293a4b5c6d7e8f90", // legacy 16-byte-hex ID, no separator
		"",
		".",
		".abc123", // empty shard before the separator
		"iad.",    // empty suffix after the separator
		"nodotatall123",
	} {
		if shard, ok := ParseShard(id); ok {
			t.Errorf("ParseShard(%q) = (%q, true), want ok=false", id, shard)
		}
	}
}

func TestParseShardHandlesMultipleSeparators(t *testing.T) {
	// Only the first separator delimits the shard prefix — a random
	// suffix that happens to contain "." (can't today, hex never does,
	// but the parser shouldn't rely on that) still yields the right shard.
	shard, ok := ParseShard("iad.ab.cd")
	if !ok || shard != "iad" {
		t.Errorf("ParseShard(\"iad.ab.cd\") = (%q, %v), want (\"iad\", true)", shard, ok)
	}
}
