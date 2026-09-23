package statuslist

import "testing"

// Test vectors transcribed and hand-verified from
// draft-ietf-oauth-status-list-21 §4.1's worked examples. See the
// package doc for the derivation.

func TestBitmap_SpecVector_Bits1(t *testing.T) {
	// 16 entries, bits=1. Byte 0 = 0xB9, byte 1 = 0xA3.
	values := []Status{1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1}
	bm, err := NewBitmap(uint64(len(values)), 1)
	if err != nil {
		t.Fatalf("NewBitmap: %v", err)
	}
	for i, v := range values {
		if err := bm.Set(uint64(i), v); err != nil {
			t.Fatalf("Set(%d): %v", i, err)
		}
	}
	got := bm.Bytes()
	want := []byte{0xB9, 0xA3}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("packed bytes = %#v, want %#v", got, want)
	}

	for i, v := range values {
		got, err := bm.Get(uint64(i))
		if err != nil {
			t.Fatalf("Get(%d): %v", i, err)
		}
		if got != v {
			t.Fatalf("Get(%d) = %v, want %v", i, got, v)
		}
	}
}

func TestBitmap_SpecVector_Bits2(t *testing.T) {
	// 12 entries, bits=2. Bytes = 0xC9, 0x44, 0xF9.
	values := []Status{1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3}
	bm, err := NewBitmap(uint64(len(values)), 2)
	if err != nil {
		t.Fatalf("NewBitmap: %v", err)
	}
	for i, v := range values {
		if err := bm.Set(uint64(i), v); err != nil {
			t.Fatalf("Set(%d): %v", i, err)
		}
	}
	got := bm.Bytes()
	want := []byte{0xC9, 0x44, 0xF9}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("packed byte %d = %#02x, want %#02x (full: %#v)", i, got[i], want[i], got)
		}
	}

	for i, v := range values {
		got, err := bm.Get(uint64(i))
		if err != nil {
			t.Fatalf("Get(%d): %v", i, err)
		}
		if got != v {
			t.Fatalf("Get(%d) = %v, want %v", i, got, v)
		}
	}
}

func TestBitmap_ZeroInitializedIsValid(t *testing.T) {
	bm, err := NewBitmap(1000, 2)
	if err != nil {
		t.Fatalf("NewBitmap: %v", err)
	}
	for _, idx := range []uint64{0, 1, 500, 999} {
		got, err := bm.Get(idx)
		if err != nil {
			t.Fatalf("Get(%d): %v", idx, err)
		}
		if got != StatusValid {
			t.Fatalf("Get(%d) on fresh bitmap = %v, want StatusValid (allocation must be metadata-only)", idx, got)
		}
	}
}

func TestBitmap_OutOfRange(t *testing.T) {
	bm, err := NewBitmap(10, 2)
	if err != nil {
		t.Fatalf("NewBitmap: %v", err)
	}
	if err := bm.Set(10, StatusInvalid); err == nil {
		t.Fatal("expected error setting index == size")
	}
	if _, err := bm.Get(10); err == nil {
		t.Fatal("expected error getting index == size")
	}
}

func TestBitmap_RejectsBadInput(t *testing.T) {
	if _, err := NewBitmap(10, 3); err == nil {
		t.Fatal("expected error for invalid bit width 3")
	}
	if _, err := NewBitmap(0, 2); err == nil {
		t.Fatal("expected error for size 0")
	}
	bm, err := NewBitmap(10, 1)
	if err != nil {
		t.Fatalf("NewBitmap: %v", err)
	}
	if err := bm.Set(0, 2); err == nil {
		t.Fatal("expected error setting a value that doesn't fit in 1 bit")
	}
}

func TestWrapBitmap_SizeMismatch(t *testing.T) {
	if _, err := WrapBitmap(make([]byte, 3), 100, 2); err == nil {
		t.Fatal("expected error: 3 bytes cannot hold 100 entries at 2 bits each")
	}
	// 12 entries * 2 bits = 24 bits = 3 bytes exactly.
	if _, err := WrapBitmap(make([]byte, 3), 12, 2); err != nil {
		t.Fatalf("WrapBitmap: unexpected error for exact fit: %v", err)
	}
}

func TestByteOffset_NeverSpansAByteBoundary(t *testing.T) {
	for _, bits := range []int{1, 2, 4, 8} {
		for idx := range uint64(64) {
			byteIdx, bitOffset := ByteOffset(idx, bits)
			if bitOffset+uint(bits) > 8 {
				t.Fatalf("bits=%d idx=%d: field [%d,%d) crosses byte %d's boundary", bits, idx, bitOffset, bitOffset+uint(bits), byteIdx)
			}
		}
	}
}
