// Package statuslist implements the wire format defined by
// draft-ietf-oauth-status-list-21: bit-packing status values into a byte
// array (§4.1), compressing and encoding that array (§4.2), and building
// a signed Status List Token (§5.1) around it.
//
// Bit-packing layout (draft-ietf-oauth-status-list-21 §4.1, verified
// against the draft's own worked examples): entries are packed from the
// least significant bit of byte 0 upward. For an entry at index `idx`
// with a `bits`-wide status field:
//
//	byteIndex = idx * bits / 8
//	bitOffset = (idx * bits) % 8         // offset from the byte's LSB
//
// Because bits is always 1, 2, 4, or 8, `8 % bits == 0`, so a field never
// spans a byte boundary — byteIndex/bitOffset arithmetic alone is enough,
// with no cross-byte carry to handle. The status value itself is written
// with its own least-significant bit at the field's low (LSB-ward)
// position, i.e. `byte |= (value & mask) << bitOffset` — ordinary,
// unreversed binary packing.
//
// This intentionally does NOT match Redis's SETBIT/BITFIELD bit
// numbering, which is MSB-first (Redis bit offset 0 is the most
// significant bit of byte 0). internal/store does not use BITFIELD's
// automatic field addressing for this reason — see its package doc.
package statuslist

import "fmt"

// Status is a status list entry value (draft-ietf-oauth-status-list-21
// §7.1).
type Status byte

const (
	StatusValid     Status = 0x00
	StatusInvalid   Status = 0x01 // revoked
	StatusSuspended Status = 0x02
	// 0x03 and 0x0C-0x0F are reserved for application-specific use;
	// 0x04-0x0B are reserved for future IANA registration. Neither range
	// is modeled here — the service treats any in-range value opaquely.
)

// ValidBitWidth reports whether bits is one of the widths the spec
// allows (1, 2, 4, or 8).
func ValidBitWidth(bits int) bool {
	switch bits {
	case 1, 2, 4, 8:
		return true
	default:
		return false
	}
}

// Bitmap is the in-memory, spec-packed byte array backing a single
// status list.
type Bitmap struct {
	bits int
	size uint64
	data []byte
}

// NewBitmap allocates a zero-initialized bitmap for `size` entries at
// the given bit width. Zero-valued bytes decode to StatusValid for every
// entry, matching the design's "allocation is metadata-only, new entries
// default to VALID" property (docs/design.md §7).
func NewBitmap(size uint64, bits int) (*Bitmap, error) {
	if !ValidBitWidth(bits) {
		return nil, fmt.Errorf("statuslist: invalid bit width %d", bits)
	}
	if size == 0 {
		return nil, fmt.Errorf("statuslist: size must be > 0")
	}
	nBytes := (size*uint64(bits) + 7) / 8
	return &Bitmap{bits: bits, size: size, data: make([]byte, nBytes)}, nil
}

// WrapBitmap wraps an existing byte array (e.g. one just fetched from
// Redis) as a Bitmap, validating that it is exactly the size expected
// for `size` entries at `bits` width.
func WrapBitmap(data []byte, size uint64, bits int) (*Bitmap, error) {
	if !ValidBitWidth(bits) {
		return nil, fmt.Errorf("statuslist: invalid bit width %d", bits)
	}
	want := (size*uint64(bits) + 7) / 8
	if uint64(len(data)) != want {
		return nil, fmt.Errorf("statuslist: expected %d bytes for %d entries at %d bits, got %d", want, size, bits, len(data))
	}
	return &Bitmap{bits: bits, size: size, data: data}, nil
}

// Bytes returns the underlying packed byte array. Callers must not
// retain a mutable reference beyond the Bitmap's own lifetime if they
// intend to keep using the Bitmap afterwards.
func (b *Bitmap) Bytes() []byte { return b.data }

// Bits returns the configured bit width per entry.
func (b *Bitmap) Bits() int { return b.bits }

// Size returns the number of entries the bitmap holds.
func (b *Bitmap) Size() uint64 { return b.size }

// ByteOffset returns the byte index and within-byte bit offset (from the
// LSB) for the given entry index, per the spec's packing rule described
// in the package doc. It is exported so internal/store can perform the
// equivalent whole-byte read-modify-write against Redis without
// depending on this package's in-memory representation.
func ByteOffset(idx uint64, bits int) (byteIndex uint64, bitOffset uint) {
	byteIndex = idx * uint64(bits) / 8
	bitOffset = uint(idx*uint64(bits)) % 8
	return
}

// Set writes status at idx.
func (b *Bitmap) Set(idx uint64, status Status) error {
	if idx >= b.size {
		return fmt.Errorf("statuslist: index %d out of range for size %d", idx, b.size)
	}
	mask := byte(1<<uint(b.bits) - 1)
	if byte(status) > mask {
		return fmt.Errorf("statuslist: status %#x does not fit in %d bits", status, b.bits)
	}
	byteIndex, bitOffset := ByteOffset(idx, b.bits)
	b.data[byteIndex] = (b.data[byteIndex] &^ (mask << bitOffset)) | (byte(status) << bitOffset)
	return nil
}

// Get reads the status at idx.
func (b *Bitmap) Get(idx uint64) (Status, error) {
	if idx >= b.size {
		return 0, fmt.Errorf("statuslist: index %d out of range for size %d", idx, b.size)
	}
	mask := byte(1<<uint(b.bits) - 1)
	byteIndex, bitOffset := ByteOffset(idx, b.bits)
	return Status((b.data[byteIndex] >> bitOffset) & mask), nil
}
