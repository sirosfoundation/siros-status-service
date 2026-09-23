// Package allocator implements the keyed format-preserving permutation
// described in docs/design.md §5A: given a list of capacity N and a
// per-list secret key, it maps a monotonically increasing cursor (0..N)
// to a pseudorandom, collision-free index in [0, N) without ever storing
// an explicit permutation array.
//
// The permutation is a small unbalanced Feistel network over
// ceil(log2(N)) bits, with cycle-walking to fold results that land
// outside [0, N) back into range. HMAC-SHA256 (truncated) is the round
// function; it need not be a full cryptographic PRP, only unpredictable
// to anyone without the key, since the goal is unlinkability of issuance
// order, not confidentiality of the index itself.
package allocator

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/bits"
)

// KeySize is the required length, in bytes, of a per-list allocator key.
const KeySize = 32

// rounds is the number of Feistel rounds. 4 rounds is the standard
// minimum for a balanced/unbalanced Feistel network to behave like a
// pseudorandom permutation; more rounds buy no privacy margin here since
// the threat model is "unpredictable without the key," not resistance to
// cryptanalysis with the key exposed.
const rounds = 4

// maxCycleWalks bounds cycle-walking so a pathological key/N combination
// can never spin forever. In the worst case (N a little over a power of
// two) roughly half of the domain is out of range, so the expected walk
// length is ~2 and 1000 is an astronomically generous ceiling.
const maxCycleWalks = 1000

// Allocator derives pseudorandom, collision-free indices for a single
// status list of a fixed capacity.
//
// The Feistel network always splits its domain into two EQUAL-width
// halves (padding the bit-length up to the next even number if needed).
// A balanced Feistel round, L',R' = R, L^F(R), is bijective on its full
// domain for any round function F and any number of rounds >= 1 — it
// never has to worry about the width-mismatch pitfalls that an unbalanced
// split (odd total bit count) would introduce. Cycle-walking (in Index)
// absorbs the fact that the padded domain can be larger than N.
type Allocator struct {
	key  [KeySize]byte
	n    uint64
	half uint // bit-width of EACH half; domain is 2*half bits
}

// New builds an Allocator for a list of capacity n using key as the
// per-list secret. key must be exactly KeySize bytes; use NewKey to
// generate one.
func New(key []byte, n uint64) (*Allocator, error) {
	if len(key) != KeySize {
		return nil, errors.New("allocator: key must be 32 bytes")
	}
	if n == 0 {
		return nil, errors.New("allocator: capacity must be > 0")
	}
	total := uint(bits.Len64(n - 1))
	if total == 0 {
		total = 1 // n == 1
	}
	if total%2 != 0 {
		total++ // pad to an even bit-length so both halves match exactly
	}
	half := total / 2
	if half == 0 {
		half = 1
	}
	a := &Allocator{n: n, half: half}
	copy(a.key[:], key)
	return a, nil
}

// NewKey generates a fresh random allocator key using the supplied
// cryptographically secure random source (typically crypto/rand.Reader).
func NewKey(random func([]byte) (int, error)) ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := random(key); err != nil {
		return nil, err
	}
	return key, nil
}

// Index returns the pseudorandom index assigned to the given cursor
// position. cursor must be in [0, N); callers allocate by calling this
// with a monotonically increasing counter starting at 0.
func (a *Allocator) Index(cursor uint64) (uint64, error) {
	if cursor >= a.n {
		return 0, errors.New("allocator: cursor out of range")
	}
	for range maxCycleWalks {
		cursor = a.permute(cursor)
		if cursor < a.n {
			return cursor, nil
		}
	}
	return 0, errors.New("allocator: cycle walk did not converge")
}

// permute applies the balanced Feistel network to x, treating x as a
// 2*half-bit value split into two equal-width halves.
func (a *Allocator) permute(x uint64) uint64 {
	mask := uint64(1)<<a.half - 1

	l := (x >> a.half) & mask
	r := x & mask

	for round := range rounds {
		f := a.round(byte(round), r) & mask
		l, r = r, l^f
	}

	return (l << a.half) | r
}

// round is the Feistel round function: a keyed, domain-separated PRF
// truncated to the left-half width.
func (a *Allocator) round(round byte, r uint64) uint64 {
	var buf [9]byte
	buf[0] = round
	binary.BigEndian.PutUint64(buf[1:], r)

	mac := hmac.New(sha256.New, a.key[:])
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	return binary.BigEndian.Uint64(sum[:8])
}
