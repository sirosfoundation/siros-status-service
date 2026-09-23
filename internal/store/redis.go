// Package store holds the two backing stores described in
// docs/design.md §9/§10: Redis for the hot, per-entry status bitmap, and
// Postgres for list/ownership metadata.
//
// Deliberate departure from the design doc's original wording: §6/§9
// suggested using Redis's BITFIELD command directly, since it does
// native arbitrary-bit-width field access. That turned out not to be
// safe to use as-is: Redis's own SETBIT/BITFIELD bit numbering is
// MSB-first (bit offset 0 is the most significant bit of byte 0), while
// draft-ietf-oauth-status-list-21 §4.1 packs entries LSB-first (index 0
// in the least significant bit(s) of byte 0) — confirmed against the
// draft's own worked examples in internal/statuslist. Using BITFIELD's
// `#idx` field shorthand directly would silently produce a
// spec-nonconformant byte layout.
//
// Rather than hand-deriving and trusting a bit-offset translation
// formula with no live Redis available to verify it against, this store
// operates at the whole-BYTE level instead: a Lua script does an atomic
// GETRANGE + (identical to internal/statuslist's own LSB-first bit math,
// just re-expressed in Lua) + SETRANGE. Because every allowed bit width
// (1, 2, 4, 8) divides 8 evenly, a field never spans a byte boundary, so
// whole-byte granularity is sufficient and this never depends on Redis's
// bit-numbering convention at all. A single Lua script invocation is
// atomic in Redis, so this is still one round trip and race-free against
// concurrent writers to the same byte (which happens whenever bits < 8,
// since several entries then share a byte).
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/redis/go-redis/v9"
)

// setByteScript performs the read-modify-write described in the package
// doc. Redis's embedded Lua 5.1 has no native bitwise operators, so this
// uses the `bit` library (Lua BitOp) that Redis scripting exposes for
// exactly this purpose.
//
// KEYS[1] = bitmap key
// ARGV[1] = byte index
// ARGV[2] = bit offset within the byte, from the LSB (0..7)
// ARGV[3] = field width in bits (1, 2, 4, or 8)
// ARGV[4] = new status value (0..2^bits-1)
//
// Returns the resulting byte value (for tests/observability).
const setByteScript = `
local byteIdx = tonumber(ARGV[1])
local bitOffset = tonumber(ARGV[2])
local bits = tonumber(ARGV[3])
local value = tonumber(ARGV[4])
local mask = bit.lshift(1, bits) - 1

local cur = redis.call('GETRANGE', KEYS[1], byteIdx, byteIdx)
local b = 0
if #cur == 1 then
  b = string.byte(cur, 1)
end

local cleared = bit.band(b, bit.bnot(bit.lshift(mask, bitOffset)))
local newByte = bit.bor(cleared, bit.lshift(bit.band(value, mask), bitOffset))

redis.call('SETRANGE', KEYS[1], byteIdx, string.char(newByte))
return newByte
`

// BitmapStore is the Redis-backed hot store for status bitmaps. Keys are
// namespaced by list ID; one Redis string per list holds its whole
// packed byte array, plus a separate integer key tracking the list's
// write version (docs/design.md §9).
type BitmapStore struct {
	rdb    *redis.Client
	script *redis.Script
}

func NewBitmapStore(rdb *redis.Client) *BitmapStore {
	return &BitmapStore{rdb: rdb, script: redis.NewScript(setByteScript)}
}

func bitmapKey(listID string) string  { return "bitmap:" + listID }
func versionKey(listID string) string { return "version:" + listID }

// Init allocates the zero-filled bitmap for a newly created list. It is
// a no-op (NX) if the key already exists, so it is safe to call
// unconditionally when a list might already have been initialized by a
// concurrent request.
func (s *BitmapStore) Init(ctx context.Context, listID string, byteLen int64) error {
	zeros := make([]byte, byteLen)
	ok, err := s.rdb.SetNX(ctx, bitmapKey(listID), zeros, 0).Result()
	if err != nil {
		return fmt.Errorf("store: init bitmap %s: %w", listID, err)
	}
	_ = ok // false just means it already existed; not an error
	return nil
}

// SetStatus atomically updates a single entry and returns the list's new
// version number.
func (s *BitmapStore) SetStatus(ctx context.Context, listID string, byteIndex uint64, bitOffset uint, bits int, value byte) (version int64, err error) {
	if err := s.script.Run(ctx, s.rdb, []string{bitmapKey(listID)}, byteIndex, bitOffset, bits, value).Err(); err != nil {
		return 0, fmt.Errorf("store: set status in list %s: %w", listID, err)
	}
	v, err := s.rdb.Incr(ctx, versionKey(listID)).Result()
	if err != nil {
		return 0, fmt.Errorf("store: bump version for list %s: %w", listID, err)
	}
	return v, nil
}

// Snapshot returns the full packed byte array for a list, as it stands
// right now — used by the publisher to build a fresh StatusListToken.
func (s *BitmapStore) Snapshot(ctx context.Context, listID string, byteLen int64) ([]byte, error) {
	raw, err := s.rdb.Get(ctx, bitmapKey(listID)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return make([]byte, byteLen), nil
		}
		return nil, fmt.Errorf("store: snapshot list %s: %w", listID, err)
	}
	if int64(len(raw)) != byteLen {
		// Defensive: Init always allocates the exact length up front, so
		// this should be unreachable in practice.
		padded := make([]byte, byteLen)
		copy(padded, raw)
		return padded, nil
	}
	return raw, nil
}

// Version returns a list's current write version (0 if it has never
// been written to).
func (s *BitmapStore) Version(ctx context.Context, listID string) (int64, error) {
	v, err := s.rdb.Get(ctx, versionKey(listID)).Int64()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, nil
		}
		return 0, fmt.Errorf("store: get version for list %s: %w", listID, err)
	}
	return v, nil
}

// Purge drops a list's bitmap and version keys from Redis — the "drop
// the bitmap from hot storage" step of GC (docs/design.md §7 point 4),
// once a list is archived and past its retention window. Deleting a
// key that's already gone is a no-op in Redis, so this is safe to call
// more than once, though internal/gc tracks a purged flag in Postgres
// to avoid doing so needlessly.
func (s *BitmapStore) Purge(ctx context.Context, listID string) error {
	if err := s.rdb.Del(ctx, bitmapKey(listID), versionKey(listID)).Err(); err != nil {
		return fmt.Errorf("store: purge list %s: %w", listID, err)
	}
	return nil
}
