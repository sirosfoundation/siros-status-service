// Package decoy injects camouflage noise into unallocated status-list
// capacity (docs/design.md §17: "herd immunity" for real revocations).
//
// The threat this defends against: draft-ietf-oauth-status-list-21's whole
// design publishes the raw packed bitmap, not per-index answers — a
// verifier (or anyone else who fetches the list) can decode every entry,
// not just the one they were looking for. Because allocation never writes
// a never-issued index (it decodes as VALID via the bitmap's own
// zero-initialization — see internal/ingestion's handleAllocate doc
// comment), every non-VALID byte an observer finds is otherwise
// unambiguous: it can only be a real credential a real issuer really
// revoked or suspended. That turns "download the list, diff it over time"
// into a way to count, and eventually correlate, real revocation events —
// exactly the signal §8's issuer-blind pool placement already goes to
// lengths to avoid leaking through *list choice*; this is the same leak
// through *bit values* instead.
//
// The fix is the same shape as chaff traffic in an anonymity network:
// periodically flip a random sample of never-yet-allocated indices to a
// real non-VALID state too, so a non-VALID bit alone no longer proves
// anything. Decoy dynamics deliberately mirror real ones exactly (see
// nextDecoyStatus) — anything statistically distinguishable from a real
// entry's behavior would defeat the purpose.
//
// Safety: a decoy candidate is always derived from a cursor position
// strictly at or beyond a list's CURRENT cursor — i.e. a position that has
// never been, and (for ACTIVE/FROZEN lists) might one day be, handed out.
// internal/ingestion's handleAllocate resets a freshly allocated index to
// VALID as its very next write after reserving it, which is what makes
// this safe even under a race: the issuer only ever sees the index after
// that reset has completed, and internal/store.ReserveCursorAndRecord's
// atomic cursor bump means a position, once consumed, is never a decoy
// candidate again (see NoiseLists's doc comment for why ARCHIVED lists
// have no such race to worry about at all — their cursor is permanently
// frozen).
package decoy

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/sirosfoundation/siros-status-service/internal/allocator"
	"github.com/sirosfoundation/siros-status-service/internal/publisher"
	"github.com/sirosfoundation/siros-status-service/internal/statuslist"
	"github.com/sirosfoundation/siros-status-service/internal/store"
)

// Noiser periodically injects decoy status flips into a shard's lists.
type Noiser struct {
	meta    *store.MetaStore
	bitmaps *store.BitmapStore
	pub     *publisher.Publisher
	shardID string

	// Rate is the fraction (0, 1] of a list's never-allocated capacity
	// targeted per Sweep pass. Zero (the zero value) disables noising
	// entirely — Sweep becomes a no-op, so it is always safe to construct
	// and run a Noiser regardless of configuration.
	Rate float64
	// DefaultTTLSeconds mirrors handleSetStatus's own MarkDirty call —
	// a decoy flip is cache-invalidated exactly like a real one, so an
	// observer can't tell the two apart by cache behavior either.
	DefaultTTLSeconds int64
}

func NewNoiser(meta *store.MetaStore, bitmaps *store.BitmapStore, pub *publisher.Publisher, shardID string, rate float64, defaultTTLSeconds int64) *Noiser {
	return &Noiser{meta: meta, bitmaps: bitmaps, pub: pub, shardID: shardID, Rate: rate, DefaultTTLSeconds: defaultTTLSeconds}
}

// Sweep runs one pass over every list NoiseLists returns for this shard.
func (n *Noiser) Sweep(ctx context.Context) error {
	if n.Rate <= 0 {
		return nil
	}
	lists, err := n.meta.NoiseLists(ctx, n.shardID)
	if err != nil {
		return err
	}
	for _, lm := range lists {
		if err := n.sweepList(ctx, lm); err != nil {
			slog.Error("decoy: sweep list failed", "list_id", lm.ID, "error", err)
		}
	}
	return nil
}

func (n *Noiser) sweepList(ctx context.Context, lm *store.ListMeta) error {
	unallocated := lm.Size - lm.Cursor
	if unallocated == 0 {
		return nil
	}

	// Expected count is unallocated*Rate; fractional remainders roll into
	// one more-or-less coin flip so a small list/low rate still gets an
	// occasional decoy instead of always rounding down to zero.
	expected := float64(unallocated) * n.Rate
	count := uint64(expected)
	if rand.Float64() < expected-float64(count) {
		count++
	}
	if count == 0 {
		return nil
	}

	alloc, err := allocator.New(lm.FPEKey, lm.Size)
	if err != nil {
		return err
	}

	byteLen := int64((lm.Size*uint64(lm.Bits) + 7) / 8)
	raw, err := n.bitmaps.Snapshot(ctx, lm.ID, byteLen)
	if err != nil {
		return err
	}
	bm, err := statuslist.WrapBitmap(raw, lm.Size, lm.Bits)
	if err != nil {
		return err
	}

	dirty := false
	for range count {
		// A random cursor position at or beyond the list's current
		// cursor — see the package doc for why this is always safe.
		pos := lm.Cursor + rand.Uint64N(unallocated)
		idx, err := alloc.Index(pos)
		if err != nil {
			return err
		}

		cur, err := bm.Get(idx)
		if err != nil {
			return err
		}
		next, changed := nextDecoyStatus(cur)
		if !changed {
			continue
		}

		byteIndex, bitOffset := statuslist.ByteOffset(idx, lm.Bits)
		if _, err := n.bitmaps.SetStatus(ctx, lm.ID, byteIndex, bitOffset, lm.Bits, byte(next)); err != nil {
			return err
		}
		dirty = true
	}

	if dirty {
		n.pub.MarkDirty(lm.ID, n.DefaultTTLSeconds)
	}
	return nil
}

// nextDecoyStatus picks the next state for one decoy flip, deliberately
// matching real status dynamics exactly: a VALID entry moves to either
// INVALID or SUSPENDED; a SUSPENDED one may revert to VALID (a real
// suspension can be lifted) or stay put; an INVALID one never changes
// again (a real revocation is permanent) — mirroring
// draft-ietf-oauth-status-list-21's own state semantics rather than
// inventing decoy-only behavior an observer could learn to spot.
// changed is false when nextDecoyStatus decides not to touch this index
// this pass (including the "already INVALID" case, which is always
// false).
func nextDecoyStatus(cur statuslist.Status) (next statuslist.Status, changed bool) {
	switch cur {
	case statuslist.StatusValid:
		if rand.IntN(2) == 0 {
			return statuslist.StatusInvalid, true
		}
		return statuslist.StatusSuspended, true
	case statuslist.StatusSuspended:
		if rand.IntN(2) == 0 {
			return statuslist.StatusValid, true
		}
		return cur, false
	default: // StatusInvalid, or any application-specific value — leave alone
		return cur, false
	}
}

// Run calls Sweep on a fixed interval until ctx is canceled, matching
// internal/gc.Sweeper's Run.
func (n *Noiser) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := n.Sweep(ctx); err != nil {
				slog.Error("decoy: sweep failed", "error", err)
			}
		}
	}
}
