// Package pool implements the issuer-blind, load-balanced list
// distribution from docs/design.md §8: maintaining a pool of K
// concurrently-ACTIVE lists and choosing among them by power-of-two-
// choices, plus the administrative rotation knobs from §8.2 (N_max is
// enforced in internal/store's ReserveCursorAndRecord; T_max — a list's
// maximum age while ACTIVE — is enforced here).
//
// Deferred from this package (docs/design.md §8.3, §8.2's target-based
// knob): expiry-bucketed pools and the throughput-derived auto-tuning
// surface. Both need real traffic data to size sensibly and are called
// out as fast-follows once this raw-knob version has run for a while.
package pool

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	mathrand "math/rand/v2"
	"time"

	"github.com/sirosfoundation/siros-status-service/internal/allocator"
	"github.com/sirosfoundation/siros-status-service/internal/store"
)

// ChooseByPowerOfTwo implements §8.1's placement rule: sample two
// candidates at random from the ACTIVE pool and return whichever has
// more remaining capacity. With zero candidates it returns nil (caller
// must create a list first); with one, it returns that one unconditionally.
//
// This is deliberately issuer-blind — it takes no issuer identity as
// input, only the candidates' fill state — which is what gives every
// list an unbiased mix of all recent issuance traffic instead of a
// function of who happened to call the API.
func ChooseByPowerOfTwo(candidates []*store.ListMeta, r *mathrand.Rand) *store.ListMeta {
	switch len(candidates) {
	case 0:
		return nil
	case 1:
		return candidates[0]
	}
	i, j := r.IntN(len(candidates)), r.IntN(len(candidates)-1)
	if j >= i {
		j++ // pick distinct indices without rejection sampling
	}
	a, b := candidates[i], candidates[j]
	if b.Remaining() > a.Remaining() {
		return b
	}
	return a
}

// Manager keeps a pool of lists healthy: it freezes ACTIVE lists past
// their maximum age (T_max) and tops the pool back up to Width so
// allocation always has K candidates to choose between.
type Manager struct {
	meta     *store.MetaStore
	bitmaps  *store.BitmapStore
	Width    int    // K
	Capacity uint64 // N_max, per new list
	Bits     int
	MaxAge   time.Duration // T_max

	rand *mathrand.Rand
}

func NewManager(meta *store.MetaStore, bitmaps *store.BitmapStore, width int, capacity uint64, bits int, maxAge time.Duration) *Manager {
	return &Manager{
		meta:     meta,
		bitmaps:  bitmaps,
		Width:    width,
		Capacity: capacity,
		Bits:     bits,
		MaxAge:   maxAge,
		rand:     mathrand.New(mathrand.NewPCG(mathrand.Uint64(), mathrand.Uint64())),
	}
}

// EnsureHealthy freezes any ACTIVE list past T_max, then creates fresh
// lists until the ACTIVE count reaches Width.
//
// This does not take a cross-process lock around the "count then create"
// steps: a transient overshoot (briefly more than Width ACTIVE lists) is
// possible if this races with another caller, but is harmless — Width is
// a target for anonymity-set mixing, not a safety invariant, and the
// next tick's Freeze pass self-corrects nothing needs correcting (extra
// ACTIVE lists just get selected less often by ChooseByPowerOfTwo until
// they age out or fill up like any other pool member). Worth revisiting
// with an advisory lock only if this stops being true at higher scale.
func (m *Manager) EnsureHealthy(ctx context.Context) error {
	active, err := m.meta.ActiveLists(ctx)
	if err != nil {
		return err
	}

	remaining := active[:0]
	for _, lm := range active {
		if m.MaxAge > 0 && time.Since(lm.CreatedAt) >= m.MaxAge {
			if err := m.meta.Freeze(ctx, lm.ID); err != nil {
				return err
			}
			slog.Info("pool: froze list past max age", "list_id", lm.ID, "age", time.Since(lm.CreatedAt))
			continue
		}
		remaining = append(remaining, lm)
	}

	for len(remaining) < m.Width {
		lm, err := m.createList(ctx)
		if err != nil {
			return err
		}
		remaining = append(remaining, lm)
	}
	return nil
}

func (m *Manager) createList(ctx context.Context) (*store.ListMeta, error) {
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	key, err := allocator.NewKey(rand.Read)
	if err != nil {
		return nil, err
	}
	lm, err := m.meta.CreateList(ctx, id, m.Bits, m.Capacity, key)
	if err != nil {
		return nil, err
	}
	byteLen := int64((lm.Size*uint64(lm.Bits) + 7) / 8)
	if err := m.bitmaps.Init(ctx, lm.ID, byteLen); err != nil {
		return nil, err
	}
	slog.Info("pool: created list", "list_id", lm.ID, "capacity", lm.Size)
	return lm, nil
}

// PickForAllocation returns the list a new allocation should target,
// bootstrapping the pool synchronously if it happens to be empty (e.g.
// on first startup, before Run's first tick) rather than making the
// caller wait for the background loop.
func (m *Manager) PickForAllocation(ctx context.Context) (*store.ListMeta, error) {
	active, err := m.meta.ActiveLists(ctx)
	if err != nil {
		return nil, err
	}
	if len(active) == 0 {
		if err := m.EnsureHealthy(ctx); err != nil {
			return nil, err
		}
		active, err = m.meta.ActiveLists(ctx)
		if err != nil {
			return nil, err
		}
	}
	return ChooseByPowerOfTwo(active, m.rand), nil
}

// randomID generates an opaque, unguessable list identifier
// (docs/design.md §4: "a sequential list_id leaks issuance volume/rate
// the same way sequential indices would").
func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Run periodically calls EnsureHealthy until ctx is canceled. Rotation
// maintenance deliberately lives in its own background loop rather than
// the allocation request path (docs/design.md §12: "keep both as
// separate, infrequent background jobs rather than folding them into
// the request path, so they don't become a scaling constraint").
func (m *Manager) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.EnsureHealthy(ctx); err != nil {
				slog.Error("pool: EnsureHealthy failed", "error", err)
			}
		}
	}
}
