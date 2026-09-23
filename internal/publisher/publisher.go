// Package publisher builds and caches signed StatusListTokens from the
// live Redis bitmap, decoupled from individual status writes
// (docs/design.md §9).
//
// Simplification vs. the design doc: §9 describes a debounced publisher
// ("at most every ttl seconds, or immediately if idle"). This prototype
// instead polls on a fixed interval (Config.PublishInterval) and
// republishes any list whose live version has moved past what was last
// published. That's simpler to reason about and sufficient to prove the
// allocator/publisher/API contract end-to-end (docs/design.md §14); true
// debouncing (publish immediately when a burst of writes goes idle,
// without waiting for the next tick) is a reasonable fast-follow once
// this is running against real traffic.
package publisher

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/sirosfoundation/siros-status-service/internal/statuslist"
	"github.com/sirosfoundation/siros-status-service/internal/store"
)

// Published is a cached, signed token plus the version it was built
// from, so the API layer can serve conditional GETs without re-signing
// on every request.
type Published struct {
	Token   string
	Version int64
	Bits    int
	TTL     int64
}

type Publisher struct {
	bitmaps *store.BitmapStore
	meta    *store.MetaStore
	key     *ecdsa.PrivateKey
	keyID   string
	baseURL string

	mu    sync.RWMutex
	cache map[string]*Published
}

func New(bitmaps *store.BitmapStore, meta *store.MetaStore, key *ecdsa.PrivateKey, keyID, baseURL string) *Publisher {
	return &Publisher{
		bitmaps: bitmaps,
		meta:    meta,
		key:     key,
		keyID:   keyID,
		baseURL: baseURL,
		cache:   make(map[string]*Published),
	}
}

// Get returns the last-published token for a list, if any has been
// published yet.
func (p *Publisher) Get(listID string) (*Published, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	pub, ok := p.cache[listID]
	return pub, ok
}

// PublishIfStale rebuilds and signs a fresh token for listID if its live
// Redis version has moved past the cached one (or nothing has been
// published yet). ttlSeconds is the per-list/issuer cache lifetime to
// embed in the token (docs/design.md §9/§13).
func (p *Publisher) PublishIfStale(ctx context.Context, lm *store.ListMeta, ttlSeconds int64) (*Published, error) {
	liveVersion, err := p.bitmaps.Version(ctx, lm.ID)
	if err != nil {
		return nil, err
	}

	p.mu.RLock()
	cached, ok := p.cache[lm.ID]
	p.mu.RUnlock()
	if ok && cached.Version == liveVersion && cached.TTL == ttlSeconds {
		return cached, nil
	}

	byteLen := int64((lm.Size*uint64(lm.Bits) + 7) / 8)
	raw, err := p.bitmaps.Snapshot(ctx, lm.ID, byteLen)
	if err != nil {
		return nil, err
	}
	bm, err := statuslist.WrapBitmap(raw, lm.Size, lm.Bits)
	if err != nil {
		return nil, fmt.Errorf("publisher: wrap snapshot for %s: %w", lm.ID, err)
	}

	token, err := statuslist.BuildToken(p.key, statuslist.TokenParams{
		ListURL:  p.baseURL + "/lists/" + lm.ID,
		IssuedAt: time.Now(),
		TTL:      ttlSeconds,
		Bitmap:   bm,
		KeyID:    p.keyID,
	})
	if err != nil {
		return nil, fmt.Errorf("publisher: build token for %s: %w", lm.ID, err)
	}

	pub := &Published{Token: token, Version: liveVersion, Bits: lm.Bits, TTL: ttlSeconds}
	p.mu.Lock()
	p.cache[lm.ID] = pub
	p.mu.Unlock()
	return pub, nil
}

// Run polls for dirty lists every interval until ctx is canceled.
// Prototype scope only ever has one ACTIVE list plus, later, the
// occasional FROZEN one still accepting status updates; this is cheap to
// poll directly rather than needing a "dirty set" data structure yet.
func (p *Publisher) Run(ctx context.Context, interval time.Duration, listIDs func(context.Context) ([]*store.ListMeta, int64, error)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			lists, ttl, err := listIDs(ctx)
			if err != nil {
				slog.Error("publisher: list lookup failed", "error", err)
				continue
			}
			for _, lm := range lists {
				if _, err := p.PublishIfStale(ctx, lm, ttl); err != nil {
					slog.Error("publisher: publish failed", "list_id", lm.ID, "error", err)
				}
			}
		}
	}
}
