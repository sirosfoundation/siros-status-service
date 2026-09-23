// Package publisher builds and caches signed StatusListTokens from the
// live Redis bitmap, decoupled from individual status writes
// (docs/design.md §9).
//
// Publishing has two paths that both call the same idempotent
// PublishIfStale, so they never conflict:
//
//   - MarkDirty, called right after a status write succeeds, implements
//     §9's debounce literally: "at most every ttl seconds (or
//     immediately if idle)" via leadingDebouncer (debounce.go). A write
//     to a list that hasn't been republished within its own ttl window
//     publishes right away; a burst of writes within that window
//     coalesces into a single deferred publish timed for exactly when
//     the window reopens, bounding resign/compress cost under load.
//   - Run polls on a fixed interval and republishes any list whose live
//     version has moved past what was last cached. With MarkDirty in
//     place this is now a backstop rather than the primary mechanism —
//     it exists so a list is never left stale indefinitely if
//     MarkDirty's in-memory debounce state is lost (e.g. a restart
//     between a write and its scheduled publish).
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

	debounce *leadingDebouncer
}

func New(bitmaps *store.BitmapStore, meta *store.MetaStore, key *ecdsa.PrivateKey, keyID, baseURL string) *Publisher {
	return &Publisher{
		bitmaps:  bitmaps,
		meta:     meta,
		key:      key,
		keyID:    keyID,
		baseURL:  baseURL,
		cache:    make(map[string]*Published),
		debounce: newLeadingDebouncer(),
	}
}

// MarkDirty schedules a publish for listID shortly after a status write
// succeeds — see the package doc for how the debounce/coalescing works.
// ttlSeconds is the same value that will be embedded in the token, so
// the debounce floor never publishes more often than what verifiers are
// told they may cache for.
func (p *Publisher) MarkDirty(listID string, ttlSeconds int64) {
	floor := time.Duration(ttlSeconds) * time.Second
	p.debounce.Trigger(listID, floor, func() {
		ctx, cancel := context.WithTimeout(context.Background(), dirtyPublishTimeout)
		defer cancel()

		lm, err := p.meta.GetList(ctx, listID)
		if err != nil || lm == nil {
			slog.Error("publisher: dirty-triggered lookup failed", "list_id", listID, "error", err)
			return
		}
		if _, err := p.PublishIfStale(ctx, lm, ttlSeconds); err != nil {
			slog.Error("publisher: dirty-triggered publish failed", "list_id", listID, "error", err)
		}
	})
}

// dirtyPublishTimeout bounds a MarkDirty-triggered publish, which runs
// detached from any request context (the HTTP handler that called
// MarkDirty has typically already returned its response by the time
// this fires).
const dirtyPublishTimeout = 30 * time.Second

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
	slog.Debug("publisher: rebuilt token", "list_id", lm.ID, "version", liveVersion)
	return pub, nil
}

// Run polls every interval and republishes any stale list until ctx is
// canceled. See the package doc: with MarkDirty handling the common
// case, this is a backstop, not the primary publish path — cheap to run
// since PublishIfStale is a no-op for anything already up to date.
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
