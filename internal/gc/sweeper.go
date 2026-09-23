// Package gc implements the list lifecycle's expiry/archival end
// (docs/design.md §7 point 4): FROZEN lists whose every credential has
// expired move to ARCHIVED, and ARCHIVED lists past their retention
// window have their Redis bitmap dropped, freeing hot storage.
//
// This is deliberately a separate, infrequent background job rather
// than folded into the request path (docs/design.md §12), the same
// design choice as internal/pool's rotation maintenance.
package gc

import (
	"context"
	"log/slog"
	"time"

	"github.com/sirosfoundation/siros-status-service/internal/store"
)

// Sweeper runs the two-phase archive/purge sweep.
type Sweeper struct {
	meta      *store.MetaStore
	bitmaps   *store.BitmapStore
	Grace     time.Duration // grace_period: buffer past max_exp before archiving
	Retention time.Duration // retention window: how long an archived list stays servable
}

func NewSweeper(meta *store.MetaStore, bitmaps *store.BitmapStore, grace, retention time.Duration) *Sweeper {
	return &Sweeper{meta: meta, bitmaps: bitmaps, Grace: grace, Retention: retention}
}

// Sweep runs one pass: archive what's earned it, then purge what's past
// retention. Archiving a list in this pass and purging it in the same
// pass would require Retention <= 0, which isn't a real configuration,
// so the two phases never need to interact within a single call.
func (s *Sweeper) Sweep(ctx context.Context) error {
	now := time.Now()

	frozen, err := s.meta.FrozenListsPastGrace(ctx, now.Add(-s.Grace))
	if err != nil {
		return err
	}
	for _, lm := range frozen {
		if err := s.meta.Archive(ctx, lm.ID); err != nil {
			return err
		}
		slog.Info("gc: archived list", "list_id", lm.ID, "max_exp", lm.MaxExp)
	}

	archived, err := s.meta.ArchivedListsPastRetention(ctx, now.Add(-s.Retention))
	if err != nil {
		return err
	}
	for _, lm := range archived {
		if err := s.bitmaps.Purge(ctx, lm.ID); err != nil {
			return err
		}
		if err := s.meta.MarkPurged(ctx, lm.ID); err != nil {
			return err
		}
		slog.Info("gc: purged list bitmap", "list_id", lm.ID, "archived_at", lm.ArchivedAt)
	}

	return nil
}

// Run calls Sweep on a fixed interval until ctx is canceled.
func (s *Sweeper) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.Sweep(ctx); err != nil {
				slog.Error("gc: sweep failed", "error", err)
			}
		}
	}
}
