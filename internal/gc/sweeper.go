// Package gc implements the list lifecycle's expiry/archival end
// (docs/design.md §7 point 4): FROZEN lists whose every credential has
// expired move to ARCHIVED, ARCHIVED lists past their retention window
// have their Redis bitmap dropped, and (opt-in, §22) purged lists past a
// second, independently-configured retention window have their Postgres
// row — and every allocation recorded against it — hard-deleted.
//
// This is deliberately a separate, infrequent background job rather
// than folded into the request path (docs/design.md §12), the same
// design choice as internal/pool's rotation maintenance.
package gc

import (
	"context"
	"log/slog"
	"time"

	"github.com/sirosfoundation/siros-status-service/internal/metrics"
	"github.com/sirosfoundation/siros-status-service/internal/store"
)

// Sweeper runs the three-phase archive/purge/delete sweep.
type Sweeper struct {
	meta      *store.MetaStore
	bitmaps   *store.BitmapStore
	Grace     time.Duration // grace_period: buffer past max_exp before archiving
	Retention time.Duration // retention window: how long an archived list stays servable
	// DBRetention is how long after a list's Redis bitmap is purged
	// before its Postgres row (and every allocation recorded against it)
	// is hard-deleted (§22). Zero — the default — disables this phase
	// entirely: rows are kept forever, matching this service's original
	// behavior, since some deployments have real audit-history/
	// compliance reasons to never delete them. Enable deliberately once
	// that tradeoff has actually been made for a given deployment.
	DBRetention time.Duration
}

func NewSweeper(meta *store.MetaStore, bitmaps *store.BitmapStore, grace, retention, dbRetention time.Duration) *Sweeper {
	return &Sweeper{meta: meta, bitmaps: bitmaps, Grace: grace, Retention: retention, DBRetention: dbRetention}
}

// Sweep runs one pass: archive what's earned it, purge what's past
// retention, then (if DBRetention > 0) hard-delete what's past that.
// Archiving a list in this pass and purging it in the same pass would
// require Retention <= 0, which isn't a real configuration, so the
// phases never need to interact within a single call — same reasoning
// extends to the delete phase and DBRetention.
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
		metrics.IngestionGCArchivedTotal.WithLabelValues(lm.ShardID).Inc()
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
		metrics.IngestionGCPurgedTotal.WithLabelValues(lm.ShardID).Inc()
		slog.Info("gc: purged list bitmap", "list_id", lm.ID, "archived_at", lm.ArchivedAt)
	}

	if s.DBRetention <= 0 {
		return nil
	}
	purged, err := s.meta.PurgedListsPastDBRetention(ctx, now.Add(-s.DBRetention))
	if err != nil {
		return err
	}
	for _, lm := range purged {
		if err := s.meta.DeleteList(ctx, lm.ID); err != nil {
			return err
		}
		metrics.IngestionGCRowsDeletedTotal.WithLabelValues(lm.ShardID).Inc()
		slog.Info("gc: deleted list row and its allocations", "list_id", lm.ID, "purged_at", lm.PurgedAt)
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
