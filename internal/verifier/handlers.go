package verifier

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// handleGetList implements the verifier-facing GET, including
// conditional-request support (docs/design.md §9) and the archived-list
// retention-window/410 policy (§7 point 4, §13). It looks up shard_id
// from the (shared) Postgres row and lets internal/publisher (already
// shard-aware — see its package doc) pick the right shard's Redis.
func (s *Server) handleGetList(c *gin.Context) {
	listID := c.Param("listID")
	ctx := c.Request.Context()

	lm, err := s.meta.GetList(ctx, listID)
	if err != nil {
		c.JSON(500, gin.H{"error": "lookup failed"})
		return
	}
	if lm == nil {
		c.JSON(404, gin.H{"error": "list not found"})
		return
	}
	if lm.State == "ARCHIVED" {
		// Keep serving the last-published token for a retention window
		// after archival (so a verifier that checks late doesn't hit a
		// dead link out of nowhere), then 410 Gone once that window has
		// elapsed. Within the window this falls through to the same
		// publish path below — harmless, since an archived list accepts
		// no further writes (internal/ingestion enforces this), so
		// PublishIfStale is just a cache hit after its first rebuild.
		if lm.ArchivedAt == nil || time.Since(*lm.ArchivedAt) > s.cfg.GCRetentionPeriod {
			c.JSON(410, gin.H{"error": "this status list has been archived"})
			return
		}
	}

	pub, err := s.pub.PublishIfStale(ctx, lm, s.cfg.DefaultTTLSeconds)
	if err != nil {
		c.JSON(500, gin.H{"error": "could not publish list"})
		return
	}

	etag := `"` + strconv.FormatInt(pub.Version, 10) + `"`
	if match := c.GetHeader("If-None-Match"); match == etag {
		c.Status(304)
		return
	}

	c.Header("ETag", etag)
	c.Header("Cache-Control", "public, max-age="+strconv.FormatInt(pub.TTL, 10))
	c.Data(200, "application/statuslist+jwt", []byte(pub.Token))
}
