package api

import (
	"errors"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/sirosfoundation/siros-status-service/internal/allocator"
	"github.com/sirosfoundation/siros-status-service/internal/statuslist"
	"github.com/sirosfoundation/siros-status-service/internal/store"
)

type allocateRequest struct {
	Exp time.Time `json:"exp" binding:"required"`
}

type allocateResponse struct {
	ListURL string `json:"list_url"`
	Index   uint64 `json:"index"`
}

// maxAllocateAttempts bounds retries when the list picked by §8.1's
// power-of-two-choices gets filled or frozen by a concurrent request
// between selection and reservation. Each retry re-queries the ACTIVE
// pool fresh, so a stale candidate drops out immediately; this many
// attempts comfortably outlasts any realistic race without the request
// path needing to coordinate with internal/pool's background loop.
const maxAllocateAttempts = 5

// handleAllocate implements docs/design.md §14 item 3: "a minimal issuer
// API: POST /allocate ... only the credential's expiration is needed."
// List selection is §8.1's issuer-blind, power-of-two-choices placement
// across the ACTIVE pool (internal/pool), not a single fixed list.
func (s *Server) handleAllocate(c *gin.Context) {
	var req allocateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid request: " + err.Error()})
		return
	}

	ctx := c.Request.Context()
	issuerID := issuerFromContext(c)

	for range maxAllocateAttempts {
		lm, err := s.pool.PickForAllocation(ctx)
		if err != nil {
			c.JSON(500, gin.H{"error": "could not obtain an active list"})
			return
		}
		if lm == nil {
			c.JSON(503, gin.H{"error": "no active list available"})
			return
		}

		alloc, err := allocator.New(lm.FPEKey, lm.Size)
		if err != nil {
			c.JSON(500, gin.H{"error": "internal allocator error"})
			return
		}

		idx, err := s.meta.ReserveCursorAndRecord(ctx, lm.ID, issuerID, req.Exp, alloc.Index)
		if err != nil {
			if errors.Is(err, store.ErrListFull) {
				continue // §8.1: try again against a freshly-queried pool
			}
			c.JSON(500, gin.H{"error": "could not allocate an index"})
			return
		}

		c.JSON(201, allocateResponse{
			ListURL: s.cfg.BaseURL + "/lists/" + lm.ID,
			Index:   idx,
		})
		return
	}

	c.JSON(503, gin.H{"error": "could not allocate after retrying against the active pool; try again shortly"})
}

type setStatusRequest struct {
	Status string `json:"status" binding:"required"`
}

var statusNames = map[string]statuslist.Status{
	"VALID":     statuslist.StatusValid,
	"INVALID":   statuslist.StatusInvalid,
	"SUSPENDED": statuslist.StatusSuspended,
}

// handleSetStatus implements the PATCH /status/{listID}/{idx} half of
// §14 item 3, enforcing the server-side ownership lookup decided in §13.
func (s *Server) handleSetStatus(c *gin.Context) {
	listID := c.Param("listID")
	idx, err := strconv.ParseUint(c.Param("idx"), 10, 64)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid index"})
		return
	}

	var req setStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid request: " + err.Error()})
		return
	}
	status, ok := statusNames[req.Status]
	if !ok {
		c.JSON(400, gin.H{"error": "unknown status value; expected VALID, INVALID, or SUSPENDED"})
		return
	}

	issuerID := issuerFromContext(c)
	ctx := c.Request.Context()

	if err := s.meta.CheckOwnership(ctx, listID, idx, issuerID); err != nil {
		if errors.Is(err, store.ErrNotOwner) {
			c.JSON(403, gin.H{"error": "you do not own this index"})
			return
		}
		c.JSON(500, gin.H{"error": "could not verify ownership"})
		return
	}

	lm, err := s.meta.GetList(ctx, listID)
	if err != nil || lm == nil {
		c.JSON(404, gin.H{"error": "list not found"})
		return
	}
	if lm.State == "ARCHIVED" {
		// GC (§7 point 4) only archives once every credential in the
		// list has expired, so there's never a legitimate revocation
		// left to make here — reject rather than silently accepting a
		// write that can no longer affect anything a verifier would see.
		c.JSON(410, gin.H{"error": "this status list has been archived; no further updates are possible"})
		return
	}

	byteIndex, bitOffset := statuslist.ByteOffset(idx, lm.Bits)
	if _, err := s.bitmaps.SetStatus(ctx, listID, byteIndex, bitOffset, lm.Bits, byte(status)); err != nil {
		c.JSON(500, gin.H{"error": "could not update status"})
		return
	}

	c.Status(204)
}

// handleGetList implements the verifier-facing GET, including
// conditional-request support (docs/design.md §9).
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
		// docs/design.md §7/§13: keep serving the last-published token
		// for a retention window after archival (so a verifier that
		// checks late doesn't hit a dead link out of nowhere), then 410
		// Gone once that window has elapsed. Within the window this
		// falls through to the same publish path below — harmless,
		// since an archived list accepts no further writes (see
		// handleSetStatus), so PublishIfStale is just a cache hit after
		// its first rebuild.
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
