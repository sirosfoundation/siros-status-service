package ingestion

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/sirosfoundation/siros-status-service/internal/allocator"
	"github.com/sirosfoundation/siros-status-service/internal/statuslist"
	"github.com/sirosfoundation/siros-status-service/internal/store"
)

// Exp is optional (docs/design.md §19): a request that omits it gets
// exactly the maximum allowed expiration (MaxExpiry from now), not an
// arbitrary short default. binding:"required" was removed for exactly
// this reason — a zero-value Exp (the JSON field absent) is a real,
// meaningful "give me the max" request, not an error.
type allocateRequest struct {
	Exp time.Time `json:"exp"`
}

type allocateResponse struct {
	ListURL string    `json:"list_url"`
	Index   uint64    `json:"index"`
	Exp     time.Time `json:"exp"`
}

// maxAllocateAttempts bounds retries when the list picked by §8.1's
// power-of-two-choices gets filled or frozen by a concurrent request
// between selection and reservation. Each retry re-queries the ACTIVE
// pool fresh, so a stale candidate drops out immediately; this many
// attempts comfortably outlasts any realistic race without the request
// path needing to coordinate with internal/pool's background loop.
const maxAllocateAttempts = 5

// handleAllocate implements docs/design.md §14 item 3 / §15.1/§19: the
// caller's issuer identity comes from their verified access token
// (§15.3), not a request field, and `exp` is optional — omitting it
// returns the maximum allowed expiration (§19's MaxExpiry), and naming
// one further out than that is rejected outright rather than silently
// clamped, so an issuer never gets a shorter-lived credential than they
// asked for without knowing it.
func (s *Server) handleAllocate(c *gin.Context) {
	var req allocateRequest
	// A request body is optional (empty/absent means "no exp given" —
	// see allocateRequest's doc comment); ShouldBindJSON on a genuinely
	// empty body would otherwise fail with "EOF" before ever reaching the
	// zero-value-Exp handling below.
	if c.Request.ContentLength != 0 {
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": "invalid request: " + err.Error()})
			return
		}
	}

	maxExp := time.Now().Add(s.cfg.MaxExpiry)
	exp := req.Exp
	switch {
	case exp.IsZero():
		exp = maxExp
	case exp.After(maxExp):
		c.JSON(400, gin.H{"error": fmt.Sprintf("exp exceeds the maximum allowed expiration of %s", maxExp.Format(time.RFC3339))})
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

		idx, err := s.meta.ReserveCursorAndRecord(ctx, lm.ID, issuerID, s.cfg.ShardID, exp, alloc.Index)
		if err != nil {
			if errors.Is(err, store.ErrListFull) {
				continue // §8.1: try again against a freshly-queried pool
			}
			c.JSON(500, gin.H{"error": "could not allocate an index"})
			return
		}

		// Explicit reset to VALID (docs/design.md §17): allocation used to
		// be metadata-only, relying on the bitmap's zero-initialization to
		// make a fresh index read VALID. Now that internal/decoy can write
		// camouflage noise into never-yet-allocated capacity, a newly
		// allocated index might have decoy noise sitting on it from before
		// it was handed out — this write unconditionally clears that,
		// before the response (and therefore the index) ever reaches the
		// issuer. internal/decoy never targets a position once its cursor
		// slot has been consumed, so this is a one-time reset, not an
		// ongoing race.
		byteIndex, bitOffset := statuslist.ByteOffset(idx, lm.Bits)
		if _, err := s.bitmaps.SetStatus(ctx, lm.ID, byteIndex, bitOffset, lm.Bits, byte(statuslist.StatusValid)); err != nil {
			c.JSON(500, gin.H{"error": "could not initialize allocated index"})
			return
		}
		s.pub.MarkDirty(lm.ID, s.cfg.DefaultTTLSeconds)

		c.JSON(201, allocateResponse{
			ListURL: s.cfg.BaseURL + "/lists/" + lm.ID,
			Index:   idx,
			Exp:     exp,
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

// handleSetStatus implements PATCH /status/{listID}/{idx}, enforcing the
// server-side ownership lookup decided in §13.
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

	// docs/design.md §9: publish immediately if idle, or coalesce into
	// the debounce window if not — see internal/publisher's package doc.
	// Scheduling only; does not block this response on a rebuild+sign.
	s.pub.MarkDirty(listID, s.cfg.DefaultTTLSeconds)

	c.Status(204)
}

type usageResponse struct {
	ShardID    string `json:"shard_id"`
	IndexCount int64  `json:"index_count"`
}

// handleAccountingMe implements docs/design.md §15.4: self-service usage
// lookup, scoped to the caller's own issuer identity from their access
// token — no separate admin auth needed for a number issuers already
// have every incentive to track honestly.
func (s *Server) handleAccountingMe(c *gin.Context) {
	issuerID := issuerFromContext(c)
	usage, err := s.meta.GetUsage(c.Request.Context(), issuerID)
	if err != nil {
		c.JSON(500, gin.H{"error": "could not look up usage"})
		return
	}

	out := make([]usageResponse, 0, len(usage))
	for _, u := range usage {
		out = append(out, usageResponse{ShardID: u.ShardID, IndexCount: u.IndexCount})
	}
	c.JSON(200, gin.H{"issuer_id": issuerID, "usage": out})
}
