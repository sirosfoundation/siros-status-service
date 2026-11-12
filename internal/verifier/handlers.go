package verifier

import (
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/sirosfoundation/siros-status-service/internal/store"
)

// jwtMediaType and cwtMediaType are the two Status List Token wire
// formats this service can serve (docs/design.md §27) — CWT is opt-in
// per request via Accept, JWT stays the unconditional default (an empty
// or `*/*` Accept, or no header at all, gets JWT — the format every
// client before this feature shipped already expects).
const (
	jwtMediaType = "application/statuslist+jwt"
	cwtMediaType = "application/statuslist+cwt"
)

// negotiateListFormat picks jwtMediaType or cwtMediaType from an Accept
// header, or "" if neither is acceptable (the caller then responds 406).
// This is deliberately simple string matching, not RFC 7231 §5.3.2
// q-value-weighted negotiation: gin has no built-in helper for a custom
// media type like ours, and the only two values that will ever appear on
// either side of this negotiation don't need one.
func negotiateListFormat(accept string) string {
	accept = strings.TrimSpace(accept)
	if accept == "" || accept == "*/*" {
		return jwtMediaType
	}
	for part := range strings.SplitSeq(accept, ",") {
		part = strings.TrimSpace(strings.SplitN(part, ";", 2)[0])
		switch part {
		case cwtMediaType:
			return cwtMediaType
		case jwtMediaType, "*/*":
			return jwtMediaType
		}
	}
	return ""
}

// handleGetList implements the verifier-facing GET, including
// conditional-request support (docs/design.md §9) and the archived-list
// retention-window/410 policy (§7 point 4, §13). It looks up shard_id
// from the (shared) Postgres row and lets internal/publisher (already
// shard-aware — see its package doc) pick the right shard's Redis.
func (s *Server) handleGetList(c *gin.Context) {
	ctx := c.Request.Context()
	lm := s.lookupServableList(c)
	if lm == nil {
		return
	}

	format := negotiateListFormat(c.GetHeader("Accept"))
	if format == "" {
		c.JSON(406, gin.H{"error": "Accept must include " + jwtMediaType + " or " + cwtMediaType})
		return
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
	if format == cwtMediaType {
		c.Data(200, cwtMediaType, pub.CWT)
		return
	}
	c.Data(200, jwtMediaType, []byte(pub.Token))
}

// jwksCacheSeconds is how long a relying party may cache a list's JWK
// Set. The signing key is static for the life of a deployment (key
// rotation is a redeploy), so this only bounds how quickly a rotated
// key becomes visible.
const jwksCacheSeconds = 300

// handleGetListJWKS serves the StatusListToken signing key as a JWK Set
// under the list's own URI (docs/design.md §28). A relying party's
// trust evaluator that binds a signer by discovering keys from the
// entity it is asked about — for a status list that entity is the
// token's `sub`, the list URI — fetches this document and matches the
// key that signed the token against it. The key is the same for every
// list this deployment serves; the document is still served per list,
// with the same 404/410 answers as the list itself, because the list
// URI is the identifier the trust decision is keyed on.
func (s *Server) handleGetListJWKS(c *gin.Context) {
	if s.lookupServableList(c) == nil {
		return
	}
	c.Header("Cache-Control", "public, max-age="+strconv.Itoa(jwksCacheSeconds))
	c.JSON(200, s.pub.JWKS())
}

// lookupServableList resolves the request's :listID to a list this
// service still serves. It returns nil after writing the response
// itself when the list is unknown (404), archived past its retention
// window (410, §7 point 4, §13), or the lookup failed (500).
func (s *Server) lookupServableList(c *gin.Context) *store.ListMeta {
	lm, err := s.meta.GetList(c.Request.Context(), c.Param("listID"))
	if err != nil {
		c.JSON(500, gin.H{"error": "lookup failed"})
		return nil
	}
	if lm == nil {
		c.JSON(404, gin.H{"error": "list not found"})
		return nil
	}
	if lm.State == "ARCHIVED" {
		// Keep serving the last-published token for a retention window
		// after archival (so a verifier that checks late doesn't hit a
		// dead link out of nowhere), then 410 Gone once that window has
		// elapsed. Within the window handleGetList falls through to its
		// usual publish path — harmless, since an archived list accepts
		// no further writes (internal/ingestion enforces this), so
		// PublishIfStale is just a cache hit after its first rebuild.
		if lm.ArchivedAt == nil || time.Since(*lm.ArchivedAt) > s.cfg.GCRetentionPeriod {
			c.JSON(410, gin.H{"error": "this status list has been archived"})
			return nil
		}
	}
	return lm
}
