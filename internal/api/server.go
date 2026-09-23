// Package api wires the minimal issuer- and verifier-facing HTTP surface
// described in docs/design.md §14 item 3: POST /allocate, PATCH /status,
// and a conditional-GET-aware GET /lists/{id}.
package api

import (
	"context"

	"github.com/gin-gonic/gin"

	"github.com/sirosfoundation/siros-status-service/internal/config"
	"github.com/sirosfoundation/siros-status-service/internal/pool"
	"github.com/sirosfoundation/siros-status-service/internal/publisher"
	"github.com/sirosfoundation/siros-status-service/internal/store"
)

type Server struct {
	cfg     *config.Config
	meta    *store.MetaStore
	bitmaps *store.BitmapStore
	pub     *publisher.Publisher
	pool    *pool.Manager
}

func New(cfg *config.Config, meta *store.MetaStore, bitmaps *store.BitmapStore, pub *publisher.Publisher, pm *pool.Manager) *Server {
	return &Server{cfg: cfg, meta: meta, bitmaps: bitmaps, pub: pub, pool: pm}
}

func (s *Server) Router() *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/healthz", s.handleHealthz)
	r.GET("/lists/:listID", s.handleGetList)

	authed := r.Group("/", issuerAuth(s.cfg.IssuerAPIKeys))
	authed.POST("/allocate", s.handleAllocate)
	authed.PATCH("/status/:listID/:idx", s.handleSetStatus)

	return r
}

// ListsForPublishing returns every list the publisher should consider —
// ACTIVE and FROZEN (§7 point 3: a frozen list still accepts status
// updates until it's archived) — along with the ttl to publish them
// with. See README "Known gaps" re: per-issuer/type ttl not yet existing.
func (s *Server) ListsForPublishing(ctx context.Context) ([]*store.ListMeta, int64, error) {
	lists, err := s.meta.LiveLists(ctx)
	if err != nil {
		return nil, 0, err
	}
	return lists, s.cfg.DefaultTTLSeconds, nil
}

func (s *Server) handleHealthz(c *gin.Context) {
	c.JSON(200, gin.H{"status": "ok"})
}
