// Package ingestion is the issuer-facing half of the split described in
// docs/design.md §15.1: POST /allocate, PATCH /status, and
// GET /accounting/me. It never serves verifier reads — that's
// internal/verifier, a separate service entirely.
package ingestion

import (
	"context"

	"github.com/gin-gonic/gin"

	"github.com/sirosfoundation/go-tokenauth/tokengin"
	tokenauthvalidator "github.com/sirosfoundation/go-tokenauth/validator"

	"github.com/sirosfoundation/siros-status-service/internal/config"
	"github.com/sirosfoundation/siros-status-service/internal/pool"
	"github.com/sirosfoundation/siros-status-service/internal/publisher"
	"github.com/sirosfoundation/siros-status-service/internal/store"
)

type Server struct {
	cfg       *config.IngestionConfig
	meta      *store.MetaStore
	bitmaps   *store.BitmapStore
	pub       *publisher.Publisher
	pool      *pool.Manager
	validator *tokenauthvalidator.Validator
}

func New(cfg *config.IngestionConfig, meta *store.MetaStore, bitmaps *store.BitmapStore, pub *publisher.Publisher, pm *pool.Manager, validator *tokenauthvalidator.Validator) *Server {
	return &Server{cfg: cfg, meta: meta, bitmaps: bitmaps, pub: pub, pool: pm, validator: validator}
}

// TAC requirements per route (docs/design.md §15.4's accounting is a
// read; allocation creates a new index; status updates write to an
// existing one — go-tokenauth's TAC gives real per-route permission
// granularity for free once tokens carry it).
const (
	tacAllocate   = "i" // insert: create a new index
	tacSetStatus  = "w" // write: update an existing index
	tacAccounting = "r" // read
)

func (s *Server) Router() *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/healthz", s.handleHealthz)

	authed := r.Group("/", tokengin.TokenAuth(s.validator), requireShard(s.cfg.ShardID))
	authed.POST("/allocate", tokengin.MustHaveTAC(tacAllocate), s.handleAllocate)
	authed.PATCH("/status/:listID/:idx", tokengin.MustHaveTAC(tacSetStatus), s.handleSetStatus)
	authed.GET("/accounting/me", tokengin.MustHaveTAC(tacAccounting), s.handleAccountingMe)

	return r
}

// ListsForPublishing feeds internal/publisher's periodic backstop
// (docs/design.md §9): every ACTIVE/FROZEN list in this shard.
func (s *Server) ListsForPublishing(ctx context.Context) ([]*store.ListMeta, int64, error) {
	lists, err := s.meta.LiveLists(ctx, s.cfg.ShardID)
	if err != nil {
		return nil, 0, err
	}
	return lists, s.cfg.DefaultTTLSeconds, nil
}

func (s *Server) handleHealthz(c *gin.Context) {
	c.JSON(200, gin.H{"status": "ok", "shard": s.cfg.ShardID})
}
