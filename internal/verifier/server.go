// Package verifier is the read-only, unauthenticated half of the split
// described in docs/design.md §15.1: GET /lists/{id} only. It never
// handles issuer writes — that's internal/ingestion, a separate service
// (and, per shard, a separate process) entirely.
package verifier

import (
	"github.com/gin-gonic/gin"

	"github.com/sirosfoundation/siros-status-service/internal/config"
	"github.com/sirosfoundation/siros-status-service/internal/metrics"
	"github.com/sirosfoundation/siros-status-service/internal/publisher"
	"github.com/sirosfoundation/siros-status-service/internal/store"
)

type Server struct {
	cfg  *config.VerifierConfig
	meta *store.MetaStore
	pub  *publisher.Publisher
}

func New(cfg *config.VerifierConfig, meta *store.MetaStore, pub *publisher.Publisher) *Server {
	return &Server{cfg: cfg, meta: meta, pub: pub}
}

func (s *Server) Router() *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery(), metrics.GinMiddleware())

	r.GET("/healthz", s.handleHealthz)
	r.GET("/lists/:listID", s.handleGetList)
	r.GET("/metrics", gin.WrapH(metrics.Handler()))

	return r
}

func (s *Server) handleHealthz(c *gin.Context) {
	c.JSON(200, gin.H{"status": "ok"})
}
