// Package as is the Authorization Server described in docs/design.md
// §15.2: verifies an issuer's client-assertion (proof of possession of
// their own signing key), asks a trust.Evaluator whether that key is
// trusted, and — if so — mints an offline-verifiable access token
// (§15.3) naming the issuer's assigned shard (§15.5).
package as

import (
	"github.com/gin-gonic/gin"

	"github.com/sirosfoundation/siros-status-service/internal/accesstoken"
	"github.com/sirosfoundation/siros-status-service/internal/config"
	"github.com/sirosfoundation/siros-status-service/internal/trust"
)

type Server struct {
	cfg       *config.ASConfig
	km        *accesstoken.KeyManager
	evaluator trust.Evaluator
	registry  *trust.StaticRegistryEvaluator
	shards    *ShardAssigner
}

func New(cfg *config.ASConfig, km *accesstoken.KeyManager, evaluator trust.Evaluator, registry *trust.StaticRegistryEvaluator, shards *ShardAssigner) *Server {
	return &Server{cfg: cfg, km: km, evaluator: evaluator, registry: registry, shards: shards}
}

func (s *Server) Router() *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/healthz", s.handleHealthz)
	r.GET("/.well-known/jwks.json", s.handleJWKS)
	r.POST("/token", s.handleToken)
	r.POST("/admin/issuers", s.handleRegisterIssuer)

	return r
}

func (s *Server) handleHealthz(c *gin.Context) {
	c.JSON(200, gin.H{"status": "ok"})
}

func (s *Server) handleJWKS(c *gin.Context) {
	c.JSON(200, s.km.JWKS())
}
