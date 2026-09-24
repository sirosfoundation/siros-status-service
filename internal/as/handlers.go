package as

import (
	"crypto/subtle"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/sirosfoundation/siros-status-service/internal/accesstoken"
	"github.com/sirosfoundation/siros-status-service/internal/clientassertion"
)

const (
	grantTypeClientCredentials   = "client_credentials"
	clientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

// handleToken implements the client-credentials grant with a JWT-bearer
// client assertion (RFC 7523 §2.2) — docs/design.md §15.2. The issuer's
// self-signed assertion is both their proof of possession and, once
// trust.Evaluator confirms the key is trusted, their entire
// authentication — there's no separate registered client secret.
func (s *Server) handleToken(c *gin.Context) {
	if c.PostForm("grant_type") != grantTypeClientCredentials {
		c.JSON(400, gin.H{"error": "unsupported_grant_type"})
		return
	}
	if c.PostForm("client_assertion_type") != clientAssertionTypeJWTBearer {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "client_assertion_type must be " + clientAssertionTypeJWTBearer})
		return
	}
	assertion := c.PostForm("client_assertion")
	if assertion == "" {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "client_assertion is required"})
		return
	}

	result, err := clientassertion.Verify(assertion, s.cfg.BaseURL+"/token")
	if err != nil {
		c.JSON(401, gin.H{"error": "invalid_client", "error_description": "client assertion did not verify"})
		return
	}

	ctx := c.Request.Context()
	decision, err := s.evaluator.Evaluate(ctx, result.IssuerID, result.JWK)
	if err != nil {
		c.JSON(500, gin.H{"error": "server_error", "error_description": "trust evaluation failed"})
		return
	}
	if !decision.Trusted {
		c.JSON(401, gin.H{"error": "invalid_client", "error_description": "key is not trusted: " + decision.Reason})
		return
	}

	shardID, err := s.shards.AssignOrLookup(ctx, result.IssuerID)
	if err != nil {
		c.JSON(500, gin.H{"error": "server_error", "error_description": "shard assignment failed"})
		return
	}

	expiresIn := s.cfg.AccessTokenTTL
	token, err := s.km.Issue(accesstoken.IssueParams{
		Issuer:   s.cfg.BaseURL,
		Audience: s.cfg.AccessTokenAudience,
		Subject:  result.IssuerID,
		TenantID: shardID,
		// riw: read (accounting), insert (allocate), write (status
		// updates) — the full set this prototype's single token class
		// needs; go-tokenauth's tokengin.MustHaveTAC then enforces the
		// narrower per-route requirement (see internal/ingestion).
		TAC: "riw",
		TTL: expiresIn,
	})
	if err != nil {
		c.JSON(500, gin.H{"error": "server_error", "error_description": "could not mint token"})
		return
	}

	c.JSON(200, tokenResponse{AccessToken: token, TokenType: "Bearer", ExpiresIn: int64(expiresIn.Seconds())})
}

type registerIssuerRequest struct {
	IssuerID string         `json:"issuer_id" binding:"required"`
	JWK      map[string]any `json:"jwk" binding:"required"`
}

// handleRegisterIssuer is the admin operation backing
// StaticRegistryEvaluator (docs/design.md §15.8: "no self-service flow
// yet"). Gated by a static admin token — a prototype-appropriate
// simplification of the same kind as internal/api's earlier no-auth mode,
// not a real admin-authentication story.
func (s *Server) handleRegisterIssuer(c *gin.Context) {
	authz := c.GetHeader("Authorization")
	token, ok := strings.CutPrefix(authz, "Bearer ")
	if !ok || subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.AdminToken)) != 1 {
		c.AbortWithStatusJSON(401, gin.H{"error": "missing or invalid admin token"})
		return
	}

	var req registerIssuerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid request: " + err.Error()})
		return
	}

	if err := s.registry.Register(c.Request.Context(), req.IssuerID, req.JWK); err != nil {
		c.JSON(500, gin.H{"error": "could not register issuer"})
		return
	}
	c.Status(204)
}
