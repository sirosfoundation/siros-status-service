package ingestion

import (
	"github.com/gin-gonic/gin"

	"github.com/sirosfoundation/go-tokenauth/tokengin"
)

// requireShard rejects a token whose tenant_id (this service's "shard",
// docs/design.md §15.5) doesn't match shardID. The ingress router
// (§15.6) should never route a request here otherwise, but this is
// defense in depth against a misconfigured router or a request that
// reached this node directly. Must run after tokengin.TokenAuth.
func requireShard(shardID string) gin.HandlerFunc {
	return func(c *gin.Context) {
		result, ok := tokengin.GetResult(c)
		if !ok {
			c.AbortWithStatusJSON(401, gin.H{"error": "no authentication context"})
			return
		}
		if result.TenantID != shardID {
			c.AbortWithStatusJSON(403, gin.H{"error": "token is not authorized for this shard"})
			return
		}
		c.Next()
	}
}

// issuerFromContext returns the caller's issuer identity, established by
// tokengin.TokenAuth from the access token's `sub` claim.
func issuerFromContext(c *gin.Context) string {
	result, ok := tokengin.GetResult(c)
	if !ok {
		return ""
	}
	return result.UserID
}
