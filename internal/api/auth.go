package api

import (
	"strings"

	"github.com/gin-gonic/gin"
)

const issuerContextKey = "issuer_id"

// noAuthIssuerID is the fixed issuer_id used when no ISSUER_API_KEYS are
// configured at all. It exists only to make manual/exploratory testing
// against a deployed instance easy (no bearer token to manage); it is
// not a real multi-tenancy mechanism, since every unauthenticated caller
// shares one identity and can therefore revoke/suspend every other
// unauthenticated caller's allocations (docs/design.md §13's ownership
// check still applies — it just isn't distinguishing anyone in this mode).
const noAuthIssuerID = "anonymous"

// issuerAuth is a deliberately minimal prototype-only authentication
// scheme: a static map of bearer token -> issuer_id (see
// internal/config's package doc). It's enough to exercise the ownership
// check in docs/design.md §13 without building real issuer onboarding.
//
// If apiKeys is empty, auth is skipped entirely and every request is
// treated as noAuthIssuerID — a deliberate escape hatch for quick
// exploratory deployments, not a production posture.
func issuerAuth(apiKeys map[string]string) gin.HandlerFunc {
	if len(apiKeys) == 0 {
		return func(c *gin.Context) {
			c.Set(issuerContextKey, noAuthIssuerID)
			c.Next()
		}
	}
	return func(c *gin.Context) {
		authz := c.GetHeader("Authorization")
		token, ok := strings.CutPrefix(authz, "Bearer ")
		if !ok || token == "" {
			c.AbortWithStatusJSON(401, gin.H{"error": "missing or malformed Authorization header"})
			return
		}
		issuerID, ok := apiKeys[token]
		if !ok {
			c.AbortWithStatusJSON(401, gin.H{"error": "unknown API key"})
			return
		}
		c.Set(issuerContextKey, issuerID)
		c.Next()
	}
}

func issuerFromContext(c *gin.Context) string {
	v, _ := c.Get(issuerContextKey)
	id, _ := v.(string)
	return id
}
