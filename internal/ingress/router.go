// Package ingress implements the JWT-claim-based routing described in
// docs/design.md §15.6: verify the caller's access token fully offline
// via go-tokenauth's validator (the same JWKS-cached mechanism every
// other consumer uses), read its tenant_id claim (this service's
// "shard", §15.5), and forward to that shard's configured backend.
// Issuers only ever see one router URL; the token's tenant_id, not
// anything the issuer supplies directly, decides where their traffic
// lands.
package ingress

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	tokenauthvalidator "github.com/sirosfoundation/go-tokenauth/validator"
)

// Router verifies inbound requests and reverse-proxies them to the
// backend named by the token's tenant_id (shard) claim.
type Router struct {
	validator *tokenauthvalidator.Validator
	proxies   map[string]*httputil.ReverseProxy // shard_id -> pre-built proxy
}

// New builds a Router. backends maps shard_id -> that shard's ingestion
// service base URL (e.g. "http://ingestion-a:8080").
func New(validator *tokenauthvalidator.Validator, backends map[string]string) (*Router, error) {
	proxies := make(map[string]*httputil.ReverseProxy, len(backends))
	for shardID, backend := range backends {
		target, err := url.Parse(backend)
		if err != nil {
			return nil, err
		}
		proxies[shardID] = httputil.NewSingleHostReverseProxy(target)
	}
	return &Router{validator: validator, proxies: proxies}, nil
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	token, ok := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		http.Error(w, "missing or malformed Authorization header", http.StatusUnauthorized)
		return
	}

	result, err := r.validator.Validate(req.Context(), token)
	if err != nil {
		http.Error(w, "invalid access token", http.StatusUnauthorized)
		return
	}

	proxy, ok := r.proxies[result.TenantID]
	if !ok {
		http.Error(w, "no backend configured for this token's shard", http.StatusBadGateway)
		return
	}
	proxy.ServeHTTP(w, req)
}
