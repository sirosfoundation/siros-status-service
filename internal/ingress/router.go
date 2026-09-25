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
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	gojosejwt "github.com/go-jose/go-jose/v4/jwt"
	golangjwt "github.com/golang-jwt/jwt/v5"

	tokenauthvalidator "github.com/sirosfoundation/go-tokenauth/validator"

	"github.com/sirosfoundation/siros-status-service/internal/metrics"
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
		// Built via Rewrite (not NewSingleHostReverseProxy's Director,
		// which leaves the outbound Host header as the inbound request's
		// original Host) — harmless against a plain backend, but each
		// shard backend here is itself a separate Fly app reachable only
		// over its own public *.fly.dev hostname (docs/design.md §18: no
		// private networking between these apps). Fly's edge picks the
		// destination app from the TLS SNI (correctly, the shard's
		// hostname, from target.Host) but then finds the HTTP Host header
		// names a DIFFERENT app — an authority mismatch it rejects with
		// 421 Misdirected Request (RFC 7540 §9.1.2), before the request
		// ever reaches the shard's own handler. Found live against the
		// real multi-region deployment (unit tests use httptest backends,
		// which don't enforce SNI/Host agreement, so this never surfaced
		// there). Setting pr.Out.Host = target.Host keeps SNI and Host in
		// agreement.
		proxies[shardID] = &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetURL(target)
				pr.Out.Host = target.Host
			},
		}
	}
	return &Router{validator: validator, proxies: proxies}, nil
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	token, ok := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		// RFC 6750 §3: the request itself is malformed (no bearer
		// token was even presented), as distinct from a bearer token
		// that was presented but rejected.
		metrics.IngressProxyTotal.WithLabelValues("", "missing_token").Inc()
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_request"`)
		http.Error(w, "missing or malformed Authorization header", http.StatusUnauthorized)
		return
	}

	result, err := r.validator.Validate(req.Context(), token)
	if err != nil {
		result := "invalid_token"
		if errors.Is(err, gojosejwt.ErrExpired) || errors.Is(err, golangjwt.ErrTokenExpired) {
			result = "expired_token"
		}
		metrics.IngressProxyTotal.WithLabelValues("", result).Inc()
		w.Header().Set("WWW-Authenticate", bearerInvalidTokenChallenge(err))
		http.Error(w, "invalid access token", http.StatusUnauthorized)
		return
	}

	proxy, ok := r.proxies[result.TenantID]
	if !ok {
		metrics.IngressProxyTotal.WithLabelValues(result.TenantID, "unknown_shard").Inc()
		http.Error(w, "no backend configured for this token's shard", http.StatusBadGateway)
		return
	}

	start := time.Now()
	proxy.ServeHTTP(w, req)
	metrics.IngressProxyDuration.WithLabelValues(result.TenantID).Observe(time.Since(start).Seconds())
	metrics.IngressProxyTotal.WithLabelValues(result.TenantID, "proxied").Inc()
}

// bearerInvalidTokenChallenge builds the RFC 6750 §3 WWW-Authenticate
// challenge for a rejected bearer token, distinguishing an expired
// token (via the expiry sentinels from both the asymmetric-token path,
// which validates claims with go-jose/go-jose's jwt package, and the
// legacy HMAC path, which uses golang-jwt/jwt/v5) from every other
// rejection reason. There is no separate "expired" error code in RFC
// 6750 — expiry is signaled via error_description on invalid_token.
func bearerInvalidTokenChallenge(err error) string {
	description := "the access token is invalid"
	if errors.Is(err, gojosejwt.ErrExpired) || errors.Is(err, golangjwt.ErrTokenExpired) {
		description = "the access token expired"
	}
	return `Bearer error="invalid_token", error_description="` + description + `"`
}
