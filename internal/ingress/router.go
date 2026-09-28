// Package ingress implements the JWT-claim-based routing described in
// docs/design.md §15.6: verify the caller's access token fully offline
// via go-tokenauth's validator (the same JWKS-cached mechanism every
// other consumer uses), read its tenant_id claim (this service's
// "shard", §15.5), and forward to that shard's configured backend.
// Issuers only ever see one router URL.
//
// One exception (§23): PATCH /status/{listID}/{idx} routes by the
// *list's own* embedded shard (internal/listid), not the token's
// tenant_id claim — a shard reassignment changes where an issuer's next
// allocation lands, not where their already-issued credentials live, so
// trusting tenant_id for a request naming an existing list would send it
// to the wrong shard the moment reassignment exists.
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

	"github.com/sirosfoundation/siros-status-service/internal/listid"
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

	// Route by the shard embedded in an existing list's own ID, not the
	// caller's current token claim, wherever a request names an existing
	// list — anything else (allocating a *new* index, self-service
	// accounting) has no existing list to be authoritative about, so the
	// token's current tenant_id claim is exactly right for those (docs/
	// design.md §23: a shard reassignment changes where an issuer's
	// *next* allocation lands, never where their already-issued
	// credentials live). Falls back to the token's claim for a list ID
	// that predates this scheme (no embedded shard) or whose embedded
	// shard isn't configured here — either way, tenant_id was the only
	// signal that existed before this, so it's the correct fallback, not
	// a new failure mode.
	shardID := result.TenantID
	if listID, ok := listIDFromStatusPath(req.URL.Path); ok {
		if s, ok := listid.ParseShard(listID); ok {
			if _, exists := r.proxies[s]; exists {
				shardID = s
			}
		}
	}

	proxy, ok := r.proxies[shardID]
	if !ok {
		metrics.IngressProxyTotal.WithLabelValues(shardID, "unknown_shard").Inc()
		http.Error(w, "no backend configured for this shard", http.StatusBadGateway)
		return
	}

	start := time.Now()
	proxy.ServeHTTP(w, req)
	metrics.IngressProxyDuration.WithLabelValues(shardID).Observe(time.Since(start).Seconds())
	metrics.IngressProxyTotal.WithLabelValues(shardID, "proxied").Inc()
}

// listIDFromStatusPath extracts {listID} from a PATCH /status/{listID}/{idx}
// request path — the one route where an existing list's own shard, not
// the caller's token claim, must decide routing (see ServeHTTP). Plain
// string splitting, not a full router: ingress-router deliberately has
// no route table of its own (docs/design.md §15.6 — it's a claim-routed
// proxy, not a second copy of cmd/ingestion-service's actual routes), so
// this only needs to recognize the one path shape that matters here,
// not validate the request the way cmd/ingestion-service's own gin
// route eventually will.
func listIDFromStatusPath(path string) (listID string, ok bool) {
	segments := strings.Split(strings.Trim(path, "/"), "/")
	if len(segments) != 3 || segments[0] != "status" || segments[1] == "" {
		return "", false
	}
	return segments[1], true
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
