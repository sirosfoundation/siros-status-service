package ingress

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	tokenauthvalidator "github.com/sirosfoundation/go-tokenauth/validator"

	"github.com/sirosfoundation/siros-status-service/internal/accesstoken"
)

const (
	testIssuer   = "https://as.example.org"
	testAudience = "siros-status-service"
)

func testValidator(t *testing.T) (*accesstoken.KeyManager, *tokenauthvalidator.Validator) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	km := accesstoken.NewKeyManager(key, "as-key-1")

	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(km.JWKS())
	}))
	t.Cleanup(jwksSrv.Close)

	v := tokenauthvalidator.New(tokenauthvalidator.Config{
		JWKSURL:   jwksSrv.URL,
		Issuer:    testIssuer,
		Audiences: []string{testAudience},
	})
	v.Start(t.Context())
	t.Cleanup(v.Stop)
	return km, v
}

func issueToken(t *testing.T, km *accesstoken.KeyManager, shard string) string {
	t.Helper()
	token, err := km.Issue(accesstoken.IssueParams{
		Issuer:   testIssuer,
		Audience: testAudience,
		Subject:  "issuer-a",
		TenantID: shard,
		TAC:      "riw",
		TTL:      time.Hour,
	})
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	return token
}

func backendServer(t *testing.T, name string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", name)
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestRouter_RoutesByShardClaim(t *testing.T) {
	km, validator := testValidator(t)
	shardA := backendServer(t, "shard-a")
	shardB := backendServer(t, "shard-b")

	router, err := New(validator, map[string]string{"shard-a": shardA.URL, "shard-b": shardB.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	proxySrv := httptest.NewServer(router)
	defer proxySrv.Close()

	for _, tc := range []struct {
		shard, wantBackend string
	}{
		{"shard-a", "shard-a"},
		{"shard-b", "shard-b"},
	} {
		req, _ := http.NewRequest(http.MethodPost, proxySrv.URL+"/allocate", nil)
		req.Header.Set("Authorization", "Bearer "+issueToken(t, km, tc.shard))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request for shard %s: %v", tc.shard, err)
		}
		_ = resp.Body.Close()
		if got := resp.Header.Get("X-Backend"); got != tc.wantBackend {
			t.Errorf("shard %s routed to backend %q, want %q", tc.shard, got, tc.wantBackend)
		}
	}
}

// TestRouter_ForwardsWithBackendHost guards against a real bug found
// against the live multi-region deployment: NewSingleHostReverseProxy
// leaves the outbound Host header as the router's own inbound Host,
// which a plain httptest backend never notices (it dispatches on
// connection, not Host) but which Fly's edge rejects with 421 when a
// shard backend is itself a separate Fly app reachable only by its own
// public hostname (see router.go's New for the full explanation).
func TestRouter_ForwardsWithBackendHost(t *testing.T) {
	km, validator := testValidator(t)

	var gotHost string
	shardA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.WriteHeader(200)
	}))
	defer shardA.Close()
	shardAURL, err := url.Parse(shardA.URL)
	if err != nil {
		t.Fatalf("parse shard URL: %v", err)
	}

	router, err := New(validator, map[string]string{"shard-a": shardA.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	proxySrv := httptest.NewServer(router)
	defer proxySrv.Close()

	req, _ := http.NewRequest(http.MethodPost, proxySrv.URL+"/allocate", nil)
	req.Header.Set("Authorization", "Bearer "+issueToken(t, km, "shard-a"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_ = resp.Body.Close()

	if gotHost != shardAURL.Host {
		t.Errorf("backend saw Host %q, want %q (the shard's own host, not the router's)", gotHost, shardAURL.Host)
	}
}

// TestRouter_StatusRoutesByListShardNotTokenClaim is the correctness
// property §23 exists for: an issuer reassigned to a different shard
// (a fresh token now claims shard-b) must still be able to PATCH the
// status of a credential issued before the reassignment, which lives in
// a list on shard-a. Routing by the token's tenant_id claim (the old
// behavior) would send this to shard-b, which has never heard of that
// list.
func TestRouter_StatusRoutesByListShardNotTokenClaim(t *testing.T) {
	km, validator := testValidator(t)
	shardA := backendServer(t, "shard-a")
	shardB := backendServer(t, "shard-b")

	router, err := New(validator, map[string]string{"shard-a": shardA.URL, "shard-b": shardB.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	proxySrv := httptest.NewServer(router)
	defer proxySrv.Close()

	req, _ := http.NewRequest(http.MethodPatch, proxySrv.URL+"/status/shard-a.deadbeef/0", nil)
	// Token claims shard-b (as if this issuer were reassigned there), but
	// the list ID in the path names shard-a — routing must follow the
	// list, landing on shard-a's backend, not shard-b's.
	req.Header.Set("Authorization", "Bearer "+issueToken(t, km, "shard-b"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_ = resp.Body.Close()
	if got := resp.Header.Get("X-Backend"); got != "shard-a" {
		t.Errorf("routed to backend %q, want %q (the list's own shard, not the token's tenant_id claim)", got, "shard-a")
	}
}

// TestRouter_StatusFallsBackToTokenClaimForLegacyListID covers a list ID
// that predates the shard-prefix scheme (internal/listid) — must still
// route somewhere sensible (the token's claim, the only signal that
// existed before §23), not fail outright.
func TestRouter_StatusFallsBackToTokenClaimForLegacyListID(t *testing.T) {
	km, validator := testValidator(t)
	shardA := backendServer(t, "shard-a")

	router, err := New(validator, map[string]string{"shard-a": shardA.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	proxySrv := httptest.NewServer(router)
	defer proxySrv.Close()

	req, _ := http.NewRequest(http.MethodPatch, proxySrv.URL+"/status/a1b2c3d4e5f60718293a4b5c6d7e8f90/0", nil)
	req.Header.Set("Authorization", "Bearer "+issueToken(t, km, "shard-a"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_ = resp.Body.Close()
	if got := resp.Header.Get("X-Backend"); got != "shard-a" {
		t.Errorf("routed to backend %q, want %q (fell back to the token's claim)", got, "shard-a")
	}
}

// TestRouter_StatusFallsBackToTokenClaimForUnconfiguredEmbeddedShard
// covers a list ID whose embedded shard was once real but isn't
// configured on this router instance (e.g. a decommissioned shard whose
// backend entry was removed) — falls back rather than 502ing outright.
func TestRouter_StatusFallsBackToTokenClaimForUnconfiguredEmbeddedShard(t *testing.T) {
	km, validator := testValidator(t)
	shardA := backendServer(t, "shard-a")

	router, err := New(validator, map[string]string{"shard-a": shardA.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	proxySrv := httptest.NewServer(router)
	defer proxySrv.Close()

	req, _ := http.NewRequest(http.MethodPatch, proxySrv.URL+"/status/shard-gone.deadbeef/0", nil)
	req.Header.Set("Authorization", "Bearer "+issueToken(t, km, "shard-a"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_ = resp.Body.Close()
	if got := resp.Header.Get("X-Backend"); got != "shard-a" {
		t.Errorf("routed to backend %q, want %q (fell back to the token's claim)", got, "shard-a")
	}
}

// TestRouter_AllocateStillRoutesByTokenClaim confirms /allocate (no
// existing list to be authoritative about) is unaffected by §23 — always
// the token's current tenant_id claim, exactly as before.
func TestRouter_AllocateStillRoutesByTokenClaim(t *testing.T) {
	km, validator := testValidator(t)
	shardA := backendServer(t, "shard-a")
	shardB := backendServer(t, "shard-b")

	router, err := New(validator, map[string]string{"shard-a": shardA.URL, "shard-b": shardB.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	proxySrv := httptest.NewServer(router)
	defer proxySrv.Close()

	req, _ := http.NewRequest(http.MethodPost, proxySrv.URL+"/allocate", nil)
	req.Header.Set("Authorization", "Bearer "+issueToken(t, km, "shard-b"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_ = resp.Body.Close()
	if got := resp.Header.Get("X-Backend"); got != "shard-b" {
		t.Errorf("routed to backend %q, want %q (the token's own current claim)", got, "shard-b")
	}
}

func TestRouter_RejectsMissingToken(t *testing.T) {
	_, validator := testValidator(t)
	router, err := New(validator, map[string]string{"shard-a": "http://unused.invalid"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	proxySrv := httptest.NewServer(router)
	defer proxySrv.Close()

	resp, err := http.Post(proxySrv.URL+"/allocate", "application/json", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	// RFC 6750 §3: no bearer token was even presented, so the challenge
	// is invalid_request, not invalid_token.
	if want, got := `Bearer error="invalid_request"`, resp.Header.Get("WWW-Authenticate"); got != want {
		t.Errorf("WWW-Authenticate = %q, want %q", got, want)
	}
}

func TestRouter_RejectsInvalidToken(t *testing.T) {
	_, validator := testValidator(t)
	router, err := New(validator, map[string]string{"shard-a": "http://unused.invalid"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	proxySrv := httptest.NewServer(router)
	defer proxySrv.Close()

	req, _ := http.NewRequest(http.MethodPost, proxySrv.URL+"/allocate", nil)
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	if want, got := `Bearer error="invalid_token", error_description="the access token is invalid"`, resp.Header.Get("WWW-Authenticate"); got != want {
		t.Errorf("WWW-Authenticate = %q, want %q", got, want)
	}
}

func TestRouter_RejectsExpiredToken(t *testing.T) {
	km, validator := testValidator(t)
	router, err := New(validator, map[string]string{"shard-a": "http://unused.invalid"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	proxySrv := httptest.NewServer(router)
	defer proxySrv.Close()

	// A negative TTL mints a token whose exp is already in the past.
	token, err := km.Issue(accesstoken.IssueParams{
		Issuer:   testIssuer,
		Audience: testAudience,
		Subject:  "issuer-a",
		TenantID: "shard-a",
		TAC:      "riw",
		TTL:      -time.Hour,
	})
	if err != nil {
		t.Fatalf("issue expired token: %v", err)
	}

	req, _ := http.NewRequest(http.MethodPost, proxySrv.URL+"/allocate", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	if want, got := `Bearer error="invalid_token", error_description="the access token expired"`, resp.Header.Get("WWW-Authenticate"); got != want {
		t.Errorf("WWW-Authenticate = %q, want %q", got, want)
	}
}

func TestRouter_RejectsWrongIssuerToken(t *testing.T) {
	km, validator := testValidator(t)
	router, err := New(validator, map[string]string{"shard-a": "http://unused.invalid"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	proxySrv := httptest.NewServer(router)
	defer proxySrv.Close()

	// A token that is otherwise well-formed and signed by the right key,
	// but carries an issuer the validator doesn't accept: a rejection
	// reason distinct from expiry, which should still get invalid_token
	// but the generic (non-expiry) description.
	token, err := km.Issue(accesstoken.IssueParams{
		Issuer:   "https://not-the-expected-issuer.example.org",
		Audience: testAudience,
		Subject:  "issuer-a",
		TenantID: "shard-a",
		TAC:      "riw",
		TTL:      time.Hour,
	})
	if err != nil {
		t.Fatalf("issue wrong-issuer token: %v", err)
	}

	req, _ := http.NewRequest(http.MethodPost, proxySrv.URL+"/allocate", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	if want, got := `Bearer error="invalid_token", error_description="the access token is invalid"`, resp.Header.Get("WWW-Authenticate"); got != want {
		t.Errorf("WWW-Authenticate = %q, want %q", got, want)
	}
}

func TestRouter_RejectsUnknownShard(t *testing.T) {
	km, validator := testValidator(t)
	router, err := New(validator, map[string]string{"shard-a": "http://unused.invalid"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	proxySrv := httptest.NewServer(router)
	defer proxySrv.Close()

	req, _ := http.NewRequest(http.MethodPost, proxySrv.URL+"/allocate", nil)
	req.Header.Set("Authorization", "Bearer "+issueToken(t, km, "shard-nonexistent"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) == 0 {
		t.Error("expected a body explaining the 502")
	}
}
