package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	rediscli "github.com/redis/go-redis/v9"

	"github.com/sirosfoundation/siros-status-service/internal/allocator"
	"github.com/sirosfoundation/siros-status-service/internal/config"
	"github.com/sirosfoundation/siros-status-service/internal/publisher"
	"github.com/sirosfoundation/siros-status-service/internal/statuslist"
	"github.com/sirosfoundation/siros-status-service/internal/store"
	"github.com/sirosfoundation/siros-status-service/internal/testsupport"
)

// newTestServer spins up a real Postgres+Redis-backed verifier Server
// with one already-allocated list, so handleGetList's content
// negotiation (docs/design.md §27) can be exercised over real HTTP
// against a real publish path, not a mock.
func newTestServer(t *testing.T) (*Server, string, *ecdsa.PrivateKey) {
	t.Helper()
	pgDSN, pgCleanup := testsupport.StartPostgres(t)
	t.Cleanup(pgCleanup)
	redisAddr, redisCleanup := testsupport.StartRedis(t)
	t.Cleanup(redisCleanup)

	meta, err := store.NewMetaStore(t.Context(), pgDSN)
	if err != nil {
		t.Fatalf("NewMetaStore: %v", err)
	}
	t.Cleanup(meta.Close)

	rdb := rediscli.NewClient(&rediscli.Options{Addr: redisAddr})
	t.Cleanup(func() { _ = rdb.Close() })
	if err := rdb.Ping(t.Context()).Err(); err != nil {
		t.Fatalf("ping redis: %v", err)
	}
	bitmaps := store.NewBitmapStore(rdb)

	const listID = "verifier-negotiation-list"
	key, err := allocator.NewKey(rand.Read)
	if err != nil {
		t.Fatalf("allocator.NewKey: %v", err)
	}
	lm, err := meta.CreateList(t.Context(), listID, 1, 10, key, "default")
	if err != nil {
		t.Fatalf("CreateList: %v", err)
	}
	if err := bitmaps.Init(t.Context(), lm.ID, int64((lm.Size*uint64(lm.Bits)+7)/8)); err != nil {
		t.Fatalf("bitmaps.Init: %v", err)
	}

	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	pub, err := publisher.New(map[string]*store.BitmapStore{"default": bitmaps}, meta, signingKey, "test-key", "https://verifier.example.org", nil)
	if err != nil {
		t.Fatalf("publisher.New: %v", err)
	}

	cfg := &config.VerifierConfig{DefaultTTLSeconds: 3600}
	return New(cfg, meta, pub), listID, signingKey
}

func TestHandleGetList_DefaultsToJWT(t *testing.T) {
	srv, listID, key := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/lists/"+listID, nil)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != jwtMediaType {
		t.Errorf("Content-Type = %q, want %q", ct, jwtMediaType)
	}
	if _, err := statuslist.ParseToken(w.Body.String(), &key.PublicKey); err != nil {
		t.Errorf("body did not parse as a valid JWT Status List Token: %v", err)
	}
}

func TestHandleGetList_ExplicitJWTAccept(t *testing.T) {
	srv, listID, key := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/lists/"+listID, nil)
	req.Header.Set("Accept", jwtMediaType)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if _, err := statuslist.ParseToken(w.Body.String(), &key.PublicKey); err != nil {
		t.Errorf("body did not parse as a valid JWT Status List Token: %v", err)
	}
}

func TestHandleGetList_ExplicitCWTAccept(t *testing.T) {
	srv, listID, key := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/lists/"+listID, nil)
	req.Header.Set("Accept", cwtMediaType)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != cwtMediaType {
		t.Errorf("Content-Type = %q, want %q", ct, cwtMediaType)
	}
	claims, err := statuslist.ParseCWTToken(w.Body.Bytes(), &key.PublicKey)
	if err != nil {
		t.Fatalf("body did not parse as a valid CWT Status List Token: %v", err)
	}
	if claims.Subject == "" {
		t.Error("expected a non-empty sub claim")
	}
}

func TestHandleGetList_WildcardAcceptGetsJWT(t *testing.T) {
	srv, listID, key := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/lists/"+listID, nil)
	req.Header.Set("Accept", "*/*")
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if _, err := statuslist.ParseToken(w.Body.String(), &key.PublicKey); err != nil {
		t.Errorf("body did not parse as a valid JWT Status List Token: %v", err)
	}
}

func TestHandleGetList_UnacceptableAcceptReturns406(t *testing.T) {
	srv, listID, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/lists/"+listID, nil)
	req.Header.Set("Accept", "application/xml")
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)

	if w.Code != 406 {
		t.Fatalf("status = %d, want 406", w.Code)
	}
}

func TestHandleGetList_ETagStillWorksAcrossFormats(t *testing.T) {
	srv, listID, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/lists/"+listID, nil)
	req.Header.Set("Accept", cwtMediaType)
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	etag := w.Header().Get("ETag")
	if etag == "" {
		t.Fatal("expected a non-empty ETag")
	}

	req2 := httptest.NewRequest(http.MethodGet, "/lists/"+listID, nil)
	req2.Header.Set("Accept", cwtMediaType)
	req2.Header.Set("If-None-Match", etag)
	w2 := httptest.NewRecorder()
	srv.Router().ServeHTTP(w2, req2)
	if w2.Code != 304 {
		t.Fatalf("status = %d, want 304 for a matching If-None-Match", w2.Code)
	}
}

// TestHandleGetListJWKS_KeyVerifiesTheListsOwnToken is the property the
// endpoint exists for (docs/design.md §28): the key discovered under
// the list URI is the key that signed the token served at that URI, and
// it carries the same kid as the token's JWS header.
func TestHandleGetListJWKS_KeyVerifiesTheListsOwnToken(t *testing.T) {
	srv, listID, _ := newTestServer(t)
	router := srv.Router()

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/lists/"+listID+"/.well-known/jwks.json", nil))
	if w.Code != 200 {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if cc := w.Header().Get("Cache-Control"); cc != "public, max-age=300" {
		t.Errorf("Cache-Control = %q, want %q", cc, "public, max-age=300")
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(w.Body.Bytes(), &set); err != nil {
		t.Fatalf("body is not a JWK Set: %v; body: %s", err, w.Body.String())
	}
	if len(set.Keys) != 1 {
		t.Fatalf("JWK Set has %d keys, want 1", len(set.Keys))
	}
	jwk := set.Keys[0]
	if jwk.KeyID != "test-key" || jwk.Use != "sig" || jwk.Algorithm != "ES256" {
		t.Errorf("kid/use/alg = %q/%q/%q, want test-key/sig/ES256", jwk.KeyID, jwk.Use, jwk.Algorithm)
	}
	discovered, ok := jwk.Key.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("discovered key is %T, want *ecdsa.PublicKey", jwk.Key)
	}

	tw := httptest.NewRecorder()
	router.ServeHTTP(tw, httptest.NewRequest(http.MethodGet, "/lists/"+listID, nil))
	if tw.Code != 200 {
		t.Fatalf("list status = %d, want 200", tw.Code)
	}
	if _, err := statuslist.ParseToken(tw.Body.String(), discovered); err != nil {
		t.Errorf("the list's token does not verify under the key discovered at its own URI: %v", err)
	}
	header, err := base64.RawURLEncoding.DecodeString(strings.SplitN(tw.Body.String(), ".", 2)[0])
	if err != nil {
		t.Fatalf("decode token header: %v", err)
	}
	var hdr struct {
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(header, &hdr); err != nil {
		t.Fatalf("parse token header: %v", err)
	}
	if hdr.Kid != jwk.KeyID {
		t.Errorf("token header kid = %q, discovered key kid = %q; they must match", hdr.Kid, jwk.KeyID)
	}
}

// TestHandleGetListJWKS_UnknownListReturns404: keys are published for
// lists this service serves, with the same answer as the list itself.
func TestHandleGetListJWKS_UnknownListReturns404(t *testing.T) {
	srv, _, _ := newTestServer(t)

	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/lists/no-such-list/.well-known/jwks.json", nil))
	if w.Code != 404 {
		t.Errorf("status = %d, want 404; body: %s", w.Code, w.Body.String())
	}
}

// TestArchivedList_KeysFollowTheListsOwnAvailability: an archived list
// keeps serving its token and its keys through the retention window,
// and both answer 410 once the window has elapsed.
func TestArchivedList_KeysFollowTheListsOwnAvailability(t *testing.T) {
	srv, listID, _ := newTestServer(t)
	if err := srv.meta.Freeze(t.Context(), listID); err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	if err := srv.meta.Archive(t.Context(), listID); err != nil {
		t.Fatalf("Archive: %v", err)
	}
	paths := []string{"/lists/" + listID, "/lists/" + listID + "/.well-known/jwks.json"}

	srv.cfg.GCRetentionPeriod = time.Hour
	for _, path := range paths {
		w := httptest.NewRecorder()
		srv.Router().ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != 200 {
			t.Errorf("within retention: GET %s = %d, want 200; body: %s", path, w.Code, w.Body.String())
		}
	}

	srv.cfg.GCRetentionPeriod = 0
	for _, path := range paths {
		w := httptest.NewRecorder()
		srv.Router().ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != 410 {
			t.Errorf("past retention: GET %s = %d, want 410; body: %s", path, w.Code, w.Body.String())
		}
	}
}
