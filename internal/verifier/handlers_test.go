package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"

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
