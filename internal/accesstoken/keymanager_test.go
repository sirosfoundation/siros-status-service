package accesstoken

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	tokenauthclaims "github.com/sirosfoundation/go-tokenauth/claims"
	"github.com/sirosfoundation/go-tokenauth/validator"
)

// This test proves our issuance is actually consumable by go-tokenauth's
// real validator — not just that our own code parses its own output.
// Any drift between AccessTokenClaims here and what the validator
// expects (a wrong claim type, an unexpected header) would show up as a
// failure here, not silently at runtime in production.

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func testValidator(t *testing.T, km *KeyManager, issuer string, audiences ...string) *validator.Validator {
	t.Helper()
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(km.JWKS())
	}))
	t.Cleanup(jwksSrv.Close)

	v := validator.New(validator.Config{
		JWKSURL:   jwksSrv.URL,
		Issuer:    issuer,
		Audiences: audiences,
	})
	v.Start(t.Context())
	t.Cleanup(v.Stop)
	return v
}

func TestIssueAndValidate_RoundTripWithRealGoTokenauth(t *testing.T) {
	km := NewKeyManager(testKey(t), "as-key-1")
	v := testValidator(t, km, "https://as.example.org", "siros-status-service")

	token, err := km.Issue(IssueParams{
		Issuer:   "https://as.example.org",
		Audience: "siros-status-service",
		Subject:  "issuer-a",
		TenantID: "shard-a",
		TAC:      "riw",
		TTL:      time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	result, err := v.Validate(context.Background(), token)
	if err != nil {
		t.Fatalf("go-tokenauth validator.Validate: %v", err)
	}
	if result.UserID != "issuer-a" {
		t.Errorf("UserID = %q, want issuer-a", result.UserID)
	}
	if result.TenantID != "shard-a" {
		t.Errorf("TenantID = %q, want shard-a", result.TenantID)
	}
	if !result.TAC.HasAll("riw") {
		t.Errorf("TAC = %q, want to contain riw", result.TAC)
	}
	if result.Mode != tokenauthclaims.ModeSession {
		t.Errorf("Mode = %q, want session (new-style asymmetric)", result.Mode)
	}
}

func TestIssue_RejectsInvalidTAC(t *testing.T) {
	km := NewKeyManager(testKey(t), "as-key-1")
	_, err := km.Issue(IssueParams{
		Issuer: "https://as.example.org", Audience: "siros-status-service",
		Subject: "issuer-a", TenantID: "shard-a", TAC: "riwz", TTL: time.Hour, // 'z' is not a valid TAC char
	})
	if err == nil {
		t.Fatal("expected an error for an invalid TAC character")
	}
}

func TestValidate_RejectsWrongAudience(t *testing.T) {
	km := NewKeyManager(testKey(t), "as-key-1")
	v := testValidator(t, km, "https://as.example.org", "siros-status-service")

	token, err := km.Issue(IssueParams{
		Issuer: "https://as.example.org", Audience: "some-other-service",
		Subject: "issuer-a", TenantID: "shard-a", TAC: "r", TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := v.Validate(context.Background(), token); err == nil {
		t.Fatal("expected an error for a token addressed to a different audience")
	}
}

func TestValidate_RejectsExpired(t *testing.T) {
	km := NewKeyManager(testKey(t), "as-key-1")
	v := testValidator(t, km, "https://as.example.org", "siros-status-service")

	token, err := km.Issue(IssueParams{
		Issuer: "https://as.example.org", Audience: "siros-status-service",
		Subject: "issuer-a", TenantID: "shard-a", TAC: "r", TTL: -time.Hour, // already expired
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := v.Validate(context.Background(), token); err == nil {
		t.Fatal("expected an error for an expired token")
	}
}
