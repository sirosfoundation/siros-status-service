package clientassertion

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

const testAudience = "https://as.example.org/token"

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

// publicJWKMap marshals a public key to a JWK and back to a plain
// map[string]any, matching the shape jwt.Header will actually contain
// after JSON round-tripping through the wire (as opposed to a
// jose.JSONWebKey value, which the real header decode never produces).
func publicJWKMap(t *testing.T, pub *ecdsa.PublicKey) map[string]any {
	t.Helper()
	jwk := jose.JSONWebKey{Key: pub}
	raw, err := jwk.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal jwk: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal jwk: %v", err)
	}
	return m
}

// buildAssertion signs a client assertion with key, embedding its own
// public key in the `jwk` header, matching what a real issuer client
// would send.
func buildAssertion(t *testing.T, key *ecdsa.PrivateKey, issuerID, audience string, iat, exp time.Time) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.RegisteredClaims{
		Issuer:    issuerID,
		Subject:   issuerID,
		Audience:  jwt.ClaimStrings{audience},
		IssuedAt:  jwt.NewNumericDate(iat),
		ExpiresAt: jwt.NewNumericDate(exp),
	})
	token.Header["jwk"] = publicJWKMap(t, &key.PublicKey)
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}
	return signed
}

func TestVerify_ValidAssertion(t *testing.T) {
	key := testKey(t)
	now := time.Now()
	assertion := buildAssertion(t, key, "issuer-a", testAudience, now, now.Add(time.Minute))

	result, err := Verify(assertion, testAudience)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.IssuerID != "issuer-a" {
		t.Errorf("IssuerID = %q, want %q", result.IssuerID, "issuer-a")
	}
	if result.JWK["kty"] != "EC" {
		t.Errorf("JWK[kty] = %v, want EC", result.JWK["kty"])
	}
}

func TestVerify_RejectsWrongAudience(t *testing.T) {
	key := testKey(t)
	now := time.Now()
	assertion := buildAssertion(t, key, "issuer-a", "https://someone-else.example.org/token", now, now.Add(time.Minute))

	if _, err := Verify(assertion, testAudience); err == nil {
		t.Fatal("expected an error for an assertion addressed to a different audience")
	}
}

func TestVerify_RejectsExpired(t *testing.T) {
	key := testKey(t)
	now := time.Now()
	assertion := buildAssertion(t, key, "issuer-a", testAudience, now.Add(-time.Hour), now.Add(-time.Minute))

	if _, err := Verify(assertion, testAudience); err == nil {
		t.Fatal("expected an error for an expired assertion")
	}
}

func TestVerify_RejectsIssuerSubjectMismatch(t *testing.T) {
	key := testKey(t)
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.RegisteredClaims{
		Issuer:    "issuer-a",
		Subject:   "issuer-b", // mismatch
		Audience:  jwt.ClaimStrings{testAudience},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
	})
	token.Header["jwk"] = publicJWKMap(t, &key.PublicKey)
	assertion, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if _, err := Verify(assertion, testAudience); err == nil {
		t.Fatal("expected an error when iss != sub")
	}
}

func TestVerify_RejectsOverlyLongLifetime(t *testing.T) {
	key := testKey(t)
	now := time.Now()
	// Well within any normal exp check, but the assertion's own
	// iat..exp window exceeds the 5-minute cap this package enforces
	// independent of the AS's own leeway.
	assertion := buildAssertion(t, key, "issuer-a", testAudience, now, now.Add(time.Hour))

	if _, err := Verify(assertion, testAudience); err == nil {
		t.Fatal("expected an error for an assertion whose own lifetime exceeds the cap")
	}
}

func TestVerify_RejectsMissingJWKHeader(t *testing.T) {
	key := testKey(t)
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.RegisteredClaims{
		Issuer:    "issuer-a",
		Subject:   "issuer-a",
		Audience:  jwt.ClaimStrings{testAudience},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
	})
	// No embedded jwk header.
	assertion, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if _, err := Verify(assertion, testAudience); err == nil {
		t.Fatal("expected an error for an assertion with no embedded jwk header")
	}
}

func TestVerify_RejectsSignatureNotMatchingEmbeddedKey(t *testing.T) {
	signingKey := testKey(t)
	otherKey := testKey(t) // embedded in the header, but NOT used to sign
	now := time.Now()

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.RegisteredClaims{
		Issuer:    "issuer-a",
		Subject:   "issuer-a",
		Audience:  jwt.ClaimStrings{testAudience},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
	})
	token.Header["jwk"] = publicJWKMap(t, &otherKey.PublicKey) // mismatched key
	assertion, err := token.SignedString(signingKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if _, err := Verify(assertion, testAudience); err == nil {
		t.Fatal("expected an error when the signature doesn't verify against the embedded key")
	}
}
