package clientassertion

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
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

// selfSignedCertB64 issues a minimal self-signed certificate for key and
// returns it base64-STANDARD-encoded DER — the RFC 7515 §4.1.6 x5c
// encoding, and go-trust's AuthZEN wire protocol's x5c resource entries.
// Self-signed is fine here: this package never validates the chain
// against any root (see resolveX5C's doc comment) — only that the leaf's
// public key matches the assertion's signature. Whether the chain itself
// roots in a real trust list is internal/trust's job, exercised there.
func selfSignedCertB64(t *testing.T, key *ecdsa.PrivateKey, commonName string) string {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

// buildX5CAssertion mirrors buildAssertion but embeds an x5c chain
// instead of a bare jwk header.
func buildX5CAssertion(t *testing.T, key *ecdsa.PrivateKey, chain []string, issuerID, audience string, iat, exp time.Time) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.RegisteredClaims{
		Issuer:    issuerID,
		Subject:   issuerID,
		Audience:  jwt.ClaimStrings{audience},
		IssuedAt:  jwt.NewNumericDate(iat),
		ExpiresAt: jwt.NewNumericDate(exp),
	})
	chainAny := make([]any, len(chain))
	for i, c := range chain {
		chainAny[i] = c
	}
	token.Header["x5c"] = chainAny
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}
	return signed
}

func TestVerify_ValidX5CAssertion(t *testing.T) {
	key := testKey(t)
	leaf := selfSignedCertB64(t, key, "issuer-a")
	now := time.Now()
	assertion := buildX5CAssertion(t, key, []string{leaf}, "issuer-a", testAudience, now, now.Add(time.Minute))

	result, err := Verify(assertion, testAudience)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.IssuerID != "issuer-a" {
		t.Errorf("IssuerID = %q, want %q", result.IssuerID, "issuer-a")
	}
	if result.JWK != nil {
		t.Errorf("JWK = %+v, want nil for an x5c-backed assertion", result.JWK)
	}
	if len(result.X5C) != 1 || result.X5C[0] != leaf {
		t.Errorf("X5C = %+v, want the single leaf cert unchanged", result.X5C)
	}
}

func TestVerify_ValidX5CAssertion_FullChainForwarded(t *testing.T) {
	key := testKey(t)
	intermediateKey := testKey(t)
	leaf := selfSignedCertB64(t, key, "issuer-a")
	intermediate := selfSignedCertB64(t, intermediateKey, "intermediate-ca")
	now := time.Now()
	// Signed by the LEAF key (proof of possession is always the leaf's),
	// but the chain carries an extra entry — internal/trust, not this
	// package, is what actually walks the chain to a root, so the whole
	// chain must be forwarded unchanged, not just the leaf.
	assertion := buildX5CAssertion(t, key, []string{leaf, intermediate}, "issuer-a", testAudience, now, now.Add(time.Minute))

	result, err := Verify(assertion, testAudience)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(result.X5C) != 2 || result.X5C[0] != leaf || result.X5C[1] != intermediate {
		t.Errorf("X5C = %+v, want [leaf, intermediate] unchanged and in order", result.X5C)
	}
}

func TestVerify_RejectsSignatureNotMatchingX5CLeaf(t *testing.T) {
	signingKey := testKey(t)
	otherKey := testKey(t)
	leaf := selfSignedCertB64(t, otherKey, "issuer-a") // certifies otherKey, not signingKey
	now := time.Now()
	assertion := buildX5CAssertion(t, signingKey, []string{leaf}, "issuer-a", testAudience, now, now.Add(time.Minute))

	if _, err := Verify(assertion, testAudience); err == nil {
		t.Fatal("expected an error when the signature doesn't verify against the x5c leaf's key")
	}
}

func TestVerify_RejectsEmptyX5CHeader(t *testing.T) {
	key := testKey(t)
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.RegisteredClaims{
		Issuer:    "issuer-a",
		Subject:   "issuer-a",
		Audience:  jwt.ClaimStrings{testAudience},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
	})
	token.Header["x5c"] = []any{}
	assertion, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if _, err := Verify(assertion, testAudience); err == nil {
		t.Fatal("expected an error for an empty x5c array")
	}
}

func TestVerify_RejectsBothJWKAndX5CHeaders(t *testing.T) {
	key := testKey(t)
	leaf := selfSignedCertB64(t, key, "issuer-a")
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.RegisteredClaims{
		Issuer:    "issuer-a",
		Subject:   "issuer-a",
		Audience:  jwt.ClaimStrings{testAudience},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
	})
	token.Header["jwk"] = publicJWKMap(t, &key.PublicKey)
	token.Header["x5c"] = []any{leaf}
	assertion, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if _, err := Verify(assertion, testAudience); err == nil {
		t.Fatal("expected an error when both jwk and x5c headers are present")
	}
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
