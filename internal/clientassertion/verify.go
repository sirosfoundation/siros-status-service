// Package clientassertion verifies the RFC 7523-flavored client
// assertion an issuer presents to the AS's token endpoint (docs/
// design.md §15.2/§20): a JWT self-signed by the issuer's own key, with
// proof of that key embedded directly in the JWT header so it can be
// verified without any prior registration step — either a bare public
// key (the `jwk` parameter, RFC 7515 §4.1.3) or a full X.509 certificate
// chain (the `x5c` parameter, RFC 7515 §4.1.6), so an issuer with a real
// PKI-issued signing certificate can use it as-is rather than minting a
// separate, unchained key just for this API. Verifying the signature
// here only proves possession of the key — whether that key (or its
// certificate chain) is actually *trusted* is a separate question,
// answered by internal/trust, which for an x5c-backed assertion can mean
// validating the chain against an external trust list (e.g. an ETSI
// Trusted List / eIDAS LoTL) rather than a simple allow-list.
package clientassertion

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

// maxLifetime bounds how long an assertion's own exp-iat window may be,
// independent of the AS's own leeway — an assertion is a one-shot proof
// of possession for this token request, not a long-lived credential.
const maxLifetime = 5 * time.Minute

// Result is what a verified assertion establishes: a claimed issuer
// identity, and the proof of possession it used to establish it — exactly
// one of JWK or X5C is populated, matching whichever header the
// assertion carried.
type Result struct {
	IssuerID string
	JWK      map[string]any
	// X5C is the certificate chain exactly as presented, leaf first,
	// each entry base64-STANDARD-encoded DER (RFC 7515 §4.1.6 — the same
	// encoding go-trust's AuthZEN wire protocol's x5c resource type
	// expects, so this can be forwarded to internal/trust unchanged).
	X5C []string
}

// Verify checks assertion's signature against the key its own header
// asserts (a bare JWK, or an X.509 chain's leaf certificate — see
// resolveProofOfPossession), and validates the standard client-assertion
// claims (RFC 7523 §3): iss == sub (the issuer's claimed identity), aud
// == expectedAudience (the AS's token endpoint — prevents an assertion
// minted for a different AS from being replayed here), and a bounded
// exp/iat window. It does not consult any trust decision — that's the
// caller's job.
func Verify(assertion, expectedAudience string) (*Result, error) {
	var unverified jwt.RegisteredClaims
	unverifiedToken, _, err := jwt.NewParser().ParseUnverified(assertion, &unverified)
	if err != nil {
		return nil, fmt.Errorf("clientassertion: parse: %w", err)
	}

	pubKey, jwkMap, x5c, err := resolveProofOfPossession(unverifiedToken.Header)
	if err != nil {
		return nil, err
	}

	verified, err := jwt.ParseWithClaims(assertion, &jwt.RegisteredClaims{},
		func(*jwt.Token) (any, error) { return pubKey, nil },
		jwt.WithValidMethods([]string{"ES256"}),
		jwt.WithAudience(expectedAudience),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("clientassertion: verify signature/claims: %w", err)
	}
	claims, ok := verified.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return nil, errors.New("clientassertion: unexpected claims type")
	}

	if claims.Subject == "" || claims.Issuer != claims.Subject {
		return nil, errors.New("clientassertion: iss must equal sub")
	}
	if claims.IssuedAt != nil && claims.ExpiresAt != nil {
		if claims.ExpiresAt.Sub(claims.IssuedAt.Time) > maxLifetime {
			return nil, fmt.Errorf("clientassertion: assertion lifetime exceeds %s", maxLifetime)
		}
	}

	return &Result{IssuerID: claims.Subject, JWK: jwkMap, X5C: x5c}, nil
}

// resolveProofOfPossession extracts the public key to verify the
// assertion's signature against, from whichever proof-of-possession
// header is present — preferring neither over the other, an assertion
// must carry exactly one. Only EC (P-256) keys are supported either way,
// matching the only algorithm this service's AS itself ever issues
// tokens with (ES256).
func resolveProofOfPossession(header map[string]any) (pubKey *ecdsa.PublicKey, jwkMap map[string]any, x5c []string, err error) {
	_, hasJWK := header["jwk"]
	_, hasX5C := header["x5c"]
	switch {
	case hasJWK && hasX5C:
		return nil, nil, nil, errors.New("clientassertion: assertion header must carry exactly one of jwk or x5c, not both")
	case hasJWK:
		pubKey, jwkMap, err = resolveJWK(header["jwk"])
	case hasX5C:
		pubKey, x5c, err = resolveX5C(header["x5c"])
	default:
		err = errors.New("clientassertion: missing embedded jwk or x5c header")
	}
	return pubKey, jwkMap, x5c, err
}

func resolveJWK(raw any) (*ecdsa.PublicKey, map[string]any, error) {
	jwkMap, ok := raw.(map[string]any)
	if !ok {
		return nil, nil, errors.New("clientassertion: jwk header is not a JSON object")
	}
	jwkBytes, err := json.Marshal(jwkMap)
	if err != nil {
		return nil, nil, fmt.Errorf("clientassertion: re-marshal embedded jwk: %w", err)
	}
	var jwk jose.JSONWebKey
	if err := jwk.UnmarshalJSON(jwkBytes); err != nil {
		return nil, nil, fmt.Errorf("clientassertion: decode embedded jwk: %w", err)
	}
	pubKey, ok := jwk.Key.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("clientassertion: only EC public keys are supported")
	}
	return pubKey, jwkMap, nil
}

// resolveX5C parses an x5c header (RFC 7515 §4.1.6: an array of
// base64-STANDARD-encoded — not base64url — DER certificates, leaf
// first) and returns the leaf certificate's public key to verify the
// assertion's own signature against, plus the chain exactly as
// presented for internal/trust to validate against a trust list. This
// deliberately does not itself validate the chain against any root —
// that's the whole reason to hand it to internal/trust rather than
// deciding it here: which roots (e.g. which ETSI Trusted List) are
// authoritative is a trust-policy decision, not a signature-verification
// one.
func resolveX5C(raw any) (*ecdsa.PublicKey, []string, error) {
	items, ok := raw.([]any)
	if !ok || len(items) == 0 {
		return nil, nil, errors.New("clientassertion: x5c header is not a non-empty array")
	}
	chain := make([]string, len(items))
	for i, item := range items {
		s, ok := item.(string)
		if !ok {
			return nil, nil, fmt.Errorf("clientassertion: x5c[%d] is not a string", i)
		}
		chain[i] = s
	}

	leafDER, err := base64.StdEncoding.DecodeString(chain[0])
	if err != nil {
		return nil, nil, fmt.Errorf("clientassertion: decode x5c[0]: %w", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, nil, fmt.Errorf("clientassertion: parse leaf certificate: %w", err)
	}
	pubKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("clientassertion: only EC leaf certificates are supported")
	}
	return pubKey, chain, nil
}
