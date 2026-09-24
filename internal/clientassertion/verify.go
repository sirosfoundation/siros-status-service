// Package clientassertion verifies the RFC 7523-flavored client
// assertion an issuer presents to the AS's token endpoint
// (docs/design.md §15.2): a JWT self-signed by the issuer's own key,
// with that public key embedded directly in the JWT header (the `jwk`
// parameter, RFC 7515 §4.1.3) so it can be verified without any prior
// registration step. Verifying the signature here only proves
// possession of the key — whether that key is actually *trusted* is a
// separate question, answered by internal/trust.
package clientassertion

import (
	"crypto/ecdsa"
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
// identity, and the public key it just proved possession of.
type Result struct {
	IssuerID string
	JWK      map[string]any
}

// Verify checks assertion's signature against its own embedded JWK,
// and validates the standard client-assertion claims (RFC 7523 §3):
// iss == sub (the issuer's claimed identity), aud == expectedAudience
// (the AS's token endpoint — prevents an assertion minted for a
// different AS from being replayed here), and a bounded exp/iat window.
// It does not consult any trust decision — that's the caller's job.
func Verify(assertion, expectedAudience string) (*Result, error) {
	var unverified jwt.RegisteredClaims
	unverifiedToken, _, err := jwt.NewParser().ParseUnverified(assertion, &unverified)
	if err != nil {
		return nil, fmt.Errorf("clientassertion: parse: %w", err)
	}

	jwkHeader, ok := unverifiedToken.Header["jwk"]
	if !ok {
		return nil, errors.New("clientassertion: missing embedded jwk header")
	}
	jwkMap, ok := jwkHeader.(map[string]any)
	if !ok {
		return nil, errors.New("clientassertion: jwk header is not a JSON object")
	}
	jwkBytes, err := json.Marshal(jwkMap)
	if err != nil {
		return nil, fmt.Errorf("clientassertion: re-marshal embedded jwk: %w", err)
	}
	var jwk jose.JSONWebKey
	if err := jwk.UnmarshalJSON(jwkBytes); err != nil {
		return nil, fmt.Errorf("clientassertion: decode embedded jwk: %w", err)
	}
	pubKey, ok := jwk.Key.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("clientassertion: only EC public keys are supported")
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

	return &Result{IssuerID: claims.Subject, JWK: jwkMap}, nil
}
