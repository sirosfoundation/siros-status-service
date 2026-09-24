// Package accesstoken is the AS-side issuance half of docs/design.md
// §15.3: holds the AS's signing key, mints access tokens shaped exactly
// like github.com/sirosfoundation/go-tokenauth's claims.AccessTokenClaims,
// and serves the corresponding JWKS.
//
// Verification is deliberately not reimplemented here: ingestion nodes
// and the ingress router use go-tokenauth's own validator/jwks/tokengin
// packages directly (its jwks.Fetcher + validator.Validator are exactly
// the offline, JWKS-cached verification §15.3 calls for), so a token
// minted here is verified by the same library used elsewhere in the org
// for this exact purpose, not a hand-rolled lookalike.
package accesstoken

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	gojosejwt "github.com/go-jose/go-jose/v4/jwt"

	tokenauthclaims "github.com/sirosfoundation/go-tokenauth/claims"
)

// KeyManager holds the AS's signing key (§15.8: a single static key for
// this prototype, not a rotating set) and issues/publishes it.
type KeyManager struct {
	key   *ecdsa.PrivateKey
	keyID string
}

func NewKeyManager(key *ecdsa.PrivateKey, keyID string) *KeyManager {
	return &KeyManager{key: key, keyID: keyID}
}

// IssueParams collects what varies per token; Issue fills in iat/exp/jti
// consistently.
type IssueParams struct {
	Issuer   string
	Audience string
	Subject  string // the issuer's identity (docs/design.md §15.2)
	TenantID string // this service's "shard" (§15.5), carried as go-tokenauth's tenant_id
	TAC      tokenauthclaims.TAC
	TTL      time.Duration
}

// Issue signs an AccessTokenClaims token — the same shape
// go-tokenauth's validator parses, built with go-jose's jwt package
// (not golang-jwt) because that's what AccessTokenClaims itself embeds.
func (m *KeyManager) Issue(p IssueParams) (string, error) {
	if err := p.TAC.Validate(); err != nil {
		return "", fmt.Errorf("accesstoken: invalid tac: %w", err)
	}

	jti, err := randomID()
	if err != nil {
		return "", fmt.Errorf("accesstoken: generate jti: %w", err)
	}

	now := time.Now()
	claims := tokenauthclaims.AccessTokenClaims{
		Claims: gojosejwt.Claims{
			ID:       jti,
			Issuer:   p.Issuer,
			Subject:  p.Subject,
			Audience: gojosejwt.Audience{p.Audience},
			IssuedAt: gojosejwt.NewNumericDate(now),
			Expiry:   gojosejwt.NewNumericDate(now.Add(p.TTL)),
		},
		TenantID: p.TenantID,
		TAC:      p.TAC,
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: m.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", m.keyID),
	)
	if err != nil {
		return "", fmt.Errorf("accesstoken: create signer: %w", err)
	}

	token, err := gojosejwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("accesstoken: sign: %w", err)
	}
	return token, nil
}

// JWKS returns the public half of the signing key as a JSON Web Key Set,
// suitable for serving at /.well-known/jwks.json — exactly the shape
// go-tokenauth's jwks.Fetcher expects.
func (m *KeyManager) JWKS() jose.JSONWebKeySet {
	return jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       &m.key.PublicKey,
				KeyID:     m.keyID,
				Algorithm: string(jose.ES256),
				Use:       "sig",
			},
		},
	}
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
