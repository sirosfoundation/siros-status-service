package statuslist

import (
	"bytes"
	"compress/zlib"
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

// EncodeLst compresses a packed bitmap with DEFLATE/zlib
// (draft-ietf-oauth-status-list-21 §4.1: "DEFLATE [RFC1951] with the
// ZLIB [RFC1950] data format") and base64url-encodes it with padding
// omitted (§4.2), producing the `lst` claim value.
func EncodeLst(raw []byte) (string, error) {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(raw); err != nil {
		return "", fmt.Errorf("statuslist: compress: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("statuslist: compress: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
}

// DecodeLst reverses EncodeLst. It exists primarily for round-trip
// testing and for a future verifier-side implementation; the issuer
// service itself never needs to decode a list it just built.
func DecodeLst(lst string) ([]byte, error) {
	compressed, err := base64.RawURLEncoding.DecodeString(lst)
	if err != nil {
		return nil, fmt.Errorf("statuslist: base64url decode: %w", err)
	}
	r, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("statuslist: zlib reader: %w", err)
	}
	defer func() { _ = r.Close() }()
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("statuslist: decompress: %w", err)
	}
	return raw, nil
}

// StatusListClaim is the `status_list` claim (§4.2).
type StatusListClaim struct {
	Bits           int    `json:"bits"`
	Lst            string `json:"lst"`
	AggregationURI string `json:"aggregation_uri,omitempty"`
}

// Claims is the claim set of a Status List Token (§5.1). sub/iat/exp are
// carried via jwt.RegisteredClaims; ttl and status_list are specific to
// this token type.
type Claims struct {
	jwt.RegisteredClaims
	TTL        int64           `json:"ttl,omitempty"`
	StatusList StatusListClaim `json:"status_list"`
}

// TokenParams collects the inputs needed to build a Status List Token
// for one list.
type TokenParams struct {
	// ListURL is this list's own URI; becomes the `sub` claim (§5.1:
	// "the sub claim MUST specify the URI of the Status List Token").
	ListURL  string
	IssuedAt time.Time
	// TTL is how long, in seconds, a verifier may cache this token
	// (docs/design.md §9 / §13: configurable per issuer/credential type,
	// with a conservative fallback applied by the caller if unset).
	TTL int64
	// Bitmap is the current, live status bitmap to publish.
	Bitmap *Bitmap
	// KeyID is placed in the JWS header (kid) if non-empty.
	KeyID string
	// JWK, if non-nil, is embedded in the JWS header (RFC 7515 §4.1.3) —
	// the signing key's own public half, letting any verifier validate
	// this token's signature with nothing beyond the token itself (docs/
	// design.md §25: this was a real gap — there was no other way to
	// discover this key at all). Build with JWKFromPublicKey.
	JWK map[string]any
	// X5C, if non-empty, is embedded in the JWS header (RFC 7515
	// §4.1.6) — the signing key's certificate chain, leaf first, each
	// entry base64-STANDARD-encoded DER (matching
	// internal/clientassertion's x5c convention on the issuer side).
	// Lets a verifier additionally *evaluate trust* in the signer (chain
	// it to a real trust list), not just validate the signature — the
	// same distinction docs/design.md §20 draws for client assertions.
	// JWK and X5C are independent, unlike a client assertion's proof of
	// possession (which requires exactly one): a status list signer's
	// own key is not a secret proving identity the way an issuer's
	// assertion key is, so both may be present, either alone, or (if
	// this deployment's signing key has no associated certificate)
	// neither — a verifier that can't discover the key any other way
	// can then only decode the list's contents without a trust
	// decision, this service's original, more limited behavior.
	X5C []string
}

// JWKFromPublicKey renders pub as a bare JWK map — kty/crv/x/y only, no
// kid/alg/use (those belong at the JWS header's own top level, or don't
// apply to an embedded signing key the way they would to a discovery
// document) — matching the shape this repo's own client-assertion
// examples already use for a bare `jwk` header (status.siros.org's
// in-browser generator, internal/clientassertion's tests).
func JWKFromPublicKey(pub *ecdsa.PublicKey) (map[string]any, error) {
	raw, err := (&jose.JSONWebKey{Key: pub}).MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("statuslist: marshal jwk: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("statuslist: unmarshal jwk: %w", err)
	}
	return m, nil
}

// BuildToken signs a Status List Token (JWT form, `typ: statuslist+jwt`
// per §5.1) over the given bitmap.
func BuildToken(key crypto.Signer, p TokenParams) (string, error) {
	lst, err := EncodeLst(p.Bitmap.Bytes())
	if err != nil {
		return "", err
	}

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:  p.ListURL,
			IssuedAt: jwt.NewNumericDate(p.IssuedAt),
		},
		TTL: p.TTL,
		StatusList: StatusListClaim{
			Bits: p.Bitmap.Bits(),
			Lst:  lst,
		},
	}

	// es256CryptoSignerMethod, not jwt.SigningMethodES256: this signs
	// through crypto.Signer (see signer.go's doc comment), which both an
	// in-memory *ecdsa.PrivateKey and a PKCS#11-backed signer (§26)
	// implement identically — jwt.SigningMethodES256 only accepts a
	// concrete *ecdsa.PrivateKey. The wire format is unchanged either
	// way, so verification (ParseToken, any real verifier) is unaffected.
	tok := jwt.NewWithClaims(es256CryptoSignerMethod{}, claims)
	tok.Header["typ"] = "statuslist+jwt"
	if p.KeyID != "" {
		tok.Header["kid"] = p.KeyID
	}
	if p.JWK != nil {
		tok.Header["jwk"] = p.JWK
	}
	if len(p.X5C) > 0 {
		tok.Header["x5c"] = p.X5C
	}

	signed, err := tok.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("statuslist: sign token: %w", err)
	}
	return signed, nil
}

// ParseToken verifies and decodes a Status List Token against the given
// public key. It exists for round-trip testing; production verifiers
// are a separate concern from this issuer-side service.
func ParseToken(token string, key *ecdsa.PublicKey) (*Claims, error) {
	claims := &Claims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("statuslist: unexpected signing method %v", t.Header["alg"])
		}
		return key, nil
	})
	if err != nil {
		return nil, err
	}
	if !parsed.Valid {
		return nil, fmt.Errorf("statuslist: token not valid")
	}
	return claims, nil
}
