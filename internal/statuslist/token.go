package statuslist

import (
	"bytes"
	"compress/zlib"
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"io"
	"time"

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
}

// BuildToken signs a Status List Token (JWT form, `typ: statuslist+jwt`
// per §5.1) over the given bitmap.
func BuildToken(key *ecdsa.PrivateKey, p TokenParams) (string, error) {
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

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = "statuslist+jwt"
	if p.KeyID != "" {
		tok.Header["kid"] = p.KeyID
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
