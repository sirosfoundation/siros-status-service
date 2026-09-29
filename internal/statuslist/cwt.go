// CWT (CBOR/COSE) support for Status List Tokens — the alternative wire
// format draft-ietf-oauth-status-list-21 §4.3/§5.2 defines alongside the
// JWT form the rest of this package implements. Deliberately its own
// file: the claim shapes, header labels, and signing pre-image (COSE's
// Sig_structure, not JOSE's dot-concatenated header.payload) are all
// genuinely different encodings of the same underlying bitmap, not a
// re-wrap of token.go's JWT logic.
//
// Key-discovery scope (docs/design.md §27): only `x5chain` (RFC 9360,
// COSE header label 33) is supported here, the direct COSE analog of
// the JWT form's `x5c`. COSE has no standard header for a bare embedded
// verification key — JOSE's `jwk` header has no COSE equivalent — so
// unlike BuildToken, there is no bare-key option: a deployment with no
// certificate for its signing key publishes a CWT with no key-discovery
// header at all, the same fallback BuildToken has when both JWK and X5C
// are absent.
package statuslist

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// coseAlgES256 is the COSE Algorithms registry value for ES256 (RFC 9053
// §2.1) — the CWT analog of the JWT form's "ES256" alg string.
const coseAlgES256 = -7

// COSE header labels used here (RFC 9052 §3.1, RFC 9360 §2).
const (
	coseHeaderAlg     = 1
	coseHeaderKid     = 4
	coseHeaderTyp     = 16
	coseHeaderX5Chain = 33
)

// statuslistCWTContentType is the CWT form's `typ` header value
// (draft-ietf-oauth-status-list-21 §5.2), the COSE analog of the JWT
// form's "statuslist+jwt".
const statuslistCWTContentType = "application/statuslist+cwt"

// cwtEncMode is Core Deterministic CBOR (RFC 8949bis) — canonical map key
// ordering and shortest-form integers, matching COSE's own recommended
// encoding discipline (RFC 9052 §14) so two implementations building the
// same claims produce byte-identical output.
var cwtEncMode = func() cbor.EncMode {
	em, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(fmt.Sprintf("statuslist: build CBOR encode mode: %v", err))
	}
	return em
}()

// cwtStatusListClaim mirrors StatusListClaim, but §4.3 registers text
// string keys here (unlike the integer-keyed claims one level up) and
// Lst is a raw byte string, never base64-encoded (§4.3, unlike §4.2's
// JSON/JWT form).
type cwtStatusListClaim struct {
	Bits           int    `cbor:"bits"`
	Lst            []byte `cbor:"lst"`
	AggregationURI string `cbor:"aggregation_uri,omitempty"`
}

// cwtClaims is the CWT form's claim set (§5.2) — the integer-keyed
// analog of Claims.
type cwtClaims struct {
	Sub        string             `cbor:"2,keyasint"`
	Iat        int64              `cbor:"6,keyasint"`
	TTL        int64              `cbor:"65534,keyasint,omitempty"`
	StatusList cwtStatusListClaim `cbor:"65533,keyasint"`
}

// BuildCWTToken signs a Status List Token in CWT form (COSE_Sign1_Tagged,
// §5.2) over the given bitmap — the CBOR/COSE analog of BuildToken.
// key and p are the same inputs BuildToken takes; p.JWK is ignored (see
// the package doc's key-discovery scope note) and p.X5C, if set, is
// embedded as `x5chain` rather than `x5c`.
func BuildCWTToken(key crypto.Signer, p TokenParams) ([]byte, error) {
	pub, ok := key.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("statuslist: BuildCWTToken: signing key is not ECDSA (got %T)", key.Public())
	}
	if pub.Curve.Params().BitSize != 256 {
		return nil, fmt.Errorf("statuslist: BuildCWTToken: ES256 requires a P-256 key, got a %d-bit curve", pub.Curve.Params().BitSize)
	}

	compressed, err := compressLst(p.Bitmap.Bytes())
	if err != nil {
		return nil, err
	}

	claims := cwtClaims{
		Sub: p.ListURL,
		Iat: p.IssuedAt.Unix(),
		TTL: p.TTL,
		StatusList: cwtStatusListClaim{
			Bits: p.Bitmap.Bits(),
			Lst:  compressed,
		},
	}
	payload, err := cwtEncMode.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("statuslist: marshal CWT claims: %w", err)
	}

	protectedMap := map[int]any{
		coseHeaderAlg: coseAlgES256,
		coseHeaderTyp: statuslistCWTContentType,
	}
	if p.KeyID != "" {
		protectedMap[coseHeaderKid] = []byte(p.KeyID)
	}
	if len(p.X5C) > 0 {
		chain, err := decodeX5CToDER(p.X5C)
		if err != nil {
			return nil, err
		}
		if len(chain) == 1 {
			protectedMap[coseHeaderX5Chain] = chain[0]
		} else {
			protectedMap[coseHeaderX5Chain] = chain
		}
	}
	protected, err := cwtEncMode.Marshal(protectedMap)
	if err != nil {
		return nil, fmt.Errorf("statuslist: marshal COSE protected header: %w", err)
	}

	sig, err := signCOSESign1(key, protected, payload)
	if err != nil {
		return nil, err
	}

	unprotected := map[int]any{}
	tagged := cbor.Tag{
		Number:  18, // COSE_Sign1_Tagged, RFC 9052 §4.2
		Content: []any{protected, unprotected, payload, sig},
	}
	out, err := cwtEncMode.Marshal(tagged)
	if err != nil {
		return nil, fmt.Errorf("statuslist: marshal COSE_Sign1: %w", err)
	}
	return out, nil
}

// signCOSESign1 signs protected||payload per RFC 9052 §4.4's
// Sig_structure ("Signature1", body_protected, external_aad, payload),
// with an empty external_aad — this service has none to bind. Reuses
// asn1ToRawECDSA (signer.go): ES256's ASN.1-DER-to-raw-r‖s conversion is
// identical in COSE and JOSE, only the pre-image that gets hashed
// differs.
func signCOSESign1(key crypto.Signer, protected, payload []byte) ([]byte, error) {
	sigStructure := []any{"Signature1", protected, []byte{}, payload}
	toBeSigned, err := cwtEncMode.Marshal(sigStructure)
	if err != nil {
		return nil, fmt.Errorf("statuslist: marshal Sig_structure: %w", err)
	}

	hash := sha256.Sum256(toBeSigned)
	der, err := key.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("statuslist: sign COSE_Sign1: %w", err)
	}
	return asn1ToRawECDSA(der, 32) // P-256: 32-byte r, 32-byte s
}

// decodeX5CToDER decodes TokenParams.X5C's base64-STANDARD strings (the
// JWT `x5c` convention, RFC 7515 §4.1.6) back to raw DER — `x5chain`
// (RFC 9360) carries certificates as CBOR byte strings directly, with no
// base64 layer.
func decodeX5CToDER(x5c []string) ([][]byte, error) {
	chain := make([][]byte, len(x5c))
	for i, entry := range x5c {
		der, err := base64.StdEncoding.DecodeString(entry)
		if err != nil {
			return nil, fmt.Errorf("statuslist: x5c[%d] is not valid base64: %w", i, err)
		}
		chain[i] = der
	}
	return chain, nil
}

// CWTClaimsResult is what ParseCWTToken returns — the CWT analog of
// Claims. Lst is already decompressed (unlike Claims.StatusList.Lst,
// which is JWT's base64url text) and ready to pass to WrapBitmap.
type CWTClaimsResult struct {
	Subject        string
	IssuedAt       time.Time
	TTL            int64
	Bits           int
	Lst            []byte
	AggregationURI string
}

// ParseCWTToken verifies and decodes a CWT Status List Token against the
// given public key — the CBOR/COSE analog of ParseToken, existing for
// the same reason: round-trip testing, not production verification
// (which is a separate service's concern).
func ParseCWTToken(token []byte, key *ecdsa.PublicKey) (*CWTClaimsResult, error) {
	var tag cbor.RawTag
	if err := cbor.Unmarshal(token, &tag); err != nil {
		return nil, fmt.Errorf("statuslist: decode COSE_Sign1: %w", err)
	}
	if tag.Number != 18 {
		return nil, fmt.Errorf("statuslist: expected COSE_Sign1_Tagged (18), got tag %d", tag.Number)
	}

	var parts []cbor.RawMessage
	if err := cbor.Unmarshal(tag.Content, &parts); err != nil {
		return nil, fmt.Errorf("statuslist: decode COSE_Sign1 array: %w", err)
	}
	if len(parts) != 4 {
		return nil, fmt.Errorf("statuslist: COSE_Sign1 has %d elements, want 4", len(parts))
	}

	var protected, payload, sig []byte
	if err := cbor.Unmarshal(parts[0], &protected); err != nil {
		return nil, fmt.Errorf("statuslist: decode protected header: %w", err)
	}
	if err := cbor.Unmarshal(parts[2], &payload); err != nil {
		return nil, fmt.Errorf("statuslist: decode payload: %w", err)
	}
	if err := cbor.Unmarshal(parts[3], &sig); err != nil {
		return nil, fmt.Errorf("statuslist: decode signature: %w", err)
	}

	if err := verifyCOSESign1(key, protected, payload, sig); err != nil {
		return nil, err
	}

	var claims cwtClaims
	if err := cbor.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("statuslist: decode CWT claims: %w", err)
	}

	raw, err := decompressLst(claims.StatusList.Lst)
	if err != nil {
		return nil, fmt.Errorf("statuslist: decompress status_list.lst: %w", err)
	}

	return &CWTClaimsResult{
		Subject:        claims.Sub,
		IssuedAt:       time.Unix(claims.Iat, 0),
		TTL:            claims.TTL,
		Bits:           claims.StatusList.Bits,
		Lst:            raw,
		AggregationURI: claims.StatusList.AggregationURI,
	}, nil
}

func verifyCOSESign1(key *ecdsa.PublicKey, protected, payload, sig []byte) error {
	if len(sig) != 64 {
		return fmt.Errorf("statuslist: COSE_Sign1 signature is %d bytes, want 64 (raw r||s for P-256)", len(sig))
	}
	sigStructure := []any{"Signature1", protected, []byte{}, payload}
	toBeSigned, err := cwtEncMode.Marshal(sigStructure)
	if err != nil {
		return fmt.Errorf("statuslist: marshal Sig_structure: %w", err)
	}
	hash := sha256.Sum256(toBeSigned)

	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(key, hash[:], r, s) {
		return fmt.Errorf("statuslist: COSE_Sign1 signature verification failed")
	}
	return nil
}
