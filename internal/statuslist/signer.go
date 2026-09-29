package statuslist

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/golang-jwt/jwt/v5"
)

// es256CryptoSignerMethod is a jwt.SigningMethod for ES256 that signs
// through the standard library's crypto.Signer interface instead of
// requiring a concrete *ecdsa.PrivateKey the way jwt.SigningMethodES256
// does — needed for §26's PKCS#11 support, where the private key never
// leaves the HSM and there is no *ecdsa.PrivateKey to hand golang-jwt at
// all, only a crypto.Signer.
//
// *ecdsa.PrivateKey and *pkcs11pool.Signer both implement crypto.Signer
// and both return an ASN.1 DER-encoded signature from Sign (Go's
// standard convention for crypto.Signer + ECDSA — see crypto/ecdsa's own
// doc), so this one method handles both signing backends identically;
// BuildToken always uses it, never the stock jwt.SigningMethodES256.
//
// JWS ES256 (RFC 7518 §3.4) requires the raw, fixed-width r||s
// concatenation, not ASN.1 DER — asn1ToRawECDSA does that conversion.
// Verification is unaffected: the wire format this produces is
// byte-for-byte what jwt.SigningMethodES256 itself produces, so
// ParseToken (and any real verifier) keeps using the stock method to
// verify regardless of which method signed it.
type es256CryptoSignerMethod struct{}

func (es256CryptoSignerMethod) Alg() string { return "ES256" }

func (es256CryptoSignerMethod) Sign(signingString string, key any) ([]byte, error) {
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("statuslist: sign: key does not implement crypto.Signer (got %T)", key)
	}
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("statuslist: sign: signer's public key is not an ECDSA key (got %T)", signer.Public())
	}
	if pub.Curve.Params().BitSize != 256 {
		return nil, fmt.Errorf("statuslist: sign: ES256 requires a P-256 key, got a %d-bit curve", pub.Curve.Params().BitSize)
	}

	hash := sha256.Sum256([]byte(signingString))
	der, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("statuslist: sign: %w", err)
	}
	return asn1ToRawECDSA(der, 32) // P-256: 32-byte r, 32-byte s
}

func (es256CryptoSignerMethod) Verify(signingString string, sig []byte, key any) error {
	// The wire format is identical regardless of which method signed it
	// — delegate to the stock method rather than duplicating its
	// (already-correct) raw-r||s verification.
	return jwt.SigningMethodES256.Verify(signingString, sig, key)
}

// asn1ToRawECDSA converts an ASN.1 DER ECDSA signature (crypto.Signer's
// standard output) to JWS's raw, fixed-width r||s concatenation (RFC
// 7518 §3.4) — the exact inverse of the raw-to-ASN.1 conversion a PKCS#11
// token's own C_Sign output needs before it can implement crypto.Signer
// correctly (already handled inside pkcs11pool itself, not this
// service's concern) — big.Int.FillBytes left-pads each of r and s to
// byteLen, matching a fixed-width field that's always exactly this long
// for a valid P-256 signature.
func asn1ToRawECDSA(der []byte, byteLen int) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		return nil, fmt.Errorf("statuslist: parse ASN.1 ECDSA signature: %w", err)
	}
	out := make([]byte, 2*byteLen)
	sig.R.FillBytes(out[:byteLen])
	sig.S.FillBytes(out[byteLen:])
	return out, nil
}
