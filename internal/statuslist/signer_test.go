package statuslist

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func generateEd25519(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	t.Helper()
	return ed25519.GenerateKey(rand.Reader)
}

func TestEs256CryptoSignerMethod_SignVerifyRoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	method := es256CryptoSignerMethod{}

	sig, err := method.Sign("signing-input", key)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("signature length = %d, want 64 (raw r||s for P-256)", len(sig))
	}

	// The stock ES256 method must accept what this one produces — proves
	// the wire format really is identical, not just internally consistent.
	if err := jwt.SigningMethodES256.Verify("signing-input", sig, &key.PublicKey); err != nil {
		t.Errorf("stock ES256 rejected our signature: %v", err)
	}
	if err := method.Verify("signing-input", sig, &key.PublicKey); err != nil {
		t.Errorf("Verify rejected our own signature: %v", err)
	}
}

func TestEs256CryptoSignerMethod_AcceptsStockSignatures(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sig, err := jwt.SigningMethodES256.Sign("signing-input", key)
	if err != nil {
		t.Fatalf("stock Sign: %v", err)
	}
	if err := (es256CryptoSignerMethod{}).Verify("signing-input", sig, &key.PublicKey); err != nil {
		t.Errorf("our Verify rejected a stock ES256 signature: %v", err)
	}
}

func TestEs256CryptoSignerMethod_RejectsNonSigner(t *testing.T) {
	if _, err := (es256CryptoSignerMethod{}).Sign("x", "not-a-signer"); err == nil {
		t.Fatal("expected an error for a key that does not implement crypto.Signer")
	}
}

func TestEs256CryptoSignerMethod_RejectsNonECDSAKey(t *testing.T) {
	// ed25519 implements crypto.Signer but is not ECDSA — must be rejected
	// before ever reaching asn1ToRawECDSA.
	_, priv, err := generateEd25519(t)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	if _, err := (es256CryptoSignerMethod{}).Sign("x", priv); err == nil {
		t.Fatal("expected an error for a non-ECDSA crypto.Signer")
	}
}

func TestAsn1ToRawECDSA_RoundTrip(t *testing.T) {
	r := big.NewInt(12345)
	s := big.NewInt(67890)
	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		t.Fatalf("asn1.Marshal: %v", err)
	}

	raw, err := asn1ToRawECDSA(der, 32)
	if err != nil {
		t.Fatalf("asn1ToRawECDSA: %v", err)
	}
	if len(raw) != 64 {
		t.Fatalf("length = %d, want 64", len(raw))
	}

	gotR := new(big.Int).SetBytes(raw[:32])
	gotS := new(big.Int).SetBytes(raw[32:])
	if gotR.Cmp(r) != 0 {
		t.Errorf("r = %v, want %v", gotR, r)
	}
	if gotS.Cmp(s) != 0 {
		t.Errorf("s = %v, want %v", gotS, s)
	}
}

func TestAsn1ToRawECDSA_RejectsGarbage(t *testing.T) {
	if _, err := asn1ToRawECDSA([]byte{0xFF, 0xFF, 0xFF}, 32); err == nil {
		t.Fatal("expected an error for invalid ASN.1 input")
	}
}
