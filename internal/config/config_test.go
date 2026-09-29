package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func testECKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

func testSelfSignedCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "status-list-test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestLoadSigningSource_DefaultsToPEMKey(t *testing.T) {
	t.Setenv("SIGNING_KEY_PEM", testECKeyPEM(t))

	src, err := loadSigningSource("SIGNING_KEY_PEM")
	if err != nil {
		t.Fatalf("loadSigningSource: %v", err)
	}
	if src.Key == nil {
		t.Error("expected Key to be set")
	}
	if src.PKCS11 != nil {
		t.Error("expected PKCS11 to be nil when PKCS11_MODULE_PATH is unset")
	}
}

func TestLoadSigningSource_MissingPEMKeyErrors(t *testing.T) {
	if _, err := loadSigningSource("SIGNING_KEY_PEM"); err == nil {
		t.Fatal("expected an error when neither PKCS11_MODULE_PATH nor the PEM env var is set")
	}
}

func TestLoadSigningSource_RejectsBothConfigured(t *testing.T) {
	t.Setenv("SIGNING_KEY_PEM", testECKeyPEM(t))
	t.Setenv("PKCS11_MODULE_PATH", "/usr/lib/softhsm/libsofthsm2.so")
	t.Setenv("PKCS11_TOKEN_LABEL", "test")
	t.Setenv("PKCS11_KEY_LABEL", "test-key")
	t.Setenv("PKCS11_PIN", "1234")

	if _, err := loadSigningSource("SIGNING_KEY_PEM"); err == nil {
		t.Fatal("expected an error when both PKCS11_MODULE_PATH and the PEM env var are set")
	}
}

func TestLoadSigningSource_PKCS11Path(t *testing.T) {
	t.Setenv("PKCS11_MODULE_PATH", "/usr/lib/softhsm/libsofthsm2.so")
	t.Setenv("PKCS11_TOKEN_LABEL", "my-token")
	t.Setenv("PKCS11_KEY_LABEL", "my-key")
	t.Setenv("PKCS11_PIN", "1234")
	t.Setenv("PKCS11_POOL_SIZE", "8")

	src, err := loadSigningSource("SIGNING_KEY_PEM")
	if err != nil {
		t.Fatalf("loadSigningSource: %v", err)
	}
	if src.Key != nil {
		t.Error("expected Key to be nil on the PKCS#11 path")
	}
	if src.PKCS11 == nil {
		t.Fatal("expected PKCS11 to be set")
	}
	if src.PKCS11.ModulePath != "/usr/lib/softhsm/libsofthsm2.so" {
		t.Errorf("ModulePath = %q", src.PKCS11.ModulePath)
	}
	if src.PKCS11.TokenLabel != "my-token" {
		t.Errorf("TokenLabel = %q", src.PKCS11.TokenLabel)
	}
	if src.PKCS11.KeyLabel != "my-key" {
		t.Errorf("KeyLabel = %q", src.PKCS11.KeyLabel)
	}
	if src.PKCS11.PIN != "1234" {
		t.Errorf("PIN = %q", src.PKCS11.PIN)
	}
	if src.PKCS11.PoolSize != 8 {
		t.Errorf("PoolSize = %d, want 8", src.PKCS11.PoolSize)
	}
}

func TestLoadSigningSource_PKCS11DefaultsPoolSize(t *testing.T) {
	t.Setenv("PKCS11_MODULE_PATH", "/usr/lib/softhsm/libsofthsm2.so")
	t.Setenv("PKCS11_TOKEN_LABEL", "my-token")
	t.Setenv("PKCS11_KEY_LABEL", "my-key")
	t.Setenv("PKCS11_PIN", "1234")

	src, err := loadSigningSource("SIGNING_KEY_PEM")
	if err != nil {
		t.Fatalf("loadSigningSource: %v", err)
	}
	if src.PKCS11.PoolSize != 4 {
		t.Errorf("PoolSize = %d, want default of 4", src.PKCS11.PoolSize)
	}
}

func TestLoadSigningSource_PKCS11RequiresTokenLabel(t *testing.T) {
	t.Setenv("PKCS11_MODULE_PATH", "/usr/lib/softhsm/libsofthsm2.so")
	t.Setenv("PKCS11_KEY_LABEL", "my-key")
	t.Setenv("PKCS11_PIN", "1234")

	if _, err := loadSigningSource("SIGNING_KEY_PEM"); err == nil {
		t.Fatal("expected an error when PKCS11_TOKEN_LABEL is missing")
	}
}

func TestLoadSigningSource_PKCS11RequiresKeyLabel(t *testing.T) {
	t.Setenv("PKCS11_MODULE_PATH", "/usr/lib/softhsm/libsofthsm2.so")
	t.Setenv("PKCS11_TOKEN_LABEL", "my-token")
	t.Setenv("PKCS11_PIN", "1234")

	if _, err := loadSigningSource("SIGNING_KEY_PEM"); err == nil {
		t.Fatal("expected an error when PKCS11_KEY_LABEL is missing")
	}
}

func TestLoadSigningSource_PKCS11RequiresPIN(t *testing.T) {
	t.Setenv("PKCS11_MODULE_PATH", "/usr/lib/softhsm/libsofthsm2.so")
	t.Setenv("PKCS11_TOKEN_LABEL", "my-token")
	t.Setenv("PKCS11_KEY_LABEL", "my-key")

	if _, err := loadSigningSource("SIGNING_KEY_PEM"); err == nil {
		t.Fatal("expected an error when PKCS11_PIN is missing")
	}
}

func TestOptionalCertChainEnv_UnsetReturnsNilNoError(t *testing.T) {
	chain, err := optionalCertChainEnv("SIGNING_CERT_CHAIN_PEM")
	if err != nil {
		t.Fatalf("expected no error when unset, got %v", err)
	}
	if chain != nil {
		t.Errorf("expected nil chain when unset, got %v", chain)
	}
}

func TestOptionalCertChainEnv_SingleCert(t *testing.T) {
	t.Setenv("SIGNING_CERT_CHAIN_PEM", testSelfSignedCertPEM(t))

	chain, err := optionalCertChainEnv("SIGNING_CERT_CHAIN_PEM")
	if err != nil {
		t.Fatalf("optionalCertChainEnv: %v", err)
	}
	if len(chain) != 1 {
		t.Fatalf("chain has %d entries, want 1", len(chain))
	}
	if _, err := x509.ParseCertificate(mustBase64Decode(t, chain[0])); err != nil {
		t.Errorf("chain[0] is not valid DER: %v", err)
	}
}

func TestOptionalCertChainEnv_MultipleCertsLeafFirst(t *testing.T) {
	leaf := testSelfSignedCertPEM(t)
	intermediate := testSelfSignedCertPEM(t)
	t.Setenv("SIGNING_CERT_CHAIN_PEM", leaf+intermediate)

	chain, err := optionalCertChainEnv("SIGNING_CERT_CHAIN_PEM")
	if err != nil {
		t.Fatalf("optionalCertChainEnv: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("chain has %d entries, want 2", len(chain))
	}
}

func TestOptionalCertChainEnv_NoPEMBlockErrors(t *testing.T) {
	t.Setenv("SIGNING_CERT_CHAIN_PEM", "not a pem file at all")

	if _, err := optionalCertChainEnv("SIGNING_CERT_CHAIN_PEM"); err == nil {
		t.Fatal("expected an error for a value with no PEM CERTIFICATE block")
	}
}

func mustBase64Decode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	return b
}
