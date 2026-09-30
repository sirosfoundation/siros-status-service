//go:build !pkcs11

package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/sirosfoundation/siros-status-service/internal/config"
)

func TestNewSigner_InMemoryKeyBypassesPKCS11(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, closer, err := NewSigner(config.SigningSource{Key: key})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	defer func() { _ = closer.Close() }()

	if signer != crypto.Signer(key) {
		t.Error("expected NewSigner to return the *ecdsa.PrivateKey itself unwrapped, for the in-memory path")
	}
}

func TestNewSigner_PKCS11ConfiguredWithoutBuildTagErrors(t *testing.T) {
	pkcs11Cfg := config.PKCS11Config{
		ModulePath: "/usr/lib/softhsm/libsofthsm2.so",
		TokenLabel: "some-token",
		KeyLabel:   "some-key",
		PIN:        "1234",
	}
	_, _, err := NewSigner(config.SigningSource{PKCS11: &pkcs11Cfg})
	if err == nil {
		t.Fatal("expected an error: this build was compiled without -tags pkcs11, so PKCS#11 config must be refused, not silently ignored")
	}
}
