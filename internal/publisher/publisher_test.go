package publisher

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"testing"

	"github.com/sirosfoundation/siros-status-service/internal/statuslist"
	"github.com/sirosfoundation/siros-status-service/internal/store"
)

func TestNew_BuildsJWKFromECDSAKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	p, err := New(nil, nil, key, "test-key-1", "https://status.example.org", nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p.jwk == nil {
		t.Fatal("expected jwk to be derived from the signing key's public half")
	}
	wantJWK, err := statuslist.JWKFromPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("JWKFromPublicKey: %v", err)
	}
	if p.jwk["x"] != wantJWK["x"] || p.jwk["y"] != wantJWK["y"] {
		t.Errorf("jwk = %v, want %v", p.jwk, wantJWK)
	}
	if p.certChain != nil {
		t.Errorf("expected nil certChain when none was passed, got %v", p.certChain)
	}
}

func TestNew_StoresCertChain(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	chain := []string{"leaf", "intermediate"}

	p, err := New(map[string]*store.BitmapStore{}, nil, key, "kid", "https://status.example.org", chain)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(p.certChain) != 2 || p.certChain[0] != "leaf" || p.certChain[1] != "intermediate" {
		t.Errorf("certChain = %v, want %v", p.certChain, chain)
	}
}

// nonECDSASigner is a minimal crypto.Signer whose Public() is not ECDSA —
// exercises New's validation without depending on any real Ed25519 signing.
type nonECDSASigner struct{ pub ed25519.PublicKey }

func (s nonECDSASigner) Public() crypto.PublicKey { return s.pub }
func (s nonECDSASigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	panic("not used in this test")
}

func TestNew_RejectsNonECDSAKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}

	_, err = New(nil, nil, nonECDSASigner{pub: pub}, "kid", "https://status.example.org", nil)
	if err == nil {
		t.Fatal("expected an error for a non-ECDSA signing key")
	}
}
