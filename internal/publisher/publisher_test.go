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

// TestJWKS_CarriesTheSigningKeyAndTokenKid: the JWK Set served under a
// list URI (docs/design.md §28) holds the signing key's public half
// with the kid tokens are signed under, and each call returns its own
// copy.
func TestJWKS_CarriesTheSigningKeyAndTokenKid(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	p, err := New(nil, nil, key, "test-key-1", "https://status.example.org", nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	set := p.JWKS()
	keys, ok := set["keys"].([]any)
	if !ok || len(keys) != 1 {
		t.Fatalf("keys = %v, want a one-element array", set["keys"])
	}
	jwk := keys[0].(map[string]any)
	wantJWK, err := statuslist.JWKFromPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("JWKFromPublicKey: %v", err)
	}
	for _, member := range []string{"kty", "crv", "x", "y"} {
		if jwk[member] != wantJWK[member] {
			t.Errorf("jwk[%q] = %v, want %v", member, jwk[member], wantJWK[member])
		}
	}
	if jwk["kid"] != "test-key-1" || jwk["use"] != "sig" || jwk["alg"] != "ES256" {
		t.Errorf("kid/use/alg = %v/%v/%v, want test-key-1/sig/ES256", jwk["kid"], jwk["use"], jwk["alg"])
	}

	jwk["x"] = "tampered"
	again := p.JWKS()["keys"].([]any)[0].(map[string]any)
	if again["x"] != wantJWK["x"] {
		t.Error("mutating a returned JWK Set changed the publisher's key")
	}
	if _, leaked := p.jwk["kid"]; leaked {
		t.Error("JWKS() wrote kid into the publisher's shared jwk map")
	}
}

// TestJWKS_OmitsKidWhenNoKeyIDConfigured mirrors BuildToken, which
// signs without a kid header when no key id is configured.
func TestJWKS_OmitsKidWhenNoKeyIDConfigured(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	p, err := New(nil, nil, key, "", "https://status.example.org", nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	jwk := p.JWKS()["keys"].([]any)[0].(map[string]any)
	if _, has := jwk["kid"]; has {
		t.Errorf("kid = %v, want it absent", jwk["kid"])
	}
}
