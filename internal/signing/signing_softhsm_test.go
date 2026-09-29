package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/sirosfoundation/siros-status-service/internal/config"
	"github.com/sirosfoundation/siros-status-service/internal/statuslist"
)

// softHSMConfig initializes a real (software) SoftHSM token and returns a
// config.PKCS11Config pointing at it — the same harness shape as
// go-cryptoutil/pkcs11pool's own pool_test.go, so a real end-to-end test
// exercises the exact PKCS#11 module/token/key flow a real HSM deployment
// would, not a mock.
func softHSMConfig(t *testing.T) config.PKCS11Config {
	t.Helper()

	if _, err := exec.LookPath("softhsm2-util"); err != nil {
		t.Skip("softhsm2-util not found; skipping PKCS#11 integration test")
	}
	modulePath := ""
	for _, p := range []string{
		"/usr/lib/softhsm/libsofthsm2.so",
		"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
		"/usr/local/lib/softhsm/libsofthsm2.so",
	} {
		if _, err := os.Stat(p); err == nil {
			modulePath = p
			break
		}
	}
	if modulePath == "" {
		t.Skip("SoftHSM2 module not found")
	}

	tmpDir := t.TempDir()
	tokenDir := filepath.Join(tmpDir, "tokens")
	if err := os.MkdirAll(tokenDir, 0o700); err != nil {
		t.Fatal(err)
	}
	confFile := filepath.Join(tmpDir, "softhsm2.conf")
	if err := os.WriteFile(confFile, []byte("directories.tokendir = "+tokenDir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOFTHSM2_CONF", confFile)

	initCmd := exec.Command("softhsm2-util", "--init-token", "--slot", "0",
		"--label", "status-list-test", "--pin", "1234", "--so-pin", "5678")
	initCmd.Env = append(os.Environ(), "SOFTHSM2_CONF="+confFile)
	if out, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("softhsm2-util --init-token failed: %v\n%s", err, out)
	}

	keyLabel := "status-list-signing-key"
	genCmd := exec.Command("pkcs11-tool", "--module", modulePath,
		"--token-label", "status-list-test", "--pin", "1234",
		"--keypairgen", "--key-type", "EC:prime256v1", "--label", keyLabel,
		"--id", "01")
	genCmd.Env = append(os.Environ(), "SOFTHSM2_CONF="+confFile)
	if out, err := genCmd.CombinedOutput(); err != nil {
		t.Fatalf("pkcs11-tool --keypairgen failed: %v\n%s", err, out)
	}

	return config.PKCS11Config{
		ModulePath: modulePath,
		TokenLabel: "status-list-test",
		PIN:        "1234",
		KeyLabel:   keyLabel,
		PoolSize:   2,
	}
}

// TestNewSigner_PKCS11_SignsAndVerifiesRealStatusListToken proves the full
// path end to end against a real (software) HSM: config.SigningSource ->
// NewSigner -> a crypto.Signer whose private key never leaves the token ->
// statuslist.BuildToken (via the custom es256CryptoSignerMethod, since
// jwt.SigningMethodES256 itself cannot accept this signer) -> ParseToken
// against the same key's public half.
func TestNewSigner_PKCS11_SignsAndVerifiesRealStatusListToken(t *testing.T) {
	pkcs11Cfg := softHSMConfig(t)

	signer, closer, err := NewSigner(config.SigningSource{PKCS11: &pkcs11Cfg})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("signer.Public() is not an ECDSA key: %T", signer.Public())
	}

	jwk, err := statuslist.JWKFromPublicKey(pub)
	if err != nil {
		t.Fatalf("JWKFromPublicKey: %v", err)
	}

	bm, err := statuslist.NewBitmap(10, 1)
	if err != nil {
		t.Fatalf("NewBitmap: %v", err)
	}
	if err := bm.Set(3, statuslist.StatusInvalid); err != nil {
		t.Fatalf("Set: %v", err)
	}

	token, err := statuslist.BuildToken(signer, statuslist.TokenParams{
		ListURL: "https://status.example.org/lists/hsm-test",
		Bitmap:  bm,
		KeyID:   "hsm-key-1",
		JWK:     jwk,
	})
	if err != nil {
		t.Fatalf("BuildToken (PKCS#11-backed signer): %v", err)
	}

	claims, err := statuslist.ParseToken(token, pub)
	if err != nil {
		t.Fatalf("ParseToken: %v", err)
	}
	if claims.Subject != "https://status.example.org/lists/hsm-test" {
		t.Errorf("sub = %q", claims.Subject)
	}

	// A second, freshly-opened pool against the same token/key (opened
	// only after the first is closed — the underlying PKCS#11 module
	// rejects a concurrent second C_Initialize in one process) must
	// produce signatures verifiable against the same public key — proves
	// the key is stable/persisted in the token, not an ephemeral
	// in-process key.
	if err := closer.Close(); err != nil {
		t.Fatalf("close first pool: %v", err)
	}
	signer2, closer2, err := NewSigner(config.SigningSource{PKCS11: &pkcs11Cfg})
	if err != nil {
		t.Fatalf("NewSigner (second pool): %v", err)
	}
	defer func() { _ = closer2.Close() }()
	pub2, ok := signer2.Public().(*ecdsa.PublicKey)
	if !ok || !pub2.Equal(pub) {
		t.Fatalf("second signer's public key does not match the first: %v vs %v", pub2, pub)
	}

	token2, err := statuslist.BuildToken(signer2, statuslist.TokenParams{
		ListURL: "https://status.example.org/lists/hsm-test-2",
		Bitmap:  bm,
	})
	if err != nil {
		t.Fatalf("BuildToken (second signer): %v", err)
	}
	if _, err := statuslist.ParseToken(token2, pub); err != nil {
		t.Fatalf("ParseToken (second signer's token against first signer's public key): %v", err)
	}
}

func TestNewSigner_PKCS11_UnknownKeyLabelErrors(t *testing.T) {
	pkcs11Cfg := softHSMConfig(t)
	pkcs11Cfg.KeyLabel = "no-such-key-on-this-token"

	_, _, err := NewSigner(config.SigningSource{PKCS11: &pkcs11Cfg})
	if err == nil {
		t.Fatal("expected an error for a key label that doesn't exist on the token")
	}
}

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
