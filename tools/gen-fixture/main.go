// Command gen-fixture regenerates rust/token-format/testdata/{token.txt,jwks.json}
// — a real access token minted by internal/accesstoken.KeyManager (the exact
// code path cmd/as uses) plus its JWKS, so the Rust token-format crate's
// tests decode/verify a token that genuinely came out of this service's own
// issuance path, not a hand-crafted lookalike. Re-run this
// (`go run ./tools/gen-fixture`) whenever AccessTokenClaims' shape changes.
//
// The signing key is fixed (not randomly generated) so the fixture is
// reproducible and diffs cleanly in git when regenerated.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	tokenauthclaims "github.com/sirosfoundation/go-tokenauth/claims"

	"github.com/sirosfoundation/siros-status-service/internal/accesstoken"
)

// Fixed test-only P-256 key (never used for anything but this fixture) so
// regenerating produces a byte-identical JWKS every time.
const fixedKeyD = "9c46e9ec5c9fbb9e6f74c8f2e4c0eefcdbb03c5b0d5fbf2b3e4b6c9e5f4d3c2b"

func main() {
	seed, err := hex.DecodeString(fixedKeyD)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen-fixture: bad hex constant:", err)
		os.Exit(1)
	}
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), seed)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen-fixture: parse fixed private key:", err)
		os.Exit(1)
	}

	km := accesstoken.NewKeyManager(key, "test-key-1")

	now := time.Now()
	token, err := km.Issue(accesstoken.IssueParams{
		Issuer:   "https://as.example.org",
		Audience: "siros-status-service",
		Subject:  "issuer-abc",
		TenantID: "shard-a",
		TAC:      tokenauthclaims.TAC("iwr"),
		TTL:      time.Hour,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen-fixture: issue:", err)
		os.Exit(1)
	}

	jwks, err := json.MarshalIndent(km.JWKS(), "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen-fixture: marshal jwks:", err)
		os.Exit(1)
	}

	// Also dump the raw private key PEM, purely for anyone regenerating the
	// fixture by hand later or cross-checking with another tool — not
	// consumed by the Rust tests, which only ever see the public JWKS.
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen-fixture: marshal key:", err)
		os.Exit(1)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	outDir := filepath.Join("rust", "token-format", "testdata")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "gen-fixture: mkdir:", err)
		os.Exit(1)
	}
	writeFile(filepath.Join(outDir, "token.txt"), []byte(token+"\n"))
	writeFile(filepath.Join(outDir, "jwks.json"), append(jwks, '\n'))
	writeFile(filepath.Join(outDir, "signing_key.pem"), keyPEM)

	fmt.Printf("wrote fixture to %s (issued_at=%s, expires_at=%s)\n", outDir, now.Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339))
}

func writeFile(path string, data []byte) {
	if err := os.WriteFile(path, data, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "gen-fixture: write", path, ":", err)
		os.Exit(1)
	}
}
