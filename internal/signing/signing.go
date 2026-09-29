// Package signing turns a config.SigningSource into a real crypto.Signer
// (docs/design.md §26) — an in-memory *ecdsa.PrivateKey (already a
// crypto.Signer, Go's standard library), or a pooled PKCS#11-backed
// signer (github.com/sirosfoundation/go-cryptoutil/pkcs11pool) that
// never exposes the private key material to this process at all.
//
// Deliberately its own package, separate from internal/config: config
// stays a thin env-var loader with no PKCS#11 driver dependency and no
// I/O — actually connecting to an HSM is a real, potentially slow or
// failing operation, done here, at the same point cmd/ingestion-service
// and cmd/verifier-service already connect to Postgres/Redis, not
// buried inside config loading.
package signing

import (
	"crypto"
	"fmt"
	"io"

	"github.com/sirosfoundation/go-cryptoutil/pkcs11pool"

	"github.com/sirosfoundation/siros-status-service/internal/config"
)

// NewSigner resolves src into a crypto.Signer plus an io.Closer to
// release whatever resources it holds on shutdown (a no-op for the
// in-memory path; the PKCS#11 session pool for that path).
func NewSigner(src config.SigningSource) (crypto.Signer, io.Closer, error) {
	if src.PKCS11 == nil {
		// *ecdsa.PrivateKey implements crypto.Signer natively — nothing
		// to wrap.
		return src.Key, noopCloser{}, nil
	}

	pool, err := pkcs11pool.New(pkcs11pool.Config{
		ModulePath: src.PKCS11.ModulePath,
		TokenLabel: src.PKCS11.TokenLabel,
		SlotID:     src.PKCS11.SlotID,
		PIN:        src.PKCS11.PIN,
		PoolSize:   src.PKCS11.PoolSize,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("signing: open PKCS#11 pool: %w", err)
	}

	signer, err := pkcs11pool.NewSigner(pool, pkcs11pool.KeyByLabel(src.PKCS11.KeyLabel))
	if err != nil {
		_ = pool.Close()
		return nil, nil, fmt.Errorf("signing: create PKCS#11 signer for key %q: %w", src.PKCS11.KeyLabel, err)
	}
	return signer, pool, nil
}

type noopCloser struct{}

func (noopCloser) Close() error { return nil }
