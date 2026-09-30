//go:build pkcs11

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
// in-memory path; the PKCS#11 session pool for that path). This is the
// `-tags pkcs11` build — see the package doc (signing.go) for why this
// is a separate build at all rather than an unconditional import.
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
