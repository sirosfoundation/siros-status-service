//go:build !pkcs11

package signing

import (
	"crypto"
	"fmt"
	"io"

	"github.com/sirosfoundation/siros-status-service/internal/config"
)

// NewSigner resolves src into a crypto.Signer plus an io.Closer to
// release whatever resources it holds on shutdown (a no-op here — see
// the package doc: this is the default, untagged build, which never
// links the PKCS#11 driver at all).
func NewSigner(src config.SigningSource) (crypto.Signer, io.Closer, error) {
	if src.PKCS11 == nil {
		// *ecdsa.PrivateKey implements crypto.Signer natively — nothing
		// to wrap.
		return src.Key, noopCloser{}, nil
	}
	return nil, nil, fmt.Errorf("signing: PKCS11_MODULE_PATH is set, but this binary was built without PKCS#11 support — rebuild with -tags pkcs11 (requires CGO_ENABLED=1 and a C toolchain); see internal/signing's package doc (docs/design.md §26)")
}
