// Package signing turns a config.SigningSource into a real crypto.Signer
// (docs/design.md §26) — an in-memory *ecdsa.PrivateKey (already a
// crypto.Signer, Go's standard library), or, in a `-tags pkcs11` build
// (signing_pkcs11.go), a pooled PKCS#11-backed signer
// (github.com/sirosfoundation/go-cryptoutil/pkcs11pool) that never
// exposes the private key material to this process at all.
//
// PKCS#11 support is gated behind a build tag, not just the runtime
// config check config.SigningSource already does — this is a real
// compile-time constraint, not just a deployment preference. A PKCS#11
// client dlopens a vendor-provided C shared object at runtime, which
// requires cgo; this repo's production Dockerfile builds a fully static
// CGO_ENABLED=0 binary (a deliberate choice: no libc/cgo runtime
// dependency at all), and the two are simply incompatible in one binary.
// The default, untagged build (signing_default.go) refuses PKCS#11
// config with a clear, actionable error instead of either silently
// ignoring it or breaking the static build for every deployment whether
// or not it uses an HSM. A deployment that actually needs PKCS#11 HSM
// signing builds instead with `-tags pkcs11 CGO_ENABLED=1` and a C
// toolchain (signing_pkcs11.go) — its own separate image, not this
// repo's default one.
//
// Deliberately its own package, separate from internal/config: config
// stays a thin env-var loader with no PKCS#11 driver dependency and no
// I/O — actually connecting to an HSM is a real, potentially slow or
// failing operation, done here, at the same point cmd/ingestion-service
// and cmd/verifier-service already connect to Postgres/Redis, not
// buried inside config loading.
package signing

type noopCloser struct{}

func (noopCloser) Close() error { return nil }
