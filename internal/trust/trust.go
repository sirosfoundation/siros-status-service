// Package trust decides whether a name-to-key binding presented by an
// issuer is trustworthy (docs/design.md §15.2/§20). This is deliberately
// a small interface with swappable implementations, mirroring the shape
// of go-trust's own pkg/trustapi.TrustEvaluator, so a real go-trust-backed
// evaluator is a drop-in later without touching any caller.
package trust

import "context"

// Decision is the outcome of a trust evaluation.
type Decision struct {
	Trusted bool
	Reason  string
}

// Credential proof types, matching go-trust's AuthZEN wire protocol's
// resource.type values exactly (verified against go-trust/pkg/authzen's
// own struct definitions and tests) — "jwk" for a bare public key,
// "x5c" for an X.509 certificate chain.
const (
	CredentialJWK = "jwk"
	CredentialX5C = "x5c"
)

// Credential is the proof of possession an issuer's client assertion
// carried (internal/clientassertion.Result) — exactly one of JWK or X5C
// populated, matching Type.
type Credential struct {
	Type string
	JWK  map[string]any
	// X5C is the certificate chain, leaf first, each entry
	// base64-STANDARD-encoded DER — see internal/clientassertion.Result.X5C.
	X5C []string
}

// CredentialFromJWK builds a Credential for a bare-public-key assertion.
func CredentialFromJWK(jwk map[string]any) Credential {
	return Credential{Type: CredentialJWK, JWK: jwk}
}

// CredentialFromX5C builds a Credential for an X.509-chain assertion.
func CredentialFromX5C(chain []string) Credential {
	return Credential{Type: CredentialX5C, X5C: chain}
}

// Evaluator decides whether the given credential is a trusted signing
// identity for subjectID acting as an issuer. Implementations should not
// error for a "not trusted" outcome — that's Decision.Trusted == false —
// only for genuine failures (network, malformed input) that keep them
// from answering at all.
type Evaluator interface {
	Evaluate(ctx context.Context, subjectID string, cred Credential) (Decision, error)
	Name() string
}
