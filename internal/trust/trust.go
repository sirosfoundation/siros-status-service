// Package trust decides whether a name-to-key binding presented by an
// issuer is trustworthy (docs/design.md §15.2). This is deliberately a
// small interface with swappable implementations, mirroring the shape of
// go-trust's own pkg/trustapi.TrustEvaluator, so a real go-trust-backed
// evaluator is a drop-in later without touching any caller.
package trust

import "context"

// Decision is the outcome of a trust evaluation.
type Decision struct {
	Trusted bool
	Reason  string
}

// Evaluator decides whether the given JWK is a trusted signing key for
// subjectID acting as an issuer. Implementations should not error for a
// "not trusted" outcome — that's Decision.Trusted == false — only for
// genuine failures (network, malformed input) that keep them from
// answering at all.
type Evaluator interface {
	Evaluate(ctx context.Context, subjectID string, jwk map[string]any) (Decision, error)
	Name() string
}
