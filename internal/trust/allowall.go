package trust

import "context"

// AllowAllEvaluator trusts every name-to-key binding unconditionally.
// This is the default when no PDP is configured (docs/design.md §15.2,
// decided 2026-09-24): fail *open* in that case, so a prototype/dev
// deployment works without standing up a PDP first. This is explicitly
// not a production posture — see cmd/as's startup log warning when it's
// selected.
//
// This mirrors go-trust's own AllowAllEvaluator concept (see
// project memory: "AllowAllEvaluator.ResolveKey erroring is BY DESIGN"),
// reimplemented locally for the same reason internal/trust doesn't
// import go-trust as a Go dependency at all (see authzen.go's doc
// comment on the toolchain version gap).
type AllowAllEvaluator struct{}

func (AllowAllEvaluator) Name() string { return "allow-all" }

func (AllowAllEvaluator) Evaluate(ctx context.Context, subjectID string, cred Credential) (Decision, error) {
	return Decision{Trusted: true, Reason: "no trust PDP configured (fail-open default)"}, nil
}
