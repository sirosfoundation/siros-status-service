package trust

import "context"

// Any tries each evaluator in order and returns the first Trusted
// decision, or the last (untrusted) decision if none trust it — the AS
// (docs/design.md §15.2) uses this to combine the always-available
// StaticRegistryEvaluator with an optional AuthZENEvaluator when a
// TRUST_PDP_URL is configured, without either evaluator needing to know
// about the other.
type Any []Evaluator

func (a Any) Name() string { return "any" }

func (a Any) Evaluate(ctx context.Context, subjectID string, jwk map[string]any) (Decision, error) {
	var last Decision
	for _, e := range a {
		d, err := e.Evaluate(ctx, subjectID, jwk)
		if err != nil {
			return Decision{}, err
		}
		if d.Trusted {
			return d, nil
		}
		last = d
	}
	if last.Reason == "" {
		last.Reason = "no evaluators configured"
	}
	return last, nil
}
