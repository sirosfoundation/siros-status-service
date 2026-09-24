package trust

import (
	"context"
	"errors"
	"testing"
)

type stubEvaluator struct {
	decision Decision
	err      error
	called   *int
}

func (s stubEvaluator) Name() string { return "stub" }

func (s stubEvaluator) Evaluate(ctx context.Context, subjectID string, jwk map[string]any) (Decision, error) {
	if s.called != nil {
		*s.called++
	}
	return s.decision, s.err
}

func TestAny_ReturnsFirstTrustedDecision(t *testing.T) {
	firstCalled, secondCalled := 0, 0
	a := Any{
		stubEvaluator{decision: Decision{Trusted: false, Reason: "not in this one"}, called: &firstCalled},
		stubEvaluator{decision: Decision{Trusted: true, Reason: "found here"}, called: &secondCalled},
	}

	d, err := a.Evaluate(context.Background(), "issuer-a", nil)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !d.Trusted || d.Reason != "found here" {
		t.Fatalf("got %+v, want Trusted=true Reason=\"found here\"", d)
	}
	if firstCalled != 1 || secondCalled != 1 {
		t.Fatalf("expected both evaluators called once each, got first=%d second=%d", firstCalled, secondCalled)
	}
}

func TestAny_ReturnsLastDecisionWhenNoneTrust(t *testing.T) {
	a := Any{
		stubEvaluator{decision: Decision{Trusted: false, Reason: "no"}},
		stubEvaluator{decision: Decision{Trusted: false, Reason: "still no"}},
	}
	d, err := a.Evaluate(context.Background(), "issuer-a", nil)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Trusted || d.Reason != "still no" {
		t.Fatalf("got %+v, want the last (untrusted) decision", d)
	}
}

func TestAny_ShortCircuitsAfterFirstTrust(t *testing.T) {
	secondCalled := 0
	a := Any{
		stubEvaluator{decision: Decision{Trusted: true, Reason: "yes"}},
		stubEvaluator{decision: Decision{Trusted: false}, called: &secondCalled},
	}
	if _, err := a.Evaluate(context.Background(), "issuer-a", nil); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if secondCalled != 0 {
		t.Fatalf("expected the second evaluator to be skipped once the first trusted, but it was called %d times", secondCalled)
	}
}

func TestAny_PropagatesError(t *testing.T) {
	wantErr := errors.New("boom")
	a := Any{stubEvaluator{err: wantErr}}
	if _, err := a.Evaluate(context.Background(), "issuer-a", nil); !errors.Is(err, wantErr) {
		t.Fatalf("expected the underlying error to propagate, got %v", err)
	}
}

func TestAny_EmptyIsUntrusted(t *testing.T) {
	d, err := Any{}.Evaluate(context.Background(), "issuer-a", nil)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Trusted {
		t.Fatal("expected an empty Any to never trust anything")
	}
}
