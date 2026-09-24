package trust

import "testing"

func TestAllowAllEvaluator_AlwaysTrusts(t *testing.T) {
	e := AllowAllEvaluator{}
	d, err := e.Evaluate(t.Context(), "any-issuer", CredentialFromJWK(map[string]any{"kty": "EC"}))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !d.Trusted {
		t.Fatal("expected AllowAllEvaluator to always trust")
	}
	if d.Reason == "" {
		t.Error("expected a non-empty reason explaining the fail-open default")
	}
}

func TestAllowAllEvaluator_Name(t *testing.T) {
	if got := (AllowAllEvaluator{}).Name(); got != "allow-all" {
		t.Errorf("Name() = %q, want allow-all", got)
	}
}

func TestAllowAllEvaluator_TrustsEvenWithNilJWK(t *testing.T) {
	e := AllowAllEvaluator{}
	d, err := e.Evaluate(t.Context(), "issuer-a", Credential{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !d.Trusted {
		t.Fatal("expected AllowAllEvaluator to trust regardless of input")
	}
}
