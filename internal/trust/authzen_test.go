package trust

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthZENEvaluator_TrustedDecision(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/evaluation" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		var req authzenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if req.Subject.Type != "key" || req.Subject.ID != "issuer-a" {
			t.Errorf("unexpected subject: %+v", req.Subject)
		}
		if req.Resource.Type != "jwk" || len(req.Resource.Key) != 1 {
			t.Errorf("unexpected resource: %+v", req.Resource)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(authzenResponse{Decision: true})
	}))
	defer srv.Close()

	e := NewAuthZENEvaluator(srv.URL, "issue-status-list", nil)
	d, err := e.Evaluate(t.Context(), "issuer-a", map[string]any{"kty": "EC"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !d.Trusted {
		t.Fatal("expected a trusted decision")
	}
}

func TestAuthZENEvaluator_UntrustedDecision(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"decision": false,
			"context":  map[string]any{"reason": map[string]any{"message": "key not in whitelist"}},
		})
	}))
	defer srv.Close()

	e := NewAuthZENEvaluator(srv.URL, "", nil)
	d, err := e.Evaluate(t.Context(), "issuer-a", map[string]any{"kty": "EC"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if d.Trusted {
		t.Fatal("expected an untrusted decision")
	}
	if d.Reason != "key not in whitelist" {
		t.Errorf("Reason = %q, want the PDP's message", d.Reason)
	}
}

// The following all exercise docs/design.md §15.2's decided fail-closed
// behavior: a PDP that's configured but unreachable/erroring must never
// be treated as "trusted", unlike AllowAllEvaluator's fail-open default
// when no PDP is configured at all.

func TestAuthZENEvaluator_FailsClosedOnConnectionError(t *testing.T) {
	e := NewAuthZENEvaluator("http://127.0.0.1:1", "", nil) // nothing listens here
	d, err := e.Evaluate(t.Context(), "issuer-a", map[string]any{"kty": "EC"})
	if err == nil {
		t.Fatal("expected an error for an unreachable PDP")
	}
	if d.Trusted {
		t.Fatal("expected Trusted=false alongside the error")
	}
}

func TestAuthZENEvaluator_FailsClosedOnNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	e := NewAuthZENEvaluator(srv.URL, "", nil)
	d, err := e.Evaluate(t.Context(), "issuer-a", map[string]any{"kty": "EC"})
	if err == nil {
		t.Fatal("expected an error for a non-200 PDP response")
	}
	if d.Trusted {
		t.Fatal("expected Trusted=false alongside the error")
	}
}

func TestAuthZENEvaluator_FailsClosedOnMalformedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{not valid json"))
	}))
	defer srv.Close()

	e := NewAuthZENEvaluator(srv.URL, "", nil)
	d, err := e.Evaluate(t.Context(), "issuer-a", map[string]any{"kty": "EC"})
	if err == nil {
		t.Fatal("expected an error for a malformed PDP response")
	}
	if d.Trusted {
		t.Fatal("expected Trusted=false alongside the error")
	}
}

func TestAuthZENEvaluator_SendsActionNameWhenConfigured(t *testing.T) {
	var gotAction *authzenAction
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req authzenRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		gotAction = req.Action
		_ = json.NewEncoder(w).Encode(authzenResponse{Decision: true})
	}))
	defer srv.Close()

	e := NewAuthZENEvaluator(srv.URL, "issue-status-list", nil)
	if _, err := e.Evaluate(t.Context(), "issuer-a", map[string]any{"kty": "EC"}); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if gotAction == nil || gotAction.Name != "issue-status-list" {
		t.Fatalf("expected action.name %q to be sent, got %+v", "issue-status-list", gotAction)
	}
}

func TestAuthZENEvaluator_OmitsActionWhenNotConfigured(t *testing.T) {
	var sawActionField bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var raw map[string]any
		_ = json.NewDecoder(r.Body).Decode(&raw)
		_, sawActionField = raw["action"]
		_ = json.NewEncoder(w).Encode(authzenResponse{Decision: true})
	}))
	defer srv.Close()

	e := NewAuthZENEvaluator(srv.URL, "", nil)
	if _, err := e.Evaluate(t.Context(), "issuer-a", map[string]any{"kty": "EC"}); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if sawActionField {
		t.Fatal("expected no action field in the request when actionName is empty")
	}
}
