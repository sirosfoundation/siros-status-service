package trust

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// AuthZENEvaluator calls a go-trust Policy Decision Point over its real
// AuthZEN wire protocol (docs/design.md §15.2). It deliberately does not
// import go-trust as a Go module dependency — see the design doc for why
// (a toolchain version gap: go-trust requires go 1.27, one step ahead of
// this org's current 1.26.6 pin) — and instead speaks the same JSON shape
// go-trust's own pkg/authzen defines, verified directly against that
// package's struct tags rather than assumed.
type AuthZENEvaluator struct {
	baseURL    string
	httpClient *http.Client
	// actionName is the AuthZEN action.name sent with every evaluation —
	// must match whatever the target PDP's policy expects for "this key
	// may act as a credential-issuing signer." Configurable because it's
	// a policy-taxonomy detail owned by whoever operates the PDP, not by
	// this service.
	actionName string
}

func NewAuthZENEvaluator(baseURL, actionName string, httpClient *http.Client) *AuthZENEvaluator {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &AuthZENEvaluator{baseURL: baseURL, httpClient: httpClient, actionName: actionName}
}

func (e *AuthZENEvaluator) Name() string { return "authzen:" + e.baseURL }

// authzenSubject/Resource/Action/Request/Response mirror the JSON shape
// of go-trust's pkg/authzen types (field names and `omitempty` behavior
// checked against that package's struct tags directly).
type authzenSubject struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type authzenResource struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	Key  []any  `json:"key"`
}

type authzenAction struct {
	Name string `json:"name"`
}

type authzenRequest struct {
	Subject  authzenSubject  `json:"subject"`
	Resource authzenResource `json:"resource"`
	Action   *authzenAction  `json:"action,omitempty"`
}

type authzenResponse struct {
	Decision bool `json:"decision"`
	Context  *struct {
		Reason map[string]any `json:"reason,omitempty"`
	} `json:"context,omitempty"`
}

const maxAuthZENResponseBytes = 1 << 20 // 1 MiB — generous for a decision payload

func (e *AuthZENEvaluator) Evaluate(ctx context.Context, subjectID string, jwk map[string]any) (Decision, error) {
	reqBody := authzenRequest{
		Subject:  authzenSubject{Type: "key", ID: subjectID},
		Resource: authzenResource{Type: "jwk", ID: subjectID, Key: []any{jwk}},
	}
	if e.actionName != "" {
		reqBody.Action = &authzenAction{Name: e.actionName}
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return Decision{}, fmt.Errorf("trust: marshal authzen request: %w", err)
	}

	url := e.baseURL + "/evaluation"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return Decision{}, fmt.Errorf("trust: build authzen request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := e.httpClient.Do(httpReq)
	if err != nil {
		return Decision{}, fmt.Errorf("trust: authzen request to %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return Decision{}, fmt.Errorf("trust: authzen PDP returned HTTP %d", resp.StatusCode)
	}

	limited := io.LimitReader(resp.Body, maxAuthZENResponseBytes)
	var parsed authzenResponse
	if err := json.NewDecoder(limited).Decode(&parsed); err != nil {
		return Decision{}, fmt.Errorf("trust: decode authzen response: %w", err)
	}

	reason := "denied by policy"
	if parsed.Context != nil {
		if r, ok := parsed.Context.Reason["message"].(string); ok {
			reason = r
		}
	}
	if parsed.Decision {
		reason = "trusted by policy"
	}
	return Decision{Trusted: parsed.Decision, Reason: reason}, nil
}
