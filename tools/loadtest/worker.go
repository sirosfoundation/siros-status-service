package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"
)

// opWeights controls the traffic mix one issuer generates — POST
// /allocate dominates real traffic (each credential needs exactly one),
// PATCH /status models occasional revocations, GET /accounting/me
// models an issuer occasionally checking their own usage (docs/
// design.md §15.4). Defaults live in main.go's flags.
type opWeights struct {
	allocate, status, accounting float64
}

// pick chooses one operation name, weighted by the three fields above.
func (w opWeights) pick() string {
	total := w.allocate + w.status + w.accounting
	r := rand.Float64() * total
	if r < w.allocate {
		return "allocate"
	}
	if r < w.allocate+w.status {
		return "status"
	}
	return "accounting"
}

// allocRecord is one index this load test allocated, tracked so a later
// "status" operation can PATCH something this issuer actually owns
// (docs/design.md §13: ownership is enforced server-side, so a random
// index would just 403), and so verify.go can check the system's real
// current state against what this harness itself last wrote — the
// invariant a decoy-noise bug would violate (docs/design.md §17).
type allocRecord struct {
	listID   string
	index    uint64
	expected string // "VALID", "INVALID", or "SUSPENDED" — last write THIS harness made
}

// workerResult accumulates one issuer-worker's own observations, kept
// entirely local (no shared mutex) so measured latencies reflect real
// request time, not lock contention between workers.
type workerResult struct {
	issuerID string
	latency  map[string][]time.Duration // op -> latencies of successful calls
	errors   map[string]int             // op -> count of failed calls
	skipped  int                        // "status" attempted with nothing yet allocated
	allocs   []allocRecord
}

func newWorkerResult(issuerID string) *workerResult {
	return &workerResult{
		issuerID: issuerID,
		latency:  map[string][]time.Duration{"allocate": {}, "status": {}, "accounting": {}},
		errors:   map[string]int{"allocate": 0, "status": 0, "accounting": 0},
	}
}

// runWorker drives one issuer's traffic against ingressURL until
// deadline, using token for every call — cmd/ingress-router verifies it
// offline against the AS's JWKS and routes on its tenant_id claim
// (docs/design.md §15.6), so from here it's an ordinary bearer token.
func runWorker(client *http.Client, ingressURL, token string, weights opWeights, deadline time.Time, result *workerResult) {
	for time.Now().Before(deadline) {
		op := weights.pick()
		start := time.Now()
		err := doOp(client, ingressURL, token, op, result)
		if op == "status" && errors.Is(err, errNothingAllocatedYet) {
			result.skipped++
			continue
		}
		if err != nil {
			result.errors[op]++
			continue
		}
		result.latency[op] = append(result.latency[op], time.Since(start))
	}
}

var errNothingAllocatedYet = fmt.Errorf("no allocated index to update yet")

func doOp(client *http.Client, ingressURL, token, op string, result *workerResult) error {
	switch op {
	case "allocate":
		return doAllocate(client, ingressURL, token, result)
	case "status":
		return doStatus(client, ingressURL, token, result)
	default:
		return doAccounting(client, ingressURL, token)
	}
}

type allocateRequestBody struct {
	Exp time.Time `json:"exp"`
}

type allocateResponseBody struct {
	ListURL string `json:"list_url"`
	Index   uint64 `json:"index"`
}

// doAllocate mirrors internal/ingestion's real allocateRequest — only an
// expiration, 1 to 365 days out, matching real credential lifetimes
// better than a fixed constant would (varied exp spreads GC eligibility
// out too, docs/design.md §7 point 4).
func doAllocate(client *http.Client, ingressURL, token string, result *workerResult) error {
	exp := time.Now().Add(time.Duration(1+rand.IntN(365)) * 24 * time.Hour)
	body, err := json.Marshal(allocateRequestBody{Exp: exp})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, ingressURL+"/allocate", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		drainAndDiscard(resp.Body)
		return fmt.Errorf("allocate: status %d", resp.StatusCode)
	}
	var ar allocateResponseBody
	if err := json.NewDecoder(resp.Body).Decode(&ar); err != nil {
		return fmt.Errorf("allocate: decode response: %w", err)
	}
	listID, err := listIDFromURL(ar.ListURL)
	if err != nil {
		return err
	}
	result.allocs = append(result.allocs, allocRecord{listID: listID, index: ar.Index, expected: "VALID"})
	return nil
}

var statusChoices = []string{"VALID", "INVALID", "SUSPENDED"}

type setStatusRequestBody struct {
	Status string `json:"status"`
}

// doStatus PATCHes a random index this same issuer already allocated —
// docs/design.md §13's server-side ownership check would 403 anything
// else, so unlike doAllocate this can't just synthesize an id/index.
func doStatus(client *http.Client, ingressURL, token string, result *workerResult) error {
	if len(result.allocs) == 0 {
		return errNothingAllocatedYet
	}
	i := rand.IntN(len(result.allocs))
	rec := &result.allocs[i]
	newStatus := statusChoices[rand.IntN(len(statusChoices))]

	body, err := json.Marshal(setStatusRequestBody{Status: newStatus})
	if err != nil {
		return err
	}
	path := fmt.Sprintf("/status/%s/%d", rec.listID, rec.index)
	req, err := http.NewRequest(http.MethodPatch, ingressURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	drainAndDiscard(resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("status: status %d", resp.StatusCode)
	}
	rec.expected = newStatus
	return nil
}

func doAccounting(client *http.Client, ingressURL, token string) error {
	req, err := http.NewRequest(http.MethodGet, ingressURL+"/accounting/me", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	drainAndDiscard(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("accounting: status %d", resp.StatusCode)
	}
	return nil
}

// listIDFromURL extracts the trailing path segment from a list_url like
// "https://verifier.example.org/lists/abc123" — internal/ingestion never
// returns a bare list ID, only the full URL a verifier would fetch.
func listIDFromURL(listURL string) (string, error) {
	idx := strings.LastIndex(listURL, "/")
	if idx == -1 || idx == len(listURL)-1 {
		return "", fmt.Errorf("could not parse list id from %q", listURL)
	}
	return listURL[idx+1:], nil
}

func drainAndDiscard(body io.Reader) {
	_, _ = io.Copy(io.Discard, body)
}
