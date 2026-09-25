package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

// opWeights controls the traffic mix one issuer generates — POST
// /allocate dominates real traffic (each credential needs exactly one),
// PATCH /status models occasional revocations, GET /accounting/me
// models an issuer occasionally checking their own usage (docs/
// design.md §15.4), and lifecycle runs the full public allocate/verify/
// revoke/verify round trip as an end-to-end correctness check under the
// same concurrent load (lifecycle.go). Defaults live in main.go's flags.
type opWeights struct {
	allocate, status, accounting, lifecycle float64
}

// pick chooses one operation name, weighted by the four fields above.
func (w opWeights) pick() string {
	total := w.allocate + w.status + w.accounting + w.lifecycle
	r := rand.Float64() * total
	if r < w.allocate {
		return "allocate"
	}
	if r < w.allocate+w.status {
		return "status"
	}
	if r < w.allocate+w.status+w.accounting {
		return "accounting"
	}
	return "lifecycle"
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
	issuerID   string
	latency    map[string][]time.Duration // op -> latencies of successful calls
	errors     map[string]int             // op -> count of failed calls
	skipped    int                        // "status" attempted with nothing yet allocated
	allocs     []allocRecord
	mismatches []string // lifecycle.go: published-list status disagreed with what was just written
}

func newWorkerResult(issuerID string) *workerResult {
	return &workerResult{
		issuerID: issuerID,
		latency:  map[string][]time.Duration{"allocate": {}, "status": {}, "accounting": {}, "lifecycle": {}},
		errors:   map[string]int{"allocate": 0, "status": 0, "accounting": 0, "lifecycle": 0},
	}
}

// runWorker drives one issuer's traffic against ingressURL until
// deadline, using token for every call — cmd/ingress-router verifies it
// offline against the AS's JWKS and routes on its tenant_id claim
// (docs/design.md §15.6), so from here it's an ordinary bearer token.
// limiter is shared across every worker in this run (main.go's run):
// waiting on it here, rather than each worker having its own share of
// the budget, means the cap holds however many issuer goroutines happen
// to be producing the traffic.
func runWorker(client *http.Client, ingressURL, token string, weights opWeights, limiter *rate.Limiter, deadline time.Time, result *workerResult) {
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	for {
		if err := limiter.Wait(ctx); err != nil {
			// Deadline reached while waiting for rate budget — an
			// ordinary end of run, not a failure.
			return
		}
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
	case "lifecycle":
		return doLifecycle(client, ingressURL, token, result)
	default:
		return doAccounting(client, ingressURL, token)
	}
}

type allocateResponseBody struct {
	ListURL string    `json:"list_url"`
	Index   uint64    `json:"index"`
	Exp     time.Time `json:"exp"`
}

// doAllocate omits `exp` entirely (docs/design.md §19): the server
// returns exactly its own MAX_EXPIRY-bounded maximum, which works
// against any target regardless of that deployment's own MAX_EXPIRY —
// unlike a fixed or randomized exp far in the future, which would now
// get rejected outright against a tightly-configured target (e.g. the
// test deployment's 24h). This also directly exercises the §19 default
// path under real concurrent load, which is worth having covered here.
func doAllocate(client *http.Client, ingressURL, token string, result *workerResult) error {
	ar, err := allocate(client, ingressURL, token)
	if err != nil {
		return err
	}
	listID, err := listIDFromURL(ar.ListURL)
	if err != nil {
		return err
	}
	result.allocs = append(result.allocs, allocRecord{listID: listID, index: ar.Index, expected: "VALID"})
	return nil
}

// allocate is the bare POST /allocate call, with no result bookkeeping —
// shared by doAllocate (the weighted-mix op) and doLifecycle (lifecycle.go),
// which needs the response's list_url/index directly rather than a
// side-effected result.allocs entry.
func allocate(client *http.Client, ingressURL, token string) (*allocateResponseBody, error) {
	req, err := http.NewRequest(http.MethodPost, ingressURL+"/allocate", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		drainAndDiscard(resp.Body)
		return nil, fmt.Errorf("allocate: status %d", resp.StatusCode)
	}
	var ar allocateResponseBody
	if err := json.NewDecoder(resp.Body).Decode(&ar); err != nil {
		return nil, fmt.Errorf("allocate: decode response: %w", err)
	}
	return &ar, nil
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

	if err := patchStatus(client, ingressURL, token, rec.listID, rec.index, newStatus); err != nil {
		return err
	}
	rec.expected = newStatus
	return nil
}

// patchStatus is the bare PATCH /status/{listID}/{index} call, with no
// result bookkeeping — shared by doStatus (which picks a random already-
// owned index and status) and doLifecycle (lifecycle.go, which revokes a
// specific just-allocated index).
func patchStatus(client *http.Client, ingressURL, token, listID string, index uint64, status string) error {
	body, err := json.Marshal(setStatusRequestBody{Status: status})
	if err != nil {
		return err
	}
	path := fmt.Sprintf("/status/%s/%d", listID, index)
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
