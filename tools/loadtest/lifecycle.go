package main

import (
	"fmt"
	"io"
	"net/http"

	"github.com/golang-jwt/jwt/v5"

	"github.com/sirosfoundation/siros-status-service/internal/statuslist"
)

// doLifecycle drives one full issuer-visible credential lifecycle
// end-to-end — allocate, verify VALID, revoke, verify INVALID — through
// the same two public surfaces a real integration actually uses: ingress
// for writes, the verifier's own published StatusListToken for reads.
// Unlike verifyDecoySafety (verify.go), which reads the shard's Postgres/
// Redis directly and needs deployment-internal access, this only ever
// calls public HTTP endpoints — the same round trip an issuer plus a
// real relying party would make — so it runs the same way against the
// live deployment as against the local walkthrough, no tunnel needed.
//
// A mismatch here (the published list disagreeing with what was just
// written) is recorded into result.mismatches rather than folded into
// the plain error count: an HTTP failure and "the system told us the
// wrong status" are different findings, and the latter is the actual
// reason this flow exists.
func doLifecycle(client *http.Client, ingressURL, token string, result *workerResult) error {
	ar, err := allocate(client, ingressURL, token)
	if err != nil {
		return fmt.Errorf("lifecycle: allocate: %w", err)
	}
	listID, err := listIDFromURL(ar.ListURL)
	if err != nil {
		return fmt.Errorf("lifecycle: %w", err)
	}

	if err := checkStatus(client, result, listID, ar.ListURL, ar.Index, statuslist.StatusValid); err != nil {
		return fmt.Errorf("lifecycle: %w", err)
	}

	if err := patchStatus(client, ingressURL, token, listID, ar.Index, "INVALID"); err != nil {
		return fmt.Errorf("lifecycle: revoke: %w", err)
	}
	result.allocs = append(result.allocs, allocRecord{listID: listID, index: ar.Index, expected: "INVALID"})

	if err := checkStatus(client, result, listID, ar.ListURL, ar.Index, statuslist.StatusInvalid); err != nil {
		return fmt.Errorf("lifecycle: %w", err)
	}
	return nil
}

// checkStatus fetches listURL — the verifier's own published token, the
// same URL a real relying party would fetch — and compares the status at
// index against want, recording a mismatch on result if they disagree.
func checkStatus(client *http.Client, result *workerResult, listID, listURL string, index uint64, want statuslist.Status) error {
	actual, err := fetchStatus(client, listURL, index)
	if err != nil {
		return err
	}
	if actual != want {
		msg := fmt.Sprintf("issuer=%s list=%s index=%d expected=%s actual=%s (via published list, not backend store)",
			result.issuerID, listID, index, statusName(want), statusName(actual))
		result.mismatches = append(result.mismatches, msg)
		return fmt.Errorf("status mismatch: %s", msg)
	}
	return nil
}

// fetchStatus fetches and decodes listURL's current published
// StatusListToken and reads the status at index. The signature is
// deliberately not verified: this checks self-consistency (does the
// published list reflect what was just written), not trust — there is
// no JWKS endpoint yet for the StatusListToken signing key (a real
// relying party integration would need one; a known gap, see
// docs/design.md and README's "Known gaps").
func fetchStatus(client *http.Client, listURL string, index uint64) (statuslist.Status, error) {
	resp, err := client.Get(listURL)
	if err != nil {
		return 0, fmt.Errorf("fetch %s: %w", listURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", listURL, err)
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("fetch %s: status %d: %s", listURL, resp.StatusCode, body)
	}

	var claims statuslist.Claims
	if _, _, err := jwt.NewParser().ParseUnverified(string(body), &claims); err != nil {
		return 0, fmt.Errorf("parse status list token from %s: %w", listURL, err)
	}

	raw, err := statuslist.DecodeLst(claims.StatusList.Lst)
	if err != nil {
		return 0, fmt.Errorf("decode lst from %s: %w", listURL, err)
	}
	bits := claims.StatusList.Bits
	// The `lst` claim carries only the packed byte array, not the list's
	// configured entry count — recompute the largest size WrapBitmap
	// would accept for this many bytes at this bit width (exact, since a
	// packed array is always a whole number of bytes: bits divides 8
	// evenly for every width the spec allows). This is only ever used
	// for Get's own bounds check against a real allocated index, so it
	// being an upper bound rather than the list's true configured size
	// is harmless here.
	size := uint64(len(raw)) * 8 / uint64(bits)
	bm, err := statuslist.WrapBitmap(raw, size, bits)
	if err != nil {
		return 0, fmt.Errorf("wrap bitmap from %s: %w", listURL, err)
	}
	return bm.Get(index)
}
