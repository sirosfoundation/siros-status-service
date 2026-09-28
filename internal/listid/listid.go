// Package listid implements the shard-prefixed list ID scheme (docs/
// design.md §23): every list ID embeds which shard created it, so a
// list's shard is a static, parseable property of the ID string itself
// — no database lookup needed to know it. That's what lets
// cmd/ingress-router route a PATCH /status request to the list's own
// permanent shard, rather than trusting the caller's current access
// token claim, which stops being reliable the moment an issuer can be
// reassigned to a different shard (docs/design.md §23's whole reason
// for existing) — an issuer's *new* allocations should follow their
// current assignment, but a PATCH against a credential issued before
// the reassignment must still reach the shard that actually holds it.
//
// Deliberately its own tiny package with zero external dependencies —
// both internal/pool (creation) and internal/ingress (routing) need it,
// and internal/ingress is otherwise a stateless proxy with no database
// dependency at all; pulling in internal/pool or internal/store just for
// this would bloat it with a Postgres/Redis driver it has no other use
// for.
package listid

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

// separator must never appear inside a shard_id (docs/design.md §15.5:
// shard IDs are short, operator-chosen identifiers like "iad"/"fra" —
// this is a naming constraint on those, not on list IDs).
const separator = "."

// New generates a fresh, opaque list ID for shardID. The random suffix
// remains the only unguessable part (docs/design.md §4: "a sequential
// list_id leaks issuance volume/rate the same way sequential indices
// would") — the shard prefix is deliberately public; which shard a list
// lives on was never sensitive.
func New(shardID string) (string, error) {
	if strings.Contains(shardID, separator) {
		return "", fmt.Errorf("listid: shard_id %q must not contain %q", shardID, separator)
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("listid: %w", err)
	}
	return shardID + separator + hex.EncodeToString(b), nil
}

// ParseShard extracts a list ID's embedded shard. False for anything
// that doesn't match the expected shape — including list IDs created
// before this scheme existed (pure random hex, no separator), which
// callers should treat as "fall back to some other routing signal," not
// an error: those lists are still perfectly valid, they just predate a
// feature that didn't exist yet.
func ParseShard(listID string) (shardID string, ok bool) {
	i := strings.Index(listID, separator)
	if i <= 0 || i == len(listID)-1 {
		return "", false
	}
	return listID[:i], true
}
