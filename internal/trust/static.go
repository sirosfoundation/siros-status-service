package trust

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sirosfoundation/siros-status-service/internal/pgutil"
)

// jwkComparisonFields are the fields that actually identify an EC or RSA
// public key. Registered/presented JWKs may otherwise differ in
// optional metadata (kid, use, alg) without that meaning anything for
// trust purposes, so comparison is scoped to these.
var jwkComparisonFields = []string{"kty", "crv", "x", "y", "n", "e"}

func canonicalize(jwk map[string]any) map[string]any {
	out := make(map[string]any, len(jwkComparisonFields))
	for _, f := range jwkComparisonFields {
		if v, ok := jwk[f]; ok {
			out[f] = v
		}
	}
	return out
}

const staticRegistrySchema = `
CREATE TABLE IF NOT EXISTS trusted_issuer_keys (
	issuer_id  text PRIMARY KEY,
	jwk        jsonb NOT NULL,
	created_at timestamptz NOT NULL DEFAULT now()
);
`

// StaticRegistryEvaluator trusts a name-to-key binding if it matches a
// pre-registered entry (docs/design.md §15.2 — the dev/default path,
// mirroring vc-mdoc-preset's pre-registered-jwks_uri client-assertion
// pattern but storing the key itself rather than a URI to fetch it from).
type StaticRegistryEvaluator struct {
	pool *pgxpool.Pool
}

// NewStaticRegistryEvaluator connects to Postgres and applies the
// (idempotent) schema for the trusted-issuer-key registry.
func NewStaticRegistryEvaluator(ctx context.Context, dsn string) (*StaticRegistryEvaluator, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("trust: connect postgres: %w", err)
	}
	if err := pgutil.ApplySchema(ctx, pool, "siros-status-service:trust-schema", staticRegistrySchema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("trust: %w", err)
	}
	return &StaticRegistryEvaluator{pool: pool}, nil
}

func (e *StaticRegistryEvaluator) Close() { e.pool.Close() }

func (e *StaticRegistryEvaluator) Name() string { return "static-registry" }

// Register adds or replaces the trusted key for issuerID — an admin
// operation (docs/design.md §15.8: "no self-service flow yet").
func (e *StaticRegistryEvaluator) Register(ctx context.Context, issuerID string, jwk map[string]any) error {
	raw, err := json.Marshal(jwk)
	if err != nil {
		return fmt.Errorf("trust: marshal jwk: %w", err)
	}
	_, err = e.pool.Exec(ctx,
		`INSERT INTO trusted_issuer_keys (issuer_id, jwk) VALUES ($1, $2)
		 ON CONFLICT (issuer_id) DO UPDATE SET jwk = EXCLUDED.jwk, created_at = now()`,
		issuerID, raw,
	)
	if err != nil {
		return fmt.Errorf("trust: register issuer %s: %w", issuerID, err)
	}
	return nil
}

func (e *StaticRegistryEvaluator) Evaluate(ctx context.Context, subjectID string, jwk map[string]any) (Decision, error) {
	var raw []byte
	err := e.pool.QueryRow(ctx, `SELECT jwk FROM trusted_issuer_keys WHERE issuer_id = $1`, subjectID).Scan(&raw)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Decision{Trusted: false, Reason: "no registered key for this issuer"}, nil
		}
		return Decision{}, fmt.Errorf("trust: lookup issuer %s: %w", subjectID, err)
	}

	var registered map[string]any
	if err := json.Unmarshal(raw, &registered); err != nil {
		return Decision{}, fmt.Errorf("trust: decode registered jwk for %s: %w", subjectID, err)
	}

	if reflect.DeepEqual(canonicalize(registered), canonicalize(jwk)) {
		return Decision{Trusted: true, Reason: "matches registered key"}, nil
	}
	return Decision{Trusted: false, Reason: "presented key does not match the registered key"}, nil
}
