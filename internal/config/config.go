// Package config loads the prototype's runtime configuration from the
// environment, matching the Fly deployment model in docs/design.md §12
// (env-based config, no separate config-file convention needed at this
// scale).
package config

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	// HTTPAddr is the address the API server listens on.
	HTTPAddr string
	// BaseURL is this service's own public base URL, used to build
	// {list_url} values returned from POST /allocate.
	BaseURL string

	// RedisAddr is a bare host:port, used when no auth/TLS is needed
	// (e.g. local docker compose). RedisURL, if set, takes precedence and
	// is a full connection string (redis:// or rediss://) as required by
	// managed offerings like Fly's Upstash-backed Redis, which need
	// password auth and TLS — a bare address can't express either.
	RedisAddr   string
	RedisURL    string
	PostgresDSN string

	// ListCapacity is N_max (docs/design.md §7/§8.2): the per-list
	// capacity internal/pool creates new lists with.
	ListCapacity uint64
	// ListBits is the per-entry bit width (1, 2, 4, or 8).
	ListBits int

	// PoolWidth is K (docs/design.md §8.1/§8.2): the number of
	// concurrently-ACTIVE lists that power-of-two-choices placement
	// picks between.
	PoolWidth int
	// RotationMaxAge is T_max (§8.2): the maximum time a list stays
	// ACTIVE regardless of fill, after which internal/pool freezes it.
	// Zero disables age-based rotation (fullness, via N_max, still
	// applies).
	RotationMaxAge time.Duration
	// PoolCheckInterval is how often internal/pool's background loop
	// checks for lists past RotationMaxAge and tops the pool back up to
	// PoolWidth (docs/design.md §12: rotation maintenance is a separate,
	// infrequent background job, not folded into the request path).
	PoolCheckInterval time.Duration

	// DefaultTTLSeconds is the fallback cache lifetime applied when an
	// issuer doesn't set its own (docs/design.md §9/§13: ttl is
	// configurable per issuer/credential type, decided 2026-09-23).
	DefaultTTLSeconds int64

	// PublishInterval is how often the publisher checks for lists whose
	// live version has moved past their last-published version
	// (docs/design.md §9's "debounced" publisher, simplified for the
	// prototype to a fixed poll interval rather than true debouncing —
	// see internal/publisher's package doc).
	PublishInterval time.Duration

	// SigningKey signs StatusListTokens; SigningKeyID is placed in the
	// JWS `kid` header.
	SigningKey   *ecdsa.PrivateKey
	SigningKeyID string

	// IssuerAPIKeys maps a bearer token to the issuer_id it
	// authenticates as. This is a deliberately minimal prototype-only
	// mechanism (docs/design.md doesn't specify issuer onboarding);
	// production would replace it with OAuth2 client-credentials or
	// mTLS without touching anything downstream of authentication.
	IssuerAPIKeys map[string]string
}

// FromEnv loads configuration from environment variables, applying
// sensible prototype defaults where the design doc doesn't mandate a
// specific value.
func FromEnv() (*Config, error) {
	c := &Config{
		HTTPAddr:          getEnv("HTTP_ADDR", ":8080"),
		BaseURL:           getEnv("BASE_URL", "http://localhost:8080"),
		RedisAddr:         getEnv("REDIS_ADDR", "localhost:6379"),
		RedisURL:          os.Getenv("REDIS_URL"),
		PostgresDSN:       getEnv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/statuslist?sslmode=disable"),
		DefaultTTLSeconds: 3600,
		ListBits:          2,
		PublishInterval:   10 * time.Second,
		SigningKeyID:      getEnv("SIGNING_KEY_ID", "prototype-1"),
		IssuerAPIKeys:     map[string]string{},
		PoolWidth:         4,
		RotationMaxAge:    24 * time.Hour,
		PoolCheckInterval: 30 * time.Second,
	}

	if v := os.Getenv("LIST_CAPACITY"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("config: LIST_CAPACITY: %w", err)
		}
		c.ListCapacity = n
	} else {
		c.ListCapacity = 100_000
	}

	if v := os.Getenv("LIST_BITS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("config: LIST_BITS: %w", err)
		}
		c.ListBits = n
	}

	if v := os.Getenv("DEFAULT_TTL_SECONDS"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("config: DEFAULT_TTL_SECONDS: %w", err)
		}
		c.DefaultTTLSeconds = n
	}

	if v := os.Getenv("POOL_WIDTH"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("config: POOL_WIDTH: %w", err)
		}
		c.PoolWidth = n
	}

	if v := os.Getenv("ROTATION_MAX_AGE"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("config: ROTATION_MAX_AGE: %w", err)
		}
		c.RotationMaxAge = d
	}

	if v := os.Getenv("POOL_CHECK_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("config: POOL_CHECK_INTERVAL: %w", err)
		}
		c.PoolCheckInterval = d
	}

	keyPEM := os.Getenv("SIGNING_KEY_PEM")
	if keyPEM == "" {
		return nil, fmt.Errorf("config: SIGNING_KEY_PEM is required (PEM-encoded EC private key, P-256)")
	}
	key, err := parseECKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("config: SIGNING_KEY_PEM: %w", err)
	}
	c.SigningKey = key

	if v := os.Getenv("ISSUER_API_KEYS"); v != "" {
		var m map[string]string
		if err := json.Unmarshal([]byte(v), &m); err != nil {
			return nil, fmt.Errorf("config: ISSUER_API_KEYS must be a JSON object of token->issuer_id: %w", err)
		}
		c.IssuerAPIKeys = m
	}

	return c, nil
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func parseECKey(pemStr string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse EC private key: %w", err)
	}
	return key, nil
}
