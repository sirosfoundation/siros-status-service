// Package config loads each binary's runtime configuration from the
// environment, matching the Fly deployment model in docs/design.md §12
// (env-based config, no separate config-file convention needed at this
// scale). Each of the four services (cmd/ingestion-service,
// cmd/verifier-service, cmd/as, cmd/ingress-router — docs/design.md §15)
// gets its own focused Load function and struct rather than sharing one
// config type with fields irrelevant to most of them.
package config

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// IngestionConfig configures cmd/ingestion-service.
type IngestionConfig struct {
	HTTPAddr string
	// BaseURL is this service's own public base URL, used to build
	// {list_url} values returned from POST /allocate.
	BaseURL string

	RedisAddr   string
	RedisURL    string
	PostgresDSN string

	// ShardID is which shard (docs/design.md §15.5) this instance owns —
	// every list it creates, and every access token it will accept,
	// belongs to this shard.
	ShardID string

	// ListCapacity is N_max (§7/§8.2): the per-list capacity
	// internal/pool creates new lists with.
	ListCapacity uint64
	// ListBits is the per-entry bit width (1, 2, 4, or 8).
	ListBits int

	// PoolWidth is K (§8.1/§8.2): concurrently-ACTIVE lists that
	// power-of-two-choices placement picks between.
	PoolWidth int
	// RotationMaxAge is T_max (§8.2). Zero disables age-based rotation.
	RotationMaxAge time.Duration
	// PoolCheckInterval is how often internal/pool's background loop
	// checks for lists past RotationMaxAge and tops the pool back up.
	PoolCheckInterval time.Duration

	// DefaultTTLSeconds is the fallback cache lifetime applied when an
	// issuer doesn't set its own (§9/§13).
	DefaultTTLSeconds int64
	// PublishInterval is the periodic-republish backstop interval (§9).
	PublishInterval time.Duration

	// DecoyNoiseRate is the fraction (0, 1] of a list's never-allocated
	// capacity internal/decoy targets per check pass (§17). Zero (the
	// default) disables decoy noising entirely.
	DecoyNoiseRate float64
	// DecoyCheckInterval is how often internal/decoy sweeps this shard's
	// lists for noise injection.
	DecoyCheckInterval time.Duration

	// MaxExpiry bounds how far in the future POST /allocate's `exp` may be
	// set (docs/design.md §19): a request naming a later `exp` is
	// rejected outright, and a request that omits `exp` gets exactly
	// now+MaxExpiry — the maximum, not an arbitrary/short fallback. Real
	// deployments are expected to tighten this well below the permissive
	// default (e.g. the test deployment uses 24h).
	MaxExpiry time.Duration

	GCGracePeriod     time.Duration
	GCRetentionPeriod time.Duration
	GCCheckInterval   time.Duration

	// SigningKey signs StatusListTokens; SigningKeyID is placed in the
	// JWS `kid` header.
	SigningKey   *ecdsa.PrivateKey
	SigningKeyID string

	// ASJWKSURL, AccessTokenIssuer, and AccessTokenAudience configure
	// offline access-token verification (§15.3) — the AS is never
	// called on the request path, only its JWKS is fetched and cached.
	ASJWKSURL           string
	AccessTokenIssuer   string
	AccessTokenAudience string
	JWKSRefreshInterval time.Duration
}

func LoadIngestion() (*IngestionConfig, error) {
	c := &IngestionConfig{
		HTTPAddr:            getEnv("HTTP_ADDR", ":8080"),
		BaseURL:             getEnv("BASE_URL", "http://localhost:8080"),
		RedisAddr:           getEnv("REDIS_ADDR", "localhost:6379"),
		RedisURL:            os.Getenv("REDIS_URL"),
		PostgresDSN:         getEnv("DATABASE_URL", defaultPostgresDSN),
		ShardID:             getEnv("SHARD_ID", "default"),
		ListBits:            2,
		PoolWidth:           4,
		RotationMaxAge:      24 * time.Hour,
		PoolCheckInterval:   30 * time.Second,
		DefaultTTLSeconds:   3600,
		PublishInterval:     10 * time.Second,
		DecoyNoiseRate:      0, // opt-in (§17): unverified against real traffic, never on by default
		DecoyCheckInterval:  15 * time.Minute,
		MaxExpiry:           365 * 24 * time.Hour, // permissive default (§19); tighten per deployment
		GCGracePeriod:       24 * time.Hour,
		GCRetentionPeriod:   30 * 24 * time.Hour,
		GCCheckInterval:     time.Hour,
		SigningKeyID:        getEnv("SIGNING_KEY_ID", "prototype-1"),
		AccessTokenIssuer:   os.Getenv("ACCESS_TOKEN_ISSUER"),
		AccessTokenAudience: getEnv("ACCESS_TOKEN_AUDIENCE", "siros-status-service"),
		JWKSRefreshInterval: 5 * time.Minute,
	}
	var err error
	if c.ListCapacity, err = getUint64Env("LIST_CAPACITY", 100_000); err != nil {
		return nil, err
	}
	if c.ListBits, err = getIntEnv("LIST_BITS", c.ListBits); err != nil {
		return nil, err
	}
	if c.PoolWidth, err = getIntEnv("POOL_WIDTH", c.PoolWidth); err != nil {
		return nil, err
	}
	if c.RotationMaxAge, err = getDurationEnv("ROTATION_MAX_AGE", c.RotationMaxAge); err != nil {
		return nil, err
	}
	if c.PoolCheckInterval, err = getDurationEnv("POOL_CHECK_INTERVAL", c.PoolCheckInterval); err != nil {
		return nil, err
	}
	if c.DefaultTTLSeconds, err = getInt64Env("DEFAULT_TTL_SECONDS", c.DefaultTTLSeconds); err != nil {
		return nil, err
	}
	if c.PublishInterval, err = getDurationEnv("PUBLISH_INTERVAL", c.PublishInterval); err != nil {
		return nil, err
	}
	if c.DecoyNoiseRate, err = getFloat64Env("DECOY_NOISE_RATE", c.DecoyNoiseRate); err != nil {
		return nil, err
	}
	if c.DecoyCheckInterval, err = getDurationEnv("DECOY_CHECK_INTERVAL", c.DecoyCheckInterval); err != nil {
		return nil, err
	}
	if c.MaxExpiry, err = getDurationEnv("MAX_EXPIRY", c.MaxExpiry); err != nil {
		return nil, err
	}
	if c.GCGracePeriod, err = getDurationEnv("GC_GRACE_PERIOD", c.GCGracePeriod); err != nil {
		return nil, err
	}
	if c.GCRetentionPeriod, err = getDurationEnv("GC_RETENTION_PERIOD", c.GCRetentionPeriod); err != nil {
		return nil, err
	}
	if c.GCCheckInterval, err = getDurationEnv("GC_CHECK_INTERVAL", c.GCCheckInterval); err != nil {
		return nil, err
	}
	if c.JWKSRefreshInterval, err = getDurationEnv("JWKS_REFRESH_INTERVAL", c.JWKSRefreshInterval); err != nil {
		return nil, err
	}
	if c.SigningKey, err = requireECKeyEnv("SIGNING_KEY_PEM"); err != nil {
		return nil, err
	}

	c.ASJWKSURL = os.Getenv("AS_JWKS_URL")
	if c.ASJWKSURL == "" {
		return nil, fmt.Errorf("config: AS_JWKS_URL is required")
	}
	if c.AccessTokenIssuer == "" {
		return nil, fmt.Errorf("config: ACCESS_TOKEN_ISSUER is required")
	}
	return c, nil
}

// VerifierConfig configures cmd/verifier-service.
type VerifierConfig struct {
	HTTPAddr    string
	BaseURL     string
	PostgresDSN string

	// ShardRedisURLs maps shard_id -> that shard's Redis connection
	// string, since a verifier may need to read any shard's bitmap
	// depending on which shard a requested list belongs to (§15.5).
	ShardRedisURLs map[string]string

	DefaultTTLSeconds int64
	// GCRetentionPeriod must match the ingestion shards' own setting —
	// it's how the verifier decides whether an ARCHIVED list is still
	// within its serve-the-last-token window or should now 410 (§7 point
	// 4, §13). GC itself (archiving, purging) still runs only on the
	// ingestion side (internal/gc); the verifier only reads this value.
	GCRetentionPeriod time.Duration

	SigningKey   *ecdsa.PrivateKey
	SigningKeyID string
}

func LoadVerifier() (*VerifierConfig, error) {
	c := &VerifierConfig{
		HTTPAddr:          getEnv("HTTP_ADDR", ":8081"),
		BaseURL:           getEnv("BASE_URL", "http://localhost:8081"),
		PostgresDSN:       getEnv("DATABASE_URL", defaultPostgresDSN),
		DefaultTTLSeconds: 3600,
		GCRetentionPeriod: 30 * 24 * time.Hour,
		SigningKeyID:      getEnv("SIGNING_KEY_ID", "prototype-1"),
	}
	var err error
	if c.DefaultTTLSeconds, err = getInt64Env("DEFAULT_TTL_SECONDS", c.DefaultTTLSeconds); err != nil {
		return nil, err
	}
	if c.GCRetentionPeriod, err = getDurationEnv("GC_RETENTION_PERIOD", c.GCRetentionPeriod); err != nil {
		return nil, err
	}
	if c.SigningKey, err = requireECKeyEnv("SIGNING_KEY_PEM"); err != nil {
		return nil, err
	}

	raw := os.Getenv("SHARD_REDIS_URLS")
	if raw == "" {
		return nil, fmt.Errorf("config: SHARD_REDIS_URLS is required (JSON object of shard_id -> redis URL)")
	}
	if err := json.Unmarshal([]byte(raw), &c.ShardRedisURLs); err != nil {
		return nil, fmt.Errorf("config: SHARD_REDIS_URLS: %w", err)
	}
	return c, nil
}

// ASConfig configures cmd/as, the Authorization Server (§15.2).
type ASConfig struct {
	HTTPAddr string
	// BaseURL is the AS's own public base URL — both the `iss` claim on
	// minted tokens and the expected `aud` on inbound client assertions.
	BaseURL string

	PostgresDSN string

	// SigningKey signs access tokens; deliberately distinct from the
	// StatusListToken signing key (different service, different trust
	// boundary — see docs/design.md §15.8).
	SigningKey   *ecdsa.PrivateKey
	SigningKeyID string

	AccessTokenTTL      time.Duration
	AccessTokenAudience string

	// Shards is the pool of shard IDs new issuers get round-robin
	// assigned into on first token issuance (§15.5).
	Shards []string

	// TrustPDPURL selects the trust source (decided 2026-09-24): if set,
	// evaluations go to a real go-trust PDP over AuthZEN, and a PDP
	// error/unreachability fails closed (no token issued). If unset, the
	// default is AllowAllEvaluator — fail *open* — so a prototype/dev
	// deployment works without a PDP; never appropriate for production.
	TrustPDPURL     string
	TrustActionName string
}

func LoadAS() (*ASConfig, error) {
	c := &ASConfig{
		HTTPAddr:            getEnv("HTTP_ADDR", ":8082"),
		BaseURL:             getEnv("BASE_URL", "http://localhost:8082"),
		PostgresDSN:         getEnv("DATABASE_URL", defaultPostgresDSN),
		SigningKeyID:        getEnv("SIGNING_KEY_ID", "as-prototype-1"),
		AccessTokenTTL:      time.Hour,
		AccessTokenAudience: getEnv("ACCESS_TOKEN_AUDIENCE", "siros-status-service"),
		TrustPDPURL:         os.Getenv("TRUST_PDP_URL"),
		TrustActionName:     os.Getenv("TRUST_ACTION_NAME"),
	}
	var err error
	if c.AccessTokenTTL, err = getDurationEnv("ACCESS_TOKEN_TTL", c.AccessTokenTTL); err != nil {
		return nil, err
	}
	if c.SigningKey, err = requireECKeyEnv("AS_SIGNING_KEY_PEM"); err != nil {
		return nil, err
	}

	shards := getEnv("SHARDS", "default")
	c.Shards = strings.Split(shards, ",")
	return c, nil
}

// IngressConfig configures cmd/ingress-router (§15.6).
type IngressConfig struct {
	HTTPAddr string

	ASJWKSURL           string
	AccessTokenIssuer   string
	AccessTokenAudience string
	JWKSRefreshInterval time.Duration

	// ShardBackends maps shard_id -> that shard's ingestion-service base
	// URL, read from the access token's shard claim per request.
	ShardBackends map[string]string
}

func LoadIngress() (*IngressConfig, error) {
	c := &IngressConfig{
		HTTPAddr:            getEnv("HTTP_ADDR", ":8083"),
		AccessTokenAudience: getEnv("ACCESS_TOKEN_AUDIENCE", "siros-status-service"),
		JWKSRefreshInterval: 5 * time.Minute,
	}
	var err error
	if c.JWKSRefreshInterval, err = getDurationEnv("JWKS_REFRESH_INTERVAL", c.JWKSRefreshInterval); err != nil {
		return nil, err
	}

	c.ASJWKSURL = os.Getenv("AS_JWKS_URL")
	if c.ASJWKSURL == "" {
		return nil, fmt.Errorf("config: AS_JWKS_URL is required")
	}
	c.AccessTokenIssuer = os.Getenv("ACCESS_TOKEN_ISSUER")
	if c.AccessTokenIssuer == "" {
		return nil, fmt.Errorf("config: ACCESS_TOKEN_ISSUER is required")
	}

	raw := os.Getenv("SHARD_BACKENDS")
	if raw == "" {
		return nil, fmt.Errorf("config: SHARD_BACKENDS is required (JSON object of shard_id -> backend base URL)")
	}
	if err := json.Unmarshal([]byte(raw), &c.ShardBackends); err != nil {
		return nil, fmt.Errorf("config: SHARD_BACKENDS: %w", err)
	}
	return c, nil
}

const defaultPostgresDSN = "postgres://postgres:postgres@localhost:5432/statuslist?sslmode=disable"

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getIntEnv(key string, def int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("config: %s: %w", key, err)
	}
	return n, nil
}

func getInt64Env(key string, def int64) (int64, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("config: %s: %w", key, err)
	}
	return n, nil
}

func getUint64Env(key string, def uint64) (uint64, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("config: %s: %w", key, err)
	}
	return n, nil
}

func getFloat64Env(key string, def float64) (float64, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0, fmt.Errorf("config: %s: %w", key, err)
	}
	return f, nil
}

func getDurationEnv(key string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("config: %s: %w", key, err)
	}
	return d, nil
}

func requireECKeyEnv(key string) (*ecdsa.PrivateKey, error) {
	pemStr := os.Getenv(key)
	if pemStr == "" {
		return nil, fmt.Errorf("config: %s is required (PEM-encoded EC private key, P-256)", key)
	}
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("config: %s: no PEM block found", key)
	}
	k, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("config: %s: parse EC private key: %w", key, err)
	}
	return k, nil
}
