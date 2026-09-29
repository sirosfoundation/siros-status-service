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
	"encoding/base64"
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
	// HTTPAddr is the address this service listens on (host:port, or
	// just :port).
	HTTPAddr string
	// BaseURL is this service's own public base URL, used to build
	// {list_url} values returned from POST /allocate.
	BaseURL string

	// RedisAddr is used only if RedisURL is unset. RedisURL (a full
	// redis:// or rediss:// URL) takes priority when set, and is
	// required for managed offerings needing auth/TLS (e.g. Fly's
	// Upstash-backed Redis).
	RedisAddr string
	RedisURL  string
	// PostgresDSN is the shared metadata Postgres connection string —
	// the same database as cmd/as and cmd/verifier-service point at
	// (docs/design.md §18).
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

	// GCGracePeriod, GCRetentionPeriod, and GCCheckInterval configure
	// internal/gc's archive/purge sweep (§7 point 4) — see
	// VerifierConfig.GCRetentionPeriod's own comment for why the
	// verifier needs a copy of just that one value.
	GCGracePeriod     time.Duration
	GCRetentionPeriod time.Duration
	GCCheckInterval   time.Duration
	// DBRetentionPeriod is how long after a list's Redis bitmap is
	// purged before its Postgres row (and every allocation recorded
	// against it) is hard-deleted (§22). Zero (the default) disables
	// this phase entirely — rows are kept forever, since some
	// deployments have real audit-history/compliance reasons to never
	// delete them; enable deliberately, per deployment.
	DBRetentionPeriod time.Duration

	// Signing is where StatusListTokens' signing key actually comes from:
	// SIGNING_KEY_PEM (PEM-encoded EC private key, the default), or,
	// opt-in, a PKCS#11 HSM via PKCS11_MODULE_PATH + PKCS11_TOKEN_LABEL +
	// PKCS11_KEY_LABEL + PKCS11_PIN (PKCS11_POOL_SIZE optional, default
	// 4) — §26. Configure exactly one; must resolve to the same signing
	// identity across every ingestion shard and the verifier.
	// SigningKeyID is placed in the JWS `kid` header.
	Signing      SigningSource
	SigningKeyID string
	// SigningCertChain, from SIGNING_CERT_CHAIN_PEM (a PEM bundle, leaf
	// first) if set, is embedded as the published StatusListToken's own
	// `x5c` header (§25) — the signing key's certificate chain, letting a
	// verifier evaluate trust in the signer, not just validate the
	// signature. Optional: nil if this deployment's signing key has no
	// associated certificate.
	SigningCertChain []string

	// ASJWKSURL, AccessTokenIssuer, and AccessTokenAudience configure
	// offline access-token verification (§15.3) — the AS is never
	// called on the request path, only its JWKS is fetched and cached.
	ASJWKSURL           string
	AccessTokenIssuer   string
	AccessTokenAudience string
	// JWKSRefreshInterval is how often ASJWKSURL is re-fetched.
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
		DBRetentionPeriod:   0, // disabled by default (§22): rows kept forever unless explicitly enabled
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
	if c.DBRetentionPeriod, err = getDurationEnv("DB_RETENTION_PERIOD", c.DBRetentionPeriod); err != nil {
		return nil, err
	}
	if c.JWKSRefreshInterval, err = getDurationEnv("JWKS_REFRESH_INTERVAL", c.JWKSRefreshInterval); err != nil {
		return nil, err
	}
	if c.Signing, err = loadSigningSource("SIGNING_KEY_PEM"); err != nil {
		return nil, err
	}
	if c.SigningCertChain, err = optionalCertChainEnv("SIGNING_CERT_CHAIN_PEM"); err != nil {
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
	// HTTPAddr is the address this service listens on (host:port, or
	// just :port).
	HTTPAddr string
	// BaseURL is this service's own public base URL — signed into every
	// published StatusListToken's `sub` claim, and what every ingestion
	// shard's own BaseURL points POST /allocate's `list_url` response at
	// (docs/design.md §18).
	BaseURL string
	// PostgresDSN is the shared metadata Postgres connection string —
	// the same database as cmd/as and every cmd/ingestion-service shard
	// point at (docs/design.md §18).
	PostgresDSN string

	// ShardRedisURLs maps shard_id -> that shard's Redis connection
	// string, since a verifier may need to read any shard's bitmap
	// depending on which shard a requested list belongs to (§15.5).
	ShardRedisURLs map[string]string

	// DefaultTTLSeconds is the fallback cache lifetime applied when an
	// issuer didn't set its own at allocation time (§9/§13).
	DefaultTTLSeconds int64
	// GCRetentionPeriod must match the ingestion shards' own setting —
	// it's how the verifier decides whether an ARCHIVED list is still
	// within its serve-the-last-token window or should now 410 (§7 point
	// 4, §13). GC itself (archiving, purging) still runs only on the
	// ingestion side (internal/gc); the verifier only reads this value.
	GCRetentionPeriod time.Duration

	// Signing is where StatusListTokens' signing key actually comes from:
	// SIGNING_KEY_PEM (PEM-encoded EC private key, the default), or,
	// opt-in, a PKCS#11 HSM via PKCS11_MODULE_PATH + PKCS11_TOKEN_LABEL +
	// PKCS11_KEY_LABEL + PKCS11_PIN (PKCS11_POOL_SIZE optional, default
	// 4) — §26. Configure exactly one; must resolve to the same signing
	// identity as every ingestion shard.
	Signing SigningSource
	// SigningKeyID is placed in the JWS `kid` header on published
	// StatusListTokens — must match every ingestion shard's own value
	// (one signing identity).
	SigningKeyID string
	// SigningCertChain, from SIGNING_CERT_CHAIN_PEM (a PEM bundle, leaf
	// first) if set, is embedded as the published StatusListToken's own
	// `x5c` header (§25) — must match every ingestion shard's own value.
	SigningCertChain []string
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
	if c.Signing, err = loadSigningSource("SIGNING_KEY_PEM"); err != nil {
		return nil, err
	}
	if c.SigningCertChain, err = optionalCertChainEnv("SIGNING_CERT_CHAIN_PEM"); err != nil {
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
	// HTTPAddr is the address this service listens on (host:port, or
	// just :port).
	HTTPAddr string
	// BaseURL is the AS's own public base URL — both the `iss` claim on
	// minted tokens and the expected `aud` on inbound client assertions.
	BaseURL string

	// PostgresDSN is the shared metadata Postgres connection string —
	// the same database as every cmd/ingestion-service shard and
	// cmd/verifier-service point at (docs/design.md §18).
	PostgresDSN string

	// SigningKey signs access tokens; deliberately distinct from the
	// StatusListToken signing key (different service, different trust
	// boundary — see docs/design.md §15.8). SigningKeyID is placed in
	// the JWS `kid` header on minted access tokens.
	SigningKey   *ecdsa.PrivateKey
	SigningKeyID string

	AccessTokenTTL time.Duration
	// AccessTokenAudience is the `aud` claim minted access tokens carry,
	// and what every consumer (cmd/ingress-router, cmd/ingestion-service)
	// requires an inbound token to match.
	AccessTokenAudience string

	// Shards is the pool of shard IDs new issuers get round-robin
	// assigned into on first token issuance (§15.5).
	Shards []string

	// TrustPDPURL selects the trust source (decided 2026-09-24): if set,
	// evaluations go to a real go-trust PDP over AuthZEN, and a PDP
	// error/unreachability fails closed (no token issued). If unset, the
	// default is AllowAllEvaluator — fail *open* — so a prototype/dev
	// deployment works without a PDP; never appropriate for production.
	TrustPDPURL string
	// TrustActionName is the AuthZEN action name sent to the PDP — only
	// meaningful when TrustPDPURL is set.
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
	// HTTPAddr is the address this service listens on (host:port, or
	// just :port).
	HTTPAddr string

	// ASJWKSURL, AccessTokenIssuer, and AccessTokenAudience configure
	// offline access-token verification (§15.3/§15.6) — the AS is never
	// called on the request path, only its JWKS is fetched and cached.
	ASJWKSURL           string
	AccessTokenIssuer   string
	AccessTokenAudience string
	// JWKSRefreshInterval is how often ASJWKSURL is re-fetched.
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

// SigningSource is where a StatusListToken signing identity actually
// comes from (docs/design.md §26): exactly one of Key or PKCS11 is set.
// Deliberately just data here — internal/config stays a thin env-var
// loader with no PKCS#11 driver dependency; internal/signing is what
// turns this into a real crypto.Signer, connecting to the HSM only if
// PKCS11 is actually configured.
type SigningSource struct {
	Key    *ecdsa.PrivateKey
	PKCS11 *PKCS11Config
}

// PKCS11Config configures a pooled PKCS#11 HSM signer
// (github.com/sirosfoundation/go-cryptoutil/pkcs11pool).
type PKCS11Config struct {
	ModulePath string
	// Exactly one of TokenLabel or SlotID identifies which slot to use;
	// TokenLabel wins if both are set (matches pkcs11pool.Config's own
	// precedence).
	TokenLabel string
	SlotID     uint
	PIN        string
	// KeyLabel identifies the key on the token (CKA_LABEL) — this
	// service always selects by label, never by raw CKA_ID, since a
	// human-assigned label is what an operator actually provisions the
	// HSM with.
	KeyLabel string
	PoolSize int
}

// loadSigningSource resolves a StatusListToken signing identity from
// the environment: PKCS11_MODULE_PATH set means PKCS#11 (§26, opt-in —
// unset by default, so every existing deployment's behavior is
// unchanged); otherwise pemEnvVar (e.g. SIGNING_KEY_PEM) is required,
// matching this service's original, only-ever behavior. Configuring
// both is rejected outright rather than silently preferring one — an
// operator who set both almost certainly means something different than
// either alone would do.
func loadSigningSource(pemEnvVar string) (SigningSource, error) {
	modulePath := os.Getenv("PKCS11_MODULE_PATH")
	pemStr := os.Getenv(pemEnvVar)
	if modulePath != "" && pemStr != "" {
		return SigningSource{}, fmt.Errorf("config: both PKCS11_MODULE_PATH and %s are set — configure exactly one signing source", pemEnvVar)
	}
	if modulePath == "" {
		key, err := requireECKeyEnv(pemEnvVar)
		if err != nil {
			return SigningSource{}, err
		}
		return SigningSource{Key: key}, nil
	}

	poolSize, err := getIntEnv("PKCS11_POOL_SIZE", 4)
	if err != nil {
		return SigningSource{}, err
	}
	// Selecting by token label (not raw slot number) is the primary path
	// this service supports — a label is what an operator actually
	// provisions the HSM with, and unlike a slot number it can't be
	// silently ambiguous with "unset" (0 is both a valid real slot and
	// getUint64Env's zero-value default). PKCS11Config.SlotID stays
	// available on the struct for a future caller that wants it, but
	// this loader doesn't validate or default it — TokenLabel is
	// required here.
	tokenLabel := os.Getenv("PKCS11_TOKEN_LABEL")
	if tokenLabel == "" {
		return SigningSource{}, fmt.Errorf("config: PKCS11_MODULE_PATH is set — PKCS11_TOKEN_LABEL is required")
	}
	keyLabel := os.Getenv("PKCS11_KEY_LABEL")
	if keyLabel == "" {
		return SigningSource{}, fmt.Errorf("config: PKCS11_MODULE_PATH is set — PKCS11_KEY_LABEL is required")
	}
	pin := os.Getenv("PKCS11_PIN")
	if pin == "" {
		return SigningSource{}, fmt.Errorf("config: PKCS11_MODULE_PATH is set — PKCS11_PIN is required")
	}

	return SigningSource{PKCS11: &PKCS11Config{
		ModulePath: modulePath,
		TokenLabel: tokenLabel,
		PIN:        pin,
		KeyLabel:   keyLabel,
		PoolSize:   poolSize,
	}}, nil
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

// optionalCertChainEnv parses a PEM bundle of one or more certificates
// (concatenated, leaf first) into an x5c-shaped array — each entry
// base64-STANDARD-encoded DER, matching internal/clientassertion's x5c
// convention (RFC 7515 §4.1.6) — for embedding in published Status List
// Tokens' own JWS header (docs/design.md §25). Unlike requireECKeyEnv,
// unset is not an error: whether this deployment's signing key has an
// associated certificate at all is optional, not required — nil, nil
// means "no chain configured," not "misconfigured."
func optionalCertChainEnv(key string) ([]string, error) {
	pemStr := os.Getenv(key)
	if pemStr == "" {
		return nil, nil
	}
	rest := []byte(pemStr)
	var chain []string
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		chain = append(chain, base64.StdEncoding.EncodeToString(block.Bytes))
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("config: %s: no PEM CERTIFICATE block found", key)
	}
	return chain, nil
}
