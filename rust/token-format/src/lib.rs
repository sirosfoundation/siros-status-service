//! Decode and validate the ES256 access tokens minted by
//! `internal/accesstoken.KeyManager` (this service's own Authorization
//! Server, `cmd/as` — see `docs/design.md` §15.2/§15.3) and normally
//! verified by `go-tokenauth`'s `validator.Validator`.
//!
//! This crate does **not** fetch a JWKS itself, and does not implement
//! anything beyond the one algorithm/claim shape this service's AS actually
//! issues (`ES256`, `go-tokenauth/claims.AccessTokenClaims`) — it is
//! deliberately not a general-purpose JWT library. A caller supplies an
//! already-fetched [`JwkSet`] (however it got it — an HTTP fetch, a KV
//! Store cache, a config file) and gets back validated claims. That split
//! is what makes this portable to `wasm32-wasip1` for Fastly Compute (see
//! `../fastly-ingress-sample`): fetching/caching the JWKS is inherently
//! platform-specific (Fastly has no persistent process memory between
//! requests — see that crate's README), decoding and verifying a token
//! against a key set already in hand is not.
//!
//! Field names and validation semantics are matched against
//! `go-tokenauth@v0.4.0`'s `validator.validateAsymmetric` and
//! `go-jose/go-jose/v4/jwt`'s `Claims.ValidateWithLeeway` — see the doc
//! comments below for exactly which behaviors were cross-checked against
//! that source, and `tests/cross_lang.rs` for a token minted by this
//! service's real `internal/accesstoken.KeyManager` (not a hand-crafted
//! fixture), via `tools/gen-fixture`.

use std::fmt;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::{Deserialize, Deserializer};

/// The claims carried by a `go-tokenauth/claims.AccessTokenClaims`-shaped
/// token. Field names and optionality mirror that Go struct (embedded
/// `jwt.Claims` plus `tenant_id`/`tac`/`acr`) exactly — see
/// `internal/accesstoken/keymanager.go` for the issuing side.
#[derive(Debug, Clone, Deserialize)]
pub struct AccessTokenClaims {
    pub iss: String,
    #[serde(default)]
    pub sub: String,
    #[serde(default)]
    pub aud: Audience,
    pub exp: Option<i64>,
    pub nbf: Option<i64>,
    pub iat: Option<i64>,
    #[serde(default)]
    pub jti: String,
    /// This service's "shard" (docs/design.md §15.5) — the value
    /// `cmd/ingress-router` reads to pick a backend.
    pub tenant_id: String,
    /// Token access control permission characters (docs/design.md §15.2:
    /// `i`=insert/allocate, `w`=write/status-update, `r`=read/accounting).
    pub tac: String,
    #[serde(default)]
    pub acr: Option<String>,
}

/// The JWT `aud` claim: go-jose's `jwt.Audience` marshals a single value as
/// a bare JSON string (not a one-element array) and only uses an array for
/// two or more — this deserializer accepts either shape.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Audience(pub Vec<String>);

impl Audience {
    pub fn contains(&self, v: &str) -> bool {
        self.0.iter().any(|a| a == v)
    }
}

impl<'de> Deserialize<'de> for Audience {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error as _;
        match serde_json::Value::deserialize(deserializer)? {
            serde_json::Value::String(s) => Ok(Audience(vec![s])),
            serde_json::Value::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    match item {
                        serde_json::Value::String(s) => out.push(s),
                        _ => return Err(D::Error::custom("aud: array must contain only strings")),
                    }
                }
                Ok(Audience(out))
            }
            _ => Err(D::Error::custom(
                "aud: must be a string or an array of strings",
            )),
        }
    }
}

/// One EC public key from a JOSE JWK Set, as published at
/// `cmd/as`'s `/.well-known/jwks.json` (`internal/accesstoken.KeyManager.JWKS`).
/// Only what verification needs — no private-key or non-EC fields.
#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub crv: Option<String>,
    pub kid: String,
    pub x: Option<String>,
    pub y: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

impl JwkSet {
    pub fn find(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|k| k.kid == kid)
    }
}

/// Mirrors `go-tokenauth/validator.Config`'s subset that actually affects
/// verification of one token: the AS's own `Issuer`, this service's
/// accepted `Audiences` (`AnyAudience` — a match against any one of them
/// is enough, same as the Go validator), and `Leeway` for `exp`/`nbf`/`iat`
/// (go-tokenauth defaults this to 5s when unset; this crate has no
/// implicit default — callers state it explicitly).
pub struct ValidationOptions<'a> {
    pub issuer: &'a str,
    pub audience: &'a [&'a str],
    pub leeway_secs: i64,
    /// Overrides "now" for the exp/nbf/iat checks below. `None` uses the
    /// system clock (works under Fastly Compute's WASI clock too — this is
    /// only for deterministic tests, not a platform workaround).
    pub now: Option<i64>,
}

impl<'a> ValidationOptions<'a> {
    pub fn new(issuer: &'a str, audience: &'a [&'a str]) -> Self {
        ValidationOptions {
            issuer,
            audience,
            leeway_secs: 5,
            now: None,
        }
    }
}

#[derive(Debug)]
pub enum TokenError {
    Malformed(String),
    UnsupportedAlgorithm(String),
    MissingKid,
    UnknownKid(String),
    UnsupportedKeyType(String),
    InvalidKey(String),
    SignatureInvalid,
    InvalidClaims(String),
    InvalidIssuer,
    InvalidAudience,
    NotYetValid,
    Expired,
    IssuedInFuture,
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenError::Malformed(why) => write!(f, "token-format: malformed token: {why}"),
            TokenError::UnsupportedAlgorithm(alg) => write!(f, "token-format: unsupported algorithm {alg:?} (only ES256 is issued by this service's AS)"),
            TokenError::MissingKid => write!(f, "token-format: token header has no kid"),
            TokenError::UnknownKid(kid) => write!(f, "token-format: no key in the supplied JWKS with kid {kid:?}"),
            TokenError::UnsupportedKeyType(kty) => write!(f, "token-format: unsupported key type {kty:?} (only EC P-256 is issued by this service's AS)"),
            TokenError::InvalidKey(why) => write!(f, "token-format: invalid key material: {why}"),
            TokenError::SignatureInvalid => write!(f, "token-format: signature verification failed"),
            TokenError::InvalidClaims(why) => write!(f, "token-format: could not parse claims: {why}"),
            TokenError::InvalidIssuer => write!(f, "token-format: unexpected issuer"),
            TokenError::InvalidAudience => write!(f, "token-format: no accepted audience present"),
            TokenError::NotYetValid => write!(f, "token-format: token not yet valid (nbf)"),
            TokenError::Expired => write!(f, "token-format: token expired"),
            TokenError::IssuedInFuture => write!(f, "token-format: token issued in the future (iat)"),
        }
    }
}

impl std::error::Error for TokenError {}

#[derive(Deserialize)]
struct Header {
    alg: String,
    kid: Option<String>,
}

/// Decodes and fully validates `token` against `jwks`: signature (ES256
/// only — the only algorithm this service's AS issues), `iss` (exact
/// match), `aud` (non-empty intersection with `opts.audience`, matching
/// go-jose's `AnyAudience` semantics), and `exp`/`nbf`/`iat` with
/// `opts.leeway_secs` — the exact checks `Claims.ValidateWithLeeway`
/// performs (go-jose/go-jose/v4/jwt/validation.go), specifically:
///   - `nbf`: reject if `now + leeway < nbf`
///   - `exp`: reject if `now - leeway > exp`
///   - `iat`: reject if `now + leeway < iat`
///
/// (each only checked when the claim is present — none of these are
/// mandatory per RFC 7519, though this service's AS always sets `exp`/`iat`).
pub fn validate(
    token: &str,
    jwks: &JwkSet,
    opts: &ValidationOptions,
) -> Result<AccessTokenClaims, TokenError> {
    let mut parts = token.split('.');
    let (header_b64, payload_b64, sig_b64) =
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(h), Some(p), Some(s), None) => (h, p, s),
            _ => {
                return Err(TokenError::Malformed(
                    "expected exactly three '.'-separated parts".into(),
                ))
            }
        };

    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| TokenError::Malformed("header is not valid base64url".into()))?;
    let header: Header = serde_json::from_slice(&header_bytes)
        .map_err(|e| TokenError::Malformed(format!("header is not valid JSON: {e}")))?;
    if header.alg != "ES256" {
        return Err(TokenError::UnsupportedAlgorithm(header.alg));
    }
    let kid = header.kid.ok_or(TokenError::MissingKid)?;

    let jwk = jwks
        .find(&kid)
        .ok_or_else(|| TokenError::UnknownKid(kid.clone()))?;
    let verifying_key = verifying_key_from_jwk(jwk)?;

    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| TokenError::Malformed("signature is not valid base64url".into()))?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|_| TokenError::SignatureInvalid)?;
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| TokenError::SignatureInvalid)?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| TokenError::Malformed("payload is not valid base64url".into()))?;
    let claims: AccessTokenClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| TokenError::InvalidClaims(e.to_string()))?;

    if !opts.issuer.is_empty() && claims.iss != opts.issuer {
        return Err(TokenError::InvalidIssuer);
    }
    if !opts.audience.is_empty() && !opts.audience.iter().any(|want| claims.aud.contains(want)) {
        return Err(TokenError::InvalidAudience);
    }

    let now = opts.now.unwrap_or_else(current_unix_time);
    let leeway = opts.leeway_secs;
    if let Some(nbf) = claims.nbf {
        if now + leeway < nbf {
            return Err(TokenError::NotYetValid);
        }
    }
    if let Some(exp) = claims.exp {
        if now - leeway > exp {
            return Err(TokenError::Expired);
        }
    }
    if let Some(iat) = claims.iat {
        if now + leeway < iat {
            return Err(TokenError::IssuedInFuture);
        }
    }

    Ok(claims)
}

fn verifying_key_from_jwk(jwk: &Jwk) -> Result<VerifyingKey, TokenError> {
    if jwk.kty != "EC" {
        return Err(TokenError::UnsupportedKeyType(jwk.kty.clone()));
    }
    if jwk.crv.as_deref() != Some("P-256") {
        return Err(TokenError::UnsupportedKeyType(format!(
            "EC/{}",
            jwk.crv.as_deref().unwrap_or("?")
        )));
    }
    let x = URL_SAFE_NO_PAD
        .decode(
            jwk.x
                .as_deref()
                .ok_or_else(|| TokenError::InvalidKey("missing x".into()))?,
        )
        .map_err(|_| TokenError::InvalidKey("x is not valid base64url".into()))?;
    let y = URL_SAFE_NO_PAD
        .decode(
            jwk.y
                .as_deref()
                .ok_or_else(|| TokenError::InvalidKey("missing y".into()))?,
        )
        .map_err(|_| TokenError::InvalidKey("y is not valid base64url".into()))?;
    if x.len() != 32 || y.len() != 32 {
        return Err(TokenError::InvalidKey(
            "x/y must each be 32 bytes for P-256".into(),
        ));
    }

    // Uncompressed SEC1 point: 0x04 || X || Y (RFC 7518 §6.2.1's x/y are
    // exactly those coordinates, base64url-encoded with no padding).
    let mut point = Vec::with_capacity(65);
    point.push(0x04);
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);

    VerifyingKey::from_sec1_bytes(&point).map_err(|e| TokenError::InvalidKey(e.to_string()))
}

fn current_unix_time() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
