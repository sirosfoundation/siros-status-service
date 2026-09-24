//! Sample Fastly Compute reimplementation of `cmd/ingress-router`'s logic
//! (docs/design.md §15.6): verify a `token-format`-decodable access token,
//! read its `tenant_id` claim, and reverse-proxy to that shard's backend.
//!
//! This is a **sample**, not a drop-in replacement for `cmd/ingress-router`
//! — see README.md for exactly what it demonstrates vs. what a real
//! deployment would still need (config-store-driven AS URL, error-path
//! hardening, observability). It exists to prove the pattern discussed in
//! docs/design.md's Fastly Compute investigation actually compiles and
//! runs, using the real `token-format` crate.

use std::time::Duration;

use fastly::http::header::WWW_AUTHENTICATE;
use fastly::http::{StatusCode, Url};
use fastly::kv_store::{KVStore, KVStoreError};
use fastly::{Backend, ConfigStore, Error, Request, Response};
use token_format::{validate, JwkSet, TokenError, ValidationOptions};

/// In a real deployment these three would come from a Config Store entry
/// (set once at `fastly compute deploy` time, no rebuild needed to point
/// at a different AS) rather than being compiled in — hardcoded here only
/// because this is a sample meant to run standalone with minimal setup.
/// See README.md.
const AS_HOST: &str = "siros-status-service-as.fly.dev";
const ACCESS_TOKEN_ISSUER: &str = "https://siros-status-service-as.fly.dev";
const ACCESS_TOKEN_AUDIENCE: &str = "siros-status-service";

const JWKS_CACHE_KEY: &str = "as_jwks";
// Matches go-tokenauth/validator.Config's JWKSRefresh default (5m) — see
// internal/config's JWKSRefreshInterval default in the Go services.
const JWKS_CACHE_TTL: Duration = Duration::from_secs(300);

#[fastly::main]
fn main(req: Request) -> Result<Response, Error> {
    if req.get_path() == "/healthz" {
        return Ok(Response::from_status(StatusCode::OK).with_body_text_plain(r#"{"status":"ok"}"#));
    }

    let token = match bearer_token(&req) {
        Some(t) => t,
        None => {
            // RFC 6750 §3: the request itself is malformed (no bearer token
            // was even presented), as distinct from a bearer token that was
            // presented but rejected.
            return Ok(text_response(
                StatusCode::UNAUTHORIZED,
                "missing or malformed Authorization header",
            )
            .with_header(WWW_AUTHENTICATE, r#"Bearer error="invalid_request""#));
        }
    };

    let jwks = match load_jwks() {
        Ok(jwks) => jwks,
        Err(e) => {
            return Ok(text_response(
                StatusCode::BAD_GATEWAY,
                &format!("could not load AS JWKS: {e}"),
            ))
        }
    };

    let opts = ValidationOptions::new(ACCESS_TOKEN_ISSUER, &[ACCESS_TOKEN_AUDIENCE]);
    let claims = match validate(token, &jwks, &opts) {
        Ok(claims) => claims,
        Err(e) => {
            let challenge = bearer_invalid_token_challenge(&e);
            return Ok(text_response(
                StatusCode::UNAUTHORIZED,
                &format!("invalid access token: {e}"),
            )
            .with_header(WWW_AUTHENTICATE, challenge));
        }
    };

    // shard_id -> backend base URL (e.g. "https://siros-status-service-ingestion.fly.dev"),
    // one Config Store item per shard — the Fastly analog of cmd/ingress-router's
    // SHARD_BACKENDS JSON map, but settable without a redeploy.
    let shard_backends = ConfigStore::open("shard_backends");
    let backend_base = match shard_backends.get(&claims.tenant_id) {
        Some(url) => url,
        None => {
            return Ok(text_response(
                StatusCode::BAD_GATEWAY,
                &format!("no backend configured for shard {:?}", claims.tenant_id),
            ))
        }
    };

    forward(req, &claims.tenant_id, &backend_base)
}

fn bearer_token(req: &Request) -> Option<&str> {
    let value = req.get_header_str("authorization")?;
    let token = value.strip_prefix("Bearer ")?;
    if token.is_empty() {
        None
    } else {
        Some(token)
    }
}

fn text_response(status: StatusCode, body: &str) -> Response {
    Response::from_status(status).with_body_text_plain(body)
}

/// Builds the RFC 6750 §3 `WWW-Authenticate` challenge for a rejected
/// bearer token, distinguishing `TokenError::Expired` from every other
/// rejection reason via `error_description` (RFC 6750 has no separate
/// "expired" error *code* — expiry is signaled via `error_description` on
/// `invalid_token`). Mirrors `internal/ingress/router.go`'s
/// `bearerInvalidTokenChallenge` (Go) so both implementations of "the same
/// service" signal the same way, matched explicitly on the `TokenError`
/// variant rather than its `Display` text.
fn bearer_invalid_token_challenge(err: &TokenError) -> String {
    let description = match err {
        TokenError::Expired => "the access token expired",
        _ => "the access token is invalid",
    };
    format!(r#"Bearer error="invalid_token", error_description="{description}""#)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_invalid_token_challenge_flags_expiry_specifically() {
        assert_eq!(
            bearer_invalid_token_challenge(&TokenError::Expired),
            r#"Bearer error="invalid_token", error_description="the access token expired""#
        );
    }

    #[test]
    fn bearer_invalid_token_challenge_is_generic_for_other_variants() {
        let generic =
            r#"Bearer error="invalid_token", error_description="the access token is invalid""#;
        assert_eq!(
            bearer_invalid_token_challenge(&TokenError::SignatureInvalid),
            generic
        );
        assert_eq!(
            bearer_invalid_token_challenge(&TokenError::InvalidIssuer),
            generic
        );
        assert_eq!(
            bearer_invalid_token_challenge(&TokenError::InvalidAudience),
            generic
        );
        assert_eq!(
            bearer_invalid_token_challenge(&TokenError::NotYetValid),
            generic
        );
        assert_eq!(
            bearer_invalid_token_challenge(&TokenError::IssuedInFuture),
            generic
        );
        assert_eq!(
            bearer_invalid_token_challenge(&TokenError::MissingKid),
            generic
        );
    }
}

/// Cache-aside JWKS load: each Fastly Compute invocation starts with no
/// persistent memory (docs/design.md's Fastly investigation, point 3), so
/// there is no equivalent of go-tokenauth's in-process background-refresh
/// goroutine here — the KV Store plays that role instead, with a plain TTL
/// rather than a refresh loop.
fn load_jwks() -> Result<JwkSet, Error> {
    let store = KVStore::open("jwks_cache")?;
    let Some(store) = store else {
        // No KV Store provisioned for this service (e.g. a from-scratch
        // `fastly compute serve` run with none configured yet) — fetch on
        // every request rather than fail; correct, just uncached.
        return Ok(serde_json::from_slice(&fetch_jwks()?)?);
    };

    match store.lookup(JWKS_CACHE_KEY) {
        Ok(mut hit) => Ok(serde_json::from_slice(&hit.take_body_bytes())?),
        Err(KVStoreError::ItemNotFound) => {
            let body = fetch_jwks()?;
            // Best-effort: a failed cache write shouldn't fail the request
            // that triggered the refresh — the next request just refetches.
            let _ = store
                .build_insert()
                .time_to_live(JWKS_CACHE_TTL)
                .execute(JWKS_CACHE_KEY, body.clone());
            Ok(serde_json::from_slice(&body)?)
        }
        Err(e) => Err(e.into()),
    }
}

fn fetch_jwks() -> Result<Vec<u8>, Error> {
    let backend = Backend::builder("as-jwks", AS_HOST).enable_ssl().finish()?;
    let url = format!("https://{AS_HOST}/.well-known/jwks.json");
    let mut resp = Request::get(url).send(&backend)?;
    Ok(resp.take_body_bytes())
}

/// Reverse-proxies `req` to `backend_base` (e.g.
/// `"https://siros-status-service-ingestion.fly.dev"`), preserving path and
/// query — the Fastly analog of `internal/ingress.Router`'s
/// `httputil.ReverseProxy`. `shard_id` only names the dynamic backend so
/// distinct shards don't collide within one execution.
fn forward(mut req: Request, shard_id: &str, backend_base: &str) -> Result<Response, Error> {
    let target = Url::parse(backend_base)
        .map_err(|e| Error::msg(format!("invalid backend URL {backend_base:?}: {e}")))?;
    let host = target
        .host_str()
        .ok_or_else(|| Error::msg(format!("backend URL {backend_base:?} has no host")))?;
    let use_ssl = target.scheme() == "https";

    let mut builder = Backend::builder(format!("shard-{shard_id}"), host);
    if use_ssl {
        builder = builder.enable_ssl();
    }
    let backend = builder.finish()?;

    let mut new_url = target;
    new_url.set_path(req.get_path());
    new_url.set_query(req.get_url().query());

    req.set_url(new_url);

    Ok(req.send(&backend)?)
}
