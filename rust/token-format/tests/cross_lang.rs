//! Verifies this crate against a token minted by the real Go issuance path
//! (`internal/accesstoken.KeyManager.Issue`, the exact code `cmd/as` runs),
//! not a token constructed by this crate itself — that would only prove
//! self-consistency, not actual wire compatibility with go-tokenauth's
//! validator. Fixture regenerated via `go run ./tools/gen-fixture` (see
//! that file's doc comment); committed under `testdata/`.
//!
//! `now` is derived from the token's own `iat` rather than hardcoded, so
//! this test keeps passing regardless of when it's run rather than going
//! stale once the fixture's real-world `exp` passes.

use token_format::{validate, JwkSet, TokenError, ValidationOptions};

const TOKEN: &str = include_str!("../testdata/token.txt");
const JWKS_JSON: &str = include_str!("../testdata/jwks.json");

// Matches tools/gen-fixture/main.go's Issue() call exactly.
const ISSUER: &str = "https://as.example.org";
const AUDIENCE: &str = "siros-status-service";
const SUBJECT: &str = "issuer-abc";
const TENANT_ID: &str = "shard-a";
const TAC: &str = "iwr";

fn jwks() -> JwkSet {
    serde_json::from_str(JWKS_JSON).expect("fixture jwks.json should parse")
}

fn token() -> &'static str {
    TOKEN.trim()
}

/// Decodes the payload without any verification, purely to read `iat` as a
/// self-consistent "now" for the tests below — deliberately not using this
/// crate's own `validate()` for this, so a bug in `validate()` can't hide a
/// bad test setup.
fn fixture_iat() -> i64 {
    let payload_b64 = token()
        .split('.')
        .nth(1)
        .expect("token has a payload segment");
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .expect("payload is valid base64url");
    let v: serde_json::Value = serde_json::from_slice(&bytes).expect("payload is valid JSON");
    v["iat"].as_i64().expect("fixture token has an iat claim")
}

#[test]
fn valid_token_decodes_and_verifies() {
    let jwks = jwks();
    let mut opts = ValidationOptions::new(ISSUER, &[AUDIENCE]);
    opts.now = Some(fixture_iat());

    let claims = validate(token(), &jwks, &opts).expect("fixture token should validate");
    assert_eq!(claims.iss, ISSUER);
    assert_eq!(claims.sub, SUBJECT);
    assert!(claims.aud.contains(AUDIENCE));
    assert_eq!(claims.tenant_id, TENANT_ID);
    assert_eq!(claims.tac, TAC);
    assert!(!claims.jti.is_empty());
    assert_eq!(claims.exp, Some(fixture_iat() + 3600));
}

#[test]
fn wrong_issuer_rejected() {
    let jwks = jwks();
    let mut opts = ValidationOptions::new("https://not-the-as.example.org", &[AUDIENCE]);
    opts.now = Some(fixture_iat());

    match validate(token(), &jwks, &opts) {
        Err(TokenError::InvalidIssuer) => {}
        other => panic!("expected InvalidIssuer, got {other:?}"),
    }
}

#[test]
fn wrong_audience_rejected() {
    let jwks = jwks();
    let mut opts = ValidationOptions::new(ISSUER, &["some-other-service"]);
    opts.now = Some(fixture_iat());

    match validate(token(), &jwks, &opts) {
        Err(TokenError::InvalidAudience) => {}
        other => panic!("expected InvalidAudience, got {other:?}"),
    }
}

#[test]
fn unknown_kid_rejected() {
    let jwks: JwkSet = serde_json::from_str(r#"{"keys":[]}"#).unwrap();
    let mut opts = ValidationOptions::new(ISSUER, &[AUDIENCE]);
    opts.now = Some(fixture_iat());

    match validate(token(), &jwks, &opts) {
        Err(TokenError::UnknownKid(kid)) => assert_eq!(kid, "test-key-1"),
        other => panic!("expected UnknownKid, got {other:?}"),
    }
}

#[test]
fn expired_token_rejected() {
    let jwks = jwks();
    let mut opts = ValidationOptions::new(ISSUER, &[AUDIENCE]);
    // Well past exp (iat + 3600s) and past the default leeway.
    opts.now = Some(fixture_iat() + 3600 + 3600);

    match validate(token(), &jwks, &opts) {
        Err(TokenError::Expired) => {}
        other => panic!("expected Expired, got {other:?}"),
    }
}

#[test]
fn not_yet_valid_rejected() {
    let jwks = jwks();
    let mut opts = ValidationOptions::new(ISSUER, &[AUDIENCE]);
    opts.now = Some(fixture_iat() - 3600);

    match validate(token(), &jwks, &opts) {
        Err(TokenError::IssuedInFuture) => {}
        other => panic!("expected IssuedInFuture, got {other:?}"),
    }
}

#[test]
fn tampered_signature_rejected() {
    let jwks = jwks();
    let mut opts = ValidationOptions::new(ISSUER, &[AUDIENCE]);
    opts.now = Some(fixture_iat());

    let mut parts: Vec<&str> = token().split('.').collect();
    // Flip the last base64url character of the payload — still decodes as
    // valid base64 and (almost always) valid JSON-shaped bytes are not
    // required, since signature verification happens on the raw encoded
    // bytes before the payload is even parsed.
    let mut payload = parts[1].to_string();
    let last = payload.pop().unwrap();
    payload.push(if last == 'A' { 'B' } else { 'A' });
    parts[1] = &payload;
    let tampered = parts.join(".");

    match validate(&tampered, &jwks, &opts) {
        Err(TokenError::SignatureInvalid) => {}
        other => panic!("expected SignatureInvalid, got {other:?}"),
    }
}

#[test]
fn malformed_token_rejected() {
    let jwks = jwks();
    let opts = ValidationOptions::new(ISSUER, &[AUDIENCE]);
    match validate("not-a-jwt", &jwks, &opts) {
        Err(TokenError::Malformed(_)) => {}
        other => panic!("expected Malformed, got {other:?}"),
    }
}
