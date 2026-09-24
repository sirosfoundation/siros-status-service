# token-format

Decodes and validates the ES256 access tokens minted by
`internal/accesstoken.KeyManager` (this service's own Authorization
Server, `cmd/as` — see `docs/design.md` §15.2/§15.3), matching what
[`go-tokenauth`](https://github.com/sirosfoundation/go-tokenauth)'s
`validator.Validator` checks: signature, `iss`, `aud` (intersection
against an accepted set), and `exp`/`nbf`/`iat` with leeway.

This is not a general-purpose JWT library — it only implements the one
algorithm and claim shape this service's AS actually issues (`ES256`,
`go-tokenauth/claims.AccessTokenClaims`). It also does not fetch a JWKS
itself: callers supply an already-fetched [`JwkSet`], which is what makes
this portable to `wasm32-wasip1` (see `../fastly-ingress-sample`) — JWKS
fetching/caching is inherently platform-specific, verifying a token
against a key set already in hand is not.

```rust
use token_format::{validate, JwkSet, ValidationOptions};

let jwks: JwkSet = serde_json::from_str(jwks_json)?;
let opts = ValidationOptions::new("https://as.example.org", &["siros-status-service"]);
let claims = validate(&token, &jwks, &opts)?;
// claims.tenant_id, claims.tac, claims.sub, ...
```

## Testing

`cargo test` runs `tests/cross_lang.rs` against a token minted by the real
Go issuance path (`tools/gen-fixture` at the repo root, using
`internal/accesstoken.KeyManager.Issue` directly — the exact code `cmd/as`
runs), not a token this crate constructed itself. That's a materially
stronger check: it proves wire compatibility with `go-tokenauth`, not just
internal self-consistency. Regenerate the fixture (`go run
./tools/gen-fixture` from the repo root) whenever `AccessTokenClaims`'
shape changes.

```sh
cargo test                              # native target
cargo build --target wasm32-wasip1      # confirm it still builds for Fastly Compute
```
