# rust/

A Cargo workspace, separate from the rest of this Go repo, holding the
output of investigating Fastly Compute as an alternative deployment target
for `cmd/ingress-router`'s logic (`docs/design.md` §16). The main
Go-service architecture (§15) is unaffected — nothing here is wired into
`cmd/`, the Dockerfile, or the Go module.

- **[`token-format`](token-format/)** — a small library that decodes and
  validates this service's ES256 access tokens (the
  `go-tokenauth/claims.AccessTokenClaims` shape), tested against a token
  minted by the real Go AS. Portable, `wasm32-wasip1`-compatible, has no
  Fastly dependency at all.
- **[`fastly-ingress-sample`](fastly-ingress-sample/)** — a sample Fastly
  Compute service built on `token-format`, reimplementing
  `cmd/ingress-router`'s verify-then-route logic. See its README for what
  is and isn't actually verified — no `fastly` CLI or account was
  available in the environment this was built in.

```sh
cd rust
cargo test -p token-format                              # native
cargo build -p token-format --target wasm32-wasip1       # confirm WASM portability
cargo build -p fastly-ingress-sample --target wasm32-wasip1 --release
```

`wasm32-wasip1` needs `rustup target add wasm32-wasip1` if not already
installed. `fastly-ingress-sample` is deliberately excluded from the
workspace's `default-members`, so a plain `cargo build`/`cargo test` here
only touches `token-format`.
