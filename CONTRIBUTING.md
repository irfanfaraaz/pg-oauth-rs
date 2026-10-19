# Contributing to pg-oauth-rs

Thanks for helping. This guide says how to report problems, suggest changes and send code.

By taking part you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Security problems

Do not open a public issue. Follow [SECURITY.md](SECURITY.md).

## Reporting a bug

Open an issue with the **Bug report** form. Include:

- PostgreSQL version and OS.
- pg-oauth-rs version or commit.
- Your IdP (Keycloak, Okta, Entra ID, ...).
- The relevant `pg_hba.conf` line and `pg_oauth_rs.*` settings.
- Server log lines around the failed login.

**Never paste a token**, not even an expired one. Remove secrets from logs and configs.

## Suggesting a feature

Open an issue with the **Feature request** form first. Say what problem it solves. Agree on the approach
before you write a large change.

## Development setup

You need:

- Rust (stable, see `rust-toolchain.toml` once the code lands).
- [`cargo-pgrx`](https://github.com/pgcentralfoundation/pgrx) at the version in `Cargo.toml`.
- PostgreSQL 18 with development headers, plus libcurl.
- Docker and Docker Compose for the demo and integration tests.

The Linux Docker build is the reference build. macOS works for development, best effort.

Exact commands will be listed here when the first code lands.

## Rules for code

- **No panics across the FFI line.** Code that runs inside PostgreSQL must not use `unwrap`, `expect`,
  `panic!` or unchecked indexing. Clippy enforces this.
- **Fail closed.** Any error means the login is refused.
- **Never log a token** or any part of one.
- **Stay interruptible.** Network waits go through PostgreSQL's latch, so a cancel or shutdown stops them.
- Add or update tests for every behaviour change, including the "refuse" cases.
- Run `cargo fmt` and `cargo clippy` before you push.

## Pull requests

1. Fork the repo and make a branch from `main`.
2. Keep the change focused on one thing.
3. Fill in the pull request template.
4. Update `CHANGELOG.md` under **Unreleased** for user-visible changes.
5. Make sure CI passes.

## Commit messages

Use a short imperative subject line (`Add JWKS cache`, `Fix leeway on nbf`). Explain the why in the body
when it is not obvious.

## License of contributions

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work
by you, as defined in the Apache-2.0 license, shall be dual licensed under MIT OR Apache-2.0, without any
additional terms or conditions.
