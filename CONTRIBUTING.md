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

- Rust, pinned in `rust-toolchain.toml` (rustup installs it for you).
- [`cargo-pgrx`](https://github.com/pgcentralfoundation/pgrx) at the version in `Cargo.toml`.
- PostgreSQL 18 with development headers, plus libcurl.
- Docker and Docker Compose for the demo and integration tests.

The Linux Docker build is the reference build. macOS works for development, best effort.

One-time setup:

```sh
cargo install --locked cargo-pgrx --version 0.19.3
cargo pgrx init --pg18 download --configure-flag=--without-icu   # builds PostgreSQL 18 under ~/.pgrx
# or reuse an installed server: cargo pgrx init --pg18 /path/to/pg_config
```

`build.rs` finds `pg_config` through `PGRX_PG_CONFIG_PATH`, then `PG_CONFIG`, then `~/.pgrx/config.toml`,
then `PATH`. After `cargo pgrx init` nothing else needs setting.

Everyday commands (CI runs the same ones):

```sh
cargo fmt --all -- --check                                    # formatting
cargo clippy --all-targets --features pg18 -- -D warnings     # lint
cargo test --lib --features pg18                              # unit tests, no server
cargo pgrx test pg18                                          # tests inside a pgrx-managed PostgreSQL 18
bash demo/run-itests.sh                                       # integration tests: Keycloak + PostgreSQL 18 in Docker
cargo deny check                                              # licenses, advisories, bans, sources
```

`cargo deny` needs [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny) (`cargo install --locked cargo-deny`).
See [`demo/README.md`](demo/README.md) for the demo stack.

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

## Releasing (maintainers)

1. Set `version` in `Cargo.toml` and run `cargo check` to update `Cargo.lock`.
2. In `CHANGELOG.md`, move the **Unreleased** entries under `## [X.Y.Z] - YYYY-MM-DD` and update the
   links at the bottom. Also set `version` and `date-released` in `CITATION.cff`.
3. Merge that to `main` through a pull request. Its CI runs the release build as a dry run.
4. Tag `main` and push the tag: `git tag -a vX.Y.Z -m vX.Y.Z && git push origin vX.Y.Z`.

The `Release` workflow then checks that the tag matches `Cargo.toml` and the CHANGELOG, builds the
tarballs and the multi-arch image, attests them, and publishes the GitHub Release with the CHANGELOG
section as its notes.

## License of contributions

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work
by you, as defined in the Apache-2.0 license, shall be dual licensed under MIT OR Apache-2.0, without any
additional terms or conditions.
