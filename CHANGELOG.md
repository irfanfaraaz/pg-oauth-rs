# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-19

### Added

- Project files: README, licenses (MIT OR Apache-2.0), contributing guide, Code of Conduct,
  security policy, issue and pull request templates.
- PostgreSQL 18 OAuth validator module (`pg_oauth_rs`): verifies JWT access tokens against the
  IdP's JWKS, with a shared-memory JWKS cache and interruptible network fetches.
- Demo stack (`demo/`): Keycloak and PostgreSQL 18 with the module, run with Docker Compose.
- Integration tests (`tests/itest`) that run against the demo stack, started with
  `demo/run-itests.sh`.
- CI (GitHub Actions): rustfmt, clippy, unit and pgrx tests, integration tests, cargo-deny,
  and CodeQL for Rust and workflows. Every action is pinned to a commit SHA.
- Dependabot updates for the demo's Dockerfiles and the Compose file (Keycloak image).
- Release workflow: a version tag publishes Linux tarballs (amd64, arm64), `SHA256SUMS`, and the
  Docker image `ghcr.io/irfanfaraaz/pg-oauth-rs`, each with a signed build-provenance attestation.

[Unreleased]: https://github.com/irfanfaraaz/pg-oauth-rs/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/irfanfaraaz/pg-oauth-rs/releases/tag/v0.1.0
