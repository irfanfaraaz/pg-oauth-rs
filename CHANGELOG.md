# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
