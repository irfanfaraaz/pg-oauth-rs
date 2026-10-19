# pg-oauth-rs

Log in to PostgreSQL with your company login (Keycloak, Okta, Entra ID, Google) instead of a database password.

pg-oauth-rs is an **OAuth token validator module for PostgreSQL 18**, written in Rust with [pgrx](https://github.com/pgcentralfoundation/pgrx).

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
![Status: pre-alpha](https://img.shields.io/badge/status-pre--alpha-orange.svg)
![PostgreSQL 18](https://img.shields.io/badge/PostgreSQL-18-336791.svg)

> **Status: pre-alpha.** The design is done. The code is being written. Nothing here is ready for production yet.

## Why

- Every database user has a password. When someone leaves, an admin has to remember to remove it.
- Shared passwords end up in `.env` files and chat logs.
- Your company already has one login system (an identity provider, or IdP). The database sits outside it.

PostgreSQL 18 added the `oauth` login method. Postgres does not check the token itself. It asks a
**validator module**, and Postgres ships no production validator. pg-oauth-rs is that module.

## How it works

```
psql ──device login──▶ IdP            (you approve in a browser)
psql ◀──access token── IdP
psql ──token──▶ PostgreSQL ──validate──▶ pg-oauth-rs ──(keys, cached)──▶ IdP
                PostgreSQL ◀──yes + who──┘
                PostgreSQL maps "who" to a database role (pg_ident.conf)
```

1. `psql` (libpq 18) gets an access token from your IdP with the device-code flow.
2. PostgreSQL passes the token to pg-oauth-rs.
3. pg-oauth-rs checks the signature against the IdP's public keys (JWKS), then checks issuer, audience and expiry.
4. It tells PostgreSQL who the user is (the `sub` claim by default).
5. PostgreSQL decides which role that person may use, with an exact match or a `pg_ident.conf` map.

## Planned for v0.1

- Verifies RS256 and ES256 JWT access tokens.
- Checks `iss`, `aud`, `exp` and `nbf`, with 60 s clock leeway.
- Caches the IdP's keys in shared memory, so they are fetched once for all connections.
- Fetches keys over HTTPS only, with a timeout, and never blocks a cancel or shutdown.
- Fails closed: any error means "no".
- Never writes a token to the log.
- One-command Docker Compose demo with Keycloak.

See [CHANGELOG.md](CHANGELOG.md) for what has shipped.

## Configuration (planned)

`postgresql.conf`:

```ini
oauth_validator_libraries = 'pg_oauth_rs'
pg_oauth_rs.audience = 'postgres'
pg_oauth_rs.jwks_uri = 'https://login.example.com/realms/acme/protocol/openid-connect/certs'
# optional
pg_oauth_rs.identity_claim = 'sub'        # or 'email' (then email_verified must be true)
pg_oauth_rs.clock_skew_leeway = '60s'
pg_oauth_rs.jwks_timeout = '5s'
```

`pg_hba.conf`:

```
host  all  all  0.0.0.0/0  oauth  issuer="https://login.example.com/realms/acme" scope="openid" map=oauth
```

`pg_ident.conf`:

```
oauth  /^(.*)@example\.com$  \1
```

The issuer is set only in `pg_hba.conf`. pg-oauth-rs reads it from there.

## Who this is for

- People who connect **straight to the database** with `psql`: developers, DBAs, analysts.
- Not the end users of an app that stores data in PostgreSQL. The app keeps its own database account.
- Not scripts or CI jobs yet. They cannot click a browser link.
- GUI tools (DBeaver, pgAdmin) do not support PostgreSQL OAuth yet.
- libpq's built-in device flow does not work on Windows.

## Roadmap

- Token introspection for opaque tokens (RFC 7662).
- Group claims mapped to many roles.
- PostgreSQL 19 support (log-only failure details, per-line `pg_hba.conf` options).
- Machine logins for scripts and CI.
- Provider presets for Google, Okta, Entra ID, Auth0 and Keycloak.
- Packages: GitHub Releases, PGXN, Debian/RPM, Docker image.

## Security

Please do not open a public issue for a security problem. See [SECURITY.md](SECURITY.md).

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md).
For questions, see [SUPPORT.md](SUPPORT.md).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work
by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms
or conditions.
