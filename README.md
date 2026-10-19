# pg-oauth-rs

Log in to PostgreSQL with your company login (Keycloak, Okta, Entra ID) instead of a database password.

pg-oauth-rs is an **OAuth token validator module for PostgreSQL 18**, written in Rust with [pgrx](https://github.com/pgcentralfoundation/pgrx).

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Status: pre-alpha](https://img.shields.io/badge/status-pre--alpha-orange.svg)
![PostgreSQL 18](https://img.shields.io/badge/PostgreSQL-18-336791.svg)

> **Status: pre-alpha.** v0.2.0 is released and tested end to end against Keycloak. It has not been used
> in production yet.

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
4. It tells PostgreSQL who the user is (the `sub` claim by default, `oid` for Entra ID).
5. PostgreSQL decides which role that person may use, with an exact match or a `pg_ident.conf` map.

## Quick start (demo)

You need Docker. This starts Keycloak and PostgreSQL 18 with pg-oauth-rs, then logs you in as `alice`:

```sh
docker compose -f demo/compose.yaml up -d --build
docker compose -f demo/compose.yaml run --rm psql \
  "host=postgres dbname=postgres user=alice oauth_issuer=https://keycloak.localtest.me:8443/realms/demo oauth_client_id=psql"
```

1. `psql` prints a link and a code.
2. Open the link in your browser and accept the certificate warning (the demo makes its own CA).
3. Enter the code, log in as `alice` / `alice` (demo-only password), approve.
4. `psql` connects as `alice`. No database password was used.

If `keycloak.localtest.me` does not resolve, add `127.0.0.1 keycloak.localtest.me` to `/etc/hosts`.
Details, accounts and reset steps: [demo/README.md](demo/README.md).

## Install

You need PostgreSQL 18. Pick one:

- **Docker image:** PostgreSQL 18 with the module already installed, for `linux/amd64` and `linux/arm64`.

  ```sh
  docker pull ghcr.io/irfanfaraaz/pg-oauth-rs:0.2.0
  ```

- **Tarball** for Debian 12+ or Ubuntu 24.04+ with the PGDG `postgresql-18` package. Download it from
  [Releases](https://github.com/irfanfaraaz/pg-oauth-rs/releases), check it, and unpack it into `/`:

  ```sh
  sha256sum -c --ignore-missing SHA256SUMS
  gh attestation verify pg_oauth_rs-0.2.0-pg18-linux-amd64.tar.gz --repo irfanfaraaz/pg-oauth-rs
  sudo tar -C / -xzf pg_oauth_rs-0.2.0-pg18-linux-amd64.tar.gz
  ```

  The module needs libcurl (`libcurl4` or `libcurl4t64`). Then set it up as in [Configuration](#configuration)
  and restart PostgreSQL.

- **From source:** see [CONTRIBUTING.md](CONTRIBUTING.md#development-setup).

## What v0.1 does

- Verifies RS256 and ES256 JWT access tokens.
- Checks `iss`, `aud`, `exp` and `nbf`, with 60 s clock leeway.
- Caches the IdP's keys in shared memory, so they are fetched once for all connections.
- Fetches keys over HTTPS only, with a timeout, and never blocks a cancel or shutdown.
- Fails closed: any error means "no".
- Never writes a token to the log.
- One-command Docker Compose demo with Keycloak.
- 20 end-to-end login tests against the demo, run in CI on every pull request.

See [CHANGELOG.md](CHANGELOG.md) for the full list.

## Configuration

`postgresql.conf`:

```ini
oauth_validator_libraries = 'pg_oauth_rs'
pg_oauth_rs.audience = 'postgres'
pg_oauth_rs.jwks_uri = 'https://login.example.com/realms/acme/protocol/openid-connect/certs'
# optional
pg_oauth_rs.provider = 'generic'          # or entra, okta, keycloak
pg_oauth_rs.identity_claim = ''           # empty = the provider's claim ('sub' for generic); or 'email' (then email_verified must be true)
pg_oauth_rs.clock_skew_leeway = '60s'
pg_oauth_rs.jwks_timeout = '5s'
pg_oauth_rs.jwks_refetch_interval = '60s' # at most one JWKS fetch per interval, for all connections
pg_oauth_rs.jwks_max_age = '1h'           # refresh cached keys older than this
pg_oauth_rs.jwks_max_stale = '24h'        # if the IdP is down, keep using cached keys up to this age
```

Every setting can be changed with a reload (`SELECT pg_reload_conf()`); no restart is needed.

`pg_hba.conf`:

```
host  all  all  0.0.0.0/0  oauth  issuer="https://login.example.com/realms/acme" scope="openid" map=oauth
```

`pg_ident.conf`:

```
oauth  /^(.*)@example\.com$  \1
```

The issuer is set only in `pg_hba.conf`. pg-oauth-rs reads it from there.

With a provider (`entra`, `okta` or `keycloak`), two settings can stay empty:

- An empty `jwks_uri` is built from the issuer. Set it and pg-oauth-rs uses your value as is.
- An empty `identity_claim` uses the provider's claim: `oid` for Entra, `sub` for the others.

With `generic` (the default), nothing changes: `jwks_uri` is required and the identity is `sub`.
`audience` is required for every provider. See [Providers](#providers).

pg-oauth-rs is loaded only when someone logs in, so Postgres cannot check `pg_oauth_rs.provider` at reload.
If you misspell it, every login is refused and logged as
`pg_oauth_rs: not configured: pg_oauth_rs.provider has an unknown value; use generic, entra, okta or keycloak`,
next to Postgres's own WARNING (`invalid value for parameter "pg_oauth_rs.provider"`). After you change it,
look at the server log. To check it yourself, run this as a superuser:

```sql
LOAD 'pg_oauth_rs';
SHOW pg_oauth_rs.provider;
```

## Providers

A provider setting tells pg-oauth-rs what your IdP's issuer looks like. It then builds the key (JWKS) URL
for you and picks the right identity claim. If the issuer in `pg_hba.conf` has the wrong shape, pg-oauth-rs
refuses the login and logs `pg_oauth_rs: not configured: ...` with the shape it expected.

### Entra ID

Use a single-tenant app registration. Multi-tenant issuers (`common`, `organizations`) do not work.

In the Entra admin center:

1. Create an app registration for your tenant only.
2. Under *Expose an API*, add a scope (for example `postgres`).
3. In the app manifest, set `requestedAccessTokenVersion` to `2`.
4. Under *Authentication*, turn on *Allow public client flows*. `psql` needs this for device login.

`postgresql.conf`:

```ini
pg_oauth_rs.provider = 'entra'
pg_oauth_rs.audience = '<app-client-id>'
```

`pg_hba.conf`:

```
host  all  all  0.0.0.0/0  oauth  issuer="https://login.microsoftonline.com/<tenant-id>/v2.0" scope="openid profile api://<app-id>/<scope>" map=oauth
```

- `<tenant-id>` is the tenant ID, a GUID. The domain name (for example `contoso.onmicrosoft.com`) is refused.
- The scope must include `profile`. Without it, Entra leaves `tid`, `oid` and `preferred_username` out of the token, and every login is refused.
- `audience` is the app's client ID.
- pg-oauth-rs checks that the token's `tid` is the tenant in the issuer.
- A v1 token is refused with a hint to set `requestedAccessTokenVersion` to `2`.

The identity is the user's `oid` (object ID). It never changes, so it is safe to trust. Add one line per
person to `pg_ident.conf`:

```
oauth  <object-id>  alice
```

Find the object ID in the Entra admin center: *Users*, pick the user, then the *Overview* page.

To use names like `alice@contoso.com` instead, set `pg_oauth_rs.identity_claim = 'preferred_username'`. Then
one regex line can map your whole company. The risk: an Entra admin can rename a user. If a name is later
reused, the new owner gets the old person's database role. Use this only if you accept that.

Do not use `email` with Entra. Entra does not verify it, and pg-oauth-rs refuses it without `email_verified`.

### Okta

Use a custom authorization server. The built-in `default` server works. The Okta org authorization server
(an issuer without `/oauth2/...`) is not supported.

In the Okta admin console:

1. Add a custom scope to the authorization server.
2. Add an access policy rule that allows the *Device Authorization* grant.
3. Create a native app and turn on the *Device Authorization* grant.

`postgresql.conf`:

```ini
pg_oauth_rs.provider = 'okta'
pg_oauth_rs.audience = 'api://default'   # the audience of your authorization server
```

`pg_hba.conf`:

```
host  all  all  0.0.0.0/0  oauth  issuer="https://<org>.okta.com/oauth2/default" scope="openid <your-scope>" map=oauth
```

- `audience` is your authorization server's audience. For `default`, it is `api://default`.
- The identity is `sub`, which is the Okta login. The risk: an Okta admin can change a user's login. If a
  login is later reused, the new owner gets the old person's database role.
- Okta access tokens usually carry no `email` claim, so `identity_claim = 'email'` does not work with Okta.

### Keycloak

Set the issuer to `https://<host>/realms/<realm>`. This is the issuer shape the demo uses.

`postgresql.conf`:

```ini
pg_oauth_rs.provider = 'keycloak'
pg_oauth_rs.audience = 'postgres'
```

`pg_hba.conf`:

```
host  all  all  0.0.0.0/0  oauth  issuer="https://<host>/realms/<realm>" scope="openid" map=oauth
```

The identity is `sub`. If Keycloak runs under a path prefix, the issuer is `https://<host>/<prefix>/realms/<realm>`.

### Why not Google

Google is not supported, for two reasons:

- Google access tokens are opaque. They are not JWTs, so pg-oauth-rs cannot check them offline.
- Google's device login only allows the `openid`, `email` and `profile` scopes. A token cannot say
  "this user allowed access to Postgres". The libpq author calls a login like this stealable: any other
  "Log in with Google" site could use the same shared client ID to get a token that your database accepts.
  See [the pgsql-hackers thread](https://www.mail-archive.com/pgsql-hackers@lists.postgresql.org/msg207205.html).

Google may come back if opaque-token support lands and a safe client flow exists (see the Roadmap).

## Who this is for

- People who connect **straight to the database** with `psql`: developers, DBAs, analysts.
- Not the end users of an app that stores data in PostgreSQL. The app keeps its own database account.
- Not scripts or CI jobs yet. They cannot click a browser link.
- GUI tools (DBeaver, pgAdmin) do not support PostgreSQL OAuth yet.
- libpq's built-in device flow does not work on Windows.

## Roadmap

- Token introspection for opaque tokens (RFC 7662), and Google if a safe client flow exists.
- Group claims mapped to many roles.
- PostgreSQL 19 support (log-only failure details, per-line `pg_hba.conf` options).
- Machine logins for scripts and CI.
- Provider presets for Auth0.
- Packages: GitHub Releases, PGXN, Debian/RPM, Docker image.

## Security

Please do not open a public issue for a security problem. See [SECURITY.md](SECURITY.md).

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md).
For questions, see [SUPPORT.md](SUPPORT.md).

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

Contributions are accepted under the same license, as described in section 5 of the Apache License.
