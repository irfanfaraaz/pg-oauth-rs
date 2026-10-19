# pg-oauth-rs demo

Keycloak and PostgreSQL 18 with pg-oauth-rs, in Docker Compose. You log in to Postgres as `alice`
with the OAuth device flow: `psql` shows a link and a code, you approve in your browser, you are in.

**Demo only.** Every password, key and certificate here is public or throwaway.

## Run it

From the repository root:

```sh
docker compose -f demo/compose.yaml up -d --build
docker compose -f demo/compose.yaml run --rm psql \
  "host=postgres dbname=postgres user=alice oauth_issuer=https://keycloak.localtest.me:8443/realms/demo oauth_client_id=psql"
```

1. `psql` prints a URL (`https://keycloak.localtest.me:8443/realms/demo/device`) and a code.
2. Open the URL in your browser. It warns about the certificate (see below).
3. Enter the code. Log in as `alice`, password `alice`. Approve.
4. `psql` connects. `SELECT current_user;` returns `alice`.

The first `--build` compiles the module and takes several minutes.

## What runs

| Service | What it does |
|---|---|
| `certs` | One-shot. Runs `make-certs.sh`: a demo CA and a Keycloak certificate in `demo/certs/` (git-ignored). Skips if they exist. |
| `keycloak` | Keycloak on `https://keycloak.localtest.me:8443`, HTTPS only, realm `demo` imported from `keycloak/realm-demo.json`. |
| `postgres` | PostgreSQL 18 with pg-oauth-rs, config from `postgres/`, demo CA trusted. Not published to the host. |
| `psql` | Profile `cli`. The same image, used as a client: libpq 18 with the OAuth device flow (`libpq-oauth`). |
| `itest` | Profile `test`. Runs the integration tests (`tests/itest`). See below. |

## Accounts (demo only)

| Who | Login | Notes |
|---|---|---|
| alice | Keycloak `alice` / `alice` | `alice@example.com`, verified. Maps to role `alice`. |
| bob | Keycloak `bob` / `bob` | `bob@other.example`. Role `bob` exists, but no map line matches, so Postgres refuses him. |
| Keycloak admin | `admin` / `admin` | `https://keycloak.localtest.me:8443/admin/` |
| Postgres admin | `postgres` / `postgres` | Password login, for admin work and the integration tests. |

Keycloak clients: `psql` (public, device flow only) and `itest` (public, password grant, test-only).
Both add `postgres` to the access token's `aud`.

## How the pieces line up

- **One issuer everywhere:** `https://keycloak.localtest.me:8443/realms/demo`.
  `localtest.me` resolves to `127.0.0.1` in public DNS, so your browser reaches the published port.
  Inside Compose, `keycloak.localtest.me` is a network alias of the `keycloak` service.
  So `iss` in every token matches the `issuer` in `pg_hba.conf`.
- **Postgres config** (`postgres/postgresql.conf`): `oauth_validator_libraries = 'pg_oauth_rs'`,
  audience `postgres`, `identity_claim = 'email'`, JWKS from Keycloak.
- **`pg_hba.conf`:** local socket trusted; `postgres` uses a password; everyone else uses `oauth`.
- **`pg_ident.conf`:** `alice@example.com` becomes role `alice`. Other domains match nothing.

## Certificate warning

Keycloak's certificate comes from the demo CA that `certs` just made, so your browser does not trust it.
Accept the warning for this demo, or import `demo/certs/ca.crt` into your browser.
Do not add it to your system trust store for longer than you need: its private key sits in `demo/certs/`.

The `postgres` and `psql` containers add the demo CA to their own trust store at start. No insecure
switch is used anywhere.

## If `keycloak.localtest.me` does not resolve

Some DNS resolvers and routers block public names that point to `127.0.0.1`. Add this line to
`/etc/hosts`:

```
127.0.0.1 keycloak.localtest.me
```

## Reset

```sh
docker compose -f demo/compose.yaml down -v   # drops the database; init scripts run again next time
rm -f demo/certs/*.crt demo/certs/*.key        # new CA and certificate next time
```

## Integration tests

From the repository root:

```sh
demo/run-itests.sh
```

It starts Keycloak and Postgres, builds the `itest` image, runs every test once, and exits with the
tests' exit code. On failure it prints the Postgres and Keycloak logs. The first run compiles the
module and the tests and takes several minutes.

- **What they do:** log in through libpq with real tokens (Keycloak password grant, client `itest`)
  and forged ones (signed with the test key below), one test per accept or refuse case.
- **How the token gets in:** a libpq auth-data hook (`PQsetAuthDataHook`) hands libpq the token, so
  no browser is needed.
- **They change the stack while they run:** `ALTER SYSTEM` on Postgres, a rotated key and a disabled
  user in Keycloak, and Keycloak stopped and started. Every change is undone when its test ends.
- **The `itest` container mounts `/var/run/docker.sock`,** so it can stop Keycloak and read the
  Postgres log. That gives it control of your Docker daemon. Demo and test use only.
- **Serial on purpose:** the tests share one Postgres, one Keycloak and one JWKS cache.

## Test key

The realm imports a fixed RSA key (`tests/itest/keys/itest-rsa.pem`) and signs tokens with it.
The integration tests hold its private half to forge tokens. Its private key is public, so this realm
must never protect anything real.
