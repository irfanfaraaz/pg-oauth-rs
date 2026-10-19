# Security policy

pg-oauth-rs decides who may log in to a database. We treat security reports as the top priority.

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request.**

Report it privately through GitHub:
[Report a vulnerability](https://github.com/irfanfaraaz/pg-oauth-rs/security/advisories/new).

Please include:

- What an attacker can do, and under which configuration.
- Steps to reproduce, or a proof of concept.
- Affected versions or commits.

Do not include real tokens or credentials. Use test values.

## What to expect

- We confirm we got the report within 7 days.
- We share our assessment and a plan within 14 days.
- We agree a disclosure date with you, normally within 90 days.
- We credit you in the advisory, unless you ask us not to.

## Supported versions

pg-oauth-rs is pre-alpha. Fixes go to `main` and ship in the next release of the latest line.

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |
| `main`  | Yes       |

## In scope

- A token that should be refused is accepted (signature, issuer, audience, expiry, algorithm checks).
- Any part of a token written to a log.
- A crash or hang of a PostgreSQL backend caused by a login attempt.
- Bypassing the HTTPS or certificate checks on the key fetch.

## Out of scope

- Problems in PostgreSQL, libpq or your identity provider. Please report those upstream.
- Insecure demo settings in the Docker Compose demo, which is for local use only.
