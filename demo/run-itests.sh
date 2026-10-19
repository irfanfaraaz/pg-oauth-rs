#!/bin/sh
# Runs the integration tests (tests/itest) against the demo stack, from any directory.
# Exits with the tests' exit code; prints the Postgres and Keycloak logs when they fail.
set -u

cd "$(dirname "$0")/.."
compose="docker compose -f demo/compose.yaml"

# `up --abort-on-container-exit` does not fit: the one-shot `certs` service exits by design.
if ! $compose up -d --build --wait keycloak postgres; then
    $compose logs postgres keycloak
    exit 1
fi

$compose --profile test run --rm --build itest
status=$?

# The tests change settings with ALTER SYSTEM. Drop them all, pass or fail, so the demo runs on
# demo/postgres/postgresql.conf again. Separate -c commands: ALTER SYSTEM cannot run in a transaction.
$compose exec -T postgres psql -U postgres -q \
    -c "ALTER SYSTEM RESET ALL" -c "SELECT pg_reload_conf()" >/dev/null

if [ "$status" -ne 0 ]; then
    echo "integration tests failed (exit $status); server logs follow" >&2
    $compose logs postgres keycloak
fi
exit "$status"
