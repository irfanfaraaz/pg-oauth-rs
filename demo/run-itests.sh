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

if [ "$status" -ne 0 ]; then
    echo "integration tests failed (exit $status); server logs follow" >&2
    $compose logs postgres keycloak
fi
exit "$status"
