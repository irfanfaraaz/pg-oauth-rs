#!/bin/sh
# Builds pg_oauth_rs inside a Debian-based postgres:18 image (the official Docker image).
# Used by demo/Dockerfile.postgres (the demo and the release image) and the release tarballs.
# Run from the repository root.
#   build-module.sh deps          build tools, PG18 headers, the pinned Rust toolchain, cargo-pgrx
#   build-module.sh build <dir>   build the module into <dir> (usr/lib/... and usr/share/...)
set -eux

export RUSTUP_HOME="${RUSTUP_HOME:-/usr/local/rustup}"
export CARGO_HOME="${CARGO_HOME:-/usr/local/cargo}"
export PATH="$CARGO_HOME/bin:$PATH"
PG_CONFIG="/usr/lib/postgresql/${PG_MAJOR}/bin/pg_config"

case "${1:-}" in
deps)
    apt-get update
    # libicu-dev, libkrb5-dev: the PG18 server headers include unicode/ucol.h and gssapi/gssapi.h
    # (bookworm's server-dev package does not pull them in).
    apt-get install -y --no-install-recommends \
        build-essential pkg-config clang libclang-dev curl ca-certificates \
        "postgresql-server-dev-${PG_MAJOR}=${PG_VERSION}" \
        libcurl4-openssl-dev libssl-dev libicu-dev libkrb5-dev
    rm -rf /var/lib/apt/lists/*
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain none
    rustup toolchain install # the version in rust-toolchain.toml
    cargo install cargo-pgrx --version 0.19.3 --locked
    cargo pgrx init --pg18 "$PG_CONFIG"
    ;;
build)
    : "${2:?usage: $0 build <dir>}"
    cargo pgrx package --features pg18 --pg-config "$PG_CONFIG" --out-dir "$2"
    ;;
*)
    echo "usage: $0 deps | build <dir>" >&2
    exit 2
    ;;
esac
