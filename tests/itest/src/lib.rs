//! Helpers for the integration tests in `tests/login.rs`.
//!
//! They run inside the compose `itest` container (`demo/Dockerfile.itest`), on the same network as
//! the demo Keycloak and Postgres. Every name and password here is from `demo/` and demo-only.

pub mod libpq;
pub mod stack;
pub mod tokens;

use ureq::tls::{RootCerts, TlsConfig};

/// The issuer in every token and in `demo/postgres/pg_hba.conf`.
pub const ISSUER: &str = "https://keycloak.localtest.me:8443/realms/demo";
/// The JWKS URL from `demo/postgres/postgresql.conf`.
pub const JWKS_URI: &str =
    "https://keycloak.localtest.me:8443/realms/demo/protocol/openid-connect/certs";
/// Password login as the Postgres superuser (`POSTGRES_PASSWORD` in `demo/compose.yaml`).
pub const ADMIN_CONNINFO: &str = "host=postgres dbname=postgres user=postgres password=postgres";

/// libpq connection string for an OAuth login as `user`. libpq requires `oauth_issuer` and
/// `oauth_client_id` even when, as here, our auth-data hook hands it the token directly.
pub fn login_conninfo(user: &str) -> String {
    format!(
        "host=postgres dbname=postgres user={user} oauth_issuer={ISSUER} \
         oauth_client_id=itest connect_timeout=10"
    )
}

/// A blocking HTTP client that trusts the system CA store (the container adds the demo CA to it)
/// and returns 4xx/5xx responses instead of turning them into errors.
pub fn http() -> ureq::Agent {
    ureq::Agent::config_builder()
        .tls_config(TlsConfig::builder().root_certs(RootCerts::PlatformVerifier).build())
        .http_status_as_error(false)
        .build()
        .new_agent()
}
