//! The `pg_oauth_rs.*` GUC settings.

use std::ffi::{CStr, CString};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use pgrx::guc::{GucContext, GucFlags, GucRegistry, GucSetting, PostgresGucEnum};
use pgrx::pg_sys;

use crate::provider::Provider;

/// One week, the cap for every time setting.
const MAX_SECS: i32 = 604_800;

static AUDIENCE: GucSetting<Option<CString>> = GucSetting::<Option<CString>>::new(None);
static JWKS_URI: GucSetting<Option<CString>> = GucSetting::<Option<CString>>::new(None);
static IDENTITY_CLAIM: GucSetting<Option<CString>> = GucSetting::<Option<CString>>::new(None);
static CLOCK_SKEW_LEEWAY: GucSetting<i32> = GucSetting::<i32>::new(60);
static JWKS_TIMEOUT: GucSetting<i32> = GucSetting::<i32>::new(5);
static JWKS_REFETCH_INTERVAL: GucSetting<i32> = GucSetting::<i32>::new(60);
static JWKS_MAX_AGE: GucSetting<i32> = GucSetting::<i32>::new(3600);
static JWKS_MAX_STALE: GucSetting<i32> = GucSetting::<i32>::new(86400);
static PROVIDER: GucSetting<ProviderGuc> = GucSetting::<ProviderGuc>::new(ProviderGuc::Generic);
/// The config files gave `pg_oauth_rs.provider` a value that is not a preset.
static PROVIDER_UNKNOWN: AtomicBool = AtomicBool::new(false);

/// `pg_oauth_rs.provider` values, as Postgres shows them.
#[derive(PostgresGucEnum, Clone, Copy, PartialEq, Eq, Debug)]
enum ProviderGuc {
    #[name = c"generic"]
    Generic,
    #[name = c"entra"]
    Entra,
    #[name = c"okta"]
    Okta,
    #[name = c"keycloak"]
    Keycloak,
}

/// Snapshot of all `pg_oauth_rs.*` settings.
#[derive(Debug, Clone)]
pub struct Settings {
    pub audience: String,
    pub jwks_uri: String,
    pub identity_claim: String,
    pub leeway: Duration,
    pub jwks_timeout: Duration,
    pub refetch_interval: Duration,
    pub max_age: Duration,
    pub max_stale: Duration,
    pub provider: Provider,
    pub provider_unknown: bool,
}

/// Whether a raw `pg_oauth_rs.provider` value names a preset. Empty counts as not set.
fn provider_value_known(raw: &str) -> bool {
    raw.is_empty()
        || ["generic", "entra", "okta", "keycloak"].iter().any(|l| raw.eq_ignore_ascii_case(l))
}

fn string_guc(
    name: &'static CStr,
    short: &'static CStr,
    setting: &'static GucSetting<Option<CString>>,
) {
    GucRegistry::define_string_guc(
        name,
        short,
        c"",
        setting,
        GucContext::Sighup,
        GucFlags::default(),
    );
}

fn secs_guc(
    name: &'static CStr,
    short: &'static CStr,
    setting: &'static GucSetting<i32>,
    min: i32,
) {
    GucRegistry::define_int_guc(
        name,
        short,
        c"",
        setting,
        min,
        MAX_SECS,
        GucContext::Sighup,
        GucFlags::UNIT_S,
    );
}

pub fn register() {
    string_guc(
        c"pg_oauth_rs.audience",
        c"Audience (aud) that access tokens must carry.",
        &AUDIENCE,
    );
    string_guc(
        c"pg_oauth_rs.jwks_uri",
        c"HTTPS URL of the identity provider's JWKS document.",
        &JWKS_URI,
    );
    string_guc(
        c"pg_oauth_rs.identity_claim",
        c"Token claim that holds the authenticated identity; empty uses the provider's default.",
        &IDENTITY_CLAIM,
    );
    secs_guc(
        c"pg_oauth_rs.clock_skew_leeway",
        c"Clock skew tolerated when checking exp and nbf.",
        &CLOCK_SKEW_LEEWAY,
        0,
    );
    secs_guc(
        c"pg_oauth_rs.jwks_timeout",
        c"Overall timeout for fetching the JWKS.",
        &JWKS_TIMEOUT,
        1,
    );
    secs_guc(
        c"pg_oauth_rs.jwks_refetch_interval",
        c"Minimum time between JWKS fetch attempts.",
        &JWKS_REFETCH_INTERVAL,
        0,
    );
    secs_guc(
        c"pg_oauth_rs.jwks_max_age",
        c"Age after which the cached JWKS is refreshed.",
        &JWKS_MAX_AGE,
        0,
    );
    secs_guc(
        c"pg_oauth_rs.jwks_max_stale",
        c"Age after which the cached JWKS is no longer used.",
        &JWKS_MAX_STALE,
        0,
    );
    // Postgres replaces an unknown value with the default when the enum is defined, so read
    // the unchecked placeholder from the config files first.
    // SAFETY: the name is a valid C string; with missing_ok the result is NULL or a valid
    // C string owned by the GUC machinery, copied before anything can change it.
    let raw = unsafe { pg_sys::GetConfigOption(c"pg_oauth_rs.provider".as_ptr(), true, false) };
    if !raw.is_null() {
        // SAFETY: non-NULL result of GetConfigOption, a NUL-terminated string.
        let raw = unsafe { CStr::from_ptr(raw) }.to_string_lossy();
        PROVIDER_UNKNOWN.store(!provider_value_known(&raw), Ordering::Relaxed);
    }
    GucRegistry::define_enum_guc(
        c"pg_oauth_rs.provider",
        c"Identity provider preset: generic, entra, okta or keycloak.",
        c"",
        &PROVIDER,
        GucContext::Sighup,
        GucFlags::default(),
    );
}

fn string_value(setting: &GucSetting<Option<CString>>, default: &str) -> String {
    setting.get().map_or_else(|| default.to_owned(), |c| c.to_string_lossy().into_owned())
}

fn secs(setting: &GucSetting<i32>) -> Duration {
    Duration::from_secs(u64::try_from(setting.get()).unwrap_or(0))
}

pub fn current() -> Settings {
    Settings {
        audience: string_value(&AUDIENCE, ""),
        jwks_uri: string_value(&JWKS_URI, ""),
        identity_claim: string_value(&IDENTITY_CLAIM, ""),
        leeway: secs(&CLOCK_SKEW_LEEWAY),
        jwks_timeout: secs(&JWKS_TIMEOUT),
        refetch_interval: secs(&JWKS_REFETCH_INTERVAL),
        max_age: secs(&JWKS_MAX_AGE),
        max_stale: secs(&JWKS_MAX_STALE),
        provider: match PROVIDER.get() {
            ProviderGuc::Generic => Provider::Generic,
            ProviderGuc::Entra => Provider::Entra,
            ProviderGuc::Okta => Provider::Okta,
            ProviderGuc::Keycloak => Provider::Keycloak,
        },
        provider_unknown: PROVIDER_UNKNOWN.load(Ordering::Relaxed),
    }
}

#[cfg(test)]
mod tests {
    use super::provider_value_known;

    #[test]
    fn known_provider_values() {
        for v in ["", "generic", "entra", "okta", "keycloak", "ENTRA"] {
            assert!(provider_value_known(v), "{v:?}");
        }
    }

    #[test]
    fn unknown_provider_values() {
        for v in ["entraid", "azure", " entra"] {
            assert!(!provider_value_known(v), "{v:?}");
        }
    }
}
