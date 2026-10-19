//! The `pg_oauth_rs.*` GUC settings.

use std::ffi::CString;
use std::time::Duration;

use pgrx::guc::{GucContext, GucFlags, GucRegistry, GucSetting};

/// One week, the cap for every time setting.
const MAX_SECS: i32 = 604_800;

static AUDIENCE: GucSetting<Option<CString>> = GucSetting::<Option<CString>>::new(None);
static JWKS_URI: GucSetting<Option<CString>> = GucSetting::<Option<CString>>::new(None);
static IDENTITY_CLAIM: GucSetting<Option<CString>> =
    GucSetting::<Option<CString>>::new(Some(c"sub"));
static CLOCK_SKEW_LEEWAY: GucSetting<i32> = GucSetting::<i32>::new(60);
static JWKS_TIMEOUT: GucSetting<i32> = GucSetting::<i32>::new(5);
static JWKS_REFETCH_INTERVAL: GucSetting<i32> = GucSetting::<i32>::new(60);
static JWKS_MAX_AGE: GucSetting<i32> = GucSetting::<i32>::new(3600);
static JWKS_MAX_STALE: GucSetting<i32> = GucSetting::<i32>::new(86400);

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
}

fn string_guc(
    name: &'static std::ffi::CStr,
    short: &'static std::ffi::CStr,
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
    name: &'static std::ffi::CStr,
    short: &'static std::ffi::CStr,
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
        c"Token claim that holds the authenticated identity.",
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
}

fn string_value(setting: &GucSetting<Option<CString>>, default: &str) -> String {
    setting
        .get()
        .map_or_else(|| default.to_owned(), |c| c.to_string_lossy().into_owned())
}

fn secs(setting: &GucSetting<i32>) -> Duration {
    Duration::from_secs(u64::try_from(setting.get()).unwrap_or(0))
}

pub fn current() -> Settings {
    Settings {
        audience: string_value(&AUDIENCE, ""),
        jwks_uri: string_value(&JWKS_URI, ""),
        identity_claim: string_value(&IDENTITY_CLAIM, "sub"),
        leeway: secs(&CLOCK_SKEW_LEEWAY),
        jwks_timeout: secs(&JWKS_TIMEOUT),
        refetch_interval: secs(&JWKS_REFETCH_INTERVAL),
        max_age: secs(&JWKS_MAX_AGE),
        max_stale: secs(&JWKS_MAX_STALE),
    }
}
