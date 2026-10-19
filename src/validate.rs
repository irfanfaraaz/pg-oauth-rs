//! Glue that combines settings, cache, fetch and token checks into the authorization decision.

use std::ffi::{c_int, c_long, CStr};
use std::time::{Duration, Instant, SystemTime};

use jsonwebtoken::jwk::JwkSet;
use pgrx::pg_sys;

use crate::cache::{self, Plan, Snapshot};
use crate::provider;
use crate::settings::{self, Settings};
use crate::token::{self, CheckConfig};
use crate::{fetch, log, pg_oauth_rs_hba_issuer};

/// Outcome of checking one token.
pub enum Decision {
    /// The token is good; `authn_id` becomes the SYSTEM_USER.
    Allow { authn_id: String },
    /// The token is bad. `authn_id` is set only when the signature already passed.
    Deny { authn_id: Option<String> },
    /// We could not decide (not configured, no keys, internal error).
    Error,
}

/// Why the keys could not be loaded: a short reason for the log and the specifics.
type KeysError = (&'static str, String);

/// Longest `kid` put in a log line; the header is unverified, so it is attacker-sized.
const KID_LOG_CHARS: usize = 64;
/// How long one sleep lasts while waiting for another backend's fetch.
const WAIT_STEP_MS: c_long = 100;
/// How many times one login tries to claim a JWKS fetch before using its last plan.
const CLAIM_TRIES: usize = 3;

/// Decide one login. Logs every non-Allow outcome exactly once; never logs the token.
pub fn decide(token: &str, _role: &str) -> Decision {
    const BOTH_SET: &str = "pg_oauth_rs.audience and pg_oauth_rs.jwks_uri must both be set";
    let mut set = settings::current();
    if set.provider_unknown {
        return error(
            "not configured",
            "pg_oauth_rs.provider has an unknown value; use generic, entra, okta or keycloak",
        );
    }
    if set.audience.is_empty() {
        return error("not configured", BOTH_SET);
    }
    // The HBA line is only valid during authentication: checks that can fail without it go first.
    let Some(issuer) = hba_issuer() else {
        return error("internal error", "no issuer on the matched pg_hba.conf line");
    };
    let tenant = match apply_preset(&mut set, &issuer) {
        Ok(tenant) => tenant,
        Err(detail) => return error("not configured", &detail),
    };
    if set.jwks_uri.is_empty() {
        return error("not configured", BOTH_SET);
    }

    let kid = match token::header_kid(token) {
        Ok(kid) => kid,
        Err(refusal) => {
            log::refusal(refusal.log_reason(), &context(None, &issuer, None, None));
            return Decision::Deny { authn_id: None };
        }
    };

    let (keys, note) = match load_keys(&kid, &set) {
        Ok(loaded) => loaded,
        Err((reason, msg)) => {
            return error(reason, &format!("{msg}; {}", context(Some(&kid), &issuer, None, None)));
        }
    };

    let cfg = CheckConfig {
        issuer: &issuer,
        audience: &set.audience,
        identity_claim: &set.identity_claim,
        leeway_secs: set.leeway.as_secs(),
        entra_tenant: tenant.as_deref(),
    };
    match token::verify(token, &keys, &cfg) {
        Ok(authn_id) => Decision::Allow { authn_id },
        Err(refusal) => {
            let authn_id = refusal.authn_id().map(str::to_owned);
            let ctx = context(Some(&kid), &issuer, authn_id.as_deref(), note.as_deref());
            log::refusal(refusal.log_reason(), &ctx);
            Decision::Deny { authn_id }
        }
    }
}

/// Run `provider::resolve` and fill the settings left empty. Returns the Entra tenant.
/// `Err` is the "not configured" log detail.
fn apply_preset(set: &mut Settings, issuer: &str) -> Result<Option<String>, String> {
    let resolved = provider::resolve(set.provider, issuer)?;
    if set.jwks_uri.is_empty() {
        if let Some(uri) = resolved.jwks_uri {
            set.jwks_uri = uri;
        }
    }
    if set.identity_claim.is_empty() {
        resolved.identity_claim.clone_into(&mut set.identity_claim);
    }
    Ok(resolved.entra_tenant)
}

/// Log a "could not decide" reason and answer `Error`.
fn error(reason: &str, detail: &str) -> Decision {
    log::refusal(reason, detail);
    Decision::Error
}

/// Issuer of the matched HBA line; `None` when there is none (or it is empty).
fn hba_issuer() -> Option<String> {
    // SAFETY: the shim returns NULL or a NUL-terminated string that outlives this call.
    let p = unsafe { pg_oauth_rs_hba_issuer() };
    if p.is_null() {
        return None;
    }
    // SAFETY: non-NULL (checked above), NUL-terminated.
    let issuer = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
    (!issuer.is_empty()).then_some(issuer)
}

/// `kid`, issuer and (when known) `authn_id` for the log line. `{:?}` escapes control
/// characters, so an odd `kid` from the unverified header cannot forge extra log text.
fn context(kid: Option<&str>, issuer: &str, authn_id: Option<&str>, note: Option<&str>) -> String {
    let mut parts = Vec::new();
    if let Some(kid) = kid {
        let short: String = kid.chars().take(KID_LOG_CHARS).collect();
        let more = if short.len() < kid.len() { "…" } else { "" };
        parts.push(format!("kid={short:?}{more}"));
    }
    parts.push(format!("issuer={issuer:?}"));
    if let Some(id) = authn_id {
        parts.push(format!("authn_id={id:?}"));
    }
    if let Some(note) = note {
        parts.push(note.to_owned());
    }
    parts.join(" ")
}

fn has_kid(keys: &JwkSet, kid: &str) -> bool {
    keys.keys.iter().any(|k| k.common.key_id.as_deref() == Some(kid))
}

/// Get the JWKS to verify with, from the cache or a fetch. The second value is a note about a
/// failed refresh when stale-but-usable cached keys were used instead.
fn load_keys(kid: &str, set: &Settings) -> Result<(JwkSet, Option<String>), KeysError> {
    let mut view = look(kid, set)?;
    // Claim the attempt before fetching, so a failing IdP is not hammered by every backend. A lost
    // claim means another backend just claimed it: plan again with what it recorded.
    // shortcut: after CLAIM_TRIES lost claims the last plan is used as is; only reachable with
    // a near-zero jwks_refetch_interval under heavy contention.
    for _ in 0..CLAIM_TRIES {
        if view.plan == Plan::Refuse {
            view = wait_for_fetch(kid, set, view)?;
        }
        let claimed = view.plan == Plan::Fetch
            && cache::claim_attempt(&set.jwks_uri, &view.snap, view.now)
                .map_err(|e| ("internal error", format!("cache write failed: {e:?}")))?;
        if view.plan != Plan::Fetch || claimed {
            break;
        }
        view = look(kid, set)?;
    }
    let View { now, snap, cached, plan } = view;

    match plan {
        Plan::UseCache | Plan::UseCacheNoFetch => cached
            .map(|k| (k, None))
            .ok_or(("internal error", "cached JWKS is not valid JSON".to_owned())),
        Plan::Refuse => {
            Err(("no usable keys", "no cached JWKS and a fetch is throttled".to_owned()))
        }
        Plan::Fetch => {
            match fetch::fetch_jwks(&set.jwks_uri, set.jwks_timeout, cache::JWKS_MAX_BYTES) {
                Ok(body) => {
                    let keys = serde_json::from_slice::<JwkSet>(&body).map_err(|_| {
                        ("internal error", "fetched JWKS is not valid JSON".to_owned())
                    })?;
                    cache::store_ok(&set.jwks_uri, &body, now)
                        .map_err(|e| ("internal error", format!("cache write failed: {e:?}")))?;
                    Ok((keys, None))
                }
                Err(e) => {
                    let msg = format!("jwks fetch failed: {e:?}");
                    // Same rule as `cache::plan`: cached keys older than max_stale are not used.
                    let usable = snap.last_ok.is_some_and(|t| {
                        now.duration_since(t).unwrap_or(Duration::ZERO) <= set.max_stale
                    });
                    match cached {
                        Some(keys) if usable => Ok((keys, Some(msg))),
                        _ => Err(("no usable keys", msg)),
                    }
                }
            }
        }
    }
}

/// The cache as this backend sees it right now.
struct View {
    now: SystemTime,
    snap: Snapshot,
    /// The cached keys, when they are for the configured URI and parse.
    cached: Option<JwkSet>,
    plan: Plan,
}

fn look(kid: &str, set: &Settings) -> Result<View, KeysError> {
    let now = SystemTime::now();
    let snap =
        cache::read().map_err(|e| ("internal error", format!("cache read failed: {e:?}")))?;
    let cached = (snap.uri == set.jwks_uri)
        .then(|| serde_json::from_slice::<JwkSet>(&snap.jwks).ok())
        .flatten();
    let need_kid = !cached.as_ref().is_some_and(|k| has_kid(k, kid));
    let plan = cache::plan(&snap, &set.jwks_uri, need_kid, now, set);
    Ok(View { now, snap, cached, plan })
}

/// Nothing usable is cached and fetching is throttled. If the throttling attempt (for this URI)
/// is younger than `jwks_timeout`, another backend may still be fetching: sleep on the latch and
/// re-read until the plan changes or that attempt is `jwks_timeout` old (also capped locally, in
/// case the clock jumped back).
fn wait_for_fetch(kid: &str, set: &Settings, mut view: View) -> Result<View, KeysError> {
    let deadline = Instant::now().checked_add(set.jwks_timeout);
    while view.plan == Plan::Refuse
        && deadline.is_some_and(|d| Instant::now() < d)
        && view.snap.last_attempt.filter(|_| view.snap.attempt_uri == set.jwks_uri).is_some_and(
            |t| view.now.duration_since(t).unwrap_or(Duration::ZERO) < set.jwks_timeout,
        )
    {
        let events = pg_sys::WL_LATCH_SET | pg_sys::WL_TIMEOUT | pg_sys::WL_EXIT_ON_PM_DEATH;
        // SAFETY: MyLatch is this backend's own latch.
        let rc = unsafe { pg_sys::WaitLatch(pg_sys::MyLatch, events as c_int, WAIT_STEP_MS, 0) };
        if rc as u32 & pg_sys::WL_LATCH_SET != 0 {
            fetch::on_latch();
        }
        view = look(kid, set)?;
    }
    Ok(view)
}

#[cfg(any(test, feature = "pg_test"))]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
#[pgrx::pg_schema]
mod tests {
    use pgrx::prelude::*;

    use super::{decide, Decision};
    use crate::provider::Provider;
    use crate::settings;

    #[pg_test]
    fn module_init_returns_magic() {
        let callbacks = crate::entry::_PG_oauth_validator_module_init();
        // SAFETY: the entry point returns a pointer to a static that lives for the whole process.
        let callbacks = unsafe { &*callbacks };
        assert_eq!(callbacks.magic, 0x2025_0220);
        assert!(callbacks.validate_cb.is_some());
    }

    #[pg_test]
    fn provider_defaults_to_generic() {
        let shown = Spi::get_one::<String>("SHOW pg_oauth_rs.provider").unwrap();
        assert_eq!(shown.as_deref(), Some("generic"));
        let set = settings::current();
        assert_eq!(set.provider, Provider::Generic);
        assert_eq!(set.identity_claim, "");
    }

    #[pg_test]
    fn decide_without_config_is_error() {
        // audience is empty by default: Error, returned before the HBA line is read.
        assert!(matches!(decide("a.b.c", "alice"), Decision::Error));
    }

    #[pg_test]
    fn only_one_claim_per_snapshot() {
        let uri = "https://idp.example/claim-test";
        let seen = crate::cache::read().unwrap();
        let now = std::time::SystemTime::now();
        assert!(crate::cache::claim_attempt(uri, &seen, now).unwrap());
        // A second backend that planned with the same snapshot loses the claim.
        assert!(!crate::cache::claim_attempt(uri, &seen, now).unwrap());
        let after = crate::cache::read().unwrap();
        assert_eq!(after.attempt_uri, uri);
        assert!(crate::cache::claim_attempt(uri, &after, now).unwrap());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
mod preset_tests {
    use std::time::Duration;

    use super::apply_preset;
    use crate::provider::Provider;
    use crate::settings::Settings;

    const T: &str = "6f1c2a3b-4d5e-4f60-8a9b-0c1d2e3f4a5b";

    fn entra_issuer() -> String {
        format!("https://login.microsoftonline.com/{T}/v2.0")
    }

    fn set(provider: Provider, jwks_uri: &str, identity_claim: &str) -> Settings {
        Settings {
            audience: "db".into(),
            jwks_uri: jwks_uri.into(),
            identity_claim: identity_claim.into(),
            leeway: Duration::from_secs(60),
            jwks_timeout: Duration::from_secs(5),
            refetch_interval: Duration::from_secs(60),
            max_age: Duration::from_secs(3600),
            max_stale: Duration::from_secs(86400),
            provider,
            provider_unknown: false,
        }
    }

    #[test]
    fn explicit_identity_claim_wins() {
        let mut s = set(Provider::Entra, "", "sub");
        apply_preset(&mut s, &entra_issuer()).unwrap();
        assert_eq!(s.identity_claim, "sub");
    }

    #[test]
    fn empty_identity_claim_takes_preset() {
        let mut s = set(Provider::Entra, "", "");
        apply_preset(&mut s, &entra_issuer()).unwrap();
        assert_eq!(s.identity_claim, "oid");
    }

    #[test]
    fn explicit_jwks_uri_wins_and_tenant_still_checked() {
        let mut s = set(Provider::Entra, "https://keys.example/jwks", "");
        let tenant = apply_preset(&mut s, &entra_issuer()).unwrap();
        assert_eq!(s.jwks_uri, "https://keys.example/jwks");
        assert_eq!(tenant.as_deref(), Some(T));
    }

    #[test]
    fn explicit_jwks_uri_does_not_skip_shape_check() {
        let mut s = set(Provider::Okta, "https://keys.example/jwks", "");
        assert!(apply_preset(&mut s, "https://acme.okta.com").is_err());
    }

    #[test]
    fn generic_keeps_everything() {
        let mut s = set(Provider::Generic, "", "");
        assert_eq!(apply_preset(&mut s, "https://idp.example").unwrap(), None);
        assert_eq!(s.jwks_uri, "");
        assert_eq!(s.identity_claim, "sub");
    }
}
