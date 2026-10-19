//! Glue that combines settings, cache, fetch and token checks into the authorization decision.

use std::ffi::CStr;
use std::time::{Duration, SystemTime};

use jsonwebtoken::jwk::JwkSet;

use crate::cache::{self, Plan};
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

/// Decide one login. Logs every non-Allow outcome exactly once; never logs the token.
pub fn decide(token: &str, _role: &str) -> Decision {
    let set = settings::current();
    if set.audience.is_empty() || set.jwks_uri.is_empty() {
        return error(
            "not configured",
            "pg_oauth_rs.audience and pg_oauth_rs.jwks_uri must both be set",
        );
    }
    let Some(issuer) = hba_issuer() else {
        return error("internal error", "no issuer on the matched pg_hba.conf line");
    };

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
        parts.push(format!("kid={kid:?}"));
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
    let now = SystemTime::now();
    let snap =
        cache::read().map_err(|e| ("internal error", format!("cache read failed: {e:?}")))?;
    let cached = (snap.uri == set.jwks_uri)
        .then(|| serde_json::from_slice::<JwkSet>(&snap.jwks).ok())
        .flatten();
    let need_kid = !cached.as_ref().is_some_and(|k| has_kid(k, kid));

    match cache::plan(&snap, &set.jwks_uri, need_kid, now, set) {
        Plan::UseCache | Plan::UseCacheNoFetch => cached
            .map(|k| (k, None))
            .ok_or(("internal error", "cached JWKS is not valid JSON".to_owned())),
        Plan::Refuse => {
            Err(("no usable keys", "no cached JWKS and a fetch is throttled".to_owned()))
        }
        Plan::Fetch => {
            // Record the attempt first so a failing IdP is not hammered by every backend.
            cache::note_attempt(now)
                .map_err(|e| ("internal error", format!("cache write failed: {e:?}")))?;
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

#[cfg(any(test, feature = "pg_test"))]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
#[pgrx::pg_schema]
mod tests {
    use pgrx::prelude::*;

    use super::{decide, Decision};

    #[pg_test]
    fn module_init_returns_magic() {
        let callbacks = crate::entry::_PG_oauth_validator_module_init();
        // SAFETY: the entry point returns a pointer to a static that lives for the whole process.
        let callbacks = unsafe { &*callbacks };
        assert_eq!(callbacks.magic, 0x2025_0220);
        assert!(callbacks.validate_cb.is_some());
    }

    #[pg_test]
    fn decide_without_config_is_error() {
        // audience and jwks_uri are empty by default, so this cannot be decided.
        assert!(matches!(decide("a.b.c", "alice"), Decision::Error));
    }
}
