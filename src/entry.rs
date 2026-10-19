//! The `_PG_oauth_validator_module_init` entry point, `validate_cb` and the panic wall around it.

use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::ptr;

use pgrx::pg_sys;
use pgrx::pg_sys::panic::CaughtError;
use pgrx::prelude::*;

use crate::ffi::{
    OAuthValidatorCallbacks, ValidatorModuleResult, ValidatorModuleState, PG_OAUTH_VALIDATOR_MAGIC,
};
use crate::log;
use crate::validate::{self, Decision};

static CALLBACKS: OAuthValidatorCallbacks = OAuthValidatorCallbacks {
    magic: PG_OAUTH_VALIDATOR_MAGIC,
    startup_cb: None,
    shutdown_cb: None,
    validate_cb: Some(validate_cb),
};

#[no_mangle]
pub extern "C-unwind" fn _PG_oauth_validator_module_init() -> *const OAuthValidatorCallbacks {
    &CALLBACKS
}

/// `false` = could not decide; `true` = decided, see `result.authorized`.
#[pg_guard]
extern "C-unwind" fn validate_cb(
    _state: *const ValidatorModuleState,
    token: *const c_char,
    role: *const c_char,
    result: *mut ValidatorModuleResult,
) -> bool {
    if token.is_null() || role.is_null() || result.is_null() {
        log::refusal("internal error", "validate_cb got a NULL pointer");
        return false;
    }
    // SAFETY: non-NULL (checked above); Postgres passes NUL-terminated strings valid for this call.
    let (token, role) = unsafe { (CStr::from_ptr(token), CStr::from_ptr(role)) };

    let decision = match (token.to_str(), role.to_str()) {
        (Ok(token), Ok(role)) => {
            match catch_unwind(AssertUnwindSafe(|| validate::decide(token, role))) {
                Ok(decision) => decision,
                Err(payload) => {
                    // A Postgres ERROR (e.g. a cancel seen by CHECK_FOR_INTERRUPTS in the JWKS
                    // fetch) arrives as a pgrx CaughtError; #[pg_guard] must re-raise it into
                    // Postgres, so only plain Rust panics are swallowed here.
                    if payload.is::<CaughtError>() {
                        resume_unwind(payload);
                    }
                    log::refusal("internal error", "caught a panic while validating the token");
                    return false;
                }
            }
        }
        _ => {
            log::refusal("token refused", "token or role is not valid UTF-8");
            Decision::Deny { authn_id: None }
        }
    };

    // SAFETY: non-NULL (checked above); Postgres owns the struct for the duration of this call.
    let result = unsafe { &mut *result };
    match decision {
        Decision::Allow { authn_id } => {
            let copy = pstrdup(&authn_id);
            if copy.is_null() {
                log::refusal("token refused", "identity claim contains a NUL byte");
            }
            result.authorized = !copy.is_null();
            result.authn_id = copy;
            true
        }
        Decision::Deny { authn_id } => {
            result.authorized = false;
            result.authn_id = authn_id.as_deref().map_or(ptr::null_mut(), pstrdup);
            true
        }
        // decide() logs its own refusal reason.
        Decision::Error => false,
    }
}

/// `palloc`'d copy of `s`, or NULL if `s` has an interior NUL.
fn pstrdup(s: &str) -> *mut c_char {
    match CString::new(s) {
        // SAFETY: `c` is a valid NUL-terminated string; pstrdup copies it into CurrentMemoryContext.
        Ok(c) => unsafe { pg_sys::pstrdup(c.as_ptr()) },
        Err(_) => ptr::null_mut(),
    }
}
