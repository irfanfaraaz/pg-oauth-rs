//! Hand-written FFI types for the PostgreSQL OAuth validator callbacks (OAuthValidatorCallbacks, ValidatorModuleState, ValidatorModuleResult).
//!
//! Layout copied from `src/include/libpq/oauth.h` (REL_18_STABLE); pgrx does not bind it.

use std::ffi::{c_char, c_int, c_void};

/// `PG_OAUTH_VALIDATOR_MAGIC`: ABI version of the validator callbacks.
pub const PG_OAUTH_VALIDATOR_MAGIC: u32 = 0x2025_0220;

#[repr(C)]
pub struct ValidatorModuleState {
    /// The server's `PG_VERSION_NUM`.
    pub sversion: c_int,
    pub private_data: *mut c_void,
}

#[repr(C)]
pub struct ValidatorModuleResult {
    pub authorized: bool,
    /// Must be `palloc`'d.
    pub authn_id: *mut c_char,
    /// Added after PG 18; compiled but not tested in v0.1.
    #[cfg(feature = "pg19")]
    pub error_detail: *mut c_char,
}

pub type ValidatorStartupCb = unsafe extern "C-unwind" fn(state: *mut ValidatorModuleState);
pub type ValidatorShutdownCb = unsafe extern "C-unwind" fn(state: *mut ValidatorModuleState);
pub type ValidateCb = unsafe extern "C-unwind" fn(
    state: *const ValidatorModuleState,
    token: *const c_char,
    role: *const c_char,
    result: *mut ValidatorModuleResult,
) -> bool;

#[repr(C)]
pub struct OAuthValidatorCallbacks {
    pub magic: u32,
    pub startup_cb: Option<ValidatorStartupCb>,
    pub shutdown_cb: Option<ValidatorShutdownCb>,
    pub validate_cb: Option<ValidateCb>,
}
