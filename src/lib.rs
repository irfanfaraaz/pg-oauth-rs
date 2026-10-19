use std::ffi::c_char;

use pgrx::prelude::*;

pub mod cache;
pub mod entry;
pub mod fetch;
pub mod ffi;
pub mod log;
pub mod settings;
pub mod token;
pub mod validate;

::pgrx::pg_module_magic!(name, version);

unsafe extern "C" {
    /// Issuer of the matched pg_hba.conf line; NULL when there is no port or HBA line.
    pub(crate) fn pg_oauth_rs_hba_issuer() -> *const c_char;
}

#[pg_guard]
pub extern "C-unwind" fn _PG_init() {
    settings::register();
}

/// This module is required by `cargo pgrx test` invocations.
#[cfg(test)]
pub mod pg_test {
    pub fn setup(_options: Vec<&str>) {}

    #[must_use]
    pub fn postgresql_conf_options() -> Vec<&'static str> {
        vec![]
    }
}
