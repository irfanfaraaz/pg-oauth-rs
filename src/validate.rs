//! Glue that combines settings, cache, fetch and token checks into the authorization decision.

/// Outcome of checking one token.
pub enum Decision {
    /// The token is good; `authn_id` becomes the SYSTEM_USER.
    Allow { authn_id: String },
    /// The token is bad. `authn_id` is set only when the signature already passed.
    Deny { authn_id: Option<String> },
    /// We could not decide (not configured, no keys, internal error).
    Error,
}

/// Stub until ticket 07 wires settings, cache, fetch and token checks.
pub fn decide(_token: &str, _role: &str) -> Decision {
    Decision::Error
}
