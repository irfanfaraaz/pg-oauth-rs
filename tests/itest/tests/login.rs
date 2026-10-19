//! End-to-end logins through libpq against the demo stack (spec §7).
//!
//! Run serially (`--test-threads=1`): the tests share one Postgres, one Keycloak and one JWKS
//! cache. libtest runs them in name order, so `zz_no_token_in_server_log` comes last.
//! Each refusal test also finds the module's reason in the server log, so a token refused for
//! the wrong reason (say, no keys) fails the test.

use std::sync::Barrier;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use itest::libpq::connect_with_token;
use itest::{login_conninfo, stack, tokens, ISSUER};
use serde_json::json;

/// Spec bound for a login while the IdP is down: `jwks_timeout` (2 s in tests) + 2 s.
const FAST: Duration = Duration::from_secs(4);
const JWKS_URI_SETTING: &str = "pg_oauth_rs.jwks_uri";

fn logs_in(user: &str, token: &str) {
    let who = connect_with_token(&login_conninfo(user), token)
        .unwrap_or_else(|e| panic!("{user} should log in: {e}"));
    assert_eq!(who, user);
}

/// The login is refused and a server log line contains `reason`. Returns how long the login took.
fn refused(user: &str, token: &str, reason: &str) -> Duration {
    let since = SystemTime::now();
    let started = Instant::now();
    let result = connect_with_token(&login_conninfo(user), token);
    let took = started.elapsed();
    let err = result.expect_err("the login should be refused");
    eprintln!("refused as expected after {took:?}: {err}");
    stack::wait_for_log(since, reason);
    took
}

/// `n` logins at once with the same token. Returns each result and how long it took.
fn parallel_logins(n: usize, user: &str, token: &str) -> Vec<(Result<String, String>, Duration)> {
    let conninfo = &login_conninfo(user);
    let barrier = &Barrier::new(n); // start all logins at the same moment
    thread::scope(|s| {
        let handles: Vec<_> = (0..n)
            .map(|_| {
                s.spawn(move || {
                    barrier.wait();
                    let started = Instant::now();
                    let result = connect_with_token(conninfo, token);
                    (result, started.elapsed())
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    })
}

fn alice_claims() -> serde_json::Value {
    tokens::claims("alice@example.com")
}

#[test]
fn good_token_logs_in() {
    stack::start();
    logs_in("alice", &tokens::alice());
}

#[test]
fn wrong_aud_refused() {
    stack::start();
    let mut claims = alice_claims();
    claims["aud"] = json!("someone-else");
    refused("alice", &tokens::forged(&claims), "pg_oauth_rs: audience mismatch");
}

#[test]
fn wrong_iss_refused() {
    stack::start();
    let mut claims = alice_claims();
    claims["iss"] = json!(format!("{ISSUER}/")); // differs only by a trailing slash
    refused("alice", &tokens::forged(&claims), "pg_oauth_rs: issuer mismatch");
}

#[test]
fn expired_beyond_leeway_refused() {
    stack::start();
    let mut claims = alice_claims();
    claims["exp"] = json!(tokens::now_secs() - 120); // default leeway is 60 s
    refused("alice", &tokens::forged(&claims), "pg_oauth_rs: token expired");
}

#[test]
fn expired_within_leeway_logs_in() {
    stack::start();
    let mut claims = alice_claims();
    claims["exp"] = json!(tokens::now_secs() - 10);
    logs_in("alice", &tokens::forged(&claims));
}

#[test]
fn missing_exp_refused() {
    stack::start();
    let mut claims = alice_claims();
    claims.as_object_mut().unwrap().remove("exp");
    refused("alice", &tokens::forged(&claims), "pg_oauth_rs: exp missing or invalid");
}

#[test]
fn future_nbf_refused() {
    stack::start();
    let mut claims = alice_claims();
    claims["nbf"] = json!(tokens::now_secs() + 600);
    refused("alice", &tokens::forged(&claims), "pg_oauth_rs: token not yet valid (nbf)");
}

#[test]
fn bad_signature_refused() {
    stack::start();
    let token = tokens::with_bad_signature(&tokens::forged(&alice_claims()));
    refused("alice", &token, "pg_oauth_rs: bad signature");
}

#[test]
fn alg_none_refused() {
    stack::start();
    // `none` is not an algorithm the header parser knows, so the token is malformed.
    refused("alice", &tokens::forged_alg_none(&alice_claims()), "pg_oauth_rs: malformed token");
}

#[test]
fn hs256_public_key_trick_refused() {
    stack::start();
    let token = tokens::forged_hs256_with_public_key(&alice_claims());
    refused("alice", &token, "pg_oauth_rs: token alg not allowed for the key");
}

#[test]
fn rotated_key_logs_in_after_refetch() {
    stack::start();
    logs_in("alice", &tokens::alice()); // the cache now holds the realm's current keys
    let _rotation = stack::admin().rotate_keys();
    let token = tokens::alice();
    assert_ne!(
        tokens::header_kid(&token),
        tokens::itest_kid(),
        "Keycloak should sign with the new key"
    );
    // The unknown kid triggers a refetch once the throttle (1 s) allows it.
    thread::sleep(Duration::from_millis(1100));
    logs_in("alice", &token);
}

#[test]
fn email_unverified_refused() {
    stack::start();
    let mut claims = alice_claims();
    claims["email_verified"] = json!(false);
    refused("alice", &tokens::forged(&claims), "pg_oauth_rs: email not verified");
}

#[test]
fn identity_not_mapped_refused_by_postgres() {
    stack::start();
    // The module accepts bob's token; pg_ident.conf has no line for bob@other.example.
    let token =
        tokens::keycloak_token("bob", "bob").expect("Keycloak should issue a token for bob");
    refused("bob", &token, "no match in usermap");
}

#[test]
fn idp_down_warm_cache_logs_in() {
    stack::start();
    let token = tokens::alice();
    logs_in("alice", &token); // warm the cache
    let _down = stack::keycloak_down();
    logs_in("alice", &token);
}

#[test]
fn idp_down_cold_cache_refused_fast() {
    stack::start();
    let token = tokens::alice();
    let _cold = stack::guc(JWKS_URI_SETTING, &stack::cold_jwks_uri());
    let _down = stack::keycloak_down();
    let took = refused("alice", &token, "pg_oauth_rs: no usable keys");
    assert!(took < FAST, "refusal took {took:?}, want < {FAST:?}");
}

#[test]
fn jwks_uri_change_drops_old_keys() {
    stack::start();
    let token = tokens::alice();
    logs_in("alice", &token); // keys cached for the configured URI
    let missing = format!("{ISSUER}/protocol/openid-connect/no-such-endpoint");
    let _uri = stack::guc(JWKS_URI_SETTING, &missing);
    // The cached keys belong to the old URI: the module must fetch the new one (404), not use them.
    refused("alice", &token, "jwks fetch failed: Http(404)");
}

#[test]
fn parallel_cold_start_logins_both_succeed() {
    stack::start();
    let token = tokens::alice();
    let _cold = stack::guc(JWKS_URI_SETTING, &stack::cold_jwks_uri());
    // One backend fetches; the other waits for that fetch instead of being refused.
    for (result, _) in parallel_logins(2, "alice", &token) {
        assert_eq!(result.expect("both cold-start logins should succeed"), "alice");
    }
}

#[test]
fn parallel_logins_idp_down_one_fetch() {
    stack::start();
    let token = tokens::alice();
    // A throttle window longer than the test, so "one fetch" cannot be blurred by a second window.
    let _interval = stack::guc("pg_oauth_rs.jwks_refetch_interval", "10");
    let _cold = stack::guc(JWKS_URI_SETTING, &stack::cold_jwks_uri());
    let _down = stack::keycloak_down();
    let since = SystemTime::now();
    let results = parallel_logins(20, "alice", &token);
    for (result, took) in &results {
        assert!(result.is_err(), "no keys, so every login is refused");
        assert!(*took < FAST, "a login took {took:?}, want < {FAST:?}");
    }
    let log = stack::wait_for_log(since, "jwks fetch failed");
    assert_eq!(
        log.matches("jwks fetch failed").count(),
        1,
        "20 logins should cause one JWKS fetch"
    );
}

#[test]
fn disabled_user_gets_no_new_token() {
    stack::start();
    {
        let _disabled = stack::admin().disable_user("alice");
        let err = tokens::keycloak_token("alice", "alice")
            .expect_err("a disabled user must get no token");
        eprintln!("token refused as expected: {err}");
    }
    tokens::alice(); // enabled again: tokens again
}

/// Last (name order): no token, nor its payload or signature, appears in the Postgres log.
#[test]
fn zz_no_token_in_server_log() {
    stack::start();
    logs_in("alice", &tokens::alice()); // at least one token, also when this test runs alone
    let log = stack::server_log();
    for token in tokens::used_tokens() {
        // Skip the header: it is short and the same for many tokens. Do not print the token.
        for part in token.split('.').skip(1).filter(|p| !p.is_empty()) {
            assert!(!log.contains(part), "part of a token appears in the Postgres server log");
        }
    }
    stack::reset_timing();
}
