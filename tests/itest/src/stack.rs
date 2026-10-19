//! Control of the demo stack: Postgres settings, the Keycloak admin API, and Docker.
//!
//! Every change a test makes comes back as a guard that undoes it on drop, also when the test
//! panics, so one failing test does not leave the stack broken for the next.

use std::process::Command;
use std::sync::Once;
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::{http, libpq, tokens, ADMIN_CONNINFO, JWKS_URI};

/// Fixed `container_name`s from `demo/compose.yaml`.
const KEYCLOAK_CONTAINER: &str = "pg-oauth-rs-keycloak";
const POSTGRES_CONTAINER: &str = "pg-oauth-rs-postgres";
const ADMIN_API: &str = "https://keycloak.localtest.me:8443/admin/realms/demo";

/// Call first in every test.
pub fn start() {
    static SETUP: Once = Once::new();
    SETUP.call_once(|| {
        wait_for_keycloak();
        admin().install_test_key();
        set_guc("pg_oauth_rs.jwks_refetch_interval", "1");
        set_guc("pg_oauth_rs.jwks_timeout", "2");
    });
    // Let the previous test's fetch throttle (jwks_refetch_interval = 1 s) run out, and keep
    // its log lines in an earlier second than this test's (see `server_log_since`).
    sleep(Duration::from_millis(1100));
}

// ---- Postgres ----

/// Run one statement as the superuser over a password connection.
pub fn admin_sql(sql: &str) -> Option<String> {
    try_admin_sql(sql).unwrap_or_else(|e| panic!("{sql}: {e}"))
}

/// Like `admin_sql`, but a failed statement comes back as the error text.
pub fn try_admin_sql(sql: &str) -> Result<Option<String>, String> {
    let conn = libpq::connect(ADMIN_CONNINFO).expect("superuser password login");
    conn.query(sql)
}

/// `ALTER SYSTEM SET` plus reload. Names and values come from the tests, never from outside.
pub fn set_guc(name: &str, value: &str) {
    // Separate statements: ALTER SYSTEM refuses to run inside a (multi-statement) transaction.
    admin_sql(&format!("ALTER SYSTEM SET {name} = '{value}'"));
    admin_sql("SELECT pg_reload_conf()");
    // The postmaster applies the reload asynchronously; give it a moment before the next login.
    sleep(Duration::from_millis(500));
}

/// Undoes `guc` on drop.
pub struct GucGuard {
    name: &'static str,
    old: String,
}

impl Drop for GucGuard {
    fn drop(&mut self) {
        set_guc(self.name, &self.old);
    }
}

/// Set a setting until the guard is dropped.
pub fn guc(name: &'static str, value: &str) -> GucGuard {
    let old = admin_sql(&format!("SELECT current_setting('{name}')")).expect("setting exists");
    set_guc(name, value);
    GucGuard { name, old }
}

/// An equivalent JWKS URL the module has never seen. The cache holds keys for one URI only, so
/// switching to this gives a cold cache. Unique across runs: the server's cache outlives them.
pub fn cold_jwks_uri() -> String {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    format!("{JWKS_URI}?cold={nanos}")
}

// ---- Docker ----

fn docker(args: &[&str]) -> String {
    let out = Command::new("docker").args(args).output().expect("run the docker CLI");
    assert!(
        out.status.success(),
        "docker {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // `docker logs` replays the container's stderr, where Postgres logs, on our stderr.
    format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
}

/// The whole Postgres server log.
pub fn server_log() -> String {
    docker(&["logs", POSTGRES_CONTAINER])
}

/// The Postgres log from the start of the second `since` falls in.
pub fn server_log_since(since: SystemTime) -> String {
    let secs = since.duration_since(UNIX_EPOCH).unwrap().as_secs().to_string();
    docker(&["logs", "--since", &secs, POSTGRES_CONTAINER])
}

/// Wait until the log since `since` has a line containing `needle`; returns that log.
pub fn wait_for_log(since: SystemTime, needle: &str) -> String {
    let mut log = String::new();
    // Log lines reach Docker a little after the login fails.
    for _ in 0..30 {
        log = server_log_since(since);
        if log.contains(needle) {
            return log;
        }
        sleep(Duration::from_millis(100));
    }
    let lines: Vec<&str> = log.lines().collect();
    let tail = lines[lines.len().saturating_sub(40)..].join("\n");
    panic!("no server log line contains {needle:?}. Log since the test started:\n{tail}");
}

/// Keycloak is stopped until the guard is dropped (IdP down).
pub struct KeycloakDown;

impl Drop for KeycloakDown {
    fn drop(&mut self) {
        docker(&["start", KEYCLOAK_CONTAINER]);
        wait_for_keycloak();
    }
}

pub fn keycloak_down() -> KeycloakDown {
    docker(&["stop", KEYCLOAK_CONTAINER]);
    KeycloakDown
}

/// Wait until the realm's JWKS answers.
pub fn wait_for_keycloak() {
    let deadline = Instant::now() + Duration::from_secs(180);
    while !http().get(JWKS_URI).call().is_ok_and(|r| r.status() == 200) {
        assert!(Instant::now() < deadline, "Keycloak did not come up within 180 s");
        sleep(Duration::from_secs(1));
    }
}

// ---- Keycloak admin REST API ----

/// A logged-in Keycloak admin (admin/admin from `demo/compose.yaml`). Its token lives ~60 s, so
/// make a new one per use instead of keeping it.
pub struct KeycloakAdmin {
    token: String,
}

pub fn admin() -> KeycloakAdmin {
    let token = tokens::password_grant("master", "admin-cli", "admin", "admin")
        .expect("Keycloak admin login");
    KeycloakAdmin { token }
}

impl KeycloakAdmin {
    fn auth(&self) -> String {
        format!("Bearer {}", self.token)
    }

    fn get(&self, path: &str) -> Value {
        let mut response = http()
            .get(format!("{ADMIN_API}{path}"))
            .header("Authorization", self.auth())
            .call()
            .unwrap();
        assert_eq!(response.status(), 200, "GET {path}");
        response.body_mut().read_json().unwrap()
    }

    /// Load the test key (`tokens::PRIVATE_PEM`) as the realm's top RS256 key (priority 1000), so
    /// Keycloak signs real tokens with it and publishes it. Replaces an `itest-key` from an
    /// earlier run, whose key may differ. It stays after the run; it signs demo tokens harmlessly.
    pub fn install_test_key(&self) {
        let found = self.get("/components?type=org.keycloak.keys.KeyProvider&name=itest-key");
        for old in found.as_array().expect("component list") {
            let id = old["id"].as_str().expect("component id");
            self.delete(&format!("/components/{id}"));
        }
        self.create_key(json!({
            "name": "itest-key",
            "providerId": "rsa",
            "config": {
                "privateKey": [tokens::PRIVATE_PEM.as_str()],
                "priority": ["1000"],
                "algorithm": ["RS256"],
                "keyUse": ["sig"],
                "active": ["true"],
                "enabled": ["true"],
            },
        }));
    }

    /// Add a generated RS256 key that outranks the test key (priority 1000), so Keycloak signs
    /// new tokens with a `kid` the module has not cached. Removed again when the guard drops.
    pub fn rotate_keys(&self) -> Rotation {
        let component_id = self.create_key(json!({
            "name": "itest-rotated",
            "providerId": "rsa-generated",
            "config": {
                "priority": ["2000"],
                "keySize": ["2048"],
                "algorithm": ["RS256"],
                "active": ["true"],
                "enabled": ["true"],
            },
        }));
        Rotation { component_id }
    }

    /// Add a key provider to the realm. Returns its component id.
    fn create_key(&self, mut component: Value) -> String {
        component["providerType"] = json!("org.keycloak.keys.KeyProvider");
        component["parentId"] = self.get("")["id"].clone();
        let response = http()
            .post(format!("{ADMIN_API}/components"))
            .header("Authorization", self.auth())
            .send_json(component)
            .unwrap();
        assert_eq!(response.status(), 201, "create key component");
        let location =
            response.headers().get("location").expect("Location header").to_str().unwrap();
        location.rsplit('/').next().unwrap().to_owned()
    }

    fn delete(&self, path: &str) {
        let response = http()
            .delete(format!("{ADMIN_API}{path}"))
            .header("Authorization", self.auth())
            .call()
            .unwrap();
        assert_eq!(response.status(), 204, "DELETE {path}");
    }

    /// Turn a demo user's account off or on. Sends the full user back (GET, change, PUT), so
    /// no other field is touched.
    pub fn set_user_enabled(&self, username: &str, enabled: bool) {
        let mut user = self.get(&format!("/users?username={username}&exact=true"))[0].clone();
        let id = user["id"].as_str().expect("user id").to_owned();
        user["enabled"] = json!(enabled);
        let response = http()
            .put(format!("{ADMIN_API}/users/{id}"))
            .header("Authorization", self.auth())
            .send_json(user)
            .unwrap();
        assert_eq!(response.status(), 204, "update user {username}");
    }

    /// `username` is disabled until the guard is dropped.
    pub fn disable_user(&self, username: &'static str) -> DisabledUser {
        self.set_user_enabled(username, false);
        DisabledUser { username }
    }
}

/// Deletes the rotated key on drop, so the test key signs again.
pub struct Rotation {
    component_id: String,
}

impl Drop for Rotation {
    fn drop(&mut self) {
        admin().delete(&format!("/components/{}", self.component_id));
    }
}

/// Enables the user again on drop.
pub struct DisabledUser {
    username: &'static str,
}

impl Drop for DisabledUser {
    fn drop(&mut self) {
        admin().set_user_enabled(self.username, true);
    }
}
