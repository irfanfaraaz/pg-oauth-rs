//! Access tokens: real ones from Keycloak, and forged ones signed with the test key.
//!
//! The demo realm imports `keys/itest-rsa.pem` and publishes it in its JWKS, so a forged token
//! passes the key lookup and fails only the check a test is about.

use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPublicKey;
use serde_json::{json, Value};

use crate::{http, ISSUER, JWKS_URI};

const PRIVATE_PEM: &[u8] = include_bytes!("../keys/itest-rsa.pem");
const PUBLIC_PEM: &[u8] = include_bytes!("../keys/itest-rsa.pub.pem");

/// Every token handed out in this run, so the last test can check none reached the server log.
static USED: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn remember(token: String) -> String {
    USED.lock().unwrap().push(token.clone());
    token
}

/// All tokens made so far in this test process.
pub fn used_tokens() -> Vec<String> {
    USED.lock().unwrap().clone()
}

/// OAuth password grant against `realm`. Returns the access token, or the error response.
pub fn password_grant(
    realm: &str,
    client_id: &str,
    user: &str,
    password: &str,
) -> Result<String, String> {
    let url =
        format!("https://keycloak.localtest.me:8443/realms/{realm}/protocol/openid-connect/token");
    let mut response = http()
        .post(&url)
        .send_form([
            ("grant_type", "password"),
            ("client_id", client_id),
            ("username", user),
            ("password", password),
            ("scope", "openid"),
        ])
        .map_err(|e| e.to_string())?;
    let body: Value = response.body_mut().read_json().map_err(|e| e.to_string())?;
    body["access_token"].as_str().map(str::to_owned).ok_or_else(|| body.to_string())
}

/// A real access token for a demo user, from the test-only `itest` client.
pub fn keycloak_token(user: &str, password: &str) -> Result<String, String> {
    password_grant("demo", "itest", user, password).map(remember)
}

/// A fresh real token for alice.
pub fn alice() -> String {
    keycloak_token("alice", "alice").expect("Keycloak should issue a token for alice")
}

/// The `kid` Keycloak gave the test key: the JWKS entry whose modulus equals ours.
pub fn itest_kid() -> String {
    static KID: OnceLock<String> = OnceLock::new();
    KID.get_or_init(|| {
        let public = RsaPublicKey::from_public_key_pem(std::str::from_utf8(PUBLIC_PEM).unwrap())
            .expect("keys/itest-rsa.pub.pem is an RSA public key");
        let n = URL_SAFE_NO_PAD.encode(public.n().to_bytes_be());
        let jwks: Value = http().get(JWKS_URI).call().unwrap().body_mut().read_json().unwrap();
        jwks["keys"]
            .as_array()
            .expect("JWKS has a keys array")
            .iter()
            .find(|key| key["n"] == n.as_str())
            .and_then(|key| key["kid"].as_str())
            .expect("the realm's JWKS lists the test key")
            .to_owned()
    })
    .clone()
}

/// The `kid` in a token's header (not verified).
pub fn header_kid(token: &str) -> String {
    jsonwebtoken::decode_header(token).unwrap().kid.expect("token header has a kid")
}

pub fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

/// Claims that pass every check for `email`. Tests change one field to make them fail one check.
pub fn claims(email: &str) -> Value {
    let now = now_secs();
    json!({
        "iss": ISSUER,
        "aud": "postgres",
        "sub": email,
        "email": email,
        "email_verified": true,
        "iat": now,
        "exp": now + 300,
    })
}

/// RS256, signed with the test key, `kid` of the test key.
pub fn forged(claims: &Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(itest_kid());
    let key = EncodingKey::from_rsa_pem(PRIVATE_PEM).expect("keys/itest-rsa.pem is an RSA key");
    remember(encode(&header, claims, &key).unwrap())
}

/// The classic key-confusion attack: HS256 with the RSA public key (PEM text) as the HMAC secret.
pub fn forged_hs256_with_public_key(claims: &Value) -> String {
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(itest_kid());
    remember(encode(&header, claims, &EncodingKey::from_secret(PUBLIC_PEM)).unwrap())
}

/// `alg: none` and an empty signature, assembled by hand (no library will make one).
pub fn forged_alg_none(claims: &Value) -> String {
    let part = |v: &Value| URL_SAFE_NO_PAD.encode(v.to_string());
    let header = json!({ "alg": "none", "typ": "JWT", "kid": itest_kid() });
    remember(format!("{}.{}.", part(&header), part(claims)))
}

/// The same token with its first signature character changed: well-formed, wrong signature.
pub fn with_bad_signature(token: &str) -> String {
    let (signed_part, signature) = token.rsplit_once('.').unwrap();
    let first = if signature.starts_with('A') { 'B' } else { 'A' };
    remember(format!("{signed_part}.{first}{}", &signature[1..]))
}
