#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

use std::time::{Duration, Instant};

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{encode, get_current_timestamp, Algorithm, EncodingKey, Header};
use serde_json::{json, Value};

use super::{header_kid, verify, CheckConfig, Refusal};

const ISS: &str = "https://idp.example.com/realms/demo";
const AUD: &str = "postgres";
const TENANT: &str = "6f1c2a3b-4d5e-4f60-8a9b-0c1d2e3f4a5b";
const RSA_PRIVATE_PKCS1: &[u8] = include_bytes!("testdata/rsa_private_pkcs1.der");
const RSA_PUBLIC_SPKI: &[u8] = include_bytes!("testdata/rsa_public_spki.der");
const EC_PRIVATE_PKCS8: &[u8] = include_bytes!("testdata/ec_private_pkcs8.der");
const OCT_SECRET: &[u8] = b"a-shared-secret-of-thirty-two-by";

fn rsa_jwk() -> Value {
    serde_json::from_str(include_str!("testdata/rsa.jwk.json")).unwrap()
}

fn ec_jwk() -> Value {
    serde_json::from_str(include_str!("testdata/ec.jwk.json")).unwrap()
}

fn jwks(keys: Vec<Value>) -> JwkSet {
    serde_json::from_value(json!({ "keys": keys })).unwrap()
}

fn default_jwks() -> JwkSet {
    jwks(vec![rsa_jwk(), ec_jwk()])
}

fn cfg() -> CheckConfig<'static> {
    CheckConfig {
        issuer: ISS,
        audience: AUD,
        identity_claim: "sub",
        leeway_secs: 60,
        entra_tenant: None,
    }
}

fn entra_cfg() -> CheckConfig<'static> {
    CheckConfig { entra_tenant: Some(TENANT), ..cfg() }
}

fn now() -> u64 {
    get_current_timestamp()
}

fn claims() -> Value {
    json!({ "iss": ISS, "aud": AUD, "sub": "alice", "iat": now(), "exp": now() + 300 })
}

fn with(mut base: Value, key: &str, value: Value) -> Value {
    base[key] = value;
    base
}

fn without(mut base: Value, key: &str) -> Value {
    base.as_object_mut().unwrap().remove(key);
    base
}

fn sign(alg: Algorithm, kid: Option<&str>, claims: &Value, key: &EncodingKey) -> String {
    let mut header = Header::new(alg);
    header.kid = kid.map(str::to_owned);
    encode(&header, claims, key).unwrap()
}

fn rs256(claims: &Value) -> String {
    sign(Algorithm::RS256, Some("rsa-1"), claims, &EncodingKey::from_rsa_der(RSA_PRIVATE_PKCS1))
}

fn es256(claims: &Value) -> String {
    sign(Algorithm::ES256, Some("ec-1"), claims, &EncodingKey::from_ec_der(EC_PRIVATE_PKCS8))
}

/// Unpadded base64url, enough to hand-craft hostile headers.
fn b64url(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
        let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
        let n = (u32::from(chunk[0]) << 16) | (b1 << 8) | b2;
        for i in 0..=chunk.len() {
            out.push(char::from(T[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    out
}

fn assert_claims(res: Result<String, Refusal>, reason: &str, authn_id: Option<&str>) {
    let err = res.unwrap_err();
    assert!(matches!(err, Refusal::Claims { .. }), "{err:?}");
    assert_eq!(err.log_reason(), reason);
    assert_eq!(err.authn_id(), authn_id);
}

#[test]
fn accepts_valid_rs256() {
    assert_eq!(verify(&rs256(&claims()), &default_jwks(), &cfg()), Ok("alice".to_owned()));
}

#[test]
fn accepts_valid_es256() {
    assert_eq!(verify(&es256(&claims()), &default_jwks(), &cfg()), Ok("alice".to_owned()));
}

#[test]
fn rejects_wrong_aud() {
    let t = rs256(&with(claims(), "aud", json!("other")));
    assert_claims(verify(&t, &default_jwks(), &cfg()), "audience mismatch", Some("alice"));
    let t = rs256(&without(claims(), "aud"));
    assert_claims(verify(&t, &default_jwks(), &cfg()), "aud missing or invalid", Some("alice"));
}

#[test]
fn rejects_iss_trailing_slash() {
    let t = rs256(&with(claims(), "iss", json!(format!("{ISS}/"))));
    assert_claims(verify(&t, &default_jwks(), &cfg()), "issuer mismatch", Some("alice"));
}

#[test]
fn rejects_iss_array() {
    let t = rs256(&with(claims(), "iss", json!([ISS])));
    assert_claims(verify(&t, &default_jwks(), &cfg()), "issuer mismatch", Some("alice"));
}

#[test]
fn accepts_aud_array_containing_audience() {
    let t = rs256(&with(claims(), "aud", json!(["account", AUD])));
    assert_eq!(verify(&t, &default_jwks(), &cfg()), Ok("alice".to_owned()));
}

#[test]
fn rejects_expired_beyond_leeway() {
    let t = rs256(&with(claims(), "exp", json!(now() - 120)));
    assert_claims(verify(&t, &default_jwks(), &cfg()), "token expired", Some("alice"));
}

#[test]
fn accepts_expired_within_leeway() {
    let t = rs256(&with(claims(), "exp", json!(now() - 30)));
    assert_eq!(verify(&t, &default_jwks(), &cfg()), Ok("alice".to_owned()));
}

#[test]
fn rejects_missing_exp() {
    let t = rs256(&without(claims(), "exp"));
    assert_claims(verify(&t, &default_jwks(), &cfg()), "exp missing or invalid", Some("alice"));
}

#[test]
fn rejects_future_nbf() {
    let t = rs256(&with(claims(), "nbf", json!(now() + 300)));
    assert_claims(verify(&t, &default_jwks(), &cfg()), "token not yet valid (nbf)", Some("alice"));
    // Within leeway is fine.
    let t = rs256(&with(claims(), "nbf", json!(now() + 30)));
    assert_eq!(verify(&t, &default_jwks(), &cfg()), Ok("alice".to_owned()));
}

#[test]
fn rejects_alg_none() {
    let header = b64url(br#"{"alg":"none","kid":"rsa-1","typ":"JWT"}"#);
    let payload = b64url(claims().to_string().as_bytes());
    for t in [format!("{header}.{payload}."), format!("{header}.{payload}.c2ln")] {
        let err = verify(&t, &default_jwks(), &cfg()).unwrap_err();
        assert_eq!(err, Refusal::Malformed);
        assert_eq!(err.authn_id(), None);
    }
}

#[test]
fn rejects_hs256_signed_with_public_key() {
    let t = sign(
        Algorithm::HS256,
        Some("rsa-1"),
        &claims(),
        &EncodingKey::from_secret(RSA_PUBLIC_SPKI),
    );
    let err = verify(&t, &default_jwks(), &cfg()).unwrap_err();
    assert_eq!(err, Refusal::BadAlgorithm);
    assert_eq!(err.authn_id(), None);
}

#[test]
fn rejects_header_alg_mismatch() {
    // Same RSA key, but a different RSA algorithm in the header.
    let t = sign(
        Algorithm::RS384,
        Some("rsa-1"),
        &claims(),
        &EncodingKey::from_rsa_der(RSA_PRIVATE_PKCS1),
    );
    assert_eq!(verify(&t, &default_jwks(), &cfg()), Err(Refusal::BadAlgorithm));
    // ES256 token pointing at the RSA key.
    let t = sign(
        Algorithm::ES256,
        Some("rsa-1"),
        &claims(),
        &EncodingKey::from_ec_der(EC_PRIVATE_PKCS8),
    );
    assert_eq!(verify(&t, &default_jwks(), &cfg()), Err(Refusal::BadAlgorithm));
}

#[test]
fn ignores_oct_key_with_same_kid() {
    let oct = json!({ "kty": "oct", "kid": "rsa-1", "k": b64url(OCT_SECRET) });
    let set = jwks(vec![oct.clone(), rsa_jwk()]);
    let forged =
        sign(Algorithm::HS256, Some("rsa-1"), &claims(), &EncodingKey::from_secret(OCT_SECRET));
    assert_eq!(verify(&forged, &set, &cfg()), Err(Refusal::BadAlgorithm));
    assert_eq!(verify(&rs256(&claims()), &set, &cfg()), Ok("alice".to_owned()));
    // With only the symmetric key published, nothing is usable.
    assert_eq!(verify(&forged, &jwks(vec![oct]), &cfg()), Err(Refusal::UnknownKid));
}

#[test]
fn ignores_odd_jwks_keys() {
    let t = rs256(&claims());
    let mut no_kid = rsa_jwk();
    no_kid.as_object_mut().unwrap().remove("kid");
    let enc_use = with(rsa_jwk(), "use", json!("enc"));
    let other_alg = with(rsa_jwk(), "alg", json!("RS512"));
    for set in [
        jwks(vec![no_kid]),
        jwks(vec![rsa_jwk(), rsa_jwk()]), // duplicate kid: ambiguous
        jwks(vec![enc_use]),
        jwks(vec![other_alg]),
    ] {
        assert_eq!(verify(&t, &set, &cfg()), Err(Refusal::UnknownKid));
    }
    // A matching JWK `alg` is fine.
    let set = jwks(vec![with(rsa_jwk(), "alg", json!("RS256"))]);
    assert_eq!(verify(&t, &set, &cfg()), Ok("alice".to_owned()));

    let t = es256(&claims());
    for crv in ["P-999", "P-384"] {
        let set = jwks(vec![with(ec_jwk(), "crv", json!(crv))]);
        assert_eq!(verify(&t, &set, &cfg()), Err(Refusal::UnknownKid));
    }
}

#[test]
fn unknown_kid_is_unknownkid() {
    let t = sign(
        Algorithm::RS256,
        Some("nope"),
        &claims(),
        &EncodingKey::from_rsa_der(RSA_PRIVATE_PKCS1),
    );
    assert_eq!(header_kid(&t), Ok("nope".to_owned()));
    assert_eq!(verify(&t, &default_jwks(), &cfg()), Err(Refusal::UnknownKid));
}

#[test]
fn rejects_numeric_sub() {
    let t = rs256(&with(claims(), "sub", json!(12345)));
    let err = verify(&t, &default_jwks(), &cfg()).unwrap_err();
    assert!(matches!(err, Refusal::Identity { .. }), "{err:?}");
    assert_eq!(err.authn_id(), None);
    let t = rs256(&with(claims(), "sub", json!("")));
    assert!(matches!(
        verify(&t, &default_jwks(), &cfg()),
        Err(Refusal::Identity { authn_id: None, .. })
    ));
}

fn email_cfg() -> CheckConfig<'static> {
    CheckConfig { identity_claim: "email", ..cfg() }
}

#[test]
fn email_mode_requires_email_verified_true() {
    let base = with(claims(), "email", json!("alice@example.com"));
    let ok = rs256(&with(base.clone(), "email_verified", json!(true)));
    assert_eq!(verify(&ok, &default_jwks(), &email_cfg()), Ok("alice@example.com".to_owned()));

    for t in [rs256(&with(base.clone(), "email_verified", json!(false))), rs256(&base)] {
        let err = verify(&t, &default_jwks(), &email_cfg()).unwrap_err();
        assert!(matches!(err, Refusal::Identity { .. }), "{err:?}");
        assert_eq!(err.log_reason(), "email not verified");
        assert_eq!(err.authn_id(), Some("alice@example.com"));
    }
}

#[test]
fn email_mode_rejects_string_true() {
    let base = with(claims(), "email", json!("alice@example.com"));
    let t = rs256(&with(base, "email_verified", json!("true")));
    let err = verify(&t, &default_jwks(), &email_cfg()).unwrap_err();
    assert_eq!(err.log_reason(), "email not verified");
}

#[test]
fn expired_token_reports_authn_id() {
    let t = rs256(&with(claims(), "exp", json!(now() - 3600)));
    let err = verify(&t, &default_jwks(), &cfg()).unwrap_err();
    assert_eq!(err.authn_id(), Some("alice"));
}

#[test]
fn bad_signature_has_no_authn_id() {
    // Mallory's (expired) payload spliced onto a genuine header and signature.
    let genuine = rs256(&claims());
    let other = rs256(&with(with(claims(), "sub", json!("mallory")), "exp", json!(now() - 3600)));
    let g: Vec<&str> = genuine.split('.').collect();
    let o: Vec<&str> = other.split('.').collect();
    let spliced = format!("{}.{}.{}", g[0], o[1], g[2]);
    let err = verify(&spliced, &default_jwks(), &cfg()).unwrap_err();
    assert_eq!(err, Refusal::BadSignature);
    assert_eq!(err.authn_id(), None);

    let es = es256(&claims());
    let e: Vec<&str> = es.split('.').collect();
    let spliced = format!("{}.{}.{}", e[0], o[1], e[2]);
    assert_eq!(verify(&spliced, &default_jwks(), &cfg()), Err(Refusal::BadSignature));
}

#[test]
fn rejects_malformed_inputs() {
    let valid = rs256(&claims());
    let payload = b64url(claims().to_string().as_bytes());
    let oversized = rs256(&with(claims(), "pad", json!("x".repeat(super::MAX_TOKEN_LEN))));
    let cases = [
        String::new(),
        "a.b".to_owned(),                                          // two segments
        format!("{valid}.AAAA.BBBB"),                              // five segments (JWE shape)
        "!!!!.@@@@.####".to_owned(),                               // bad base64
        format!("{}.{payload}.c2ln", b64url(&[0xff, 0xfe, 0xfd])), // header not UTF-8
        format!("{}.{payload}.c2ln", b64url(b"[1,2,3]")),          // header not an object
        sign(Algorithm::RS256, None, &claims(), &EncodingKey::from_rsa_der(RSA_PRIVATE_PKCS1)), // no kid
        oversized,                                                          // > 16 KiB
        "A".repeat(1 << 20),                                                // 1 MiB of junk
        format!("{}.{}.{}", "A".repeat(1 << 19), "A".repeat(1 << 19), "A"), // 1 MiB, three parts
    ];
    for t in &cases {
        let start = Instant::now();
        assert_eq!(header_kid(t), Err(Refusal::Malformed), "header_kid on {} bytes", t.len());
        assert_eq!(
            verify(t, &default_jwks(), &cfg()),
            Err(Refusal::Malformed),
            "verify on {} bytes",
            t.len()
        );
        assert!(start.elapsed() < Duration::from_millis(50), "slow on {} bytes", t.len());
    }
}

const TID_MISSING: &str = "tid missing (add profile to the pg_hba.conf scope)";
const V1_HINT: &str =
    "issuer mismatch (v1 token: set requestedAccessTokenVersion to 2 in the app manifest)";

fn v1_claims() -> Value {
    with(
        with(claims(), "iss", json!(format!("https://sts.windows.net/{TENANT}/"))),
        "tid",
        json!(TENANT),
    )
}

#[test]
fn entra_accepts_matching_tid() {
    let t = rs256(&with(claims(), "tid", json!(TENANT)));
    assert_eq!(verify(&t, &default_jwks(), &entra_cfg()), Ok("alice".to_owned()));
}

#[test]
fn entra_accepts_tid_other_case() {
    let t = rs256(&with(claims(), "tid", json!(TENANT.to_uppercase())));
    assert_eq!(verify(&t, &default_jwks(), &entra_cfg()), Ok("alice".to_owned()));
}

#[test]
fn entra_rejects_wrong_tid() {
    let t = rs256(&with(claims(), "tid", json!("00000000-0000-0000-0000-000000000000")));
    assert_claims(
        verify(&t, &default_jwks(), &entra_cfg()),
        "tenant (tid) mismatch",
        Some("alice"),
    );
}

#[test]
fn entra_rejects_missing_tid() {
    let t = rs256(&claims());
    assert_claims(verify(&t, &default_jwks(), &entra_cfg()), TID_MISSING, Some("alice"));
}

#[test]
fn entra_rejects_non_string_tid() {
    let t = rs256(&with(claims(), "tid", json!(42)));
    assert_claims(verify(&t, &default_jwks(), &entra_cfg()), TID_MISSING, Some("alice"));
}

#[test]
fn entra_v1_token_gets_hint() {
    let t = rs256(&v1_claims());
    assert_claims(verify(&t, &default_jwks(), &entra_cfg()), V1_HINT, Some("alice"));
}

#[test]
fn v1_issuer_without_entra_is_plain_mismatch() {
    let t = rs256(&v1_claims());
    assert_claims(verify(&t, &default_jwks(), &cfg()), "issuer mismatch", Some("alice"));
}

#[test]
fn generic_ignores_tid() {
    let t = rs256(&with(claims(), "tid", json!("wrong")));
    assert_eq!(verify(&t, &default_jwks(), &cfg()), Ok("alice".to_owned()));
}
