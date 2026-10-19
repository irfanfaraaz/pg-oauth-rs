//! Pure Rust token checks (JWT parsing, JWKS keys, claim validation) with no Postgres dependency.

use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::jwk::{
    AlgorithmParameters, EllipticCurve, Jwk, JwkSet, KeyAlgorithm, PublicKeyUse,
};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Header, Validation};
use serde_json::Value;

#[cfg(test)]
mod tests;

/// Tokens longer than this are refused before any decoding.
pub const MAX_TOKEN_LEN: usize = 16 * 1024;

/// What a token must satisfy, taken from the HBA line and the settings.
#[derive(Debug, Clone, Copy)]
pub struct CheckConfig<'a> {
    /// Expected `iss`, compared as an exact string.
    pub issuer: &'a str,
    /// Value that `aud` must equal (string) or contain (array).
    pub audience: &'a str,
    /// Claim that becomes `authn_id`.
    pub identity_claim: &'a str,
    /// Grace on `exp` and `nbf`, in seconds.
    pub leeway_secs: u64,
}

/// Why a token was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Not a well-formed three-part JWS, too long, or no `kid`.
    Malformed,
    /// No single usable RSA / EC P-256 key with the token's `kid`.
    UnknownKid,
    /// Header `alg` is not the algorithm the key dictates.
    BadAlgorithm,
    /// The signature does not verify.
    BadSignature,
    /// Signature passed; a standard claim (`exp`, `nbf`, `iss`, `aud`) failed.
    Claims { reason: &'static str, authn_id: Option<String> },
    /// Signature and claims passed; the identity claim is unusable.
    Identity { reason: &'static str, authn_id: Option<String> },
}

impl Refusal {
    /// Short reason for the server log. Never contains token data.
    #[must_use]
    pub fn log_reason(&self) -> &'static str {
        match self {
            Refusal::Malformed => "malformed token",
            Refusal::UnknownKid => "no usable key for the token's kid",
            Refusal::BadAlgorithm => "token alg not allowed for the key",
            Refusal::BadSignature => "bad signature",
            Refusal::Claims { reason, .. } | Refusal::Identity { reason, .. } => reason,
        }
    }

    /// Identity from a token whose signature passed; `None` otherwise.
    #[must_use]
    pub fn authn_id(&self) -> Option<&str> {
        match self {
            Refusal::Claims { authn_id, .. } | Refusal::Identity { authn_id, .. } => {
                authn_id.as_deref()
            }
            _ => None,
        }
    }
}

/// Decode the header without trusting it. Rejects oversized and non-three-part tokens first.
fn header(token: &str) -> Result<Header, Refusal> {
    if token.len() > MAX_TOKEN_LEN || token.split('.').count() != 3 {
        return Err(Refusal::Malformed);
    }
    decode_header(token).map_err(|_| Refusal::Malformed)
}

/// The `kid` from the token header (no trust). Used to look up the key in the JWKS cache.
pub fn header_kid(token: &str) -> Result<String, Refusal> {
    header(token)?.kid.ok_or(Refusal::Malformed)
}

/// The only algorithm a key may be used with, or `None` for keys we never use
/// (symmetric, unknown curve, encryption keys, or a JWK `alg` that disagrees).
fn key_algorithm(jwk: &Jwk) -> Option<Algorithm> {
    let (alg, key_alg) = match &jwk.algorithm {
        AlgorithmParameters::RSA(_) => (Algorithm::RS256, KeyAlgorithm::RS256),
        AlgorithmParameters::EllipticCurve(p) if p.curve == EllipticCurve::P256 => {
            (Algorithm::ES256, KeyAlgorithm::ES256)
        }
        _ => return None,
    };
    if matches!(&jwk.common.public_key_use, Some(u) if *u != PublicKeyUse::Signature) {
        return None;
    }
    match jwk.common.key_algorithm {
        Some(a) if a != key_alg => None,
        _ => Some(alg),
    }
}

/// Exactly one usable key with this `kid`; duplicates are ambiguous and refused.
fn find_key<'a>(jwks: &'a JwkSet, kid: &str) -> Option<(&'a Jwk, Algorithm)> {
    let mut usable = jwks
        .keys
        .iter()
        .filter(|k| k.common.key_id.as_deref() == Some(kid))
        .filter_map(|k| key_algorithm(k).map(|alg| (k, alg)));
    match (usable.next(), usable.next()) {
        (Some(found), None) => Some(found),
        _ => None,
    }
}

fn claims_reason(kind: &ErrorKind) -> &'static str {
    match kind {
        ErrorKind::ExpiredSignature => "token expired",
        ErrorKind::ImmatureSignature => "token not yet valid (nbf)",
        ErrorKind::InvalidIssuer => "issuer mismatch",
        ErrorKind::InvalidAudience => "audience mismatch",
        ErrorKind::MissingRequiredClaim(c) | ErrorKind::InvalidClaimFormat(c) => match c.as_str() {
            "exp" => "exp missing or invalid",
            "nbf" => "nbf invalid",
            "iss" => "iss missing or invalid",
            "aud" => "aud missing or invalid",
            _ => "required claim missing or invalid",
        },
        _ => "claims invalid",
    }
}

/// Verify `token` against `jwks` and `cfg`. Returns the identity (`authn_id`) on success.
pub fn verify(token: &str, jwks: &JwkSet, cfg: &CheckConfig) -> Result<String, Refusal> {
    let hdr = header(token)?;
    let kid = hdr.kid.as_deref().ok_or(Refusal::Malformed)?;
    let (jwk, alg) = find_key(jwks, kid).ok_or(Refusal::UnknownKid)?;
    if hdr.alg != alg {
        return Err(Refusal::BadAlgorithm);
    }
    let key = DecodingKey::from_jwk(jwk).map_err(|_| Refusal::UnknownKid)?;

    // Pass 1: signature only. Everything read from `claims` below is signed by the IdP,
    // so any identity we report on a later refusal comes from a verified token.
    let mut sig_only = Validation::new(alg);
    sig_only.required_spec_claims.clear();
    sig_only.validate_exp = false;
    sig_only.validate_nbf = false;
    sig_only.validate_aud = false;
    let claims = match decode::<Value>(token, &key, &sig_only) {
        Ok(data) => data.claims,
        Err(e) => {
            return Err(match e.kind() {
                ErrorKind::InvalidSignature => Refusal::BadSignature,
                ErrorKind::InvalidAlgorithm => Refusal::BadAlgorithm,
                _ => Refusal::Malformed,
            })
        }
    };
    let id = claims
        .get(cfg.identity_claim)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);

    // Pass 2: standard claims. Re-verifying the signature is cheap and keeps the library's
    // claim rules (aud string/array, numeric exp/nbf, leeway) in one place.
    let mut full = Validation::new(alg);
    full.set_required_spec_claims(&["exp", "iss", "aud"]);
    full.set_issuer(&[cfg.issuer]);
    full.set_audience(&[cfg.audience]);
    full.validate_nbf = true;
    full.leeway = cfg.leeway_secs;
    if let Err(e) = decode::<Value>(token, &key, &full) {
        return Err(Refusal::Claims { reason: claims_reason(e.kind()), authn_id: id });
    }
    // The library also accepts an `iss` array containing the issuer; the spec wants one exact string.
    if claims.get("iss").and_then(Value::as_str) != Some(cfg.issuer) {
        return Err(Refusal::Claims { reason: "issuer mismatch", authn_id: id });
    }

    let Some(id) = id else {
        return Err(Refusal::Identity {
            reason: "identity claim missing or not a non-empty string",
            authn_id: None,
        });
    };
    if cfg.identity_claim == "email" && claims.get("email_verified") != Some(&Value::Bool(true)) {
        return Err(Refusal::Identity { reason: "email not verified", authn_id: Some(id) });
    }
    Ok(id)
}
