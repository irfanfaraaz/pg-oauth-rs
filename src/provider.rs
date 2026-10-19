//! Provider presets: issuer shape checks and the values derived from the issuer.
//! Pure Rust with no Postgres dependency.

/// Which identity provider the `pg_oauth_rs.provider` setting selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    /// No preset: the JWKS URL comes from discovery and the identity claim is `sub`.
    Generic,
    /// Microsoft Entra ID (and Entra External ID).
    Entra,
    /// Okta custom authorization server.
    Okta,
    /// Keycloak realm.
    Keycloak,
}

/// What a preset derives from the HBA issuer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// Built JWKS URL; `None` for `Generic`.
    pub jwks_uri: Option<String>,
    /// Identity claim used when `pg_oauth_rs.identity_claim` is empty.
    pub identity_claim: &'static str,
    /// Entra tenant GUID from the issuer, as written there; `None` for other providers.
    pub entra_tenant: Option<String>,
}

const ENTRA_SHAPE: &str = "pg_oauth_rs.provider is entra but the pg_hba.conf issuer is not https://<host>/<tenant-id>/v2.0";
const OKTA_SHAPE: &str = "pg_oauth_rs.provider is okta but the pg_hba.conf issuer is not https://<host>/oauth2/<server-id>";
const OKTA_ORG_SERVER: &str = "pg_oauth_rs.provider is okta but the issuer has no /oauth2/<server-id>; the Okta org authorization server is not supported, use a custom authorization server";
const KEYCLOAK_SHAPE: &str = "pg_oauth_rs.provider is keycloak but the pg_hba.conf issuer is not https://<host>/realms/<realm>";

/// Check the issuer shape for `provider` and derive its values.
///
/// # Errors
/// `Err` is the "not configured" log detail naming the provider and the expected shape.
pub fn resolve(provider: Provider, issuer: &str) -> Result<Resolved, String> {
    let ok = |jwks_uri: String, identity_claim, entra_tenant| {
        Ok(Resolved { jwks_uri: Some(jwks_uri), identity_claim, entra_tenant })
    };
    match provider {
        Provider::Generic => {
            Ok(Resolved { jwks_uri: None, identity_claim: "sub", entra_tenant: None })
        }
        Provider::Entra => match split(issuer) {
            Some((host, segs)) => match segs.as_slice() {
                [tenant, "v2.0"] if is_guid(tenant) => ok(
                    format!("https://{host}/{tenant}/discovery/v2.0/keys"),
                    "oid",
                    Some((*tenant).to_owned()),
                ),
                _ => Err(ENTRA_SHAPE.to_owned()),
            },
            None => Err(ENTRA_SHAPE.to_owned()),
        },
        Provider::Okta => match split(issuer) {
            Some((_, segs)) if matches!(segs.as_slice(), ["oauth2", _]) => {
                ok(format!("{issuer}/v1/keys"), "sub", None)
            }
            _ if is_okta_org_server(issuer) => Err(OKTA_ORG_SERVER.to_owned()),
            _ => Err(OKTA_SHAPE.to_owned()),
        },
        Provider::Keycloak => match split(issuer) {
            Some((_, segs)) if matches!(segs.as_slice(), [.., "realms", _]) => {
                ok(format!("{issuer}/protocol/openid-connect/certs"), "sub", None)
            }
            _ => Err(KEYCLOAK_SHAPE.to_owned()),
        },
    }
}

/// Split a preset issuer into its host (with any `:port`) and path segments.
/// `None` unless it is `https://`, has no query, fragment or trailing `/`,
/// a non-empty host, and only non-empty path segments.
fn split(issuer: &str) -> Option<(&str, Vec<&str>)> {
    let rest = issuer.strip_prefix("https://")?;
    if rest.contains(['?', '#']) || rest.ends_with('/') {
        return None;
    }
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    if host.is_empty() {
        return None;
    }
    let segs: Vec<&str> = if path.is_empty() { Vec::new() } else { path.split('/').collect() };
    if segs.contains(&"") {
        return None;
    }
    Some((host, segs))
}

/// 8-4-4-4-12 ASCII hex, any case.
fn is_guid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 5
        && parts
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(p, n)| p.len() == n && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// `https://<host>` with at most one trailing `/`: the Okta org server issuer.
fn is_okta_org_server(issuer: &str) -> bool {
    issuer.strip_prefix("https://").is_some_and(|r| {
        let host = r.strip_suffix('/').unwrap_or(r);
        !host.is_empty() && !host.contains(['/', '?', '#'])
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

    use super::{resolve, Provider};

    const T: &str = "6f1c2a3b-4d5e-4f60-8a9b-0c1d2e3f4a5b";

    fn is_err(p: Provider, issuer: &str) -> bool {
        resolve(p, issuer).is_err()
    }

    #[test]
    fn generic_never_fails() {
        let r = resolve(Provider::Generic, "anything").unwrap();
        assert_eq!(r.jwks_uri, None);
        assert_eq!(r.identity_claim, "sub");
        assert_eq!(r.entra_tenant, None);
    }

    #[test]
    fn entra_builds_jwks() {
        let r = resolve(Provider::Entra, &format!("https://login.microsoftonline.com/{T}/v2.0"))
            .unwrap();
        assert_eq!(
            r.jwks_uri.as_deref(),
            Some(format!("https://login.microsoftonline.com/{T}/discovery/v2.0/keys").as_str())
        );
        assert_eq!(r.identity_claim, "oid");
        assert_eq!(r.entra_tenant.as_deref(), Some(T));
    }

    #[test]
    fn entra_uppercase_guid_ok() {
        let up = T.to_uppercase();
        let r = resolve(Provider::Entra, &format!("https://login.microsoftonline.com/{up}/v2.0"))
            .unwrap();
        assert_eq!(r.entra_tenant.as_deref(), Some(up.as_str()));
    }

    #[test]
    fn entra_ciamlogin_ok() {
        let r = resolve(Provider::Entra, &format!("https://{T}.ciamlogin.com/{T}/v2.0")).unwrap();
        assert_eq!(
            r.jwks_uri.as_deref(),
            Some(format!("https://{T}.ciamlogin.com/{T}/discovery/v2.0/keys").as_str())
        );
    }

    #[test]
    fn entra_refuses_common() {
        for t in ["common", "organizations", "consumers"] {
            assert!(is_err(Provider::Entra, &format!("https://login.microsoftonline.com/{t}/v2.0")));
        }
    }

    #[test]
    fn entra_refuses_tenant_domain() {
        assert!(is_err(
            Provider::Entra,
            "https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0"
        ));
    }

    #[test]
    fn entra_refuses_trailing_slash() {
        assert!(is_err(Provider::Entra, &format!("https://login.microsoftonline.com/{T}/v2.0/")));
    }

    #[test]
    fn entra_refuses_v1_issuer() {
        assert!(is_err(Provider::Entra, &format!("https://sts.windows.net/{T}/")));
    }

    #[test]
    fn entra_refuses_http() {
        assert!(is_err(Provider::Entra, &format!("http://login.microsoftonline.com/{T}/v2.0")));
    }

    #[test]
    fn okta_builds_jwks() {
        let r = resolve(Provider::Okta, "https://acme.okta.com/oauth2/default").unwrap();
        assert_eq!(r.jwks_uri.as_deref(), Some("https://acme.okta.com/oauth2/default/v1/keys"));
        assert_eq!(r.identity_claim, "sub");
        assert_eq!(r.entra_tenant, None);
    }

    #[test]
    fn okta_refuses_org_server() {
        for issuer in ["https://acme.okta.com", "https://acme.okta.com/"] {
            let e = resolve(Provider::Okta, issuer).unwrap_err();
            assert!(e.contains("org authorization server"), "{e}");
        }
    }

    #[test]
    fn okta_refuses_extra_segment() {
        assert!(is_err(Provider::Okta, "https://acme.okta.com/oauth2/default/v1"));
    }

    #[test]
    fn okta_refuses_trailing_slash() {
        assert!(is_err(Provider::Okta, "https://acme.okta.com/oauth2/default/"));
    }

    #[test]
    fn keycloak_builds_jwks_with_port() {
        let r = resolve(Provider::Keycloak, "https://keycloak.localtest.me:8443/realms/demo")
            .unwrap();
        assert_eq!(
            r.jwks_uri.as_deref(),
            Some("https://keycloak.localtest.me:8443/realms/demo/protocol/openid-connect/certs")
        );
        assert_eq!(r.identity_claim, "sub");
    }

    #[test]
    fn keycloak_with_prefix_ok() {
        assert!(resolve(Provider::Keycloak, "https://sso.example.com/auth/realms/acme").is_ok());
    }

    #[test]
    fn keycloak_refuses_missing_realm() {
        assert!(is_err(Provider::Keycloak, "https://sso.example.com/realms/"));
        assert!(is_err(Provider::Keycloak, "https://sso.example.com/"));
    }

    #[test]
    fn presets_refuse_query_and_fragment() {
        assert!(is_err(Provider::Okta, "https://acme.okta.com/oauth2/default?x=1"));
        assert!(is_err(Provider::Okta, "https://acme.okta.com/oauth2/default#x"));
    }
}
