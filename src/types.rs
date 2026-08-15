//! Operator-facing spec for the LDAP backend plugin.
//!
//! One binding = one directory search = one MCP tool (or resource). The
//! connection (url + bind credentials) and the search (base/scope/filter/
//! attributes) all live on the per-binding spec, mirroring the http/soap
//! one-profile-per-binding shape.

use serde::Deserialize;

/// LDAP search scope. Defaults to `subtree` (the common "search under this
/// base" case).
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum LdapScope {
    /// The base object only.
    Base,
    /// Immediate children of the base.
    One,
    /// The base and its whole subtree.
    #[default]
    Subtree,
}

impl LdapScope {
    pub fn to_ldap3(self) -> ldap3::Scope {
        match self {
            LdapScope::Base => ldap3::Scope::Base,
            LdapScope::One => ldap3::Scope::OneLevel,
            LdapScope::Subtree => ldap3::Scope::Subtree,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            LdapScope::Base => "base",
            LdapScope::One => "one",
            LdapScope::Subtree => "subtree",
        }
    }
}

/// Operator-facing spec the gateway serializes when calling
/// `register_profile`. Mirrors `LdapBackendConfig` in the gateway crate.
// NOTE: intentionally NOT #[serde(deny_unknown_fields)] — the gateway injects
// the reserved `__mcpg_secret_refs` hint key into this spec at register_profile
// (secret-rotation scoping); denying unknown fields would reject it. The
// operator-facing schema is closed on the gateway-side *BackendConfig instead.
#[derive(Debug, Clone, Deserialize)]
pub struct LdapBackendSpec {
    /// `ldap://host:389` or `ldaps://host:636`. Operator-configured (not
    /// caller-templated), so there is no SSRF/arg-injection vector on the
    /// host itself.
    pub url: String,

    /// Service-account bind DN.
    pub bind_dn: String,

    /// Service-account bind password — a literal, or a `cred://…` URI
    /// resolved through the gateway credential cache at dispatch time.
    pub bind_password: String,

    /// Search base DN.
    pub base_dn: String,

    /// Search scope (default `subtree`).
    #[serde(default)]
    pub scope: LdapScope,

    /// LDAP filter, CEL-templated with `${arguments.*}`. Interpolated
    /// string argument values are RFC 4515 LDAP-escaped to prevent filter
    /// injection.
    pub filter: String,

    /// Attributes to return. Empty = all user attributes (`*`).
    #[serde(default)]
    pub attributes: Vec<String>,

    /// Client-side cap on returned entries (default 100).
    #[serde(default = "default_size_limit")]
    pub size_limit: usize,

    /// Per-call timeout (ms) for connect + bind + search (default 10 s).
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_size_limit() -> usize {
    100
}
fn default_timeout_ms() -> u64 {
    10_000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_defaults_to_subtree() {
        assert_eq!(LdapScope::default(), LdapScope::Subtree);
    }

    #[test]
    fn spec_applies_defaults() {
        let spec: LdapBackendSpec = serde_json::from_value(serde_json::json!({
            "url": "ldaps://dc.example.com:636",
            "bind_dn": "cn=svc,dc=example,dc=com",
            "bind_password": "cred://vault/svc",
            "base_dn": "ou=people,dc=example,dc=com",
            "filter": "(cn=*${arguments.q}*)",
        }))
        .unwrap();
        assert_eq!(spec.scope, LdapScope::Subtree);
        assert_eq!(spec.size_limit, 100);
        assert_eq!(spec.timeout_ms, 10_000);
        assert!(spec.attributes.is_empty());
    }
}
