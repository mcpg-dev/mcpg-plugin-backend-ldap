//! LDAP-specific machinery: filter-argument escaping, connect/bind/search,
//! and entry → JSON projection.

use std::time::Duration;

use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use serde_json::{Map, Value};

/// RFC 4515 LDAP-escape the string leaves of the tool arguments, so CEL
/// `${arguments.*}` interpolation into the search filter cannot break out
/// of it (filter-injection defense). Numbers / bools / null pass through.
pub fn escape_arguments(value: &Value) -> Value {
    match value {
        Value::String(s) => Value::String(ldap3::ldap_escape(s).into_owned()),
        Value::Array(items) => Value::Array(items.iter().map(escape_arguments).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), escape_arguments(v)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// One returned entry as JSON: `{ "dn": …, "attributes": { attr: [values…] } }`.
/// Attribute values stay arrays (LDAP attributes are inherently
/// multi-valued) for shape stability.
pub fn entry_to_json(entry: SearchEntry) -> Value {
    let mut attrs = Map::new();
    for (name, values) in entry.attrs {
        attrs.insert(
            name,
            Value::Array(values.into_iter().map(Value::String).collect()),
        );
    }
    serde_json::json!({ "dn": entry.dn, "attributes": Value::Object(attrs) })
}

/// Result of a completed search — the matched entries projected to JSON.
pub struct SearchOutcome {
    pub entries: Vec<Value>,
}

/// Connect → bind (service account) → search → project entries to JSON.
/// Returns an error string on any transport / bind / search failure.
#[allow(clippy::too_many_arguments)]
pub async fn run_search(
    url: &str,
    bind_dn: &str,
    bind_password: &str,
    base_dn: &str,
    scope: Scope,
    filter: &str,
    attributes: &[String],
    size_limit: usize,
    timeout: Duration,
) -> Result<SearchOutcome, String> {
    let settings = LdapConnSettings::new().set_conn_timeout(timeout);
    let (conn, mut ldap) = LdapConnAsync::with_settings(settings, url)
        .await
        .map_err(|e| {
            mcpg_plugin_protocol::redact::redact_in_text(&format!("LDAP connect failed: {e}"))
        })?;
    ldap3::drive!(conn);

    ldap.with_timeout(timeout);
    ldap.simple_bind(bind_dn, bind_password)
        .await
        .map_err(|e| {
            mcpg_plugin_protocol::redact::redact_in_text(&format!("LDAP bind failed: {e}"))
        })?
        .success()
        .map_err(|e| {
            mcpg_plugin_protocol::redact::redact_in_text(&format!("LDAP bind rejected: {e}"))
        })?;

    let attrs: Vec<&str> = if attributes.is_empty() {
        vec!["*"]
    } else {
        attributes.iter().map(String::as_str).collect()
    };

    ldap.with_timeout(timeout);
    let (result_entries, _res) = ldap
        .search(base_dn, scope, filter, attrs)
        .await
        .map_err(|e| format!("LDAP search failed: {e}"))?
        .success()
        .map_err(|e| format!("LDAP search rejected: {e}"))?;

    let mut entries = Vec::new();
    for re in result_entries.into_iter().take(size_limit) {
        entries.push(entry_to_json(SearchEntry::construct(re)));
    }
    let _ = ldap.unbind().await;
    Ok(SearchOutcome { entries })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn escapes_filter_metachars_only_on_strings() {
        let escaped = escape_arguments(&json!({ "q": "a)(b*c", "n": 5, "nested": { "x": "(" } }));
        let q = escaped["q"].as_str().unwrap();
        for c in [')', '(', '*'] {
            assert!(!q.contains(c), "unescaped {c} leaked: {q}");
        }
        assert!(q.contains('\\'), "expected backslash escapes: {q}");
        assert_eq!(escaped["n"], json!(5));
        assert!(!escaped["nested"]["x"].as_str().unwrap().contains('('));
    }
}
