//! LDAP structured response envelope — the `BackendResponse.payload` the
//! gateway projects onto `tools/call`. A non-null `downstreamError` slot is
//! the gateway's `is_error` signal (same contract as the http/soap
//! backends).

use serde_json::{Value, json};

/// Build a downstream-error object for the envelope's `downstreamError`
/// slot. `retryable` connectivity/timeout failures get backoff guidance;
/// bind/search rejections do not.
pub fn ldap_downstream_error(kind: &str, message: &str, retryable: bool) -> Value {
    json!({
        "kind": kind,
        "code": format!("mcpg.downstream_ldap.{kind}"),
        "message": message,
        "retryable": retryable,
        "retryClass": if retryable { "with_backoff" } else { "do_not_retry" },
        "suggestedAction": if retryable { "check_directory_connectivity_and_retry" } else { "inspect_ldap_error" },
    })
}

/// Classify a `run_search` error string into a downstream error.
/// Connection-level failures (connect / timeout / dropped connection) are
/// retryable transport errors; bind/search rejections are caller/config
/// problems and are not.
pub fn classify_error(message: &str) -> Value {
    let lower = message.to_ascii_lowercase();
    let retryable = lower.contains("connect")
        || lower.contains("timed out")
        || lower.contains("timeout")
        // ldap3 surfaces a dropped/half-up connection (e.g. a directory
        // still starting) as the connection driver's channel closing.
        || lower.contains("channel closed")
        || lower.contains("recv error")
        || lower.contains("broken pipe")
        || lower.contains("connection reset");
    let kind = if retryable {
        "transport_error"
    } else {
        "ldap_error"
    };
    ldap_downstream_error(kind, message, retryable)
}

/// Build the LDAP structured-content envelope returned as the
/// `BackendResponse.payload`.
#[allow(clippy::too_many_arguments)]
pub fn build_result_envelope(
    tool_name: &str,
    profile_name: &str,
    url: &str,
    base_dn: &str,
    scope: &str,
    resolved_filter: &str,
    attributes: &[String],
    entries: Option<&[Value]>,
    duration_ms: u128,
    downstream_error: Option<&Value>,
    error: Option<&str>,
) -> Value {
    json!({
        "toolName": tool_name,
        "profile": profile_name,
        "request": {
            "url": url,
            "baseDn": base_dn,
            "scope": scope,
            "filter": resolved_filter,
            "attributes": attributes,
        },
        "response": entries.map(|e| json!({
            "entries": e,
            "count": e.len(),
            "durationMs": duration_ms,
        })),
        "downstreamError": downstream_error,
        "downstreamErrors": downstream_error
            .map(|d| vec![d.clone()])
            .unwrap_or_default(),
        "error": error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_failure_is_retryable_transport_error() {
        let e = classify_error("LDAP connect failed: connection refused");
        assert_eq!(e["kind"], json!("transport_error"));
        assert_eq!(e["retryable"], json!(true));
    }

    #[test]
    fn bind_rejection_is_not_retryable() {
        let e = classify_error("LDAP bind rejected: invalidCredentials");
        assert_eq!(e["kind"], json!("ldap_error"));
        assert_eq!(e["retryable"], json!(false));
    }

    #[test]
    fn success_envelope_has_entries_and_null_error() {
        let entries = vec![json!({ "dn": "cn=a" })];
        let env = build_result_envelope(
            "people.search",
            "people",
            "ldaps://dc",
            "ou=people",
            "subtree",
            "(cn=a)",
            &["cn".to_owned()],
            Some(&entries),
            12,
            None,
            None,
        );
        assert_eq!(env["response"]["count"], json!(1));
        assert!(env["downstreamError"].is_null());
    }
}
