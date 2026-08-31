//! LDAP / Active Directory backend binding plugin for mcpg.
//!
//! Implements [`LdapBackendPlugin`] — `BackendPlugin` for `kind: "ldap"`.
//! Binds a configured service account and runs a directory search whose
//! filter is CEL-templated from the tool arguments (argument values
//! RFC-4515-escaped against filter injection), returning the matched
//! entries as JSON. The bind password resolves through the gateway
//! credential cache via `cred://`. Structurally mirrors the soap/http
//! backends; LDAP-specific machinery lives in [`ldap`] + [`envelope`].

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use mcpg_expr::{DynamicValue, ExprContext, ExprRequestContext};
use mcpg_plugin_protocol::audit::{AuditEvent, AuditOutcome};
use mcpg_plugin_protocol::types::PluginIdentity;
use mcpg_plugin_protocol::{
    BackendError, BackendHost, BackendInvocationContext, BackendPlugin, BackendRequest,
    BackendResponse, PluginManifest, firstparty_manifest,
};
use mcpg_plugin_sdk::{HostHandle, SpanGuard};
use serde_json::{Value, json};
use tokio::sync::RwLock;
use tracing::debug;

/// cdylib sync bridge.
pub mod cdylib;
mod envelope;
mod ldap;
mod types;

use envelope::{build_result_envelope, classify_error};
pub use types::{LdapBackendSpec, LdapScope};

/// Embedded plugin descriptor.
pub const BINDING_DESCRIPTOR_YAML: &str = include_str!("../plugin.yaml");

// --------------------------------------------------------------------- obs

fn audit_action_for_outcome(label: &str) -> Option<&'static str> {
    match label {
        "timeout" => Some("dev.mcpg.backend.ldap.request_timeout"),
        "transport_error" => Some("dev.mcpg.backend.ldap.request_failed"),
        "ldap_error" => Some("dev.mcpg.backend.ldap.search_rejected"),
        "invalid_spec" => Some("dev.mcpg.backend.ldap.request_failed"),
        _ => None,
    }
}

fn rfc3339_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn synthetic_system_identity() -> PluginIdentity {
    PluginIdentity {
        kind: "system".into(),
        trust_level: "verified".into(),
        subject_id: Some("dev.mcpg.backend.ldap".into()),
        auth_provider: None,
        issuer: None,
        roles: vec![],
        groups: vec![],
        scopes: vec![],
        attributes: Default::default(),
    }
}

/// Build an [`ExprContext`] for one call (identity claims → `$context.*`).
/// Local copy of net-core's helper — LDAP doesn't link the HTTP core.
fn build_expr_context(arguments: &Value, tool_name: &str, request: &BackendRequest) -> ExprContext {
    let mut ctx = ExprRequestContext {
        session_id: request.session_id.clone(),
        ..ExprRequestContext::default()
    };
    if let Some(identity) = request.identity.as_ref() {
        ctx.principal_id = identity.subject_id.clone();
        ctx.trust_level = identity.trust_level.clone();
        ctx.auth_provider = identity.auth_provider.clone();
        ctx.transport = identity.kind.clone();
        ctx.roles = identity.roles.clone();
        ctx.groups = identity.groups.clone();
        ctx.scopes = identity.scopes.clone();
        ctx.attributes = identity.attributes.clone();
    }
    ExprContext {
        arguments: arguments.clone(),
        tool_name: tool_name.to_owned(),
        context: ctx,
        steps: None,
        env: Arc::new(HashMap::new()),
    }
}

/// Resolve a `cred://…` bind password through the host per caller. A
/// literal password passes through. Mirrors the net-core map-resolve shape:
/// the whole `bind_password` must be a single `cred://` URI (not embedded).
async fn resolve_bind_password(
    host: &Arc<dyn BackendHost>,
    raw: &str,
    request: &BackendRequest,
    backend_name: &str,
) -> Result<String, String> {
    if !raw.starts_with("cred://") {
        return Ok(raw.to_owned());
    }
    let mut snapshot = serde_json::Map::new();
    snapshot.insert(raw.to_owned(), Value::String(raw.to_owned()));
    let mut snapshot = Value::Object(snapshot);
    let mut ctx = BackendInvocationContext::root(
        request.request_id.clone(),
        request.session_id.clone(),
        backend_name.to_owned(),
    );
    ctx.identity = request.identity.clone();
    host.resolve_credentials(&ctx, &mut snapshot)
        .await
        .map_err(|e| format!("{e:?}"))?;
    snapshot
        .get(raw)
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or_else(|| "bind credential did not resolve".to_owned())
}

fn finalize_payload(envelope: Value) -> Result<BackendResponse, BackendError> {
    let payload = serde_json::to_vec(&envelope).map_err(|e| BackendError::Transport {
        message: format!("LDAP plugin envelope serialization failed: {e}"),
    })?;
    Ok(BackendResponse {
        payload,
        truncated: false,
    })
}

// ------------------------------------------------------------------ plugin

/// Per-binding LDAP runtime — connection + compiled filter + the host
/// (for `cred://` bind-password resolution). Cheap to clone.
#[derive(Clone)]
struct LdapProfile {
    url: String,
    bind_dn: String,
    bind_password: String,
    base_dn: String,
    scope: LdapScope,
    compiled_filter: Arc<DynamicValue<String>>,
    attributes: Vec<String>,
    size_limit: usize,
    timeout: Duration,
    host: Arc<dyn BackendHost>,
}

/// `BackendPlugin` implementation for `kind: "ldap"`.
pub struct LdapBackendPlugin {
    manifest: PluginManifest,
    profiles: RwLock<BTreeMap<String, LdapProfile>>,
    host_handle: OnceLock<HostHandle>,
}

impl Default for LdapBackendPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl LdapBackendPlugin {
    #[must_use]
    pub fn new() -> Self {
        Self {
            manifest: firstparty_manifest! {
                id: "dev.mcpg.backend.ldap",
                name: "LDAP Binding",
                class: Backend,
            },
            profiles: RwLock::new(BTreeMap::new()),
            host_handle: OnceLock::new(),
        }
    }

    pub fn set_host_handle(&self, host: HostHandle) -> bool {
        self.host_handle.set(host).is_ok()
    }

    fn host_handle(&self) -> Option<&HostHandle> {
        self.host_handle.get()
    }

    /// Per-call observability triad (latency + counter + optional audit)
    /// through the installed [`HostHandle`]. No-op when none is installed.
    async fn emit_host_observability(
        &self,
        backend_name: &str,
        outcome_label: &'static str,
        reason: Option<&str>,
        identity: Option<&PluginIdentity>,
        request_id: &str,
        duration: Duration,
    ) {
        let Some(host) = self.host_handle() else {
            return;
        };
        host.histogram(
            "mcpg_ldap_backend_latency_seconds",
            duration.as_secs_f64(),
            &[("outcome", outcome_label)],
        );
        host.counter(
            "mcpg_ldap_backend_calls_total",
            1,
            &[("outcome", outcome_label)],
        );
        if let Some(action) = audit_action_for_outcome(outcome_label) {
            let actor = identity.cloned().unwrap_or_else(synthetic_system_identity);
            let mut details = json!({
                "backend": backend_name,
                "duration_ms": duration.as_millis() as u64,
                "outcome": outcome_label,
                "alias": host.alias(),
            });
            if let Some(reason) = reason {
                details
                    .as_object_mut()
                    .expect("json object")
                    .insert("reason".into(), Value::String(reason.to_owned()));
            }
            let event = AuditEvent {
                event_id: format!("ldap-{}-{}", request_id, duration.as_nanos()),
                occurred_at: rfc3339_now(),
                actor,
                action: action.to_owned(),
                resource: Some(format!("ldap-binding://{backend_name}")),
                outcome: AuditOutcome::Failure,
                request_id: Some(request_id.to_owned()),
                upstream_request_id: None,
                node_id: None,
                details,
                prev_event_hash: None,
            };
            let host_for_audit = host.clone();
            if let Err(join_err) = tokio::task::spawn_blocking(move || {
                let _ = host_for_audit.audit_event(event);
            })
            .await
            {
                debug!(target: "mcpg::ldap::host_handle", error = %join_err, "audit spawn_blocking failed");
            }
        }
    }

    /// Build an error envelope (render / cred-resolution failures), emit the
    /// triad, and return it as a normal payload (structured `downstreamError`
    /// rather than an opaque `Err`) — matching the soap/http backends.
    #[allow(clippy::too_many_arguments)]
    async fn finish_error(
        &self,
        profile: &LdapProfile,
        backend_name: &str,
        tool_name: &str,
        message: &str,
        label: &'static str,
        identity: Option<&PluginIdentity>,
        request_id: &str,
        started: Instant,
        host_span: Option<SpanGuard>,
    ) -> Result<BackendResponse, BackendError> {
        let downstream = classify_error(message);
        let envelope = build_result_envelope(
            tool_name,
            backend_name,
            &profile.url,
            &profile.base_dn,
            profile.scope.as_str(),
            "",
            &profile.attributes,
            None,
            started.elapsed().as_millis(),
            Some(&downstream),
            Some(message),
        );
        self.emit_host_observability(
            backend_name,
            label,
            Some(message),
            identity,
            request_id,
            started.elapsed(),
        )
        .await;
        drop(host_span);
        finalize_payload(envelope)
    }
}

impl std::fmt::Debug for LdapBackendPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LdapBackendPlugin")
            .field("id", &self.manifest.id)
            .finish()
    }
}

#[async_trait]
impl BackendPlugin for LdapBackendPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        "ldap"
    }

    async fn register_profile(
        &self,
        backend_name: &str,
        spec: &Value,
        host: Arc<dyn BackendHost>,
    ) -> Result<(), BackendError> {
        let parsed: LdapBackendSpec =
            serde_json::from_value(spec.clone()).map_err(|e| BackendError::InvalidSpec {
                message: format!("LDAP binding spec: {e}"),
            })?;

        let invalid = |m: String| BackendError::InvalidSpec { message: m };
        if !parsed.url.starts_with("ldap://") && !parsed.url.starts_with("ldaps://") {
            return Err(invalid(format!(
                "url must start with ldap:// or ldaps://, got '{}'",
                parsed.url
            )));
        }
        if parsed.url.starts_with("ldap://") && !parsed.bind_password.is_empty() {
            tracing::warn!(
                backend = %backend_name,
                "ldap: a bind password is sent over a plaintext ldap:// connection — \
                 the credential travels in cleartext. Use ldaps:// (or start_tls) \
                 unless on a trusted network."
            );
        }
        if parsed.bind_dn.trim().is_empty() {
            return Err(invalid("bind_dn must not be empty".into()));
        }
        if parsed.base_dn.trim().is_empty() {
            return Err(invalid("base_dn must not be empty".into()));
        }
        if parsed.filter.trim().is_empty() {
            return Err(invalid("filter must not be empty".into()));
        }
        if parsed.timeout_ms == 0 {
            return Err(invalid("timeout_ms must be greater than 0".into()));
        }
        if parsed.size_limit == 0 {
            return Err(invalid("size_limit must be greater than 0".into()));
        }
        // `cred://` belongs in bind_password (resolved per caller), not the
        // filter (which is CEL-templated from arguments).
        if parsed.filter.contains("cred://") {
            return Err(invalid(
                "filter must not contain cred:// — put bind credentials in bind_password".into(),
            ));
        }

        let compiled_filter = Arc::new(
            DynamicValue::<String>::parse(&parsed.filter)
                .map_err(|e| invalid(format!("filter expression: {e}")))?,
        );

        debug!(
            backend = %backend_name,
            url = %parsed.url,
            base_dn = %parsed.base_dn,
            scope = parsed.scope.as_str(),
            "registered LDAP binding profile"
        );

        self.profiles.write().await.insert(
            backend_name.to_owned(),
            LdapProfile {
                url: parsed.url,
                bind_dn: parsed.bind_dn,
                bind_password: parsed.bind_password,
                base_dn: parsed.base_dn,
                scope: parsed.scope,
                compiled_filter,
                attributes: parsed.attributes,
                size_limit: parsed.size_limit,
                timeout: Duration::from_millis(parsed.timeout_ms),
                host,
            },
        );
        Ok(())
    }

    async fn execute(
        &self,
        backend_name: &str,
        request: BackendRequest,
    ) -> Result<BackendResponse, BackendError> {
        let started = Instant::now();
        let request_id = request.request_id.clone();
        let identity = request.identity.clone();
        let host_span = self.host_handle().map(|h| {
            h.span(
                "ldap_backend.execute",
                json!({ "backend": backend_name, "request_id": request_id }),
            )
        });

        let profile = {
            let guard = self.profiles.read().await;
            match guard.get(backend_name).cloned() {
                Some(p) => p,
                None => {
                    let err = BackendError::ProfileNotFound {
                        backend_name: backend_name.to_owned(),
                    };
                    self.emit_host_observability(
                        backend_name,
                        "profile_not_found",
                        Some(&err.to_string()),
                        identity.as_ref(),
                        &request_id,
                        started.elapsed(),
                    )
                    .await;
                    drop(host_span);
                    return Err(err);
                }
            }
        };

        let arguments: Value = if request.payload.is_empty() {
            json!({})
        } else {
            match serde_json::from_slice(&request.payload) {
                Ok(v) => v,
                Err(e) => {
                    let err = BackendError::InvalidSpec {
                        message: format!("LDAP plugin payload is not valid JSON: {e}"),
                    };
                    self.emit_host_observability(
                        backend_name,
                        "invalid_spec",
                        Some(&err.to_string()),
                        identity.as_ref(),
                        &request_id,
                        started.elapsed(),
                    )
                    .await;
                    drop(host_span);
                    return Err(err);
                }
            }
        };

        let tool_name = request
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("mcpg-tool-name"))
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| backend_name.to_owned());

        // Render the filter against LDAP-escaped arguments (injection-safe).
        let escaped = ldap::escape_arguments(&arguments);
        let filter_ctx = build_expr_context(&escaped, &tool_name, &request);
        let nil_cred = |_uri: &str| None::<String>;
        let resolved_filter = match profile
            .compiled_filter
            .resolve_with_credentials(&filter_ctx, nil_cred)
        {
            Ok(s) => s,
            Err(e) => {
                return self
                    .finish_error(
                        &profile,
                        backend_name,
                        &tool_name,
                        &format!("evaluating filter: {e}"),
                        "invalid_spec",
                        identity.as_ref(),
                        &request_id,
                        started,
                        host_span,
                    )
                    .await;
            }
        };

        let bind_password = match resolve_bind_password(
            &profile.host,
            &profile.bind_password,
            &request,
            backend_name,
        )
        .await
        {
            Ok(p) => p,
            Err(e) => {
                return self
                    .finish_error(
                        &profile,
                        backend_name,
                        &tool_name,
                        &format!("bind credential: {e}"),
                        "invalid_spec",
                        identity.as_ref(),
                        &request_id,
                        started,
                        host_span,
                    )
                    .await;
            }
        };

        let search = ldap::run_search(
            &profile.url,
            &profile.bind_dn,
            &bind_password,
            &profile.base_dn,
            profile.scope.to_ldap3(),
            &resolved_filter,
            &profile.attributes,
            profile.size_limit,
            profile.timeout,
        )
        .await;

        let (envelope, outcome_label, audit_reason): (Value, &'static str, Option<String>) =
            match search {
                Ok(outcome) => (
                    build_result_envelope(
                        &tool_name,
                        backend_name,
                        &profile.url,
                        &profile.base_dn,
                        profile.scope.as_str(),
                        &resolved_filter,
                        &profile.attributes,
                        Some(&outcome.entries),
                        started.elapsed().as_millis(),
                        None,
                        None,
                    ),
                    "ok",
                    None,
                ),
                Err(message) => {
                    let downstream = classify_error(&message);
                    let lower = message.to_ascii_lowercase();
                    let label = if lower.contains("timed out") || lower.contains("timeout") {
                        "timeout"
                    } else if downstream["kind"] == json!("transport_error") {
                        "transport_error"
                    } else {
                        "ldap_error"
                    };
                    let env = build_result_envelope(
                        &tool_name,
                        backend_name,
                        &profile.url,
                        &profile.base_dn,
                        profile.scope.as_str(),
                        &resolved_filter,
                        &profile.attributes,
                        None,
                        started.elapsed().as_millis(),
                        Some(&downstream),
                        Some(&message),
                    );
                    (env, label, Some(message))
                }
            };

        self.emit_host_observability(
            backend_name,
            outcome_label,
            audit_reason.as_deref(),
            identity.as_ref(),
            &request_id,
            started.elapsed(),
        )
        .await;
        drop(host_span);
        finalize_payload(envelope)
    }

    fn audit_metadata(&self, _backend_name: &str) -> serde_json::Map<String, Value> {
        let mut map = serde_json::Map::new();
        map.insert("ldap.transport".to_owned(), json!("plugin"));
        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_op_host() -> Arc<dyn BackendHost> {
        Arc::new(NoOpHost)
    }

    fn minimal_spec() -> Value {
        json!({
            "url": "ldaps://dc.example.com:636",
            "bind_dn": "cn=svc,dc=example,dc=com",
            "bind_password": "cred://vault/svc",
            "base_dn": "ou=people,dc=example,dc=com",
            "filter": "(&(objectClass=person)(cn=*${arguments.q}*))",
        })
    }

    #[test]
    fn kind_is_ldap() {
        assert_eq!(LdapBackendPlugin::new().kind(), "ldap");
    }

    #[test]
    fn manifest_id() {
        assert_eq!(
            LdapBackendPlugin::new().manifest().id,
            "dev.mcpg.backend.ldap"
        );
    }

    #[tokio::test]
    async fn register_accepts_minimal_spec() {
        let plugin = LdapBackendPlugin::new();
        plugin
            .register_profile("people", &minimal_spec(), no_op_host())
            .await
            .expect("register");
        let profiles = plugin.profiles.read().await;
        let p = profiles.get("people").unwrap();
        assert_eq!(p.scope, LdapScope::Subtree);
        assert_eq!(p.base_dn, "ou=people,dc=example,dc=com");
    }

    #[tokio::test]
    async fn register_rejects_non_ldap_scheme() {
        let plugin = LdapBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["url"] = json!("https://x/");
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("non-ldap");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn register_rejects_cred_in_filter() {
        let plugin = LdapBackendPlugin::new();
        let mut spec = minimal_spec();
        spec["filter"] = json!("(cn=cred://x/y)");
        let err = plugin
            .register_profile("x", &spec, no_op_host())
            .await
            .expect_err("cred in filter");
        assert!(matches!(err, BackendError::InvalidSpec { .. }));
    }

    #[tokio::test]
    async fn execute_unknown_profile_is_profile_not_found() {
        let plugin = LdapBackendPlugin::new();
        let req = BackendRequest {
            payload: vec![],
            headers: vec![],
            request_id: "rq-1".into(),
            session_id: None,
            identity: None,
            idempotency: None,
        };
        let err = plugin.execute("missing", req).await.expect_err("missing");
        assert!(matches!(err, BackendError::ProfileNotFound { .. }));
    }

    struct NoOpHost;

    #[async_trait]
    impl BackendHost for NoOpHost {
        async fn invoke_tool(
            &self,
            _ctx: &BackendInvocationContext,
            _tool_name: &str,
            _args: &serde_json::Value,
        ) -> Result<serde_json::Value, mcpg_plugin_protocol::BackendHostError> {
            Err(mcpg_plugin_protocol::BackendHostError::NotImplemented)
        }
    }
}
