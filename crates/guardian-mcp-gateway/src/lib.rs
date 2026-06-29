//! `guardian-mcp-gateway` — the mediation gateway (ROADMAP Task 6.4).
//!
//! This is the primary interception point: a tool call arriving from a harness is
//! normalized into a [`guardian_core::Action`], evaluated by the deterministic
//! policy engine, recorded to the tamper-evident audit log, and then either
//! forwarded to the real upstream tool/MCP server or blocked.
//!
//! The wire transport (an MCP / JSON-RPC server speaking to real clients and
//! upstreams) plugs in on top via the [`Approver`] and [`Upstream`] ports; this
//! crate is the transport-agnostic *logic*, fully testable with a fake upstream.
//!
//! **Fast-path invariant.** The [`Checker`] and the [`Approver`] are invoked
//! **only** for an `ask` decision. The allow/deny path performs no LLM call and
//! no human round-trip — a cross-cutting gate (see `CLAUDE.md` / `evaluation/`).

#![forbid(unsafe_code)]

/// Optional Presidio sidecar detector (ADR-0005) — behind the `presidio` feature.
#[cfg(feature = "presidio")]
pub mod presidio;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use guardian_audit::{AuditEntry, AuditError, AuditLog};
use guardian_broker::DataVault;
use guardian_checker::{Checker, Explanation};
use guardian_core::{Action, ActionContext, ActionId, ActionKind, Capability, Decision};
use guardian_policy::{CompiledPolicy, EvalEnv};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A tool invocation arriving from a harness / MCP client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub tool: String,
    #[serde(default)]
    pub args: Value,
    /// Optional classification hint from a well-behaved adapter. When absent the
    /// gateway falls back to a conservative heuristic (unknown → `Other` → the
    /// policy's restrictive default).
    #[serde(default)]
    pub kind: Option<ActionKind>,
    #[serde(default)]
    pub capability: Option<Capability>,
    /// Session this call belongs to. Scopes the data vault so a tokenized value can
    /// only be detokenized within the session that produced it (never replayed across
    /// sessions). Absent → the shared `"default"` session (single-agent / CLI use).
    #[serde(default)]
    pub session: Option<String>,
}

/// The human's resolution of an `ask` action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalResponse {
    Approved,
    Denied,
}

/// Port: ask the human to resolve an `ask` action (implemented by the daemon/UI).
/// Implementations must fail closed — a timeout or error should map to `Denied`.
#[async_trait::async_trait]
pub trait Approver: Send + Sync {
    async fn request_approval(
        &self,
        action: &Action,
        explanation: &Explanation,
    ) -> ApprovalResponse;
}

/// Port: execute a forwarded tool call against the real upstream tool/MCP server.
#[async_trait::async_trait]
pub trait Upstream: Send + Sync {
    async fn forward(&self, call: &ToolCall) -> Result<Value, String>;
}

/// Port: an **optional** sensitive-data detector (ADR-0005). Given text, it returns the
/// substrings that should be tokenized — e.g. names in free text found by a Presidio /
/// LLM-Guard sidecar. It is **advisory**: a miss just falls back to the deterministic
/// known-values + card detection, and the secret-exfiltration deny rule remains the
/// backstop. The fuzzy NER is delegated here so the deterministic core stays small.
#[async_trait::async_trait]
pub trait PiiDetector: Send + Sync {
    async fn detect(&self, text: &str) -> Vec<String>;
}

/// Routes a tool call to a decision + execution. Implemented in-process by
/// [`Gateway`] and remotely by a daemon bridge, so the MCP server can front
/// either without duplicating protocol handling.
#[async_trait::async_trait]
pub trait ToolRouter: Send + Sync {
    async fn route(&self, call: ToolCall) -> GatewayOutcome;
}

/// What the gateway did with a tool call.
#[derive(Debug, Clone, PartialEq)]
pub enum GatewayOutcome {
    /// Allowed and forwarded; carries the upstream result.
    Allowed(Value),
    /// Allowed and forwarded, but the upstream itself returned an error.
    UpstreamError(String),
    /// Blocked by policy or by the user; carries the reason.
    Blocked(String),
}

/// Deterministic self-protection — hard overrides the gateway applies **before**
/// the policy, so a misconfigured policy can't weaken them (README §5.8/§5.9):
/// (1) a **kill switch** — while the sentinel file exists, every action is denied;
/// (2) **self-protection** — refuse to write/delete Guardian's own files (config,
/// policy, audit, socket, the `.guardian` dir).
#[derive(Default)]
pub struct SelfProtection {
    protected_prefixes: Vec<PathBuf>,
    kill_switch: Option<PathBuf>,
}

impl SelfProtection {
    /// `protected_prefixes`: path prefixes that must never be modified.
    /// `kill_switch`: a sentinel file whose presence denies everything.
    pub fn new(protected_prefixes: Vec<PathBuf>, kill_switch: Option<PathBuf>) -> Self {
        Self {
            protected_prefixes,
            kill_switch,
        }
    }

    /// `Some(reason)` if this action must be hard-denied regardless of policy.
    fn override_deny(&self, action: &Action) -> Option<String> {
        if let Some(ks) = &self.kill_switch {
            if ks.exists() {
                return Some(
                    "Guardian kill switch is engaged — all actions are blocked.".to_string(),
                );
            }
        }
        // Refuse writes/deletes that target Guardian's own files. Paths are
        // normalized (absolutized + `.`/`..` resolved) so a relative or `..`-laden
        // path can't evade the prefix check. (Symlinks still need the OS sandbox.)
        if matches!(action.kind, ActionKind::FileWrite | ActionKind::Delete) {
            if let Some(path) = &action.context.path {
                let target = normalize_abs(Path::new(path));
                if self
                    .protected_prefixes
                    .iter()
                    .any(|p| target.starts_with(normalize_abs(p)))
                {
                    return Some(format!(
                        "Guardian self-protection: refusing to modify its own file ({path})."
                    ));
                }
            }
        }
        None
    }
}

/// Absolutize (against the current dir) and lexically resolve `.`/`..`, so a
/// relative or `..`-laden path cannot slip past a prefix check. Does not resolve
/// symlinks — that residual is left to the OS sandbox (ROADMAP §7.3).
fn normalize_abs(path: &Path) -> PathBuf {
    use std::path::Component;
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(path)
    };
    let mut out = PathBuf::new();
    for comp in abs.components() {
        match comp {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// The mediation gateway: ties the policy engine, Checker, audit log, an
/// [`Approver`], and an [`Upstream`] together.
pub struct Gateway {
    source: String,
    policy: CompiledPolicy,
    checker: Box<dyn Checker>,
    approver: Box<dyn Approver>,
    upstream: Box<dyn Upstream>,
    audit: Mutex<AuditLog>,
    env: EvalEnv,
    self_protection: SelfProtection,
    counter: AtomicU64,
    /// Sensitive values to tokenize in tool results before the agent sees them
    /// (empty = tokenization off, zero overhead). The agent works with opaque tokens
    /// and Guardian restores them only into an authorized outbound call (ADR-0005).
    data_protection: Vec<String>,
    /// Per-session data vaults (token↔value), so a token only resolves in the session
    /// that minted it.
    vaults: Mutex<HashMap<String, DataVault>>,
    /// Optional sidecar detector for fuzzy PII in tool results (ADR-0005).
    pii_detector: Option<Arc<dyn PiiDetector>>,
}

impl Gateway {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source: impl Into<String>,
        policy: CompiledPolicy,
        checker: Box<dyn Checker>,
        approver: Box<dyn Approver>,
        upstream: Box<dyn Upstream>,
        audit: AuditLog,
        env: EvalEnv,
    ) -> Self {
        Self {
            source: source.into(),
            policy,
            checker,
            approver,
            upstream,
            audit: Mutex::new(audit),
            env,
            self_protection: SelfProtection::default(),
            counter: AtomicU64::new(0),
            data_protection: Vec::new(),
            vaults: Mutex::new(HashMap::new()),
            pii_detector: None,
        }
    }

    /// Enable self-protection + kill switch (default: none).
    pub fn with_self_protection(mut self, self_protection: SelfProtection) -> Self {
        self.self_protection = self_protection;
        self
    }

    /// Protect these sensitive values: they are replaced with opaque tokens in tool
    /// results before the agent sees them, and restored only into an authorized
    /// outbound call (ADR-0005). Empty (default) leaves tokenization off.
    pub fn with_data_protection(mut self, values: Vec<String>) -> Self {
        self.data_protection = values;
        self
    }

    /// Attach an optional PII detector sidecar (ADR-0005): detected spans are learned
    /// into the session vault and tokenized along with the known values.
    pub fn with_pii_detector(mut self, detector: Arc<dyn PiiDetector>) -> Self {
        self.pii_detector = Some(detector);
        self
    }

    /// Tokenization runs when there is anything to redact: configured known values
    /// and/or a sidecar detector.
    fn tokenization_on(&self) -> bool {
        !self.data_protection.is_empty() || self.pii_detector.is_some()
    }

    /// The session vault, created (and seeded with the protected values) on first use.
    fn with_vault<T>(&self, session: &str, f: impl FnOnce(&mut DataVault) -> T) -> T {
        let mut vaults = self.vaults.lock().expect("vault mutex poisoned");
        let vault = vaults.entry(session.to_string()).or_insert_with(|| {
            let mut v = DataVault::new();
            for s in &self.data_protection {
                v.learn(s);
            }
            v
        });
        f(vault)
    }

    /// Mediate one tool call: normalize → evaluate → (for `ask` only) explain +
    /// ask the human → record → forward or block.
    pub async fn handle(&self, call: ToolCall) -> GatewayOutcome {
        let action = self.normalize(&call);

        // Deterministic hard overrides, applied before (and never weakened by) the
        // policy: kill switch and self-protection. Recorded as a deny.
        if let Some(reason) = self.self_protection.override_deny(&action) {
            let decision = Decision::Deny {
                reason: reason.clone(),
            };
            // A hard deny is blocked regardless, so a failed audit write here can't
            // fail open — record best-effort.
            let _ = self.record(
                &action,
                &decision,
                Some("self-protection".to_string()),
                None,
                None,
                false,
            );
            return GatewayOutcome::Blocked(reason);
        }

        let outcome = self.policy.evaluate(&action, &self.env);

        // The Checker and Approver are consulted ONLY for `ask`. Allow/deny never
        // touch the LLM or the human (fast-path invariant).
        let (proceed, explanation, user_response) = match &outcome.decision {
            Decision::Allow => (true, None, None),
            Decision::Deny { .. } => (false, None, None),
            Decision::Ask { .. } => {
                let explanation = self.checker.explain(&action).await;
                let approved = self.approver.request_approval(&action, &explanation).await
                    == ApprovalResponse::Approved;
                let response = if approved { "approved" } else { "denied" };
                (approved, Some(explanation), Some(response.to_string()))
            }
        };

        let recorded = self.record(
            &action,
            &outcome.decision,
            outcome.matched_rule.clone(),
            explanation.as_ref(),
            user_response,
            outcome.critical,
        );

        // Fail closed: never forward an allowed action we couldn't durably record
        // (invariant 5 + 7), matching the proxy's behavior.
        if proceed && !recorded {
            return GatewayOutcome::Blocked(
                "Guardian audit log unavailable; action blocked (fail-closed).".to_string(),
            );
        }

        if proceed {
            // Tokenization (ADR-0005), only when enabled. Detokenize the agent's args
            // into real values **only here**, at the authorized egress (the agent only
            // ever held opaque tokens); tokenize sensitive values in the result before
            // it reaches the agent. Per-session vault, so a token can't cross sessions.
            if !self.tokenization_on() {
                return match self.upstream.forward(&call).await {
                    Ok(value) => GatewayOutcome::Allowed(value),
                    Err(err) => GatewayOutcome::UpstreamError(err),
                };
            }
            let session = call.session.clone().unwrap_or_default();
            let real_args = self.with_vault(&session, |v| v.detokenize_json(&call.args));
            let forwarded = ToolCall {
                args: real_args,
                ..call
            };
            match self.upstream.forward(&forwarded).await {
                Ok(value) => {
                    // Optional sidecar (ADR-0005): detect fuzzy PII in the result and
                    // `learn` it so it is tokenized too. A miss just falls back to the
                    // known-values + card detection — the sidecar is advisory.
                    if let Some(det) = &self.pii_detector {
                        for found in det.detect(&value.to_string()).await {
                            self.with_vault(&session, |v| v.learn(&found));
                        }
                    }
                    let redacted = self.with_vault(&session, |v| v.tokenize_json(&value));
                    GatewayOutcome::Allowed(redacted)
                }
                Err(err) => GatewayOutcome::UpstreamError(err),
            }
        } else {
            let reason = match &outcome.decision {
                Decision::Deny { reason } => reason.clone(),
                _ => "Denied by the user.".to_string(),
            };
            GatewayOutcome::Blocked(reason)
        }
    }

    /// Verify the integrity of the gateway's audit log.
    pub fn audit_verify(&self) -> Result<(), AuditError> {
        self.audit.lock().expect("audit mutex poisoned").verify()
    }

    /// Number of entries recorded so far.
    pub fn audit_len(&self) -> u64 {
        self.audit
            .lock()
            .expect("audit mutex poisoned")
            .len()
            .unwrap_or(0)
    }

    /// The most recent `limit` audit entries (oldest-first) — the agent's activity
    /// archive, for the cockpit's history view. Empty if the log can't be read.
    pub fn audit_tail(&self, limit: usize) -> Vec<AuditEntry> {
        self.audit
            .lock()
            .expect("audit mutex poisoned")
            .tail(limit)
            .map(|rows| rows.into_iter().map(|(_, e)| e).collect())
            .unwrap_or_default()
    }

    /// Record a decision. Returns `false` if it could not be durably persisted
    /// (poisoned lock or DB error) so the caller can **fail closed** on the critical
    /// path rather than forward an unlogged allow (invariant 5 + 7).
    #[allow(clippy::too_many_arguments)]
    fn record(
        &self,
        action: &Action,
        decision: &Decision,
        matched_rule: Option<String>,
        explanation: Option<&Explanation>,
        user_response: Option<String>,
        critical: bool,
    ) -> bool {
        let entry = AuditEntry::for_decision(
            action,
            decision,
            matched_rule,
            explanation.map(|e| e.rationale.clone()),
            user_response,
            critical,
        );
        match self.audit.lock() {
            Ok(mut log) => log.append(&entry).is_ok(),
            Err(_) => false,
        }
    }

    fn normalize(&self, call: &ToolCall) -> Action {
        let id = ActionId::new(format!(
            "act-{}",
            self.counter.fetch_add(1, Ordering::Relaxed)
        ));
        build_action(call, self.source.clone(), id, now_ms())
    }
}

#[async_trait::async_trait]
impl ToolRouter for Gateway {
    async fn route(&self, call: ToolCall) -> GatewayOutcome {
        self.handle(call).await
    }
}

/// Normalize a [`ToolCall`] into an [`Action`]: infer `kind`/`capability` when
/// the adapter gives no hint, and lift `host`/`path` from args. Exposed so other
/// front-ends (e.g. `guardian decide`) classify actions identically.
pub fn build_action(
    call: &ToolCall,
    source: impl Into<String>,
    id: ActionId,
    timestamp_ms: i64,
) -> Action {
    let kind = call.kind.unwrap_or_else(|| infer_kind(&call.tool));
    let capability = call.capability.or_else(|| infer_capability(kind));
    Action {
        id,
        kind,
        tool: call.tool.clone(),
        args: call.args.clone(),
        capability,
        context: ActionContext {
            timestamp_ms,
            source: source.into(),
            session: None,
            // Lift common fields the policy references into context.
            host: str_arg(&call.args, "host"),
            principal: None,
            path: str_arg(&call.args, "path"),
            extra: serde_json::Map::new(),
        },
    }
}

fn str_arg(args: &Value, key: &str) -> Option<String> {
    args.get(key).and_then(|v| v.as_str()).map(String::from)
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Conservative heuristic mapping a tool name to an [`ActionKind`] when the
/// adapter gives no explicit hint. Unknown tools map to `Other`, which hits the
/// policy's restrictive default — fail safe.
fn infer_kind(tool: &str) -> ActionKind {
    let t = tool.to_ascii_lowercase();
    if t.contains("payment") || t.contains("transfer") || t.contains("pay") {
        ActionKind::Payment
    } else if t.contains("delete") || t.contains("remove") {
        ActionKind::Delete
    } else if t.contains("email") || t.contains("mail") {
        ActionKind::Email
    } else if t.contains("exec") || t.contains("shell") || t.contains("bash") || t.contains("run") {
        ActionKind::Exec
    } else if t.contains("http") || t.contains("fetch") || t.contains("request") {
        ActionKind::HttpRequest
    } else if t.contains("write") || t.contains("create") || t.contains("edit") {
        ActionKind::FileWrite
    } else if t.contains("read") || t.contains("open") {
        ActionKind::FileRead
    } else {
        ActionKind::Other
    }
}

fn infer_capability(kind: ActionKind) -> Option<Capability> {
    match kind {
        ActionKind::Payment => Some(Capability::Payment),
        ActionKind::Delete => Some(Capability::IrreversibleDelete),
        ActionKind::Email => Some(Capability::Messaging),
        ActionKind::HttpRequest => Some(Capability::Network),
        ActionKind::FileRead | ActionKind::FileWrite => Some(Capability::Filesystem),
        ActionKind::Exec | ActionKind::Other => None,
    }
}

/// A minimal MCP server (JSON-RPC 2.0 over stdio) that fronts a [`Gateway`].
///
/// Handles `initialize`, `tools/list`, `ping`, and `tools/call`. Each
/// `tools/call` is routed through the gateway, so a real MCP client (any harness
/// that speaks MCP over stdio) is mediated by Guardian: `Allow` returns the tool
/// result, `Deny` returns a JSON-RPC error, and an upstream failure returns a
/// tool result with `isError: true`.
pub mod mcp {
    use std::collections::HashMap;

    use serde::Serialize;
    use serde_json::{json, Value};

    use super::{ActionKind, GatewayOutcome, ToolCall, ToolRouter};

    /// A tool advertised in `tools/list`.
    #[derive(Debug, Clone, Serialize)]
    pub struct ToolSpec {
        pub name: String,
        pub description: String,
        #[serde(rename = "inputSchema")]
        pub input_schema: Value,
    }

    /// An MCP server fronting a [`ToolRouter`] (the in-process gateway, or a
    /// bridge to a running daemon).
    pub struct McpServer {
        router: Box<dyn ToolRouter>,
        tools: Vec<ToolSpec>,
        /// Trusted tool-name → ActionKind classification. A tool NOT in this map is
        /// classified `Other` (the restrictive default) — never inferred from its
        /// (untrusted) name, so a proxied upstream tool cannot fail open to allow.
        classifier: HashMap<String, ActionKind>,
        name: String,
        version: String,
    }

    impl McpServer {
        pub fn new(router: Box<dyn ToolRouter>, tools: Vec<ToolSpec>) -> Self {
            Self {
                router,
                tools,
                classifier: HashMap::new(),
                name: "guardian".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            }
        }

        /// Set the trusted tool→kind classification (the host's known-safe tools).
        /// Tools left unmapped are evaluated as `Other` — fail safe.
        pub fn with_classifier(mut self, classifier: HashMap<String, ActionKind>) -> Self {
            self.classifier = classifier;
            self
        }

        /// Handle one JSON-RPC message line. Returns the response line, or `None`
        /// for a notification (a message without an `id`).
        pub async fn handle_line(&self, line: &str) -> Option<String> {
            let request: Value = match serde_json::from_str(line) {
                Ok(value) => value,
                Err(_) => return Some(error_line(Value::Null, -32700, "parse error")),
            };
            let id = request.get("id").cloned();
            if matches!(id, None | Some(Value::Null)) {
                // Notifications (e.g. notifications/initialized) get no response.
                return None;
            }
            let id = id.unwrap_or(Value::Null);
            let method = request.get("method").and_then(Value::as_str).unwrap_or("");
            let params = request.get("params").cloned().unwrap_or(Value::Null);
            match self.dispatch(method, params).await {
                Ok(result) => Some(success_line(id, result)),
                Err((code, message)) => Some(error_line(id, code, &message)),
            }
        }

        async fn dispatch(&self, method: &str, params: Value) -> Result<Value, (i64, String)> {
            match method {
                "initialize" => {
                    let version = params
                        .get("protocolVersion")
                        .and_then(Value::as_str)
                        .unwrap_or("2024-11-05")
                        .to_string();
                    Ok(json!({
                        "protocolVersion": version,
                        "capabilities": { "tools": {} },
                        "serverInfo": { "name": self.name, "version": self.version },
                    }))
                }
                "tools/list" => Ok(json!({ "tools": self.tools })),
                "ping" => Ok(json!({})),
                "tools/call" => self.tools_call(params).await,
                other => Err((-32601, format!("method not found: {other}"))),
            }
        }

        async fn tools_call(&self, params: Value) -> Result<Value, (i64, String)> {
            let name = params
                .get("name")
                .and_then(Value::as_str)
                .ok_or((-32602, "missing tool name".to_string()))?
                .to_string();
            let args = params.get("arguments").cloned().unwrap_or(Value::Null);
            // Classify from the trusted map; an unmapped tool is `Other` (restrictive
            // default), never inferred from its name — upholds the no-fail-open gate.
            let kind = self
                .classifier
                .get(&name)
                .copied()
                .unwrap_or(ActionKind::Other);
            let call = ToolCall {
                tool: name,
                args,
                kind: Some(kind),
                capability: None,
                session: None,
            };
            match self.router.route(call).await {
                GatewayOutcome::Allowed(value) => Ok(json!({
                    "content": [{ "type": "text", "text": value.to_string() }],
                    "isError": false,
                })),
                GatewayOutcome::UpstreamError(error) => Ok(json!({
                    "content": [{ "type": "text", "text": format!("tool error: {error}") }],
                    "isError": true,
                })),
                GatewayOutcome::Blocked(reason) => {
                    Err((-32000, format!("Blocked by Guardian: {reason}")))
                }
            }
        }

        /// Run the server over stdin/stdout until end of input.
        pub async fn serve_stdio(&self) -> std::io::Result<()> {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
            let mut lines = BufReader::new(tokio::io::stdin()).lines();
            let mut stdout = tokio::io::stdout();
            while let Some(line) = lines.next_line().await? {
                if line.trim().is_empty() {
                    continue;
                }
                if let Some(response) = self.handle_line(&line).await {
                    stdout.write_all(response.as_bytes()).await?;
                    stdout.write_all(b"\n").await?;
                    stdout.flush().await?;
                }
            }
            Ok(())
        }
    }

    fn success_line(id: Value, result: Value) -> String {
        json!({ "jsonrpc": "2.0", "id": id, "result": result }).to_string()
    }

    fn error_line(id: Value, code: i64, message: &str) -> String {
        json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
            .to_string()
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{ApprovalResponse, Approver, Gateway, Upstream};
        use guardian_audit::AuditLog;
        use guardian_checker::{Explanation, StubChecker};
        use guardian_core::Action;
        use guardian_policy::{CompiledPolicy, EvalEnv};

        struct Echo;
        #[async_trait::async_trait]
        impl Upstream for Echo {
            async fn forward(&self, call: &ToolCall) -> Result<Value, String> {
                Ok(json!({ "ran": call.tool }))
            }
        }

        struct DenyAsks;
        #[async_trait::async_trait]
        impl Approver for DenyAsks {
            async fn request_approval(&self, _: &Action, _: &Explanation) -> ApprovalResponse {
                ApprovalResponse::Denied
            }
        }

        const POLICY: &str = r#"
version = 1
role = "t"
[defaults]
decision = "ask"
[[rules]]
id = "read"
when = 'action.kind == "FileRead"'
decision = "allow"
[[rules]]
id = "deny-exec"
when = 'action.kind == "Exec"'
decision = "deny"
"#;

        fn server() -> McpServer {
            let gateway = Box::new(Gateway::new(
                "mcp-test",
                CompiledPolicy::from_toml_str(POLICY).unwrap(),
                Box::new(StubChecker),
                Box::new(DenyAsks),
                Box::new(Echo),
                AuditLog::open_in_memory().unwrap(),
                EvalEnv::default(),
            ));
            McpServer::new(
                gateway,
                vec![ToolSpec {
                    name: "read_file".to_string(),
                    description: "Read a file".to_string(),
                    input_schema: json!({ "type": "object" }),
                }],
            )
            .with_classifier(HashMap::from([
                ("read_file".to_string(), ActionKind::FileRead),
                ("run_shell".to_string(), ActionKind::Exec),
            ]))
        }

        #[tokio::test]
        async fn initialize_returns_server_info() {
            let resp = server()
                .handle_line(
                    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}"#,
                )
                .await
                .unwrap();
            assert!(resp.contains("serverInfo"));
            assert!(resp.contains("guardian"));
            assert!(resp.contains("2024-11-05"));
        }

        #[tokio::test]
        async fn tools_list_includes_the_tool() {
            let resp = server()
                .handle_line(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#)
                .await
                .unwrap();
            assert!(resp.contains("read_file"));
            assert!(resp.contains("inputSchema"));
        }

        #[tokio::test]
        async fn allowed_call_returns_result() {
            let resp = server()
                .handle_line(
                    r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{}}}"#,
                )
                .await
                .unwrap();
            assert!(resp.contains(r#""isError":false"#), "got {resp}");
            assert!(resp.contains("ran"), "got {resp}");
        }

        #[tokio::test]
        async fn denied_call_returns_jsonrpc_error() {
            // "run_shell" → inferred Exec → policy denies.
            let resp = server()
                .handle_line(
                    r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"run_shell","arguments":{}}}"#,
                )
                .await
                .unwrap();
            assert!(resp.contains(r#""error""#), "got {resp}");
            assert!(resp.contains("Blocked by Guardian"), "got {resp}");
        }

        #[tokio::test]
        async fn unmapped_tool_is_not_auto_allowed() {
            // A tool named like a reader but absent from the classifier must NOT be
            // auto-allowed: it is classified Other → restrictive default → blocked.
            let resp = server()
                .handle_line(
                    r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"sneaky_read","arguments":{}}}"#,
                )
                .await
                .unwrap();
            assert!(resp.contains(r#""error""#), "got {resp}");
            assert!(resp.contains("Blocked by Guardian"), "got {resp}");
        }

        #[tokio::test]
        async fn notification_has_no_response() {
            let resp = server()
                .handle_line(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
                .await;
            assert!(resp.is_none());
        }

        #[tokio::test]
        async fn unknown_method_is_method_not_found() {
            let resp = server()
                .handle_line(r#"{"jsonrpc":"2.0","id":5,"method":"bogus"}"#)
                .await
                .unwrap();
            assert!(resp.contains("-32601"), "got {resp}");
        }
    }
}

/// A generic **upstream MCP client** over stdio: spawns an MCP server process,
/// performs the handshake, discovers its tools, and forwards `tools/call`s. This
/// turns the gateway into a real MCP **proxy** — it can front any stdio MCP server
/// (ROADMAP §7.5), not only the built-in tools.
pub mod upstream {
    use std::collections::HashMap;
    use std::process::Stdio;
    use std::sync::atomic::{AtomicI64, Ordering};

    use serde_json::{json, Value};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
    use tokio::process::{Child, ChildStdin, ChildStdout, Command};
    use tokio::sync::Mutex;

    use crate::mcp::ToolSpec;
    use crate::{ToolCall, Upstream};

    /// Namespace separator for multi-server aggregation (matches the MCP
    /// convention, e.g. `server__tool`).
    const SEP: &str = "__";

    /// `label__tool` (or just `tool` for the unlabeled single-server case).
    pub fn namespaced_name(label: &str, tool: &str) -> String {
        if label.is_empty() {
            tool.to_string()
        } else {
            format!("{label}{SEP}{tool}")
        }
    }

    /// Resolve a (possibly namespaced) tool name to `(label, real_tool)` given
    /// which labels exist. A namespaced name routes to its server; otherwise it
    /// falls back to the unlabeled server (`""`) if present.
    fn route(name: &str, known: impl Fn(&str) -> bool) -> Option<(&str, &str)> {
        if let Some((label, tool)) = name.split_once(SEP) {
            if known(label) {
                return Some((label, tool));
            }
        }
        if known("") {
            Some(("", name))
        } else {
            None
        }
    }

    /// An MCP server reached over a child process's stdio. Requests are serialized
    /// (one in flight at a time) for simplicity and correctness.
    pub struct McpStdioUpstream {
        conn: Mutex<Conn>,
        tools: Vec<ToolSpec>,
        id_counter: AtomicI64,
    }

    struct Conn {
        // Kept alive (and killed on drop) for the lifetime of the proxy.
        _child: Child,
        stdin: ChildStdin,
        stdout: Lines<BufReader<ChildStdout>>,
    }

    impl McpStdioUpstream {
        /// Spawn `program args...`, handshake, and discover the upstream's tools.
        pub async fn spawn(program: &str, args: &[String]) -> Result<Self, String> {
            let mut child = Command::new(program)
                .args(args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .kill_on_drop(true)
                .spawn()
                .map_err(|e| format!("failed to spawn upstream `{program}`: {e}"))?;
            let stdin = child.stdin.take().ok_or("upstream has no stdin")?;
            let stdout = child.stdout.take().ok_or("upstream has no stdout")?;
            let conn = Conn {
                _child: child,
                stdin,
                stdout: BufReader::new(stdout).lines(),
            };
            let mut up = Self {
                conn: Mutex::new(conn),
                tools: Vec::new(),
                id_counter: AtomicI64::new(1),
            };
            up.request(
                "initialize",
                json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": { "name": "guardian", "version": env!("CARGO_PKG_VERSION") },
                }),
            )
            .await?;
            up.notify("notifications/initialized").await?;
            let listed = up.request("tools/list", json!({})).await?;
            up.tools = parse_tools(&listed);
            Ok(up)
        }

        /// The tools discovered upstream (to re-advertise downstream).
        pub fn tools(&self) -> Vec<ToolSpec> {
            self.tools.clone()
        }

        async fn request(&self, method: &str, params: Value) -> Result<Value, String> {
            let id = self.id_counter.fetch_add(1, Ordering::Relaxed);
            let line = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
                .to_string();
            let mut conn = self.conn.lock().await;
            write_line(&mut conn.stdin, &line).await?;
            // Read until the response with our id (skipping notifications / other ids).
            loop {
                let line = conn
                    .stdout
                    .next_line()
                    .await
                    .map_err(|e| e.to_string())?
                    .ok_or("upstream closed the connection")?;
                let Ok(v) = serde_json::from_str::<Value>(&line) else {
                    continue; // ignore non-JSON noise on stdout
                };
                if v.get("id").and_then(Value::as_i64) != Some(id) {
                    continue;
                }
                if let Some(err) = v.get("error") {
                    let msg = err
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or("upstream error");
                    return Err(msg.to_string());
                }
                return Ok(v.get("result").cloned().unwrap_or(Value::Null));
            }
        }

        async fn notify(&self, method: &str) -> Result<(), String> {
            let line = json!({ "jsonrpc": "2.0", "method": method }).to_string();
            let mut conn = self.conn.lock().await;
            write_line(&mut conn.stdin, &line).await
        }
    }

    async fn write_line(stdin: &mut ChildStdin, line: &str) -> Result<(), String> {
        stdin
            .write_all(line.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        stdin.write_all(b"\n").await.map_err(|e| e.to_string())?;
        stdin.flush().await.map_err(|e| e.to_string())
    }

    /// Parse a `tools/list` result into `ToolSpec`s (best-effort; skips malformed).
    pub fn parse_tools(result: &Value) -> Vec<ToolSpec> {
        result
            .get("tools")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|t| {
                        Some(ToolSpec {
                            name: t.get("name")?.as_str()?.to_string(),
                            description: t
                                .get("description")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_string(),
                            input_schema: t
                                .get("inputSchema")
                                .cloned()
                                .unwrap_or_else(|| json!({ "type": "object" })),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    #[async_trait::async_trait]
    impl Upstream for McpStdioUpstream {
        async fn forward(&self, call: &ToolCall) -> Result<Value, String> {
            self.request(
                "tools/call",
                json!({ "name": call.tool, "arguments": call.args }),
            )
            .await
        }
    }

    /// Several upstream MCP servers behind one proxy. Tools are aggregated and
    /// namespaced (`label__tool`); a `tools/call` is routed to the owning server
    /// with the namespace stripped. One server may use the empty label (no prefix).
    #[derive(Default)]
    pub struct MultiUpstream {
        servers: HashMap<String, McpStdioUpstream>,
    }

    impl MultiUpstream {
        pub fn new() -> Self {
            Self::default()
        }

        /// Add a server under `label`. Returns `false` if the label is taken.
        pub fn add(&mut self, label: String, server: McpStdioUpstream) -> bool {
            if self.servers.contains_key(&label) {
                return false;
            }
            self.servers.insert(label, server);
            true
        }

        /// The aggregated, namespaced tool list to advertise downstream.
        pub fn tools(&self) -> Vec<ToolSpec> {
            let mut out = Vec::new();
            for (label, server) in &self.servers {
                for tool in server.tools() {
                    out.push(ToolSpec {
                        name: namespaced_name(label, &tool.name),
                        description: tool.description,
                        input_schema: tool.input_schema,
                    });
                }
            }
            out
        }
    }

    #[async_trait::async_trait]
    impl Upstream for MultiUpstream {
        async fn forward(&self, call: &ToolCall) -> Result<Value, String> {
            let (label, tool) = route(&call.tool, |l| self.servers.contains_key(l))
                .ok_or_else(|| format!("no upstream server routes tool '{}'", call.tool))?;
            let server = self
                .servers
                .get(label)
                .ok_or_else(|| format!("no upstream server '{label}'"))?;
            server
                .forward(&ToolCall {
                    tool: tool.to_string(),
                    args: call.args.clone(),
                    kind: None,
                    capability: None,
                    session: None,
                })
                .await
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parse_tools_reads_names_and_skips_malformed() {
            let listed = json!({
                "tools": [
                    { "name": "read_file", "description": "Read", "inputSchema": { "type": "object" } },
                    { "description": "no name -> skipped" },
                    { "name": "run_shell" }
                ]
            });
            let tools = parse_tools(&listed);
            let names: Vec<_> = tools.iter().map(|t| t.name.as_str()).collect();
            assert_eq!(names, vec!["read_file", "run_shell"]);
        }

        #[test]
        fn namespacing_roundtrips() {
            assert_eq!(namespaced_name("files", "read"), "files__read");
            assert_eq!(namespaced_name("", "read"), "read"); // unlabeled: no prefix
        }

        #[test]
        fn route_resolves_namespace_and_falls_back() {
            let known = |l: &str| matches!(l, "a" | "b");
            assert_eq!(route("a__read_file", known), Some(("a", "read_file")));
            // Unknown label and no unlabeled server -> unroutable.
            assert_eq!(route("z__x", known), None);

            let with_unlabeled = |l: &str| matches!(l, "" | "a");
            // A bare name falls back to the unlabeled server.
            assert_eq!(route("read_file", with_unlabeled), Some(("", "read_file")));
            // A "__"-containing name whose label is unknown also falls back, intact.
            assert_eq!(route("foo__bar", with_unlabeled), Some(("", "foo__bar")));
            // A known namespace still routes (stripped).
            assert_eq!(route("a__x", with_unlabeled), Some(("a", "x")));
        }
    }
}

/// Compile-time guarantee that the gateway can be shared across async tasks
/// (e.g. behind an `Arc` in the daemon's IPC server).
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Gateway>();
};

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const POLICY: &str = r#"
version = 1
role = "t"
[defaults]
decision = "ask"
[[rules]]
id = "read"
when = 'action.kind == "FileRead"'
decision = "allow"
[[rules]]
id = "deny-exec"
when = 'action.kind == "Exec"'
decision = "deny"
explain = "Running shell commands is blocked here."
[[rules]]
id = "ask-email"
when = 'action.kind == "Email"'
decision = "ask"
explain = "Sends an email on your behalf."
"#;

    /// Records every forwarded tool name so tests can assert what was/ wasn't sent.
    struct RecordingUpstream {
        forwarded: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait::async_trait]
    impl Upstream for RecordingUpstream {
        async fn forward(&self, call: &ToolCall) -> Result<Value, String> {
            self.forwarded.lock().unwrap().push(call.tool.clone());
            Ok(serde_json::json!({ "ok": true }))
        }
    }

    struct AutoApprove;
    #[async_trait::async_trait]
    impl Approver for AutoApprove {
        async fn request_approval(&self, _: &Action, _: &Explanation) -> ApprovalResponse {
            ApprovalResponse::Approved
        }
    }

    struct AutoDeny;
    #[async_trait::async_trait]
    impl Approver for AutoDeny {
        async fn request_approval(&self, _: &Action, _: &Explanation) -> ApprovalResponse {
            ApprovalResponse::Denied
        }
    }

    /// A Checker that must never be called on the allow/deny fast path.
    struct PanicChecker;
    #[async_trait::async_trait]
    impl Checker for PanicChecker {
        async fn explain(&self, _: &Action) -> Explanation {
            panic!("the Checker must not run on the allow/deny fast path");
        }
    }

    fn gateway_with(
        approver: Box<dyn Approver>,
        checker: Box<dyn Checker>,
    ) -> (Gateway, Arc<Mutex<Vec<String>>>) {
        let forwarded = Arc::new(Mutex::new(Vec::new()));
        let upstream = Box::new(RecordingUpstream {
            forwarded: forwarded.clone(),
        });
        let gw = Gateway::new(
            "test",
            CompiledPolicy::from_toml_str(POLICY).unwrap(),
            checker,
            approver,
            upstream,
            AuditLog::open_in_memory().unwrap(),
            EvalEnv::default(),
        );
        (gw, forwarded)
    }

    fn call(tool: &str, kind: ActionKind) -> ToolCall {
        ToolCall {
            tool: tool.to_string(),
            args: serde_json::json!({}),
            kind: Some(kind),
            capability: None,
            session: None,
        }
    }

    #[tokio::test]
    async fn allow_forwards_to_upstream() {
        let (gw, forwarded) =
            gateway_with(Box::new(AutoDeny), Box::new(guardian_checker::StubChecker));
        let out = gw.handle(call("fs.read", ActionKind::FileRead)).await;
        assert!(matches!(out, GatewayOutcome::Allowed(_)));
        assert_eq!(*forwarded.lock().unwrap(), vec!["fs.read".to_string()]);
    }

    // --- Data-vault tokenization wired into the gateway (ADR-0005) ---------------

    /// Returns the user's IBAN on "read"; on any other tool records the args it was
    /// actually given (so a test can assert detokenization happened at egress).
    struct PiiUpstream {
        last_args: Arc<Mutex<Value>>,
    }
    #[async_trait::async_trait]
    impl Upstream for PiiUpstream {
        async fn forward(&self, call: &ToolCall) -> Result<Value, String> {
            *self.last_args.lock().unwrap() = call.args.clone();
            if call.tool == "read" {
                Ok(json!({ "iban": "IT60X0542811101000000123456" }))
            } else {
                Ok(json!({ "ok": true }))
            }
        }
    }

    fn protected_gateway() -> (Gateway, Arc<Mutex<Value>>) {
        let last = Arc::new(Mutex::new(Value::Null));
        let policy = CompiledPolicy::from_toml_str(
            "version=1\nrole=\"t\"\n[defaults]\ndecision=\"ask\"\n[[rules]]\nid=\"all\"\nwhen='true'\ndecision=\"allow\"\n",
        )
        .unwrap();
        let gw = Gateway::new(
            "test",
            policy,
            Box::new(guardian_checker::StubChecker),
            Box::new(AutoApprove),
            Box::new(PiiUpstream {
                last_args: last.clone(),
            }),
            AuditLog::open_in_memory().unwrap(),
            EvalEnv::default(),
        )
        .with_data_protection(vec!["IT60X0542811101000000123456".to_string()]);
        (gw, last)
    }

    fn rd(tool: &str, args: Value, session: &str) -> ToolCall {
        ToolCall {
            tool: tool.to_string(),
            args,
            kind: Some(ActionKind::FileRead),
            capability: None,
            session: Some(session.to_string()),
        }
    }

    #[tokio::test]
    async fn result_is_tokenized_to_the_agent_and_detokenized_at_egress() {
        let (gw, last) = protected_gateway();
        // 1) A tool result carrying the IBAN comes back tokenized — the agent never sees it.
        let out = gw.handle(rd("read", json!({}), "s1")).await;
        let GatewayOutcome::Allowed(v) = out else {
            panic!("expected allow")
        };
        let tok = v["iban"].as_str().unwrap().to_string();
        assert!(tok.starts_with("[[GDN-"), "result not tokenized: {v}");
        assert!(
            !v.to_string().contains("IT60X0542811101000000123456"),
            "IBAN leaked to agent"
        );

        // 2) The agent passes that token back in a new (authorized) call; Guardian
        //    detokenizes it into the real IBAN only at the egress to the upstream.
        let _ = gw.handle(rd("send", json!({ "to": tok }), "s1")).await;
        assert_eq!(
            last.lock().unwrap()["to"].as_str(),
            Some("IT60X0542811101000000123456"),
            "egress was not detokenized"
        );
    }

    struct FakeDetector;
    #[async_trait::async_trait]
    impl PiiDetector for FakeDetector {
        async fn detect(&self, _text: &str) -> Vec<String> {
            vec!["Top Secret".to_string()]
        }
    }

    #[tokio::test]
    async fn sidecar_detected_value_is_tokenized_even_without_known_values() {
        let policy = CompiledPolicy::from_toml_str(
            "version=1\nrole=\"t\"\n[defaults]\ndecision=\"ask\"\n[[rules]]\nid=\"all\"\nwhen='true'\ndecision=\"allow\"\n",
        )
        .unwrap();
        struct NoteUpstream;
        #[async_trait::async_trait]
        impl Upstream for NoteUpstream {
            async fn forward(&self, _: &ToolCall) -> Result<Value, String> {
                Ok(json!({ "note": "Top Secret stuff here" }))
            }
        }
        let gw = Gateway::new(
            "test",
            policy,
            Box::new(guardian_checker::StubChecker),
            Box::new(AutoApprove),
            Box::new(NoteUpstream),
            AuditLog::open_in_memory().unwrap(),
            EvalEnv::default(),
        )
        .with_pii_detector(Arc::new(FakeDetector));
        let out = gw.handle(rd("read", json!({}), "s1")).await;
        let GatewayOutcome::Allowed(v) = out else {
            panic!()
        };
        assert!(
            !v.to_string().contains("Top Secret"),
            "sidecar-detected PII leaked: {v}"
        );
        assert!(v["note"].as_str().unwrap().contains("[[GDN-"));
    }

    #[tokio::test]
    async fn a_token_does_not_resolve_in_another_session() {
        let (gw, last) = protected_gateway();
        let out = gw.handle(rd("read", json!({}), "alice")).await;
        let GatewayOutcome::Allowed(v) = out else {
            panic!()
        };
        let tok = v["iban"].as_str().unwrap().to_string();
        // Replaying alice's token in bob's session must NOT resolve to the real value.
        let _ = gw
            .handle(rd("send", json!({ "to": tok.clone() }), "bob"))
            .await;
        assert_eq!(
            last.lock().unwrap()["to"].as_str(),
            Some(tok.as_str()),
            "cross-session replay leaked the value"
        );
    }

    #[tokio::test]
    async fn deny_blocks_and_does_not_forward() {
        let (gw, forwarded) = gateway_with(
            Box::new(AutoApprove),
            Box::new(guardian_checker::StubChecker),
        );
        let out = gw.handle(call("shell.run", ActionKind::Exec)).await;
        match out {
            GatewayOutcome::Blocked(reason) => {
                assert!(reason.contains("blocked"));
            }
            other => panic!("expected Blocked, got {other:?}"),
        }
        assert!(forwarded.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn ask_then_approve_forwards() {
        let (gw, forwarded) = gateway_with(
            Box::new(AutoApprove),
            Box::new(guardian_checker::StubChecker),
        );
        let out = gw.handle(call("mail.send", ActionKind::Email)).await;
        assert!(matches!(out, GatewayOutcome::Allowed(_)));
        assert_eq!(*forwarded.lock().unwrap(), vec!["mail.send".to_string()]);
    }

    #[tokio::test]
    async fn ask_then_deny_blocks() {
        let (gw, forwarded) =
            gateway_with(Box::new(AutoDeny), Box::new(guardian_checker::StubChecker));
        let out = gw.handle(call("mail.send", ActionKind::Email)).await;
        assert!(matches!(out, GatewayOutcome::Blocked(_)));
        assert!(forwarded.lock().unwrap().is_empty());
    }

    #[test]
    fn build_action_never_panics_on_arbitrary_input() {
        // In-process fuzzing of the untrusted-input boundary (JSON → ToolCall →
        // Action): garbage bytes and crafted values must never panic the
        // normalizer. (See `fuzz/` for deep cargo-fuzz runs of the same path.)
        let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let kinds = [
            "FileRead",
            "Exec",
            "HttpRequest",
            "Email",
            "Other",
            "bogus",
            "",
        ];
        for _ in 0..5000 {
            // 1) raw bytes parsed as a JSON document.
            let len = (next() % 96) as usize;
            let bytes: Vec<u8> = (0..len).map(|_| (next() % 256) as u8).collect();
            if let Ok(s) = std::str::from_utf8(&bytes) {
                if let Ok(call) = serde_json::from_str::<ToolCall>(s) {
                    let _ = build_action(&call, "fuzz", ActionId::new("f"), next() as i64);
                }
            }
            // 2) a structurally-plausible ToolCall with random-ish fields.
            let kind = kinds[(next() as usize) % kinds.len()];
            let value = serde_json::json!({
                "tool": format!("t{}", next() % 997),
                "args": { "path": format!("/{}", next()), "method": "GET", "cmd": "x", "amount": (next() % 10000) as f64 },
                "kind": if kind.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(kind.to_string()) },
            });
            if let Ok(call) = serde_json::from_value::<ToolCall>(value) {
                let _ = build_action(&call, "fuzz", ActionId::new("f"), next() as i64);
            }
        }
    }

    #[tokio::test]
    async fn checker_is_not_called_on_the_fast_path() {
        // PanicChecker panics if explain() runs; allow and deny must not call it.
        let (gw, _) = gateway_with(Box::new(AutoApprove), Box::new(PanicChecker));
        assert!(matches!(
            gw.handle(call("fs.read", ActionKind::FileRead)).await,
            GatewayOutcome::Allowed(_)
        ));
        assert!(matches!(
            gw.handle(call("shell.run", ActionKind::Exec)).await,
            GatewayOutcome::Blocked(_)
        ));
    }

    #[tokio::test]
    async fn decisions_are_recorded_and_log_verifies() {
        let (gw, _) = gateway_with(
            Box::new(AutoApprove),
            Box::new(guardian_checker::StubChecker),
        );
        gw.handle(call("fs.read", ActionKind::FileRead)).await;
        gw.handle(call("shell.run", ActionKind::Exec)).await;
        gw.handle(call("mail.send", ActionKind::Email)).await;
        assert_eq!(gw.audit_len(), 3);
        assert!(gw.audit_verify().is_ok());
    }

    #[test]
    fn unknown_tool_infers_other() {
        assert_eq!(infer_kind("mystery.thing"), ActionKind::Other);
        assert_eq!(infer_kind("bank.transfer"), ActionKind::Payment);
        assert_eq!(infer_kind("shell.exec"), ActionKind::Exec);
    }

    #[tokio::test]
    async fn self_protection_blocks_writes_to_its_own_files() {
        let (gw, forwarded) = gateway_with(
            Box::new(AutoApprove),
            Box::new(guardian_checker::StubChecker),
        );
        let gw = gw.with_self_protection(SelfProtection::new(
            vec![std::path::PathBuf::from("/grd")],
            None,
        ));
        let write = ToolCall {
            tool: "write_file".to_string(),
            args: serde_json::json!({ "path": "/grd/policy.toml" }),
            kind: Some(ActionKind::FileWrite),
            capability: None,
            session: None,
        };
        assert!(matches!(gw.handle(write).await, GatewayOutcome::Blocked(_)));
        assert!(forwarded.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn kill_switch_denies_everything_then_releases() {
        let ks = std::env::temp_dir().join(format!("guardian-ks-{}", std::process::id()));
        std::fs::write(&ks, "").unwrap(); // engage
        let (gw, _f) = gateway_with(
            Box::new(AutoApprove),
            Box::new(guardian_checker::StubChecker),
        );
        let gw = gw.with_self_protection(SelfProtection::new(vec![], Some(ks.clone())));
        // Even a normally-allowed read is blocked while the switch is engaged.
        assert!(matches!(
            gw.handle(call("fs.read", ActionKind::FileRead)).await,
            GatewayOutcome::Blocked(_)
        ));
        // Disengage → the policy applies again.
        std::fs::remove_file(&ks).unwrap();
        assert!(matches!(
            gw.handle(call("fs.read", ActionKind::FileRead)).await,
            GatewayOutcome::Allowed(_)
        ));
    }

    #[tokio::test]
    async fn self_protection_normalizes_paths_and_scopes_to_writes() {
        let (gw, _f) = gateway_with(
            Box::new(AutoApprove),
            Box::new(guardian_checker::StubChecker),
        );
        let gw = gw.with_self_protection(SelfProtection::new(
            vec![std::path::PathBuf::from("/grd")],
            None,
        ));
        let write = |p: &str| ToolCall {
            tool: "write_file".to_string(),
            args: serde_json::json!({ "path": p }),
            kind: Some(ActionKind::FileWrite),
            capability: None,
            session: None,
        };
        // `..` that resolves INTO the protected dir is blocked (lexical-match bypass).
        assert!(matches!(
            gw.handle(write("/x/../grd/policy.toml")).await,
            GatewayOutcome::Blocked(_)
        ));
        assert!(matches!(
            gw.handle(write("/grd/sub/../config.toml")).await,
            GatewayOutcome::Blocked(_)
        ));
        // A sibling prefix is NOT protected (component-wise match, not substring).
        assert!(!matches!(
            gw.handle(write("/grd-evil/x")).await,
            GatewayOutcome::Blocked(_)
        ));
        // Self-protection guards modification, not reads.
        let read = ToolCall {
            tool: "read_file".to_string(),
            args: serde_json::json!({ "path": "/grd/policy.toml" }),
            kind: Some(ActionKind::FileRead),
            capability: None,
            session: None,
        };
        assert!(matches!(gw.handle(read).await, GatewayOutcome::Allowed(_)));
    }
}
