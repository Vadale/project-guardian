//! `guardian-daemon` — the long-running service backbone (ROADMAP Task 6.5).
//!
//! The core piece here is the human-in-the-loop **approval queue**: when the
//! gateway reaches an `ask` decision it calls [`QueueApprover`], which enqueues a
//! [`PendingApproval`] and awaits the human's response. If no response arrives
//! within the configured timeout the request **fails closed** (Denied). The
//! UI/CLI drive it via [`ApprovalQueue::pending`] and [`ApprovalQueue::respond`].
//!
//! The IPC/wire server that exposes these over a local socket is the next step;
//! this module is the tested orchestration core.

#![forbid(unsafe_code)]

pub mod config;
pub use config::{Config, ConfigError};

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use guardian_checker::Explanation;
use guardian_core::Action;
use guardian_mcp_gateway::{ApprovalResponse, Approver};
use tokio::sync::oneshot;
use tokio::time::{timeout, Duration};

pub use guardian_mcp_gateway::ApprovalResponse as Resolution;

/// A snapshot of a pending approval, for display in the UI/CLI.
#[derive(Debug, Clone)]
pub struct PendingApproval {
    pub id: u64,
    pub action_id: String,
    pub tool: String,
    pub explanation: Explanation,
}

struct Entry {
    info: PendingApproval,
    responder: oneshot::Sender<ApprovalResponse>,
}

/// A queue of pending human approvals with a fail-closed timeout.
///
/// Cheap to share behind an `Arc`; all methods take `&self`.
pub struct ApprovalQueue {
    pending: Mutex<HashMap<u64, Entry>>,
    counter: AtomicU64,
    timeout: Duration,
}

impl ApprovalQueue {
    /// Create a queue whose requests fail closed after `timeout`.
    pub fn new(timeout: Duration) -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
            counter: AtomicU64::new(0),
            timeout,
        }
    }

    /// Enqueue an approval request and await the human's response. Returns
    /// [`ApprovalResponse::Denied`] if the timeout elapses first (fail closed).
    pub async fn request(
        &self,
        action_id: String,
        tool: String,
        explanation: Explanation,
    ) -> ApprovalResponse {
        let id = self.counter.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.lock();
            pending.insert(
                id,
                Entry {
                    info: PendingApproval {
                        id,
                        action_id,
                        tool,
                        explanation,
                    },
                    responder: tx,
                },
            );
        }
        match timeout(self.timeout, rx).await {
            Ok(Ok(response)) => response,
            // Timed out, or the responder was dropped: clean up and fail closed.
            _ => {
                self.lock().remove(&id);
                ApprovalResponse::Denied
            }
        }
    }

    /// Snapshot of the currently pending approvals.
    pub fn pending(&self) -> Vec<PendingApproval> {
        self.lock().values().map(|e| e.info.clone()).collect()
    }

    /// Resolve a pending approval. Returns `true` if it existed and was delivered.
    pub fn respond(&self, id: u64, response: ApprovalResponse) -> bool {
        let entry = self.lock().remove(&id);
        match entry {
            Some(entry) => entry.responder.send(response).is_ok(),
            None => false,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Entry>> {
        self.pending.lock().expect("approval queue mutex poisoned")
    }
}

/// An [`Approver`] that routes the gateway's `ask` decisions through an
/// [`ApprovalQueue`].
pub struct QueueApprover {
    queue: Arc<ApprovalQueue>,
}

impl QueueApprover {
    pub fn new(queue: Arc<ApprovalQueue>) -> Self {
        Self { queue }
    }
}

#[async_trait]
impl Approver for QueueApprover {
    async fn request_approval(
        &self,
        action: &Action,
        explanation: &Explanation,
    ) -> ApprovalResponse {
        self.queue
            .request(
                action.id.as_str().to_string(),
                action.tool.clone(),
                explanation.clone(),
            )
            .await
    }
}

/// An [`guardian_mcp_gateway::Upstream`] that executes a few tools locally with
/// real filesystem operations — a stand-in until a downstream MCP proxy lands.
/// Only *allowed* actions ever reach it (the gateway decides first).
pub struct LocalToolsUpstream;

#[async_trait]
impl guardian_mcp_gateway::Upstream for LocalToolsUpstream {
    async fn forward(
        &self,
        call: &guardian_mcp_gateway::ToolCall,
    ) -> Result<serde_json::Value, String> {
        match call.tool.as_str() {
            "read_file" => {
                let path = call
                    .args
                    .get("path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| "read_file needs a string `path`".to_string())?;
                let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
                Ok(serde_json::json!({ "path": path, "content": content }))
            }
            "write_file" => {
                let path = call
                    .args
                    .get("path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| "write_file needs a string `path`".to_string())?;
                let content = call
                    .args
                    .get("content")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                std::fs::write(path, content).map_err(|e| e.to_string())?;
                Ok(serde_json::json!({ "path": path, "bytes_written": content.len() }))
            }
            other => Err(format!(
                "tool not implemented by the local upstream: {other}"
            )),
        }
    }
}

/// Local control socket: a newline-delimited JSON protocol over a **cross-platform
/// local socket** (Unix domain socket on unix, named pipe on Windows, via the
/// `interprocess` crate — §9b.3), exposing `call` / `pending` / `respond` /
/// `verify_audit`.
mod server {
    use std::io;
    use std::path::Path;
    use std::sync::Arc;

    use guardian_checker::Explanation;
    use guardian_core::{ActionKind, Capability};
    use guardian_mcp_gateway::{Gateway, GatewayOutcome, ToolCall, ToolRouter};
    use interprocess::local_socket::tokio::prelude::*;
    use interprocess::local_socket::{ListenerOptions, Name};
    use serde::{Deserialize, Serialize};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    #[cfg(not(windows))]
    use interprocess::local_socket::GenericFilePath;
    #[cfg(windows)]
    use interprocess::local_socket::GenericNamespaced;

    use crate::{ApprovalQueue, ApprovalResponse};

    /// Build the local-socket name from a path: the filesystem socket path on unix,
    /// and a `\\.\pipe\<file-name>` named pipe on Windows (derived from the path's
    /// file name). Borrows `path`, so it lives until the listener/stream is built.
    fn socket_name(path: &Path) -> io::Result<Name<'_>> {
        #[cfg(windows)]
        {
            let stem = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("guardian");
            stem.to_ns_name::<GenericNamespaced>()
        }
        #[cfg(not(windows))]
        {
            path.as_os_str().to_fs_name::<GenericFilePath>()
        }
    }

    /// Connect a client stream to the daemon's local socket.
    async fn connect_stream(path: &Path) -> io::Result<interprocess::local_socket::tokio::Stream> {
        let name = socket_name(path)?;
        interprocess::local_socket::tokio::Stream::connect(name).await
    }

    /// A client request (one JSON object per line).
    #[derive(Debug, Deserialize)]
    #[serde(tag = "cmd", rename_all = "snake_case")]
    pub enum Request {
        /// Submit a tool call for mediation.
        Call {
            tool: String,
            #[serde(default)]
            args: serde_json::Value,
            #[serde(default)]
            kind: Option<ActionKind>,
            #[serde(default)]
            capability: Option<Capability>,
        },
        /// List pending approvals.
        Pending,
        /// Resolve a pending approval.
        Respond { id: u64, approve: bool },
        /// Enqueue an approval request and block until the cockpit resolves it (or
        /// it times out → denied). Used by an external proxy to route its `ask`s to
        /// this daemon's queue + cockpit, while it keeps its own upstream.
        Approve {
            #[serde(default)]
            action_id: String,
            tool: String,
            #[serde(default)]
            plain_text: String,
            #[serde(default)]
            risk: u8,
        },
        /// Engage/disengage the emergency kill switch (a deny-all sentinel file).
        KillSwitch { engage: bool },
        /// Report audit-log status.
        VerifyAudit,
        /// Recent decisions — the agent's activity archive (most recent `limit`).
        History {
            #[serde(default = "default_history_limit")]
            limit: usize,
        },
    }

    fn default_history_limit() -> usize {
        50
    }

    /// One row of the activity archive, for the cockpit's history view.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct HistoryView {
        pub decision: String,
        pub kind: String,
        #[serde(default)]
        pub host: Option<String>,
        #[serde(default)]
        pub rule: Option<String>,
        #[serde(default)]
        pub reason: Option<String>,
        #[serde(default)]
        pub critical: bool,
    }

    /// A server response (one JSON object per line).
    #[derive(Debug, Serialize)]
    #[serde(tag = "result", rename_all = "snake_case")]
    pub enum Response {
        Outcome {
            status: String,
            detail: serde_json::Value,
        },
        Pending {
            items: Vec<PendingView>,
        },
        Responded {
            ok: bool,
        },
        Approval {
            approved: bool,
        },
        KillSwitch {
            engaged: bool,
        },
        Audit {
            entries: u64,
            intact: bool,
        },
        History {
            items: Vec<HistoryView>,
        },
        Error {
            message: String,
        },
    }

    /// A pending approval as seen by a client.
    #[derive(Debug, Serialize, Deserialize)]
    pub struct PendingView {
        pub id: u64,
        pub action_id: String,
        pub tool: String,
        pub plain_text: String,
        pub risk: u8,
    }

    /// Serve the control socket at `path` until error. Each connection is handled
    /// concurrently, so a `Call` blocked on approval does not prevent a `Respond`
    /// (on another connection) from resolving it.
    pub async fn serve(
        path: &Path,
        gateway: Arc<Gateway>,
        queue: Arc<ApprovalQueue>,
    ) -> std::io::Result<()> {
        // On unix, clear a stale socket file so re-binding succeeds.
        #[cfg(not(windows))]
        let _ = std::fs::remove_file(path);
        let name = socket_name(path)?;
        let listener = ListenerOptions::new().name(name).create_tokio()?;
        loop {
            let stream = listener.accept().await?;
            let gateway = gateway.clone();
            let queue = queue.clone();
            tokio::spawn(async move {
                let _ = handle_connection(stream, gateway, queue).await;
            });
        }
    }

    async fn handle_connection(
        stream: interprocess::local_socket::tokio::Stream,
        gateway: Arc<Gateway>,
        queue: Arc<ApprovalQueue>,
    ) -> std::io::Result<()> {
        let (read_half, mut write_half) = stream.split();
        let mut lines = BufReader::new(read_half).lines();
        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }
            let response = match serde_json::from_str::<Request>(&line) {
                Ok(request) => dispatch(request, &gateway, &queue).await,
                Err(e) => {
                    tracing::warn!(error = %e, "invalid control request");
                    Response::Error {
                        message: format!("invalid request: {e}"),
                    }
                }
            };
            let mut encoded = serde_json::to_string(&response)
                .unwrap_or_else(|_| r#"{"result":"error","message":"encode failed"}"#.to_string());
            encoded.push('\n');
            write_half.write_all(encoded.as_bytes()).await?;
        }
        Ok(())
    }

    async fn dispatch(
        request: Request,
        gateway: &Arc<Gateway>,
        queue: &Arc<ApprovalQueue>,
    ) -> Response {
        match request {
            Request::Call {
                tool,
                args,
                kind,
                capability,
            } => {
                let call = ToolCall {
                    tool,
                    args,
                    kind,
                    capability,
                };
                let tool = call.tool.clone();
                let outcome = gateway.handle(call).await;
                let status = match &outcome {
                    GatewayOutcome::Allowed(_) => "allowed",
                    GatewayOutcome::Blocked(_) => "blocked",
                    GatewayOutcome::UpstreamError(_) => "upstream_error",
                };
                tracing::info!(%tool, status, "tool call mediated");
                match outcome {
                    GatewayOutcome::Allowed(detail) => Response::Outcome {
                        status: "allowed".to_string(),
                        detail,
                    },
                    GatewayOutcome::Blocked(reason) => Response::Outcome {
                        status: "blocked".to_string(),
                        detail: serde_json::json!({ "reason": reason }),
                    },
                    GatewayOutcome::UpstreamError(error) => Response::Outcome {
                        status: "upstream_error".to_string(),
                        detail: serde_json::json!({ "error": error }),
                    },
                }
            }
            Request::Pending => {
                let items = queue
                    .pending()
                    .into_iter()
                    .map(|p| PendingView {
                        id: p.id,
                        action_id: p.action_id,
                        tool: p.tool,
                        plain_text: p.explanation.plain_text,
                        risk: p.explanation.risk,
                    })
                    .collect();
                Response::Pending { items }
            }
            Request::Respond { id, approve } => {
                let response = if approve {
                    ApprovalResponse::Approved
                } else {
                    ApprovalResponse::Denied
                };
                Response::Responded {
                    ok: queue.respond(id, response),
                }
            }
            Request::Approve {
                action_id,
                tool,
                plain_text,
                risk,
            } => {
                let explanation = Explanation {
                    plain_text,
                    risk,
                    rationale: String::new(),
                };
                let resolution = queue.request(action_id, tool, explanation).await;
                Response::Approval {
                    approved: resolution == ApprovalResponse::Approved,
                }
            }
            Request::KillSwitch { engage } => {
                let path = crate::config::kill_switch_path();
                if engage {
                    if let Some(dir) = path.parent() {
                        let _ = std::fs::create_dir_all(dir);
                    }
                    // The panic button must be loud if it fails to engage.
                    if let Err(e) = std::fs::write(&path, "engaged\n") {
                        tracing::error!(path = %path.display(), error = %e, "FAILED to engage kill switch");
                    }
                } else {
                    let _ = std::fs::remove_file(&path);
                }
                Response::KillSwitch {
                    engaged: path.exists(),
                }
            }
            Request::VerifyAudit => Response::Audit {
                entries: gateway.audit_len(),
                intact: gateway.audit_verify().is_ok(),
            },
            Request::History { limit } => {
                let items = gateway
                    .audit_tail(limit)
                    .into_iter()
                    .map(|e| HistoryView {
                        decision: e.decision,
                        kind: e.action_kind,
                        host: e.host,
                        rule: e.matched_rule,
                        reason: e.decision_reason.or(e.checker_rationale),
                        critical: e.critical,
                    })
                    .collect();
                Response::History { items }
            }
        }
    }

    /// A client for the control socket, used by the CLI and the Tauri UI.
    pub struct DaemonClient {
        path: std::path::PathBuf,
    }

    impl DaemonClient {
        pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
            Self { path: path.into() }
        }

        /// Send one request line and read one response line.
        async fn rpc(&self, request: &str) -> std::io::Result<serde_json::Value> {
            let stream = connect_stream(&self.path).await?;
            let (read_half, mut write_half) = stream.split();
            write_half
                .write_all(format!("{request}\n").as_bytes())
                .await?;
            let mut lines = BufReader::new(read_half).lines();
            let line = lines.next_line().await?.ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "no response")
            })?;
            serde_json::from_str(&line)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        }

        /// List pending approvals.
        pub async fn pending(&self) -> std::io::Result<Vec<PendingView>> {
            let value = self.rpc(r#"{"cmd":"pending"}"#).await?;
            let items = value
                .get("items")
                .cloned()
                .unwrap_or_else(|| serde_json::Value::Array(Vec::new()));
            serde_json::from_value(items)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        }

        /// Resolve a pending approval; returns whether it existed.
        pub async fn respond(&self, id: u64, approve: bool) -> std::io::Result<bool> {
            let value = self
                .rpc(&format!(
                    r#"{{"cmd":"respond","id":{id},"approve":{approve}}}"#
                ))
                .await?;
            Ok(value
                .get("ok")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false))
        }

        /// Enqueue an approval request and block until the cockpit resolves it
        /// (or it times out → denied). Used by a proxy to route its `ask`s here.
        pub async fn approve(
            &self,
            action_id: &str,
            tool: &str,
            plain_text: &str,
            risk: u8,
        ) -> std::io::Result<bool> {
            let request = serde_json::json!({
                "cmd": "approve",
                "action_id": action_id,
                "tool": tool,
                "plain_text": plain_text,
                "risk": risk,
            });
            let value = self.rpc(&request.to_string()).await?;
            Ok(value
                .get("approved")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false))
        }

        /// Engage/disengage the emergency kill switch; returns the resulting state.
        pub async fn kill_switch(&self, engage: bool) -> std::io::Result<bool> {
            let value = self
                .rpc(&format!(r#"{{"cmd":"kill_switch","engage":{engage}}}"#))
                .await?;
            Ok(value
                .get("engaged")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false))
        }

        /// The recent activity archive (most recent `limit` decisions).
        pub async fn history(&self, limit: usize) -> std::io::Result<Vec<HistoryView>> {
            let value = self
                .rpc(&format!(r#"{{"cmd":"history","limit":{limit}}}"#))
                .await?;
            let items = value
                .get("items")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            serde_json::from_value(items)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        }

        /// Submit a tool call and return the gateway's outcome.
        pub async fn call(&self, call: &ToolCall) -> std::io::Result<GatewayOutcome> {
            let mut request = serde_json::to_value(call)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            if let Some(obj) = request.as_object_mut() {
                obj.insert(
                    "cmd".to_string(),
                    serde_json::Value::String("call".to_string()),
                );
            }
            let value = self.rpc(&request.to_string()).await?;
            let status = value.get("status").and_then(|v| v.as_str()).unwrap_or("");
            let detail = value
                .get("detail")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            Ok(match status {
                "allowed" => GatewayOutcome::Allowed(detail),
                "blocked" => GatewayOutcome::Blocked(
                    detail
                        .get("reason")
                        .and_then(|v| v.as_str())
                        .unwrap_or("blocked")
                        .to_string(),
                ),
                "upstream_error" => GatewayOutcome::UpstreamError(
                    detail
                        .get("error")
                        .and_then(|v| v.as_str())
                        .unwrap_or("error")
                        .to_string(),
                ),
                other => GatewayOutcome::Blocked(format!("unexpected daemon response: {other}")),
            })
        }
    }

    /// A [`ToolRouter`] that forwards calls to a running daemon over the socket,
    /// so a thin front-end (e.g. `guardian mcp`) is mediated by the daemon's
    /// gateway (policy + approval queue + audit + upstream).
    pub struct DaemonRouter {
        client: DaemonClient,
    }

    impl DaemonRouter {
        pub fn new(client: DaemonClient) -> Self {
            Self { client }
        }
    }

    #[async_trait::async_trait]
    impl ToolRouter for DaemonRouter {
        async fn route(&self, call: ToolCall) -> GatewayOutcome {
            self.client
                .call(&call)
                .await
                .unwrap_or_else(|e| GatewayOutcome::Blocked(format!("daemon unreachable: {e}")))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::Duration;

        use guardian_audit::AuditLog;
        use guardian_checker::StubChecker;
        use guardian_mcp_gateway::Upstream;
        use guardian_policy::{CompiledPolicy, EvalEnv};

        use crate::QueueApprover;

        static N: AtomicU64 = AtomicU64::new(0);

        struct EchoUpstream;
        #[async_trait::async_trait]
        impl Upstream for EchoUpstream {
            async fn forward(&self, call: &ToolCall) -> Result<serde_json::Value, String> {
                Ok(serde_json::json!({ "echoed": call.tool }))
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
[[rules]]
id = "ask-email"
when = 'action.kind == "Email"'
decision = "ask"
"#;

        async fn start() -> std::path::PathBuf {
            let queue = Arc::new(ApprovalQueue::new(Duration::from_secs(5)));
            let approver = QueueApprover::new(queue.clone());
            let gateway = Arc::new(Gateway::new(
                "daemon-test",
                CompiledPolicy::from_toml_str(POLICY).unwrap(),
                Box::new(StubChecker),
                Box::new(approver),
                Box::new(EchoUpstream),
                AuditLog::open_in_memory().unwrap(),
                EvalEnv::default(),
            ));
            let path = std::env::temp_dir().join(format!(
                "guardian-daemon-test-{}-{}.sock",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            let serve_path = path.clone();
            tokio::spawn(async move {
                let _ = serve(&serve_path, gateway, queue).await;
            });
            // Wait until the server accepts connections (cross-platform: a named pipe
            // has no filesystem presence to poll, so retry connecting).
            for _ in 0..200 {
                if connect_stream(&path).await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            path
        }

        /// Send one request line on a fresh connection and return one response line.
        async fn rpc(path: &Path, request: &str) -> String {
            let stream = connect_stream(path).await.unwrap();
            let (read_half, mut write_half) = stream.split();
            write_half
                .write_all(format!("{request}\n").as_bytes())
                .await
                .unwrap();
            let mut lines = BufReader::new(read_half).lines();
            lines.next_line().await.unwrap().unwrap()
        }

        #[tokio::test]
        async fn allow_call_over_socket() {
            let path = start().await;
            let resp = rpc(
                &path,
                r#"{"cmd":"call","tool":"fs.read","kind":"FileRead"}"#,
            )
            .await;
            assert!(resp.contains(r#""status":"allowed""#), "got {resp}");
        }

        #[tokio::test]
        async fn deny_call_over_socket() {
            let path = start().await;
            let resp = rpc(&path, r#"{"cmd":"call","tool":"shell.run","kind":"Exec"}"#).await;
            assert!(resp.contains(r#""status":"blocked""#), "got {resp}");
        }

        #[tokio::test]
        async fn ask_flow_pending_then_approve() {
            let path = start().await;
            // Submit an `ask` call on its own connection; it blocks on approval.
            let call_path = path.clone();
            let call = tokio::spawn(async move {
                rpc(
                    &call_path,
                    r#"{"cmd":"call","tool":"mail.send","kind":"Email"}"#,
                )
                .await
            });
            // Find the pending item's id (crude parse, test-only).
            let id = loop {
                let pending = rpc(&path, r#"{"cmd":"pending"}"#).await;
                if let Some(idx) = pending.find(r#""id":"#) {
                    let rest = &pending[idx + 5..];
                    let end = rest
                        .find(|c: char| !c.is_ascii_digit())
                        .unwrap_or(rest.len());
                    if end > 0 {
                        break rest[..end].parse::<u64>().unwrap();
                    }
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            };
            let responded = rpc(
                &path,
                &format!(r#"{{"cmd":"respond","id":{id},"approve":true}}"#),
            )
            .await;
            assert!(responded.contains(r#""ok":true"#), "got {responded}");
            let outcome = call.await.unwrap();
            assert!(outcome.contains(r#""status":"allowed""#), "got {outcome}");
        }

        #[tokio::test]
        async fn approve_request_enqueues_and_resolves() {
            let path = start().await;
            // An external `approve` request blocks until the cockpit resolves it.
            let approve_path = path.clone();
            let approve = tokio::spawn(async move {
                rpc(
                    &approve_path,
                    r#"{"cmd":"approve","tool":"x__write","plain_text":"writes a file","risk":40}"#,
                )
                .await
            });
            // It must appear in `pending`; resolve it approved.
            let id = loop {
                let pending = rpc(&path, r#"{"cmd":"pending"}"#).await;
                if let Some(idx) = pending.find(r#""id":"#) {
                    let rest = &pending[idx + 5..];
                    let end = rest
                        .find(|c: char| !c.is_ascii_digit())
                        .unwrap_or(rest.len());
                    if end > 0 {
                        break rest[..end].parse::<u64>().unwrap();
                    }
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            };
            let responded = rpc(
                &path,
                &format!(r#"{{"cmd":"respond","id":{id},"approve":true}}"#),
            )
            .await;
            assert!(responded.contains(r#""ok":true"#), "got {responded}");
            let outcome = approve.await.unwrap();
            assert!(outcome.contains(r#""approved":true"#), "got {outcome}");
        }

        #[tokio::test]
        async fn verify_audit_over_socket() {
            let path = start().await;
            rpc(
                &path,
                r#"{"cmd":"call","tool":"fs.read","kind":"FileRead"}"#,
            )
            .await;
            let resp = rpc(&path, r#"{"cmd":"verify_audit"}"#).await;
            assert!(resp.contains(r#""intact":true"#), "got {resp}");
        }

        #[tokio::test]
        async fn daemon_client_lists_and_responds() {
            let path = start().await;
            let client = DaemonClient::new(path);
            assert!(client.pending().await.unwrap().is_empty());
            // Responding to an unknown id returns false.
            assert!(!client.respond(999, true).await.unwrap());
        }

        #[tokio::test]
        async fn daemon_router_routes_a_call_through_the_daemon() {
            use guardian_core::ActionKind;
            let path = start().await;
            let router = DaemonRouter::new(DaemonClient::new(path));
            let outcome = router
                .route(ToolCall {
                    tool: "fs.read".to_string(),
                    args: serde_json::json!({}),
                    kind: Some(ActionKind::FileRead),
                    capability: None,
                })
                .await;
            assert!(
                matches!(outcome, GatewayOutcome::Allowed(_)),
                "got {outcome:?}"
            );
        }
    }
}

pub use server::{serve, DaemonClient, DaemonRouter, HistoryView, PendingView, Request, Response};

#[cfg(test)]
mod tests {
    use super::*;

    fn expl() -> Explanation {
        Explanation {
            plain_text: "do a thing".to_string(),
            risk: 50,
            rationale: "test".to_string(),
        }
    }

    /// Spin until the first pending item appears, then return its id.
    async fn first_pending_id(q: &ApprovalQueue) -> u64 {
        loop {
            if let Some(item) = q.pending().first() {
                return item.id;
            }
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn approve_resolves_the_request() {
        let q = Arc::new(ApprovalQueue::new(Duration::from_secs(5)));
        let q2 = q.clone();
        let handle =
            tokio::spawn(async move { q2.request("a1".into(), "tool".into(), expl()).await });
        let id = first_pending_id(&q).await;
        assert!(q.respond(id, ApprovalResponse::Approved));
        assert_eq!(handle.await.unwrap(), ApprovalResponse::Approved);
        assert!(q.pending().is_empty());
    }

    #[tokio::test]
    async fn deny_resolves_the_request() {
        let q = Arc::new(ApprovalQueue::new(Duration::from_secs(5)));
        let q2 = q.clone();
        let handle = tokio::spawn(async move { q2.request("a".into(), "t".into(), expl()).await });
        let id = first_pending_id(&q).await;
        q.respond(id, ApprovalResponse::Denied);
        assert_eq!(handle.await.unwrap(), ApprovalResponse::Denied);
    }

    #[tokio::test]
    async fn timeout_fails_closed() {
        let q = ApprovalQueue::new(Duration::from_millis(20));
        let response = q.request("a1".into(), "tool".into(), expl()).await;
        assert_eq!(response, ApprovalResponse::Denied);
        assert!(q.pending().is_empty());
    }

    #[tokio::test]
    async fn respond_to_unknown_id_is_false() {
        let q = ApprovalQueue::new(Duration::from_secs(5));
        assert!(!q.respond(999, ApprovalResponse::Approved));
    }

    #[tokio::test]
    async fn queue_approver_routes_and_carries_tool_name() {
        use guardian_core::{ActionContext, ActionId, ActionKind};

        let q = Arc::new(ApprovalQueue::new(Duration::from_secs(5)));
        let q2 = q.clone();
        let approver = QueueApprover::new(q.clone());
        let action = Action {
            id: ActionId::new("act-1"),
            kind: ActionKind::Exec,
            tool: "shell.run".to_string(),
            args: serde_json::json!({}),
            capability: None,
            context: ActionContext {
                timestamp_ms: 0,
                source: "t".to_string(),
                session: None,
                host: None,
                principal: None,
                path: None,
                extra: serde_json::Map::new(),
            },
        };
        let handle = tokio::spawn(async move { approver.request_approval(&action, &expl()).await });
        let id = first_pending_id(&q2).await;
        assert_eq!(
            q2.pending().iter().find(|p| p.id == id).unwrap().tool,
            "shell.run"
        );
        q2.respond(id, ApprovalResponse::Approved);
        assert_eq!(handle.await.unwrap(), ApprovalResponse::Approved);
    }

    #[tokio::test]
    async fn local_tools_upstream_reads_and_writes() {
        use guardian_mcp_gateway::{ToolCall, Upstream};
        let path = std::env::temp_dir().join(format!("guardian-lt-{}.txt", std::process::id()));
        let up = LocalToolsUpstream;
        let written = up
            .forward(&ToolCall {
                tool: "write_file".to_string(),
                args: serde_json::json!({ "path": path.to_str().unwrap(), "content": "hi" }),
                kind: None,
                capability: None,
            })
            .await;
        assert!(written.is_ok(), "write failed: {written:?}");
        let read = up
            .forward(&ToolCall {
                tool: "read_file".to_string(),
                args: serde_json::json!({ "path": path.to_str().unwrap() }),
                kind: None,
                capability: None,
            })
            .await
            .unwrap();
        assert_eq!(read.get("content").and_then(|v| v.as_str()), Some("hi"));
        let _ = std::fs::remove_file(&path);
    }
}
