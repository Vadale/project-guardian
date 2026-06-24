//! `guardian-daemon` binary — starts the local control socket server.
//!
//! Wires the default policy, an offline `StubChecker`, the approval queue, and a
//! placeholder upstream into a [`Gateway`], then serves the newline-delimited
//! JSON protocol over a Unix socket. Set `GUARDIAN_SOCK` to override the path.

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use guardian_audit::AuditLog;
use guardian_checker::StubChecker;
use guardian_daemon::{serve, ApprovalQueue, LocalToolsUpstream, QueueApprover};
use guardian_mcp_gateway::Gateway;
use guardian_policy::{CompiledPolicy, EvalEnv};

/// The shipped default policy pack.
const DEFAULT_POLICY: &str = include_str!("../../../policies/default/personal-assistant.toml");

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let policy =
        CompiledPolicy::from_toml_str(DEFAULT_POLICY).expect("default policy must compile");
    let env = EvalEnv {
        user_home: std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string()),
        trusted_hosts: Vec::new(),
    };
    let queue = Arc::new(ApprovalQueue::new(Duration::from_secs(120)));
    let approver = QueueApprover::new(queue.clone());
    let gateway = Arc::new(Gateway::new(
        "daemon",
        policy,
        Box::new(StubChecker),
        Box::new(approver),
        Box::new(LocalToolsUpstream),
        AuditLog::open_in_memory().expect("audit log"),
        env,
    ));

    let path = std::env::var("GUARDIAN_SOCK")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("guardian.sock"));

    println!("guardian-daemon: listening on {}", path.display());
    println!(r#"  protocol: newline-delimited JSON, e.g. {{"cmd":"pending"}}"#);
    serve(&path, gateway, queue).await
}
