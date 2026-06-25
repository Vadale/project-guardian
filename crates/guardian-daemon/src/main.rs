//! `guardian-daemon` binary — starts the local control socket server.
//!
//! Wires a policy, an offline `StubChecker`, the approval queue, and the local
//! tools upstream into a [`Gateway`], then serves the newline-delimited JSON
//! protocol over a Unix socket. Set `GUARDIAN_SOCK` to override the socket path
//! and `GUARDIAN_POLICY` to load a policy file (defaults to the shipped pack).

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use guardian_audit::AuditLog;
use guardian_checker::StubChecker;
use guardian_daemon::{serve, ApprovalQueue, LocalToolsUpstream, QueueApprover};
use guardian_mcp_gateway::Gateway;
use guardian_policy::{CompiledPolicy, EvalEnv};

/// The shipped default policy pack, embedded as a fallback.
const DEFAULT_POLICY: &str = include_str!("../../../policies/default/personal-assistant.toml");

/// Load the policy from `GUARDIAN_POLICY` if set, else the embedded default.
/// The policy is the security boundary, so a bad `GUARDIAN_POLICY` is fatal —
/// the daemon refuses to start rather than run with a silent fallback.
fn load_policy() -> CompiledPolicy {
    match std::env::var("GUARDIAN_POLICY") {
        Ok(path) => {
            let src = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("cannot read GUARDIAN_POLICY ({path}): {e}"));
            let policy = CompiledPolicy::from_toml_str(&src)
                .unwrap_or_else(|e| panic!("GUARDIAN_POLICY ({path}) failed to compile: {e}"));
            println!(
                "guardian-daemon: policy `{}` from {path}",
                policy.policy().role
            );
            policy
        }
        Err(_) => {
            let policy =
                CompiledPolicy::from_toml_str(DEFAULT_POLICY).expect("default policy must compile");
            println!(
                "guardian-daemon: policy `{}` (built-in default)",
                policy.policy().role
            );
            policy
        }
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let policy = load_policy();
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
