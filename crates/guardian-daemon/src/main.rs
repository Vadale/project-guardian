//! `guardian-daemon` binary — starts the local control socket server.
//!
//! Wires a policy, an offline `StubChecker`, the approval queue, and the local
//! tools upstream into a [`Gateway`], then serves the newline-delimited JSON
//! protocol over a Unix socket. Env overrides: `GUARDIAN_SOCK` (socket path),
//! `GUARDIAN_POLICY` (policy file; defaults to the shipped pack), `GUARDIAN_AUDIT`
//! (audit-log file; defaults to `~/.guardian/audit.db`).

#![forbid(unsafe_code)]

use std::path::PathBuf;
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

/// Open the persistent audit log (`GUARDIAN_AUDIT`, else `~/.guardian/audit.db`)
/// and verify its chain. Fail closed: refuse to start on a broken/tampered chain
/// rather than append to a log whose integrity can no longer be vouched for.
fn open_audit() -> AuditLog {
    let path = match std::env::var("GUARDIAN_AUDIT") {
        Ok(p) => PathBuf::from(p),
        Err(_) => {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            let dir = PathBuf::from(home).join(".guardian");
            std::fs::create_dir_all(&dir)
                .unwrap_or_else(|e| panic!("cannot create {}: {e}", dir.display()));
            dir.join("audit.db")
        }
    };
    let log = AuditLog::open(&path)
        .unwrap_or_else(|e| panic!("cannot open audit log {}: {e}", path.display()));
    log.verify().unwrap_or_else(|e| {
        panic!(
            "audit log {} failed its integrity check ({e}); refusing to start",
            path.display()
        )
    });
    println!(
        "guardian-daemon: audit log {} ({} entries, intact)",
        path.display(),
        log.len().unwrap_or(0)
    );
    log
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
        open_audit(),
        env,
    ));

    let path = std::env::var("GUARDIAN_SOCK")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("guardian.sock"));

    println!("guardian-daemon: listening on {}", path.display());
    println!(r#"  protocol: newline-delimited JSON, e.g. {{"cmd":"pending"}}"#);
    serve(&path, gateway, queue).await
}
