//! `guardian-daemon` binary — starts the local control socket server.
//!
//! Wires a policy, an offline `StubChecker`, the approval queue, and the local
//! tools upstream into a [`Gateway`], then serves the newline-delimited JSON
//! protocol over a Unix socket. Configuration is loaded from `GUARDIAN_CONFIG`
//! (default `~/.guardian/config.toml`); per-value precedence is built-in default
//! < config file < `GUARDIAN_*` env (`GUARDIAN_SOCK`/`POLICY`/`AUDIT`).

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::Arc;

use guardian_audit::AuditLog;
use guardian_checker::StubChecker;
use guardian_daemon::{serve, ApprovalQueue, Config, LocalToolsUpstream, QueueApprover};
use guardian_mcp_gateway::Gateway;
use guardian_policy::{CompiledPolicy, EvalEnv};

/// The shipped default policy pack, embedded as a fallback.
const DEFAULT_POLICY: &str = include_str!("../../../policies/default/personal-assistant.toml");

/// Load the policy from the resolved path, else the embedded default. The policy
/// is the security boundary, so a bad file is fatal — the daemon refuses to start
/// rather than run with a silent fallback.
fn load_policy(path: Option<PathBuf>) -> CompiledPolicy {
    match path {
        Some(path) => {
            let display = path.display().to_string();
            let src = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("cannot read policy ({display}): {e}"));
            let policy = CompiledPolicy::from_toml_str(&src)
                .unwrap_or_else(|e| panic!("policy ({display}) failed to compile: {e}"));
            println!(
                "guardian-daemon: policy `{}` from {display}",
                policy.policy().role
            );
            policy
        }
        None => {
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

/// Open the persistent audit log at `path` and verify its chain. Fail closed:
/// refuse to start on a broken/tampered chain rather than append to a log whose
/// integrity can no longer be vouched for.
fn open_audit(path: PathBuf) -> AuditLog {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .unwrap_or_else(|e| panic!("cannot create {}: {e}", dir.display()));
    }
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
    // Fail closed on a malformed config rather than guessing.
    let cfg = Config::load().unwrap_or_else(|e| panic!("config: {e}"));
    let policy = load_policy(cfg.policy_path());
    let env = EvalEnv {
        user_home: std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string()),
        trusted_hosts: cfg.trusted_hosts.clone(),
    };
    // Surface trust widening: trusted_hosts exempts hosts from host-gated critical
    // rules (exfiltration/credentials), so make any configured value visible.
    if !cfg.trusted_hosts.is_empty() {
        println!(
            "guardian-daemon: trusted_hosts = {:?} (exempt from host-gated critical rules)",
            cfg.trusted_hosts
        );
    }
    let queue = Arc::new(ApprovalQueue::new(cfg.approval_timeout()));
    let approver = QueueApprover::new(queue.clone());
    let gateway = Arc::new(Gateway::new(
        "daemon",
        policy,
        Box::new(StubChecker),
        Box::new(approver),
        Box::new(LocalToolsUpstream),
        open_audit(cfg.audit_path()),
        env,
    ));

    let path = cfg.socket_path();
    println!("guardian-daemon: listening on {}", path.display());
    println!(r#"  protocol: newline-delimited JSON, e.g. {{"cmd":"pending"}}"#);
    serve(&path, gateway, queue).await
}
