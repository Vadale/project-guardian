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
use guardian_checker::{Checker, HttpChecker, StubChecker};
use guardian_daemon::config;
use guardian_daemon::{serve, ApprovalQueue, Config, LocalToolsUpstream, QueueApprover};
use guardian_mcp_gateway::{Gateway, SelfProtection};
use guardian_policy::{CompiledPolicy, EvalEnv};

/// The shipped default policy pack, embedded as a fallback.
const DEFAULT_POLICY: &str = include_str!("../../../policies/default/personal-assistant.toml");

/// Load the policy from the resolved path, else the embedded default. The policy
/// is the security boundary, so a bad file is fatal — the daemon refuses to start
/// rather than run with a silent fallback.
fn load_policy(path: Option<PathBuf>) -> CompiledPolicy {
    match path {
        Some(path) => {
            let path_str = path.display().to_string();
            let src = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("cannot read policy ({path_str}): {e}"));
            let policy = CompiledPolicy::from_toml_str(&src)
                .unwrap_or_else(|e| panic!("policy ({path_str}) failed to compile: {e}"));
            tracing::info!(role = %policy.policy().role, path = %path_str, "policy loaded");
            policy
        }
        None => {
            let policy =
                CompiledPolicy::from_toml_str(DEFAULT_POLICY).expect("default policy must compile");
            tracing::info!(role = %policy.policy().role, "policy loaded (built-in default)");
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
    tracing::info!(
        path = %path.display(),
        entries = log.len().unwrap_or(0),
        "audit log opened (chain intact)"
    );
    log
}

/// Initialize structured logging (`tracing`). Level via `RUST_LOG` (default
/// `info`). This is operational logging — distinct from the tamper-evident audit.
fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    init_tracing();
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
        tracing::warn!(
            trusted_hosts = ?cfg.trusted_hosts,
            "trusted_hosts configured — these are exempt from host-gated critical rules"
        );
    }
    let queue = Arc::new(ApprovalQueue::new(cfg.approval_timeout()));
    let approver = QueueApprover::new(queue.clone());

    // Self-protection: refuse to write/delete Guardian's own files, and honor the
    // kill switch (a `STOP` sentinel next to the config denies everything).
    let mut protected = vec![
        config::guardian_dir(),
        config::config_path(),
        config::kill_switch_path(), // so the agent can't delete STOP to disengage
        cfg.audit_path(),
        cfg.socket_path(),
    ];
    if let Some(p) = cfg.policy_path() {
        protected.push(p);
    }
    let self_protection = SelfProtection::new(protected, Some(config::kill_switch_path()));

    // Advisory Checker: an HTTP model endpoint if configured, else the offline
    // StubChecker (privacy default). Never on the allow/deny path (ADR-0003).
    let checker: Box<dyn Checker> = match cfg.checker_endpoint() {
        Some(url) => {
            if url.starts_with("https") {
                tracing::warn!(
                    "checker endpoint is https but this build has no TLS; it will fail and fall back to the offline checker"
                );
            }
            let local =
                url.contains("127.0.0.1") || url.contains("localhost") || url.contains("[::1]");
            if !local {
                tracing::warn!(
                    "checker endpoint is non-local: the full action (including args) is sent there — ensure it is trusted"
                );
            }
            // Don't log the URL itself — it may embed credentials.
            tracing::info!(local, "advisory checker: HTTP model endpoint configured");
            Box::new(HttpChecker::new(url))
        }
        None => Box::new(StubChecker),
    };

    let gateway = Arc::new(
        Gateway::new(
            "daemon",
            policy,
            checker,
            Box::new(approver),
            Box::new(LocalToolsUpstream),
            open_audit(cfg.audit_path()),
            env,
        )
        .with_self_protection(self_protection)
        .with_data_protection(cfg.protect.clone()),
    );
    if !cfg.protect.is_empty() {
        tracing::info!(
            count = cfg.protect.len(),
            "data-vault: seeded protected values from config"
        );
    }

    let path = cfg.socket_path();
    tracing::info!(socket = %path.display(), "guardian-daemon listening (newline-delimited JSON control protocol)");
    serve(&path, gateway, queue).await
}
