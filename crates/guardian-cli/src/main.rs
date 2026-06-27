//! `guardian` — the command-line interface (ROADMAP Task 6.7, partial).
//!
//! `demo` runs a scripted scenario end to end through the mediation gateway,
//! printing the traffic-light decisions; `policy-validate` compiles a policy file.

#![forbid(unsafe_code)]

use std::path::PathBuf;

use async_trait::async_trait;
use clap::{Parser, Subcommand};
use guardian_audit::AuditLog;
use guardian_checker::{Explanation, StubChecker};
use guardian_core::{Action, ActionId, ActionKind, Capability, Decision};
use guardian_mcp_gateway::mcp::{McpServer, ToolSpec};
use guardian_mcp_gateway::{
    ApprovalResponse, Approver, Gateway, GatewayOutcome, ToolCall, Upstream,
};
use guardian_policy::{CompiledPolicy, EvalEnv};
use serde_json::{json, Value};

mod eval;
mod tui;

#[derive(Parser)]
#[command(name = "guardian", about = "Project Guardian — AI guardian firewall")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a scripted demo of the traffic-light mediation, end to end.
    Demo,
    /// Parse, validate, and compile a policy file.
    #[command(name = "policy-validate")]
    PolicyValidate { path: PathBuf },
    /// Run Guardian as an MCP server over stdio (newline-delimited JSON-RPC).
    /// With --daemon, mediate through a running daemon so asks reach the UI.
    /// With --upstream, act as a proxy in front of a real upstream MCP server.
    Mcp {
        /// Path to a running daemon's control socket to mediate through.
        #[arg(long)]
        daemon: Option<PathBuf>,
        /// Proxy upstream MCP server(s); repeatable. Each is `[label=]command args`
        /// (e.g. --upstream "files=/path/to/server --flag"). Tools are namespaced
        /// `label__tool` when labeled or when several are given; a single unlabeled
        /// upstream keeps the raw tool names.
        #[arg(long)]
        upstream: Vec<String>,
        /// Policy file for the local gateway (proxy / default modes; not --daemon).
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Token-broker secrets file (`target = "token"`). In proxy mode the token
        /// is injected into upstream calls so the agent never sees the credential.
        #[arg(long)]
        secrets: Option<PathBuf>,
    },
    /// Open the terminal cockpit to review and approve pending actions.
    Ui {
        /// Path to the daemon's control socket (default: $GUARDIAN_SOCK or temp).
        #[arg(long)]
        daemon: Option<PathBuf>,
        /// Preview the cockpit with sample actions; do not contact a daemon.
        #[arg(long)]
        demo: bool,
    },
    /// Run the internal red-team evaluation suite and print a scorecard.
    Eval,
    /// Read a tool-call JSON on stdin and print the policy decision (no execution).
    Decide {
        /// Policy file to evaluate against (defaults to the built-in demo policy).
        #[arg(long)]
        policy: Option<PathBuf>,
    },
    /// Claude Code `PreToolUse` hook adapter: read the hook JSON on stdin and emit
    /// the permission decision (allow/ask/deny) so Guardian mediates native tools.
    Hook {
        /// Policy file to evaluate against (defaults to the built-in demo policy).
        #[arg(long)]
        policy: Option<PathBuf>,
    },
    /// Browse the tamper-evident audit log: recent decisions + integrity status.
    Log {
        /// Audit-log file (default: `$GUARDIAN_AUDIT`, else `~/.guardian/audit.db`).
        #[arg(long)]
        audit: Option<PathBuf>,
        /// How many of the most recent entries to show.
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// Trusted ed25519 public key (hex) of a **signed** log (§9.2): verifies the
        /// head signature too, so a full rewrite without the sealed key is detected.
        #[arg(long)]
        verify_key: Option<String>,
    },
    /// Run the user-space HTTP(S) forward proxy (Phase 2): mediates the agent's web
    /// traffic with the same policy + token broker. Point the agent's
    /// `HTTP_PROXY`/`HTTPS_PROXY` at the listen address; for HTTPS, install the
    /// local CA (`guardian proxy --print-ca-path` shows where it lives).
    Proxy {
        /// Address to listen on (default 127.0.0.1:8080).
        #[arg(long, default_value = "127.0.0.1:8080")]
        listen: String,
        /// Policy file (defaults to the built-in demo policy).
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Token-broker secrets file (`target = "token"`); the proxy attaches the
        /// credential as `Authorization` only on an allowed request.
        #[arg(long)]
        secrets: Option<PathBuf>,
        /// Load the secret for this target from the **OS keychain** instead of a
        /// file (repeatable). Manage it with `guardian broker set <target>`.
        #[arg(long = "keychain")]
        keychain: Vec<String>,
        /// TOML file of per-target least-privilege caveats (§8.1): a `[target]`
        /// table with `not_after_ms`, `allowed_hosts`, `max_amount`,
        /// `require_fresh_approval_for_critical`.
        #[arg(long)]
        caveats: Option<PathBuf>,
        /// Audit-log file (default: `$GUARDIAN_AUDIT`, else `~/.guardian/audit.db`).
        #[arg(long)]
        audit: Option<PathBuf>,
        /// Directory holding the local CA (default: `<guardian-dir>/proxy-ca`).
        #[arg(long)]
        ca_dir: Option<PathBuf>,
        /// Route `ask` decisions to a running daemon's cockpit for human approval
        /// (its control socket). Without it, `ask` fails closed (blocked).
        #[arg(long)]
        daemon: Option<PathBuf>,
        /// Print the CA certificate path (to install/trust) and exit.
        #[arg(long)]
        print_ca_path: bool,
        /// Install/trust the local CA in this machine's trust store (HTTPS
        /// onboarding), then exit. Security-sensitive — see the printed warning.
        #[arg(long)]
        install_ca: bool,
    },
    /// Manage broker secrets in the OS keychain (Phase 3): store/remove/check the
    /// credentials Guardian injects, so they live in the platform credential store,
    /// never plaintext on disk and never shown to the agent.
    Broker {
        #[command(subcommand)]
        action: BrokerAction,
    },
    /// Sign or verify a community policy pack (Phase 3 / §8.4): an ed25519-signed
    /// directory of policy TOML. Verification refuses unsigned/tampered packs and
    /// packs that widen a critical category without explicit opt-in.
    Pack {
        #[command(subcommand)]
        action: PackAction,
    },
    /// Summarize recent activity from the audit log (Phase 3 / §8.3): allow/ask/deny
    /// counts, the top blocked rules, and **suggestions** to confirm (§8.2) — a
    /// non-critical rule you keep approving may be worth allowing. Suggestions are
    /// advisory only; Guardian never edits the policy.
    Report {
        /// Audit-log file (default: `$GUARDIAN_AUDIT`, else `~/.guardian/audit.db`).
        #[arg(long)]
        audit: Option<PathBuf>,
        /// How many of the most recent entries to analyze (the decaying window).
        #[arg(long, default_value_t = 500)]
        window: usize,
    },
    /// Decide an `exec`-class command against the policy and, if allowed, run it —
    /// **sandboxed** (no network, read-only FS) when the matched rule sets
    /// `sandbox = true` (ROADMAP §7.3). Usage: `guardian exec [opts] -- <cmd> [args…]`.
    Exec {
        /// Policy file (defaults to the built-in demo policy).
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Audit-log file (default: `$GUARDIAN_AUDIT`, else `~/.guardian/audit.db`).
        #[arg(long)]
        audit: Option<PathBuf>,
        /// Allow outbound network inside the sandbox (default: denied). **Operator
        /// input** — set by whoever runs `guardian exec`, not by the agent (whose
        /// input is only the command after `--`).
        #[arg(long)]
        allow_network: bool,
        /// Extra path the sandboxed command may write to (repeatable). **Operator
        /// input** — must not be sourced from the agent.
        #[arg(long = "writable")]
        writable: Vec<PathBuf>,
        /// The command and its arguments, after `--`.
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
}

#[derive(Subcommand)]
enum BrokerAction {
    /// Store a secret for <target>, read from **stdin** (so it's not in your shell
    /// history): e.g. `printf %s "$TOKEN" | guardian broker set api.example.com`.
    Set { target: String },
    /// Remove the secret for <target> (a no-op if there is none).
    Delete { target: String },
    /// Report whether a secret is stored for <target> — never prints the value.
    Has { target: String },
}

#[derive(Subcommand)]
enum PackAction {
    /// Sign the policy `.toml` files in <dir>, writing `guardian-pack.json`. Uses
    /// the 32-byte hex seed in --key-file (generated and saved there if absent).
    Sign {
        dir: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "0.1.0")]
        version: String,
        /// File holding the publisher's hex signing seed (created if missing, 0600).
        #[arg(long)]
        key_file: PathBuf,
    },
    /// Verify <dir>: signature, file hashes, and (optionally) that the publisher is
    /// --pubkey. Reports any critical-widening rules. Non-zero exit on failure.
    Verify {
        dir: PathBuf,
        /// Required publisher public key (hex); if omitted, any valid signature is
        /// accepted (still proves integrity, not provenance).
        #[arg(long)]
        pubkey: Option<String>,
        /// Audit-log file to record the verified pack's provenance into.
        #[arg(long)]
        audit: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Demo => run_demo().await,
        Command::PolicyValidate { path } => validate_policy(&path),
        Command::Mcp {
            daemon,
            upstream,
            policy,
            secrets,
        } => run_mcp(daemon, upstream, policy, secrets).await,
        Command::Ui { daemon, demo } => {
            let socket = daemon
                .or_else(|| std::env::var_os("GUARDIAN_SOCK").map(PathBuf::from))
                .unwrap_or_else(|| std::env::temp_dir().join("guardian.sock"));
            tui::run(socket, demo).await
        }
        Command::Eval => {
            eval::run_and_print();
            Ok(())
        }
        Command::Decide { policy } => run_decide(policy),
        Command::Hook { policy } => run_claude_hook(policy),
        Command::Log {
            audit,
            limit,
            verify_key,
        } => run_log(audit, limit, verify_key),
        Command::Proxy {
            listen,
            policy,
            secrets,
            keychain,
            caveats,
            audit,
            ca_dir,
            daemon,
            print_ca_path,
            install_ca,
        } => {
            run_proxy(
                listen,
                policy,
                secrets,
                keychain,
                caveats,
                audit,
                ca_dir,
                daemon,
                print_ca_path,
                install_ca,
            )
            .await
        }
        Command::Broker { action } => run_broker(action),
        Command::Pack { action } => run_pack(action),
        Command::Report { audit, window } => run_report(audit, window),
        Command::Exec {
            policy,
            audit,
            allow_network,
            writable,
            cmd,
        } => run_exec(policy, audit, allow_network, writable, cmd),
    }
}

/// Decide an exec command against the policy and, if allowed, run it — sandboxed
/// when the matched rule requested it. Exits non-zero on deny/ask, on a missing
/// sandbox backend for a sandboxed action (fail closed), or with the child's code.
fn run_exec(
    policy_path: Option<PathBuf>,
    audit: Option<PathBuf>,
    allow_network: bool,
    writable: Vec<PathBuf>,
    cmd: Vec<String>,
) -> anyhow::Result<()> {
    use guardian_sandbox::{detect, SandboxOpts};

    let (program, args) = cmd.split_first().expect("clap requires a command");
    let call = ToolCall {
        tool: program.clone(),
        args: json!({ "cmd": cmd.join(" ") }),
        kind: Some(ActionKind::Exec),
        capability: None,
    };
    let action =
        guardian_mcp_gateway::build_action(&call, "exec", ActionId::new("exec"), now_ms_cli());

    let policy = load_policy(&policy_path)?;
    let outcome = policy.evaluate(&action, &eval_env());

    // Record the decision (best-effort: the audit log is the forensic record, not a
    // gate for the local exec front-end).
    let audit_path = audit
        .or_else(|| std::env::var_os("GUARDIAN_AUDIT").map(PathBuf::from))
        .unwrap_or_else(|| guardian_daemon::config::guardian_dir().join("audit.db"));
    if let Some(parent) = audit_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match AuditLog::open(&audit_path) {
        Ok(mut log) => {
            let entry = guardian_audit::AuditEntry::for_decision(
                &action,
                &outcome.decision,
                outcome.matched_rule.clone(),
                None,
                None,
                outcome.critical,
            );
            if log.append(&entry).is_err() {
                eprintln!("guardian: warning: could not write the audit entry for this exec");
            }
        }
        Err(e) => eprintln!("guardian: warning: could not open the audit log ({e})"),
    }

    match &outcome.decision {
        Decision::Deny { reason } => {
            eprintln!("guardian: denied: {reason}");
            std::process::exit(126);
        }
        Decision::Ask { reason } => {
            // No human is attached to this one-shot front-end: fail closed.
            eprintln!("guardian: needs approval, not running: {reason}");
            std::process::exit(126);
        }
        Decision::Allow => {}
    }

    let status = if outcome.sandbox {
        match detect() {
            Some(runner) => {
                eprintln!("guardian: running sandboxed via {}", runner.name());
                let opts = SandboxOpts {
                    allow_network,
                    writable_paths: writable,
                };
                runner.run(program, args, &opts)
            }
            None => {
                // Policy demanded a sandbox but none is available → fail closed.
                eprintln!("guardian: policy requires a sandbox but no backend is available; refusing to run unconfined");
                std::process::exit(126);
            }
        }
    } else {
        std::process::Command::new(program).args(args).status()
    };

    match status {
        Ok(st) => std::process::exit(st.code().unwrap_or(1)),
        Err(e) => {
            eprintln!("guardian: failed to run {program}: {e}");
            std::process::exit(1);
        }
    }
}

/// Wall-clock milliseconds for the exec action's timestamp.
fn now_ms_cli() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Run the network proxy: load policy + broker + audit + local CA, then mediate
/// every request until Ctrl-C. (Thin CLI adapter — the args mirror the `Proxy`
/// clap variant 1:1, so a wrapper struct would only duplicate it.)
#[allow(clippy::too_many_arguments)]
async fn run_proxy(
    listen: String,
    policy_path: Option<PathBuf>,
    secrets: Option<PathBuf>,
    keychain: Vec<String>,
    caveats: Option<PathBuf>,
    audit: Option<PathBuf>,
    ca_dir: Option<PathBuf>,
    daemon: Option<PathBuf>,
    print_ca_path: bool,
    install_ca: bool,
) -> anyhow::Result<()> {
    use guardian_proxy::ca::LocalCa;
    use std::sync::{Arc, Mutex};

    let ca_dir = ca_dir.unwrap_or_else(|| guardian_daemon::config::guardian_dir().join("proxy-ca"));
    if print_ca_path {
        let (cert_path, _) = LocalCa::paths(&ca_dir);
        // Ensure it exists so the path is real to install.
        LocalCa::load_or_generate(&ca_dir)?;
        println!("{}", cert_path.display());
        return Ok(());
    }
    if install_ca {
        LocalCa::load_or_generate(&ca_dir)?;
        let (cert_path, _) = LocalCa::paths(&ca_dir);
        return install_ca_trust(&cert_path);
    }

    let addr: std::net::SocketAddr = listen
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid --listen address {listen:?}: {e}"))?;

    let policy = Arc::new(load_policy(&policy_path)?);
    let env = Arc::new(eval_env());

    let mut broker = match &secrets {
        Some(path) => {
            warn_if_world_readable(path);
            let src = std::fs::read_to_string(path)?;
            guardian_broker::Broker::from_toml_str(&src)
                .map_err(|e| anyhow::anyhow!("secrets file {}: {e}", path.display()))?
        }
        None => guardian_broker::Broker::default(),
    };
    // Least-privilege caveats per target (§8.1), if supplied.
    if let Some(path) = &caveats {
        let src = std::fs::read_to_string(path)?;
        broker
            .caveats_from_toml_str(&src)
            .map_err(|e| anyhow::anyhow!("caveats file {}: {e}", path.display()))?;
    }
    // Overlay any keychain-sourced secrets (preferred Phase 3 store).
    if !keychain.is_empty() {
        broker
            .add_keychain_targets(&keychain)
            .map_err(|e| anyhow::anyhow!("keychain: {e}"))?;
        // Tell the operator which targets actually resolved (values never printed),
        // so a typo or unstored target doesn't silently leave a host uncredentialed.
        let (resolved, skipped): (Vec<_>, Vec<_>) = keychain.iter().partition(|t| broker.has(t));
        eprintln!(
            "keychain: {} resolved, {} not found",
            resolved.len(),
            skipped.len()
        );
        if !skipped.is_empty() {
            eprintln!(
                "  not in keychain (no credential): {}",
                skipped
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    let broker = Arc::new(broker);

    let audit_path = audit
        .or_else(|| std::env::var_os("GUARDIAN_AUDIT").map(PathBuf::from))
        .unwrap_or_else(|| guardian_daemon::config::guardian_dir().join("audit.db"));
    if let Some(parent) = audit_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let audit_log = Arc::new(Mutex::new(AuditLog::open(&audit_path)?));

    let ca = LocalCa::load_or_generate(&ca_dir)?;
    let (cert_path, _) = LocalCa::paths(&ca_dir);
    let mut handler = guardian_proxy::server::GuardianHandler::new(policy, env, broker, audit_log);
    if let Some(socket) = &daemon {
        handler = handler.with_approver(Arc::new(ProxyDaemonApprover {
            client: guardian_daemon::DaemonClient::new(socket.clone()),
        }));
    }

    println!("guardian proxy listening on http://{addr}");
    println!("  audit log : {}", audit_path.display());
    println!(
        "  local CA  : {} (install/trust for HTTPS)",
        cert_path.display()
    );
    match &daemon {
        Some(s) => println!("  ask → cockpit at {}", s.display()),
        None => println!("  ask → fail-closed (no --daemon cockpit wired)"),
    }
    println!("  point the agent at it: export HTTP_PROXY=http://{addr} HTTPS_PROXY=http://{addr}");
    println!("  Ctrl-C to stop.");

    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    guardian_proxy::server::run(addr, &ca, handler, shutdown).await?;
    Ok(())
}

/// Install/trust the local proxy CA so HTTPS interception works. Installing a CA
/// is **security-sensitive** — it lets Guardian (and anyone holding the CA key)
/// present a trusted certificate for any site — so we warn first. On macOS we run
/// `security add-trusted-cert` (the OS prompts you to authorize); elsewhere we print
/// the exact command for you to run (it needs your administrator rights).
fn install_ca_trust(cert_path: &std::path::Path) -> anyhow::Result<()> {
    eprintln!(
        "WARNING: trusting this CA lets Guardian intercept ALL your TLS traffic.\n\
         Install it only for the machine/agent you are guarding, and keep the CA key\n\
         (next to the cert) private.\n"
    );
    println!("{}", ca_trust_instructions(cert_path));

    if cfg!(target_os = "macos") {
        let keychain = std::env::var("HOME")
            .map(|h| format!("{h}/Library/Keychains/login.keychain-db"))
            .unwrap_or_default();
        println!("\nRunning: security add-trusted-cert -r trustRoot -k <login keychain> <cert>");
        println!("(macOS will prompt you to authorize this change.)");
        let status = std::process::Command::new("security")
            .args(["add-trusted-cert", "-r", "trustRoot", "-k", &keychain])
            .arg(cert_path)
            .status();
        match status {
            Ok(s) if s.success() => println!("CA trusted in your login keychain."),
            _ => println!("Could not install automatically — run the command above yourself."),
        }
    }
    Ok(())
}

/// The platform-specific, copy-pasteable instructions to trust `cert_path`. Pure
/// (no I/O) so it is unit-testable.
fn ca_trust_instructions(cert_path: &std::path::Path) -> String {
    let p = cert_path.display();
    if cfg!(target_os = "macos") {
        format!(
            "To trust the Guardian CA on macOS:\n  \
             security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db {p}\n  \
             (or open {p} in Keychain Access and set it to \"Always Trust\").\n  \
             To remove later: security delete-certificate -c \"Guardian Local CA\"."
        )
    } else if cfg!(target_os = "linux") {
        format!(
            "To trust the Guardian CA on Linux (Debian/Ubuntu):\n  \
             sudo cp {p} /usr/local/share/ca-certificates/guardian-local-ca.crt\n  \
             sudo update-ca-certificates\n  \
             To remove later: delete that file and re-run update-ca-certificates."
        )
    } else {
        format!("Trust this certificate in your system/client trust store: {p}")
    }
}

/// Manage broker secrets in the OS keychain. `set` reads the secret from stdin so
/// it never lands in the shell history or process arguments.
fn run_broker(action: BrokerAction) -> anyhow::Result<()> {
    use guardian_broker::keychain;
    use std::io::Read;
    match action {
        BrokerAction::Set { target } => {
            let mut secret = String::new();
            std::io::stdin().read_to_string(&mut secret)?;
            let secret = secret.trim_end_matches(['\n', '\r']);
            if secret.is_empty() {
                anyhow::bail!("no secret on stdin; nothing stored (pipe it in, e.g. `printf %s \"$TOKEN\" | guardian broker set {target}`)");
            }
            keychain::store(&target, secret)?;
            println!("Stored a secret for {target} in the OS keychain.");
        }
        BrokerAction::Delete { target } => {
            keychain::delete(&target)?;
            println!("Removed any secret for {target}.");
        }
        BrokerAction::Has { target } => {
            // Never print the value — only whether one exists.
            let present = keychain::load(&target)?.is_some();
            println!("{}", if present { "present" } else { "absent" });
        }
    }
    Ok(())
}

/// Sign or verify a signed community policy pack (§8.4).
fn run_pack(action: PackAction) -> anyhow::Result<()> {
    use guardian_policy::pack;
    match action {
        PackAction::Sign {
            dir,
            name,
            version,
            key_file,
        } => {
            // Reuse the seed if the key file exists; otherwise mint one and save it
            // owner-only so the publisher key is stable across signings.
            let seed_hex = if key_file.exists() {
                std::fs::read_to_string(&key_file)?.trim().to_string()
            } else {
                let seed = pack::generate_seed_hex()?;
                write_private_file(&key_file, &seed)?;
                eprintln!(
                    "guardian: generated a new signing key at {}",
                    key_file.display()
                );
                seed
            };
            let signed = pack::sign_with_seed_hex(&dir, &name, &version, &seed_hex)?;
            std::fs::write(
                dir.join(pack::MANIFEST_FILE),
                serde_json::to_string_pretty(&signed)?,
            )?;
            println!(
                "Signed pack '{name}' v{version} ({} file(s)).",
                signed.manifest.files.len()
            );
            println!(
                "  publisher (share this to let others pin you): {}",
                signed.publisher
            );
        }
        PackAction::Verify { dir, pubkey, audit } => {
            let signed = pack::load_signed(&dir)?;
            pack::verify(&dir, &signed, pubkey.as_deref())
                .map_err(|e| anyhow::anyhow!("pack verification FAILED: {e}"))?;
            println!(
                "OK: pack '{}' v{} verified ({} file(s)); publisher {}",
                signed.manifest.name,
                signed.manifest.version,
                signed.manifest.files.len(),
                signed.publisher
            );
            let widening = pack::critical_widening_rules(&dir)?;
            if widening.is_empty() {
                println!("  no critical-category widening.");
            } else {
                println!(
                    "  WARNING: this pack widens critical categories (needs opt-in to load): {}",
                    widening.join(", ")
                );
            }
            if let Some(audit_path) = audit {
                record_pack_provenance(&audit_path, &signed)?;
                println!("  provenance recorded in {}", audit_path.display());
            }
        }
    }
    Ok(())
}

/// Append a tamper-evident provenance entry for a verified pack (publisher, name,
/// version) to the audit log, so what policy is trusted is itself auditable.
fn record_pack_provenance(
    audit_path: &std::path::Path,
    signed: &guardian_policy::pack::SignedPack,
) -> anyhow::Result<()> {
    if let Some(parent) = audit_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let action = Action {
        id: ActionId::new("pack"),
        kind: ActionKind::Other,
        tool: "policy-pack".to_string(),
        args: json!({
            "name": signed.manifest.name,
            "version": signed.manifest.version,
            "publisher": signed.publisher,
        }),
        capability: None,
        context: guardian_core::ActionContext {
            timestamp_ms: now_ms_cli(),
            source: "pack-verify".to_string(),
            session: None,
            host: None,
            principal: None,
            path: None,
            extra: serde_json::Map::new(),
        },
    };
    let mut log = AuditLog::open(audit_path)?;
    let entry = guardian_audit::AuditEntry::for_decision(
        &action,
        &Decision::Allow,
        Some("pack-verified".to_string()),
        None,
        None,
        false,
    );
    log.append(&entry)?;
    Ok(())
}

/// Write a secret file with owner-only permissions on unix (best-effort elsewhere).
fn write_private_file(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    std::fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Summarize recent audit activity and surface (advisory) rule suggestions. Read
/// only — never edits the policy or the log.
fn run_report(audit: Option<PathBuf>, window: usize) -> anyhow::Result<()> {
    let path = audit
        .or_else(|| std::env::var_os("GUARDIAN_AUDIT").map(PathBuf::from))
        .unwrap_or_else(|| guardian_daemon::config::guardian_dir().join("audit.db"));
    if !path.exists() {
        println!("No audit log at {} yet.", path.display());
        return Ok(());
    }
    let log = AuditLog::open(&path)?;
    let entries: Vec<_> = log.tail(window)?.into_iter().map(|(_, e)| e).collect();
    let report = guardian_audit::report::build_report(&entries);

    println!(
        "Guardian report — last {} decision(s) of {}",
        report.total,
        path.display()
    );
    println!(
        "  allow {}   ask {}   deny {}",
        report.allows, report.asks, report.denies
    );

    if !report.blocked.is_empty() {
        println!("\nTop blocked:");
        for b in &report.blocked {
            println!("  {:>4}x  {}", b.count, cell(&b.label, 60));
        }
    }

    if report.suggestions.is_empty() {
        println!(
            "\nNo suggestions — nothing safe to relax. (Critical categories are never suggested.)"
        );
    } else {
        println!("\nSuggestions to confirm (advisory — Guardian never edits your policy):");
        for s in &report.suggestions {
            println!("  - {}", cell(&s.text, 110));
        }
    }
    Ok(())
}

/// Browse the tamper-evident audit log: print recent decisions and the integrity
/// status. Read-only — never modifies the log.
fn run_log(audit: Option<PathBuf>, limit: usize, verify_key: Option<String>) -> anyhow::Result<()> {
    let path = audit
        .or_else(|| std::env::var_os("GUARDIAN_AUDIT").map(PathBuf::from))
        .unwrap_or_else(|| guardian_daemon::config::guardian_dir().join("audit.db"));
    if !path.exists() {
        println!("No audit log at {} yet.", path.display());
        return Ok(());
    }
    let log = AuditLog::open(&path)?;
    let total = log.len()?;
    // With a trusted key, verify the head signature too (§9.2); otherwise the
    // hash-chain only.
    let (intact, mode) = match &verify_key {
        Some(key) => (log.verify_with_pubkey(key).is_ok(), "signed+chain"),
        None => (log.verify().is_ok(), "chain"),
    };
    println!(
        "Audit log: {}  ({total} entries)  integrity: {} ({mode})",
        path.display(),
        if intact { "OK" } else { "TAMPERED" }
    );
    if total == 0 {
        return Ok(());
    }
    println!(
        "{:>5}  {:<6}  {:<11}  {:<22}  reason",
        "seq", "decn", "kind", "rule"
    );
    for (seq, e) in log.tail(limit)? {
        let rule = cell(e.matched_rule.as_deref().unwrap_or("-"), 22);
        let reason_raw = e
            .decision_reason
            .as_deref()
            .or(e.checker_rationale.as_deref())
            .unwrap_or("-");
        let reason = cell(reason_raw, 60);
        println!(
            "{seq:>5}  {:<6}  {:<11}  {rule:<22}  {reason}",
            e.decision.to_uppercase(),
            e.action_kind,
        );
    }
    Ok(())
}

/// One table cell: collapse control chars to spaces and clip to `max` (so a
/// multi-line or very long reason can't wreck the one-row-per-entry layout).
fn cell(s: &str, max: usize) -> String {
    let flat: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if flat.chars().count() > max {
        let kept: String = flat.chars().take(max.saturating_sub(1)).collect();
        format!("{kept}…")
    } else {
        flat
    }
}

/// Read a tool-call JSON object from stdin and print the policy decision as JSON,
/// without executing anything. This is the integration point for external
/// evaluators (e.g. the AgentDojo shim): one decision per call.
fn run_decide(policy_path: Option<PathBuf>) -> anyhow::Result<()> {
    use std::io::Read;
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let call: ToolCall = serde_json::from_str(input.trim())
        .map_err(|e| anyhow::anyhow!("invalid tool-call JSON on stdin: {e}"))?;
    let action = guardian_mcp_gateway::build_action(
        &call,
        "decide",
        guardian_core::ActionId::new("decide"),
        0,
    );

    let policy = load_policy(&policy_path)?;
    let outcome = policy.evaluate(&action, &eval_env());
    let (decision, reason) = match &outcome.decision {
        Decision::Allow => ("allow", None),
        Decision::Ask { reason } => ("ask", Some(reason.clone())),
        Decision::Deny { reason } => ("deny", Some(reason.clone())),
    };
    println!(
        "{}",
        json!({
            "decision": decision,
            "reason": reason,
            "critical": outcome.critical,
            "matched_rule": outcome.matched_rule,
        })
    );
    Ok(())
}

/// Load a policy file, or the built-in demo policy when no path is given.
fn load_policy(policy_path: &Option<PathBuf>) -> anyhow::Result<CompiledPolicy> {
    let src = match policy_path {
        Some(path) => std::fs::read_to_string(path)?,
        None => DEMO_POLICY.to_string(),
    };
    Ok(CompiledPolicy::from_toml_str(&src)?)
}

/// The evaluation environment shared by the non-executing front-ends.
fn eval_env() -> EvalEnv {
    EvalEnv {
        user_home: std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string()),
        // No host is trusted until explicitly configured: an empty list means the
        // `http-get-trusted` allow rule never fires, so network actions fall to
        // ask/deny (fail safe). Avoids shipping a placeholder "trusted" host.
        trusted_hosts: Vec::new(),
    }
}

/// Claude Code `PreToolUse` hook adapter. Reads the hook payload on stdin and
/// prints the permission decision JSON Claude Code expects, so Guardian mediates
/// Claude Code's **native** tools (Bash, Edit, Write, …), not just MCP tools.
///
/// Always exits 0 with a decision (the recommended pattern): we never silently
/// fail open. If the policy can't load or the payload can't be classified we
/// emit `ask` — nothing executes without the human, but the agent isn't bricked.
fn run_claude_hook(policy_path: Option<PathBuf>) -> anyhow::Result<()> {
    use std::io::Read;
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;

    let (decision, reason) = match load_policy(&policy_path) {
        Ok(policy) => decide_hook(&input, &policy, &eval_env()),
        Err(e) => (
            "ask",
            format!("Guardian policy failed to load ({e}); escalating to you."),
        ),
    };

    println!(
        "{}",
        json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision,
                "permissionDecisionReason": reason,
            }
        })
    );
    Ok(())
}

/// Pure core of the hook: classify the Claude Code tool call and ask the policy.
/// Returns `(permissionDecision, reason)`. Fail-safe: any parse problem → `ask`.
fn decide_hook(input: &str, policy: &CompiledPolicy, env: &EvalEnv) -> (&'static str, String) {
    let value: Value = match serde_json::from_str(input.trim()) {
        Ok(v) => v,
        Err(e) => {
            return (
                "ask",
                format!("Guardian could not parse the hook input ({e}); escalating to you."),
            )
        }
    };
    let tool_name = match value.get("tool_name").and_then(Value::as_str) {
        Some(name) => name,
        None => {
            return (
                "ask",
                "Guardian saw no tool_name; escalating to you.".to_string(),
            )
        }
    };
    let tool_input = value.get("tool_input").cloned().unwrap_or(Value::Null);

    let call = claude_tool_to_call(tool_name, &tool_input);
    let action =
        guardian_mcp_gateway::build_action(&call, "claude-code-hook", ActionId::new("hook"), 0);
    let outcome = policy.evaluate(&action, env);
    match outcome.decision {
        Decision::Allow => ("allow", "Allowed by Guardian policy.".to_string()),
        Decision::Ask { reason } => ("ask", reason),
        Decision::Deny { reason } => ("deny", reason),
    }
}

/// Map a Claude Code `(tool_name, tool_input)` to a Guardian [`ToolCall`],
/// normalizing the fields the policy reads (`path`, `host`, `cmd`, `method`).
/// Tools we don't recognize (MCP, internal, future) are pinned to
/// [`ActionKind::Other`] so they hit the policy's restrictive default (`ask`).
/// We must NOT leave `kind` as `None` here: `build_action` would then infer the
/// kind from the *tool name* substring, so a tool merely named `*read*`/`*open*`
/// would be classified `FileRead` and auto-allowed — a fail-open driven by an
/// attacker-controlled name (a compromised MCP server could exploit it).
fn claude_tool_to_call(tool_name: &str, input: &Value) -> ToolCall {
    let s = |key: &str| input.get(key).and_then(Value::as_str);
    let (kind, args): (Option<ActionKind>, Value) = match tool_name {
        "Read" | "Glob" | "Grep" | "LS" | "NotebookRead" => (
            Some(ActionKind::FileRead),
            json!({ "path": s("file_path").or_else(|| s("path")).unwrap_or_default() }),
        ),
        "Write" => (
            Some(ActionKind::FileWrite),
            json!({ "path": s("file_path").unwrap_or_default() }),
        ),
        "Edit" | "MultiEdit" | "NotebookEdit" => (
            Some(ActionKind::FileWrite),
            json!({ "path": s("file_path").or_else(|| s("notebook_path")).unwrap_or_default() }),
        ),
        "Bash" => (
            Some(ActionKind::Exec),
            json!({ "cmd": s("command").unwrap_or_default() }),
        ),
        "WebFetch" => (
            Some(ActionKind::HttpRequest),
            json!({ "method": "GET", "host": host_from_url(s("url").unwrap_or_default()) }),
        ),
        "WebSearch" => (Some(ActionKind::HttpRequest), json!({ "method": "GET" })),
        // Unrecognized → Other (restrictive default), never name-inferred. See the
        // doc comment above: leaving this `None` would be a fail-open.
        _ => (Some(ActionKind::Other), input.clone()),
    };
    ToolCall {
        tool: tool_name.to_string(),
        args,
        kind,
        capability: None,
    }
}

/// Extract the host from a URL without pulling in a URL-parsing dependency.
/// `https://user@host:443/path` → `host`. Best-effort; empty on no host.
///
/// Backslashes are normalized to `/` first (WHATWG treats them as path
/// separators for special schemes), so `https://evil.net\@trusted/` resolves to
/// host `evil.net`, not `trusted` — otherwise an untrusted host could read as
/// trusted. The authority ends at the first `/`, `?`, or `#`.
fn host_from_url(url: &str) -> String {
    let url = url.replace('\\', "/");
    let after_scheme = url.split("://").nth(1).unwrap_or(&url);
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    host_port.split(':').next().unwrap_or("").to_string()
}

fn validate_policy(path: &PathBuf) -> anyhow::Result<()> {
    let text = std::fs::read_to_string(path)?;
    match CompiledPolicy::from_toml_str(&text) {
        Ok(p) => {
            println!(
                "OK: role `{}`, {} rule(s) compiled.",
                p.policy().role,
                p.policy().rules.len()
            );
            Ok(())
        }
        Err(e) => {
            eprintln!("INVALID: {e}");
            std::process::exit(1);
        }
    }
}

/// A demo policy that only uses fields the gateway populates today (no Phase-2
/// proxy fields), so the traffic light is fully exercised.
const DEMO_POLICY: &str = r#"
version = 1
role = "demo"

[defaults]
decision = "ask"

[[rules]]
id = "read-files"
when = 'action.kind == "FileRead"'
decision = "allow"

[[rules]]
id = "exec-shell"
when = 'action.kind == "Exec"'
decision = "ask"
sandbox = true
explain = "Runs a shell command on your computer."

[[rules]]
id = "money-movement"
when = 'action.capability == "Payment"'
decision = "ask"
critical = true
explain = "Sends money from your account."
cap = { amount_max = 200.0 }

[[rules]]
id = "data-exfiltration"
when = 'action.kind == "HttpRequest" && action.args.method == "POST" && !(action.context.host in trusted_hosts)'
decision = "deny"
critical = true
explain = "Tried to send data to a site that is not on your trusted list."
"#;

/// Auto-approves `ask` actions, printing the Checker's plain-language review so
/// the yellow (pause) step is visible.
struct DemoApprover;

#[async_trait]
impl Approver for DemoApprover {
    async fn request_approval(
        &self,
        _action: &Action,
        explanation: &Explanation,
    ) -> ApprovalResponse {
        println!(
            "   🟡 NEEDS REVIEW: {} [risk {}] → auto-approving for the demo",
            explanation.plain_text, explanation.risk
        );
        ApprovalResponse::Approved
    }
}

/// A stand-in for the real tool/MCP server.
struct DemoUpstream;

#[async_trait]
impl Upstream for DemoUpstream {
    async fn forward(&self, _call: &ToolCall) -> Result<Value, String> {
        Ok(json!({ "status": "executed" }))
    }
}

/// Wraps an upstream so the token broker injects the destination's credential into
/// each forwarded call — the agent never supplies (or sees) it. The destination is
/// the namespace label (`label__tool`), or the whole tool name if unnamespaced.
/// The credential field is broker-owned (any agent-supplied value is scrubbed), and
/// a token is injected only for a known registered upstream label.
struct BrokeredUpstream {
    broker: guardian_broker::Broker,
    targets: std::collections::HashSet<String>,
    inner: Box<dyn Upstream>,
}

#[async_trait]
impl Upstream for BrokeredUpstream {
    async fn forward(&self, call: &ToolCall) -> Result<Value, String> {
        let mut call = call.clone();
        // The credential field is broker-owned: drop any agent-supplied value so the
        // agent can neither set nor keep a credential there.
        if let Some(obj) = call.args.as_object_mut() {
            obj.remove(guardian_broker::DEFAULT_FIELD);
        }
        let target = call
            .tool
            .split_once("__")
            .map(|(label, _)| label.to_string())
            .unwrap_or_else(|| call.tool.clone());
        // Inject only for a known, registered upstream label (no cross-target leak).
        if self.targets.contains(&target) {
            self.broker.inject(&target, &mut call.args);
        }
        self.inner.forward(&call).await
    }
}

/// Warn (don't fail) if a secrets file is group/other-accessible.
fn warn_if_world_readable(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.mode() & 0o077 != 0 {
                eprintln!(
                    "guardian: warning: secrets file {} is group/other-accessible; `chmod 600` it",
                    path.display()
                );
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

async fn run_demo() -> anyhow::Result<()> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());
    let env = EvalEnv {
        user_home: home.clone(),
        trusted_hosts: vec!["api.example.com".to_string()],
    };
    let gateway = Gateway::new(
        "demo-cli",
        CompiledPolicy::from_toml_str(DEMO_POLICY)?,
        Box::new(StubChecker),
        Box::new(DemoApprover),
        Box::new(DemoUpstream),
        AuditLog::open_in_memory()?,
        env,
    );

    let calls = vec![
        ToolCall {
            tool: "fs.read".into(),
            args: json!({ "path": format!("{home}/notes.txt") }),
            kind: Some(ActionKind::FileRead),
            capability: None,
        },
        ToolCall {
            tool: "shell.run".into(),
            args: json!({ "cmd": "ls -la" }),
            kind: Some(ActionKind::Exec),
            capability: None,
        },
        ToolCall {
            tool: "bank.transfer".into(),
            args: json!({ "amount": 5000 }),
            kind: Some(ActionKind::Payment),
            capability: Some(Capability::Payment),
        },
        ToolCall {
            tool: "http.post".into(),
            args: json!({ "method": "POST", "host": "evil.example.net" }),
            kind: Some(ActionKind::HttpRequest),
            capability: None,
        },
        ToolCall {
            tool: "mystery.thing".into(),
            args: json!({}),
            kind: None,
            capability: None,
        },
    ];

    println!("Project Guardian — demo (trusted host: api.example.com)\n");
    for call in calls {
        println!("▶ {}", call.tool);
        match gateway.handle(call).await {
            GatewayOutcome::Allowed(_) => println!("   ✅ ALLOWED (forwarded to the tool)\n"),
            GatewayOutcome::Blocked(reason) => println!("   ⛔ BLOCKED: {reason}\n"),
            GatewayOutcome::UpstreamError(e) => {
                println!("   ⚠️  forwarded, but the tool failed: {e}\n")
            }
        }
    }

    println!(
        "Audit log: {} entries, integrity {}",
        gateway.audit_len(),
        if gateway.audit_verify().is_ok() {
            "OK ✅"
        } else {
            "TAMPERED ❌"
        }
    );
    Ok(())
}

/// An approver used when running headless (no UI attached): `ask` decisions fail
/// closed (denied). Wire the daemon in for real human approvals.
struct DenyAsksApprover;

#[async_trait]
impl Approver for DenyAsksApprover {
    async fn request_approval(&self, _: &Action, _: &Explanation) -> ApprovalResponse {
        ApprovalResponse::Denied
    }
}

/// Routes `ask` decisions to a running daemon's approval queue (and its cockpit),
/// so a human can approve a proxied tool call. Fails closed (Denied) on a denial
/// or any socket error.
struct DaemonApprover {
    client: guardian_daemon::DaemonClient,
}

#[async_trait]
impl Approver for DaemonApprover {
    async fn request_approval(
        &self,
        action: &Action,
        explanation: &Explanation,
    ) -> ApprovalResponse {
        match self
            .client
            .approve(
                action.id.as_str(),
                &action.tool,
                &explanation.plain_text,
                explanation.risk,
            )
            .await
        {
            Ok(true) => ApprovalResponse::Approved,
            _ => ApprovalResponse::Denied,
        }
    }
}

/// Bridges the network proxy's `ask` decisions to a running daemon's cockpit, so
/// the proxy stays decoupled from the daemon IPC (it only knows the `Approver`
/// trait). A no-answer/timeout from the daemon resolves to deny (fail closed).
struct ProxyDaemonApprover {
    client: guardian_daemon::DaemonClient,
}

#[async_trait]
impl guardian_proxy::server::Approver for ProxyDaemonApprover {
    async fn approve(&self, action: &Action) -> bool {
        let host = action.context.host.as_deref().unwrap_or("?");
        let method = action
            .args
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or("?");
        let path = action
            .args
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or("");
        let plain = format!("Network request: {method} {host}{path}");
        // Network egress that reaches `ask` warrants a visible risk level.
        self.client
            .approve(action.id.as_str(), &action.tool, &plain, 6)
            .await
            .unwrap_or(false)
    }
}

fn tool_spec(name: &str, description: &str) -> ToolSpec {
    ToolSpec {
        name: name.to_string(),
        description: description.to_string(),
        input_schema: serde_json::json!({ "type": "object" }),
    }
}

/// Run Guardian as an MCP server over stdio. A real MCP client (any harness) can
/// launch this and have its `tools/call`s mediated by the policy engine. Modes:
/// `--upstream` proxies a real MCP server; `--daemon` mediates via a running
/// daemon; otherwise a self-contained local gateway over the built-in tools.
async fn run_mcp(
    daemon: Option<PathBuf>,
    upstream: Vec<String>,
    policy: Option<PathBuf>,
    secrets: Option<PathBuf>,
) -> anyhow::Result<()> {
    // Proxy mode: front one or more real upstream MCP servers. Their tools are
    // UNTRUSTED, so the classifier comes only from the policy's `[tools]` map — a
    // tool the policy does not classify is `Other` (restrictive default), never
    // inferred from its name. Tools are namespaced `label__tool` (a single
    // unlabeled upstream keeps raw names).
    if !upstream.is_empty() {
        let single = upstream.len() == 1;
        let mut multi = guardian_mcp_gateway::upstream::MultiUpstream::new();
        let mut labels = std::collections::HashSet::new();
        for spec in &upstream {
            let (label_opt, program, args) = parse_upstream(spec);
            if program.is_empty() {
                return Err(anyhow::anyhow!("--upstream command is empty"));
            }
            let label = match label_opt {
                Some(l) => l,
                None if single => String::new(),
                None => derive_label(&program),
            };
            let server = guardian_mcp_gateway::upstream::McpStdioUpstream::spawn(&program, &args)
                .await
                .map_err(|e| anyhow::anyhow!("upstream '{program}': {e}"))?;
            if !multi.add(label.clone(), server) {
                return Err(anyhow::anyhow!(
                    "duplicate upstream label '{label}' — give each --upstream a unique label=..."
                ));
            }
            labels.insert(label);
        }
        let compiled = load_policy(&policy)?;
        let classifier = compiled.policy().tools.clone();
        let tools = multi.tools();
        // With --daemon, route `ask`s to its cockpit; otherwise fail closed.
        let approver: Box<dyn Approver> = match &daemon {
            Some(socket) => Box::new(DaemonApprover {
                client: guardian_daemon::DaemonClient::new(socket.clone()),
            }),
            None => Box::new(DenyAsksApprover),
        };
        // With --secrets, the broker injects the credential for the destination
        // (the namespace label) into each forwarded call — the agent never sees it.
        let upstream: Box<dyn Upstream> = match &secrets {
            Some(path) => {
                warn_if_world_readable(path);
                let src = std::fs::read_to_string(path)?;
                let broker = guardian_broker::Broker::from_toml_str(&src)
                    .map_err(|e| anyhow::anyhow!("secrets file {}: {e}", path.display()))?;
                Box::new(BrokeredUpstream {
                    broker,
                    targets: labels,
                    inner: Box::new(multi),
                })
            }
            None => Box::new(multi),
        };
        let gateway = Gateway::new(
            "guardian-mcp-proxy",
            compiled,
            Box::new(StubChecker),
            approver,
            upstream,
            AuditLog::open_in_memory()?,
            eval_env(),
        );
        McpServer::new(Box::new(gateway), tools)
            .with_classifier(classifier)
            .serve_stdio()
            .await?;
        return Ok(());
    }

    let tools = vec![
        tool_spec("read_file", "Read a file from disk"),
        tool_spec("write_file", "Create or modify a file"),
        tool_spec("http_request", "Make an HTTP request"),
        tool_spec("run_shell", "Run a shell command"),
        tool_spec("send_email", "Send an email on your behalf"),
    ];

    let router: Box<dyn guardian_mcp_gateway::ToolRouter> = match daemon {
        // Mediate through a running daemon: its gateway owns policy + the approval
        // queue the UI drives + audit + the real upstream.
        Some(socket) => Box::new(guardian_daemon::DaemonRouter::new(
            guardian_daemon::DaemonClient::new(socket),
        )),
        // Self-contained local gateway. With no UI attached, asks fail closed.
        None => Box::new(Gateway::new(
            "guardian-mcp",
            load_policy(&policy)?,
            Box::new(StubChecker),
            Box::new(DenyAsksApprover),
            Box::new(DemoUpstream),
            AuditLog::open_in_memory()?,
            eval_env(),
        )),
    };

    // The daemon-bridge and local modes advertise Guardian's own fixed tools, so
    // they use the built-in classification (not a name heuristic, not policy-driven).
    McpServer::new(router, tools)
        .with_classifier(builtin_classifier())
        .serve_stdio()
        .await?;
    Ok(())
}

/// Parse one `--upstream` spec into `(label, program, args)`. A leading
/// `label=` is recognized only when `label` is a clean identifier (no whitespace
/// or `/`), so a command with `=` in its args (and no label) is left intact.
fn parse_upstream(spec: &str) -> (Option<String>, String, Vec<String>) {
    let spec = spec.trim();
    let (label, cmd) = match spec.split_once('=') {
        Some((l, c)) if !l.is_empty() && !l.contains(char::is_whitespace) && !l.contains('/') => {
            (Some(l.to_string()), c.trim())
        }
        _ => (None, spec),
    };
    let mut parts = cmd.split_whitespace();
    let program = parts.next().unwrap_or("").to_string();
    (label, program, parts.map(String::from).collect())
}

/// Derive a namespace label from a program path: its basename without extension.
fn derive_label(program: &str) -> String {
    program
        .rsplit('/')
        .next()
        .unwrap_or(program)
        .split('.')
        .next()
        .unwrap_or(program)
        .to_string()
}

/// Trusted classification for Guardian's own built-in MCP tools.
fn builtin_classifier() -> std::collections::HashMap<String, ActionKind> {
    std::collections::HashMap::from([
        ("read_file".to_string(), ActionKind::FileRead),
        ("write_file".to_string(), ActionKind::FileWrite),
        ("http_request".to_string(), ActionKind::HttpRequest),
        ("run_shell".to_string(), ActionKind::Exec),
        ("send_email".to_string(), ActionKind::Email),
    ])
}

#[cfg(test)]
mod hook_tests {
    use super::*;

    // read → allow, exec → deny; everything else falls through to the ask default.
    const TEST_POLICY: &str = r#"
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
explain = "Shell commands are blocked here."
"#;

    fn decide(input: &str) -> (&'static str, String) {
        let policy = CompiledPolicy::from_toml_str(TEST_POLICY).unwrap();
        let env = EvalEnv {
            user_home: "/home/u".to_string(),
            trusted_hosts: vec!["api.example.com".to_string()],
        };
        decide_hook(input, &policy, &env)
    }

    #[test]
    fn read_is_allowed() {
        let (d, _) = decide(r#"{"tool_name":"Read","tool_input":{"file_path":"/home/u/x.txt"}}"#);
        assert_eq!(d, "allow");
    }

    #[test]
    fn ca_trust_instructions_name_the_cert_and_a_real_command() {
        let s = super::ca_trust_instructions(std::path::Path::new("/tmp/ca.crt"));
        assert!(s.contains("/tmp/ca.crt"));
        // Platform-appropriate, actionable command (not an empty placeholder).
        if cfg!(target_os = "macos") {
            assert!(s.contains("security add-trusted-cert"));
        } else if cfg!(target_os = "linux") {
            assert!(s.contains("update-ca-certificates"));
        } else {
            assert!(s.contains("trust"));
        }
    }

    #[test]
    fn bash_is_denied_with_reason() {
        let (d, reason) =
            decide(r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/x"}}"#);
        assert_eq!(d, "deny");
        assert!(reason.contains("blocked"), "got {reason}");
    }

    #[test]
    fn write_defaults_to_ask() {
        let (d, _) = decide(r#"{"tool_name":"Write","tool_input":{"file_path":"/home/u/x"}}"#);
        assert_eq!(d, "ask");
    }

    #[test]
    fn unknown_and_internal_tools_escalate() {
        // Unrecognized tool → no kind hint → restrictive default (ask), never allow.
        let (d, _) = decide(r#"{"tool_name":"TodoWrite","tool_input":{}}"#);
        assert_eq!(d, "ask");
    }

    #[test]
    fn malformed_input_fails_safe_to_ask() {
        assert_eq!(decide("not json at all").0, "ask");
        assert_eq!(decide(r#"{"no_tool":true}"#).0, "ask");
    }

    #[test]
    fn bash_command_lands_in_cmd_arg() {
        let call = claude_tool_to_call("Bash", &json!({ "command": "ls -la" }));
        assert_eq!(call.kind, Some(ActionKind::Exec));
        assert_eq!(call.args.get("cmd").and_then(Value::as_str), Some("ls -la"));
    }

    #[test]
    fn webfetch_extracts_host() {
        let call = claude_tool_to_call("WebFetch", &json!({ "url": "https://evil.example.net/p" }));
        assert_eq!(call.kind, Some(ActionKind::HttpRequest));
        assert_eq!(
            call.args.get("host").and_then(Value::as_str),
            Some("evil.example.net")
        );
    }

    #[test]
    fn host_from_url_handles_port_and_userinfo() {
        assert_eq!(
            host_from_url("https://user@host.example:8443/x"),
            "host.example"
        );
        assert_eq!(host_from_url("http://plain.host/a/b"), "plain.host");
        assert_eq!(host_from_url("not-a-url"), "not-a-url");
    }

    #[test]
    fn host_from_url_normalizes_backslash_and_separators() {
        // A backslash must not let an untrusted host masquerade as the trusted one.
        assert_eq!(
            host_from_url("https://evil.net\\@api.example.com/"),
            "evil.net"
        );
        assert_eq!(
            host_from_url("https://api.example.com#@evil.net"),
            "api.example.com"
        );
        assert_eq!(
            host_from_url("https://api.example.com?x=@evil.net"),
            "api.example.com"
        );
    }

    #[test]
    fn unrecognized_tool_never_auto_allows() {
        // A tool whose name merely contains "read"/"open" must NOT be auto-allowed:
        // unrecognized tools are pinned to Other → restrictive default (ask).
        assert_eq!(
            decide(r#"{"tool_name":"sneaky_reader","tool_input":{"path":"/etc/shadow"}}"#).0,
            "ask"
        );
        assert_eq!(
            decide(r#"{"tool_name":"open_url","tool_input":{"url":"https://evil.net"}}"#).0,
            "ask"
        );
        assert_eq!(
            claude_tool_to_call("mcp__files__read_secret", &json!({})).kind,
            Some(ActionKind::Other)
        );
    }
}

#[cfg(test)]
mod broker_wiring_tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, Mutex};

    /// Records the call it was asked to forward (so tests can inspect injection).
    struct Recorder(Arc<Mutex<Option<ToolCall>>>);
    #[async_trait]
    impl Upstream for Recorder {
        async fn forward(&self, call: &ToolCall) -> Result<Value, String> {
            *self.0.lock().unwrap() = Some(call.clone());
            Ok(json!({ "ok": true }))
        }
    }

    fn brokered(seen: Arc<Mutex<Option<ToolCall>>>) -> BrokeredUpstream {
        BrokeredUpstream {
            broker: guardian_broker::Broker::new(HashMap::from([(
                "bank".to_string(),
                "real-token".to_string(),
            )])),
            targets: HashSet::from(["bank".to_string()]),
            inner: Box::new(Recorder(seen)),
        }
    }

    #[tokio::test]
    async fn injects_for_known_label_and_scrubs_agent_token() {
        let seen = Arc::new(Mutex::new(None));
        let bu = brokered(seen.clone());
        // The agent tries to supply its own token; it must be replaced by the broker's.
        let call = ToolCall {
            tool: "bank__get_balance".to_string(),
            args: json!({ "auth_token": "attacker", "account": "x" }),
            kind: None,
            capability: None,
        };
        bu.forward(&call).await.unwrap();
        let fwd = seen.lock().unwrap().clone().unwrap();
        assert_eq!(
            fwd.args.get("auth_token").and_then(|v| v.as_str()),
            Some("real-token")
        );
        assert_eq!(fwd.args.get("account").and_then(|v| v.as_str()), Some("x"));
        // The caller's original call is not mutated.
        assert_eq!(
            call.args.get("auth_token").and_then(|v| v.as_str()),
            Some("attacker")
        );
    }

    #[tokio::test]
    async fn unknown_label_scrubs_but_does_not_inject() {
        let seen = Arc::new(Mutex::new(None));
        let bu = brokered(seen.clone());
        let call = ToolCall {
            tool: "other__tool".to_string(),
            args: json!({ "auth_token": "attacker" }),
            kind: None,
            capability: None,
        };
        bu.forward(&call).await.unwrap();
        // No token for an unregistered label, and the agent's value was scrubbed.
        assert!(seen
            .lock()
            .unwrap()
            .clone()
            .unwrap()
            .args
            .get("auth_token")
            .is_none());
    }
}
