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
use guardian_core::{Action, ActionKind, Capability, Decision};
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
    Mcp {
        /// Path to a running daemon's control socket to mediate through.
        #[arg(long)]
        daemon: Option<PathBuf>,
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Demo => run_demo().await,
        Command::PolicyValidate { path } => validate_policy(&path),
        Command::Mcp { daemon } => run_mcp(daemon).await,
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

    let policy_src = match &policy_path {
        Some(path) => std::fs::read_to_string(path)?,
        None => DEMO_POLICY.to_string(),
    };
    let policy = CompiledPolicy::from_toml_str(&policy_src)?;
    let env = EvalEnv {
        user_home: std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string()),
        trusted_hosts: vec!["api.example.com".to_string()],
    };

    let outcome = policy.evaluate(&action, &env);
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

fn tool_spec(name: &str, description: &str) -> ToolSpec {
    ToolSpec {
        name: name.to_string(),
        description: description.to_string(),
        input_schema: serde_json::json!({ "type": "object" }),
    }
}

/// Run Guardian as an MCP server over stdio. A real MCP client (any harness) can
/// launch this and have its `tools/call`s mediated by the policy engine.
async fn run_mcp(daemon: Option<PathBuf>) -> anyhow::Result<()> {
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
        None => {
            let env = EvalEnv {
                user_home: std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string()),
                trusted_hosts: vec!["api.example.com".to_string()],
            };
            Box::new(Gateway::new(
                "guardian-mcp",
                CompiledPolicy::from_toml_str(DEMO_POLICY)?,
                Box::new(StubChecker),
                Box::new(DenyAsksApprover),
                Box::new(DemoUpstream),
                AuditLog::open_in_memory()?,
                env,
            ))
        }
    };

    McpServer::new(router, tools).serve_stdio().await?;
    Ok(())
}
