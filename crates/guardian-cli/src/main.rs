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
        /// Proxy an upstream MCP server: the full stdio command that launches it
        /// (e.g. --upstream "/path/to/server --flag"). Its tools are mediated.
        #[arg(long)]
        upstream: Option<String>,
        /// Policy file for the local gateway (proxy / default modes; not --daemon).
        #[arg(long)]
        policy: Option<PathBuf>,
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
        } => run_mcp(daemon, upstream, policy).await,
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
/// launch this and have its `tools/call`s mediated by the policy engine. Modes:
/// `--upstream` proxies a real MCP server; `--daemon` mediates via a running
/// daemon; otherwise a self-contained local gateway over the built-in tools.
async fn run_mcp(
    daemon: Option<PathBuf>,
    upstream: Option<String>,
    policy: Option<PathBuf>,
) -> anyhow::Result<()> {
    // Proxy mode: front a real upstream MCP server. Its tools are UNTRUSTED, so the
    // classifier comes only from the policy's `[tools]` map — a tool the policy does
    // not classify is `Other` (restrictive default), never inferred from its name.
    if let Some(command) = upstream {
        let mut parts = command.split_whitespace();
        let program = parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("--upstream command is empty"))?;
        let args: Vec<String> = parts.map(String::from).collect();
        let compiled = load_policy(&policy)?;
        let classifier = compiled.policy().tools.clone();
        let up = guardian_mcp_gateway::upstream::McpStdioUpstream::spawn(program, &args)
            .await
            .map_err(|e| anyhow::anyhow!("upstream MCP server: {e}"))?;
        let tools = up.tools();
        let gateway = Gateway::new(
            "guardian-mcp-proxy",
            compiled,
            Box::new(StubChecker),
            Box::new(DenyAsksApprover),
            Box::new(up),
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
