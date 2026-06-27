//! `guardian-policy` — the deterministic policy engine, i.e. the security
//! boundary. It maps a structured [`guardian_core::Action`] to a
//! [`guardian_core::Decision`] as a pure function of (action, context, policy).
//!
//! No LLM and no I/O are ever on this path (ADR-0003). Policies are declarative
//! TOML (`docs/policy-schema.md`); rule conditions are CEL expressions evaluated
//! against the structured action — never the agent's natural-language claims.

#![forbid(unsafe_code)]

mod engine;
pub mod pack;
mod schema;

pub use engine::{CompiledPolicy, EvalEnv, EvalOutcome};
pub use schema::{Cap, DecisionKind, Defaults, Policy, PolicyError, Rule};

#[cfg(test)]
mod tests {
    use super::*;
    use guardian_core::{Action, ActionContext, ActionId, ActionKind, Capability, Decision};
    use serde_json::{json, Value};

    const POLICY: &str = r#"
version = 1
role = "test"

[defaults]
decision = "ask"

[[rules]]
id = "read-files"
when = 'action.kind == "FileRead"'
decision = "allow"

[[rules]]
id = "exec"
when = 'action.kind == "Exec"'
decision = "ask"
sandbox = true
explain = "Runs a shell command."

[[rules]]
id = "http-get-trusted"
when = 'action.kind == "HttpRequest" && action.args.method == "GET" && action.context.host in trusted_hosts'
decision = "allow"

[[rules]]
id = "payment"
when = 'action.capability == "Payment"'
decision = "ask"
critical = true
explain = "Sends money."

[[rules]]
id = "micro-allowance"
when = 'action.tool == "wallet.spend"'
decision = "allow"
cap = { amount_max = 10.0 }

[[rules]]
id = "exfil"
when = 'action.kind == "HttpRequest" && action.args.method == "POST" && !(action.context.host in trusted_hosts)'
decision = "deny"
critical = true
explain = "Posting to an untrusted host."
"#;

    fn env() -> EvalEnv {
        EvalEnv {
            user_home: "/home/u".to_string(),
            trusted_hosts: vec!["api.example.com".to_string()],
        }
    }

    fn action(kind: ActionKind, tool: &str, args: Value, host: Option<&str>) -> Action {
        action_with_capability(kind, tool, args, host, None)
    }

    fn action_with_capability(
        kind: ActionKind,
        tool: &str,
        args: Value,
        host: Option<&str>,
        capability: Option<Capability>,
    ) -> Action {
        Action {
            id: ActionId::new("01TEST"),
            kind,
            tool: tool.to_string(),
            args,
            capability,
            context: ActionContext {
                timestamp_ms: 1_700_000_000_000,
                source: "test".to_string(),
                session: None,
                host: host.map(String::from),
                principal: None,
                path: None,
                extra: serde_json::Map::new(),
            },
        }
    }

    fn compiled() -> CompiledPolicy {
        CompiledPolicy::from_toml_str(POLICY).expect("policy should compile")
    }

    #[test]
    fn green_action_is_allowed_silently() {
        let p = compiled();
        let a = action(ActionKind::FileRead, "fs.read", json!({}), None);
        let out = p.evaluate(&a, &env());
        assert_eq!(out.decision, Decision::Allow);
        assert_eq!(out.matched_rule.as_deref(), Some("read-files"));
        assert!(!out.sandbox);
        assert!(!out.critical);
    }

    #[test]
    fn yellow_action_asks_and_sets_sandbox() {
        let p = compiled();
        let a = action(ActionKind::Exec, "shell.run", json!({ "cmd": "ls" }), None);
        let out = p.evaluate(&a, &env());
        assert_eq!(
            out.decision,
            Decision::Ask {
                reason: "Runs a shell command.".to_string()
            }
        );
        assert!(out.sandbox);
        assert_eq!(out.matched_rule.as_deref(), Some("exec"));
    }

    #[test]
    fn http_get_to_trusted_host_is_allowed() {
        let p = compiled();
        let a = action(
            ActionKind::HttpRequest,
            "http.fetch",
            json!({ "method": "GET" }),
            Some("api.example.com"),
        );
        assert_eq!(p.evaluate(&a, &env()).decision, Decision::Allow);
    }

    #[test]
    fn red_exfiltration_is_denied() {
        let p = compiled();
        let a = action(
            ActionKind::HttpRequest,
            "http.fetch",
            json!({ "method": "POST" }),
            Some("evil.example.net"),
        );
        let out = p.evaluate(&a, &env());
        assert_eq!(
            out.decision,
            Decision::Deny {
                reason: "Posting to an untrusted host.".to_string()
            }
        );
        assert!(out.critical);
    }

    #[test]
    fn payment_is_ask_and_critical() {
        let p = compiled();
        let a = action_with_capability(
            ActionKind::Payment,
            "bank.transfer",
            json!({ "amount": 50.0 }),
            None,
            Some(Capability::Payment),
        );
        let out = p.evaluate(&a, &env());
        assert!(matches!(out.decision, Decision::Ask { .. }));
        assert!(out.critical);
    }

    #[test]
    fn cap_violation_escalates_allow_to_ask() {
        let p = compiled();
        let under = action(
            ActionKind::Payment,
            "wallet.spend",
            json!({ "amount": 5.0 }),
            None,
        );
        assert_eq!(p.evaluate(&under, &env()).decision, Decision::Allow);

        let over = action(
            ActionKind::Payment,
            "wallet.spend",
            json!({ "amount": 50.0 }),
            None,
        );
        assert!(matches!(
            p.evaluate(&over, &env()).decision,
            Decision::Ask { .. }
        ));
    }

    #[test]
    fn unmatched_action_falls_to_restrictive_default() {
        let p = compiled();
        let a = action(ActionKind::Other, "mystery.tool", json!({}), None);
        let out = p.evaluate(&a, &env());
        assert!(matches!(out.decision, Decision::Ask { .. }));
        assert_eq!(out.matched_rule, None);
    }

    #[test]
    fn most_restrictive_wins_across_matching_rules() {
        // Two rules both match an Exec action; deny must win over allow.
        let policy = r#"
version = 1
role = "t"
[defaults]
decision = "ask"
[[rules]]
id = "allow-exec"
when = 'action.kind == "Exec"'
decision = "allow"
[[rules]]
id = "deny-exec"
when = 'action.kind == "Exec"'
decision = "deny"
"#;
        let p = CompiledPolicy::from_toml_str(policy).unwrap();
        let a = action(ActionKind::Exec, "shell.run", json!({}), None);
        let out = p.evaluate(&a, &env());
        assert!(matches!(out.decision, Decision::Deny { .. }));
        assert_eq!(out.matched_rule.as_deref(), Some("deny-exec"));
    }

    #[test]
    fn permissive_default_is_rejected() {
        let policy = "version = 1\nrole = \"t\"\n[defaults]\ndecision = \"allow\"\n";
        assert!(matches!(
            CompiledPolicy::from_toml_str(policy),
            Err(PolicyError::PermissiveDefault)
        ));
    }

    #[test]
    fn duplicate_rule_id_is_rejected() {
        let policy = r#"
version = 1
role = "t"
[defaults]
decision = "ask"
[[rules]]
id = "dup"
when = 'true'
decision = "allow"
[[rules]]
id = "dup"
when = 'false'
decision = "deny"
"#;
        assert!(matches!(
            CompiledPolicy::from_toml_str(policy),
            Err(PolicyError::DuplicateRuleId(_))
        ));
    }

    #[test]
    fn invalid_when_expression_is_rejected() {
        let policy = r#"
version = 1
role = "t"
[defaults]
decision = "ask"
[[rules]]
id = "bad"
when = 'this is ))) not valid'
decision = "allow"
"#;
        assert!(matches!(
            CompiledPolicy::from_toml_str(policy),
            Err(PolicyError::InvalidWhen { .. })
        ));
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let policy = "version = 2\nrole = \"t\"\n[defaults]\ndecision = \"ask\"\n";
        assert!(matches!(
            CompiledPolicy::from_toml_str(policy),
            Err(PolicyError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn shipped_default_policy_compiles() {
        // The default pack must always parse and compile (regression guard).
        let toml = include_str!("../../../policies/default/personal-assistant.toml");
        let p = CompiledPolicy::from_toml_str(toml).expect("default policy must compile");
        assert_eq!(p.policy().role, "personal-assistant");
    }

    #[test]
    fn tools_classification_map_parses() {
        let policy = r#"
version = 1
role = "t"
[defaults]
decision = "ask"
[tools]
read_file = "FileRead"
danger = "Exec"
"#;
        let p = CompiledPolicy::from_toml_str(policy).unwrap();
        assert_eq!(
            p.policy().tools.get("read_file"),
            Some(&ActionKind::FileRead)
        );
        assert_eq!(p.policy().tools.get("danger"), Some(&ActionKind::Exec));
        assert_eq!(p.policy().tools.get("missing"), None);
    }

    #[test]
    fn shipped_coding_agent_policy_behaves() {
        // The coding-agent pack must compile and uphold its key decisions.
        let toml = include_str!("../../../policies/default/coding-agent.toml");
        let p = CompiledPolicy::from_toml_str(toml).expect("coding-agent policy must compile");
        assert_eq!(p.policy().role, "coding-agent");

        // Reads are silent; a benign shell command asks.
        let read = action(ActionKind::FileRead, "Read", json!({}), None);
        assert_eq!(p.evaluate(&read, &env()).decision, Decision::Allow);
        let benign = action(
            ActionKind::Exec,
            "Bash",
            json!({ "cmd": "git status" }),
            None,
        );
        assert!(matches!(
            p.evaluate(&benign, &env()).decision,
            Decision::Ask { .. }
        ));

        // A catastrophic shell command is denied, and flagged critical.
        let nuke = action(ActionKind::Exec, "Bash", json!({ "cmd": "rm -rf /" }), None);
        let out = p.evaluate(&nuke, &env());
        assert!(matches!(out.decision, Decision::Deny { .. }));
        assert!(out.critical);
    }

    #[test]
    fn count_cap_escalates_and_fails_safe() {
        let policy = r#"
version = 1
role = "t"
[defaults]
decision = "ask"
[[rules]]
id = "bulk"
when = 'action.kind == "Delete"'
decision = "allow"
cap = { count_max = 10 }
"#;
        let p = CompiledPolicy::from_toml_str(policy).unwrap();
        // Under the cap → allow.
        let under = action(ActionKind::Delete, "fs.delete", json!({ "count": 3 }), None);
        assert_eq!(p.evaluate(&under, &env()).decision, Decision::Allow);
        // Over the cap → escalated to ask.
        let over = action(
            ActionKind::Delete,
            "fs.delete",
            json!({ "count": 99 }),
            None,
        );
        assert!(matches!(
            p.evaluate(&over, &env()).decision,
            Decision::Ask { .. }
        ));
        // Missing count → cap cannot be verified → fail safe to ask.
        let missing = action(ActionKind::Delete, "fs.delete", json!({}), None);
        assert!(matches!(
            p.evaluate(&missing, &env()).decision,
            Decision::Ask { .. }
        ));
    }

    #[test]
    fn unknown_field_is_rejected() {
        // A typo in a cap key must be rejected, not silently dropped.
        let policy = r#"
version = 1
role = "t"
[defaults]
decision = "ask"
[[rules]]
id = "typo"
when = 'true'
decision = "allow"
cap = { amount_mx = 200.0 }
"#;
        assert!(CompiledPolicy::from_toml_str(policy).is_err());
    }
}
