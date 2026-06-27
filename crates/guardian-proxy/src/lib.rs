//! `guardian-proxy` — the network policy layer for an agent's web traffic.
//!
//! This module is the **transport-agnostic mediation core** (ROADMAP §7.1): it
//! normalizes an HTTP request into a [`guardian_core::Action`], asks the
//! deterministic policy whether to forward or block, and — for an allowed request
//! to a brokered host — supplies the `Authorization` value from the token broker
//! so the agent never holds the credential.
//!
//! The **live forward proxy** that plugs this core onto real sockets lives in
//! [`server`] (hudsucker + rustls TLS interception); the **local CA** it uses to
//! intercept HTTPS lives in [`ca`]. See `docs/adr/0004-network-proxy.md`.
//!
//! Known gap (tracked for a later increment): once an allowed `CONNECT` tunnel is
//! upgraded to a **WebSocket**, individual frames are not inspected — only the
//! upgrade handshake's host/method/path is policed. An allowed WS host is thus an
//! unmediated bidirectional channel until body/frame inspection lands.

#![forbid(unsafe_code)]

use guardian_broker::Broker;
use guardian_core::{Action, ActionContext, ActionId, ActionKind, Decision};
use guardian_policy::{CompiledPolicy, EvalEnv, EvalOutcome};

pub mod ca;
pub mod server;

/// The parts of an outbound HTTP request the policy needs to see.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub host: String,
    pub path: String,
}

/// What the proxy should do with a request.
#[derive(Clone, PartialEq)]
pub enum ProxyOutcome {
    /// Forward upstream. `authorization`, if present, is the broker credential the
    /// proxy must set as the `Authorization` header (the agent never sent it).
    Forward { authorization: Option<String> },
    /// Block the request; the reason is surfaced to the agent and the audit log.
    Block { reason: String },
}

// Redact the credential: `{:?}` must never leak the brokered token into a log.
impl std::fmt::Debug for ProxyOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyOutcome::Forward { authorization } => f
                .debug_struct("Forward")
                .field(
                    "authorization",
                    &authorization.as_ref().map(|_| "<redacted>"),
                )
                .finish(),
            ProxyOutcome::Block { reason } => {
                f.debug_struct("Block").field("reason", reason).finish()
            }
        }
    }
}

/// Normalize a request host for consistent policy + broker lookups: lowercase and
/// strip a default port, so `Bank.local:443` and `bank.local` are one key.
fn normalize_host(host: &str) -> String {
    let h = host.trim().to_ascii_lowercase();
    for port in [":80", ":443"] {
        if let Some(stripped) = h.strip_suffix(port) {
            return stripped.to_string();
        }
    }
    h
}

/// Normalize an HTTP request into the canonical [`Action`] the policy evaluates.
/// `method` lands in `args` and `host` in the context (the shapes the HTTP policy
/// rules reference, e.g. `action.args.method` and `action.context.host`).
pub fn to_action(req: &HttpRequest) -> Action {
    Action {
        id: ActionId::new("proxy"),
        kind: ActionKind::HttpRequest,
        tool: format!("http.{}", req.method.to_lowercase()),
        args: serde_json::json!({ "method": req.method, "path": req.path }),
        capability: None,
        context: ActionContext {
            timestamp_ms: 0,
            source: "proxy".to_string(),
            session: None,
            host: Some(normalize_host(&req.host)),
            principal: None,
            path: None,
            extra: serde_json::Map::new(),
        },
    }
}

/// Decide what to do with a request: evaluate it against the policy, and for an
/// allowed request to a brokered host attach the broker's `Authorization`.
/// `ask` fails closed here (no human attached to this layer); the live proxy will
/// route `ask` to the cockpit in a later increment.
pub fn mediate(
    req: &HttpRequest,
    policy: &CompiledPolicy,
    env: &EvalEnv,
    broker: &Broker,
) -> ProxyOutcome {
    let action = to_action(req);
    let outcome = policy.evaluate(&action, env);
    classify(&action, &outcome, broker)
}

/// Map a policy [`EvalOutcome`] to a [`ProxyOutcome`], attaching the broker
/// credential for an allowed request to a brokered host. Split out from
/// [`mediate`] so the live proxy can **record the full outcome** (matched rule,
/// critical flag) to the audit log before acting on it. The broker key is the
/// **already-normalized** `action.context.host`, so it can never diverge from the
/// host the policy matched on. `ask` fails closed (no human at this layer).
pub fn classify(action: &Action, outcome: &EvalOutcome, broker: &Broker) -> ProxyOutcome {
    match &outcome.decision {
        Decision::Allow => ProxyOutcome::Forward {
            authorization: action
                .context
                .host
                .as_deref()
                .and_then(|h| broker.token_for(h))
                .map(|t| format!("Bearer {t}")),
        },
        Decision::Deny { reason } => ProxyOutcome::Block {
            reason: reason.clone(),
        },
        Decision::Ask { reason } => ProxyOutcome::Block {
            reason: format!("needs approval: {reason}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const POLICY: &str = r#"
version = 1
role = "web-bank"
[defaults]
decision = "ask"
[[rules]]
id = "allow-get"
when = 'action.kind == "HttpRequest" && action.args.method == "GET"'
decision = "allow"
[[rules]]
id = "deny-post-to-bank"
when = 'action.kind == "HttpRequest" && action.args.method == "POST" && action.context.host == "bank.local"'
decision = "deny"
explain = "Money movement on the bank is blocked."
"#;

    fn policy() -> CompiledPolicy {
        CompiledPolicy::from_toml_str(POLICY).unwrap()
    }
    fn env() -> EvalEnv {
        EvalEnv {
            user_home: "/h".to_string(),
            trusted_hosts: vec![],
        }
    }
    fn broker() -> Broker {
        Broker::new(HashMap::from([(
            "bank.local".to_string(),
            "tok".to_string(),
        )]))
    }
    fn req(method: &str, host: &str, path: &str) -> HttpRequest {
        HttpRequest {
            method: method.to_string(),
            host: host.to_string(),
            path: path.to_string(),
        }
    }

    #[test]
    fn get_is_forwarded_with_brokered_authorization() {
        let out = mediate(
            &req("GET", "bank.local", "/balance"),
            &policy(),
            &env(),
            &broker(),
        );
        assert_eq!(
            out,
            ProxyOutcome::Forward {
                authorization: Some("Bearer tok".to_string())
            }
        );
    }

    #[test]
    fn post_transfer_to_bank_is_blocked() {
        let out = mediate(
            &req("POST", "bank.local", "/transfer"),
            &policy(),
            &env(),
            &broker(),
        );
        assert!(matches!(out, ProxyOutcome::Block { .. }));
    }

    #[test]
    fn forward_to_unbrokered_host_has_no_authorization() {
        let out = mediate(
            &req("GET", "other.host", "/x"),
            &policy(),
            &env(),
            &broker(),
        );
        assert_eq!(
            out,
            ProxyOutcome::Forward {
                authorization: None
            }
        );
    }

    #[test]
    fn host_is_normalized_for_policy_and_broker() {
        // Mixed case + default port must still match the bank rule and the broker
        // key, so policy and credential lookup never silently diverge.
        let deny = mediate(
            &req("POST", "BANK.local:443", "/transfer"),
            &policy(),
            &env(),
            &broker(),
        );
        assert!(matches!(deny, ProxyOutcome::Block { .. }));
        let fwd = mediate(
            &req("GET", "Bank.local:80", "/balance"),
            &policy(),
            &env(),
            &broker(),
        );
        assert_eq!(
            fwd,
            ProxyOutcome::Forward {
                authorization: Some("Bearer tok".to_string())
            }
        );
    }

    #[test]
    fn debug_redacts_the_brokered_token() {
        let out = ProxyOutcome::Forward {
            authorization: Some("Bearer tok".to_string()),
        };
        let dbg = format!("{out:?}");
        assert!(
            !dbg.contains("tok"),
            "token must not appear in Debug: {dbg}"
        );
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn unmatched_request_fails_closed_to_block() {
        // PUT matches no rule → default `ask` → blocked at this layer (no human).
        let out = mediate(
            &req("PUT", "other.host", "/x"),
            &policy(),
            &env(),
            &broker(),
        );
        assert!(matches!(out, ProxyOutcome::Block { .. }));
    }
}
