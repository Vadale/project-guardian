//! `guardian-core` — the canonical action model and decision types shared across
//! Project Guardian.
//!
//! This crate is the foundation every adapter normalizes into, and the only data
//! the policy engine and the Checker ever evaluate. Per the project invariants
//! (see `CLAUDE.md`, ADR-0002 / ADR-0003) it:
//!   * performs **no I/O** and has **no internal dependencies**, and
//!   * contains **no `unsafe`** code.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Opaque identifier for an intercepted [`Action`].
///
/// Generation (e.g. a ULID) happens at the adapter layer so this crate stays
/// pure and side-effect free.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ActionId(pub String);

impl ActionId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The kind of action an agent is attempting.
///
/// The serialized variant names (e.g. `"FileRead"`) are part of the **policy
/// wire contract**: policy `when` expressions compare against them, so renaming
/// a variant is a breaking change (guarded by the `serialized_names_are_stable`
/// test).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionKind {
    FileRead,
    FileWrite,
    Exec,
    HttpRequest,
    Email,
    Payment,
    Delete,
    Other,
}

/// The semantic capability class of an action.
///
/// Capabilities are coarser than [`ActionKind`] and drive the *critical
/// category* rules: critical capabilities can never be auto-downgraded by the
/// adaptive-learning layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Capability {
    Payment,
    Credential,
    Exfiltration,
    IrreversibleDelete,
    Messaging,
    Filesystem,
    Network,
    Other,
}

impl Capability {
    /// Returns `true` for the *critical categories* (money movement, credential
    /// access, data exfiltration, irreversible deletion). The adaptive-learning
    /// layer must never auto-downgrade an action in one of these categories.
    pub fn is_critical(self) -> bool {
        matches!(
            self,
            Capability::Payment
                | Capability::Credential
                | Capability::Exfiltration
                | Capability::IrreversibleDelete
        )
    }
}

/// Context surrounding an [`Action`]: when, where, and on whose behalf.
///
/// `timestamp_ms` is Unix milliseconds supplied by the caller; this crate never
/// reads the clock itself (no I/O).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionContext {
    pub timestamp_ms: i64,
    /// Identifier of the adapter that intercepted the action (e.g. "mcp-gateway").
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Adapter-specific extra fields available to policy expressions.
    #[serde(default)]
    pub extra: serde_json::Map<String, Value>,
}

/// A structured, intercepted action.
///
/// This is the **only** representation the policy engine and the Checker
/// evaluate — never the agent's natural-language claims about its intent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Action {
    pub id: ActionId,
    pub kind: ActionKind,
    /// Name of the originating tool.
    pub tool: String,
    /// Typed-where-possible arguments.
    #[serde(default)]
    pub args: Value,
    /// Semantic capability class, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability: Option<Capability>,
    pub context: ActionContext,
}

impl Action {
    /// Convenience: is this action in a critical category?
    pub fn is_critical(&self) -> bool {
        self.capability
            .map(Capability::is_critical)
            .unwrap_or(false)
    }
}

/// The outcome of evaluating an [`Action`] against policy — the output of the
/// deterministic security boundary.
///
/// No LLM is ever involved in producing a `Decision` (ADR-0003).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Decision {
    /// Allowed silently (green).
    Allow,
    /// Paused for human review (yellow); `reason` is shown to the user.
    Ask { reason: String },
    /// Blocked automatically (red); `reason` is shown and logged.
    Deny { reason: String },
}

impl Decision {
    /// Restrictiveness ordering used for *most-restrictive-wins* evaluation:
    /// `Deny` (2) > `Ask` (1) > `Allow` (0).
    pub fn restrictiveness(&self) -> u8 {
        match self {
            Decision::Allow => 0,
            Decision::Ask { .. } => 1,
            Decision::Deny { .. } => 2,
        }
    }

    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow)
    }

    /// Combine two decisions, keeping the more restrictive one. On a tie, `self`
    /// is kept. This is the core of the policy engine's most-restrictive-wins
    /// semantics (see `docs/policy-schema.md` §4).
    pub fn most_restrictive(self, other: Decision) -> Decision {
        if other.restrictiveness() > self.restrictiveness() {
            other
        } else {
            self
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_action() -> Action {
        Action {
            id: ActionId::new("01J0TESTID"),
            kind: ActionKind::Payment,
            tool: "bank.transfer".into(),
            args: serde_json::json!({ "amount": 4000, "iban": "XX00" }),
            capability: Some(Capability::Payment),
            context: ActionContext {
                timestamp_ms: 1_700_000_000_000,
                source: "mcp-gateway".into(),
                session: Some("s1".into()),
                host: None,
                principal: None,
                path: None,
                extra: serde_json::Map::new(),
            },
        }
    }

    #[test]
    fn action_round_trips_through_json() {
        let a = sample_action();
        let json = serde_json::to_string(&a).unwrap();
        let back: Action = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }

    #[test]
    fn critical_categories_are_critical() {
        assert!(Capability::Payment.is_critical());
        assert!(Capability::Credential.is_critical());
        assert!(Capability::Exfiltration.is_critical());
        assert!(Capability::IrreversibleDelete.is_critical());
        assert!(!Capability::Messaging.is_critical());
        assert!(!Capability::Network.is_critical());
        assert!(!Capability::Filesystem.is_critical());
        assert!(sample_action().is_critical());
    }

    #[test]
    fn restrictiveness_orders_deny_over_ask_over_allow() {
        let deny = Decision::Deny { reason: "x".into() };
        let ask = Decision::Ask { reason: "x".into() };
        assert!(deny.restrictiveness() > ask.restrictiveness());
        assert!(ask.restrictiveness() > Decision::Allow.restrictiveness());
    }

    #[test]
    fn most_restrictive_wins() {
        let allow = Decision::Allow;
        let ask = Decision::Ask {
            reason: "review".into(),
        };
        let deny = Decision::Deny {
            reason: "blocked".into(),
        };
        assert_eq!(allow.clone().most_restrictive(deny.clone()), deny);
        assert_eq!(ask.clone().most_restrictive(allow.clone()), ask);
        assert_eq!(deny.clone().most_restrictive(ask.clone()), deny);
        // Tie keeps `self`.
        assert_eq!(allow.clone().most_restrictive(Decision::Allow), allow);
    }

    #[test]
    fn decision_serde_is_tagged() {
        let d = Decision::Deny {
            reason: "no".into(),
        };
        let json = serde_json::to_value(&d).unwrap();
        assert_eq!(json["decision"], "deny");
        assert_eq!(json["reason"], "no");
    }

    #[test]
    fn serialized_names_are_stable() {
        // These strings are the policy wire contract; renaming a variant breaks
        // every policy that references it, so guard them explicitly.
        assert_eq!(
            serde_json::to_value(ActionKind::FileRead).unwrap(),
            "FileRead"
        );
        assert_eq!(
            serde_json::to_value(ActionKind::HttpRequest).unwrap(),
            "HttpRequest"
        );
        assert_eq!(
            serde_json::to_value(Capability::Payment).unwrap(),
            "Payment"
        );
        assert_eq!(
            serde_json::to_value(Capability::IrreversibleDelete).unwrap(),
            "IrreversibleDelete"
        );
    }
}
