//! `guardian-checker` — the advisory translator/risk-scorer.
//!
//! A [`Checker`] turns a structured [`guardian_core::Action`] into a plain-language
//! [`Explanation`] and an advisory risk score for human review.
//!
//! **Advisory only (ADR-0003).** A `Checker` can never produce or influence a
//! `Decision` — this crate does not even depend on the `Decision` type. The trait
//! is also infallible from the caller's perspective: a backend that fails (e.g. a
//! model is unreachable) returns a safe, low-confidence fallback rather than
//! erroring, so the Checker never blocks or unblocks an action.

#![forbid(unsafe_code)]

use guardian_core::{Action, ActionKind, Capability};
use serde::{Deserialize, Serialize};

/// A plain-language explanation of an action plus an advisory risk score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Explanation {
    /// Human-readable description of the action's real impact.
    pub plain_text: String,
    /// Advisory risk score in `0..=100`. **Not** used for enforcement.
    pub risk: u8,
    /// Short rationale for the score (shown in the report / log).
    pub rationale: String,
}

/// Translates and risk-scores pending actions for human review.
///
/// Implementations must be advisory only: the return type is [`Explanation`],
/// never a decision. Backends should be infallible to the caller — degrade to a
/// conservative fallback instead of returning an error.
#[async_trait::async_trait]
pub trait Checker: Send + Sync {
    async fn explain(&self, action: &Action) -> Explanation;
}

/// A deterministic, offline checker: no model, no network. Useful as a privacy
/// default and as a stable backend for tests. Real model-backed checkers
/// (local/remote) are pluggable behind the same trait and land later.
pub struct StubChecker;

#[async_trait::async_trait]
impl Checker for StubChecker {
    async fn explain(&self, action: &Action) -> Explanation {
        Explanation {
            plain_text: describe(action),
            risk: base_risk(action),
            rationale: "Heuristic offline checker (no model).".to_string(),
        }
    }
}

/// Plain-language description of what the action does.
fn describe(action: &Action) -> String {
    let what = match action.kind {
        ActionKind::FileRead => "read files on your computer",
        ActionKind::FileWrite => "create or modify files on your computer",
        ActionKind::Exec => "run a command on your computer",
        ActionKind::HttpRequest => "make a network request",
        ActionKind::Email => "send an email on your behalf",
        ActionKind::Payment => "move money",
        ActionKind::Delete => "delete data",
        ActionKind::Other => "perform an action",
    };
    format!("The agent wants to {what} (via `{}`).", action.tool)
}

/// A coarse, deterministic risk heuristic. Critical-category actions always
/// score high; this is advisory only and never gates a decision.
fn base_risk(action: &Action) -> u8 {
    let mut risk = match action.kind {
        ActionKind::FileRead => 10,
        ActionKind::FileWrite => 30,
        ActionKind::HttpRequest => 40,
        ActionKind::Email => 45,
        ActionKind::Other => 50,
        ActionKind::Delete => 65,
        ActionKind::Exec => 70,
        ActionKind::Payment => 90,
    };
    if action
        .capability
        .map(Capability::is_critical)
        .unwrap_or(false)
    {
        risk = risk.max(90);
    }
    risk
}

#[cfg(test)]
mod tests {
    use super::*;
    use guardian_core::{ActionContext, ActionId};

    fn action(kind: ActionKind, capability: Option<Capability>) -> Action {
        Action {
            id: ActionId::new("01TEST"),
            kind,
            tool: "demo.tool".to_string(),
            args: serde_json::json!({}),
            capability,
            context: ActionContext {
                timestamp_ms: 1,
                source: "test".to_string(),
                session: None,
                host: None,
                principal: None,
                path: None,
                extra: serde_json::Map::new(),
            },
        }
    }

    #[tokio::test]
    async fn explanation_is_deterministic() {
        let c = StubChecker;
        let a = action(ActionKind::FileRead, None);
        let e1 = c.explain(&a).await;
        let e2 = c.explain(&a).await;
        assert_eq!(e1, e2);
        assert!(e1.plain_text.contains("read files"));
        assert!(e1.risk <= 100);
    }

    #[tokio::test]
    async fn critical_actions_score_higher_than_reads() {
        let c = StubChecker;
        let read = c.explain(&action(ActionKind::FileRead, None)).await;
        let payment = c
            .explain(&action(ActionKind::Payment, Some(Capability::Payment)))
            .await;
        assert!(payment.risk > read.risk);
        assert_eq!(payment.risk, 90);
    }

    #[tokio::test]
    async fn usable_as_a_trait_object() {
        // The daemon will hold a `Box<dyn Checker>`; confirm object safety.
        let c: Box<dyn Checker> = Box::new(StubChecker);
        let e = c.explain(&action(ActionKind::Exec, None)).await;
        assert!(e.plain_text.contains("run a command"));
    }
}
