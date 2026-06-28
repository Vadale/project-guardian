//! The deterministic evaluator — the security boundary.
//!
//! A [`CompiledPolicy`] compiles each rule's CEL `when` expression once, then
//! maps an [`Action`] to a [`Decision`] via *most-restrictive-wins*. This is a
//! pure function: no LLM, no I/O, no clock (ADR-0003). Identical inputs always
//! produce an identical [`EvalOutcome`].

use cel_interpreter::{Context, Program, Value};
use guardian_core::{Action, Decision};

use crate::schema::{Cap, DecisionKind, Policy, PolicyError, Rule};

/// Environment values exposed to policy expressions beyond the action itself.
#[derive(Debug, Clone, Default)]
pub struct EvalEnv {
    /// Bound as `user.home`.
    pub user_home: String,
    /// Bound as `trusted_hosts`.
    pub trusted_hosts: Vec<String>,
}

/// The result of evaluating an action against a policy.
#[derive(Debug, Clone, PartialEq)]
pub struct EvalOutcome {
    pub decision: Decision,
    /// Id of the rule that produced the winning decision, if any matched.
    pub matched_rule: Option<String>,
    /// True if any matched rule requested sandboxed execution.
    pub sandbox: bool,
    /// True if any matched rule is in a critical category.
    pub critical: bool,
}

/// A policy whose CEL conditions have been compiled, ready for repeated, cheap
/// evaluation.
pub struct CompiledPolicy {
    policy: Policy,
    /// Parallel to `policy.rules`.
    programs: Vec<Program>,
    /// The CEL standard-function registry, built **once** at compile time. Each
    /// `evaluate` derives a cheap child scope from it (adding only the per-action
    /// variables) instead of re-registering every standard function per call.
    base: Context<'static>,
}

impl CompiledPolicy {
    /// Compile an already-parsed [`Policy`].
    pub fn compile(policy: Policy) -> Result<Self, PolicyError> {
        let programs = policy
            .rules
            .iter()
            .map(|r| {
                Program::compile(&r.when).map_err(|e| PolicyError::InvalidWhen {
                    id: r.id.clone(),
                    msg: e.to_string(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            policy,
            programs,
            base: Context::default(),
        })
    }

    /// Parse, validate, and compile a policy from TOML in one step.
    pub fn from_toml_str(s: &str) -> Result<Self, PolicyError> {
        Self::compile(Policy::from_toml_str(s)?)
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Evaluate `action` against the policy. Pure and deterministic.
    pub fn evaluate(&self, action: &Action, env: &EvalEnv) -> EvalOutcome {
        let ctx = build_context(&self.base, action, env);

        // Start from the (always restrictive) default; rules override on match.
        let mut outcome = EvalOutcome {
            decision: decision_from_kind(self.policy.defaults.decision, None),
            matched_rule: None,
            sandbox: false,
            critical: false,
        };
        let mut matched_any = false;

        for (rule, program) in self.policy.rules.iter().zip(&self.programs) {
            if !rule_matches(program, &ctx) {
                continue;
            }
            outcome.sandbox |= rule.sandbox;
            outcome.critical |= rule.critical;

            let rule_decision = apply_cap(
                rule,
                action,
                decision_from_kind(rule.decision, rule.explain.clone()),
            );

            if !matched_any {
                matched_any = true;
                outcome.decision = rule_decision;
                outcome.matched_rule = Some(rule.id.clone());
            } else {
                // Most-restrictive-wins: only the winner updates `matched_rule`.
                let combined = outcome.decision.clone().most_restrictive(rule_decision);
                if combined != outcome.decision {
                    outcome.decision = combined;
                    outcome.matched_rule = Some(rule.id.clone());
                }
            }
        }

        outcome
    }
}

/// Build the CEL evaluation context from the action and environment, as a cheap
/// **child scope** of `base` (which already holds the standard-function registry).
/// The action is exposed as its JSON form under `action`.
fn build_context<'a>(base: &'a Context<'a>, action: &Action, env: &EvalEnv) -> Context<'a> {
    let mut ctx = base.new_inner_scope();
    let action_json = serde_json::to_value(action).unwrap_or(serde_json::Value::Null);
    // `add_variable` only fails if the value is not serializable; ours always is.
    let _ = ctx.add_variable("action", action_json);
    let _ = ctx.add_variable("user", serde_json::json!({ "home": env.user_home }));
    let _ = ctx.add_variable("trusted_hosts", env.trusted_hosts.clone());
    let _ = ctx.add_variable("now", action.context.timestamp_ms);
    ctx
}

/// A rule matches iff its condition evaluates to boolean `true`. Anything else —
/// `false`, a non-boolean result, or an error such as referencing a field absent
/// from this action — counts as **no match**. This fails safe: with the
/// mandatory restrictive default, an unmatched action is reviewed, never allowed.
fn rule_matches(program: &Program, ctx: &Context) -> bool {
    matches!(program.execute(ctx), Ok(Value::Bool(true)))
}

fn decision_from_kind(kind: DecisionKind, explain: Option<String>) -> Decision {
    match kind {
        DecisionKind::Allow => Decision::Allow,
        DecisionKind::Ask => Decision::Ask {
            reason: explain.unwrap_or_else(|| "This action needs your review.".to_string()),
        },
        DecisionKind::Deny => Decision::Deny {
            reason: explain.unwrap_or_else(|| "This action is blocked by policy.".to_string()),
        },
    }
}

/// If the rule carries a `cap` and the action violates it, escalate the rule's
/// decision to at least `Ask`.
fn apply_cap(rule: &Rule, action: &Action, decision: Decision) -> Decision {
    match &rule.cap {
        Some(cap) if cap_violated(cap, action) => decision.most_restrictive(Decision::Ask {
            reason: format!("Exceeds the limit configured for `{}`.", rule.id),
        }),
        _ => decision,
    }
}

/// Returns `true` if the action violates the cap **or** the cap cannot be
/// verified (a configured limit whose argument is missing or non-numeric). The
/// unverifiable case is treated as a violation so it fails safe: it escalates to
/// `Ask` rather than silently allowing an over-limit action.
fn cap_violated(cap: &Cap, action: &Action) -> bool {
    if let Some(max) = cap.amount_max {
        match arg_number(action, "amount") {
            Some(amount) => {
                if amount > max {
                    return true;
                }
            }
            None => return true,
        }
    }
    if let Some(max) = cap.count_max {
        match arg_number(action, "count") {
            Some(count) => {
                if count > max as f64 {
                    return true;
                }
            }
            None => return true,
        }
    }
    false
}

/// Read a numeric argument as `f64`, accepting both JSON numbers and numeric
/// strings (an adapter may pass `"50"`). Returns `None` if absent or non-numeric.
fn arg_number(action: &Action, key: &str) -> Option<f64> {
    let v = action.args.get(key)?;
    v.as_f64()
        .or_else(|| v.as_str().and_then(|s| s.parse::<f64>().ok()))
}
