//! Policy schema: the declarative contract loaded from TOML (see
//! `docs/policy-schema.md`). This module only parses and structurally validates;
//! CEL compilation lives in [`crate::CompiledPolicy`].

use serde::Deserialize;
use std::collections::HashSet;
use thiserror::Error;

/// A policy decision as written in a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DecisionKind {
    Allow,
    Ask,
    Deny,
}

/// Quantitative limits attached to a rule (e.g. a payment cap). A violated cap
/// escalates the rule's decision to at least `Ask` (see `docs/policy-schema.md`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cap {
    #[serde(default)]
    pub amount_max: Option<f64>,
    #[serde(default)]
    pub currency: Option<String>,
    #[serde(default)]
    pub count_max: Option<i64>,
}

/// A single policy rule.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    /// A side-effect-free CEL boolean expression over the action/context.
    pub when: String,
    pub decision: DecisionKind,
    #[serde(default)]
    pub explain: Option<String>,
    /// Critical-category rules can never be auto-downgraded by learning.
    #[serde(default)]
    pub critical: bool,
    /// If true, the action runs inside an OS sandbox regardless of the decision.
    #[serde(default)]
    pub sandbox: bool,
    #[serde(default)]
    pub cap: Option<Cap>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    pub decision: DecisionKind,
}

/// A parsed policy: one named role and its rules.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    pub role: String,
    pub defaults: Defaults,
    /// Optional informational metadata (author, description, pack id/version).
    #[serde(default)]
    pub meta: Option<toml::Value>,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("failed to parse policy TOML: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("unsupported policy version {0} (this build supports v1)")]
    UnsupportedVersion(u32),
    #[error("defaults.decision must be `ask` or `deny`, never `allow`")]
    PermissiveDefault,
    #[error("duplicate rule id: {0}")]
    DuplicateRuleId(String),
    #[error("rule `{id}` has an invalid `when` expression: {msg}")]
    InvalidWhen { id: String, msg: String },
}

impl Policy {
    /// Parse and structurally validate a policy from TOML. Does not compile the
    /// CEL `when` expressions — use [`crate::CompiledPolicy`] for that.
    pub fn from_toml_str(s: &str) -> Result<Self, PolicyError> {
        let policy: Policy = toml::from_str(s)?;
        policy.validate_structure()?;
        Ok(policy)
    }

    fn validate_structure(&self) -> Result<(), PolicyError> {
        if self.version != 1 {
            return Err(PolicyError::UnsupportedVersion(self.version));
        }
        // The default must never be permissive (fail safe).
        if self.defaults.decision == DecisionKind::Allow {
            return Err(PolicyError::PermissiveDefault);
        }
        let mut seen: HashSet<&str> = HashSet::new();
        for rule in &self.rules {
            if !seen.insert(rule.id.as_str()) {
                return Err(PolicyError::DuplicateRuleId(rule.id.clone()));
            }
        }
        Ok(())
    }
}
