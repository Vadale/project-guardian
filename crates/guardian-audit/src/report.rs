//! The periodic "safety service report" (§8.3) and constrained adaptive
//! suggestions (§8.2), computed from the audit log.
//!
//! Pure analysis over a slice of [`AuditEntry`] (the caller passes a **recent**
//! window — that is the "decaying" part). It summarizes what Guardian did and
//! proposes **suggestions only** — it never edits the policy. A suggestion to relax
//! a rule is offered **only** for a non-critical rule that was consistently
//! approved; a rule that ever touched a **critical category is never suggested for
//! loosening** (invariant 4 — critical categories are never auto-downgraded).

use crate::AuditEntry;
use std::collections::HashMap;

/// How many times a rule must recur (all approved) before we suggest relaxing it.
const MIN_OCCURRENCES_FOR_SUGGESTION: usize = 3;
/// How many top blocked rules/kinds to list.
const TOP_BLOCKED: usize = 5;

/// A label and a count (a blocked rule/kind, or an ask group).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelCount {
    pub label: String,
    pub count: usize,
}

/// A constrained adaptive suggestion — advisory, never applied automatically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suggestion {
    pub label: String,
    pub asked: usize,
    pub text: String,
}

/// The report over a window of audit entries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    pub total: usize,
    pub allows: usize,
    pub asks: usize,
    pub denies: usize,
    /// Most-blocked rules/kinds, highest first (the "threats blocked").
    pub blocked: Vec<LabelCount>,
    /// Rule-relaxation suggestions to confirm (never auto-applied; never critical).
    pub suggestions: Vec<Suggestion>,
}

/// The grouping key for an entry: its matched rule, else its action kind.
fn label_of(entry: &AuditEntry) -> String {
    entry
        .matched_rule
        .clone()
        .unwrap_or_else(|| entry.action_kind.clone())
}

/// Per-ask-group tally used to decide whether a relaxation is suggestible.
#[derive(Default)]
struct AskGroup {
    asked: usize,
    approved: usize,
    /// True if any entry in this group was in a critical category — then the group
    /// is **never** suggested for loosening.
    critical: bool,
}

/// Build the report from a window of entries (newest-first or oldest-first — order
/// doesn't matter; counts and grouping are order-independent).
pub fn build_report(entries: &[AuditEntry]) -> Report {
    let mut report = Report {
        total: entries.len(),
        ..Default::default()
    };

    let mut blocked: HashMap<String, usize> = HashMap::new();
    let mut asks: HashMap<String, AskGroup> = HashMap::new();

    for e in entries {
        match e.decision.as_str() {
            "allow" => report.allows += 1,
            "deny" => {
                report.denies += 1;
                *blocked.entry(label_of(e)).or_default() += 1;
            }
            "ask" => {
                report.asks += 1;
                let g = asks.entry(label_of(e)).or_default();
                g.asked += 1;
                g.critical |= e.critical;
                if e.user_response.as_deref() == Some("approved") {
                    g.approved += 1;
                }
            }
            _ => {} // unknown decision string (e.g. a `<unreadable>` placeholder)
        }
    }

    report.blocked = top_counts(blocked, TOP_BLOCKED);

    // Suggestions: a non-critical rule asked >= N times and approved EVERY time is a
    // candidate to relax — surfaced for the user to confirm, never applied.
    let mut suggestions: Vec<Suggestion> = asks
        .into_iter()
        .filter(|(_, g)| {
            !g.critical && g.asked >= MIN_OCCURRENCES_FOR_SUGGESTION && g.approved == g.asked
        })
        .map(|(label, g)| Suggestion {
            text: format!(
                "'{label}' was asked {n} times and you approved every one — consider an allow rule. (Review first; Guardian never applies this automatically.)",
                n = g.asked
            ),
            label,
            asked: g.asked,
        })
        .collect();
    // Stable, useful ordering: most-asked first, then label.
    suggestions.sort_by(|a, b| b.asked.cmp(&a.asked).then(a.label.cmp(&b.label)));
    report.suggestions = suggestions;

    report
}

/// Sort a count map descending by count (then label) and take the top `n`.
fn top_counts(map: HashMap<String, usize>, n: usize) -> Vec<LabelCount> {
    let mut v: Vec<LabelCount> = map
        .into_iter()
        .map(|(label, count)| LabelCount { label, count })
        .collect();
    v.sort_by(|a, b| b.count.cmp(&a.count).then(a.label.cmp(&b.label)));
    v.truncate(n);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ask(label: &str, response: Option<&str>, critical: bool) -> AuditEntry {
        AuditEntry {
            timestamp_ms: 0,
            action_id: "a".into(),
            action_kind: "HttpRequest".into(),
            decision: "ask".into(),
            decision_reason: None,
            matched_rule: Some(label.into()),
            checker_rationale: None,
            user_response: response.map(|s| s.into()),
            critical,
            host: None,
        }
    }
    fn deny(label: &str) -> AuditEntry {
        AuditEntry {
            timestamp_ms: 0,
            action_id: "a".into(),
            action_kind: "Exec".into(),
            decision: "deny".into(),
            decision_reason: None,
            matched_rule: Some(label.into()),
            checker_rationale: None,
            user_response: None,
            critical: false,
            host: None,
        }
    }

    #[test]
    fn counts_and_blocked_ranking() {
        let entries = vec![
            deny("rm"),
            deny("rm"),
            deny("curl"),
            ask("x", Some("approved"), false),
        ];
        let r = build_report(&entries);
        assert_eq!((r.total, r.denies, r.asks), (4, 3, 1));
        assert_eq!(
            r.blocked[0],
            LabelCount {
                label: "rm".into(),
                count: 2
            }
        );
    }

    #[test]
    fn consistently_approved_noncritical_rule_is_suggested() {
        let entries = vec![
            ask("read-docs", Some("approved"), false),
            ask("read-docs", Some("approved"), false),
            ask("read-docs", Some("approved"), false),
        ];
        let r = build_report(&entries);
        assert_eq!(r.suggestions.len(), 1);
        assert_eq!(r.suggestions[0].label, "read-docs");
    }

    #[test]
    fn a_critical_rule_is_never_suggested_even_if_always_approved() {
        let entries = vec![
            ask("wire-transfer", Some("approved"), true),
            ask("wire-transfer", Some("approved"), true),
            ask("wire-transfer", Some("approved"), true),
            ask("wire-transfer", Some("approved"), true),
        ];
        let r = build_report(&entries);
        assert!(
            r.suggestions.is_empty(),
            "critical rules must never be suggested for loosening"
        );
    }

    #[test]
    fn a_sometimes_denied_rule_is_not_suggested() {
        let entries = vec![
            ask("maybe", Some("approved"), false),
            ask("maybe", Some("denied"), false),
            ask("maybe", Some("approved"), false),
        ];
        let r = build_report(&entries);
        assert!(
            r.suggestions.is_empty(),
            "a rule the user sometimes denies must not be suggested"
        );
    }

    #[test]
    fn below_threshold_is_not_suggested() {
        let entries = vec![ask("rare", Some("approved"), false)];
        assert!(build_report(&entries).suggestions.is_empty());
    }
}
