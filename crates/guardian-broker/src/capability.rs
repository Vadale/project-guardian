//! Least-privilege capabilities with **caveats** (Phase 3, §8.1).
//!
//! A capability attenuates how a brokered credential may be used: it expires, is
//! bound to specific hosts, caps an amount, and forces a **fresh human approval for
//! critical actions** (never a cached grant). The broker checks the caveats at the
//! boundary *before* the credential is used, so a held secret can't be replayed
//! outside its scope.
//!
//! ## Why not the `macaroon` crate?
//! ROADMAP §8.1 named macaroons. The `macaroon` crate (0.3) depends on
//! **`sodiumoxide`**, which is **unmaintained** (RUSTSEC-flagged) and needs the
//! libsodium C library at build — both at odds with this project's clean
//! supply-chain posture (the `cargo deny` gate) and cross-platform CI. Crucially,
//! macaroons' headline property is a *bearer token the holder can attenuate but not
//! widen* — but in Guardian the **agent never holds the credential** (the broker
//! injects it post-allow), so that property buys little here. What matters is the
//! **caveat model**, which we implement directly and dependency-free. If
//! cryptographic *delegation* is needed later, capabilities can be HMAC-backed with
//! the `blake3`/`ed25519-dalek` we already use — without an unmaintained C binding.

use serde::Deserialize;

/// The facts about a pending use of a capability, checked against its caveats.
#[derive(Debug, Clone)]
pub struct CapabilityRequest<'a> {
    /// Destination host for this use.
    pub host: &'a str,
    /// Current time (epoch ms), for expiry.
    pub now_ms: i64,
    /// Amount involved, if any (e.g. a payment).
    pub amount: Option<f64>,
    /// Whether the action is in a critical category.
    pub critical: bool,
    /// Whether a human approved *this* action just now (not a cached approval).
    pub freshly_approved: bool,
}

/// The attenuations on a capability. All are optional; an empty `Caveats` permits
/// any use (subject to the policy, which still decides allow/deny independently).
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct Caveats {
    /// Reject use at or after this time (epoch ms).
    pub not_after_ms: Option<i64>,
    /// Allowed destination hosts (normalized, lowercase). Empty = any host.
    pub allowed_hosts: Vec<String>,
    /// Maximum amount this capability may authorize. Enforced where the action
    /// carries an `amount` (the MCP/tool path); on the network proxy, an amount
    /// isn't parsed from arbitrary HTTP, so `max_amount` is **not** enforced there
    /// (the policy's `cap`/host rules and the read-only allowlist are the proxy
    /// control). Tracked: parse an amount or fail closed on the proxy when set.
    pub max_amount: Option<f64>,
    /// If true (the default), a **critical** action requires a *fresh* approval —
    /// a cached/automatic grant is never enough.
    pub require_fresh_approval_for_critical: bool,
}

impl Caveats {
    /// A `Caveats` that requires fresh approval for critical actions (the safe
    /// default) and imposes no other limit.
    pub fn permissive() -> Self {
        Self {
            require_fresh_approval_for_critical: true,
            ..Self::default()
        }
    }
}

/// Why a capability use was refused.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum CaveatViolation {
    #[error("capability expired")]
    Expired,
    #[error("host '{0}' is not in the capability's allowed hosts")]
    HostNotAllowed(String),
    #[error("amount {got} exceeds the capability's max {max}")]
    AmountExceeded { max: f64, got: f64 },
    #[error("a critical action requires a fresh approval (cached grant is not enough)")]
    StaleCriticalApproval,
}

impl Caveats {
    /// Check a pending use against these caveats. `Ok(())` means the caveats permit
    /// it (the deterministic policy still decides allow/deny separately).
    pub fn check(&self, req: &CapabilityRequest) -> Result<(), CaveatViolation> {
        if let Some(deadline) = self.not_after_ms {
            if req.now_ms >= deadline {
                return Err(CaveatViolation::Expired);
            }
        }
        if !self.allowed_hosts.is_empty()
            && !self
                .allowed_hosts
                .iter()
                .any(|h| h.eq_ignore_ascii_case(req.host))
        {
            return Err(CaveatViolation::HostNotAllowed(req.host.to_string()));
        }
        if let (Some(max), Some(got)) = (self.max_amount, req.amount) {
            if got > max {
                return Err(CaveatViolation::AmountExceeded { max, got });
            }
        }
        if self.require_fresh_approval_for_critical && req.critical && !req.freshly_approved {
            return Err(CaveatViolation::StaleCriticalApproval);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> CapabilityRequest<'static> {
        CapabilityRequest {
            host: "bank.example",
            now_ms: 1_000,
            amount: None,
            critical: false,
            freshly_approved: false,
        }
    }

    #[test]
    fn permissive_caveats_allow_a_plain_request() {
        assert!(Caveats::permissive().check(&req()).is_ok());
    }

    #[test]
    fn expiry_is_enforced() {
        let c = Caveats {
            not_after_ms: Some(1_000),
            ..Caveats::permissive()
        };
        // now_ms == deadline → expired.
        assert_eq!(c.check(&req()), Err(CaveatViolation::Expired));
        let before = CapabilityRequest {
            now_ms: 999,
            ..req()
        };
        assert!(c.check(&before).is_ok());
    }

    #[test]
    fn host_binding_is_enforced() {
        let c = Caveats {
            allowed_hosts: vec!["bank.example".into()],
            ..Caveats::permissive()
        };
        assert!(c.check(&req()).is_ok());
        let other = CapabilityRequest {
            host: "evil.example",
            ..req()
        };
        assert!(matches!(
            c.check(&other),
            Err(CaveatViolation::HostNotAllowed(_))
        ));
    }

    #[test]
    fn max_amount_is_enforced() {
        let c = Caveats {
            max_amount: Some(100.0),
            ..Caveats::permissive()
        };
        let ok = CapabilityRequest {
            amount: Some(100.0),
            ..req()
        };
        assert!(c.check(&ok).is_ok());
        let over = CapabilityRequest {
            amount: Some(100.01),
            ..req()
        };
        assert!(matches!(
            c.check(&over),
            Err(CaveatViolation::AmountExceeded { .. })
        ));
    }

    #[test]
    fn critical_action_needs_a_fresh_approval() {
        let c = Caveats::permissive();
        let cached_critical = CapabilityRequest {
            critical: true,
            freshly_approved: false,
            ..req()
        };
        assert_eq!(
            c.check(&cached_critical),
            Err(CaveatViolation::StaleCriticalApproval)
        );
        let fresh_critical = CapabilityRequest {
            critical: true,
            freshly_approved: true,
            ..req()
        };
        assert!(c.check(&fresh_critical).is_ok());
    }
}
