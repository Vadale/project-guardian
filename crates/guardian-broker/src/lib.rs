//! `guardian-broker` — identity & token broker.
//!
//! Holds credentials so the **agent never sees raw secrets**: Guardian injects the
//! token into an outbound tool-call (or, later, an HTTP request at the proxy) only
//! after the action is allowed, so the agent's prompt/output never carries it.
//!
//! Secrets can be a `target -> token` map (file/config) **or the OS keychain**
//! ([`keychain`], §8.1 — no plaintext on disk). A target may carry least-privilege
//! [`Caveats`] ([`capability`], §8.1): expiry, allowed hosts, a max amount, and a
//! fresh-approval requirement for critical actions, enforced by [`Broker::authorize`]
//! at the boundary. Still remaining for §8.1: scoped OAuth and hardware-backed keys.

#![forbid(unsafe_code)]

pub mod capability;
pub mod credential;
pub mod keychain;
pub mod vault;

pub use capability::{CapabilityRequest, CaveatViolation, Caveats};
pub use vault::DataVault;

use std::collections::HashMap;

/// The conventional args field Guardian injects the credential into when none is
/// requested explicitly.
pub const DEFAULT_FIELD: &str = "auth_token";

/// Holds credentials and injects them into outbound requests. Cheap to clone.
#[derive(Clone, Default)]
pub struct Broker {
    secrets: HashMap<String, String>,
    /// Optional least-privilege caveats per target (§8.1). A target with none is
    /// unconstrained by the broker (the policy still decides allow/deny).
    caveats: HashMap<String, Caveats>,
}

// Redact token values: a stray `{:?}` (a log line, a panic) must never leak them.
impl std::fmt::Debug for Broker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Broker")
            .field("targets", &self.secrets.keys().collect::<Vec<_>>())
            .field("tokens", &"<redacted>")
            .field("caveats", &self.caveats.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl Broker {
    /// Build from an explicit `target -> token` map.
    pub fn new(secrets: HashMap<String, String>) -> Self {
        Self {
            secrets,
            caveats: HashMap::new(),
        }
    }

    /// Load from a TOML file of `target = "token"` entries (the V1 secret store).
    pub fn from_toml_str(s: &str) -> Result<Self, toml::de::Error> {
        let secrets: HashMap<String, String> = toml::from_str(s)?;
        Ok(Self {
            secrets,
            caveats: HashMap::new(),
        })
    }

    /// Attach least-privilege [`Caveats`] for `target` (§8.1). The proxy/gateway
    /// calls [`authorize`](Self::authorize) before using the credential.
    pub fn set_caveats(&mut self, target: &str, caveats: Caveats) {
        self.caveats.insert(target.to_string(), caveats);
    }

    /// Load `target -> Caveats` from a TOML file (a `[target]` table per host).
    pub fn caveats_from_toml_str(&mut self, s: &str) -> Result<(), toml::de::Error> {
        let map: HashMap<String, Caveats> = toml::from_str(s)?;
        self.caveats.extend(map);
        Ok(())
    }

    /// Check a pending use of `target`'s credential against its caveats. `Ok(())`
    /// if the target has no caveats (unconstrained) or the caveats permit it. The
    /// deterministic policy still decides allow/deny independently — this is an
    /// additional least-privilege gate the broker enforces at the boundary.
    pub fn authorize(&self, target: &str, req: &CapabilityRequest) -> Result<(), CaveatViolation> {
        match self.caveats.get(target) {
            Some(caveats) => caveats.check(req),
            None => Ok(()),
        }
    }

    /// Build a broker by loading each target's secret from the **OS keychain**
    /// (Phase 3 store — no plaintext on disk). Targets with no stored secret are
    /// skipped: the proxy/gateway then holds no credential for them, so a request
    /// needing one falls to the policy's default rather than leaking.
    pub fn from_keychain(targets: &[String]) -> Result<Self, keychain::KeychainError> {
        let mut broker = Self::default();
        broker.add_keychain_targets(targets)?;
        Ok(broker)
    }

    /// Overlay keychain-stored secrets for `targets` onto this broker (so a file
    /// store and the keychain can be combined; keychain wins on conflict). Missing
    /// targets are skipped.
    pub fn add_keychain_targets(
        &mut self,
        targets: &[String],
    ) -> Result<(), keychain::KeychainError> {
        for target in targets {
            if let Some(secret) = keychain::load(target)? {
                self.secrets.insert(target.clone(), secret);
            }
        }
        Ok(())
    }

    /// Whether a credential is held for `target`.
    pub fn has(&self, target: &str) -> bool {
        self.secrets.contains_key(target)
    }

    /// The raw token for `target`, if held — e.g. to build an `Authorization`
    /// header at the network proxy. Callers must not log or expose it to the agent.
    pub fn token_for(&self, target: &str) -> Option<&str> {
        self.secrets.get(target).map(String::as_str)
    }

    /// Whether `haystack` contains **any** held secret value — i.e. the agent is
    /// trying to send one of the user's credentials somewhere (exfiltration). Used
    /// by the proxy to inspect outbound request bodies. Keeps the secrets inside
    /// the broker: the caller passes the data and gets back only a boolean. A token
    /// shorter than 8 bytes is ignored to avoid false positives on trivial values.
    pub fn body_leaks_secret(&self, haystack: &str) -> bool {
        self.secrets
            .values()
            .any(|token| token.len() >= 8 && haystack.contains(token.as_str()))
    }

    /// Inject the credential for `target` into `args` under [`DEFAULT_FIELD`], so the
    /// agent never had to supply it. Returns `true` if a token was injected.
    /// `args` is coerced to an object if it is null. Never logs the token.
    ///
    /// This method has no allow/deny guard of its own: the **caller** must inject
    /// only after the action is allowed (the gateway/CLI wiring does so — it runs
    /// on the post-decision forward path). It overwrites any existing field value,
    /// so an agent-supplied token for a brokered target cannot win.
    pub fn inject(&self, target: &str, args: &mut serde_json::Value) -> bool {
        self.inject_as(target, args, DEFAULT_FIELD)
    }

    /// Like [`inject`](Self::inject) but into a caller-chosen field.
    pub fn inject_as(&self, target: &str, args: &mut serde_json::Value, field: &str) -> bool {
        let Some(token) = self.secrets.get(target) else {
            return false;
        };
        if args.is_null() {
            *args = serde_json::Value::Object(serde_json::Map::new());
        }
        match args.as_object_mut() {
            Some(obj) => {
                obj.insert(field.to_string(), serde_json::Value::String(token.clone()));
                true
            }
            None => false, // args is a non-object (array/scalar): cannot inject
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn broker() -> Broker {
        Broker::new(HashMap::from([(
            "bank".to_string(),
            "secret-123".to_string(),
        )]))
    }

    #[test]
    fn from_toml_parses_target_token_pairs() {
        let b = Broker::from_toml_str("bank = \"secret-123\"\nmail = \"t2\"\n").unwrap();
        assert!(b.has("bank"));
        assert!(b.has("mail"));
        assert!(!b.has("unknown"));
    }

    #[test]
    fn inject_adds_token_for_known_target() {
        let b = broker();
        let mut args = json!({ "account": "checking" });
        assert!(b.inject("bank", &mut args));
        assert_eq!(
            args.get("auth_token").and_then(|v| v.as_str()),
            Some("secret-123")
        );
        // the agent-supplied fields are preserved
        assert_eq!(
            args.get("account").and_then(|v| v.as_str()),
            Some("checking")
        );
    }

    #[test]
    fn inject_overwrites_agent_supplied_token() {
        // Adversarial: the agent puts its own token in the args; the broker's value
        // for a known target must win (the field is broker-owned).
        let b = broker();
        let mut args = json!({ "auth_token": "attacker-supplied" });
        assert!(b.inject("bank", &mut args));
        assert_eq!(
            args.get("auth_token").and_then(|v| v.as_str()),
            Some("secret-123")
        );
    }

    #[test]
    fn debug_does_not_leak_token_values() {
        let dbg = format!("{:?}", broker());
        assert!(dbg.contains("bank")); // target name is fine to show
        assert!(!dbg.contains("secret-123")); // the token must not appear
    }

    #[test]
    fn inject_is_noop_for_unknown_target() {
        let b = broker();
        let mut args = json!({});
        assert!(!b.inject("unknown", &mut args));
        assert!(args.get("auth_token").is_none());
    }

    #[test]
    fn inject_coerces_null_args_to_object() {
        let b = broker();
        let mut args = serde_json::Value::Null;
        assert!(b.inject("bank", &mut args));
        assert_eq!(
            args.get("auth_token").and_then(|v| v.as_str()),
            Some("secret-123")
        );
    }

    #[test]
    fn authorize_is_ok_without_caveats_and_enforces_them_when_set() {
        let mut b = broker(); // holds target "bank"
        let req = CapabilityRequest {
            host: "bank",
            now_ms: 5_000,
            amount: None,
            critical: false,
            freshly_approved: false,
        };
        // No caveats for "bank" → unconstrained.
        assert!(b.authorize("bank", &req).is_ok());
        // Add an expiry in the past → now refused.
        b.set_caveats(
            "bank",
            Caveats {
                not_after_ms: Some(1_000),
                ..Caveats::permissive()
            },
        );
        assert_eq!(b.authorize("bank", &req), Err(CaveatViolation::Expired));
    }

    #[test]
    fn caveats_load_from_toml() {
        let mut b = broker();
        b.caveats_from_toml_str("[bank]\nallowed_hosts = [\"bank.example\"]\nmax_amount = 50.0\n")
            .unwrap();
        let ok = CapabilityRequest {
            host: "bank.example",
            now_ms: 0,
            amount: Some(40.0),
            critical: false,
            freshly_approved: false,
        };
        assert!(b.authorize("bank", &ok).is_ok());
        let over = CapabilityRequest {
            amount: Some(60.0),
            ..ok
        };
        assert!(matches!(
            b.authorize("bank", &over),
            Err(CaveatViolation::AmountExceeded { .. })
        ));
    }

    #[test]
    fn from_keychain_skips_targets_without_a_stored_secret() {
        // Mock store (no real keychain): the targets aren't present, so the broker
        // simply holds no credential for them rather than erroring.
        keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
        let b = Broker::from_keychain(&[
            "absent-a.example".to_string(),
            "absent-b.example".to_string(),
        ])
        .unwrap();
        assert!(!b.has("absent-a.example"));
        assert!(!b.has("absent-b.example"));
    }

    #[test]
    fn body_leaks_secret_detects_a_held_token_in_outbound_data() {
        let b = broker(); // holds "secret-123"
        assert!(b.body_leaks_secret("payload=secret-123&x=1"));
        assert!(!b.body_leaks_secret("nothing sensitive here"));
    }

    #[test]
    fn body_leaks_secret_ignores_too_short_tokens() {
        // A trivially short secret must not flag arbitrary bodies (false positives).
        let b = Broker::new(HashMap::from([("t".to_string(), "abc".to_string())]));
        assert!(!b.body_leaks_secret("abc appears but the token is too short"));
    }

    #[test]
    fn inject_refuses_non_object_args() {
        let b = broker();
        let mut args = json!([1, 2, 3]);
        assert!(!b.inject("bank", &mut args)); // can't inject into an array
    }
}
