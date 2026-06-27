//! `guardian-broker` — identity & token broker.
//!
//! Holds credentials so the **agent never sees raw secrets**: Guardian injects the
//! token into an outbound tool-call (or, later, an HTTP request at the proxy) only
//! after the action is allowed, so the agent's prompt/output never carries it.
//!
//! This is the **minimal V1** (ROADMAP §8.1 seed): secrets are a `target -> token`
//! map loaded from a file/config. The full Phase 3 broker adds OS-keychain storage
//! and macaroon/OAuth caveats (expiry, max amount, allowed hosts, source binding);
//! that is where the reviewed keychain FFI will live. V1 has no FFI, so:

#![forbid(unsafe_code)]

use std::collections::HashMap;

/// The conventional args field Guardian injects the credential into when none is
/// requested explicitly.
pub const DEFAULT_FIELD: &str = "auth_token";

/// Holds credentials and injects them into outbound requests. Cheap to clone.
#[derive(Clone, Default)]
pub struct Broker {
    secrets: HashMap<String, String>,
}

// Redact token values: a stray `{:?}` (a log line, a panic) must never leak them.
impl std::fmt::Debug for Broker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Broker")
            .field("targets", &self.secrets.keys().collect::<Vec<_>>())
            .field("tokens", &"<redacted>")
            .finish()
    }
}

impl Broker {
    /// Build from an explicit `target -> token` map.
    pub fn new(secrets: HashMap<String, String>) -> Self {
        Self { secrets }
    }

    /// Load from a TOML file of `target = "token"` entries (the V1 secret store).
    pub fn from_toml_str(s: &str) -> Result<Self, toml::de::Error> {
        let secrets: HashMap<String, String> = toml::from_str(s)?;
        Ok(Self { secrets })
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
    fn inject_refuses_non_object_args() {
        let b = broker();
        let mut args = json!([1, 2, 3]);
        assert!(!b.inject("bank", &mut args)); // can't inject into an array
    }
}
