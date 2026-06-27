//! OS keychain storage for broker secrets (Phase 3, §8.1).
//!
//! Secrets live in the platform credential store — Apple Keychain (macOS), Windows
//! Credential Manager, or the Linux kernel keyutils — so they are **never written
//! as plaintext on disk** (unlike the V1 TOML file store) and never shown to the
//! agent. A thin wrapper over the `keyring` crate; the broker reads from here into
//! its in-memory map at startup and injects on the post-allow path as before.

use keyring::Entry;

/// The service name under which Guardian stores secrets in the OS keychain. The
/// `target` (e.g. a host) is the keychain "username".
pub const SERVICE: &str = "guardian";

#[derive(Debug, thiserror::Error)]
pub enum KeychainError {
    #[error("keychain error: {0}")]
    Keyring(#[from] keyring::Error),
}

/// Store `secret` for `target` in the OS keychain, overwriting any existing value.
pub fn store(target: &str, secret: &str) -> Result<(), KeychainError> {
    Entry::new(SERVICE, target)?.set_password(secret)?;
    Ok(())
}

/// The secret for `target`, or `None` if the keychain holds none.
pub fn load(target: &str) -> Result<Option<String>, KeychainError> {
    match Entry::new(SERVICE, target)?.get_password() {
        Ok(secret) => Ok(Some(secret)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Remove the secret for `target` (a no-op if there is none).
pub fn delete(target: &str) -> Result<(), KeychainError> {
    match Entry::new(SERVICE, target)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Once;

    // Route the keychain at the in-memory mock store so tests never touch the real
    // OS keychain (and pass on headless CI). Set once for the test process.
    static MOCK: Once = Once::new();
    fn use_mock() {
        MOCK.call_once(|| {
            keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
        });
    }

    #[test]
    fn load_absent_target_is_none() {
        // The error→Option mapping: a target with no stored secret is `None`, not
        // an error. (keyring's mock keeps state per-Entry, so it can't simulate a
        // cross-call round-trip; that is covered by the `#[ignore]`d test below.)
        use_mock();
        assert_eq!(load("definitely-absent.example").unwrap(), None);
    }

    #[test]
    fn delete_absent_target_is_a_noop() {
        use_mock();
        delete("never-stored.example").unwrap(); // NoEntry is mapped to Ok, not Err
    }

    // Real cross-call round-trip against the **actual** OS keychain. Ignored by
    // default (it writes to your keychain and won't work on headless CI); run with
    // `cargo test -p guardian-broker -- --ignored` on a desktop to verify.
    #[test]
    #[ignore]
    fn store_load_delete_round_trips_on_the_real_keychain() {
        let target = "guardian-selftest.example";
        store(target, "tok-12345").unwrap();
        assert_eq!(load(target).unwrap().as_deref(), Some("tok-12345"));
        delete(target).unwrap();
        assert_eq!(load(target).unwrap(), None);
    }
}
