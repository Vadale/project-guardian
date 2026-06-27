//! Lightweight **verifiable credentials** for principal identity (Phase 3, §8.5).
//!
//! A credential is a set of **claims about a subject, signed by an issuer** with
//! ed25519. Guardian can verify that the principal an agent acts for presents a
//! credential from a **trusted issuer** that hasn't expired — decentralized-identity
//! style (issuer-signed claims), without a central account.
//!
//! ## Scope — why not the `ssi` crate?
//! ROADMAP §8.5 named W3C Verifiable Credentials / DIDs (the `ssi` crate). Full VC +
//! DID-method + JSON-LD interop is a **very large dependency tree** for value
//! Guardian doesn't need yet. This module implements the **substance** — verify an
//! issuer-signed, expiring claim about a subject — with the ed25519 we already use,
//! dependency-light. Full W3C/DID interop (did:key/did:web, JSON-LD) is deferred and
//! can layer on top: this verifier is the trust primitive it would reuse.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Issuer-signed claims about a subject. Serialized **deterministically** (fixed
/// field order; `claims` is a sorted `BTreeMap`) so the signature is stable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Credential {
    /// Who the credential is about (the principal identity).
    pub subject: String,
    /// The issuer's ed25519 public key, hex — the identity that vouches for it.
    pub issuer: String,
    /// Attested claims (e.g. `role = "reader"`). Sorted for a stable signature.
    pub claims: BTreeMap<String, String>,
    /// Expiry (epoch ms); `None` = no expiry.
    pub not_after_ms: Option<i64>,
}

/// A credential plus the issuer's signature over it (hex).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedCredential {
    pub credential: Credential,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum CredentialError {
    #[error("bad issuer key or signature encoding")]
    BadEncoding,
    #[error("signature does not verify against the issuer key")]
    SignatureInvalid,
    #[error("credential issuer is not the trusted issuer")]
    UntrustedIssuer,
    #[error("credential has expired")]
    Expired,
}

/// Canonical bytes of a credential for signing/verifying. Deterministic: fixed
/// struct field order and a sorted `claims` map.
fn canonical(credential: &Credential) -> Vec<u8> {
    serde_json::to_vec(credential).expect("credential is always serializable")
}

/// Issue (sign) a credential. The credential's `issuer` is set to `signing_key`'s
/// public key so it is self-describing.
pub fn issue(mut credential: Credential, signing_key: &SigningKey) -> SignedCredential {
    credential.issuer = hex::encode(signing_key.verifying_key().to_bytes());
    let signature: Signature = signing_key.sign(&canonical(&credential));
    SignedCredential {
        credential,
        signature: hex::encode(signature.to_bytes()),
    }
}

/// Verify a signed credential: the signature is valid for the embedded issuer key,
/// the issuer is the `trusted` one (when required), and it has not expired at
/// `now_ms`. Returns the verified credential's claims on success.
pub fn verify<'a>(
    signed: &'a SignedCredential,
    now_ms: i64,
    trusted_issuer: Option<&str>,
) -> Result<&'a Credential, CredentialError> {
    let key_bytes: [u8; 32] = hex::decode(&signed.credential.issuer)
        .map_err(|_| CredentialError::BadEncoding)?
        .try_into()
        .map_err(|_| CredentialError::BadEncoding)?;
    let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| CredentialError::BadEncoding)?;
    let sig_bytes: [u8; 64] = hex::decode(&signed.signature)
        .map_err(|_| CredentialError::BadEncoding)?
        .try_into()
        .map_err(|_| CredentialError::BadEncoding)?;
    let sig = Signature::from_bytes(&sig_bytes);

    key.verify(&canonical(&signed.credential), &sig)
        .map_err(|_| CredentialError::SignatureInvalid)?;

    if let Some(trusted) = trusted_issuer {
        if !signed.credential.issuer.eq_ignore_ascii_case(trusted) {
            return Err(CredentialError::UntrustedIssuer);
        }
    }
    if let Some(deadline) = signed.credential.not_after_ms {
        if now_ms >= deadline {
            return Err(CredentialError::Expired);
        }
    }
    Ok(&signed.credential)
}

/// Generate a fresh ed25519 issuer key from the OS RNG.
pub fn generate_issuer_key() -> SigningKey {
    let mut seed = [0u8; 32];
    // OS RNG failure here is unrecoverable for key generation.
    getrandom::getrandom(&mut seed).expect("OS RNG unavailable");
    SigningKey::from_bytes(&seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred() -> Credential {
        let mut claims = BTreeMap::new();
        claims.insert("role".to_string(), "reader".to_string());
        Credential {
            subject: "alice".to_string(),
            issuer: String::new(), // filled in by `issue`
            claims,
            not_after_ms: Some(10_000),
        }
    }

    #[test]
    fn a_signed_credential_verifies_and_carries_its_claims() {
        let key = generate_issuer_key();
        let signed = issue(cred(), &key);
        let verified = verify(&signed, 5_000, Some(&signed.credential.issuer)).unwrap();
        assert_eq!(verified.subject, "alice");
        assert_eq!(
            verified.claims.get("role").map(String::as_str),
            Some("reader")
        );
    }

    #[test]
    fn a_tampered_claim_fails_verification() {
        let key = generate_issuer_key();
        let mut signed = issue(cred(), &key);
        signed
            .credential
            .claims
            .insert("role".to_string(), "admin".to_string()); // privilege escalation
        assert_eq!(
            verify(&signed, 5_000, None),
            Err(CredentialError::SignatureInvalid)
        );
    }

    #[test]
    fn an_untrusted_issuer_is_rejected() {
        let key = generate_issuer_key();
        let signed = issue(cred(), &key);
        let other = hex::encode([9u8; 32]);
        assert_eq!(
            verify(&signed, 5_000, Some(&other)),
            Err(CredentialError::UntrustedIssuer)
        );
    }

    #[test]
    fn an_expired_credential_is_rejected() {
        let key = generate_issuer_key();
        let signed = issue(cred(), &key); // not_after_ms = 10_000
        assert_eq!(verify(&signed, 10_000, None), Err(CredentialError::Expired));
        assert!(verify(&signed, 9_999, None).is_ok());
    }
}
