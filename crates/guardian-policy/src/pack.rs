//! Signed community policy packs (ROADMAP §8.4).
//!
//! A **pack** is a directory of policy `.toml` files plus a manifest
//! ([`MANIFEST_FILE`]) that lists each file with its **blake3** hash and is
//! **signed with ed25519** by the publisher. The loader **refuses an unsigned or
//! altered pack**, and refuses one that **widens a critical category** (a rule that
//! `allow`s a `critical = true` action) unless the user explicitly opts in at
//! install. This is the supply-chain control for shared policy: you can verify *who*
//! authored a pack and that it hasn't been tampered with, and a pack can never
//! silently grant money-movement / credential / exfiltration / deletion.

use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::schema::{DecisionKind, Policy};

/// The signed manifest filename inside a pack directory.
pub const MANIFEST_FILE: &str = "guardian-pack.json";

/// One policy file and its content hash.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileEntry {
    pub name: String,
    /// blake3 hash of the file contents, hex-encoded.
    pub blake3: String,
}

/// The signed-over content: what the pack contains. Serialized **deterministically**
/// (fixed struct field order, `files` sorted by name) so the signature is stable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Manifest {
    pub name: String,
    pub version: String,
    pub files: Vec<FileEntry>,
}

/// A pack manifest plus its ed25519 publisher key and signature (both hex).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPack {
    pub manifest: Manifest,
    /// ed25519 public key of the publisher, hex (64 chars).
    pub publisher: String,
    /// ed25519 signature over the canonical manifest bytes, hex.
    pub signature: String,
}

#[derive(Debug, thiserror::Error)]
pub enum PackError {
    #[error("pack I/O error: {0}")]
    Io(String),
    #[error("pack is not signed (no {0})")]
    NotSigned(&'static str),
    #[error("malformed pack manifest: {0}")]
    Malformed(String),
    #[error("bad publisher key or signature encoding")]
    BadEncoding,
    #[error("signature does not verify against the publisher key")]
    SignatureInvalid,
    #[error("pack publisher is not the trusted key")]
    UntrustedPublisher,
    #[error("file '{0}' does not match the signed hash (tampered)")]
    FileAltered(String),
    #[error("pack files do not match the manifest (added/removed: {0})")]
    FileSetMismatch(String),
    #[error("pack widens critical categories without opt-in: rules {0}")]
    CriticalWidening(String),
    #[error("invalid policy in pack: {0}")]
    Policy(String),
}

/// blake3 hex of a byte slice.
fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// The policy `.toml` files in `dir`, sorted by file name (manifest order).
fn policy_files(dir: &Path) -> Result<Vec<PathBuf>, PackError> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| PackError::Io(e.to_string()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .collect();
    files.sort();
    Ok(files)
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Build the manifest for `dir` (hash every policy file, sorted by name).
pub fn build_manifest(dir: &Path, name: &str, version: &str) -> Result<Manifest, PackError> {
    let mut files = Vec::new();
    for path in policy_files(dir)? {
        let bytes = std::fs::read(&path).map_err(|e| PackError::Io(e.to_string()))?;
        files.push(FileEntry {
            name: file_name(&path),
            blake3: blake3_hex(&bytes),
        });
    }
    Ok(Manifest {
        name: name.to_string(),
        version: version.to_string(),
        files,
    })
}

/// Canonical bytes of a manifest for signing/verifying. Deterministic: the struct
/// field order is fixed and `files` is already sorted by name.
fn canonical(manifest: &Manifest) -> Vec<u8> {
    serde_json::to_vec(manifest).expect("manifest is always serializable")
}

/// Sign the policy files in `dir` with `signing_key`, returning the signed pack.
pub fn sign(
    dir: &Path,
    name: &str,
    version: &str,
    signing_key: &SigningKey,
) -> Result<SignedPack, PackError> {
    let manifest = build_manifest(dir, name, version)?;
    let signature: Signature = signing_key.sign(&canonical(&manifest));
    Ok(SignedPack {
        manifest,
        publisher: hex::encode(signing_key.verifying_key().to_bytes()),
        signature: hex::encode(signature.to_bytes()),
    })
}

/// Read the signed manifest from a pack directory.
pub fn load_signed(dir: &Path) -> Result<SignedPack, PackError> {
    let path = dir.join(MANIFEST_FILE);
    if !path.exists() {
        return Err(PackError::NotSigned(MANIFEST_FILE));
    }
    let text = std::fs::read_to_string(&path).map_err(|e| PackError::Io(e.to_string()))?;
    serde_json::from_str(&text).map_err(|e| PackError::Malformed(e.to_string()))
}

fn parse_verifying_key(hex_key: &str) -> Result<VerifyingKey, PackError> {
    let bytes: [u8; 32] = hex::decode(hex_key)
        .map_err(|_| PackError::BadEncoding)?
        .try_into()
        .map_err(|_| PackError::BadEncoding)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| PackError::BadEncoding)
}

fn parse_signature(hex_sig: &str) -> Result<Signature, PackError> {
    let bytes: [u8; 64] = hex::decode(hex_sig)
        .map_err(|_| PackError::BadEncoding)?
        .try_into()
        .map_err(|_| PackError::BadEncoding)?;
    Ok(Signature::from_bytes(&bytes))
}

/// Verify a pack: the signature is valid for the publisher key, the publisher is the
/// trusted key (when one is required), the file set matches the manifest, and every
/// file's content still hashes to the signed value. Does **not** compile the
/// policies (see [`critical_widening_rules`] / [`load_pack`]).
pub fn verify(dir: &Path, signed: &SignedPack, trusted: Option<&str>) -> Result<(), PackError> {
    let key = parse_verifying_key(&signed.publisher)?;
    let sig = parse_signature(&signed.signature)?;
    key.verify(&canonical(&signed.manifest), &sig)
        .map_err(|_| PackError::SignatureInvalid)?;

    if let Some(trusted) = trusted {
        if !signed.publisher.eq_ignore_ascii_case(trusted) {
            return Err(PackError::UntrustedPublisher);
        }
    }

    // The set of `.toml` files on disk must equal the manifest's set — neither an
    // extra (unsigned) file nor a missing one.
    let on_disk: std::collections::BTreeSet<String> =
        policy_files(dir)?.iter().map(|p| file_name(p)).collect();
    let in_manifest: std::collections::BTreeSet<String> = signed
        .manifest
        .files
        .iter()
        .map(|f| f.name.clone())
        .collect();
    if on_disk != in_manifest {
        let diff: Vec<String> = on_disk
            .symmetric_difference(&in_manifest)
            .cloned()
            .collect();
        return Err(PackError::FileSetMismatch(diff.join(", ")));
    }

    for entry in &signed.manifest.files {
        let bytes =
            std::fs::read(dir.join(&entry.name)).map_err(|e| PackError::Io(e.to_string()))?;
        if blake3_hex(&bytes) != entry.blake3 {
            return Err(PackError::FileAltered(entry.name.clone()));
        }
    }
    Ok(())
}

/// Rule ids in the pack that **widen a critical category** — a rule marked
/// `critical = true` whose decision is `allow`. These are exactly the grants a pack
/// must not make silently (money / credential / exfiltration / deletion).
pub fn critical_widening_rules(dir: &Path) -> Result<Vec<String>, PackError> {
    let mut widening = Vec::new();
    for path in policy_files(dir)? {
        let text = std::fs::read_to_string(&path).map_err(|e| PackError::Io(e.to_string()))?;
        let policy = Policy::from_toml_str(&text).map_err(|e| PackError::Policy(e.to_string()))?;
        for rule in &policy.rules {
            if rule.critical && rule.decision == DecisionKind::Allow {
                widening.push(format!("{}::{}", policy.role, rule.id));
            }
        }
    }
    Ok(widening)
}

/// Fully load a pack for use: verify the signature/hashes, then refuse it if it
/// widens a critical category unless `allow_critical` is set. Returns the parsed
/// policies on success.
pub fn load_pack(
    dir: &Path,
    trusted: Option<&str>,
    allow_critical: bool,
) -> Result<Vec<Policy>, PackError> {
    let signed = load_signed(dir)?;
    verify(dir, &signed, trusted)?;

    let widening = critical_widening_rules(dir)?;
    if !widening.is_empty() && !allow_critical {
        return Err(PackError::CriticalWidening(widening.join(", ")));
    }

    let mut policies = Vec::new();
    for entry in &signed.manifest.files {
        let text = std::fs::read_to_string(dir.join(&entry.name))
            .map_err(|e| PackError::Io(e.to_string()))?;
        policies.push(Policy::from_toml_str(&text).map_err(|e| PackError::Policy(e.to_string()))?);
    }
    Ok(policies)
}

/// Generate a fresh ed25519 signing key from the OS RNG (for publishing packs).
pub fn generate_signing_key() -> Result<SigningKey, PackError> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| PackError::Io(e.to_string()))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// A fresh 32-byte signing seed, hex-encoded — the publisher's secret key material.
/// Hex so callers (the CLI) need not depend on the ed25519 types directly.
pub fn generate_seed_hex() -> Result<String, PackError> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| PackError::Io(e.to_string()))?;
    Ok(hex::encode(seed))
}

/// Sign a pack with a hex-encoded 32-byte seed (the publisher's secret key).
pub fn sign_with_seed_hex(
    dir: &Path,
    name: &str,
    version: &str,
    seed_hex: &str,
) -> Result<SignedPack, PackError> {
    let seed: [u8; 32] = hex::decode(seed_hex.trim())
        .map_err(|_| PackError::BadEncoding)?
        .try_into()
        .map_err(|_| PackError::BadEncoding)?;
    sign(dir, name, version, &SigningKey::from_bytes(&seed))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_pack(dir: &Path, files: &[(&str, &str)]) {
        std::fs::create_dir_all(dir).unwrap();
        for (name, body) in files {
            std::fs::write(dir.join(name), body).unwrap();
        }
    }

    const SAFE: &str = r#"
version = 1
role = "safe"
[defaults]
decision = "ask"
[[rules]]
id = "allow-get"
when = 'action.args.method == "GET"'
decision = "allow"
"#;

    // A rule that ALLOWS a critical-category action — the dangerous widening.
    const WIDENING: &str = r#"
version = 1
role = "danger"
[defaults]
decision = "ask"
[[rules]]
id = "allow-transfer"
when = 'action.args.method == "POST"'
decision = "allow"
critical = true
"#;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "guardian-pack-{}-{}-{tag}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn sign_into(dir: &Path, files: &[(&str, &str)]) -> SignedPack {
        write_pack(dir, files);
        let key = generate_signing_key().unwrap();
        let signed = sign(dir, "test-pack", "1.0", &key).unwrap();
        std::fs::write(
            dir.join(MANIFEST_FILE),
            serde_json::to_string_pretty(&signed).unwrap(),
        )
        .unwrap();
        signed
    }

    #[test]
    fn a_correctly_signed_pack_verifies() {
        let dir = tmp("ok");
        let signed = sign_into(&dir, &[("a.toml", SAFE)]);
        assert!(verify(&dir, &signed, None).is_ok());
        // And with the matching trusted publisher.
        assert!(verify(&dir, &signed, Some(&signed.publisher)).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_tampered_file_is_rejected() {
        let dir = tmp("tamper");
        let signed = sign_into(&dir, &[("a.toml", SAFE)]);
        // Alter the file after signing.
        std::fs::write(dir.join("a.toml"), format!("{SAFE}\n# sneaky")).unwrap();
        assert!(matches!(
            verify(&dir, &signed, None),
            Err(PackError::FileAltered(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_added_unsigned_file_is_rejected() {
        let dir = tmp("added");
        let signed = sign_into(&dir, &[("a.toml", SAFE)]);
        std::fs::write(dir.join("evil.toml"), SAFE).unwrap();
        assert!(matches!(
            verify(&dir, &signed, None),
            Err(PackError::FileSetMismatch(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_wrong_trusted_publisher_is_rejected() {
        let dir = tmp("untrusted");
        let signed = sign_into(&dir, &[("a.toml", SAFE)]);
        let other = hex::encode([7u8; 32]);
        assert!(matches!(
            verify(&dir, &signed, Some(&other)),
            Err(PackError::UntrustedPublisher)
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_critical_widening_pack_is_blocked_without_opt_in() {
        let dir = tmp("widen");
        sign_into(&dir, &[("danger.toml", WIDENING)]);
        // Verified signature is fine, but loading without opt-in is refused.
        assert!(matches!(
            load_pack(&dir, None, false),
            Err(PackError::CriticalWidening(_))
        ));
        // With explicit opt-in it loads.
        assert!(load_pack(&dir, None, true).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unsigned_directory_is_not_a_pack() {
        let dir = tmp("unsigned");
        write_pack(&dir, &[("a.toml", SAFE)]);
        assert!(matches!(load_signed(&dir), Err(PackError::NotSigned(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
