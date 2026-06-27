//! The proxy's local Certificate Authority — generate, persist, and load the CA
//! the proxy uses to terminate TLS (MITM) for an opted-in client.
//!
//! Intercepting HTTPS means presenting certificates the client trusts, which
//! requires a CA the user installs into their trust store. **This is a
//! security-sensitive, opt-in step**: the CA private key can mint a certificate
//! for any site, so it is generated locally, stored with owner-only permissions,
//! and never leaves the machine. Guardian only ever uses it to re-sign traffic it
//! is already mediating on the user's behalf.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use hudsucker::certificate_authority::RcgenAuthority;
use hudsucker::rustls::crypto::aws_lc_rs;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};

/// How many leaf certificates the authority caches in memory.
const CERT_CACHE_SIZE: u64 = 1_000;

/// A locally generated CA, as the PEM pair we persist and reload.
#[derive(Clone)]
pub struct LocalCa {
    /// PEM-encoded CA certificate — this is what the user installs/trusts.
    pub cert_pem: String,
    /// PEM-encoded CA private key — **secret**; persisted owner-only.
    key_pem: String,
}

impl std::fmt::Debug for LocalCa {
    // Never let the private key reach a log via `{:?}`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalCa")
            .field("cert_pem", &"<cert>")
            .field("key_pem", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CaError {
    #[error("certificate generation failed: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("CA file I/O error: {0}")]
    Io(#[from] io::Error),
}

impl LocalCa {
    /// Generate a fresh local CA (self-signed, ECDSA P-256 by default).
    pub fn generate() -> Result<Self, CaError> {
        let key_pair = KeyPair::generate()?;

        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Guardian Local CA");
        dn.push(DnType::OrganizationName, "Project Guardian");
        params.distinguished_name = dn;

        let cert = params.self_signed(&key_pair)?;
        Ok(Self {
            cert_pem: cert.pem(),
            key_pem: key_pair.serialize_pem(),
        })
    }

    /// Load an existing CA from a directory, generating and persisting one on first
    /// use. The cert is world-readable (`ca.crt`, the user installs it); the key
    /// (`ca.key`) is written owner-only.
    pub fn load_or_generate(dir: impl AsRef<Path>) -> Result<Self, CaError> {
        let dir = dir.as_ref();
        let (cert_path, key_path) = Self::paths(dir);
        if cert_path.exists() && key_path.exists() {
            return Ok(Self {
                cert_pem: fs::read_to_string(&cert_path)?,
                key_pem: fs::read_to_string(&key_path)?,
            });
        }
        let ca = Self::generate()?;
        ca.persist(dir)?;
        Ok(ca)
    }

    /// Where the cert/key live under `dir`.
    pub fn paths(dir: &Path) -> (PathBuf, PathBuf) {
        (dir.join("ca.crt"), dir.join("ca.key"))
    }

    /// Write the pair to `dir`, the key with owner-only permissions.
    pub fn persist(&self, dir: impl AsRef<Path>) -> Result<(), CaError> {
        let dir = dir.as_ref();
        fs::create_dir_all(dir)?;
        let (cert_path, key_path) = Self::paths(dir);
        fs::write(&cert_path, &self.cert_pem)?;
        write_private(&key_path, &self.key_pem)?;
        Ok(())
    }

    /// Build the hudsucker authority that mints per-host leaf certs from this CA.
    pub fn authority(&self) -> Result<RcgenAuthority, CaError> {
        let key_pair = KeyPair::from_pem(&self.key_pem)?;
        let issuer = Issuer::from_ca_cert_pem(&self.cert_pem, key_pair)?;
        Ok(RcgenAuthority::new(
            issuer,
            CERT_CACHE_SIZE,
            aws_lc_rs::default_provider(),
        ))
    }
}

/// Write a secret file with owner-only permissions, applied **at creation** on
/// unix so there is no group/world-readable window between `create` and `chmod`.
/// The CA key must never be group/world readable.
#[cfg(unix)]
fn write_private(path: &Path, contents: &str) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(contents.as_bytes())?;
    // If the file pre-existed with looser perms, `.mode()` was ignored at open;
    // tighten it explicitly so the key is never group/world readable.
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn write_private(path: &Path, contents: &str) -> io::Result<()> {
    // On Windows the file inherits the user profile's ACL; tightening it further
    // is left to a later increment (the CA dir lives under the user profile).
    fs::write(path, contents)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_a_ca_cert_and_key() {
        let ca = LocalCa::generate().expect("generate");
        assert!(ca.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(ca.key_pem.contains("PRIVATE KEY"));
        // The generated CA must build a usable hudsucker authority.
        ca.authority().expect("authority from generated CA");
    }

    #[test]
    fn debug_does_not_leak_the_private_key() {
        let ca = LocalCa::generate().expect("generate");
        let dbg = format!("{ca:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("PRIVATE KEY"));
    }

    #[test]
    fn load_or_generate_persists_then_reloads_the_same_ca() {
        let dir = std::env::temp_dir().join(format!("guardian-ca-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let first = LocalCa::load_or_generate(&dir).expect("first");
        let second = LocalCa::load_or_generate(&dir).expect("second");
        // Second call reloads the persisted pair rather than minting a new one.
        assert_eq!(first.cert_pem, second.cert_pem);
        assert_eq!(first.key_pem, second.key_pem);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let (_, key_path) = LocalCa::paths(&dir);
            let mode = fs::metadata(&key_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "CA key must not be group/world readable");
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
