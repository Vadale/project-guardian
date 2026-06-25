//! Daemon configuration (ROADMAP §9b.2).
//!
//! A typed config loaded from `GUARDIAN_CONFIG` (or `~/.guardian/config.toml`).
//! Precedence: built-in default < config file, and for `socket`/`policy`/`audit`
//! a `GUARDIAN_*` env var overlays on top (env > file > default). `trusted_hosts`
//! and `approval_timeout_secs` come from the file/default only (no env override).
//! Everything is optional, so an empty/missing config yields safe defaults. On
//! first run a commented default config is written (owner-only perms) so the user
//! has something to edit. Parsing is strict: an invalid config is an error (the
//! daemon fails closed rather than running with a half-understood config).
//!
//! Security note: `trusted_hosts` is consulted by host-gated **critical** rules
//! (data-exfiltration, credential access), so adding a host exempts it from those
//! denials. The file is written owner-only and its effective value is logged at
//! startup; routing it through the critical-category opt-in is a tracked follow-up.

use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;
use thiserror::Error;

const DEFAULT_TIMEOUT_SECS: u64 = 120;

/// The on-disk config. All fields optional; missing → built-in default.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Control-socket path. Default: a temp-dir `guardian.sock`.
    pub socket: Option<PathBuf>,
    /// Policy file. Default: the built-in pack (when neither file nor env set).
    pub policy: Option<PathBuf>,
    /// Audit-log file. Default: `~/.guardian/audit.db`.
    pub audit: Option<PathBuf>,
    /// Seconds before a pending approval fails closed. Default: 120.
    pub approval_timeout_secs: Option<u64>,
    /// Hosts treated as trusted by the policy. Default: none.
    #[serde(default)]
    pub trusted_hosts: Vec<String>,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("reading config {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("parsing config {path}: {source}")]
    Toml {
        path: String,
        source: toml::de::Error,
    },
}

/// `~/.guardian` (falls back to `./.guardian` if `$HOME` is unset).
pub fn guardian_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".guardian")
}

/// The config file path: `GUARDIAN_CONFIG`, else `~/.guardian/config.toml`.
pub fn config_path() -> PathBuf {
    match std::env::var("GUARDIAN_CONFIG") {
        Ok(p) => PathBuf::from(p),
        Err(_) => guardian_dir().join("config.toml"),
    }
}

/// The kill-switch sentinel file: a `STOP` file next to the config. While it
/// exists, the gateway denies every action (emergency stop).
pub fn kill_switch_path() -> PathBuf {
    config_path()
        .parent()
        .map(|d| d.join("STOP"))
        .unwrap_or_else(|| guardian_dir().join("STOP"))
}

const DEFAULT_CONFIG_TEMPLATE: &str = r#"# Project Guardian — daemon config.
# All fields are optional; the matching GUARDIAN_* env var overrides the file.
# socket = "/tmp/guardian.sock"
# policy = "/absolute/path/to/policy.toml"   # omitted -> built-in default pack
# audit  = "~/.guardian/audit.db"
# approval_timeout_secs = 120
# trusted_hosts = ["api.example.com"]
"#;

impl Config {
    /// Load the config from `config_path()`. On first run (file absent) write a
    /// commented default and return defaults. Fails closed on a malformed file.
    pub fn load() -> Result<Self, ConfigError> {
        let path = config_path();
        if !path.exists() {
            // First run: best-effort materialize a default the user can edit, with
            // owner-only permissions (it governs trusted_hosts and the paths).
            if let Some(dir) = path.parent() {
                let _ = std::fs::create_dir_all(dir);
                restrict_permissions(dir, 0o700);
            }
            match std::fs::write(&path, DEFAULT_CONFIG_TEMPLATE) {
                Ok(()) => {
                    restrict_permissions(&path, 0o600);
                    println!("guardian-daemon: wrote default config {}", path.display());
                }
                Err(e) => eprintln!(
                    "guardian-daemon: could not write default config {} ({e}); using defaults",
                    path.display()
                ),
            }
            return Ok(Self::default());
        }
        Self::from_path(&path)
    }

    /// Parse a config file (no env overlay) — the testable core of [`load`].
    pub fn from_path(path: &std::path::Path) -> Result<Self, ConfigError> {
        let src = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.display().to_string(),
            source,
        })?;
        toml::from_str(&src).map_err(|source| ConfigError::Toml {
            path: path.display().to_string(),
            source,
        })
    }

    /// Resolved socket path: `GUARDIAN_SOCK` > file > temp `guardian.sock`.
    pub fn socket_path(&self) -> PathBuf {
        env_path("GUARDIAN_SOCK")
            .or_else(|| self.socket.clone())
            .unwrap_or_else(|| std::env::temp_dir().join("guardian.sock"))
    }

    /// Resolved policy path: `GUARDIAN_POLICY` > file > `None` (built-in pack).
    pub fn policy_path(&self) -> Option<PathBuf> {
        env_path("GUARDIAN_POLICY").or_else(|| self.policy.clone())
    }

    /// Resolved audit path: `GUARDIAN_AUDIT` > file > `~/.guardian/audit.db`.
    pub fn audit_path(&self) -> PathBuf {
        env_path("GUARDIAN_AUDIT")
            .or_else(|| self.audit.clone())
            .unwrap_or_else(|| guardian_dir().join("audit.db"))
    }

    /// Resolved approval timeout (file > built-in 120s). A configured `0` would
    /// make every `ask` deny instantly (a footgun), so it is treated as unset.
    pub fn approval_timeout(&self) -> Duration {
        let secs = self
            .approval_timeout_secs
            .filter(|&n| n > 0)
            .unwrap_or(DEFAULT_TIMEOUT_SECS);
        Duration::from_secs(secs)
    }
}

/// Read an env var as a non-empty `PathBuf`.
fn env_path(var: &str) -> Option<PathBuf> {
    match std::env::var(var) {
        Ok(v) if !v.is_empty() => Some(PathBuf::from(v)),
        _ => None,
    }
}

/// Best-effort restrict a path to owner-only (Unix); no-op elsewhere.
#[cfg(unix)]
fn restrict_permissions(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}
#[cfg(not(unix))]
fn restrict_permissions(_path: &std::path::Path, _mode: u32) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Process env is global; serialize the env-touching tests.
    static ENV_LOCK: Mutex<()> = Mutex::new(());
    const PATH_VARS: [&str; 4] = [
        "GUARDIAN_SOCK",
        "GUARDIAN_POLICY",
        "GUARDIAN_AUDIT",
        "GUARDIAN_CONFIG",
    ];

    #[test]
    fn empty_config_yields_safe_defaults() {
        let _g = ENV_LOCK.lock().unwrap();
        for v in PATH_VARS {
            std::env::remove_var(v);
        }
        let c = Config::default();
        assert!(c.policy_path().is_none()); // built-in pack
        assert_eq!(c.approval_timeout(), Duration::from_secs(120));
        assert!(c.trusted_hosts.is_empty());
        assert!(c.audit_path().ends_with("audit.db"));
    }

    #[test]
    fn env_overrides_file_and_empty_env_is_ignored() {
        let _g = ENV_LOCK.lock().unwrap();
        for v in PATH_VARS {
            std::env::remove_var(v);
        }
        let c = Config {
            socket: Some(PathBuf::from("/file.sock")),
            ..Default::default()
        };
        // env beats file
        std::env::set_var("GUARDIAN_SOCK", "/env.sock");
        assert_eq!(c.socket_path(), PathBuf::from("/env.sock"));
        // an empty env var is treated as unset → falls back to the file value
        std::env::set_var("GUARDIAN_SOCK", "");
        assert_eq!(c.socket_path(), PathBuf::from("/file.sock"));
        std::env::remove_var("GUARDIAN_SOCK");
    }

    #[test]
    fn first_run_writes_default_config() {
        let _g = ENV_LOCK.lock().unwrap();
        for v in PATH_VARS {
            std::env::remove_var(v);
        }
        let path = std::env::temp_dir().join(format!("gcfg-fr-{}.toml", std::process::id()));
        let _ = std::fs::remove_file(&path);
        std::env::set_var("GUARDIAN_CONFIG", &path);
        let c = Config::load().unwrap();
        assert!(
            path.exists(),
            "first run should materialize a default config"
        );
        assert!(c.trusted_hosts.is_empty()); // safe defaults
        std::env::remove_var("GUARDIAN_CONFIG");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn kill_switch_lives_next_to_the_config() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("GUARDIAN_CONFIG", "/tmp/guardiantest/config.toml");
        assert_eq!(kill_switch_path(), PathBuf::from("/tmp/guardiantest/STOP"));
        std::env::remove_var("GUARDIAN_CONFIG");
    }

    #[test]
    fn zero_timeout_is_treated_as_unset() {
        let c = Config {
            approval_timeout_secs: Some(0),
            ..Default::default()
        };
        assert_eq!(c.approval_timeout(), Duration::from_secs(120));
    }

    #[test]
    fn parses_a_full_config() {
        let toml = r#"
socket = "/tmp/s.sock"
policy = "/p/policy.toml"
audit = "/a/audit.db"
approval_timeout_secs = 30
trusted_hosts = ["api.example.com", "internal"]
"#;
        let dir = std::env::temp_dir().join(format!("gcfg-{}.toml", std::process::id()));
        std::fs::write(&dir, toml).unwrap();
        let c = Config::from_path(&dir).unwrap();
        assert_eq!(c.approval_timeout(), Duration::from_secs(30));
        assert_eq!(c.trusted_hosts, vec!["api.example.com", "internal"]);
        assert_eq!(
            c.policy.as_deref(),
            Some(std::path::Path::new("/p/policy.toml"))
        );
        let _ = std::fs::remove_file(&dir);
    }

    #[test]
    fn malformed_config_is_rejected() {
        let dir = std::env::temp_dir().join(format!("gcfg-bad-{}.toml", std::process::id()));
        std::fs::write(&dir, "socket = 123\nbogus_field = true\n").unwrap();
        assert!(matches!(
            Config::from_path(&dir),
            Err(ConfigError::Toml { .. })
        ));
        let _ = std::fs::remove_file(&dir);
    }
}
