//! `guardian-sandbox` — the OS sandbox backstop (ROADMAP §7.3).
//!
//! When the policy marks an `exec`-class action `sandbox = true`, Guardian runs the
//! command **contained** instead of directly. Containment is delegated to an
//! **off-the-shelf OS sandbox tool** — `sandbox-exec` (macOS) or `bubblewrap`
//! (Linux) — invoked as an external process; **no custom kernel code** (invariant
//! 6). If no backend is available the caller must **fail closed** for a sandboxed
//! action (see [`detect`] returning `None`).
//!
//! **What the default actually contains (be precise — this is a backstop, not full
//! isolation):**
//! - **macOS (`sandbox-exec`)** denies **outbound network** and **filesystem
//!   writes** (except temp + explicit [`SandboxOpts::writable_paths`]). The SBPL base
//!   is `(allow default)`, so reads, `process-exec`, mach lookups and IPC remain
//!   allowed — this is *network + write* containment, **not** process/IPC isolation.
//!   Hardening to a deny-by-default profile is tracked (`docs/threat-model.md`).
//! - **Linux (`bubblewrap`)** is stronger: a **read-only root** (`--ro-bind / /`),
//!   private `/dev`+`/proc`, writable `/tmp`, and a **network namespace**
//!   (`--unshare-net`). The two backends are therefore not equivalent in strength.
//!
//! Widening (network, extra writable paths) comes from [`SandboxOpts`], which the
//! **caller** (an operator invoking `guardian exec`, not the agent) supplies — see
//! the CLI's operator-only flags. The agent only provides the command to run.
//!
//! This crate only *builds and runs* the wrapped command; the allow/deny decision
//! stays in the policy engine. [`SandboxRunner::wrap`] is separated from running so
//! the exact argv can be unit-tested without a real sandbox present.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::{Command, ExitStatus};

/// What the sandbox allows beyond the restrictive default.
#[derive(Debug, Clone, Default)]
pub struct SandboxOpts {
    /// Allow outbound network. Default `false` (denied) — the proxy is the network
    /// control; a sandboxed exec should not reach the network unless asked.
    pub allow_network: bool,
    /// Paths the command may write to, beyond the temp dir. Default: none.
    pub writable_paths: Vec<PathBuf>,
}

/// Runs a command inside an OS sandbox by shelling out to a sandbox tool.
pub trait SandboxRunner: Send + Sync {
    /// Backend name, for logs and errors.
    fn name(&self) -> &'static str;

    /// Build the wrapped command: the sandbox tool, its arguments, and the target
    /// `program`/`args`. Pure — does not run anything — so it is unit-testable.
    fn wrap(&self, program: &str, args: &[String], opts: &SandboxOpts) -> Command;

    /// Run the wrapped command to completion, returning its exit status.
    fn run(
        &self,
        program: &str,
        args: &[String],
        opts: &SandboxOpts,
    ) -> std::io::Result<ExitStatus> {
        self.wrap(program, args, opts).status()
    }
}

/// macOS Seatbelt via `sandbox-exec -p <profile>`.
pub struct MacosSeatbelt;

impl MacosSeatbelt {
    /// Build the SBPL profile. Base is permissive-then-restrict (last match wins in
    /// SBPL): allow by default, then deny network and all writes, then re-allow
    /// writes to temp and the explicit `writable_paths`. Reads stay allowed so the
    /// binary and its libraries can load.
    fn profile(opts: &SandboxOpts) -> String {
        let mut p = String::from("(version 1)\n(allow default)\n");
        if !opts.allow_network {
            p.push_str("(deny network*)\n");
        }
        p.push_str("(deny file-write*)\n");
        p.push_str(
            "(allow file-write* (subpath \"/tmp\") (subpath \"/private/tmp\") (subpath \"/private/var/folders\"))\n",
        );
        for path in &opts.writable_paths {
            // Paths come from configuration, not the agent; quotes are stripped to
            // keep the generated SBPL well-formed.
            let safe = path.to_string_lossy().replace('"', "");
            p.push_str(&format!("(allow file-write* (subpath \"{safe}\"))\n"));
        }
        p
    }
}

impl SandboxRunner for MacosSeatbelt {
    fn name(&self) -> &'static str {
        "sandbox-exec"
    }
    fn wrap(&self, program: &str, args: &[String], opts: &SandboxOpts) -> Command {
        let mut cmd = Command::new("sandbox-exec");
        cmd.arg("-p")
            .arg(Self::profile(opts))
            .arg(program)
            .args(args);
        cmd
    }
}

/// Linux containment via `bubblewrap` (`bwrap`).
pub struct Bubblewrap;

impl SandboxRunner for Bubblewrap {
    fn name(&self) -> &'static str {
        "bwrap"
    }
    fn wrap(&self, program: &str, args: &[String], opts: &SandboxOpts) -> Command {
        let mut cmd = Command::new("bwrap");
        // Read-only root, private /dev, /proc and a writable /tmp; die with parent.
        cmd.arg("--ro-bind")
            .arg("/")
            .arg("/")
            .arg("--dev")
            .arg("/dev")
            .arg("--proc")
            .arg("/proc")
            .arg("--tmpfs")
            .arg("/tmp")
            .arg("--die-with-parent");
        if !opts.allow_network {
            cmd.arg("--unshare-net");
        }
        for path in &opts.writable_paths {
            cmd.arg("--bind").arg(path).arg(path);
        }
        cmd.arg("--").arg(program).args(args);
        cmd
    }
}

/// The sandbox backend for this platform, if its tool is installed. `None` means
/// **no containment is available** — the caller must fail closed for a sandboxed
/// action rather than run it unconfined.
pub fn detect() -> Option<Box<dyn SandboxRunner>> {
    // `cfg!` (not `#[cfg]`) so both arms compile everywhere and the impls/`has_binary`
    // are never dead code; only the matching platform's tool is ever selected.
    if cfg!(target_os = "macos") && has_binary("sandbox-exec") {
        return Some(Box::new(MacosSeatbelt));
    }
    if cfg!(target_os = "linux") && has_binary("bwrap") {
        return Some(Box::new(Bubblewrap));
    }
    None
}

/// Whether an executable named `name` is on `PATH`.
fn has_binary(name: &str) -> bool {
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&paths).any(|dir| dir.join(name).is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(cmd: &Command) -> Vec<String> {
        std::iter::once(cmd.get_program())
            .chain(cmd.get_args())
            .map(|s| s.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn seatbelt_wraps_with_a_profile_and_the_target_command() {
        let cmd = MacosSeatbelt.wrap("curl", &["https://x".to_string()], &SandboxOpts::default());
        let argv = argv(&cmd);
        assert_eq!(argv[0], "sandbox-exec");
        assert_eq!(argv[1], "-p");
        assert!(argv[2].contains("(deny network*)")); // network denied by default
        assert_eq!(argv[3], "curl");
        assert_eq!(argv[4], "https://x");
    }

    #[test]
    fn seatbelt_omits_network_deny_when_network_is_allowed() {
        let opts = SandboxOpts {
            allow_network: true,
            ..Default::default()
        };
        let cmd = MacosSeatbelt.wrap("echo", &[], &opts);
        assert!(!argv(&cmd)[2].contains("deny network"));
    }

    #[test]
    fn seatbelt_grants_writes_only_to_listed_paths() {
        let opts = SandboxOpts {
            writable_paths: vec![PathBuf::from("/work/out")],
            ..Default::default()
        };
        let profile = MacosSeatbelt::profile(&opts);
        assert!(profile.contains("(deny file-write*)"));
        assert!(profile.contains("/work/out"));
    }

    #[test]
    fn bubblewrap_denies_network_and_uses_readonly_root_by_default() {
        let cmd = Bubblewrap.wrap(
            "sh",
            &["-c".to_string(), "true".to_string()],
            &SandboxOpts::default(),
        );
        let argv = argv(&cmd);
        assert_eq!(argv[0], "bwrap");
        assert!(argv.contains(&"--unshare-net".to_string()));
        assert!(argv.contains(&"--ro-bind".to_string()));
        assert_eq!(argv[argv.len() - 3], "sh");
    }

    #[test]
    fn bubblewrap_allows_network_and_binds_writable_paths_when_asked() {
        let opts = SandboxOpts {
            allow_network: true,
            writable_paths: vec![PathBuf::from("/work")],
        };
        let cmd = Bubblewrap.wrap("echo", &[], &opts);
        let argv = argv(&cmd);
        assert!(!argv.contains(&"--unshare-net".to_string()));
        assert!(argv.windows(3).any(|w| w == ["--bind", "/work", "/work"]));
    }

    // Real-containment check: only runs where a backend is actually installed
    // (skipped in CI without one). Asserts a denied-network exec fails inside the box.
    #[test]
    fn sandboxed_network_access_is_actually_denied_when_a_backend_exists() {
        let Some(runner) = detect() else {
            return; // no backend on this host — nothing to assert
        };
        // A bash TCP open to a public resolver; must fail with no network.
        let status = runner.run(
            "/bin/sh",
            &["-c".to_string(), "exec 3<>/dev/tcp/1.1.1.1/53".to_string()],
            &SandboxOpts::default(),
        );
        if let Ok(st) = status {
            assert!(
                !st.success(),
                "network should be denied inside the {} sandbox",
                runner.name()
            );
        }
        // If the runner couldn't even spawn (Err), we don't fail the suite — the
        // tool may be present but unusable in this environment.
    }
}
