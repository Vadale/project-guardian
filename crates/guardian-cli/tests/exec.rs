//! Integration tests for `guardian exec` fail-closed behavior: a command the
//! policy does not allow must NOT run, and the exit code signals refusal. Runs the
//! built `guardian` binary; no sandbox backend is needed (the command is refused
//! before any execution), so this is CI-safe on any platform with `/bin/sh`.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn unique_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "guardian-exec-test-{}-{}-{tag}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// A policy with a restrictive default and no matching rule → `ask` → refused.
const DENY_POLICY: &str = r#"
version = 1
role = "test"
[defaults]
decision = "ask"
"#;

#[test]
fn exec_refuses_and_does_not_run_a_command_the_policy_blocks() {
    let dir = unique_dir("deny");
    let policy = dir.join("policy.toml");
    let audit = dir.join("audit.db");
    let sentinel = dir.join("SHOULD_NOT_EXIST");
    fs::write(&policy, DENY_POLICY).unwrap();

    let status = Command::new(env!("CARGO_BIN_EXE_guardian"))
        .arg("exec")
        .arg("--policy")
        .arg(&policy)
        .arg("--audit")
        .arg(&audit)
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg(format!("touch {}", sentinel.display()))
        .status()
        .expect("failed to spawn guardian");

    // Refused (not run): exit code 126, and the side effect never happened.
    assert_eq!(status.code(), Some(126), "blocked exec must exit 126");
    assert!(
        !sentinel.exists(),
        "the blocked command must not have executed"
    );

    let _ = fs::remove_dir_all(&dir);
}
