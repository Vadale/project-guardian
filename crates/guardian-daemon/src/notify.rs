//! Best-effort desktop notifications when an action needs human approval.
//!
//! This is **pure convenience** — a signal so you don't have to keep the cockpit
//! in view. It is never on the allow/deny path and **fails open** (invariant #5):
//! a missing notifier or any error is ignored; the approval still waits in the
//! queue and the cockpit. We shell out to the platform notifier rather than take a
//! dependency, to keep the auditable surface small and `#![forbid(unsafe_code)]`.

/// Fire a "needs approval" notification for `tool`, summarized by `summary`.
/// Fire-and-forget: spawns the OS notifier without waiting and ignores all errors.
pub fn approval_needed(tool: &str, summary: &str) {
    let title = format!("Guardian — approval needed: {}", clip(tool, 40));
    let body = clip(summary, 180);
    let _ = send(&title, &body);
}

/// Trim to `max` chars on a char boundary, adding an ellipsis when cut.
fn clip(s: &str, max: usize) -> String {
    let s = s.trim();
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

#[cfg(target_os = "macos")]
fn send(title: &str, body: &str) -> std::io::Result<()> {
    // `osascript` is always present on macOS. Escape for an AppleScript string.
    let script = format!(
        "display notification \"{}\" with title \"{}\"",
        applescript_escape(body),
        applescript_escape(title),
    );
    std::process::Command::new("osascript")
        .arg("-e")
        .arg(script)
        .spawn()?;
    Ok(())
}

/// Escape `\` and `"` for embedding in an AppleScript double-quoted string, and
/// strip control characters that could break the one-line script.
#[cfg(target_os = "macos")]
fn applescript_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c if c.is_control() => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn send(title: &str, body: &str) -> std::io::Result<()> {
    // `notify-send` (libnotify) is the de-facto desktop notifier; args are passed
    // literally, so no shell escaping is needed. Absent on headless boxes — fine.
    std::process::Command::new("notify-send")
        .arg("--app-name=Guardian")
        .arg(title)
        .arg(body)
        .spawn()?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn send(title: &str, body: &str) -> std::io::Result<()> {
    // Best-effort toast via PowerShell + WinRT (no extra module). Windows support
    // is experimental; if anything fails the approval still sits in the cockpit.
    let script = format!(
        "[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]|Out-Null;\
         $t=[Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02);\
         $n=$t.GetElementsByTagName('text');$n.Item(0).AppendChild($t.CreateTextNode('{}'))|Out-Null;\
         $n.Item(1).AppendChild($t.CreateTextNode('{}'))|Out-Null;\
         [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('Guardian').Show([Windows.UI.Notifications.ToastNotification]::new($t))",
        powershell_escape(title),
        powershell_escape(body),
    );
    std::process::Command::new("powershell")
        .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &script])
        .spawn()?;
    Ok(())
}

/// Escape single quotes for a PowerShell single-quoted string and drop control chars.
#[cfg(target_os = "windows")]
fn powershell_escape(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .replace('\'', "''")
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn send(_title: &str, _body: &str) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clip_keeps_short_and_truncates_long_on_char_boundary() {
        assert_eq!(clip("hello", 40), "hello");
        let long = "à".repeat(50); // multi-byte chars: must not panic on the boundary
        let out = clip(&long, 10);
        assert_eq!(out.chars().count(), 10);
        assert!(out.ends_with('…'));
    }

    #[test]
    fn approval_needed_never_panics() {
        // Fail-open contract: whatever the platform/notifier state, this returns.
        approval_needed("write_file", "Creates or modifies a file: /etc/hosts");
        approval_needed("", "");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn applescript_escape_neutralizes_quotes_and_backslashes() {
        assert_eq!(applescript_escape(r#"a"b\c"#), r#"a\"b\\c"#);
        assert_eq!(applescript_escape("a\nb"), "a b");
    }
}
