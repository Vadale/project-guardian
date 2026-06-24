//! Project Guardian desktop UI backend (Tauri v2).
//!
//! Thin bridge between the webview and the running `guardian-daemon`: the two
//! commands `pending` and `respond` proxy to the daemon's control socket via
//! [`guardian_daemon::DaemonClient`]. No policy logic lives here — the UI only
//! renders pending approvals and relays the user's allow/deny (CLAUDE.md: "no
//! business logic in the UI").

use std::path::PathBuf;

use guardian_daemon::{DaemonClient, PendingView};

/// Connect to the daemon socket (`GUARDIAN_SOCK` or a temp-dir default).
fn client() -> DaemonClient {
    let path = std::env::var("GUARDIAN_SOCK")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("guardian.sock"));
    DaemonClient::new(path)
}

/// List the actions currently awaiting human review.
#[tauri::command]
async fn pending() -> Result<Vec<PendingView>, String> {
    client().pending().await.map_err(|e| e.to_string())
}

/// Resolve a pending action: approve (allow) or deny.
#[tauri::command]
async fn respond(id: u64, approve: bool) -> Result<bool, String> {
    client().respond(id, approve).await.map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![pending, respond])
        .run(tauri::generate_context!())
        .expect("error while running the Guardian UI");
}
