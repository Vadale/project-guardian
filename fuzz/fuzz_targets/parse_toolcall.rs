//! Deep-fuzz the untrusted-input boundary: bytes → JSON → `ToolCall` → `Action`.
//! Normalizing an attacker-controlled tool call must never panic. The same path is
//! covered by an in-gate randomized test (`build_action_never_panics_on_arbitrary_input`
//! in `guardian-mcp-gateway`); this target is for deeper, coverage-guided runs.
//!
//! Run (nightly): `cargo +nightly fuzz run parse_toolcall`.
#![no_main]

use guardian_core::ActionId;
use guardian_mcp_gateway::{build_action, ToolCall};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(call) = serde_json::from_str::<ToolCall>(s) {
            let _ = build_action(&call, "fuzz", ActionId::new("fuzz"), 0);
        }
    }
});
