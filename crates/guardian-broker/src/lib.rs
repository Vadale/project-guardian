//! `guardian-broker` — identity & token broker. Holds credentials so the agent
//! never sees raw secrets; injects them at the proxy layer under macaroon/OAuth
//! caveats. Implementation lands in ROADMAP Task 8.1 (Phase 3).
//!
//! Note: this crate will host the small, reviewed FFI to the OS keychain /
//! Secure Enclave / TPM, so `unsafe` is permitted here only inside clearly
//! marked FFI modules.
