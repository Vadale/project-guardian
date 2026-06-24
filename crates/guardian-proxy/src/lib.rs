//! `guardian-proxy` — user-space HTTP(S) forward proxy (TLS-intercepting via a
//! locally installed CA). Normalizes requests into actions for the policy
//! engine, applies egress allow-lists, and handles optional header/watermark
//! injection. Implementation lands in ROADMAP Task 7.1 (Phase 2).
