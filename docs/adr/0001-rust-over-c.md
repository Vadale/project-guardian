# ADR-0001 — Implementation language: Rust, not C

**Status:** Accepted (2026-06-24). Reversible only with a specific, documented reason.

## Context
Guardian's core job is to safely parse and route **untrusted input**: agent tool
calls, JSON-RPC messages, and — in the MITM forward proxy — raw HTTP/TLS streams.
A memory-safety bug anywhere in that path *is* exactly the class of vulnerability
the product exists to prevent. The user initially proposed C.

## Decision
Implement Guardian in **Rust** (stable, Cargo workspace). The desktop UI is
TypeScript via Tauri v2. `unsafe` is permitted only inside clearly-marked,
reviewed FFI modules (OS keychain / Secure Enclave / TPM, sandbox invocation).

## Consequences
- Memory safety on untrusted input is guaranteed by the compiler (eliminates the
  #1 CVE class for a parser/proxy).
- `async`/`await` on `tokio` gives a clean concurrency model for a daemon/proxy.
- One cross-platform toolchain (macOS/Windows/Linux); Tauri, the MCP SDK, and the
  TLS/proxy libraries are Rust-native.
- Supply-chain auditing via `cargo audit` / `cargo deny`.
- Cost: contributors must know Rust; some OS integrations still need small,
  quarantined `unsafe` FFI.

## Alternatives considered
- **C:** rejected — writing a security tool in the language whose dominant failure
  mode is memory corruption is self-defeating; we would also have to hand-roll or
  bind an async runtime, JSON-RPC, a TLS MITM proxy, and a policy evaluator.
- **Go:** viable for proxy/MCP velocity, but weaker guarantees for the
  security-critical parsing core and no native Tauri story. Kept as a fallback
  note in ROADMAP §0, not chosen.
