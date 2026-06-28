# Hardening & performance (Phase 4 — §9.1, §9.5)

The security-hardening report and the performance budget for Project Guardian.

## Memory safety — no `unsafe` in our code (§9.1)
Every Guardian crate begins with `#![forbid(unsafe_code)]`, so the **compiler
rejects any `unsafe` block** in our code. A CI step (`Forbid unsafe in our crates`)
also asserts the attribute is present in every crate's `lib.rs`/`main.rs`, so a new
crate can't silently drop it. There are **zero `unsafe` blocks** we own.

`unsafe` exists only inside vetted third-party FFI crates we depend on, never in our
logic:

| Crate | Why | Surface |
|---|---|---|
| `rusqlite` / `libsqlite3-sys` | SQLite C bindings (audit log) | local file DB |
| `ring`, `aws-lc-sys` | TLS crypto (proxy) | well-reviewed, widely used |
| `keyring` / `security-framework` | OS keychain (broker) | platform credential store |
| `libfuzzer-sys` | fuzz targets only | not in shipped binaries |

## Dependency advisories & licenses (§9.1)
`cargo deny check` runs in CI and gates every PR. Its `[advisories]` section uses the
**RustSec advisory database** — the same database `cargo audit` uses — so "cargo
audit clean" is enforced by the deny gate (yanked = deny; one scoped, documented
exception: `RUSTSEC-2024-0436` for the compile-time-only `paste` macro). Licenses are
restricted to a reviewed permissive allow-list. We deliberately **rejected**
dependencies that would have pulled unmaintained/heavy transitive code: the
`macaroon` crate (unmaintained `sodiumoxide` + libsodium) and the full `ssi` stack —
see `docs/architecture/guardian-broker.md`.

## Fuzzing the untrusted-input boundary (§9.1)
The highest-risk parsing surface is an attacker-controlled tool call:
`bytes → JSON → ToolCall → Action`. Two layers cover it:
- **In-gate:** `build_action_never_panics_on_arbitrary_input` (in
  `guardian-mcp-gateway`) hammers the path with 5 000 garbage/crafted inputs every
  test run and asserts it never panics.
- **Deep:** a `cargo-fuzz` target, `fuzz/fuzz_targets/parse_toolcall.rs`, for
  coverage-guided runs: `cargo +nightly fuzz run parse_toolcall`. (The `fuzz` crate
  is excluded from the stable workspace; it needs a nightly toolchain.)

The proxy's HTTP/TLS parsing is delegated to `hyper`/`rustls` (not hand-rolled), so
that untrusted-byte surface is the responsibility of those vetted crates.

## The deterministic fast path never invokes the LLM (§9.5)
Invariant 1 (no LLM on the allow/deny path) is **test-enforced**:
`checker_is_not_called_on_the_fast_path` wires a `Checker` that panics if called and
sends an `allow` and a `deny` through the gateway — both succeed, proving the Checker
(the only LLM touchpoint) runs **only** for `ask`. No network or LLM call is on the
green path.

## Latency budget (§9.5)
The hot path is `CompiledPolicy::evaluate` (pure CEL evaluation, no I/O). Measured on
an Apple-silicon laptop, release build, a 2-rule HTTP policy:

> **≈ 2.6 µs per decision** (200 000 iterations; the CEL standard-function registry
> is built once per `CompiledPolicy`, not per call).

So Guardian adds **single-digit microseconds** to an allow/deny decision — far below
any human-perceptible or network-relevant threshold. The only places latency grows
are the explicitly-opt-in `ask` path (waits on a human) and the advisory Checker
(opt-in, never on allow/deny). Budget: **the green fast path must stay in the
low-microseconds range and perform zero network/LLM calls** — both hold today.
