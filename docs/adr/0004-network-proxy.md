# ADR-0004 — Network proxy: a user-space HTTP(S) MITM forward proxy, HTTP-first

- **Status:** Accepted
- **Date:** 2026-06-27
- **Context:** ROADMAP §7.1 (Phase 2), threat model §6 (the raw-network gap)

## Context
Guardian mediates an agent's tool calls (MCP) and Claude Code's native tools, but
an agent that drives a **browser or raw HTTP** (a real bank site, Agenzia delle
Entrate, Facebook) bypasses all of that — Guardian never sees the request. To apply
the policy (and the token broker) to *web* traffic, Guardian needs to sit on the
network path: intercept each request, normalize it, decide allow/ask/deny, and
inject brokered credentials. HTTPS requires terminating TLS (MITM) with a locally
trusted CA.

## Decision
`guardian-proxy` is a **user-space HTTP(S) forward proxy** (the agent points
`HTTP(S)_PROXY` at it — no kernel hooks, upholding invariant 6). Stack:
**`hudsucker`** (hyper-based MITM proxy) + **`rustls`** + **`rcgen`** (generate and
persist a local CA). Requests are normalized to a `guardian_core::Action` and run
through the **existing deterministic policy engine**; the **token broker** supplies
credentials as headers so the agent never holds them.

Built in increments to keep the heavy/risky parts isolated:
1. **Mediation core** *(done)* — `HttpRequest → Action → policy + broker`,
   transport-agnostic and fully unit-tested. No TLS deps.
2. **Live forward proxy + audit recording** *(done)* — hudsucker `HttpHandler`
   (`server.rs`); records every decision **before acting** (invariant 7), threading
   `matched_rule`. On the egress critical path it **fails closed** if the audit log
   is unavailable (invariant 5), rather than the gateway's fail-open convenience.
3. **TLS MITM** *(done)* — rustls + an rcgen-generated local CA (`ca.rs`, key
   `0o600`/atomic/redacted), `guardian proxy` CLI + `--print-ca-path`. Egress is
   **default-deny**: the `CONNECT` authority is mediated too (an un-allowlisted host
   gets no tunnel), closing the raw-protocol-after-CONNECT bypass. CA-trust **UI**
   onboarding is still deferred (CLI + docs for now).
4. **Cockpit/daemon `ask` routing + WebSocket-frame & body-content exfiltration
   inspection** *(deferred)* (`context.body.contains_secret`). The WS *upgrade*
   host is already policed; individual frames over an allowed tunnel are not yet.

The core normalizes the request host (lowercase, default port stripped) so the
policy context and broker lookup share one key. **HTTP policy rules reference
`action.args.method` / `action.args.path` and `action.context.host`** (the URL
path is *not* `context.path`, which stays reserved for filesystem actions).

## Consequences
- The TLS dependencies (increments 2–3) pull `rustls` with **both** `ring` and
  `aws-lc-rs` (hudsucker's `tokio-rustls` default features force the latter; we use
  `aws_lc_rs` as the active provider). In the end the crypto crates were already
  Apache-2.0/ISC, so **no exception was needed for them**; the only `deny.toml`
  addition was `CDLA-Permissive-2.0` for `webpki-roots` (the Mozilla trusted-root
  *data* list). `aws-lc-sys` builds via the C toolchain (clang here; `prebuilt-nasm`
  helps Windows) — a build-environment note, tracked for the Windows story.
- TLS interception means the user must install and trust a **local CA** — a
  security-sensitive step. It is opt-in, documented, and the CA key is generated and
  stored locally.
- The proxy is a **backstop the user opts into**, not the primary control; the
  policy/broker logic is shared with the gateway, so behavior is consistent across
  the MCP and network paths.

## Alternatives considered
- **Hand-rolled hyper proxy** — more code to own (incl. the untrusted-input HTTP
  parsing the project exists to avoid) and the same TLS problem; rejected in favor
  of the maintained `hudsucker`.
- **OS-level/transparent proxy** — heavier, platform-specific, and not user-space;
  rejected (invariant 6).
