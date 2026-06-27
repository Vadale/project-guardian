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
1. **Mediation core** *(this increment)* — `HttpRequest → Action → policy + broker`,
   transport-agnostic and fully unit-tested. **No TLS deps yet.**
2. **Live forward proxy (plain HTTP)** — hudsucker wiring for `http://`. This is
   where **audit recording lands**: the core decides but does no I/O, so every
   forward/block becomes a tamper-evident entry here (invariant 7), threading the
   policy `matched_rule`/`critical` through alongside the decision.
3. **TLS MITM** — rustls + an rcgen-generated local CA, plus the CA-trust
   onboarding UX (off by default; the user opts in).
4. **Cockpit/daemon `ask` routing + body-content exfiltration inspection**
   (`context.body.contains_secret`).

The core normalizes the request host (lowercase, default port stripped) so the
policy context and broker lookup share one key. **HTTP policy rules reference
`action.args.method` / `action.args.path` and `action.context.host`** (the URL
path is *not* `context.path`, which stays reserved for filesystem actions).

## Consequences
- The TLS dependencies (increments 2–3) pull `rustls`/`ring` (or `aws-lc-rs`),
  whose licenses (e.g. ring's mixed ISC/MIT/OpenSSL-derived terms) will likely need
  a reviewed `deny.toml` allowance/exception — **tracked**, handled when those deps
  land (the mediation core deliberately avoids them so it stays light and
  cargo-deny-clean).
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
