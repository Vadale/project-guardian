# guardian-proxy

The **network policy layer** for an agent's web traffic — the piece that lets
Guardian mediate raw HTTP(S) (a real bank site, Agenzia delle Entrate, Facebook),
not just MCP tool calls. A user-space forward proxy (no kernel hooks, invariant 6);
the agent points `HTTP(S)_PROXY` at it. Decision recorded in
[`docs/adr/0004-network-proxy.md`](../adr/0004-network-proxy.md).

Built in increments so the heavy/risky TLS stack stays isolated. **Today this crate
is the transport-agnostic mediation core only** — no sockets, no TLS, no network
deps. The live proxy (hudsucker + rustls + rcgen local CA) plugs this core into real
sockets in later increments.

## What it does (mediation core)
The core reuses the **same deterministic policy engine and token broker** as the MCP
gateway, so web and MCP traffic are governed consistently.

- **`HttpRequest { method, host, path }`** — the parts of an outbound request the
  policy needs.
- **`to_action(req)`** — normalizes the request into a `guardian_core::Action`
  (`kind = HttpRequest`). The **method and path go in `args`** and the **host in
  `context`**, so HTTP policy rules reference `action.args.method`,
  `action.args.path`, and `action.context.host`. (The URL path is *not*
  `context.path`, which stays reserved for filesystem actions.)
- **`mediate(req, policy, env, broker) -> ProxyOutcome`** — evaluates the action and:
  - `Allow` → `Forward { authorization }`, where `authorization` is the **broker's
    `Bearer <token>` for the host if one is held**, else `None`. The credential is
    attached **only** on allow, and the agent never sent it.
  - `Deny` → `Block { reason }`.
  - `Ask` → `Block` — **fails closed** at this layer (no human is attached yet; the
    live proxy will route `ask` to the cockpit).

### Invariant-relevant behavior
- **Deterministic policy is the only decider** — `mediate` never consults the
  Checker; allow/deny comes solely from `policy.evaluate` (invariant 1).
- **Credential strictly gated to `Allow`** — `Deny`/`Ask` arms carry no token.
- **Host normalization** — `normalize_host` lowercases and strips a default port
  (`:80`/`:443`), so the policy context and the broker key can't silently diverge on
  `Bank.local:443` vs `bank.local` (a mismatch would drop the `Authorization` or
  fail to match an allow rule).
- **`Debug` redacts the token** — `ProxyOutcome` has a hand-written `Debug` that
  prints `<redacted>` for the authorization (mirrors `Broker`'s redacted `Debug`), so
  a stray `{:?}` in a future log line can't leak the credential.

## Deferred to later increments (tracked in the ADR)
- **Audit recording** — the core decides but does no I/O; every forward/block becomes
  a tamper-evident entry (invariant 7) when the live proxy lands, threading the
  policy `matched_rule`/`critical` through alongside the decision.
- **TLS MITM** — rustls + an rcgen-generated local CA, plus opt-in CA-trust UX.
- **Cockpit `ask` routing** and **body-content exfiltration inspection**.

## Dependencies
`guardian-core`, `guardian-policy`, `guardian-broker`, `serde_json`. No TLS/network
deps yet (deliberate — keeps the core light and cargo-deny-clean until the transport
increment). `#![forbid(unsafe_code)]`.
