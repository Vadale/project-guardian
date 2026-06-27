# guardian-proxy

The **network policy layer** for an agent's web traffic — the piece that lets
Guardian mediate raw HTTP(S) (a real bank site, Agenzia delle Entrate, Facebook),
not just MCP tool calls. A user-space forward proxy (no kernel hooks, invariant 6);
the agent points `HTTP(S)_PROXY` at it. Decision recorded in
[`docs/adr/0004-network-proxy.md`](../adr/0004-network-proxy.md).

Built in increments so the heavy/risky TLS stack stays isolated. The
transport-agnostic **mediation core** (`lib.rs`) is now driven onto real sockets by
the **live forward proxy** (`server.rs`, via hudsucker + rustls), which intercepts
HTTPS using a **local CA** (`ca.rs`, rcgen). Run it with `guardian proxy`.

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

## The live proxy (`server.rs`)
`GuardianHandler` implements hudsucker's `HttpHandler`. For each request,
`mediate_request`:
1. normalizes it to an `Action` and evaluates the deterministic policy;
2. **records the decision to the audit log before acting** (invariant 7) — and on
   the network **egress critical path** it **fails closed** (returns a `403`) if the
   log can't be written, rather than forwarding an unlogged request (invariant 5);
3. forwards (attaching the broker `Authorization` on `Allow`, for a real request) or
   returns a `403` carrying the block reason.

**Egress is default-deny.** A `CONNECT` only opens a TLS tunnel, but it is **also
mediated** (on its authority/host): an un-allowlisted host gets no tunnel at all, so a
non-HTTP protocol can't be smuggled through an opaque tunnel. The credential is never
attached to a `CONNECT` — only to the decrypted inner requests, which are mediated
independently. Upstream TLS verification stays strict (webpki roots; Guardian does not
MITM-downgrade real servers). `run()` builds and starts the hudsucker proxy with a
graceful-shutdown future (`guardian proxy` wires it to Ctrl-C).

## The local CA (`ca.rs`)
`LocalCa` generates/persists/loads a self-signed CA (rcgen 0.14) and builds
hudsucker's `RcgenAuthority` to mint per-host leaf certs. Intercepting HTTPS requires
the client to trust this CA — a **security-sensitive, opt-in** step (the CA key can
mint a cert for any site), so: the key is generated locally, written **owner-only
(`0o600`, applied atomically at creation)**, redacted in `Debug`, and never leaves the
machine. `guardian proxy --print-ca-path` shows where `ca.crt` lives to install it.

## Deferred to later increments (tracked in the ADR)
- **CA-trust onboarding UI** (today it's CLI + docs).
- **WebSocket-frame inspection** — the WS *upgrade* request's host is policed, but
  individual frames over an allowed tunnel are not yet inspected.
- **Cockpit `ask` routing** and **body-content exfiltration inspection**.

## Dependencies
Core: `guardian-core`, `guardian-policy`, `guardian-broker`, `guardian-audit`,
`serde_json`. Live proxy: `hudsucker`, `rcgen`, `http`, `hyper`, `bytes`, `tokio`,
`tracing`, `thiserror`. The TLS stack pulls `ring` + `aws-lc-rs` (Apache-2.0/ISC) and
`webpki-roots` (`CDLA-Permissive-2.0`, allowed in `deny.toml`). `#![forbid(unsafe_code)]`
(unsafe lives only in the FFI crypto deps).
