# Project Guardian — Build Roadmap

> **Companion to `README.md`.** The README is *what* and *why*; this file is
> *how* and *in what order*, down to languages, crates, repository layout,
> acceptance criteria, and **reusable implementation prompts** for each step.
>
> Read `README.md` first. All invariants there (deterministic boundary, intercept
> structured actions, agnostic, user-space, local-first, tamper-evident) are
> binding here and are restated as the "Conventions preamble" in §3.

---

## Status snapshot (2026-06-25)

CI is green (`fmt` · `clippy -D warnings` · `test` · `cargo deny`). What exists:

- **Phase 0 — done.** Workspace + 9 crates, CI, ADRs (0001–0003), governance,
  default policy pack.
- **Phase 1 (MVP) — substantially done.** Deterministic CEL policy engine, the
  action model, tamper-evident audit (blake3 hash-chained SQLite), advisory
  `StubChecker`, an MCP gateway over stdio, the daemon + Unix-socket approval
  queue (fail-closed), the CLI (`demo`/`policy-validate`/`mcp`/`ui`/`eval`/
  `decide`/`hook`), the ratatui cockpit (TUI), and a Tauri GUI scaffold.
  ~74 unit tests + an AgentDojo A/B harness (ASR reduction demonstrated).
- **Phase 2 — started.** `guardian hook` (Claude Code `PreToolUse`, **Task 7.4 —
  done**) with a `coding-agent` policy and an `examples/claude-code/` setup. Proxy
  and sandbox not yet built.

**Honest gaps to a _product_ (not an MVP)** are now tracked as concrete tasks:
**§7.5** (MCP proxy generalization — connect to real harnesses/servers), **§9b**
(productionization: persisted+signed audit, config/first-run, cross-platform IPC,
real Checker, observability), plus the remaining Phase 2/3 work. The deterministic
security core is solid; most remaining effort is the product *around* it.

---

## 0. Technology decision: language

**Decision: Rust. Not C.** (Documented and reversible — override only with a
specific reason.)

Guardian is a security product whose core job is to safely parse and route
**untrusted input**: agent tool calls, JSON-RPC, and — in the MITM proxy — raw
HTTP/TLS streams. A memory-safety bug in that path *is* the class of
vulnerability the product exists to prevent. Writing it in C would be
self-defeating.

| Concern | C | Rust |
|---|---|---|
| Memory safety on untrusted input | manual, error-prone (the #1 CVE class) | guaranteed by the compiler |
| Concurrency for a proxy/daemon | manual threads/locks | `async`/`await` + `tokio`, fearless concurrency |
| Cross-platform (macOS/Win/Linux) | heavy per-platform glue | first-class, one toolchain (`cargo`) |
| Ecosystem we need (MCP, TLS, HTTP proxy, JSON, policy eval) | bind/write yourself | mature crates exist |
| Desktop UI | none native | **Tauri** is Rust-native |
| Supply-chain auditability | hard | `cargo audit`, `cargo deny`, reproducible builds |

Where native/`unsafe` still appears: thin FFI for OS keychain / Secure Enclave /
TPM and for invoking OS sandboxes — and even those have Rust bindings. We keep
`unsafe` quarantined and reviewed.

> **If you still want C:** expect to hand-write or bind a JSON-RPC stack, an
> async runtime, a TLS-terminating MITM proxy, and a policy evaluator, and to own
> the memory-safety audit of all of it. The roadmap below assumes Rust; porting
> the *structure* to another language is possible but every crate reference would
> change.

---

## 1. Full technology stack

### Languages & toolchain
- **Rust** (stable, edition 2021+). Workspace via **Cargo**.
- **TypeScript** for the Tauri UI frontend.
- Build/quality: `cargo`, `clippy`, `rustfmt`, `cargo-audit`, `cargo-deny`,
  `cargo-nextest` (fast test runner).

### Crates by concern (candidates — verify versions/APIs at integration time)
| Concern | Crate(s) | Notes |
|---|---|---|
| Async runtime | `tokio` | base for everything I/O |
| Serialization | `serde`, `serde_json` | the action model + JSON-RPC |
| MCP protocol | `rmcp` (official Rust MCP SDK) | young — pin a version; fallback below. Support the current spec's **Streamable HTTP** transport (rev. 2025-06-18) *and* stdio, server- and client-side (for the proxy in §7.5) |
| JSON-RPC (fallback / direct) | `jsonrpsee` | if `rmcp` API churns |
| HTTP server / middleware | `axum`, `tower`, `hyper` | gateway control plane + daemon API |
| HTTP client | `reqwest` | Checker calls, forwarding |
| MITM proxy | `hudsucker` (on `hyper`) | TLS-intercepting forward proxy |
| TLS / certs | `rustls`, `tokio-rustls`, `rcgen` | local CA generation + termination |
| Policy expressions | `cel-interpreter` (CEL) **recommended**; `regorus` (Rego) alt | decidable, side-effect-free eval |
| Policy/config parsing | `toml` + `serde` (v1); YAML optional via `serde_yml` | `serde_yaml` is archived — avoid |
| Audit store | `rusqlite` (SQLite) | append-only table + chained hashes |
| Hashing | `blake3` or `sha2` | hash-chaining the log |
| Signing | `ed25519-dalek` | optional log signing |
| Key storage | `keyring` (OS keychain); `security-framework` (macOS), `tss-esapi` (TPM) later | secrets never in plaintext |
| CLI | `clap` (derive) | `guardian` command |
| Logging | `tracing`, `tracing-subscriber` | structured logs (≠ audit log) |
| Errors | `thiserror` (libs), `anyhow` (binaries) | |
| Daemon↔UI IPC | `interprocess` (local socket/pipe) or `tonic` (gRPC) | cross-platform |
| OAuth | `oauth2` | scoped tokens (Phase 3) |
| Macaroons | `macaroon` | attenuable delegated authority (Phase 3) |
| DIDs / Verifiable Credentials | `ssi` | decentralized identity (Phase 3) |
| Testing | built-in + `cargo-nextest`, `insta` (snapshots), `proptest` (property), `wiremock` (HTTP mocks) | |

### UI
- **Tauri v2** shell; frontend in TypeScript (framework optional — Svelte/Solid
  for small footprint, or plain). UI talks to the daemon over the IPC channel.

### Sandbox backstops (Phase 2, off-the-shelf — never custom kernel code)
- macOS: `sandbox-exec` profiles. Linux: `bubblewrap` / cgroups. Windows:
  AppContainer / Windows Sandbox. Or `docker` where present. All invoked as
  external processes, not linked.

---

## 2. Repository layout (Cargo workspace)

```
project_guardian/
├─ Cargo.toml                  # workspace
├─ README.md                   # the spec
├─ ROADMAP.md                  # this file
├─ deny.toml                   # cargo-deny config (license/advisory gates)
├─ crates/
│  ├─ guardian-core/           # action model, decision types, context — no I/O
│  ├─ guardian-policy/         # schema, loader, deterministic evaluator
│  ├─ guardian-audit/          # tamper-evident hash-chained log
│  ├─ guardian-checker/        # pluggable LLM translator/risk-scorer client
│  ├─ guardian-mcp-gateway/    # MCP proxy adapter (primary interception)
│  ├─ guardian-proxy/          # HTTP(S) MITM forward proxy (Phase 2)
│  ├─ guardian-sandbox/        # OS sandbox backstop for exec-class actions (Phase 2)
│  ├─ guardian-broker/         # identity & token broker (Phase 3)
│  ├─ guardian-daemon/         # long-running service wiring it all together
│  └─ guardian-cli/            # `guardian` CLI
├─ ui/                         # Tauri v2 app
├─ policies/                   # default + example policy packs
├─ tests/                      # end-to-end scenario tests
└─ docs/                       # threat model, policy schema spec, ADRs
```

**Dependency direction (must stay acyclic):**
`core` ← `policy`, `audit`, `checker` ← `mcp-gateway`, `proxy`, `broker` ←
`daemon` ← `cli`/`ui`. `core` depends on nothing internal and does **no I/O**.

### Architecture → crate mapping (from README §5)
| README component | Crate |
|---|---|
| §5.1 interception adapters | `guardian-mcp-gateway`, `guardian-proxy` |
| §5.2 policy engine (the boundary) | `guardian-policy` (+ types in `guardian-core`) |
| §5.3 Checker (advisory) | `guardian-checker` |
| §5.4 approval UI / dashboard | `ui/` (Tauri) |
| §5.5 audit log | `guardian-audit` |
| §5.6 identity & token broker | `guardian-broker` |
| §5.7 adaptive learning | `guardian-policy` (suggestions) + `guardian-daemon` |

---

## 3. Conventions preamble (prepend to every implementation prompt)

> This block is the shared context for all reusable prompts in §5–§9. When
> running a prompt, paste this first (or reference it).

```
You are implementing Project Guardian, an agent-agnostic AI guardian firewall.
Read README.md and ROADMAP.md before writing code. Hard invariants:

1. The security boundary is DETERMINISTIC. No LLM is ever in the allow/deny
   decision path. The Checker only translates and risk-scores; it cannot unlock.
2. Evaluate STRUCTURED actions (tool name + typed args / real HTTP request),
   never the agent's natural-language claims.
3. `guardian-core` does NO I/O and has NO internal deps. Keep deps acyclic.
4. Critical categories (money movement, credential access, data exfiltration,
   irreversible deletion) can never be auto-downgraded by learning.
5. Fail closed on the critical path; fail open (log + defer) on convenience.
6. Everything in English: code, comments, docs, identifiers, commit messages.
7. Every policy rule and decision path gets tests. Use golden/snapshot tests
   (`insta`) for policy outcomes and `proptest` where inputs are adversarial.
8. No `unsafe` outside clearly-marked, reviewed FFI modules.
9. Prefer small, pure, testable functions. Errors via `thiserror`/`anyhow`.
Deliver: the code, its tests, and a one-paragraph note on what to verify.
```

---

## 4. The action model (do this first — everything depends on it)

A single canonical, serializable representation every adapter normalizes into,
and the only thing the policy engine and Checker ever see.

```rust
// guardian-core
pub struct Action {
    pub id: ActionId,                 // ulid
    pub kind: ActionKind,             // FileRead, FileWrite, Exec, HttpRequest, Email, Payment, Delete, ...
    pub tool: String,                 // originating tool name
    pub args: serde_json::Value,      // typed-where-possible arguments
    pub capability: Option<Capability>, // semantic class (payment, credential, ...)
    pub context: ActionContext,       // time, source adapter, session, destination host, ...
}
pub enum Decision { Allow, Ask { reason: String }, Deny { reason: String } }
```

> 🤖 **Reusable prompt — Task 4.1 (action model & decision types)**
> ```
> [Conventions preamble]
> In crate `guardian-core`, define the canonical Action model and Decision type
> exactly as sketched in ROADMAP.md §4. Include: ActionKind and Capability enums
> covering FileRead/FileWrite/Exec/HttpRequest/Email/Payment/Delete and a generic
> Other; ActionContext (timestamp, source adapter id, session id, optional
> destination host, optional principal); serde derive on everything; a
> `is_critical(&self) -> bool` on Capability for the critical categories. No I/O,
> no internal deps. Add unit tests for serde round-trips and is_critical. Document
> each public type.
> ```

---

## 5. Phase 0 — Foundations (≈ week 1)

**Goal:** an empty-but-correct skeleton: workspace builds, CI green, the action
model and specs exist.

- [ ] 0.1 Cargo workspace + the 9 crates as stubs that compile.
- [ ] 0.2 CI (GitHub Actions): `fmt`, `clippy -D warnings`, `nextest`, `cargo-deny`.
- [ ] 0.3 `guardian-core` action model (Task 4.1).
- [x] 0.4 `docs/threat-model.md` and `docs/policy-schema.md` living specs — **done** (initial versions).
- [x] 0.5 ADR process in `docs/adr/` — **done** (0001 Rust, 0002 boundary, 0003 deterministic).
- [x] 0.6 Governance — **done**: `LICENSE` (Apache-2.0), `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `.gitignore`, default policy pack.

**Acceptance:** `cargo nextest run` passes; CI green; `Action` round-trips.

> 🤖 **Reusable prompt — Task 0.1/0.2 (scaffold)**
> ```
> [Conventions preamble]
> Create the Cargo workspace and the nine crates listed in ROADMAP.md §2 as
> compiling stubs with correct, acyclic dependency edges. Add a GitHub Actions
> workflow running rustfmt --check, clippy with -D warnings, cargo-nextest, and
> cargo-deny (advisories + licenses). Add deny.toml allowing only permissive
> licenses. Add rust-toolchain.toml pinning stable. Nothing should depend on
> guardian-core having I/O. Verify the whole workspace builds and CI config is
> valid.
> ```

---

## 6. Phase 1 — MVP (≈ weeks 2–8)

**Goal (Definition of Done):** a non-technical user watches an agent work; green
actions run silently; one yellow action pauses with a *plain-language* prompt;
one red action (exfiltration attempt) is auto-blocked; everything is in a
tamper-evident log — **with no LLM in the deny path**.

### 6.1 Deterministic policy engine — `guardian-policy`
- [ ] Policy schema (TOML v1) + loader with strict validation.
- [ ] Deterministic evaluator over `Action` + context using **CEL**
      (`cel-interpreter`); returns exactly one `Decision`.
- [ ] `critical: true` rules are honored; unknown actions hit `defaults.decision`.
- [ ] Golden tests (`insta`) for every example rule in README §8 + adversarial
      `proptest` cases (e.g. obfuscated `chmod`, secret-bearing POST).

> 🤖 **Reusable prompt — Task 6.1 (policy engine)**
> ```
> [Conventions preamble]
> Implement `guardian-policy`: (1) a TOML policy schema matching README §8
> (defaults, rules with id/when/decision/explain/critical/cap/sandbox); (2) a
> loader that validates and rejects malformed policies with precise errors; (3) a
> deterministic evaluator that takes an Action (guardian-core) + context and
> returns exactly one Decision, using cel-interpreter for the `when` expressions.
> Constraints: evaluation is a pure function — no network, no LLM, no filesystem
> reads during eval. `critical: true` rules must never be downgradeable. Add insta
> snapshot tests for each rule in README §8 and proptest cases for obfuscated
> chmod and secret-bearing POSTs. Document the schema in docs/policy-schema.md.
> ```

### 6.2 Tamper-evident audit log — `guardian-audit`
- [ ] SQLite (`rusqlite`) append-only table; each row stores
      `prev_hash` and `hash = H(prev_hash || serialized_entry)` (`blake3`).
- [ ] `verify()` walks the chain and detects tampering.
- [ ] Records action, decision, matched rule id, Checker rationale, user response.

> 🤖 **Reusable prompt — Task 6.2 (audit log)**
> ```
> [Conventions preamble]
> Implement `guardian-audit`: an append-only, hash-chained log over SQLite
> (rusqlite). Each entry commits to the previous via blake3(prev_hash ||
> canonical_serialized_entry). Provide append(entry) and verify() -> Result<(),
> TamperError> that detects any modification/reordering/truncation. Entry fields:
> timestamp, action id, ActionKind, decision, matched_rule_id, checker_rationale,
> user_response. Leave an optional ed25519 signing hook (feature-gated) for later.
> Tests: a clean chain verifies; mutating any past row fails verify(); truncation
> fails verify().
> ```

### 6.3 Checker (advisory translator/risk-scorer) — `guardian-checker`
- [ ] Trait `Checker { async fn explain(&self, action: &Action) -> Explanation }`
      where `Explanation { plain_text, risk: 0..=100, rationale }`.
- [ ] Pluggable backends: a local model client and an opt-in remote client; a
      deterministic stub backend for tests.
- [ ] **Reads `Action` only.** Cannot return a `Decision`. Type system enforces
      that the Checker output is never wired into the policy decision.

> 🤖 **Reusable prompt — Task 6.3 (checker)**
> ```
> [Conventions preamble]
> Implement `guardian-checker`: a `Checker` trait with `async fn explain(&self,
> action: &Action) -> Explanation { plain_text, risk: u8 (0..=100), rationale }`.
> Provide three backends behind the trait: (a) StubChecker (deterministic, for
> tests), (b) LocalChecker (calls a local model endpoint), (c) RemoteChecker
> (opt-in, behind explicit config). CRITICAL: the Checker takes only an Action and
> returns only an Explanation — it must be impossible to obtain a Decision from
> it; do not import the Decision type here. Mock HTTP with wiremock in tests.
> ```

### 6.4 MCP gateway adapter — `guardian-mcp-gateway`
- [ ] An MCP server (`rmcp`) that registers upstream MCP servers/tools and
      re-exposes them; each `tools/call` is normalized to an `Action`, evaluated,
      and forwarded only if `Allow` (or after UI approval if `Ask`).
- [ ] `Deny` returns a structured MCP error to the agent.
- [ ] If `rmcp` API is unstable, fall back to a direct JSON-RPC impl (`jsonrpsee`).

> 🤖 **Reusable prompt — Task 6.4 (MCP gateway)**
> ```
> [Conventions preamble]
> Implement `guardian-mcp-gateway`: an MCP server (rmcp; fall back to jsonrpsee
> JSON-RPC 2.0 if rmcp is unstable) that proxies one or more upstream MCP servers.
> For each incoming tools/call: normalize to a guardian-core Action, call
> guardian-policy to get a Decision, then: Allow -> forward upstream and return the
> result; Ask -> emit an approval request over the daemon IPC and block until the
> UI responds, then forward or reject; Deny -> return a structured MCP error and
> log. Never forward before a decision. Integration test with a fake upstream MCP
> server proving allow forwards, deny blocks, ask waits.
> ```

### 6.5 Daemon + IPC — `guardian-daemon`
- [ ] Long-running service hosting policy engine, audit, checker, gateway.
- [ ] IPC channel (`interprocess` local socket / `tonic`) exposing: pending
      approvals stream, approve/deny, activity feed, log query.

> 🤖 **Reusable prompt — Task 6.5 (daemon)**
> ```
> [Conventions preamble]
> Implement `guardian-daemon`: wire guardian-policy, guardian-audit,
> guardian-checker, and guardian-mcp-gateway into one tokio service. Expose a
> local IPC API (interprocess crate; or tonic/gRPC) with: subscribe_pending() ->
> stream of pending Ask actions (with Checker explanation), respond(action_id,
> Approve|Deny), activity_feed(), query_log(filter). Pending approvals must time
> out to Deny (fail closed) after a configurable interval. Graceful shutdown.
> Tests for the approve/deny/timeout flows.
> ```

### 6.6 Approval UI — `ui/` (Tauri v2)
- [ ] Traffic-light approval queue showing the Checker's plain-language
      explanation + risk; one-click allow/deny.
- [ ] Live activity feed; basic log viewer.

> 🤖 **Reusable prompt — Task 6.6 (Tauri approval UI)**
> ```
> [Conventions preamble]
> Build a Tauri v2 desktop app in ui/ that connects to the guardian-daemon IPC.
> Screens: (1) Approvals — a queue of pending Ask actions, each card shows the
> Checker plain_text, risk badge (green/yellow/red), the raw action (collapsible),
> and Approve/Deny buttons; (2) Activity — live feed of decisions; (3) Log — query
> the audit log. Keep it accessible and non-technical-friendly. Frontend in
> TypeScript. No business logic in the UI — it only renders daemon state and sends
> approve/deny.
> ```

### 6.7 CLI — `guardian-cli`
- [ ] `guardian start|stop|status`, `guardian policy validate|test`, `guardian
      log verify`, `guardian approvals` (headless approve/deny).

> 🤖 **Reusable prompt — Task 6.7 (CLI)**
> ```
> [Conventions preamble]
> Implement `guardian-cli` with clap (derive): start/stop/status (manage the
> daemon), policy validate <file>, policy test <file> <action.json> (prints the
> Decision + matched rule — great for CI), log verify, approvals (list/approve/deny
> headlessly via daemon IPC). Helpful errors and exit codes (non-zero on
> deny/invalid). Tests for the policy test subcommand against golden cases.
> ```

### 6.8 End-to-end MVP scenario — `tests/`
- [ ] Scripted scenario: agent (via MCP gateway) reads project files (green,
      silent) → attempts `chmod 777` (yellow, paused, translated) → attempts a
      POST of a secret to an unknown host (red, auto-blocked) → log verifies.

> 🤖 **Reusable prompt — Task 6.8 (E2E scenario)**
> ```
> [Conventions preamble]
> Write an end-to-end test in tests/ that boots the daemon with a sample policy
> and a fake upstream MCP server, then drives three tool calls: a read under an
> allowed path (assert Allow, silent), a `chmod 777` exec (assert Ask + a non-empty
> Checker explanation), and an HTTP POST carrying a secret to an untrusted host
> (assert Deny, not forwarded). Finally assert the audit log contains all three
> and verify() passes. This test IS the MVP definition of done.
> ```

---

## 7. Phase 2 — Containment & network (post-MVP)

**Goal:** close the raw-exec/network gaps with off-the-shelf containment.

- [~] 7.1 `guardian-proxy`: HTTP(S) forward proxy (`hudsucker` + `rustls` +
      `rcgen` local CA). Normalizes requests to `Action`s; applies egress
      allowlists; optional agent-signaling header (default OFF, courtesy only);
      optional content watermark on AI-authored bodies. Built in increments
      (see `docs/adr/0004-network-proxy.md`):
  - [x] **Mediation core** — transport-agnostic `HttpRequest → Action → policy +
        broker`: `mediate()` forwards (attaching the broker's `Authorization` only
        on `Allow`) or blocks (`Deny`, and `ask` fails closed); host normalized so
        policy + broker share one key; `Debug` redacts the token. Fully unit-tested.
  - [x] **Live forward proxy + audit recording** — `server::GuardianHandler`
        (hudsucker `HttpHandler`); records each decision before acting and **fails
        closed** if the audit log is unavailable (egress critical path).
  - [x] **TLS MITM** — `ca::LocalCa` (rcgen 0.14) mints per-host certs; CA key
        `0o600` (atomic) + redacted `Debug`; `guardian proxy` CLI + `--print-ca-path`.
        **Egress is default-deny**: the `CONNECT` authority is policed too, so an
        un-allowlisted host gets no tunnel (closes the raw-protocol bypass).
  - [ ] CA-trust onboarding **UI** (currently CLI + docs); WebSocket-frame
        inspection; cockpit `ask` routing + body exfiltration inspection.
- [ ] 7.2 CA-trust onboarding UX in the UI (install/trust the local CA safely).
- [x] 7.3 Sandbox wrapper: run `exec`-class tools inside `sandbox-exec`
      (macOS) / `bubblewrap` (Linux). **Done** (`guardian-sandbox` crate:
      `SandboxRunner` + `guardian exec` — sandboxes actions whose rule sets
      `sandbox = true`; network/FS restricted by default; fails closed if no
      backend). Windows AppContainer / `docker` fallback still pending.
- [x] 7.4 Native hook adapter (Claude Code `PreToolUse`) → same policy engine,
      deterministic deny. **Done** (`guardian hook` + `coding-agent` policy +
      `examples/claude-code/`). Maps native tools → Action; unrecognized tools are
      pinned to `Other` (never name-inferred → never auto-allow); fail-safe to `ask`.
- [~] 7.5 **MCP proxy generalization (connect to real harnesses & servers).**
      **Done (stdio):** generic upstream MCP client (`McpStdioUpstream`),
      multi-server aggregation + `label__tool` namespacing (`MultiUpstream`),
      safe classification (no name-inference fail-open; policy `[tools]` map), and
      proxied `ask`s routed to the cockpit for human approval (`DaemonApprover`).
      **Deferred but planned:** **Streamable HTTP** transport + **`rmcp`** adoption
      (current spec, for remote/HTTP agents & servers — a dedicated ADR-gated step),
      and the auth passthrough hook for upstream servers (ties to the broker, §8.1).

> 🤖 **Reusable prompt — Task 7.1 (MITM proxy)**
> ```
> [Conventions preamble]
> Implement `guardian-proxy`: a user-space HTTP(S) forward proxy using hudsucker
> with rustls; generate and persist a local CA via rcgen. Intercept requests,
> normalize each to a guardian-core Action (HttpRequest with method/host/headers/
> body summary), run guardian-policy, and Allow/Ask/Deny exactly like the gateway.
> Features (all default-OFF, config-gated): inject an agent-signaling request
> header (documented as a courtesy signal, NOT a security control), and append a
> provenance watermark to AI-authored text bodies. Detect secrets in bodies for
> the exfiltration rule. Tests with wiremock upstreams covering allow/deny/header/
> watermark.
> ```

> 🤖 **Reusable prompt — Task 7.3 (exec sandbox)**
> ```
> [Conventions preamble]
> Add a sandbox backstop so any exec-class Action marked `sandbox: true` runs
> contained. Implement a SandboxRunner trait with platform impls invoking
> sandbox-exec (macOS), bubblewrap (Linux), and docker (fallback) as external
> processes — never custom kernel code. Restrict filesystem and network by default;
> only widen per policy. If no sandbox backend is available, fail closed for
> sandboxed actions. Tests assert a denied filesystem/network access inside the
> sandbox actually fails.
> ```

> 🤖 **Reusable prompt — Task 7.5 (MCP proxy generalization)**
> ```
> [Conventions preamble]
> Generalize `guardian-mcp-gateway` from a stdio server fronting LocalToolsUpstream
> into a production agent-agnostic MCP proxy, using rmcp (fallback jsonrpsee):
> 1. Generic upstream MCP CLIENT: connect to one or more configured upstream MCP
>    servers, do tools/list against each, and re-expose them to the downstream
>    agent. Support both stdio and Streamable HTTP transports (current MCP spec),
>    client- and server-side.
> 2. Aggregate tools across servers with collision-safe NAMESPACING (e.g.
>    `server__tool`); record which upstream a call routes to.
> 3. Mediate EVERY tools/call through guardian-policy exactly as today (Allow ->
>    forward upstream; Ask -> daemon approval; Deny -> structured MCP error). Never
>    forward before a decision.
> 4. SAFE CLASSIFICATION (no fail-open): do NOT infer an allow-eligible kind from a
>    tool's name. Unknown tools map to the restrictive default. Support an optional
>    per-server `tool -> {kind, capability}` map in the policy/config; anything
>    unmapped is treated conservatively (ask/deny). Add adversarial tests: an
>    upstream tool named `*read*`/`*open*` must NOT be auto-allowed.
> 5. Auth passthrough hook for upstream servers (OAuth/headers), delegating secret
>    handling to guardian-broker (§8.1) — the agent never sees raw credentials.
> Integration tests with two fake upstream MCP servers (one stdio, one HTTP) prove
> aggregation, namespacing, allow-forwards, deny-blocks, ask-waits, and no
> name-inference auto-allow.
> ```

---

## 8. Phase 3 — Identity, learning, ecosystem

- [~] 8.1 `guardian-broker`: the agent never sees raw credentials — Guardian holds
      them and injects them at the boundary. **Seed done:** `Broker` (`target →
      token`, V1 file store) + a `BrokeredUpstream` that injects on the post-allow
      forward path (token never in the audit/logs/agent), credential-field
      broker-owned, known-label-only injection; demoed end to end in
      `examples/toybank/` (read allowed, money-movement blocked). **Remaining:**
      secrets in the **OS keychain** (`keyring`); scoped **OAuth** (`oauth2`) and
      **macaroons** (`macaroon`) with caveats (expiry, max amount, allowed hosts,
      source binding); injection at the **network proxy** (Phase 2) for web
      services; hardware-backed keys (`security-framework`/`tss-esapi`).
- [ ] 8.2 Constrained adaptive learning: suggest green/yellow adjustments for
      low-risk actions, context-bound and decaying; **never** auto-downgrade
      critical categories. Surfaces as suggestions in the report, never silent.
- [ ] 8.3 Periodic report (the "safety service report"): batch low-risk
      auto-approvals, blocked threats, and rule suggestions to confirm.
- [ ] 8.4 Signed community policy packs + trust pipeline: ed25519-signed packs,
      review/reputation, and a hard rule that packs cannot widen critical-category
      permissions without explicit user opt-in.
- [ ] 8.5 W3C Verifiable Credentials / DIDs (`ssi`) for decentralized identity.
- [ ] 8.6 More adapters: Cursor, OpenAI Agents runtime, generic MCP clients.

> 🤖 **Reusable prompt — Task 8.1 (token broker)**
> ```
> [Conventions preamble]
> Implement `guardian-broker`: store secrets via the keyring crate (OS keychain) —
> never plaintext on disk, never exposed to the agent. Provide a BrokeredAuth API:
> the agent/proxy requests "perform authenticated action against host X with
> capability Y"; the broker mints a least-privilege credential and injects it at
> the proxy layer. Support scoped OAuth (oauth2) and macaroons (macaroon) with
> caveats: expiry, max_amount, allowed_hosts, source binding. Critical-capability
> use always requires a fresh user approval (never cached). Tests prove the agent
> never receives a raw secret and that caveats are enforced.
> ```

> 🤖 **Reusable prompt — Task 8.4 (signed policy packs)**
> ```
> [Conventions preamble]
> Implement signed community policy packs: a pack is a directory of policy TOML +
> a manifest signed with ed25519. Add `guardian pack verify` and loader
> enforcement that refuses unsigned/altered packs and refuses any pack that widens
> a critical category unless the user explicitly opts in at install. Record pack
> provenance (publisher key, version) in the audit log. Tests: tampered pack
> rejected; critical-widening pack blocked without opt-in.
> ```

---

## 9. Phase 4 — Hardening, packaging, 1.0

- [ ] 9.1 Security pass: `cargo audit`/`cargo deny` clean; quarantine and review
      all `unsafe`; fuzz the proxy/JSON-RPC parsers (`cargo-fuzz`).
- [ ] 9.2 Self-protection: signed/locked policy, sealed signing key, fail-closed
      verified end-to-end (Guardian is the highest-value target — see README §7).
- [ ] 9.3 Packaging: signed/notarized macOS build, Windows installer, Linux
      packages; Tauri bundler.
- [ ] 9.4 Docs: user guide, policy-authoring guide, adapter-authoring guide,
      threat model finalized, ADRs.
- [ ] 9.5 Performance: confirm the green fast-path never invokes the LLM; measure
      added latency per action; budget and document it.

> 🤖 **Reusable prompt — Task 9.1 (security hardening)**
> ```
> [Conventions preamble]
> Do a security hardening pass: make cargo-audit and cargo-deny clean; list and
> justify every `unsafe` block, moving each into a reviewed FFI module; add
> cargo-fuzz targets for the JSON-RPC parser and the HTTP proxy request parser and
> run them. Add a test proving the green/allow fast-path performs zero LLM/network
> calls. Report findings and residual risks.
> ```

---

## 9b. Productionization (MVP → shippable product)

The MVP cuts corners that a real product cannot. These make the existing core
*operable and durable*, independent of the new-capability phases (2/3).

- [~] 9b.1 **Persist + sign the audit log in the daemon.** **Done:** the daemon
      opens a persistent SQLite log at `GUARDIAN_AUDIT` (default `~/.guardian/
      audit.db`), continues the hash chain across restarts, and `verify()`s on
      startup — refusing to start on a broken/forked chain (fail closed).
      **Remaining:** the feature-gated ed25519 head signature, and a proper per-OS
      state dir (XDG / `Application Support` / `%APPDATA%`) once config (§9b.2) lands.
- [~] 9b.2 **Configuration system + first-run defaults (README §5.10).** **Done:**
      a typed `Config` (`guardian-daemon::config`) loaded from `GUARDIAN_CONFIG`
      (default `~/.guardian/config.toml`) with fields for policy path,
      `trusted_hosts`, approval timeout, socket path, and audit-log location;
      per-value precedence built-in default < config file < `GUARDIAN_*` env var
      (kept as overrides). First run writes a commented default config; strict
      parsing (`deny_unknown_fields`) fails closed on a malformed config. `main`
      now reads everything via `Config` instead of scattered env reads.
      **Remaining:** the Checker-backend field (pending §9b.4), a CLI-flag
      precedence layer, writing the default policy pack on first run, a proper
      per-OS config/state dir (XDG / `Application Support` / `%APPDATA%`), and —
      flagged by the security audit — routing config `trusted_hosts` through the
      critical-category opt-in (today it can exempt a host from host-gated critical
      deny rules; mitigated for now by owner-only file perms + a startup log of the
      effective value).
- [ ] 9b.3 **Cross-platform IPC.** Windows named pipe alongside the Unix socket
      (via the `interprocess` crate) so the daemon/UI run on Windows too.
- [~] 9b.4 **Real Checker backends.** **Done:** `HttpChecker` — POSTs the action to
      a configured HTTP endpoint (`checker_endpoint`/`GUARDIAN_CHECKER`) and parses
      an `Explanation`; daemon uses it when set, else the offline `StubChecker`
      (privacy default). Advisory-only (never on the allow/deny path); infallible
      (any error → conservative fallback), 10s timeout, 256 KB body cap; http-only.
      **Remaining:** an HTTPS/TLS build option, optional arg redaction before POST,
      and recording the Checker backend per audit entry ("per-action, logged").
- [~] 9b.5 **Observability.** **Done:** `tracing` + `tracing-subscriber` (env-filter
      `RUST_LOG`, default `info`) wired through the daemon — structured operational
      logs (startup, per-call `tool`+`status`, invalid requests, failed kill-switch
      engage), **distinct from the tamper-evident audit log**; no secrets/bodies
      logged. **Remaining:** optional metrics, and tracing in the gateway/proxy
      front-ends.
- [~] 9b.6 **Self-protection + kill switch** (README §5.8/§5.9; overlaps §9.2).
      **Done:** the gateway applies a deterministic hard override **before** the
      policy (recorded to the audit log): (1) a **kill switch** — while a `STOP`
      sentinel exists, every action is denied; (2) **self-protection** — deny
      `FileWrite`/`Delete` targeting Guardian's own files (config, policy, audit,
      socket, `STOP`, `~/.guardian`), with paths normalized (`..`/relative can't
      evade the prefix). Daemon `kill_switch` control command + `DaemonClient`.
      **Remaining (flagged by the security audit):** (a) **control-channel
      separation** — today the agent and user share one control socket, so the
      agent could `kill_switch{engage:false}`/`respond{approve}` on it; split the
      agent-facing channel from the user/control channel (peer-cred or a second
      socket) so the kill switch and approvals are user-only. (b) **`Exec`
      coverage** — a shell command can still modify Guardian's files; needs the OS
      sandbox backstop (§7.3). (c) symlink resolution (needs canonicalization /
      the sandbox). Until (a)+(b), the kill switch is effective on the mediated
      file path but not yet fully agent-proof.

> 🤖 **Reusable prompt — Task 9b.1 (persist + sign audit)**
> ```
> [Conventions preamble]
> Make guardian-daemon use a PERSISTENT, signed audit log instead of the in-memory
> one. Open the blake3 hash-chained SQLite log at a per-OS state path (XDG data dir
> / ~/Library/Application Support / %APPDATA%), creating it if absent. Enable the
> ed25519 head-signature (feature-gated in guardian-audit): sign the chain head;
> store the key via the keyring crate (never plaintext). On startup, run verify()
> and refuse to start (fail closed, clear error) if the chain is broken, reordered,
> truncated, or the head signature doesn't match. Tests: restart preserves and
> re-verifies the chain; a tampered store is rejected at startup.
> ```

> 🤖 **Reusable prompt — Task 9b.2 (config + first-run)**
> ```
> [Conventions preamble]
> Add a configuration layer: a typed Config (serde) loaded from a per-OS config dir
> (XDG / Application Support / %APPDATA%) with fields for policy path, trusted_hosts,
> approval_timeout, socket/pipe path, log path, and checker backend. Precedence:
> built-in safe defaults < config file < GUARDIAN_* env overrides < CLI flags. On
> first run, write a restrictive default config and the default policy pack, and
> tell the user where they are. Validate on load; refuse invalid config (fail
> closed). Tests for precedence and first-run materialization.
> ```

---

## 10. Milestones & rough timeline (solo, AI-assisted)

| Milestone | Scope | Status / time |
|---|---|---|
| **M0** Skeleton | Phase 0 | ✅ done |
| **M1** MVP | Phase 1 (§6) — the E2E demo | ✅ substantially done (engine, audit, gateway, daemon, CLI, TUI, hook) |
| **M2** Contained | Phase 2 — proxy + sandbox + hook adapter + **MCP proxy (§7.5)** | 🟡 hook done; proxy/sandbox/§7.5 pending (+3–5 wks) |
| **M3** Delegated | Phase 3 — broker, learning, report, signed packs | pending (+4–6 wks) |
| **Mp** Product | §9b productionization (persisted/signed audit, config, IPC, Checker, observability) | pending (+2–3 wks) |
| **M4** 1.0 | Phase 4 — hardening + packaging + docs | pending (+3–4 wks) |

Timelines assume AI-assisted implementation and tight scope discipline. M1 is the
proof point; M4 is a shippable open-source 1.0.

---

## 11. Cross-cutting acceptance gates (every phase must keep these true)
1. No LLM call exists on any allow/deny path (test-enforced).
2. `guardian-core` has no internal deps and no I/O.
3. Every new rule/decision path has golden + adversarial tests.
4. The audit log `verify()` passes after every E2E run.
5. Critical categories are never auto-downgraded (test-enforced).
6. `clippy -D warnings`, `fmt`, `cargo-deny`, `nextest` all green in CI.
7. All code, comments, and docs are in English.
8. **Classification never fails open:** an unrecognized tool/action maps to the
   restrictive default (`Other` → `ask`/`deny`), never to an allow-eligible kind
   inferred from an attacker-controlled tool name. (Test-enforced — see the hook
   and the §7.5 proxy.)
```
