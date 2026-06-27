# Changelog

All notable changes to Project Guardian are recorded here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); the project uses
[Semantic Versioning](https://semver.org/) from 1.0 onward. Maintained by the
`doc-writer` agent on every change (see `CLAUDE.md`).

## [Unreleased] — design phase

### Implemented — 2026-06-27
- **Proxy `ask` → cockpit routing (`guardian-proxy` + `guardian proxy --daemon`,
  Phase 2 / §7.1 increment 4)** — the network proxy can now resolve a yellow (`ask`)
  decision through a **human**, completing the traffic-light model for web traffic.
  A new `Approver` trait in `guardian-proxy` (kept decoupled from the daemon IPC) is
  awaited on `ask`; the CLI bridges it to a running daemon's cockpit
  (`ProxyDaemonApprover` → `DaemonClient::approve`). Approve → forward (with the
  broker credential if brokered); deny **or any non-answer/timeout/unreachable
  daemon → block** (the queue is fail-closed). Without `--daemon`, `ask` still fails
  closed exactly as before. The decision pipeline was refactored into `prepare` →
  `record_or_fail` (audit before acting; fail closed if unrecordable) →
  `resolve_and_respond`. 3 new unit tests (ask approved → forward, denied → block,
  no-approver → fail closed). Verified e2e: with an unreachable daemon an `ask`
  request returns `403` and is audited.
- **Exec sandbox backstop (`guardian-sandbox` + `guardian exec`, Phase 2 / ROADMAP
  §7.3)** — a new dependency-free crate that runs an `exec`-class action **contained**
  when the matched policy rule sets `sandbox = true`. Containment is delegated to an
  **off-the-shelf OS tool** (no custom kernel code, invariant 6): `sandbox-exec`
  (macOS Seatbelt) or `bubblewrap` (Linux). A `SandboxRunner` trait exposes `wrap()`
  (builds the exact argv — unit-testable without a real sandbox) and `run()`; the
  default is **restrictive** (network denied, filesystem read-only except temp) and
  policy widens it (`--allow-network`, `--writable <path>`). `detect()` returns the
  platform backend if its tool is on `PATH`, else `None` — and a sandboxed action
  with **no backend fails closed** (refuses to run unconfined). New `guardian exec
  [--policy] [--audit] [--allow-network] [--writable …] -- <cmd> …`: builds the
  `Exec` action, evaluates the deterministic policy, **records the decision to the
  audit log**, then refuses on deny/ask (exit 126) or runs the command — sandboxed
  when the rule asked. Verified end-to-end on macOS: an allowed `echo` runs
  sandboxed; `rm -rf` is denied and not run; a network attempt inside the sandbox
  fails (`connect: Operation not permitted`); all three are audited. 6 unit tests
  (argv construction for both backends + a backend-gated real network-denial check).
- **Network proxy — live HTTP(S) forward proxy with TLS interception
  (`guardian-proxy` + `guardian proxy`, Phase 2 / ROADMAP §7.1, increments 2–3)** —
  the mediation core now drives **real sockets** via `hudsucker` (+ `rustls`/`rcgen`).
  `server::GuardianHandler` implements hudsucker's `HttpHandler`: it normalizes each
  request, evaluates the **deterministic policy**, **records the decision to the
  tamper-evident audit log before acting** (and **fails closed** if the log is
  unavailable — this is the egress critical path), then forwards (injecting the
  broker's `Authorization` on `Allow`, never on `CONNECT`) or returns a `403` with the
  block reason. `ca::LocalCa` generates/persists/loads a **local CA** (rcgen 0.14)
  used to mint per-host leaf certs; the CA key is written **owner-only (`0o600`,
  applied atomically at creation)** and redacted in `Debug`. **Egress is
  default-deny**: the proxy mediates the `CONNECT` **authority** too, so an
  un-allowlisted host gets no tunnel at all (closes the raw-protocol-after-CONNECT
  bypass the security audit flagged) — the decrypted inner requests are still
  mediated independently. Upstream TLS verification stays strict (webpki roots; real
  servers are not MITM-downgraded). New `guardian proxy` CLI subcommand
  (`--listen/--policy/--secrets/--audit/--ca-dir/--print-ca-path`) and an
  `examples/proxy/` walkthrough (read a private site with a brokered token; block all
  state-changing requests). Verified end-to-end: plain HTTP forwards with the token
  injected, `POST` blocked `403`, HTTPS MITM returns `200` when the client trusts the
  local CA, an un-allowlisted HTTPS host has its tunnel refused, and every decision is
  audited. Reviewed by `code-reviewer` (approve-with-nits) and `security-auditor`
  (no Critical/High; the CONNECT-authority gate, fail-closed audit, and atomic CA-key
  perms were applied from its findings; WebSocket-frame inspection tracked for the
  body-inspection increment). `deny.toml` allows `CDLA-Permissive-2.0` (the
  webpki-roots data license); the TLS crypto deps are Apache-2.0/ISC.
- **Network proxy — mediation core (`guardian-proxy`, Phase 2 / ROADMAP §7.1)** —
  the first increment of the user-space HTTP(S) forward proxy (decision recorded in
  `docs/adr/0004-network-proxy.md`), built transport-first so the heavy TLS stack
  stays isolated for a later increment. A new **transport-agnostic mediation core**
  normalizes an outbound `HttpRequest` (method, host, path) into a
  `guardian_core::Action` and runs it through the **same deterministic policy
  engine** as the MCP gateway: `mediate()` returns `Forward` or `Block`. For an
  **allowed** request to a brokered host it attaches the **token broker**'s value as
  the `Authorization` (`Bearer …`) — so the agent never holds the credential, exactly
  as on the MCP path — and **only** on `Allow`; `Deny` blocks, and `ask` **fails
  closed** to a block at this layer (no human is attached yet — the live proxy will
  route `ask` to the cockpit). The request **host is normalized** (lowercase, default
  port stripped) so the policy context and the broker lookup can never silently
  diverge on `Bank.local:443` vs `bank.local`. `ProxyOutcome`'s `Debug` **redacts the
  token** (mirrors `Broker`'s redacted `Debug`) so a stray `{:?}` can't leak it. Added
  `Broker::token_for()` (raw token for header building). 6 unit tests; no TLS/network
  deps yet. Reviewed by `code-reviewer` (approve-with-nits → host normalization and
  redacting `Debug` applied; audit recording + `matched_rule` threading tracked for
  the live-proxy increment in the ADR).
- **Audit-log browser (`guardian log`)** — a read-only viewer for the tamper-evident
  log (the "black box"): `guardian log [--audit <path>] [--limit N]` opens the
  persistent log (`$GUARDIAN_AUDIT`, else `~/.guardian/audit.db`), prints the
  **integrity status** (`verify()` → OK/TAMPERED), the entry count, and a table of
  recent decisions (seq, decision, kind, matched rule, reason). Backed by a new
  `AuditLog::tail(limit)` (most-recent-first from SQL, returned oldest-first). It is
  **resilient when the log looks corrupt** — an unparseable row renders as
  `<unreadable>` rather than aborting the listing (you reach for this precisely when
  the log is suspect; `verify()` remains the authority). Cells collapse control
  chars and clip, so a multi-line reason can't break the table. Read-only; reviewed
  by code-reviewer; tests for `tail` ordering/over-limit and the corrupt-row path.
- **Token broker (vertical seed)** (ROADMAP §8.1) — `guardian-broker::Broker` holds
  `target → token` secrets so the **agent never sees the raw credential**: Guardian
  injects the token into a tool-call only on the **forward (post-allow) path**, so
  the audit log records the pre-injection action and nothing leaks. In the proxy,
  `guardian mcp --upstream … --secrets <file>` wires a `BrokeredUpstream` that
  injects the destination's token; the credential field is **broker-owned** (any
  agent-supplied value is scrubbed) and a token is injected **only for a known
  registered upstream label** (no cross-target leak). A live `examples/toybank/`
  demo shows the headline behavior end to end: with the broker, *read balance*
  works (token injected) while *transfer* is **blocked** by policy (money movement
  is critical) — so a hallucination or prompt injection can't drain the account;
  without the broker the bank returns `UNAUTHORIZED`. Reviewed by code-reviewer +
  security-auditor; fixes applied (redacted `Debug` so `{:?}` can't leak tokens,
  `*secrets*.toml` git-ignored, broker-owned field + known-label injection, a
  world-readable secrets-file warning). V1 secret store is a file; OS keychain +
  macaroon caveats remain Phase 3. Tests for injection/override/scrub + the wiring.

### Implemented — 2026-06-25
- **Real Checker backend: `HttpChecker`** (ROADMAP §9b.4) — a model-backed advisory
  Checker that POSTs the structured action to a configured HTTP endpoint and parses
  an `Explanation` back; the daemon uses it when `checker_endpoint` /
  `GUARDIAN_CHECKER` is set, else the offline `StubChecker` (privacy default, off).
  **Advisory only (ADR-0003)** — the endpoint's reply only produces the human-facing
  explanation/risk on an `ask`; it never reaches the allow/deny decision (verified
  by the security audit). Infallible to the caller: any error (unreachable, non-2xx,
  bad/oversize JSON) degrades to a conservative offline fallback, with a 10s timeout
  and a **256 KB response-body cap** (no unbounded-allocation DoS). http-only (no
  TLS) to keep the dependency/license surface small. Security-audit fixes applied:
  body cap, a startup warning when the endpoint is non-local (the full action incl.
  args is sent there) or `https`, and the URL is not logged (may embed credentials).
  wiremock tests cover success/clamp + unreachable-fallback.
- **Observability: structured logging** (ROADMAP §9b.5) — the daemon now uses
  `tracing` + `tracing-subscriber` (level via `RUST_LOG`, default `info`) instead
  of ad-hoc `println!`/`eprintln!`: startup events, a `tool`+`status` event per
  mediated call, invalid-request warnings, and a loud `error!` if the kill switch
  fails to engage. This is **operational** logging, deliberately separate from the
  tamper-evident audit log, and logs no secrets or request bodies (reviewed by
  code-reviewer). Remaining: optional metrics + tracing in the proxy front-ends.
- **Self-protection + kill switch** (ROADMAP §9b.6) — the gateway now applies a
  deterministic hard override **before** the policy (recorded to the audit log):
  a **kill switch** (while a `STOP` sentinel next to the config exists, every
  action is denied) and **self-protection** (deny `FileWrite`/`Delete` targeting
  Guardian's own files — config, policy, audit, socket, `STOP`, `~/.guardian` —
  with paths normalized so `..`/relative can't evade the prefix). Daemon gains a
  `kill_switch` control command (+ `DaemonClient::kill_switch`). Reviewed by
  code-reviewer + security-auditor; fixes applied (path normalization + adversarial
  tests, `STOP` added to the protected set, loud-fail on a failed engage). **Known
  follow-ups (tracked, §9b.6):** the agent and user still share one control socket
  (channel separation needed so the agent can't toggle the switch / self-approve),
  and `Exec` can still reach Guardian's files (needs the OS sandbox, §7.3) — so the
  kill switch is effective on the mediated file path but not yet fully agent-proof.
- **Daemon: configuration system + first-run defaults** (ROADMAP §9b.2) — a typed
  `Config` (`guardian-daemon::config`) loaded from `GUARDIAN_CONFIG` (default
  `~/.guardian/config.toml`) replaces the scattered env reads in `main`. Fields
  (`socket`, `policy`, `audit`, `approval_timeout_secs`, `trusted_hosts`) are all
  optional, so a missing/empty config yields safe defaults; per-value precedence is
  **built-in default < config file < `GUARDIAN_*` env var** (`GUARDIAN_SOCK`/
  `POLICY`/`AUDIT`). On first run it materializes a commented default config the
  user can edit. Parsing is strict (`deny_unknown_fields`) and **fails closed** on a
  malformed config (the daemon refuses to start rather than run half-understood).
  Hardened per the code/security review: the first-run config is written
  owner-only (0600, dir 0700), a `0` approval timeout is treated as unset (it would
  otherwise deny every `ask`), and the effective `trusted_hosts` is logged at
  startup (it exempts hosts from host-gated critical rules — routing it through the
  critical-category opt-in is a tracked follow-up). Covered by config tests (safe
  defaults, env-overlay precedence, first-run materialization, zero-timeout guard,
  malformed rejected).
- **Daemon: persistent, verified audit log** (ROADMAP §9b.1) — the daemon no
  longer keeps its tamper-evident log in memory (lost on restart). It opens a
  SQLite file at `GUARDIAN_AUDIT` (default `~/.guardian/audit.db`), continues the
  hash chain across restarts, and **verifies the chain on startup — failing closed
  (refusing to start) if it is broken/tampered**, rather than appending to a log
  whose integrity it can't vouch for. Verified by a live restart smoke (an entry
  recorded in one run is present and intact after a restart). ed25519 head signing
  remains a follow-up (§9b.1 / §9.2).
- **MCP proxy: human approvals via the cockpit** — an `ask` on a *proxied* tool now
  reaches the human instead of failing closed. The daemon gains an `approve`
  control-socket request that enqueues into its `ApprovalQueue` (shown by the
  cockpit's `pending`, resolved by `respond`) and blocks until resolved (or times
  out → denied). A new `DaemonApprover` in the CLI routes the proxy's `ask`
  decisions there: `guardian mcp --upstream "<cmd>" --daemon <socket>` proxies an
  upstream MCP server *and* sends its `ask`s to the cockpit, while the proxy keeps
  owning the upstream connection. Verified by a daemon integration test and a live
  3-process run (proxy → daemon queue → cockpit approve → forwarded to upstream).
- **MCP proxy: multi-server aggregation + namespacing** (ROADMAP §7.5, step 4) —
  `upstream::MultiUpstream` fronts several upstream MCP servers behind one
  Guardian. `guardian mcp --upstream` is now repeatable (`[label=]command args`);
  tools are aggregated and **namespaced** `label__tool`, and a `tools/call` is
  routed to the owning server with the namespace stripped. A single unlabeled
  upstream keeps raw tool names (back-compatible). The policy `[tools]` map keys
  on the namespaced names, so classification stays per-server and trusted.
  Verified live (one Guardian fronting two labeled Guardians: aggregated/namespaced
  `tools/list`, `a__read_file` allowed and routed to server `a`, `b__read_file`
  blocked) and unit tests for the namespacing/route helpers.
- **MCP proxy: policy-driven tool classification** (ROADMAP §7.5, step 3) — the
  policy schema gains an optional `[tools]` table (`tool name → ActionKind`). When
  Guardian proxies an upstream MCP server, the classifier comes from this trusted
  map (the proxy uses `policy.tools`); a tool not listed is `Other` (restrictive
  default). This makes the proxy practically usable — a policy can declare which
  upstream tools are safe to treat as e.g. `FileRead` (green fast-path) — while the
  trusted source of classification stays the policy, never the tool name. The
  built-in MCP modes keep their fixed `builtin_classifier()`. Verified live (a
  proxy with `[tools] read_file = "FileRead"` forwards read_file, blocks run_shell)
  and a schema parse test. See `docs/policy-schema.md` §2.1.
- **MCP proxy: generic stdio upstream client** (ROADMAP §7.5, step 2) —
  `guardian_mcp_gateway::upstream::McpStdioUpstream` spawns a real MCP server as a
  child process, performs the handshake, discovers its tools (`tools/list`), and
  forwards `tools/call`s — implementing the `Upstream` port. The CLI gains
  `guardian mcp --upstream "<command>"` (and `--policy`): Guardian then **proxies**
  that server, re-advertising its tools and mediating every call through the
  policy. The upstream's tools are untrusted, so the proxy attaches **no
  classifier** — every tool is `Other` (restrictive default) until the policy
  trusts it explicitly. Verified live (Guardian proxying Guardian: aggregated
  `tools/list`, a policy-trusted tool forwards, an untrusted one is blocked) and a
  `parse_tools` unit test. Streamable HTTP + rmcp and multi-server namespacing are
  the next step.
- **MCP gateway: trusted tool classification (fail-open closed)** — first step of
  the MCP-proxy generalization (ROADMAP §7.5). `McpServer` now classifies each
  `tools/call` via a trusted `tool-name → ActionKind` map (`with_classifier`);
  a tool **not** in the map is `Other` (the restrictive default), never inferred
  from its name. This closes the latent fail-open the security audit flagged on
  the gateway path (a proxied/upstream tool named `*read*` can no longer be
  auto-allowed) and is the classification foundation the upstream proxy needs.
  The built-in tools are mapped in `guardian mcp`; verified live (read_file→allow,
  run_shell/sneaky_read→blocked) and by a regression test. Upholds new gate §11.8.
- **Usable end to end with Claude Code.** A `coding-agent` policy pack
  (`policies/default/coding-agent.toml`) tuned for an autonomous coding agent
  (reads silent; writes/shell `ask`; destructive shell — `rm -rf /`, pipe-to-shell,
  fork bomb, `mkfs`, `dd … of=/dev/` — plus data exfiltration and credential
  access `deny`; benign `rm -rf ./build` falls through to `ask`). The daemon now
  loads `GUARDIAN_POLICY` (env, consistent with `GUARDIAN_SOCK`) and **refuses to
  start** on an unreadable/invalid policy rather than fall back silently. A ready
  `examples/claude-code/` (settings + README) wires the `PreToolUse` hook to this
  policy. Covered by a policy regression test (compiles + read→allow,
  shell→ask, `rm -rf /`→deny+critical) and verified by a CLI battery.
- **Claude Code `PreToolUse` hook adapter** (`guardian hook`) —
  [`crates/guardian-cli`](../crates/guardian-cli),
  [arch doc](architecture/guardian-cli.md). Reads a Claude Code `PreToolUse`
  payload on stdin and prints the `hookSpecificOutput` permission decision
  (`allow` / `ask` / `deny`), so Guardian mediates Claude Code's **native** tools
  (Bash, Edit, Write, Read, WebFetch, …) — not only the tools it exposes over MCP.
  It maps each native tool to a Guardian `Action` (Read/Glob/Grep → `FileRead`,
  Write/Edit → `FileWrite`, Bash → `Exec` with the command in `args.cmd`,
  WebFetch → `HttpRequest` with the host lifted from the URL) and asks the
  deterministic policy. Unrecognized/MCP/internal tools carry no `kind` hint and
  hit the restrictive default. Always exits 0 with a decision and **never fails
  open**: a parse error or an unreadable policy degrades to `ask` (human decides),
  never a silent `allow`. Covered by golden tests (allow/ask/deny, the mapping,
  URL-host parsing) and fail-safe tests (malformed input → `ask`).

### Implemented — 2026-06-24
- **Workspace & CI scaffold** (ROADMAP Phase 0). Cargo workspace
  (`resolver = "2"`, shared `[workspace.dependencies]`), pinned
  `rust-toolchain.toml`, `deny.toml`, and a GitHub Actions `ci.yml` running
  `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`, and
  `cargo deny check`.
- **`guardian-core` action model** (ROADMAP Task 4.1) —
  [`crates/guardian-core`](../crates/guardian-core),
  [arch doc](architecture/guardian-core.md). The canonical, `serde`-serializable
  action model (`Action`, `ActionKind`, `Capability`, `ActionContext`,
  `ActionId`) and the `Decision` type (`allow` / `ask` / `deny`) with
  `restrictiveness` and `most_restrictive` (the most-restrictive-wins primitive)
  and `Capability::is_critical` for the four critical categories. No I/O, no
  internal deps, `#![forbid(unsafe_code)]` — upholds CLAUDE.md invariant 3.
- **`guardian-policy` deterministic CEL engine** (the security boundary) —
  [`crates/guardian-policy`](../crates/guardian-policy),
  [arch doc](architecture/guardian-policy.md). TOML schema + structural
  validation (`schema.rs`: rejects permissive defaults, duplicate ids, and
  unsupported versions) and a CEL-based evaluator
  (`engine.rs`: `CompiledPolicy::evaluate`) that maps an `Action` to a `Decision`
  as a pure function of (action, context, policy) — no LLM, no I/O (ADR-0003).
  Implements most-restrictive-wins, cap escalation (over-cap → at least `ask`),
  the mandatory restrictive default, and a fail-safe `rule_matches` (only
  `Bool(true)` matches; errors/non-bools never grant access). Covered by
  golden-style + validation tests; a regression guard compiles the shipped
  `policies/default/personal-assistant.toml`.
- **`guardian-audit` tamper-evident log** (ROADMAP Task 6.2) —
  [`crates/guardian-audit`](../crates/guardian-audit),
  [arch doc](architecture/guardian-audit.md). Append-only, blake3 hash-chained
  SQLite log (`AuditLog::append`/`verify`) detecting content edits, reordering,
  middle deletion, and tail truncation (via a recorded chain head). An ed25519
  head signature is left behind the `signing` feature for later.
- **`guardian-checker` advisory translator** (ROADMAP Task 6.3) —
  [`crates/guardian-checker`](../crates/guardian-checker),
  [arch doc](architecture/guardian-checker.md). Async, object-safe `Checker`
  trait returning an `Explanation` (plain text + advisory risk); cannot produce a
  `Decision` (the crate has no dependency on it). Ships a deterministic offline
  `StubChecker`.
- **Review fixes to `guardian-policy`**: caps now fail safe (string-encoded
  amounts handled, and an unverifiable cap escalates to `ask`), `deny_unknown_fields`
  rejects typo'd policy keys, and added `count_max` + serialized-name guard tests.
- **`guardian-mcp-gateway` mediation gateway** (ROADMAP Task 6.4) —
  [`crates/guardian-mcp-gateway`](../crates/guardian-mcp-gateway),
  [arch doc](architecture/guardian-mcp-gateway.md). Normalizes a `ToolCall` into an
  `Action`, evaluates it, records the decision to the audit log, and forwards or
  blocks via the `Upstream`/`Approver` ports. The Checker and human approval run
  **only** for `ask` — the allow/deny fast path makes no LLM call (test-enforced
  with a `PanicChecker`). The MCP/JSON-RPC wire transport plugs in on top next.
- **`guardian` CLI** (ROADMAP Task 6.7, partial) — first runnable binary. `demo`
  runs a scripted scenario end to end (green allow, yellow review+approve, red
  block, unknown→default ask), printing the traffic light and an integrity-checked
  audit log; `policy-validate` compiles a policy file.
- **`guardian-daemon` approval-queue backbone** (ROADMAP Task 6.5) —
  [`crates/guardian-daemon`](../crates/guardian-daemon),
  [arch doc](architecture/guardian-daemon.md). The human-in-the-loop
  `ApprovalQueue` + `QueueApprover`: an `ask` decision enqueues a `PendingApproval`
  and awaits the user's response via `pending()`/`respond()`, **failing closed**
  (Denied) on timeout. A Unix-socket control server (`serve`) exposes
  `call`/`pending`/`respond`/`verify_audit` over newline-delimited JSON, handling
  connections concurrently so a blocked `ask` never blocks a `respond`; the
  `guardian-daemon` binary runs it (`GUARDIAN_SOCK` overrides the path). Verified
  live over the socket and by socket integration tests. Added a `DaemonClient`
  (control-socket client used by the CLI/UI).
- **MCP transport** (ROADMAP Task 6.4, last mile) — `guardian_mcp_gateway::mcp`:
  a JSON-RPC 2.0 MCP server over stdio (`McpServer`) fronting the gateway
  (`initialize`/`tools/list`/`ping`/`tools/call`), so a real MCP client is
  mediated by the policy engine. `Allow` → tool result, `Deny` → JSON-RPC error
  (`-32000`), upstream failure → `isError: true`. The `guardian mcp` CLI command
  runs it; verified live by piping a JSON-RPC session.
- **Desktop UI scaffold** (ROADMAP Task 6.6) — [`ui/`](../ui): a Tauri v2 app whose
  backend exposes `pending`/`respond` commands bridging to the daemon socket via
  `DaemonClient`, with a static traffic-light frontend (polls pending; Allow/Deny).
  No business logic in the UI. Its own cargo workspace, excluded from the main one.
  Compiles with `cargo build` on macOS (placeholder RGBA icon); the static frontend
  is themed to match the TUI (no emoji: bright green/red + dark-green accents, ASCII
  risk bars). Running the window still needs a display; the `DaemonClient` bridge it
  relies on is tested in `guardian-daemon`.
- **Evaluation tooling** (`evaluation/`) — `guardian eval` runs an internal
  red-team suite (labeled actions → confusion matrix; release gate: **0 critical
  false negatives**) and prints a scorecard; on the current 14-case suite:
  precision/recall 100%, FP rate 0%. `guardian decide` returns the policy verdict
  for a tool-call JSON **without executing** — the integration point for the
  AgentDojo shim. Gateway `build_action` exposed for shared classification.
- **End-to-end loop wiring** (ROADMAP Tasks 6.4/6.5) — a `ToolRouter` abstraction
  lets the MCP server front either the in-process gateway or a remote daemon.
  `guardian mcp --daemon <socket>` bridges an MCP client to a running daemon, so
  `ask` decisions reach the daemon's approval queue (and the UI); adds
  `DaemonRouter` + `DaemonClient.call` and a real `LocalToolsUpstream` (actual file
  read/write) replacing the echo. Demonstrated live for both allow and
  ask→approve: MCP client → bridge → daemon → policy → human approval → real
  execution → result.
- **AgentDojo integration** (`evaluation/agentdojo/`) — a `GuardianDefense`
  pipeline element that consults `guardian decide` before each tool call and drops
  denied ones, plus an A/B runner (`run_eval.py`) measuring ASR reduction (with vs.
  without Guardian) on the AgentDojo prompt-injection benchmark. Python; runs with
  an API or local OpenAI-compatible model. Not run in CI (needs the AgentDojo
  package + a model); the integration logic is syntax-checked.
- **AgentDojo defense, token-efficient blocking** (`evaluation/agentdojo/`) — on a
  fully-denied round `GuardianDefense` now returns the policy *reason* as a `tool`
  result (a well-formed answer to the call, so the `ToolsExecutor` executes
  nothing and the denied action never runs) instead of silently dropping the call.
  The agent gets explicit feedback and may try a *compliant* alternative for up to
  `--max-retries` (default 3) blocks per episode, after which the feedback becomes
  a hard stop; `run_eval.py` also caps the tool loop (`--max-iters`, default 10).
  This eliminates the retry loop that ballooned denied episodes (≈18-21 → 7-11
  messages) and wasted the model's tokens — the policy still decides every attempt
  (the reason explains the constraint, never a bypass), so the security guarantee
  is unchanged. Logic covered by an offline test of the feedback + retry budget.
- **Terminal cockpit `guardian ui`** (ROADMAP Task 6.6, primary UI) — a ratatui
  TUI (no emoji, ASCII-styled, keyboard + mouse) that polls the daemon's pending
  queue and relays allow/deny over the socket: a traffic-light list with ASCII
  risk bars, selectable cards, `[A]llow`/`[D]eny` (click or key), `p` panic
  (deny-all pending), a live spinner, and an "all clear" empty state. Thin client
  of `DaemonClient` — no business logic in the UI. Theme: bright green
  (`#2EE66B`) = confirm / low risk, bright red (`#FF4646`) = deny / high risk /
  errors, dark-green (`#206040`) accents. Verified by headless render tests
  (ratatui `TestBackend`). `guardian ui --demo` previews the cockpit with sample
  actions and no daemon. (The Tauri window in `ui/` remains the later GUI.)

### Added
- Docs: `testing-with-claude-code.md` (live-test guide), `owasp-nist-coverage.md`
  (framework coverage matrix), and `architecture/guardian-cli.md` (CLI + TUI).
- Founding design documents: `README.md` (spec), `ROADMAP.md` (build plan with
  reusable implementation prompts), `CLAUDE.md` (always-loaded context and
  invariants).
- `evaluation/README.md` — benchmarking plan (AgentDojo, InjecAgent, ASB,
  AgentHarm, τ-bench) for measuring "agent + Guardian vs agent alone".
- Subagents in `.claude/agents/`: rust-implementer, code-reviewer,
  security-auditor, test-engineer, ui-ux-designer, doc-writer.
- Governance: `LICENSE` (Apache-2.0), `SECURITY.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, `.gitignore`.
- Architecture Decision Records: ADR-0001 (Rust over C), ADR-0002 (act at the
  harness/tool boundary, not the OS kernel), ADR-0003 (deterministic enforcement;
  the LLM Checker is advisory only).
- `docs/threat-model.md` and `docs/policy-schema.md` specs.
- Default policy pack `policies/default/personal-assistant.toml`.

### Changed
- Project renamed from the codename **Sentinel** to **Guardian** (to avoid the
  HashiCorp Sentinel / Microsoft Sentinel naming collision). Crate prefix
  `guardian-*`, CLI `guardian`.
- Spec extended with self-protection (§5.8), kill switch (§5.9), configuration &
  first-run defaults (§5.10), data/storage/privacy (§5.11), and localization
  (§5.12); threat model gained an "agent disables its guardian" row.

### Notes
- First code has landed: Phase 0 (workspace scaffold) plus `guardian-core` and
  `guardian-policy` (see Implemented above). Next up: wiring the engine into an
  adapter and the audit log (`guardian-audit`).
