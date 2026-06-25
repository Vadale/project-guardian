# Changelog

All notable changes to Project Guardian are recorded here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); the project uses
[Semantic Versioning](https://semver.org/) from 1.0 onward. Maintained by the
`doc-writer` agent on every change (see `CLAUDE.md`).

## [Unreleased] — design phase

### Implemented — 2026-06-25
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
