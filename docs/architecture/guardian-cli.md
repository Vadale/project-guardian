# guardian-cli

The `guardian` command-line interface and the terminal cockpit (TUI). A thin
front-end over the other crates — no policy logic of its own.

## Subcommands
- **`demo`** — runs a scripted scenario through the in-process gateway and prints
  the traffic-light decisions (green allow, yellow review+approve, red block). No
  setup needed; uses an embedded demo policy + an auto-approver + a stub upstream.
- **`policy-validate <path>`** — parses, validates, and compiles a policy file;
  non-zero exit on error. Handy in CI.
- **`eval`** — runs the internal red-team suite (labeled actions → confusion
  matrix) and prints a scorecard; the release gate is **0 critical false
  negatives**. Deterministic, no model. (Source: `src/eval.rs`.)
- **`decide [--policy <path>]`** — reads a tool-call JSON on stdin and prints the
  policy decision (`allow`/`ask`/`deny` + reason + critical + matched rule)
  **without executing**. The integration point for external evaluators (the
  AgentDojo shim).
- **`hook [--policy <path>]`** — the **Claude Code `PreToolUse` hook adapter**.
  Reads the hook payload on stdin (`tool_name` + `tool_input`) and prints the
  `hookSpecificOutput` permission decision (`allow`/`ask`/`deny`) so Guardian
  mediates Claude Code's **native** tools. Maps each tool to a Guardian `Action`
  (Read/Glob/Grep → `FileRead`, Write/Edit → `FileWrite`, Bash → `Exec` with the
  command in `args.cmd`, WebFetch → `HttpRequest` with the host from the URL);
  unrecognized/MCP/internal tools carry no hint and hit the restrictive default.
  Always exits 0 with a decision and **never fails open** — a parse error or an
  unreadable policy degrades to `ask`, never a silent `allow`. See
  [testing-with-claude-code.md](../testing-with-claude-code.md) for wiring it up.
- **`mcp [--daemon <socket>] [--upstream "[label=]<cmd>"]… [--policy <path>]`** —
  runs Guardian as an MCP server over stdio. `--upstream` is **repeatable**: it
  **proxies** one or more real MCP servers (spawns them, aggregates and namespaces
  their tools `label__tool`, mediates every call; the policy `[tools]` map provides
  trusted classification, otherwise `ask`/`deny`). Combining `--upstream` **and**
  `--daemon` routes the proxy's `ask`s to that daemon's cockpit for human approval
  (`DaemonApprover`) — the proxy keeps owning the upstream. With `--daemon` alone,
  bridges to a running daemon (`DaemonRouter`). With neither, a self-contained
  gateway over the built-in tools whose `ask` decisions fail closed.
- **`log [--audit <path>] [--limit N]`** — a read-only browser for the tamper-evident
  audit log (the "black box"): prints the integrity status (`verify()` → OK/TAMPERED),
  the entry count, and a table of recent decisions. Resilient to a corrupt row
  (renders `<unreadable>`); never modifies the log.
- **`proxy [--listen <addr>] [--policy] [--secrets] [--audit] [--ca-dir] [--daemon] [--print-ca-path]`**
  — the user-space HTTP(S) forward proxy (Phase 2). Point the agent's
  `HTTP_PROXY`/`HTTPS_PROXY` at it; mediates web traffic with the same policy +
  token broker, generates/uses a local CA for HTTPS interception (`--print-ca-path`
  shows the cert to install). `--daemon <socket>` routes `ask` decisions to that
  daemon's cockpit for human approval (else `ask` fails closed). Backed by
  `guardian-proxy`.
- **`exec [--policy] [--audit] [--allow-network] [--writable <path>] -- <cmd> …`** —
  decide an `exec`-class command against the policy and, if allowed, run it —
  **sandboxed** (network/FS restricted) when the matched rule sets `sandbox = true`
  (`guardian-sandbox`). Refuses on deny/ask (exit 126); fails closed if a sandbox is
  required but no backend is installed.
- **`ui [--daemon <socket>] [--demo]`** — the terminal cockpit (see below).

## Terminal cockpit (`src/tui.rs`)
A `ratatui` TUI: a `DaemonClient` polls the daemon's pending queue and relays the
user's allow/deny over the socket. No business logic — it renders state and sends
decisions.
- Keyboard (`j/k` select, `a` allow, `d` deny, `p` panic = deny-all, `r` refresh,
  `q` quit) **and** mouse clicks on the `[A Allow]` / `[D Deny]` buttons
  (hit-tested against recorded button rects).
- Theme (no emoji): bright green `#2EE66B` = confirm / low risk, bright red
  `#FF4646` = deny / high risk / errors, dark-green `#206040` accents; ASCII risk
  bars; live spinner; "all clear" empty state.
- `--demo` seeds sample actions and never contacts a daemon (a preview).
- Verified by headless render tests (ratatui `TestBackend`), including a check
  that the theme colors are present in the rendered buffer.

## Dependencies
`guardian-core`, `guardian-policy`, `guardian-checker`, `guardian-audit`,
`guardian-mcp-gateway`, `guardian-daemon` (for `DaemonClient`/`DaemonRouter`),
`clap`, `ratatui`/`crossterm`, `tokio`. `#![forbid(unsafe_code)]`.
