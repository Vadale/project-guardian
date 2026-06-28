# guardian-daemon

The long-running service backbone (ROADMAP Task 6.5): the human-in-the-loop
approval queue plus a Unix-socket control server, wired into a runnable binary
(`guardian-daemon`).

## What it does
Provides the human-in-the-loop **approval queue** that resolves the gateway's
`ask` decisions. When the gateway needs human review it calls a `QueueApprover`,
which enqueues the request and awaits the user's response — **failing closed**
(Denied) if no response arrives in time.

## Configuration (ROADMAP §9b.2)
The binary is driven by a typed `Config` (`config.rs`), loaded with
`Config::load()` from `GUARDIAN_CONFIG` (default `~/.guardian/config.toml`). All
fields are optional, so a missing or empty config yields safe defaults:

- `socket` — control-socket path (default: temp-dir `guardian.sock`).
- `policy` — policy file (default: the built-in `personal-assistant` pack).
- `audit` — audit-log file (default: `~/.guardian/audit.db`).
- `approval_timeout_secs` — seconds before a pending approval fails closed
  (default: 120).
- `trusted_hosts` — hosts the policy treats as trusted (default: none).

**Per-value precedence: built-in default < config file < `GUARDIAN_*` env var.**
The resolver methods (`socket_path`, `policy_path`, `audit_path`,
`approval_timeout`) overlay the matching env var (`GUARDIAN_SOCK`,
`GUARDIAN_POLICY`, `GUARDIAN_AUDIT`) over the file value, so the env vars stay as
ad-hoc overrides on top of the file.

On **first run** (file absent) `load()` writes a commented default
`config.toml` the user can edit and returns defaults. Parsing is strict
(`#[serde(deny_unknown_fields)]`): a malformed config — bad type or unknown key —
is a `ConfigError` and the daemon **fails closed**, refusing to start rather than
run with a half-understood config.

## Persistence (audit)
The binary opens a **persistent** tamper-evident audit log at the configured audit
path (`GUARDIAN_AUDIT` > config file > `~/.guardian/audit.db`): the blake3 hash
chain continues across restarts, and the daemon **verifies it on startup, refusing
to start (fail closed) if the chain is broken/tampered**. (ed25519 head signing is
a follow-up.)

## Public API
- `Config` + `Config::load()` / `Config::from_path()` and the resolver methods
  (`socket_path`/`policy_path`/`audit_path`/`approval_timeout`) — see Configuration.
- `ApprovalQueue::new(timeout)`.
- `ApprovalQueue::request(action_id, tool, explanation) -> ApprovalResponse` —
  enqueue and await; returns `Denied` on timeout.
- `ApprovalQueue::pending() -> Vec<PendingApproval>` — snapshot for the UI/CLI.
- `ApprovalQueue::respond(id, response) -> bool` — resolve a pending item.
- `QueueApprover::new(Arc<ApprovalQueue>)` — implements the gateway's `Approver`
  port by routing through the queue.
- `PendingApproval { id, action_id, tool, explanation }`.

## Invariants
- **Fail closed:** a timeout (or a dropped responder) resolves to `Denied`, never
  `Approved`.
- `&self` everywhere — share behind an `Arc` across the gateway, the IPC server,
  and the UI bridge. `#![forbid(unsafe_code)]`.
- Built on `tokio` (`oneshot` for the response, `timeout` for the deadline); the
  internal mutex is never held across an `.await`.

## Control socket (IPC)
`serve(path, gateway, queue)` runs a **cross-platform local-socket** server (via the
`interprocess` crate, §9b.3): a **Unix domain socket** on unix (the configured path)
and a **named pipe** on Windows (derived from the socket file name). It speaks
**newline-delimited JSON**. One request object per line; one response per line.
Each connection is handled in its own task, so a `call` blocked on approval never
prevents a `respond` on another connection from resolving it.

Requests (`{"cmd": ...}`): `call` (tool/args/kind?/capability?), `pending`,
`respond` (id, approve), `approve` (action_id?/tool/plain_text?/risk? — enqueue an
approval and block until the cockpit resolves it; used by an external proxy to
borrow this daemon's queue + cockpit), `verify_audit`. Responses (`{"result":
...}`): `outcome` (status allowed/blocked/upstream_error + detail), `pending`
(items), `responded` (ok), `approval` (approved), `audit` (entries, intact),
`error` (message). `GUARDIAN_SOCK` overrides the socket path. Runs on unix **and
Windows** (a Windows CI job exercises the named-pipe path).

## Tests
Unit: approve, deny, fail-closed timeout, unknown-id, `QueueApprover` routing.
Socket integration (real Unix sockets, concurrent connections): allow forwards,
deny blocks, `verify_audit`, and the full ask → `pending` → `respond` → allowed
round-trip.

## Scope / next
The CLI and the Tauri UI become clients of this socket (`pending`/`respond` for
the approval surface, `call` for driving tools). A real MCP upstream replaces the
binary's placeholder echo upstream.
