# guardian-daemon

The long-running service backbone (ROADMAP Task 6.5): the human-in-the-loop
approval queue plus a Unix-socket control server, wired into a runnable binary
(`guardian-daemon`).

## What it does
Provides the human-in-the-loop **approval queue** that resolves the gateway's
`ask` decisions. When the gateway needs human review it calls a `QueueApprover`,
which enqueues the request and awaits the user's response — **failing closed**
(Denied) if no response arrives in time.

## Persistence (audit)
The binary opens a **persistent** tamper-evident audit log at `GUARDIAN_AUDIT`
(default `~/.guardian/audit.db`): the blake3 hash chain continues across restarts,
and the daemon **verifies it on startup, refusing to start (fail closed) if the
chain is broken/tampered**. (ed25519 head signing is a follow-up.)

## Public API
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
`serve(path, gateway, queue)` runs a Unix-socket server speaking
**newline-delimited JSON**. One request object per line; one response per line.
Each connection is handled in its own task, so a `call` blocked on approval never
prevents a `respond` on another connection from resolving it.

Requests (`{"cmd": ...}`): `call` (tool/args/kind?/capability?), `pending`,
`respond` (id, approve), `approve` (action_id?/tool/plain_text?/risk? — enqueue an
approval and block until the cockpit resolves it; used by an external proxy to
borrow this daemon's queue + cockpit), `verify_audit`. Responses (`{"result":
...}`): `outcome` (status allowed/blocked/upstream_error + detail), `pending`
(items), `responded` (ok), `approval` (approved), `audit` (entries, intact),
`error` (message). `GUARDIAN_SOCK` overrides the socket path. Unix-only for now;
Windows named-pipe support is a follow-up.

## Tests
Unit: approve, deny, fail-closed timeout, unknown-id, `QueueApprover` routing.
Socket integration (real Unix sockets, concurrent connections): allow forwards,
deny blocks, `verify_audit`, and the full ask → `pending` → `respond` → allowed
round-trip.

## Scope / next
The CLI and the Tauri UI become clients of this socket (`pending`/`respond` for
the approval surface, `call` for driving tools). A real MCP upstream replaces the
binary's placeholder echo upstream.
