# guardian-mcp-gateway

The mediation gateway — the primary interception point (ROADMAP Task 6.4).

## What it does
Mediates one tool call end to end: normalize → evaluate → (for `ask` only)
explain + ask the human → record → forward or block. It ties together the policy
engine, the Checker, and the audit log.

## Public API
- `ToolCall { tool, args, kind?, capability? }` — a tool invocation from a harness.
  `kind`/`capability` are optional hints; absent, a conservative heuristic
  classifies the tool (unknown → `Other` → the restrictive default).
- `trait Upstream { async fn forward(&self, &ToolCall) -> Result<Value, String> }`
  — executes a forwarded call against the real tool/MCP server.
- `trait Approver { async fn request_approval(&self, &Action, &Explanation) -> ApprovalResponse }`
  — resolves an `ask` (implemented by the daemon/UI; must fail closed).
- `Gateway::new(source, policy, checker, approver, upstream, audit, env)`.
- `Gateway::handle(call) -> GatewayOutcome` (`Allowed` | `UpstreamError` | `Blocked`).
- `Gateway::audit_verify()` / `audit_len()`.

## Flow & invariants
1. `normalize` builds an `Action` (assigns an id, lifts `host`/`path` from args so
   policy expressions can use them).
2. The policy engine returns a `Decision`.
3. **Fast-path invariant:** the Checker and Approver are consulted **only** for
   `Ask`. `Allow`/`Deny` make no LLM call and no human round-trip — enforced by a
   test using a `PanicChecker`.
4. The decision (with the rule id, optional rationale, and the user's response) is
   appended to the tamper-evident audit log; a logging hiccup never panics the
   request path.
5. On `Allow` (or an approved `Ask`) the call is forwarded; otherwise it is
   blocked with a reason.

## MCP server (`mcp` module)
`mcp::McpServer` is a JSON-RPC 2.0 MCP server over stdio that fronts a `Gateway`:
`initialize`, `tools/list`, `ping`, and `tools/call`. Each `tools/call` is routed
through the gateway — `Allow` returns the tool result, `Deny` returns a JSON-RPC
error (`-32000`, "Blocked by Guardian: …"), an upstream failure returns a result
with `isError: true`. `serve_stdio()` runs it; `handle_line()` is the testable
core. A real MCP client (any harness) can launch `guardian mcp`.

## Scope
The gateway logic is transport-agnostic; the `mcp` module is the first real
transport. Connecting to a separate downstream MCP server as the `Upstream`
(a true proxy) is a follow-up. Fully tested with a fake upstream (allow forwards,
deny blocks, ask waits, decisions recorded and verified) plus the MCP
handshake/list/call/deny. `#![forbid(unsafe_code)]`.
