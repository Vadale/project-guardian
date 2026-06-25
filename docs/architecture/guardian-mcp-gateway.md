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

**Trusted classification (`with_classifier`).** `McpServer` classifies each
`tools/call` via a trusted `tool-name → ActionKind` map. A tool **not** in the map
is `Other` (the restrictive default) — never inferred from its (untrusted) name,
so a proxied/upstream tool cannot fail open to `allow` (cross-cutting gate §11.8).

## MCP proxy: upstream client (`upstream` module)
`upstream::McpStdioUpstream` is a generic MCP **client** over stdio: it spawns a
real MCP server as a child process, does the `initialize`/`notifications/
initialized` handshake, discovers its tools (`tools/list`), and implements
`Upstream` by forwarding `tools/call`s. Requests are serialized (one in flight).
Wiring it as a `Gateway`'s `Upstream` (with the upstream's tools re-advertised and
no classifier) turns the gateway into a real **proxy** — `guardian mcp --upstream
"<command>"`. The upstream's tools are untrusted, so everything is `Other` until
the policy trusts it explicitly.

## Scope
The gateway logic is transport-agnostic; `mcp` (server) and `upstream` (client)
are the stdio transports. **Next:** Streamable HTTP + `rmcp`, and multi-server tool
aggregation with namespacing (ROADMAP §7.5). Tested with a fake upstream (allow
forwards, deny blocks, ask waits, decisions recorded and verified), the MCP
handshake/list/call/deny, the unmapped-tool fail-safe, and `parse_tools`.
`#![forbid(unsafe_code)]`.
