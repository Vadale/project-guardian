# Testing Guardian with Claude Code

How to put Guardian in front of a real agent (Claude Code) and watch it mediate
tool calls live, approving/denying from the cockpit.

> **Read this first — what is and isn't mediated today.** Claude Code can use
> Guardian in two ways:
>
> 1. **As an MCP server (works now).** Claude Code calls the tools *Guardian
>    exposes over MCP* (`read_file`, `write_file`, `http_request`, …) and those go
>    through the policy. It does **not** intercept Claude Code's *own built-in*
>    tools (its native `Bash`, `Edit`, `Read`, …) — those bypass Guardian.
> 2. **Via a `PreToolUse` hook (planned, the fuller path).** A small adapter that
>    Claude Code runs before each tool call, which asks `guardian decide` and
>    allows/denies — this mediates Claude Code's **native** tools too. Not built
>    yet; see ROADMAP.
>
> So today's live test exercises the loop and the UI for **Guardian's MCP tools**.
> Full coverage of native tools arrives with the hook adapter.

## Prerequisites
- Build the binaries: `cargo build -p guardian-cli -p guardian-daemon`.
- Pick a socket path and use it everywhere, e.g. `export GUARDIAN_SOCK=/tmp/g.sock`.

## The three pieces (three terminals)

**1 — the daemon** (owns policy + the approval queue + audit + the upstream):
```sh
GUARDIAN_SOCK=/tmp/g.sock cargo run -p guardian-daemon
```

**2 — the cockpit** (where you approve/deny). Either the terminal UI:
```sh
GUARDIAN_SOCK=/tmp/g.sock cargo run -p guardian-cli -- ui
```
or the desktop window (after `cargo build` of the Tauri app):
```sh
GUARDIAN_SOCK=/tmp/g.sock ./ui/src-tauri/target/debug/guardian-ui
```

**3 — Claude Code**, configured to use Guardian's MCP server. Register it
(use the absolute path to the built binary):
```sh
claude mcp add guardian -- /ABS/PATH/target/debug/guardian mcp --daemon /tmp/g.sock
```
or add it to a project `.mcp.json`:
```json
{
  "mcpServers": {
    "guardian": {
      "command": "/ABS/PATH/target/debug/guardian",
      "args": ["mcp", "--daemon", "/tmp/g.sock"]
    }
  }
}
```

## What you'll see
Ask Claude Code to use one of Guardian's tools, e.g. *"use the write_file tool to
create ~/notes/todo.md"*. The flow:
1. Claude Code calls `write_file` via the Guardian MCP server.
2. The daemon evaluates it. `write_file` is an `ask` → it's enqueued.
3. The action appears in the cockpit with a plain-language explanation and a risk
   badge. You **Allow** or **Deny**.
4. On Allow it executes (the upstream really writes the file) and the result goes
   back to Claude Code. On Deny, Claude Code gets a "blocked" error.

`read_file` under your home → allowed silently (green). A `deny`-class action →
blocked automatically (red) without a prompt.

## Troubleshooting
- **Nothing appears in the cockpit:** check that all three use the *same*
  `GUARDIAN_SOCK`, and that the daemon started before the UI/Claude Code.
- **`guardian mcp` exits immediately:** it speaks MCP over stdio and is meant to be
  launched *by* an MCP client, not run by hand. To poke it manually, pipe JSON-RPC:
  `printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | guardian mcp --daemon /tmp/g.sock`.
- **An `ask` never resolves:** the daemon fails closed after a timeout (denies).
  Approve promptly in the cockpit.
- **Tweak what's allowed/denied:** point the daemon at a different policy (the
  daemon currently loads the default pack; edit `policies/default/personal-assistant.toml`
  or pass a custom one when that flag lands).

## Measuring (not just demoing)
For numbers rather than a live demo, use the AgentDojo harness in
[`../evaluation/agentdojo/`](../evaluation/agentdojo/): it runs an agent with and
without Guardian and reports the attack-success-rate delta.
