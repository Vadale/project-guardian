# Integrations — putting Guardian in front of any agent (§8.6)

Guardian is **agent-agnostic**: it mediates at the **action boundary**, not inside
any one harness. There are three boundaries an agent can be pointed at, and almost
every harness uses at least one:

| Boundary | Guardian piece | Use it for |
|---|---|---|
| **MCP tool calls** | `guardian mcp` (gateway/proxy) | any MCP client/host (Cursor, Claude Desktop, custom MCP agents) |
| **Native tool hook** | `guardian hook` | Claude Code's built-in tools (Bash/Edit/Write/WebFetch…) |
| **Raw HTTP(S)** | `guardian proxy` | any agent that drives the web/an API (browser-use, OpenAI Agents, scripts) |

All three run the **same deterministic policy**, the **same token broker**, and the
**same tamper-evident audit log** — so the guarantees are identical wherever the
agent acts.

## Claude Code (native tools) — `guardian hook`
Mediates Claude Code's own tools. See
[testing-with-claude-code.md](./testing-with-claude-code.md) for the
`PreToolUse` hook wiring. This is the deepest integration (every native tool call is
a decision).

## Generic MCP client / host — `guardian mcp`
Any MCP host (Cursor's MCP support, Claude Desktop, an OpenAI/LangGraph agent using
an MCP client) can launch Guardian as an MCP server that **proxies the real
server(s)**:

```sh
guardian mcp \
  --upstream "files=/path/to/filesystem-mcp-server" \
  --upstream "bank=/path/to/bank-mcp-server" \
  --policy   my-policy.toml \
  --secrets  my-secrets.toml      # or: manage secrets with `guardian broker set`
```

Point the host's MCP config at `guardian mcp …` instead of the real server. Tools are
namespaced `label__tool`; every `tools/call` is mediated, the broker injects
credentials post-allow, and (`--daemon <socket>`) `ask` decisions go to the cockpit.

### Example: Cursor / Claude Desktop MCP config
These hosts read a JSON config listing MCP servers. Replace a server's command with
Guardian wrapping it:

```jsonc
{
  "mcpServers": {
    "files": {
      "command": "guardian",
      "args": ["mcp", "--upstream", "/path/to/filesystem-mcp-server", "--policy", "/path/to/policy.toml"]
    }
  }
}
```

The host now talks to Guardian; Guardian talks to the real server. Nothing else in
the host changes.

## Any HTTP(S) agent (OpenAI Agents runtime, browser tools, scripts) — `guardian proxy`
Agents that call web APIs or drive a browser don't go through MCP — they make HTTP
requests. Put Guardian on the network path and export the proxy env vars:

```sh
guardian proxy --listen 127.0.0.1:8080 --policy web-policy.toml --keychain api.example.com
guardian proxy --install-ca           # one time, for HTTPS interception

export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
# now launch the agent / OpenAI Agents runtime / browser-use tool in that environment
```

Egress is **default-deny** (only allow-listed hosts get a tunnel), the broker injects
the host's credential on allow, request bodies are scanned for your own secrets
(exfiltration), and `ask` can route to the cockpit (`--daemon`). See
[`examples/proxy/`](../examples/proxy/).

## Which one should I use?
- The agent uses **MCP** → `guardian mcp` (mediates the actual tools).
- The agent is **Claude Code** → `guardian hook` (mediates native tools) — and add
  `guardian proxy` if it also drives the web.
- The agent makes **raw HTTP** with no MCP → `guardian proxy`.
- Belt-and-suspenders: run **both** the MCP/hook integration *and* the proxy, so
  tool calls *and* raw network are covered.

## Adding a new adapter
A new harness needs no new Guardian code if it speaks MCP or HTTP — point it at
`guardian mcp` or `guardian proxy`. A harness with a *native* tool-call hook (like
Claude Code's) gets a thin adapter that maps its tool schema to a
`guardian_core::Action` and calls the policy, mirroring `guardian hook`.
