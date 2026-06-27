# Guardian — user guide

How to run Guardian in front of an AI agent, end to end. Guardian mediates every
action an agent takes (tool calls, shell, web) against a **deterministic policy**,
injects credentials the agent never sees, and records every decision to a
**tamper-evident audit log**.

## Build

```sh
cargo build --release          # the `guardian` binary lands in target/release/
```

(One-time, for HTTPS interception you'll later trust a local CA — see below.)

## Pick how the agent is mediated

Guardian guards at three boundaries; use whichever your agent hits (or several). See
[integrations.md](./integrations.md) for the full matrix.

### A) The agent makes web requests → the network proxy
The flagship case: let the agent *read* a private site with a token Guardian holds,
and block anything that changes state.

```sh
# 1) store the site's token in the OS keychain (agent never sees it)
printf %s "$TOKEN" | guardian broker set account.example-bank.test

# 2) trust the local CA once (HTTPS interception). Warns + asks the OS to authorize.
guardian proxy --install-ca

# 3) run the proxy with your policy, sourcing the secret from the keychain
guardian proxy --listen 127.0.0.1:8080 \
  --policy   examples/proxy/web-policy.toml \
  --keychain account.example-bank.test \
  --caveats  examples/proxy/caveats.example.toml      # optional least-privilege limits

# 4) point the agent at it
export HTTP_PROXY=http://127.0.0.1:8080 HTTPS_PROXY=http://127.0.0.1:8080
# launch your agent in this environment
```

Now a `GET` to the authorized host is forwarded with the token attached; a `POST`
(transfer/payment) is blocked; an outbound body that contains one of your secrets is
blocked as exfiltration; an un-allow-listed host gets no tunnel at all.

### B) The agent uses MCP tools → the MCP gateway
```sh
guardian mcp --upstream "files=/path/to/real-mcp-server" --policy my-policy.toml
```
Point your MCP host (Cursor, Claude Desktop, a custom agent) at `guardian mcp …`
instead of the real server. Add `--daemon <socket>` to route `ask` to the cockpit.

### C) Claude Code's native tools → the hook
See [testing-with-claude-code.md](./testing-with-claude-code.md).

### Shell commands → sandboxed exec (optional)
```sh
guardian exec --policy my-policy.toml -- some-command --flag   # runs sandboxed if the rule says so
```

## Review what happened
```sh
guardian log                       # recent decisions + integrity status
guardian log --verify-key <hex>    # also verify the head signature of a signed log
guardian report                    # counts, blocked threats, and suggestions to confirm
```

## Approvals (the yellow path)
For `ask` decisions, run the daemon + cockpit and pass `--daemon <socket>` to the
proxy/mcp; you approve or deny each pending action in the terminal cockpit
(`guardian ui`). Without a cockpit, `ask` fails closed (blocked).

## Sharing policy safely (signed packs)
```sh
guardian pack sign   my-pack/ --name my-pack --version 1.0 --key-file ~/.guardian/pack.key
guardian pack verify my-pack/ --pubkey <publisher-hex>
```
A pack can never silently widen a critical category (money / credential /
exfiltration / deletion) — that needs an explicit opt-in. See
[../examples/packs/](../examples/packs/).

## Writing policy
See [policy-authoring.md](./policy-authoring.md) (practical guide) and
[policy-schema.md](./policy-schema.md) (the authoritative schema).

## Hardening & performance
See [hardening.md](./hardening.md): no `unsafe` we own, the green fast path never
calls the LLM (~3.9 µs/decision), the audit log can be sealed with a signing key.
