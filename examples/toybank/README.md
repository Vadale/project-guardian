# Toy-bank broker demo

A self-contained, local demo of the headline Guardian feature: **the user gives
the agent access to a private service via a token Guardian holds — the agent never
sees the token — and Guardian blocks the dangerous action** (moving money) even if
the agent is tricked or hallucinates.

It uses an MCP "bank" server with two tools — `get_balance` (read) and `transfer`
(move money) — both of which require a token. Guardian proxies it: the **broker**
injects the token only into *allowed* calls, and the **policy** denies `transfer`.

## Run it
Build first: `cargo build -p guardian-cli`. Then (the proxy speaks MCP on stdio, so
pipe JSON-RPC in):

```sh
B=target/debug/guardian
EX=examples/toybank
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"bank__get_balance","arguments":{}}}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"bank__transfer","arguments":{"to":"x","amount":9999}}}' \
| "$B" mcp \
    --upstream "bank=python3 $EX/server.py" \
    --policy   "$EX/bank-policy.toml" \
    --secrets  "$EX/bank-secrets.example.toml"
```

You will see:
- **`get_balance` → `balance: EUR 4242.00`** — Guardian injected the token, the bank
  authorized the read.
- **`transfer` → a JSON-RPC error "Blocked by Guardian"** — the money-movement was
  denied by policy; the bank never received it.

Now drop `--secrets`: `get_balance` comes back **`UNAUTHORIZED`** — proof the token
comes from Guardian's broker, not the agent. And if the agent tries to smuggle its
own `auth_token` in the arguments, the broker **scrubs** it and injects the real one.

## How it maps to the design
- `--secrets` → the **broker** (`guardian-broker`); V1 reads a `target = "token"`
  file. In production these live in the OS keychain with macaroon caveats (Phase 3).
- `--upstream` → the **MCP proxy** (§7.5): one Guardian in front of the bank server.
- `bank-policy.toml` → `get_balance` classified as a read (allowed), `transfer` as
  `Payment` → a **critical** category → denied (never auto-downgraded).
- For real *web* services (not MCP), the same idea needs the network proxy (Phase 2).

> The token in `bank-secrets.example.toml` is fake. Real secret files (`*secrets*.toml`)
> are git-ignored; keep them `chmod 600`.
