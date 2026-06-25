# Running Guardian in front of Claude Code

This wires Guardian's `PreToolUse` hook so Claude Code's **native** tools (Bash,
Edit, Write, Read, WebFetch, …) are mediated by the deterministic policy.

## Setup
1. Build the binary:
   ```sh
   cargo build -p guardian-cli
   ```
2. Edit [`settings.json`](settings.json): replace every `/ABS/PATH` with the
   absolute path to this repository.
3. Copy its contents into your Claude Code settings — either global
   (`~/.claude/settings.json`) or per-project (`.claude/settings.json`).

## What happens
For each tool call, Claude Code runs `guardian hook`, which classifies the call
and asks the policy ([`coding-agent.toml`](../../policies/default/coding-agent.toml)):

| Tool / action | Decision |
|---|---|
| `Read`, `Glob`, `Grep` (file reads) | **allow** (silent) |
| `Write`, `Edit` (file writes) | **ask** (Claude Code prompts you) |
| `Bash` (shell) | **ask** |
| `Bash` with `rm -rf /`, pipe-to-shell, fork bomb, `mkfs`, … | **deny** (blocked) |
| `WebFetch` to a non-trusted host | **ask** |

It **never fails open**: if the hook can't parse the call or load the policy, it
returns `ask`, so nothing runs without you.

## Customize
Edit `coding-agent.toml` (or point `--policy` at your own). Validate it with:
```sh
guardian policy-validate policies/default/coding-agent.toml
```

## See also
- [`docs/testing-with-claude-code.md`](../../docs/testing-with-claude-code.md) —
  the fuller guide, including the MCP path (cockpit UI + real execution via the
  daemon) which mediates Guardian's *own* tools.
