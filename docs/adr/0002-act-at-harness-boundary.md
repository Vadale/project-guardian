# ADR-0002 — Act at the harness/tool boundary, not the OS kernel

**Status:** Accepted (2026-06-24).

## Context
Guardian must mediate everything an autonomous agent does, across macOS, Windows,
and Linux, as a user-space, open-source project. The candidate interception
points were the OS kernel (syscalls, network filters) versus the agent's action
boundary (the harness tool-call / MCP layer).

## Decision
Guardian acts at the **agent's action boundary — the harness / tool-call / MCP
layer — in user-space.** It does **not** install kernel modules or use
entitlement-gated OS hooks. OS sandboxing and a forward proxy are *off-the-shelf
containment backstops*, not the primary control.

## Consequences
- We get **structured actions** (tool name + typed args) instead of guessing
  intent from `write(fd, buf, n)`.
- **Agent-agnostic** for free: the tool boundary looks identical under any model.
- No vendor entitlements, no kernel code, no notarization wall; cross-platform
  parity.
- **Honest limit:** interception is only as complete as the harness's mediation. A
  raw `exec`/shell tool is the hard case. Mitigation (layered): prefer structured
  tools; contain raw exec in an OS sandbox; route all network through the proxy.
- Guardian must be unbypassable from the agent's privileges (see ADR-0003 and
  README §5.8): it is the agent's only path to tools, and fails closed.

## Alternatives considered
- **OS kernel interception** (LSM/eBPF, macOS Endpoint Security & Network
  Extension, Windows minifilter/WFP): rejected — requires vendor-granted
  entitlements + notarization, can crash the host, and exposes the wrong altitude
  (no intent). A non-starter for an indie/community open-source tool.
