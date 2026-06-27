# guardian-sandbox

The **OS sandbox backstop** (ROADMAP §7.3). When the policy marks an `exec`-class
action `sandbox = true`, Guardian runs the command **contained** instead of directly.
This is the off-the-shelf containment invariant 6 calls for — a backstop, not the
primary control (the policy engine is). **No custom kernel code**: it shells out to a
maintained OS sandbox tool.

A dependency-free crate (only `std`): it just *builds and runs* a wrapped command;
the allow/deny decision stays in the policy engine.

## API
- **`SandboxOpts { allow_network, writable_paths }`** — what to permit beyond the
  restrictive default. Default: **network denied, filesystem read-only except temp**.
- **`SandboxRunner`** trait:
  - `wrap(program, args, opts) -> Command` — builds the exact argv (the sandbox tool
    + its flags + the target command). **Pure**, so the argv is unit-tested without a
    real sandbox installed.
  - `run(program, args, opts) -> io::Result<ExitStatus>` — runs it to completion.
- **`detect() -> Option<Box<dyn SandboxRunner>>`** — the platform backend if its tool
  is on `PATH`, else `None`. `None` means **no containment available** → the caller
  must **fail closed** for a sandboxed action (never run it unconfined).

## Backends (and what they actually contain)
- **macOS — `MacosSeatbelt`** via `sandbox-exec -p <profile>`. SBPL is
  permissive-then-restrict (last match wins): `(allow default)`, then `(deny network*)`
  (unless `allow_network`), then `(deny file-write*)` re-allowing temp and each
  `writable_paths` entry. **Scope:** this denies **network + filesystem writes only**.
  Reads, `process-exec`, mach lookups and IPC remain allowed — it is **not**
  process/IPC isolation. (Tracked: harden to a deny-by-default profile.)
- **Linux — `Bubblewrap`** via `bwrap`: read-only root (`--ro-bind / /`), private
  `/dev` + `/proc`, writable `/tmp` (tmpfs), `--die-with-parent`, `--unshare-net`
  (unless `allow_network`), and `--bind <p> <p>` for each writable path. **Stronger
  than macOS** (filesystem + network-namespace isolation), but still shares the host
  PID/IPC namespaces and sets no resource limits (tracked).

The two backends are **not equivalent in strength** — see `docs/threat-model.md` §6
for the residual risks. The sandbox is a backstop; the policy engine is the control.

`SandboxOpts` widening (`allow_network`, `writable_paths`) is supplied by the
**caller/operator**, not the agent (the agent only provides the command). The
`guardian exec` `--allow-network`/`--writable` flags are operator inputs.

`detect()` uses `cfg!(...)` (not `#[cfg]`) so both impls compile on every platform and
are exercised by the unit tests; only the matching platform's tool is ever selected.
Windows AppContainer and a `docker` fallback are tracked for later.

## How it's used
`guardian exec [--policy] [--audit] [--allow-network] [--writable <path>] -- <cmd> …`:
builds the `Exec` action, evaluates the **deterministic policy**, **records the
decision to the audit log**, then refuses on deny/ask (exit 126) or runs the command —
**sandboxed when the matched rule set `sandbox = true`**. If a sandbox is required but
no backend exists, it fails closed.

## Dependencies
None (std only). `#![forbid(unsafe_code)]`.
