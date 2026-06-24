# CLAUDE.md — Project Guardian

This is the always-loaded context. It is the distilled essentials so the full
`README.md` and `ROADMAP.md` do **not** need re-reading every session. Read those
two only when you need depth on a specific area (pointers below).

## What this project is
**Guardian** is an open-source, agent-agnostic, user-space "AI guardian firewall."
It sits between an autonomous AI agent and the world (files, shell, network,
online services), intercepts every action **as a structured action at the
harness / tool-call / MCP boundary**, and enforces a **deterministic** policy
(allow / ask / deny). A separate "Checker" model only *translates and risk-scores*
pending actions into plain language — it never decides. Local-first, tamper-evident.

**Status:** design complete (`README.md`, `ROADMAP.md`); no code yet. Next step =
Phase 0 scaffold (ROADMAP Task 0.1/0.2) then the action model (Task 4.1).

## Where the detail lives (don't duplicate it here)
- `README.md` — full spec, design principles, the OS-vs-harness decision (§4),
  architecture (§5), feature set (§6), **threat model (§7)**, **policy schema (§8)**.
- `ROADMAP.md` — tech-stack & crate list (§1), repo layout (§2), the
  **Conventions preamble** (§3), phased plan with **reusable implementation
  prompts** (§4–§9), milestones (§10), cross-cutting gates (§11).
- `evaluation/README.md` — how we benchmark "agent + Guardian vs agent alone"
  (AgentDojo, InjecAgent, ASB, AgentHarm, τ-bench); metrics and the scorecard.
- `docs/` — code-explanation docs (per crate/module: how it works + recent
  changes), `docs/changelog.md`, living threat model, policy-schema spec, ADRs.
  Maintained by the `doc-writer` agent on every code change (see orchestration).

## Hard invariants (never violate — these are test-enforced gates)
1. **No LLM on any allow/deny path.** Enforcement is the deterministic policy
   engine. The Checker translates/risk-scores only and can never unlock.
2. **Evaluate structured actions, not the agent's prose.** The agent's claims are
   manipulable (prompt injection); the intercepted action is not.
3. **`guardian-core` does no I/O and has no internal deps. Deps stay acyclic.**
4. **Critical categories** (money movement, credential access, data exfiltration,
   irreversible deletion) are never auto-downgraded by adaptive learning.
5. **Fail closed on the critical path; fail open (log + defer) on convenience.**
6. **User-space only.** No kernel modules, no entitlement-gated OS hooks. OS
   sandbox / network proxy are off-the-shelf backstops, not the primary control.
7. **Tamper-evident audit log** (append-only, hash-chained) for every decision.

## Conventions
- **Language:** all artifacts — files, code, comments, identifiers, commit
  messages, docs — in **English**. Chat with the user (Alessandro) in **Italian**.
- **Language stack:** Rust (decided, ADR-0001; not C — see ROADMAP §0). Cargo
  workspace. UI in TypeScript via Tauri v2.
- **Quality bar before claiming done:** `cargo fmt --check`, `cargo clippy
  -D warnings`, `cargo nextest run`, `cargo deny check` all green. Every new
  rule/decision path gets golden (`insta`) + adversarial (`proptest`) tests.
- **`unsafe`** only inside clearly-marked, reviewed FFI modules.
- **Simplicity is a feature.** Prefer the simplest code that is correct: small
  pure functions, clear names, no speculative abstraction, no cleverness. Low
  complexity is not cosmetic — it is what lets us (and a non-expert reader) keep
  moving without getting stuck, and it is what makes a security tool auditable.
  If a reviewer can't quickly understand a decision path, that is a bug.
- Don't commit or push unless the user asks. Branch before committing.

## Repo layout (crates)
```
crates/guardian-core        # action model, Decision, context — NO I/O, no internal deps
crates/guardian-policy      # schema, loader, deterministic CEL evaluator (the boundary)
crates/guardian-audit       # hash-chained tamper-evident log
crates/guardian-checker     # pluggable LLM translator/risk-scorer (advisory only)
crates/guardian-mcp-gateway # MCP proxy adapter (primary interception)
crates/guardian-proxy       # HTTP(S) MITM forward proxy (Phase 2)
crates/guardian-broker      # identity & token broker (Phase 3)
crates/guardian-daemon      # long-running service wiring it together
crates/guardian-cli         # `guardian` CLI
ui/                         # Tauri v2 app
policies/  tests/  docs/
```

## Key tech (quick ref — full list in ROADMAP §1)
tokio · serde/serde_json · rmcp (MCP; fallback jsonrpsee) · axum/tower/hyper ·
reqwest · hudsucker+rustls+rcgen (proxy) · cel-interpreter (policy) ·
rusqlite+blake3+ed25519-dalek (audit) · keyring/oauth2/macaroon/ssi (broker) ·
clap · tracing · thiserror/anyhow · insta/proptest/wiremock · Tauri v2.

## Subagents (in `.claude/agents/`)
Delegate focused work to these. Spawn only when the user asks or the task clearly
matches; otherwise handle inline.

| Agent | Use it for |
|---|---|
| `rust-implementer` | Implementing ROADMAP tasks in Rust, following the reusable prompts and invariants. |
| `code-reviewer` | Reviewing a diff for correctness bugs and invariant violations. Review-only. |
| `security-auditor` | Threat-model alignment, `unsafe`/supply-chain audit, attack-surface review. Read-only. |
| `test-engineer` | Writing/maintaining golden + adversarial tests and the E2E scenario. |
| `ui-ux-designer` | The Tauri approval UI and the non-technical-user traffic-light UX. |
| `doc-writer` | README/ROADMAP/docs/ADRs; keeping the docs consistent with the code. |

**Recommended later (not yet created):** `policy-author` — a specialist for
writing/validating signed community policy packs (CEL rules + golden tests),
which becomes a recurring task from Phase 3. Add it when policy-pack work starts.
And `eval-engineer` — if the benchmark harnessing in `evaluation/` outgrows the
`test-engineer`.

## Agent orchestration — when to launch each agent
The main agent (you) spawns a subagent when the task clearly matches one or the
user asks. These are the standing rules:

- **After writing or changing ANY code → always run `doc-writer`** before the task
  is considered done. It updates `docs/` with how the new/changed code works and
  appends a `docs/changelog.md` entry. This is mandatory, not optional.
- **Implementing a ROADMAP task →** `rust-implementer` (or inline), with tests
  from `test-engineer` for any new rule/decision path.
- **Before merging a feature / at milestone boundaries →** `code-reviewer`, then
  `security-auditor` (both read-only; they report, they don't fix).
- **Touching the UI →** `ui-ux-designer`.
- **At milestone gates →** run the `evaluation/` suite (owned by `test-engineer`)
  and publish the scorecard.
- **At the end of every big step / milestone → do a simplify & cleanup pass**
  before moving on (the `/simplify` skill, or `code-reviewer` for the cleanup
  view). Reduce complexity, remove dead code and accidental abstraction, unify
  duplication, and make the decision paths obvious. Why: simpler code lets us keep
  advancing without piling up problems, stays understandable to both of us, and
  keeps the security-critical paths auditable. Never let complexity accumulate
  across steps — pay it down each time, not "later".

> To make "doc-writer on every code change" *enforced* rather than convention,
> add a settings.json `PostToolUse`/`Stop` hook later — ask the user first.
