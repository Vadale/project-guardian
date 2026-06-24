# ADR-0003 — Deterministic enforcement; the LLM Checker is advisory only

**Status:** Accepted (2026-06-24).

## Context
A natural design is to let an LLM "judge" each action and decide whether it is
safe. But LLMs are probabilistic and, more importantly, **attackable via prompt
injection** — the exact threat Guardian defends against. Benchmarks (e.g.
AgentDojo) show LLM-only guardrails are bypassable.

## Decision
The **security boundary is a deterministic policy engine** that returns exactly
one of `allow` / `ask` / `deny` as a pure function of (structured action, context,
policy). The **LLM Checker is advisory only**: it produces a plain-language
explanation and a risk score for human review. The type system must make it
*impossible* for Checker output to influence an allow/deny outcome.

Corollaries:
- The engine and the Checker evaluate the **structured intercepted action**, never
  the agent's natural-language claims.
- The decision path performs no LLM call and no network I/O; it is fully testable
  and reproducible (golden tests).
- Across all matching rules the **most restrictive** decision wins
  (`deny` > `ask` > `allow`); `critical` actions can never be auto-downgraded.

## Consequences
- Predictable, auditable, fast green-path; the LLM can be wrong or compromised
  without ever unlocking an action.
- The Checker can be a small local model (privacy/latency) and is fully pluggable.
- Cost: writing good deterministic policies is real work (mitigated by the schema,
  default packs, and the community pack ecosystem).

## Alternatives considered
- **LLM-as-judge enforcement:** rejected as the boundary (bypassable, non-
  deterministic). Retained only as the *advisory* translation/risk layer.
