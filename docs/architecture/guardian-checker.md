# guardian-checker

The advisory translator/risk-scorer (ROADMAP Task 6.3).

## What it does
Turns a structured `guardian_core::Action` into a plain-language `Explanation`
plus an advisory risk score, for human review of `ask` items.

## Public API
- `Explanation { plain_text: String, risk: u8 /* 0..=100 */, rationale: String }`.
- `trait Checker { async fn explain(&self, action: &Action) -> Explanation }`
  (async via `async-trait`, so it is object-safe — the daemon holds a
  `Box<dyn Checker>`).
- `StubChecker` — a deterministic, offline backend (no model, no network). It is
  the privacy default and the stable backend for tests.
- `HttpChecker` — a model-backed backend: POSTs the action (JSON) to a configured
  HTTP endpoint and parses an `Explanation` back. Suited to a **local** model
  endpoint (http-only, no TLS, to keep the dependency/license surface small).
  Advisory only and infallible: any error (unreachable, non-2xx, bad/oversize JSON)
  degrades to a conservative offline fallback. Bounded by a 10s timeout and a
  256 KB response-body cap. The daemon selects it via `checker_endpoint` /
  `GUARDIAN_CHECKER`; the full action (incl. `args`) is sent to the endpoint, so
  it must be trusted (the daemon warns when it is non-local or `https`).

## Invariants (ADR-0003)
- **Advisory only.** `explain` returns an `Explanation`, never a `Decision`. The
  crate does **not** depend on the `Decision` type, so a Checker *cannot* produce
  or influence an allow/deny outcome — enforced by the compiler, not convention.
- **Infallible to the caller.** A backend that fails returns a conservative
  fallback rather than erroring, so the Checker never blocks or unblocks anything.
- Reads only the structured `Action`, never the agent's natural-language claims.
- `#![forbid(unsafe_code)]`.

## Risk heuristic (StubChecker)
Deterministic base score by `ActionKind` (FileRead 10 … Exec 70, Payment 90),
raised to ≥90 for any critical `Capability`. Advisory only — never gates a
decision.

## Tests
Deterministic output; critical actions score higher than reads; usable as a
`Box<dyn Checker>` trait object.
