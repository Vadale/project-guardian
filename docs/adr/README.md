# Architecture Decision Records (ADRs)

An ADR captures a significant architectural decision: its **context**, the
**decision**, and its **consequences**. ADRs are immutable once accepted — if a
decision changes, write a new ADR that supersedes the old one (and mark the old
one `Superseded by ADR-XXXX`).

Each ADR uses this structure: Status · Context · Decision · Consequences ·
Alternatives considered.

## Index
| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-rust-over-c.md) | Implementation language: Rust, not C | Accepted |
| [0002](0002-act-at-harness-boundary.md) | Act at the harness/tool boundary, not the OS kernel | Accepted |
| [0003](0003-deterministic-enforcement.md) | Deterministic enforcement; the LLM Checker is advisory only | Accepted |
