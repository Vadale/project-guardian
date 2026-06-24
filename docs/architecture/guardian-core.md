# `guardian-core` — the action model and decision types

> Source: [`crates/guardian-core/src/lib.rs`](../../crates/guardian-core/src/lib.rs).
> This document describes what the crate *is*, grounded in that source. For the
> rationale see ADR-0002 (act at the harness boundary) and ADR-0003
> (deterministic enforcement).

## What this crate does

`guardian-core` defines the **canonical action model** and the **decision
types** shared across Project Guardian. It is the foundation every adapter
normalizes into and the only data the policy engine and the Checker ever
evaluate. It is intentionally tiny: a set of `serde`-serializable types plus a
few small pure methods.

By construction it upholds three invariants:

- **No I/O.** It never touches the filesystem, network, or clock. Anything
  time- or environment-dependent (timestamps, ids) is supplied by the caller.
- **No internal dependencies.** Its only dependencies are `serde` and
  `serde_json`; it depends on no other `guardian-*` crate, which keeps the
  workspace dependency graph acyclic (CLAUDE.md invariant 3).
- **No `unsafe`.** The crate is `#![forbid(unsafe_code)]`.

## Public API

### `ActionId`

```rust
pub struct ActionId(pub String);
```

An opaque identifier for an intercepted action, with `new(impl Into<String>)`
and `as_str()`. Id *generation* (e.g. a ULID) deliberately happens at the
adapter layer so this crate stays pure and side-effect-free. Derives `Hash`/`Eq`
so ids can key maps.

### `ActionKind`

```rust
pub enum ActionKind {
    FileRead, FileWrite, Exec, HttpRequest, Email, Payment, Delete, Other,
}
```

The *kind* of action an agent is attempting. Serialized by its variant name
(e.g. `"FileRead"`), which is exactly what policy `when` expressions match on
(`action.kind == "FileRead"`). `Copy`.

### `Capability`

```rust
pub enum Capability {
    Payment, Credential, Exfiltration, IrreversibleDelete,
    Messaging, Filesystem, Network, Other,
}
```

The *semantic capability class* of an action — coarser than `ActionKind`. Its
purpose is to drive the **critical-category** rules. `Capability::is_critical()`
returns `true` exactly for `Payment`, `Credential`, `Exfiltration`, and
`IrreversibleDelete` — the four critical categories from CLAUDE.md invariant 4
that the adaptive-learning layer must never auto-downgrade. `Copy`.

### `ActionContext`

```rust
pub struct ActionContext {
    pub timestamp_ms: i64,         // Unix ms, supplied by the caller — never read here
    pub source: String,            // adapter that intercepted it, e.g. "mcp-gateway"
    pub session: Option<String>,
    pub host: Option<String>,
    pub principal: Option<String>,
    pub path: Option<String>,
    pub extra: serde_json::Map<String, Value>,  // adapter-specific fields for policy use
}
```

The context surrounding an action: when, where, and on whose behalf. Optional
fields are skipped on serialization when `None`; `extra` is a free-form map that
adapters can populate and that policy expressions can read. Note
`timestamp_ms` is caller-supplied — the crate never reads the clock, preserving
the no-I/O invariant.

### `Action`

```rust
pub struct Action {
    pub id: ActionId,
    pub kind: ActionKind,
    pub tool: String,                    // originating tool name
    pub args: Value,                     // typed-where-possible arguments
    pub capability: Option<Capability>,  // semantic class, when known
    pub context: ActionContext,
}
```

A **structured, intercepted action** — the *only* representation the policy
engine and the Checker evaluate, never the agent's natural-language claims
(CLAUDE.md invariant 2, ADR-0003). `Action::is_critical()` is a convenience that
returns `true` when the action's `capability` is set and critical.

### `Decision`

```rust
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Decision {
    Allow,                    // green: allowed silently
    Ask  { reason: String },  // yellow: paused for human review; reason shown
    Deny { reason: String },  // red: blocked automatically; reason shown and logged
}
```

The outcome of evaluating an action against policy — the output of the
deterministic security boundary. The three variants are the traffic-light
decisions (`allow` / `ask` / `deny`). Serialization is internally tagged
(`{"decision":"deny","reason":"…"}`), which is the wire/audit form.

Methods that encode the engine's combination semantics:

- `restrictiveness() -> u8` — the ordering `Deny (2) > Ask (1) > Allow (0)`.
- `is_allow() -> bool`.
- `most_restrictive(self, other) -> Decision` — keeps the more restrictive of
  two decisions; **on a tie, keeps `self`**. This single method is the heart of
  the engine's *most-restrictive-wins* rule (see
  [`guardian-policy`](./guardian-policy.md) and `docs/policy-schema.md` §4).

## How data flows through it

`guardian-core` holds no state and runs no loop; it is a vocabulary, not a
process. The flow is:

1. An **adapter** (e.g. `guardian-mcp-gateway`) intercepts a tool call, mints an
   `ActionId`, reads the clock, and normalizes the call into an `Action` +
   `ActionContext`.
2. The `Action` is handed to **`guardian-policy`**, which evaluates it and
   produces a `Decision` — combining per-rule decisions with
   `Decision::most_restrictive`.
3. The `Decision` is what the daemon enforces, the audit log records, and the
   Checker annotates (advisory only — it can never produce or change a
   `Decision`).

Because every type is `serde`-serializable, an `Action` round-trips losslessly
through JSON (covered by a test), which is also the form the policy engine
exposes to CEL expressions and the form written to the audit log.

## How it upholds the invariants

- **No LLM on the allow/deny path (invariant 1, ADR-0003).** This crate only
  *defines* `Decision`; it contains no model, no scoring, and no branching on
  any LLM output. The `most_restrictive`/`restrictiveness` logic is plain,
  total, pure code.
- **Evaluate structured actions, not prose (invariant 2).** `Action` carries the
  typed `kind`, `tool`, `args`, `capability`, and `context` — never a free-text
  "the agent says it wants to…". The agent's prose has no field here.
- **`guardian-core` does no I/O and has no internal deps (invariant 3).**
  Enforced concretely: dependencies are only `serde`/`serde_json`; timestamps
  and ids are caller-supplied; `#![forbid(unsafe_code)]`.
- **Critical categories never auto-downgraded (invariant 4).**
  `Capability::is_critical()` is the single source of truth for which categories
  are protected; the learning layer consults it.
- **Restrictive by default / fail closed (invariant 5).** The
  `most_restrictive` tie-break and the `Deny > Ask > Allow` ordering bias every
  combination toward caution; the actual default-on-no-match lives in
  `guardian-policy`, but the ordering it relies on is defined here.

## Tests (in `lib.rs`)

The module-level tests pin the contract: `Action` JSON round-trip, the four
critical categories (and the non-critical ones), the `Deny > Ask > Allow`
restrictiveness ordering, `most_restrictive` (including the tie-keeps-`self`
case), and the internally-tagged `Decision` serialization.
