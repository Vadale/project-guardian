# `guardian-policy` — the deterministic policy engine (the security boundary)

> Source: [`crates/guardian-policy/src/`](../../crates/guardian-policy/src/)
> (`lib.rs`, `schema.rs`, `engine.rs`). This document describes what the crate
> *is*, grounded in that source. The policy file format it implements is
> specified authoritatively in [`docs/policy-schema.md`](../policy-schema.md);
> the rationale is ADR-0003 (deterministic enforcement).

## What this crate does

`guardian-policy` is **the security boundary**. It maps a structured
[`guardian_core::Action`](./guardian-core.md) to a `guardian_core::Decision`
(`allow` / `ask` / `deny`) as a **pure function of (action, context, policy)**.
Policies are declarative TOML; each rule's condition is a
[CEL](https://github.com/google/cel-spec) boolean expression evaluated against
the structured action — never the agent's natural-language claims.

The crate has two responsibilities, one per module:

- **`schema.rs`** — parse and *structurally* validate a policy from TOML.
- **`engine.rs`** — compile each rule's CEL `when` once, then evaluate actions
  against the compiled policy using *most-restrictive-wins*.

Like `guardian-core` it is `#![forbid(unsafe_code)]`. It depends on
`guardian-core` (the action/decision types), `serde`/`serde_json`, `toml`,
`thiserror`, and `cel-interpreter` — and on **no LLM and no I/O on the decision
path** (ADR-0003).

## Public API

Re-exported from `lib.rs`:

| Type | Module | Role |
|------|--------|------|
| `Policy`, `Defaults`, `Rule`, `Cap`, `DecisionKind` | `schema` | the parsed, validated policy contract |
| `PolicyError` | `schema` | all parse/validation/compile failures |
| `CompiledPolicy` | `engine` | a policy whose CEL is compiled; exposes `evaluate` |
| `EvalEnv`, `EvalOutcome` | `engine` | evaluation inputs (beyond the action) and result |

### The schema (`schema.rs`)

```rust
pub struct Policy   { pub version: u32, pub role: String, pub defaults: Defaults, pub rules: Vec<Rule> }
pub struct Defaults { pub decision: DecisionKind }                       // applied when no rule matches
pub enum   DecisionKind { Allow, Ask, Deny }                            // as written in a rule
pub struct Rule {
    pub id: String,
    pub when: String,              // a side-effect-free CEL boolean expression
    pub decision: DecisionKind,
    pub explain: Option<String>,   // plain-language reason surfaced to the user
    pub critical: bool,            // critical-category: never auto-downgraded by learning
    pub sandbox: bool,             // run inside an OS sandbox regardless of the decision
    pub cap: Option<Cap>,          // quantitative limit; a violation escalates to >= Ask
    pub tags: Vec<String>,
}
pub struct Cap { pub amount_max: Option<f64>, pub currency: Option<String>, pub count_max: Option<i64> }
```

`Policy::from_toml_str(s)` parses the TOML and runs `validate_structure`, which
enforces:

1. `version == 1` — anything else is `PolicyError::UnsupportedVersion` (the
   evaluator rejects schemas it does not understand: fail closed).
2. `defaults.decision != Allow` — a permissive default is rejected with
   `PolicyError::PermissiveDefault`. **The default must always be `ask` or
   `deny`.**
3. Every rule `id` is unique — a collision is `PolicyError::DuplicateRuleId`.

This module only parses and structurally validates; it does **not** compile CEL.

### The engine (`engine.rs`)

```rust
pub struct EvalEnv     { pub user_home: String, pub trusted_hosts: Vec<String> }
pub struct EvalOutcome { pub decision: Decision, pub matched_rule: Option<String>,
                         pub sandbox: bool, pub critical: bool }
pub struct CompiledPolicy { /* policy + one compiled CEL Program per rule */ }
```

- `CompiledPolicy::compile(policy)` compiles each rule's `when` into a CEL
  `Program`, kept in a `Vec` parallel to `policy.rules`. A `when` that does not
  compile yields `PolicyError::InvalidWhen { id, msg }`, naming the offending
  rule.
- `CompiledPolicy::from_toml_str(s)` does parse + validate + compile in one step.
- `CompiledPolicy::policy()` borrows the underlying `Policy`.
- `CompiledPolicy::evaluate(&self, action, env) -> EvalOutcome` is the hot path:
  pure, deterministic, and free of I/O and LLM calls.

`EvalOutcome` carries not just the `decision` but the `matched_rule` that
produced the *winning* decision (or `None` if the default applied), plus
`sandbox` and `critical` flags accumulated across **all** matched rules.

## How data flows through `evaluate`

```text
Action + EvalEnv
   │
   ├─ build_context: serialize the Action to JSON and bind CEL variables:
   │     action = <Action as JSON>,  user = { home },  trusted_hosts = [...],  now = timestamp_ms
   │
   ├─ start from the restrictive default:  outcome.decision = defaults.decision  (matched_rule = None)
   │
   └─ for each (rule, compiled program), in policy order:
         if rule_matches(program, ctx):            # condition executed to Bool(true)?
            outcome.sandbox  |= rule.sandbox        # flags OR-accumulate across all matches
            outcome.critical |= rule.critical
            rule_decision = apply_cap(rule, action, decision_from_kind(rule.decision, rule.explain))
            if first match:  outcome.decision = rule_decision;  matched_rule = rule.id
            else:            combined = outcome.decision.most_restrictive(rule_decision)
                             if combined changed the decision: adopt it and update matched_rule
   → EvalOutcome
```

Key details:

- **CEL sees the structured action as JSON.** `build_context` serializes the
  `Action` and binds it as `action`, alongside `user.home`, `trusted_hosts`, and
  `now`. CEL expressions can therefore read `action.kind`, `action.tool`,
  `action.args.*`, `action.capability`, `action.context.*`, etc. — exactly the
  bindings documented in `docs/policy-schema.md` §5. The agent's prose is not
  among them.
- **`decision_from_kind`** turns a `DecisionKind` into a `Decision`, attaching
  the rule's `explain` as the user-facing reason. When `explain` is absent it
  falls back to a generic message (`"This action needs your review."` for ask,
  `"This action is blocked by policy."` for deny).
- **Cap escalation (`apply_cap` / `cap_violated`).** If a matched rule has a
  `cap` and the action violates it — `args.amount > amount_max`, or
  `args.count > count_max` — the rule's decision is combined via
  `most_restrictive` with an `Ask` carrying `"Exceeds the limit configured for
  \`<rule.id>\`."`. So an over-cap `allow` becomes `ask`; a `deny` stays `deny`.
- **Most-restrictive-wins.** Across all matching rules the engine keeps the most
  restrictive decision using `Decision::most_restrictive` (from `guardian-core`),
  and `matched_rule` tracks whichever rule produced the current winner. **Rule
  ordering does not change the outcome** — it only breaks exact ties, and a tie
  keeps the existing winner. This prevents accidental "allow by ordering".

## How it upholds the invariants

- **No LLM on the allow/deny path (invariant 1, ADR-0003).** `evaluate` calls
  only CEL `Program::execute` and pure helpers. There is no model, no network,
  no clock read (`now` is the caller's `timestamp_ms`). Identical inputs always
  produce an identical `EvalOutcome` — which is what makes the path golden-
  testable.
- **Evaluate structured actions, not prose (invariant 2).** CEL is evaluated
  against the serialized `Action`. The only bindings are the action and explicit
  environment values (`user.home`, `trusted_hosts`, `now`); there is no binding
  for the agent's free-text intent.
- **Most-restrictive-wins.** Implemented by accumulating with
  `Decision::most_restrictive` over every matching rule; order-independent by
  construction (see test `most_restrictive_wins_across_matching_rules`).
- **Restrictive default / fail closed (invariant 5).** Two layers enforce this:
  (a) the loader *rejects* a permissive `defaults.decision = "allow"`
  (`PolicyError::PermissiveDefault`); (b) `evaluate` initializes the outcome to
  that mandatory `ask`/`deny` default, so an action matching **no** rule is
  reviewed or blocked, never silently allowed.
- **Fail-safe rule matching.** `rule_matches` returns `true` *only* when the
  compiled program executes to `Bool(true)`. **Anything else — `false`, a
  non-boolean result, or an execution error such as referencing a field absent
  from this particular action — counts as no match.** Combined with the
  restrictive default, a malformed or inapplicable condition can therefore never
  *grant* access; the worst it can do is fall through to review/deny.
- **Critical categories (invariant 4).** A rule's `critical: true` is carried
  through to `EvalOutcome.critical` (OR-accumulated across matches). The engine
  itself does not change the decision based on `critical`; the flag is the signal
  the (separate) adaptive-learning layer reads to know it must never
  auto-downgrade that action.
- **Unsupported version is fail-closed.** `validate_structure` rejects any
  `version != 1`, so a future schema can never be misinterpreted by an older
  build.

## Tests

`lib.rs` carries golden-style tests over a representative policy covering each
decision colour and mechanism: green silent `allow`, yellow `ask` that also sets
`sandbox`, HTTP-GET-to-trusted-host `allow`, red exfiltration `deny` flagged
`critical`, payment `ask`+`critical`, cap violation escalating `allow → ask`, the
restrictive default on an unmatched action, and most-restrictive-wins across two
matching rules. Validation failures are pinned too: permissive default,
duplicate rule id, invalid `when`, and unsupported version. A regression guard
(`shipped_default_policy_compiles`) loads
[`policies/default/personal-assistant.toml`](../../policies/default/personal-assistant.toml)
and asserts it compiles, keeping the shipped pack and the engine in lockstep.
