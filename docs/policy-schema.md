# Project Guardian — Policy Schema (v1)

> The formal contract for policy files. The evaluator in `guardian-policy`
> implements exactly this. README §8 shows an illustrative sketch; this document
> is authoritative. Format is **TOML** for v1 (YAML deferred — `serde_yaml` is
> archived; see ROADMAP §1).

## 1. Overview
A policy file defines one **role**: a named set of rules that map a structured
`Action` (defined in [`ROADMAP.md`](../ROADMAP.md) §4) to a `Decision`. Policies
are declarative, reviewable, version-controlled, and (for community packs) signed.

```toml
version = 1
role = "personal-assistant"

[defaults]
decision = "ask"          # used when no rule matches (fail safe)

[[rules]]
id = "read-user-docs"
when = 'action.kind == "FileRead" && action.context.path.startsWith(user.home)'
decision = "allow"

[[rules]]
id = "exec-anything"
when = 'action.kind == "Exec"'
decision = "ask"
sandbox = true
explain = "Runs a shell command on your computer."

[[rules]]
id = "money-movement"
when = 'action.capability == "Payment"'
decision = "ask"
critical = true
explain = "Sends money."
[rules.cap]
amount_max = 200
currency = "EUR"
```

## 2. Top-level fields
| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `version` | int | yes | Schema version. v1 today. |
| `role` | string | yes | Unique role name (e.g. `personal-assistant`, `web-developer`). |
| `defaults.decision` | enum | yes | Decision when no rule matches. Must be `ask` or `deny` (never `allow`). |
| `[meta]` | table | no | Free-form: author, description, pack id/version (set by signing). |

## 3. Rule fields (`[[rules]]`)
| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `id` | string | yes | Unique, stable identifier (used in the audit log and tests). |
| `when` | string (CEL) | yes | A side-effect-free boolean expression over the action/context. |
| `decision` | enum | yes | `allow` \| `ask` \| `deny`. |
| `explain` | string | no | Plain-language hint shown to the user (the Checker may enrich it). |
| `critical` | bool | no (default false) | Marks a critical-category rule. Critical rules can **never** be auto-downgraded by learning. |
| `sandbox` | bool | no | If true, the action runs inside an OS sandbox regardless of the decision (Phase 2). |
| `cap` | table | no | Quantitative limits, e.g. `amount_max`, `currency`, `count_max`. |
| `tags` | array<string> | no | For reporting/grouping. |

## 4. Evaluation semantics (deterministic — see ADR-0003)
1. The engine evaluates **all** rules whose `when` is true for the action.
2. **Most-restrictive-wins:** the resulting decision is the most restrictive among
   matches, where `deny` > `ask` > `allow`. (Ordering of rules does not change the
   outcome — this prevents accidental "allow by ordering".)
3. If **no** rule matches, `defaults.decision` applies.
4. `cap` violations escalate the rule's decision to at least `ask` (or `deny` per
   policy) — e.g. a payment over `amount_max`.
5. Evaluation is a **pure function** of (action, context, policy): no network, no
   LLM, no filesystem access. It must be reproducible and is covered by golden
   tests.
6. `critical: true` only affects the *learning* layer (no auto-downgrade); it does
   not by itself change the decision.

## 5. Context available to `when` (CEL)
Expressions are written in [CEL](https://github.com/google/cel-spec) (decidable,
side-effect-free). Available bindings:

| Binding | Fields |
|---------|--------|
| `action.kind` | `FileRead` \| `FileWrite` \| `Exec` \| `HttpRequest` \| `Email` \| `Payment` \| `Delete` \| `Other` |
| `action.tool` | originating tool name (string) |
| `action.args` | typed-where-possible arguments (map) |
| `action.capability` | semantic class (e.g. `Payment`, `Credential`) or null |
| `action.context` | `timestamp`, `source` (adapter id), `session`, `host`, `principal`, `path`, … |
| `user` | `home`, locale, and other non-secret profile fields |
| `trusted_hosts` | configured allow-list (list<string>) |
| `now` | the action's interception timestamp in ms (the engine has no clock) |

Helper predicates available on fields (illustrative): `.startsWith(...)`,
`.matches(regex)`, `in` membership, `body.contains_secret` (set by the proxy when
a secret is detected in a request body).

## 6. Validation rules (loader rejects on violation)
- `version` known; `role` non-empty and unique within a pack.
- Every `id` unique; `when` parses as a boolean CEL expression referencing only
  the bindings above.
- `defaults.decision` is `ask` or `deny` (never `allow`).
- `decision` and enums are valid; `cap` keys are recognized.
- A pack may not set a previously-`critical` rule to non-critical, nor widen a
  critical category, without explicit user opt-in (see `policies/README.md`).

## 7. Roles, packs, and precedence
- A **role** is one policy file. A **policy pack** is a signed bundle of one or
  more roles plus a manifest (see `policies/`).
- The active role is chosen in the user config (README §5.10). User-local overrides
  take precedence over packs; within evaluation, most-restrictive-wins still holds.

## 8. Versioning
This is schema **v1**. Breaking changes bump `version` and ship a migration note
in `docs/changelog.md`. The evaluator must reject versions it does not understand
(fail closed).
