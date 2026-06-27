# Policy authoring guide

A practical guide to writing Guardian policies. The **authoritative schema** is
[policy-schema.md](./policy-schema.md); this is the how-to and the patterns.

## The model in one paragraph
A policy is a TOML file with a `role`, a `[defaults]` decision, and a list of
`[[rules]]`. Each rule has a CEL `when` expression over the **structured action**
and a `decision` (`allow` / `ask` / `deny`). Evaluation is **most-restrictive-wins**
across all matching rules, and an action that matches **no** rule takes the default
(keep it `ask` or `deny` — fail safe). No LLM is ever on this path.

## What you can match on (`action`)
- `action.kind` — `"FileRead"`, `"FileWrite"`, `"Exec"`, `"HttpRequest"`, `"Email"`,
  `"Delete"`, `"Other"`, …
- `action.args.*` — per-kind fields: `args.cmd` (Exec), `args.method`/`args.path`
  (HttpRequest), `args.path` (file ops), etc.
- `action.context.host` — destination host (HttpRequest; normalized lowercase, no
  default port).
- `action.context.path` — filesystem path (file ops).
- `action.context.extra.*` — adapter signals. The proxy sets
  `body_contains_known_secret` (bool), `body_inspected`, `body_len`, and `upgrade`
  (`"websocket"`).

CEL supports `==`, `&&`, `||`, `in [..]`, `.startsWith(..)`, `.contains(..)`.

## Patterns

**Read-only web access (the flagship case):**
```toml
version = 1
role = "web-readonly"
[defaults]
decision = "ask"
[[rules]]
id = "allow-connect"
when = 'action.args.method == "CONNECT" && action.context.host in ["bank.example"]'
decision = "allow"
[[rules]]
id = "allow-reads"
when = '(action.args.method == "GET" || action.args.method == "HEAD") && action.context.host == "bank.example"'
decision = "allow"
[[rules]]
id = "deny-writes"
when = 'action.args.method in ["POST","PUT","PATCH","DELETE"]'
decision = "deny"
explain = "Reading is allowed; state-changing requests are blocked."
```

**Block exfiltration of your own secrets** (the proxy scans bodies):
```toml
[[rules]]
id = "deny-credential-exfiltration"
when = 'action.context.extra.body_contains_known_secret == true'
decision = "deny"
explain = "Outbound request carries one of your stored credentials."
```

**Sandbox a shell command** (runs contained when allowed):
```toml
[[rules]]
id = "build-only"
when = 'action.kind == "Exec" && action.args.cmd.startsWith("cargo ")'
decision = "allow"
sandbox = true
```

## Critical categories (the hard floor)
Mark a rule `critical = true` when it concerns **money movement, credential access,
data exfiltration, or irreversible deletion**. Critical rules:
- are never auto-downgraded by adaptive suggestions (`guardian report` won't propose
  loosening them);
- in a **signed community pack**, an `allow` on a `critical = true` rule cannot be
  loaded without an explicit opt-in.
Keep critical actions at `ask` or `deny`. Pair with broker **caveats**
(`require_fresh_approval_for_critical`) so a critical action always needs a fresh
human approval.

## Caps
A rule may carry a `[rules.cap]` (e.g. a payment `max_amount`); a violated or
unparseable cap escalates the decision to `ask` (never silently allows). See the
schema.

## Validate, then sign
```sh
guardian policy-validate my-policy.toml      # compiles + checks; non-zero on error
guardian pack sign my-pack/ --name … --key-file …   # to share it as a signed pack
```
A permissive default, duplicate rule id, invalid `when`, or unsupported version are
all rejected at validation.
