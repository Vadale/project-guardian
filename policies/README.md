# Policy packs

A **policy pack** is how Guardian's behavior is configured and shared. Each pack
bundles one or more **roles** (e.g. `personal-assistant`, `web-developer`), where a
role is a single policy file conforming to [`docs/policy-schema.md`](../docs/policy-schema.md).

## Layout
```
policies/
├─ README.md                       # this file
└─ default/                        # the built-in pack (ships with Guardian)
   └─ personal-assistant.toml      # the safe-by-default role
```
Community packs follow the same structure plus a signed manifest (Phase 3):
```
some-pack/
├─ manifest.toml      # pack id, version, publisher key, listed roles
├─ <role>.toml
└─ manifest.sig       # ed25519 signature over the pack contents
```

## Trust rules (security-critical)
- Packs are **ed25519-signed**; the loader **refuses** unsigned or altered packs.
- A pack may **not** widen a *critical* category (payment, credential access, data
  exfiltration, irreversible deletion) or downgrade a critical rule **without
  explicit user opt-in** at install time.
- Pack provenance (publisher key, version) is written to the audit log.
- Every rule should ship golden tests (see `tests/`); packs without tests are not
  accepted into the default channel.

## The default pack
`default/personal-assistant.toml` is intentionally **restrictive**: unknown actions
default to `ask`, the network egress allow-list is empty, and learning is off. The
user widens it deliberately — never the reverse. It is the policy used on first run
(README §5.10).

## Authoring
See [`docs/policy-schema.md`](../docs/policy-schema.md) for fields, the CEL context,
and evaluation semantics (most-restrictive-wins; `deny` > `ask` > `allow`).
Validate with `guardian policy validate <file>` and test a concrete action with
`guardian policy test <file> <action.json>`.
