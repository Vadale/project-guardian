# guardian-broker

The **identity & token broker**: Guardian holds the user's credentials so the
**agent never sees a raw secret**. The broker injects the credential at the boundary
**only after an action is allowed** — into an MCP tool call (gateway) or as an
`Authorization` header (network proxy) — so the secret never appears in the agent's
prompt/output, the audit log, or ordinary logs.

## Secret stores
- **V1 file store** (`from_toml_str`) — a `target = "token"` TOML map. Simple; the
  file must be kept private (`*secrets*.toml` is gitignored; the CLI warns if it is
  group/world-readable).
- **OS keychain** (`keychain` module, Phase 3 / §8.1) — secrets live in the platform
  credential store (Apple Keychain / Windows Credential Manager / Linux kernel
  keyutils via the `keyring` crate), so **nothing is plaintext on disk**.
  `store`/`load`/`delete` wrap `keyring::Entry::new("guardian", target)`; a missing
  entry maps to `None` (the broker simply holds no credential for that target —
  fail-to-no-credential, never fail-to-leak). `Broker::from_keychain` /
  `add_keychain_targets` load secrets into the in-memory map; a file store and the
  keychain can be combined (keychain wins on conflict).

`keyring` is pinned to **3.x** because 4.x requires Rust 1.88, above the workspace
MSRV (1.75). Native backends are enabled per platform; Linux uses kernel keyutils to
avoid a `libsecret`/dbus build dependency on CI.

## Injection
`inject` / `inject_as` write the credential into a **broker-owned field** after the
allow decision (the caller injects only on the post-decision forward path). It
**overwrites** any agent-supplied value, so an agent can't smuggle its own token for
a brokered target. `token_for(target)` returns the raw token for building an
`Authorization` header at the proxy. `body_leaks_secret(haystack)` lets the proxy
detect one of the user's own secrets in an outbound body (exfiltration) without
exposing the secret.

## Safety
- `Debug` is hand-written to **redact** all token values (test-enforced); a stray
  `{:?}` cannot leak them.
- `guardian broker set` reads the secret from **stdin** (not argv, so it stays out of
  shell history / process listings); `guardian broker has` prints only
  `present`/`absent`, never the value.
- Secrets in the in-memory map are not yet zeroized on drop (tracked for the macaroon
  work). The keychain's at-rest protection is the platform's; a fully-compromised
  same-user process is out of scope (see `docs/threat-model.md`).

## Remaining (Phase 3)
Scoped **OAuth** and **macaroons** with caveats (expiry, max amount, allowed hosts,
source binding; critical-capability use always needs a fresh approval), and
hardware-backed keys.

## Dependencies
`serde_json`, `toml`, `thiserror`, `keyring` (per-platform native backends). No
internal `guardian-*` deps (stays acyclic). `#![forbid(unsafe_code)]` (keychain FFI
lives in `keyring`/`security-framework`, not here).
