# Changelog

All notable changes to Project Guardian are recorded here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); the project uses
[Semantic Versioning](https://semver.org/) from 1.0 onward. Maintained by the
`doc-writer` agent on every change (see `CLAUDE.md`).

## [Unreleased]

### Added — 2026-06-29 (GuardianBench + red-team bank + Inspect integration)
- **`evaluation/guardianbench/`** — GuardianBench v0.1: a deterministic, model-free,
  agent-agnostic benchmark built *for an action-firewall*. It scores the **disposition
  of the structured action** (block harmful / allow benign / cite a real rule) across 8
  domains and the OWASP-agentic threat classes (money, credentials, exfiltration,
  destructive/RCE shell, self-protection, exfil-via-message, irreversible delete, memory
  poisoning). Latest: **FN 0% · FP 0% · refusal 100%** (26 cases). Exits non-zero on any
  false negative → CI-able. Motivated by the finding that AgentThreatBench scores
  *output integrity* (out of scope for an action-firewall), so it does not show what
  Guardian does; GuardianBench does.
- **`evaluation/redteam/`** — internal financial red-team bank (the finance-specific
  seed GuardianBench generalises): fake-transfer (indirect injection), tool-parameter
  abuse, and autonomy-hijack / self-protection. **FN 0% · FP 0% · refusal 100%**.
- **`evaluation/inspect/`** — Guardian as an Inspect (UK AISI) `@approver`, so AgentDojo
  and AgentThreatBench can be run with Guardian as the defense on the same metric as the
  `inspect_evals` leaderboard. Validated end-to-end (approver fires, scoring works,
  no Docker needed). Honest finding recorded: AgentThreatBench measures output-integrity,
  outside the action-firewall's scope.

### Security — 2026-06-29 (intrinsic critical-category floor)
- **The deterministic engine now enforces a runtime floor for critical categories**
  (invariant #4). An action whose *capability* is a critical category — money
  movement, credential access, data exfiltration, irreversible deletion — can **never
  resolve to `allow`**, regardless of what any rule says, **not even a signed
  community pack**. A would-be silent `allow` is floored to `ask` (with `critical`
  set) so a human or a deny rule still gates it. **Why:** the pack-loader's
  anti-widening check trusted the rule author's self-declared `critical = true` flag;
  a malicious pack could `allow` a money/credential action while simply omitting the
  flag and slip through. The floor is now intrinsic to the action's capability, not
  to a rule's flag. Golden + adversarial tests added (`guardian-policy`): an explicit
  `allow` for Payment/Credential is floored to `ask`; no critical capability is ever
  allowed under an allow-everything policy; non-critical capabilities are unaffected.
  **Coverage caveat:** the floor keys off the action's *capability*, so today it covers
  Payment/Credential/IrreversibleDelete (tagged by the gateway) but **not yet
  Exfiltration** (the proxy detects exfil via a rule, not a capability) nor untagged
  `Exec`/`Other` actions — see `docs/threat-model.md` §5.4. Surfaced by the multi-suite
  evaluation review (see `evaluation/`).

### Added — 2026-06-28 (evaluation results)
- **Published the first Guardian evaluation scorecard** (`evaluation/README.md` §7).
  AgentDojo `banking` / `important_instructions`, local Ollama, A/B (agent alone vs
  agent + Guardian): **Gemma-4 12B 100% → 0%** ASR (baseline 18/18 compromised;
  Guardian 0/9 — the block is deterministic, money-movement tools denied by name),
  **Gemma-4 E2B 3.5% → 0%** (n=144). Utility cost is the eval policy hard-denying
  money-movement that a real deployment routes to `ask`. Coverage is one suite + one
  attack family (other suites / big-model re-run are future work). Raw outputs in
  `evaluation/results/`.
- **Added `evaluation/pi/`** — a live interception demo with the real `pi` coding
  agent: a ~60-line Guardian extension on pi's `tool_call` event (the pi analogue of
  the Claude Code `PreToolUse` hook) blocks shell/delete/write while letting reads
  through; in 2 of 4 cases the model claimed success in prose while Guardian had
  blocked the real action (invariant #2 demonstrated live).

## [0.1.0] — 2026-06-28 — first tagged release
The first public, versioned release. Working MVP across Phases 0–4: deterministic
policy engine (CEL), structured action model, hash-chained signed audit log, MCP
gateway, HTTP(S) MITM proxy with secret-exfiltration scanning, OS sandbox backstop
(macOS/Linux), identity & token broker (OS keychain + caveats + signed packs +
verifiable credentials), long-running daemon with a fail-closed human-approval
queue over a `0o600` local control socket, the `guardian` CLI, and the ratatui TUI
cockpit (approvals / activity archive / create-token). All seven hard invariants
hold; quality gate green (fmt, clippy `-D warnings`, 173 tests, cargo-deny) on
macOS/Linux + Windows CI.

- **Distribution:** unsigned cross-platform CLI builds attached to the GitHub
  Release on this tag (macOS aarch64+x86_64, Linux x86_64, Windows x86_64), plus
  `cargo install`. **Code-signing is intentionally not enabled** — no certificate
  secrets are needed to download and run from GitHub (see `docs/packaging.md`).
- **Platform support:** macOS & Linux are tested; **Windows is experimental and
  not yet tested end-to-end** (compiles + unit tests pass in CI; no sandbox backend
  on Windows — `Exec` stays ask/deny, fail safe). See `docs/packaging.md`.
- All Phase 0–4 work below is included in this release.

### Fixed — 2026-06-28 (whole-codebase milestone review)
A full-system code-review pass (across Phases 0–4) found integration-seam drift
between independently-correct parts:
- **Fix (blocker): the shipped policies' exfiltration rule was dead.**
  `policies/default/{personal-assistant,coding-agent}.toml` gated exfiltration on
  `action.context.body.contains_secret` — a field that doesn't exist — while the
  proxy emits `action.context.extra.body_contains_known_secret`. The rule never
  fired (it failed *safe*, to the ask/deny default, not open, but the advertised
  control was inert and the body scan wasted). Both rules now use the path the proxy
  emits, with a **golden test driving the shipped policy through the proxy** so the
  seam can't drift again.
- **Fix: `Cap.currency` is now enforced.** A currency-scoped cap (e.g. `amount_max =
  200, currency = "EUR"`) previously ignored `currency`; a different/missing currency
  now fails safe (escalates to `ask`) instead of passing the amount check.
- **Fix: the MCP gateway now fails closed on an audit-write failure** (matching the
  proxy) — it no longer forwards an allowed action it couldn't durably record
  (invariant 5 + 7).
- **Documented:** the broker `max_amount` caveat is a no-op on the network-proxy path
  (no amount in arbitrary HTTP) — enforced on the MCP/tool path; tracked to parse or
  fail-closed later. The review confirmed all seven hard invariants otherwise hold.

### Implemented — 2026-06-28 (milestone simplify / perf / UX pass)
Multi-angle cleanup at the Phase-4 milestone (cleanup + efficiency + correctness +
security + UX reviews); behavior-preserving, gate green (170 tests).
- **perf(policy):** `CompiledPolicy` builds the CEL standard-function registry
  **once** and derives a cheap child scope per `evaluate` (instead of rebuilding it
  every call). Behavior-identical (reviewed: no cross-call variable leakage,
  `Arc<CompiledPolicy>` stays `Send+Sync`; new `evaluate_is_independent_across_calls`
  test). Hot-path latency **≈3.9 µs → ≈2.6 µs/decision**.
- **cleanup(cli):** one `resolve_audit_path` helper replaces 4 duplicated audit-path
  blocks; `write_private_file` creates the pack signing-key with mode `0o600` **at
  creation** (closes a create-then-chmod window).
- **ux(tui):** the activity **archive is now a scrollable table** (column legend,
  humanized action kind, `j/k` + mouse-wheel scroll, "… N older below" hint,
  unknown decisions flagged yellow); the **token form** shows visible `[____]` input
  tracks, a yellow "granting trust" accent on the active field/title, and clears its
  status on the next keystroke; footer surfaces `r` (refresh); panic shows an
  explicit "denied N". Reviewed by code-reviewer (approve) + security-auditor (clean).

### Implemented — 2026-06-28 (cockpit: create a token)
- **Create-a-token form in the cockpit (`guardian ui`)** — press **`n`** to open a
  form: enter the **site/host** and its **secret**; on save the secret is stored in
  the **OS keychain** (`guardian_broker::keychain`) so the agent never sees it, and
  the proxy can later inject it for that host (`--keychain <host>`). The secret field
  is **masked** (never echoed); `Tab` switches fields, `Enter` saves, `Esc` cancels.
  Local operation (no daemon needed). 3 render/logic tests (masking, field editing,
  submit validation).

### Implemented — 2026-06-28 (cockpit: activity archive)
- **Activity archive in the cockpit (`guardian ui` + daemon `history`)** — the
  terminal cockpit gains a second screen (toggle with **Tab**) showing the **archive
  of what the agent did**: each recent decision with its outcome (allow/deny/ask,
  colored), the action kind, **where it went (host)**, the matched rule, the reason,
  and a `[critical]` flag. Backed by a new daemon control command `history { limit }`
  → `HistoryView` rows (`DaemonClient::history`), served from a new
  `Gateway::audit_tail`. The audit log now also records the **`host`** ("where the
  agent went") on each entry. Headless render test for the new view.

### Implemented — 2026-06-27 (Phase 4 — Hardening)
- **Cross-platform IPC — Windows support (`guardian-daemon`, §9b.3)** — the daemon's
  control socket (`serve` / `DaemonClient` / `DaemonRouter`) now runs on **Windows**
  too. The Unix-domain-socket transport was replaced with the **`interprocess`**
  crate's one local-socket API: a Unix domain socket on unix (the configured path), a
  **named pipe** on Windows (derived from the socket file name). `mod server` is no
  longer `#[cfg(unix)]`. A new **Windows CI job** (`cargo test` on `windows-latest`)
  compiles the named-pipe path and exercises the IPC tests over a real pipe.
  `deny.toml` allows `0BSD` (interprocess's permissive transitive deps).
- **Packaging & release pipeline (Phase 4 / §9.3)** — a `v*`-tag GitHub Actions
  release workflow (`.github/workflows/release.yml`) builds the `guardian` CLI for
  macOS (aarch64 + x86_64), Linux (x86_64), and Windows (x86_64) and attaches the
  archives to the Release (unsigned developer builds). The **Tauri bundler** is
  enabled (`ui/src-tauri/tauri.conf.json` → `bundle.active`, `targets: all`,
  metadata). `docs/packaging.md` documents distribution. **Releasing needs no
  certificates** — unsigned binaries via GitHub Releases + `cargo install` are the
  supported path (users click through a one-time OS warning). Code signing /
  notarization is an **optional** later polish that removes that warning (needs paid
  Apple/Windows certs as CI secrets; commands documented and ready to wire in).
- **Docs finalized (Phase 4 / §9.4)** — `docs/user-guide.md` (end-to-end getting
  started for the three integration modes + the flagship use case), and
  `docs/policy-authoring.md` (a practical how-to + patterns, complementing the formal
  `docs/policy-schema.md`). Adapter authoring lives in `docs/integrations.md`; the
  threat model (`docs/threat-model.md`) carries residual risks current through Phase
  4; ADRs in `docs/adr/`. The README status blurb was refreshed (it claimed "62 tests
  / next: proxy/sandbox/broker…" — all now landed through Phase 4).
- **Sealed-key audit signing (`guardian-audit` + `guardian log --verify-key`, Phase 4
  / §9.2)** — the tamper-evident log can now be **ed25519-signed at the head**:
  `AuditLog::open_signed(path, key)` signs `seq || head_hash` on every append, so an
  attacker who rewrites **every row and the head consistently** (which the hash-chain
  alone can't catch) still can't produce a valid head signature — `verify()` fails.
  A read-only auditor verifies with an **externally-supplied trusted key** via
  `verify_with_pubkey()` / `guardian log --verify-key <hex>` (the key must come from
  outside the DB, so it can't be swapped in). Test-proven: a full single-row rewrite
  that keeps the hash-chain internally consistent is still caught by the signature.
  The **signed/locked policy** half of §9.2 is provided by §8.4 (deploy the policy as
  a signed pack, verify with `guardian pack verify --pubkey`). 4 new audit tests.
- **Security-hardening pass + performance budget (Phase 4 / §9.1 + §9.5)** —
  documented and test/CI-enforced in `docs/hardening.md`. (1) **No `unsafe` we own**:
  every crate `#![forbid(unsafe_code)]`, now also asserted by a CI step so a new crate
  can't drop it; `unsafe` lives only in vetted FFI deps. (2) **Advisories**: `cargo
  deny` (RustSec DB — the same one `cargo audit` uses) gates every PR; documented the
  rejection of unmaintained/heavy deps (`macaroon`/`sodiumoxide`, `ssi`). (3)
  **Fuzzing** the untrusted `bytes → JSON → ToolCall → Action` boundary: an in-gate
  randomized robustness test (`build_action_never_panics_on_arbitrary_input`, 5 000
  inputs/run) plus a `cargo-fuzz` target (`fuzz/parse_toolcall`, nightly; the `fuzz`
  crate is excluded from the stable workspace). (4) **§9.5**: the green fast path is
  test-proven to never invoke the Checker/LLM, and measured at **≈3.9 µs/decision** —
  the documented latency budget (low-µs, zero network/LLM on allow/deny).
  *(The `cargo-fuzz` target was not compiled in the dev environment — no nightly
  toolchain available; the in-gate robustness test is the verified guarantee.)*

### Implemented — 2026-06-27 (Phase 3 — Identity)
- **Lightweight verifiable credentials (`guardian-broker::credential`, Phase 3 /
  §8.5)** — verify an **issuer-signed, expiring claim about a subject** (ed25519):
  `Credential { subject, issuer, claims, not_after_ms }` + `SignedCredential`;
  `issue()` signs, `verify(now, trusted_issuer)` checks the signature, optional
  trusted-issuer pin, and expiry. This is decentralized-identity-style (issuer-signed
  claims, no central account) and the **trust primitive** for principal identity.
  Implemented dependency-light with the ed25519 we already use; **full W3C VC +
  DID-method + JSON-LD interop (the heavy `ssi` stack) is deferred** — it can layer
  on this verifier. 4 tests (verifies+claims, tampered-claim → invalid, untrusted
  issuer, expired).
- **Least-privilege capability caveats (`guardian-broker::capability` + `guardian
  proxy --caveats`, Phase 3 / §8.1)** — a brokered target can carry **caveats** that
  attenuate how its credential may be used: **expiry** (`not_after_ms`),
  **allowed_hosts**, **max_amount**, and **`require_fresh_approval_for_critical`** (a
  critical action needs a *fresh* human approval — a cached grant is never enough).
  `Broker::authorize(target, req)` checks them at the boundary; the network proxy
  calls it on the allow path and **blocks** a violation (`freshly_approved` is true
  only when the cockpit just approved *this* request). Caveats load from a TOML file
  (`[target]` tables) via `--caveats`; see `examples/proxy/caveats.example.toml`.
  Implemented **natively, dependency-free**: the `macaroon` crate was rejected — it
  pulls the **unmaintained `sodiumoxide`** + libsodium C lib (against the
  supply-chain gate), and since the agent never holds the credential a macaroon
  bearer token adds little; the caveat *model* is the value. 8 new tests (each caveat
  + broker `authorize` + TOML load + a proxy expired-capability gate). The full Phase
  3 broker now: keychain storage + caveats; remaining = OAuth, hardware keys, zeroize.
- **Integrations guide — agent adapters (`docs/integrations.md`, Phase 3 / §8.6)** —
  documents how to put Guardian in front of any harness using the **existing**
  interception boundaries (no new code, because Guardian mediates at the action
  boundary, not inside a harness): `guardian mcp` for MCP hosts (Cursor / Claude
  Desktop config snippet, generic MCP agents), `guardian hook` for Claude Code's
  native tools, and `guardian proxy` for any raw-HTTP agent (OpenAI Agents runtime,
  browser tools, scripts). All three share the same policy, broker, and audit log.
- **Safety report + constrained adaptive suggestions (`guardian-audit::report` +
  `guardian report`, Phase 3 / §8.3 + §8.2)** — `guardian report [--window N]`
  summarizes a recent window of the audit log: allow/ask/deny counts, the **top
  blocked** rules ("threats blocked"), and **suggestions to confirm** — a non-critical
  rule you were asked about and **approved every time** (≥3×) is surfaced as
  "consider an allow rule." Suggestions are **advisory only**: Guardian never edits
  the policy, and a rule that ever touched a **critical category is never suggested**
  for loosening (invariant 4). To support that guard, `AuditEntry` now records a
  `critical` flag (threaded through `for_decision` and every recorder: gateway,
  proxy, exec; serde-default so older logs still parse). Pure, order-independent
  analysis in `guardian-audit::report` with 5 unit tests (counts/ranking,
  approved-non-critical → suggested, critical → never, sometimes-denied → not,
  below-threshold → not). Verified e2e.
- **Signed community policy packs (`guardian-policy::pack` + `guardian pack`, Phase 3
  / §8.4)** — a **pack** is a directory of policy `.toml` plus `guardian-pack.json`:
  a manifest listing each file's **blake3** hash, signed with **ed25519** by the
  publisher. `guardian pack sign <dir> --name --version --key-file` signs (the
  signing seed is generated into `--key-file` at `0600` on first use; the publisher
  public key is printed to share). `guardian pack verify <dir> [--pubkey] [--audit]`
  **refuses** an unsigned, tampered (file hash mismatch), file-added/removed, or
  wrong-publisher pack (non-zero exit), reports any **critical-widening** rules, and
  can record the verified pack's **provenance** (publisher, name, version) into the
  tamper-evident audit log. The loader (`pack::load_pack`) refuses a pack that
  `allow`s a `critical = true` rule (money / credential / exfiltration / deletion)
  unless the caller explicitly opts in — packs can never silently widen a critical
  category. ed25519-dalek + blake3 + hex (licenses already permitted). 6 pack unit
  tests (signed-ok, tampered-file, added-file, wrong-publisher, critical-widening
  blocked-without-opt-in, unsigned-not-a-pack); verified e2e via the CLI. Example +
  workflow in `examples/packs/`.
- **Broker secrets in the OS keychain (`guardian-broker` keychain store + `guardian
  broker`, Phase 3 / §8.1)** — credentials now live in the **platform credential
  store** (Apple Keychain / Windows Credential Manager / Linux kernel keyutils via
  `keyring`), so they are **never plaintext on disk** (the V1 was a TOML file) and
  never shown to the agent. New `keychain` module (`store`/`load`/`delete`,
  `NoEntry`→`None`); `Broker::from_keychain` / `add_keychain_targets` load secrets
  into the in-memory map (the post-allow `inject` path is unchanged). New CLI:
  `guardian broker set <target>` (secret read from **stdin** so it never lands in
  argv/shell history), `guardian broker has <target>` (prints only `present`/`absent`
  — never the value), `guardian broker delete <target>`; and `guardian proxy
  --keychain <target>` sources a host's credential from the keychain (reporting which
  targets resolved vs were not found, without printing values). `keyring` pinned to
  3.x because 4.x requires Rust 1.88 > the workspace MSRV 1.75. Verified end-to-end on
  macOS (store → injected by the proxy as `Authorization` → delete, no residue).
  Reviewed by `code-reviewer` (approve) + `security-auditor` (no Critical/High; no
  secret-leak vectors — applied the resolved/skipped startup notice; in-memory
  zeroize tracked for the macaroon work). 13 broker tests (mock store; real keychain
  round-trip behind `#[ignore]`).

### Implemented — 2026-06-27
- **CA-trust onboarding (`guardian proxy --install-ca`, Phase 2 / §7.2)** — a guided
  flow to trust the local proxy CA so HTTPS interception works. It **warns** that
  trusting the CA lets Guardian intercept all TLS, prints **copy-pasteable,
  platform-specific** instructions (`ca_trust_instructions`, a pure/tested function:
  macOS Keychain / `security`, Linux `update-ca-certificates`, incl. how to remove
  it later), and on macOS runs `security add-trusted-cert -r trustRoot -k <login
  keychain>` — the OS prompts the user to authorize, so the consent gate is the
  user's own. Installing a trusted root is security-sensitive and hard to reverse, so
  it never happens silently (it requires the explicit `--install-ca` flag and OS
  authorization).
- **Proxy `ask` → cockpit routing (`guardian-proxy` + `guardian proxy --daemon`,
  Phase 2 / §7.1 increment 4)** — the network proxy can now resolve a yellow (`ask`)
  decision through a **human**, completing the traffic-light model for web traffic.
  A new `Approver` trait in `guardian-proxy` (kept decoupled from the daemon IPC) is
  awaited on `ask`; the CLI bridges it to a running daemon's cockpit
  (`ProxyDaemonApprover` → `DaemonClient::approve`). Approve → forward (with the
  broker credential if brokered); deny **or any non-answer/timeout/unreachable
  daemon → block** (the queue is fail-closed). Without `--daemon`, `ask` still fails
  closed exactly as before. The decision pipeline was refactored into `prepare` →
  `record_or_fail` (audit before acting; fail closed if unrecordable) →
  `resolve_and_respond`. 3 new unit tests (ask approved → forward, denied → block,
  no-approver → fail closed). Verified e2e: with an unreachable daemon an `ask`
  request returns `403` and is audited.
- **Exec sandbox backstop (`guardian-sandbox` + `guardian exec`, Phase 2 / ROADMAP
  §7.3)** — a new dependency-free crate that runs an `exec`-class action **contained**
  when the matched policy rule sets `sandbox = true`. Containment is delegated to an
  **off-the-shelf OS tool** (no custom kernel code, invariant 6): `sandbox-exec`
  (macOS Seatbelt) or `bubblewrap` (Linux). A `SandboxRunner` trait exposes `wrap()`
  (builds the exact argv — unit-testable without a real sandbox) and `run()`; the
  default is **restrictive** (network denied, filesystem read-only except temp) and
  policy widens it (`--allow-network`, `--writable <path>`). `detect()` returns the
  platform backend if its tool is on `PATH`, else `None` — and a sandboxed action
  with **no backend fails closed** (refuses to run unconfined). New `guardian exec
  [--policy] [--audit] [--allow-network] [--writable …] -- <cmd> …`: builds the
  `Exec` action, evaluates the deterministic policy, **records the decision to the
  audit log**, then refuses on deny/ask (exit 126) or runs the command — sandboxed
  when the rule asked. Verified end-to-end on macOS: an allowed `echo` runs
  sandboxed; `rm -rf` is denied and not run; a network attempt inside the sandbox
  fails (`connect: Operation not permitted`); all three are audited. 6 unit tests
  (argv construction for both backends + a backend-gated real network-denial check).
- **Network proxy — live HTTP(S) forward proxy with TLS interception
  (`guardian-proxy` + `guardian proxy`, Phase 2 / ROADMAP §7.1, increments 2–3)** —
  the mediation core now drives **real sockets** via `hudsucker` (+ `rustls`/`rcgen`).
  `server::GuardianHandler` implements hudsucker's `HttpHandler`: it normalizes each
  request, evaluates the **deterministic policy**, **records the decision to the
  tamper-evident audit log before acting** (and **fails closed** if the log is
  unavailable — this is the egress critical path), then forwards (injecting the
  broker's `Authorization` on `Allow`, never on `CONNECT`) or returns a `403` with the
  block reason. `ca::LocalCa` generates/persists/loads a **local CA** (rcgen 0.14)
  used to mint per-host leaf certs; the CA key is written **owner-only (`0o600`,
  applied atomically at creation)** and redacted in `Debug`. **Egress is
  default-deny**: the proxy mediates the `CONNECT` **authority** too, so an
  un-allowlisted host gets no tunnel at all (closes the raw-protocol-after-CONNECT
  bypass the security audit flagged) — the decrypted inner requests are still
  mediated independently. Upstream TLS verification stays strict (webpki roots; real
  servers are not MITM-downgraded). New `guardian proxy` CLI subcommand
  (`--listen/--policy/--secrets/--audit/--ca-dir/--print-ca-path`) and an
  `examples/proxy/` walkthrough (read a private site with a brokered token; block all
  state-changing requests). Verified end-to-end: plain HTTP forwards with the token
  injected, `POST` blocked `403`, HTTPS MITM returns `200` when the client trusts the
  local CA, an un-allowlisted HTTPS host has its tunnel refused, and every decision is
  audited. Reviewed by `code-reviewer` (approve-with-nits) and `security-auditor`
  (no Critical/High; the CONNECT-authority gate, fail-closed audit, and atomic CA-key
  perms were applied from its findings; WebSocket-frame inspection tracked for the
  body-inspection increment). `deny.toml` allows `CDLA-Permissive-2.0` (the
  webpki-roots data license); the TLS crypto deps are Apache-2.0/ISC.
- **Network proxy — mediation core (`guardian-proxy`, Phase 2 / ROADMAP §7.1)** —
  the first increment of the user-space HTTP(S) forward proxy (decision recorded in
  `docs/adr/0004-network-proxy.md`), built transport-first so the heavy TLS stack
  stays isolated for a later increment. A new **transport-agnostic mediation core**
  normalizes an outbound `HttpRequest` (method, host, path) into a
  `guardian_core::Action` and runs it through the **same deterministic policy
  engine** as the MCP gateway: `mediate()` returns `Forward` or `Block`. For an
  **allowed** request to a brokered host it attaches the **token broker**'s value as
  the `Authorization` (`Bearer …`) — so the agent never holds the credential, exactly
  as on the MCP path — and **only** on `Allow`; `Deny` blocks, and `ask` **fails
  closed** to a block at this layer (no human is attached yet — the live proxy will
  route `ask` to the cockpit). The request **host is normalized** (lowercase, default
  port stripped) so the policy context and the broker lookup can never silently
  diverge on `Bank.local:443` vs `bank.local`. `ProxyOutcome`'s `Debug` **redacts the
  token** (mirrors `Broker`'s redacted `Debug`) so a stray `{:?}` can't leak it. Added
  `Broker::token_for()` (raw token for header building). 6 unit tests; no TLS/network
  deps yet. Reviewed by `code-reviewer` (approve-with-nits → host normalization and
  redacting `Debug` applied; audit recording + `matched_rule` threading tracked for
  the live-proxy increment in the ADR).
- **Audit-log browser (`guardian log`)** — a read-only viewer for the tamper-evident
  log (the "black box"): `guardian log [--audit <path>] [--limit N]` opens the
  persistent log (`$GUARDIAN_AUDIT`, else `~/.guardian/audit.db`), prints the
  **integrity status** (`verify()` → OK/TAMPERED), the entry count, and a table of
  recent decisions (seq, decision, kind, matched rule, reason). Backed by a new
  `AuditLog::tail(limit)` (most-recent-first from SQL, returned oldest-first). It is
  **resilient when the log looks corrupt** — an unparseable row renders as
  `<unreadable>` rather than aborting the listing (you reach for this precisely when
  the log is suspect; `verify()` remains the authority). Cells collapse control
  chars and clip, so a multi-line reason can't break the table. Read-only; reviewed
  by code-reviewer; tests for `tail` ordering/over-limit and the corrupt-row path.
- **Token broker (vertical seed)** (ROADMAP §8.1) — `guardian-broker::Broker` holds
  `target → token` secrets so the **agent never sees the raw credential**: Guardian
  injects the token into a tool-call only on the **forward (post-allow) path**, so
  the audit log records the pre-injection action and nothing leaks. In the proxy,
  `guardian mcp --upstream … --secrets <file>` wires a `BrokeredUpstream` that
  injects the destination's token; the credential field is **broker-owned** (any
  agent-supplied value is scrubbed) and a token is injected **only for a known
  registered upstream label** (no cross-target leak). A live `examples/toybank/`
  demo shows the headline behavior end to end: with the broker, *read balance*
  works (token injected) while *transfer* is **blocked** by policy (money movement
  is critical) — so a hallucination or prompt injection can't drain the account;
  without the broker the bank returns `UNAUTHORIZED`. Reviewed by code-reviewer +
  security-auditor; fixes applied (redacted `Debug` so `{:?}` can't leak tokens,
  `*secrets*.toml` git-ignored, broker-owned field + known-label injection, a
  world-readable secrets-file warning). V1 secret store is a file; OS keychain +
  macaroon caveats remain Phase 3. Tests for injection/override/scrub + the wiring.

### Implemented — 2026-06-25
- **Real Checker backend: `HttpChecker`** (ROADMAP §9b.4) — a model-backed advisory
  Checker that POSTs the structured action to a configured HTTP endpoint and parses
  an `Explanation` back; the daemon uses it when `checker_endpoint` /
  `GUARDIAN_CHECKER` is set, else the offline `StubChecker` (privacy default, off).
  **Advisory only (ADR-0003)** — the endpoint's reply only produces the human-facing
  explanation/risk on an `ask`; it never reaches the allow/deny decision (verified
  by the security audit). Infallible to the caller: any error (unreachable, non-2xx,
  bad/oversize JSON) degrades to a conservative offline fallback, with a 10s timeout
  and a **256 KB response-body cap** (no unbounded-allocation DoS). http-only (no
  TLS) to keep the dependency/license surface small. Security-audit fixes applied:
  body cap, a startup warning when the endpoint is non-local (the full action incl.
  args is sent there) or `https`, and the URL is not logged (may embed credentials).
  wiremock tests cover success/clamp + unreachable-fallback.
- **Observability: structured logging** (ROADMAP §9b.5) — the daemon now uses
  `tracing` + `tracing-subscriber` (level via `RUST_LOG`, default `info`) instead
  of ad-hoc `println!`/`eprintln!`: startup events, a `tool`+`status` event per
  mediated call, invalid-request warnings, and a loud `error!` if the kill switch
  fails to engage. This is **operational** logging, deliberately separate from the
  tamper-evident audit log, and logs no secrets or request bodies (reviewed by
  code-reviewer). Remaining: optional metrics + tracing in the proxy front-ends.
- **Self-protection + kill switch** (ROADMAP §9b.6) — the gateway now applies a
  deterministic hard override **before** the policy (recorded to the audit log):
  a **kill switch** (while a `STOP` sentinel next to the config exists, every
  action is denied) and **self-protection** (deny `FileWrite`/`Delete` targeting
  Guardian's own files — config, policy, audit, socket, `STOP`, `~/.guardian` —
  with paths normalized so `..`/relative can't evade the prefix). Daemon gains a
  `kill_switch` control command (+ `DaemonClient::kill_switch`). Reviewed by
  code-reviewer + security-auditor; fixes applied (path normalization + adversarial
  tests, `STOP` added to the protected set, loud-fail on a failed engage). **Known
  follow-ups (tracked, §9b.6):** the agent and user still share one control socket
  (channel separation needed so the agent can't toggle the switch / self-approve),
  and `Exec` can still reach Guardian's files (needs the OS sandbox, §7.3) — so the
  kill switch is effective on the mediated file path but not yet fully agent-proof.
- **Daemon: configuration system + first-run defaults** (ROADMAP §9b.2) — a typed
  `Config` (`guardian-daemon::config`) loaded from `GUARDIAN_CONFIG` (default
  `~/.guardian/config.toml`) replaces the scattered env reads in `main`. Fields
  (`socket`, `policy`, `audit`, `approval_timeout_secs`, `trusted_hosts`) are all
  optional, so a missing/empty config yields safe defaults; per-value precedence is
  **built-in default < config file < `GUARDIAN_*` env var** (`GUARDIAN_SOCK`/
  `POLICY`/`AUDIT`). On first run it materializes a commented default config the
  user can edit. Parsing is strict (`deny_unknown_fields`) and **fails closed** on a
  malformed config (the daemon refuses to start rather than run half-understood).
  Hardened per the code/security review: the first-run config is written
  owner-only (0600, dir 0700), a `0` approval timeout is treated as unset (it would
  otherwise deny every `ask`), and the effective `trusted_hosts` is logged at
  startup (it exempts hosts from host-gated critical rules — routing it through the
  critical-category opt-in is a tracked follow-up). Covered by config tests (safe
  defaults, env-overlay precedence, first-run materialization, zero-timeout guard,
  malformed rejected).
- **Daemon: persistent, verified audit log** (ROADMAP §9b.1) — the daemon no
  longer keeps its tamper-evident log in memory (lost on restart). It opens a
  SQLite file at `GUARDIAN_AUDIT` (default `~/.guardian/audit.db`), continues the
  hash chain across restarts, and **verifies the chain on startup — failing closed
  (refusing to start) if it is broken/tampered**, rather than appending to a log
  whose integrity it can't vouch for. Verified by a live restart smoke (an entry
  recorded in one run is present and intact after a restart). ed25519 head signing
  remains a follow-up (§9b.1 / §9.2).
- **MCP proxy: human approvals via the cockpit** — an `ask` on a *proxied* tool now
  reaches the human instead of failing closed. The daemon gains an `approve`
  control-socket request that enqueues into its `ApprovalQueue` (shown by the
  cockpit's `pending`, resolved by `respond`) and blocks until resolved (or times
  out → denied). A new `DaemonApprover` in the CLI routes the proxy's `ask`
  decisions there: `guardian mcp --upstream "<cmd>" --daemon <socket>` proxies an
  upstream MCP server *and* sends its `ask`s to the cockpit, while the proxy keeps
  owning the upstream connection. Verified by a daemon integration test and a live
  3-process run (proxy → daemon queue → cockpit approve → forwarded to upstream).
- **MCP proxy: multi-server aggregation + namespacing** (ROADMAP §7.5, step 4) —
  `upstream::MultiUpstream` fronts several upstream MCP servers behind one
  Guardian. `guardian mcp --upstream` is now repeatable (`[label=]command args`);
  tools are aggregated and **namespaced** `label__tool`, and a `tools/call` is
  routed to the owning server with the namespace stripped. A single unlabeled
  upstream keeps raw tool names (back-compatible). The policy `[tools]` map keys
  on the namespaced names, so classification stays per-server and trusted.
  Verified live (one Guardian fronting two labeled Guardians: aggregated/namespaced
  `tools/list`, `a__read_file` allowed and routed to server `a`, `b__read_file`
  blocked) and unit tests for the namespacing/route helpers.
- **MCP proxy: policy-driven tool classification** (ROADMAP §7.5, step 3) — the
  policy schema gains an optional `[tools]` table (`tool name → ActionKind`). When
  Guardian proxies an upstream MCP server, the classifier comes from this trusted
  map (the proxy uses `policy.tools`); a tool not listed is `Other` (restrictive
  default). This makes the proxy practically usable — a policy can declare which
  upstream tools are safe to treat as e.g. `FileRead` (green fast-path) — while the
  trusted source of classification stays the policy, never the tool name. The
  built-in MCP modes keep their fixed `builtin_classifier()`. Verified live (a
  proxy with `[tools] read_file = "FileRead"` forwards read_file, blocks run_shell)
  and a schema parse test. See `docs/policy-schema.md` §2.1.
- **MCP proxy: generic stdio upstream client** (ROADMAP §7.5, step 2) —
  `guardian_mcp_gateway::upstream::McpStdioUpstream` spawns a real MCP server as a
  child process, performs the handshake, discovers its tools (`tools/list`), and
  forwards `tools/call`s — implementing the `Upstream` port. The CLI gains
  `guardian mcp --upstream "<command>"` (and `--policy`): Guardian then **proxies**
  that server, re-advertising its tools and mediating every call through the
  policy. The upstream's tools are untrusted, so the proxy attaches **no
  classifier** — every tool is `Other` (restrictive default) until the policy
  trusts it explicitly. Verified live (Guardian proxying Guardian: aggregated
  `tools/list`, a policy-trusted tool forwards, an untrusted one is blocked) and a
  `parse_tools` unit test. Streamable HTTP + rmcp and multi-server namespacing are
  the next step.
- **MCP gateway: trusted tool classification (fail-open closed)** — first step of
  the MCP-proxy generalization (ROADMAP §7.5). `McpServer` now classifies each
  `tools/call` via a trusted `tool-name → ActionKind` map (`with_classifier`);
  a tool **not** in the map is `Other` (the restrictive default), never inferred
  from its name. This closes the latent fail-open the security audit flagged on
  the gateway path (a proxied/upstream tool named `*read*` can no longer be
  auto-allowed) and is the classification foundation the upstream proxy needs.
  The built-in tools are mapped in `guardian mcp`; verified live (read_file→allow,
  run_shell/sneaky_read→blocked) and by a regression test. Upholds new gate §11.8.
- **Usable end to end with Claude Code.** A `coding-agent` policy pack
  (`policies/default/coding-agent.toml`) tuned for an autonomous coding agent
  (reads silent; writes/shell `ask`; destructive shell — `rm -rf /`, pipe-to-shell,
  fork bomb, `mkfs`, `dd … of=/dev/` — plus data exfiltration and credential
  access `deny`; benign `rm -rf ./build` falls through to `ask`). The daemon now
  loads `GUARDIAN_POLICY` (env, consistent with `GUARDIAN_SOCK`) and **refuses to
  start** on an unreadable/invalid policy rather than fall back silently. A ready
  `examples/claude-code/` (settings + README) wires the `PreToolUse` hook to this
  policy. Covered by a policy regression test (compiles + read→allow,
  shell→ask, `rm -rf /`→deny+critical) and verified by a CLI battery.
- **Claude Code `PreToolUse` hook adapter** (`guardian hook`) —
  [`crates/guardian-cli`](../crates/guardian-cli),
  [arch doc](architecture/guardian-cli.md). Reads a Claude Code `PreToolUse`
  payload on stdin and prints the `hookSpecificOutput` permission decision
  (`allow` / `ask` / `deny`), so Guardian mediates Claude Code's **native** tools
  (Bash, Edit, Write, Read, WebFetch, …) — not only the tools it exposes over MCP.
  It maps each native tool to a Guardian `Action` (Read/Glob/Grep → `FileRead`,
  Write/Edit → `FileWrite`, Bash → `Exec` with the command in `args.cmd`,
  WebFetch → `HttpRequest` with the host lifted from the URL) and asks the
  deterministic policy. Unrecognized/MCP/internal tools carry no `kind` hint and
  hit the restrictive default. Always exits 0 with a decision and **never fails
  open**: a parse error or an unreadable policy degrades to `ask` (human decides),
  never a silent `allow`. Covered by golden tests (allow/ask/deny, the mapping,
  URL-host parsing) and fail-safe tests (malformed input → `ask`).

### Implemented — 2026-06-24
- **Workspace & CI scaffold** (ROADMAP Phase 0). Cargo workspace
  (`resolver = "2"`, shared `[workspace.dependencies]`), pinned
  `rust-toolchain.toml`, `deny.toml`, and a GitHub Actions `ci.yml` running
  `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`, and
  `cargo deny check`.
- **`guardian-core` action model** (ROADMAP Task 4.1) —
  [`crates/guardian-core`](../crates/guardian-core),
  [arch doc](architecture/guardian-core.md). The canonical, `serde`-serializable
  action model (`Action`, `ActionKind`, `Capability`, `ActionContext`,
  `ActionId`) and the `Decision` type (`allow` / `ask` / `deny`) with
  `restrictiveness` and `most_restrictive` (the most-restrictive-wins primitive)
  and `Capability::is_critical` for the four critical categories. No I/O, no
  internal deps, `#![forbid(unsafe_code)]` — upholds CLAUDE.md invariant 3.
- **`guardian-policy` deterministic CEL engine** (the security boundary) —
  [`crates/guardian-policy`](../crates/guardian-policy),
  [arch doc](architecture/guardian-policy.md). TOML schema + structural
  validation (`schema.rs`: rejects permissive defaults, duplicate ids, and
  unsupported versions) and a CEL-based evaluator
  (`engine.rs`: `CompiledPolicy::evaluate`) that maps an `Action` to a `Decision`
  as a pure function of (action, context, policy) — no LLM, no I/O (ADR-0003).
  Implements most-restrictive-wins, cap escalation (over-cap → at least `ask`),
  the mandatory restrictive default, and a fail-safe `rule_matches` (only
  `Bool(true)` matches; errors/non-bools never grant access). Covered by
  golden-style + validation tests; a regression guard compiles the shipped
  `policies/default/personal-assistant.toml`.
- **`guardian-audit` tamper-evident log** (ROADMAP Task 6.2) —
  [`crates/guardian-audit`](../crates/guardian-audit),
  [arch doc](architecture/guardian-audit.md). Append-only, blake3 hash-chained
  SQLite log (`AuditLog::append`/`verify`) detecting content edits, reordering,
  middle deletion, and tail truncation (via a recorded chain head). An ed25519
  head signature is left behind the `signing` feature for later.
- **`guardian-checker` advisory translator** (ROADMAP Task 6.3) —
  [`crates/guardian-checker`](../crates/guardian-checker),
  [arch doc](architecture/guardian-checker.md). Async, object-safe `Checker`
  trait returning an `Explanation` (plain text + advisory risk); cannot produce a
  `Decision` (the crate has no dependency on it). Ships a deterministic offline
  `StubChecker`.
- **Review fixes to `guardian-policy`**: caps now fail safe (string-encoded
  amounts handled, and an unverifiable cap escalates to `ask`), `deny_unknown_fields`
  rejects typo'd policy keys, and added `count_max` + serialized-name guard tests.
- **`guardian-mcp-gateway` mediation gateway** (ROADMAP Task 6.4) —
  [`crates/guardian-mcp-gateway`](../crates/guardian-mcp-gateway),
  [arch doc](architecture/guardian-mcp-gateway.md). Normalizes a `ToolCall` into an
  `Action`, evaluates it, records the decision to the audit log, and forwards or
  blocks via the `Upstream`/`Approver` ports. The Checker and human approval run
  **only** for `ask` — the allow/deny fast path makes no LLM call (test-enforced
  with a `PanicChecker`). The MCP/JSON-RPC wire transport plugs in on top next.
- **`guardian` CLI** (ROADMAP Task 6.7, partial) — first runnable binary. `demo`
  runs a scripted scenario end to end (green allow, yellow review+approve, red
  block, unknown→default ask), printing the traffic light and an integrity-checked
  audit log; `policy-validate` compiles a policy file.
- **`guardian-daemon` approval-queue backbone** (ROADMAP Task 6.5) —
  [`crates/guardian-daemon`](../crates/guardian-daemon),
  [arch doc](architecture/guardian-daemon.md). The human-in-the-loop
  `ApprovalQueue` + `QueueApprover`: an `ask` decision enqueues a `PendingApproval`
  and awaits the user's response via `pending()`/`respond()`, **failing closed**
  (Denied) on timeout. A Unix-socket control server (`serve`) exposes
  `call`/`pending`/`respond`/`verify_audit` over newline-delimited JSON, handling
  connections concurrently so a blocked `ask` never blocks a `respond`; the
  `guardian-daemon` binary runs it (`GUARDIAN_SOCK` overrides the path). Verified
  live over the socket and by socket integration tests. Added a `DaemonClient`
  (control-socket client used by the CLI/UI).
- **MCP transport** (ROADMAP Task 6.4, last mile) — `guardian_mcp_gateway::mcp`:
  a JSON-RPC 2.0 MCP server over stdio (`McpServer`) fronting the gateway
  (`initialize`/`tools/list`/`ping`/`tools/call`), so a real MCP client is
  mediated by the policy engine. `Allow` → tool result, `Deny` → JSON-RPC error
  (`-32000`), upstream failure → `isError: true`. The `guardian mcp` CLI command
  runs it; verified live by piping a JSON-RPC session.
- **Desktop UI scaffold** (ROADMAP Task 6.6) — [`ui/`](../ui): a Tauri v2 app whose
  backend exposes `pending`/`respond` commands bridging to the daemon socket via
  `DaemonClient`, with a static traffic-light frontend (polls pending; Allow/Deny).
  No business logic in the UI. Its own cargo workspace, excluded from the main one.
  Compiles with `cargo build` on macOS (placeholder RGBA icon); the static frontend
  is themed to match the TUI (no emoji: bright green/red + dark-green accents, ASCII
  risk bars). Running the window still needs a display; the `DaemonClient` bridge it
  relies on is tested in `guardian-daemon`.
- **Evaluation tooling** (`evaluation/`) — `guardian eval` runs an internal
  red-team suite (labeled actions → confusion matrix; release gate: **0 critical
  false negatives**) and prints a scorecard; on the current 14-case suite:
  precision/recall 100%, FP rate 0%. `guardian decide` returns the policy verdict
  for a tool-call JSON **without executing** — the integration point for the
  AgentDojo shim. Gateway `build_action` exposed for shared classification.
- **End-to-end loop wiring** (ROADMAP Tasks 6.4/6.5) — a `ToolRouter` abstraction
  lets the MCP server front either the in-process gateway or a remote daemon.
  `guardian mcp --daemon <socket>` bridges an MCP client to a running daemon, so
  `ask` decisions reach the daemon's approval queue (and the UI); adds
  `DaemonRouter` + `DaemonClient.call` and a real `LocalToolsUpstream` (actual file
  read/write) replacing the echo. Demonstrated live for both allow and
  ask→approve: MCP client → bridge → daemon → policy → human approval → real
  execution → result.
- **AgentDojo integration** (`evaluation/agentdojo/`) — a `GuardianDefense`
  pipeline element that consults `guardian decide` before each tool call and drops
  denied ones, plus an A/B runner (`run_eval.py`) measuring ASR reduction (with vs.
  without Guardian) on the AgentDojo prompt-injection benchmark. Python; runs with
  an API or local OpenAI-compatible model. Not run in CI (needs the AgentDojo
  package + a model); the integration logic is syntax-checked.
- **AgentDojo defense, token-efficient blocking** (`evaluation/agentdojo/`) — on a
  fully-denied round `GuardianDefense` now returns the policy *reason* as a `tool`
  result (a well-formed answer to the call, so the `ToolsExecutor` executes
  nothing and the denied action never runs) instead of silently dropping the call.
  The agent gets explicit feedback and may try a *compliant* alternative for up to
  `--max-retries` (default 3) blocks per episode, after which the feedback becomes
  a hard stop; `run_eval.py` also caps the tool loop (`--max-iters`, default 10).
  This eliminates the retry loop that ballooned denied episodes (≈18-21 → 7-11
  messages) and wasted the model's tokens — the policy still decides every attempt
  (the reason explains the constraint, never a bypass), so the security guarantee
  is unchanged. Logic covered by an offline test of the feedback + retry budget.
- **Terminal cockpit `guardian ui`** (ROADMAP Task 6.6, primary UI) — a ratatui
  TUI (no emoji, ASCII-styled, keyboard + mouse) that polls the daemon's pending
  queue and relays allow/deny over the socket: a traffic-light list with ASCII
  risk bars, selectable cards, `[A]llow`/`[D]eny` (click or key), `p` panic
  (deny-all pending), a live spinner, and an "all clear" empty state. Thin client
  of `DaemonClient` — no business logic in the UI. Theme: bright green
  (`#2EE66B`) = confirm / low risk, bright red (`#FF4646`) = deny / high risk /
  errors, dark-green (`#206040`) accents. Verified by headless render tests
  (ratatui `TestBackend`). `guardian ui --demo` previews the cockpit with sample
  actions and no daemon. (The Tauri window in `ui/` remains the later GUI.)

### Added
- Docs: `testing-with-claude-code.md` (live-test guide), `owasp-nist-coverage.md`
  (framework coverage matrix), and `architecture/guardian-cli.md` (CLI + TUI).
- Founding design documents: `README.md` (spec), `ROADMAP.md` (build plan with
  reusable implementation prompts), `CLAUDE.md` (always-loaded context and
  invariants).
- `evaluation/README.md` — benchmarking plan (AgentDojo, InjecAgent, ASB,
  AgentHarm, τ-bench) for measuring "agent + Guardian vs agent alone".
- Subagents in `.claude/agents/`: rust-implementer, code-reviewer,
  security-auditor, test-engineer, ui-ux-designer, doc-writer.
- Governance: `LICENSE` (Apache-2.0), `SECURITY.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, `.gitignore`.
- Architecture Decision Records: ADR-0001 (Rust over C), ADR-0002 (act at the
  harness/tool boundary, not the OS kernel), ADR-0003 (deterministic enforcement;
  the LLM Checker is advisory only).
- `docs/threat-model.md` and `docs/policy-schema.md` specs.
- Default policy pack `policies/default/personal-assistant.toml`.

### Changed
- Project renamed from the codename **Sentinel** to **Guardian** (to avoid the
  HashiCorp Sentinel / Microsoft Sentinel naming collision). Crate prefix
  `guardian-*`, CLI `guardian`.
- Spec extended with self-protection (§5.8), kill switch (§5.9), configuration &
  first-run defaults (§5.10), data/storage/privacy (§5.11), and localization
  (§5.12); threat model gained an "agent disables its guardian" row.

### Notes
- First code has landed: Phase 0 (workspace scaffold) plus `guardian-core` and
  `guardian-policy` (see Implemented above). Next up: wiring the engine into an
  adapter and the audit log (`guardian-audit`).
