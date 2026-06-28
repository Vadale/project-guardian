# Project Guardian — Threat Model

> Living document. It expands README §7. When the design changes, update this and
> note it in `docs/changelog.md`. Reviewed at every milestone (see `evaluation/`).

## 1. Purpose & scope
Guardian mediates the actions of an autonomous AI agent on behalf of a user,
across local (files, shell) and online (network, services) operations. This
document states what we protect, who the adversaries are, and how each threat is
addressed. Enforcement is deterministic (ADR-0003) and applied at the agent's
action boundary (ADR-0002).

## 2. Assets to protect
- **User data & systems:** files, credentials, money, accounts, devices.
- **The decision boundary:** the integrity of allow/deny outcomes.
- **The audit log:** its completeness and tamper-evidence.
- **Brokered credentials:** tokens/secrets Guardian holds on the user's behalf.
- **Policies & policy packs:** their authenticity and integrity.
- **User trust / informed consent:** the human must understand what they approve.

## 3. Actors & trust boundaries
- **User (trusted):** sets policy, approves/denies, holds the kill switch.
- **Maker agent (untrusted):** the third-party agent doing the task.
- **Tool/MCP servers & the web (untrusted):** sources of actions and of injected
  content.
- **Guardian (trusted core):** the only path from the agent to the world; the
  highest-value target precisely because it is trusted.

Trust boundary: **everything the agent produces or ingests is untrusted**;
Guardian evaluates structured actions, never the agent's prose.

## 4. Assumptions
- The host is not already fully compromised at root/admin level.
- The agent runs with **lower privilege** than the Guardian daemon and cannot stop
  it, alter the proxy CA, or edit the active policy.
- The OS keychain / Secure Enclave / TPM behaves as specified.
- The user reads the kill switch and critical-category prompts (we minimize how
  often these fire, to keep attention meaningful — see click-fatigue defense).

## 5. Adversaries, vectors, and defenses

### 5.1 Hallucinating / misaligned agent
Issues a wrong or destructive action in good faith. **Defense:** deterministic
policy; `ask` for anything irreversible; Checker translation so the human catches
it; most-restrictive-wins evaluation.

### 5.2 Prompt injection (primary threat)
Instructions hidden in a web page, PDF, email, or tool result hijack the agent.
**Defense:** the policy evaluates the *real* action regardless of *why* the agent
wants it; critical categories are always `ask`/`deny`; the Checker never treats
attacker-controlled prose as authority; optional LLM-gateway sanitization of tool
results. Maps to OWASP LLM01.

### 5.3 Compromised / malicious MCP server or tool
A tool lies about what it does or exfiltrates. **Defense:** Guardian sees the
actual call/args and the actual network egress via the proxy — not the tool's
self-description; egress allow-lists; provenance recorded in the log.

### 5.4 Malicious policy pack (supply chain)
A community pack silently whitelists an exfiltration path. **Defense:** packs are
ed25519-signed; loader refuses unsigned/altered packs; a pack can **not** widen a
critical category without explicit user opt-in; pack provenance is logged. Maps to
OWASP LLM03.

### 5.5 Attack on Guardian itself
Tamper with policy, steal brokered credentials, or forge the log. **Defense:**
sealed keys (Secure Enclave/TPM), signed/locked policy, hash-chained log,
notarized builds, fail-closed defaults.

### 5.6 Agent disables / bypasses its guardian
Kill the daemon, remove the proxy CA, or route around the gateway. **Defense
(README §5.8):** Guardian is the agent's *only* path to tools, so no decision means
no action (**fail closed**); the agent lacks the privilege to stop the daemon or
alter CA/policy; supervised restart; a bypass attempt is recorded as a log gap.
Maps to OWASP Agentic "tool misuse" / "goal hijacking".

### 5.7 Habituation attack
Train the adaptive layer to auto-allow, then strike. **Defense:** critical
categories are never auto-downgraded; suggestions are context-bound and decay;
learning is opt-in and surfaced in the report, never silent.

### 5.8 Excessive agency / over-broad delegation
The agent is granted more authority than the task needs. **Defense:** least-
privilege roles; macaroon/OAuth caveats (expiry, amount caps, allowed hosts);
critical-capability use always requires a fresh approval. Maps to OWASP LLM06.

### 5.9 Click fatigue (consent erosion)
Too many prompts → the human approves blindly, nullifying safety. **Defense:**
deterministic green fast-path runs silently; only genuine `ask` items prompt;
plain-language Checker explanations; low-risk actions batched into the periodic
report. This is treated as a security control, not just UX.

### 5.10 Malicious user
Tries to use agent + Guardian for harmful ends. **Out of scope** for "protect the
user," but provenance/logging makes misuse attributable.

## 6. Residual risks (acknowledged)
- Interception completeness depends on covering every capability channel; an
  uncovered raw-exec path is the main residual risk (mitigated by sandbox + proxy).
- A deterministic policy can still encode a bad rule; hence golden tests, review,
  and the FP/FN metrics in `evaluation/`.
- Adaptive attacks may defeat static rules over time → scheduled red-teaming.
- The Checker, if remote, is a network/privacy path → off by default, opt-in,
  per-action, logged.
- **Exec sandbox strength (`guardian-sandbox`, §7.3) is a backstop, not isolation,
  and is asymmetric across platforms.** Today the **macOS** profile (`(allow default)`
  base) contains only **outbound network** and **filesystem writes** — reads,
  `process-exec`, mach lookups and IPC stay allowed, so it is *not* process/IPC
  isolation. **Linux** (`bubblewrap`) is stronger (read-only root + network
  namespace) but still shares the host PID/IPC namespaces and sets no resource
  limits (a sandboxed command can fork-bomb or fill the writable temp). Tracked
  hardening: a deny-by-default macOS SBPL profile, `--unshare-pid/ipc` and rlimits
  on Linux, and stricter validation of operator-supplied writable paths before they
  are interpolated into the SBPL profile. Until then the **policy** should keep
  `Exec` at `ask` or deny by default (exec is opaque: it carries no capability, so
  the critical-category floor is not structurally enforced for it).
- **Sandbox widening is operator-controlled, not policy-controlled (yet).** The
  `guardian exec` `--allow-network` / `--writable` flags relax the sandbox; they are
  operator inputs (the agent only supplies the command after `--`). A harness must
  not let the agent compose these flags. Moving the widening into the policy rule is
  tracked.
- **WebSocket frame content over the proxy is not inspected** (the upgrade host is
  policed; frames are not) — an allowed WS host is an unmediated channel until
  frame inspection lands (§7.1 increment 4).
- **Exfiltration body scan is framing- and size-limited.** The proxy buffers and
  scans a request body only when it has a `Content-Length` ≤ 1 MiB; a chunked /
  no-`Content-Length` / oversize body is forwarded with `body_contains_known_secret =
  false`, so the secret-exfiltration rule does **not fire** on it (it still falls to
  the restrictive default — fail safe, not open). The `action.context.extra.
  body_inspected` signal is exposed so a strict policy can require inspection for
  writes to untrusted hosts; streaming-scan up to the cap is tracked.
- **Daemon control socket is owner-only, not multi-user-hardened beyond that.** The
  socket is set to `0o600` so only the owner can connect (approve asks / toggle the
  kill switch); a *different* local user cannot. A fully-compromised **same-user**
  process is out of scope (it could connect, as it could read the keychain). The
  default path is a per-user temp socket; `GUARDIAN_SOCK` overrides it.
- **Broker keychain at-rest protection is the platform's.** Secrets stored via the
  OS keychain (§8.1) are only as protected as the platform's at-rest encryption and
  ACLs. On macOS the generic-password item is readable by any process running as the
  **same user** once the keychain is unlocked (Guardian sets no per-app ACL) —
  consistent with the model that Guardian and the agent are user-space peers and a
  fully-compromised same-user process is out of scope. In-memory secrets are not yet
  zeroized on drop (tracked for the macaroon work); no regression over the V1 file
  store.

## 7. Framework mapping
- **OWASP Top 10 for LLM Applications (2025):** LLM01 Prompt Injection, LLM02
  Sensitive Info Disclosure, LLM03 Supply Chain, LLM05 Improper Output Handling,
  LLM06 Excessive Agency.
- **OWASP Top 10 for Agentic Applications (2026):** goal hijacking, tool misuse,
  memory/context poisoning, unsafe delegation.
- **NIST AI RMF:** the audit log + report serve Measure/Manage; policy + roles
  serve Govern/Map.

Maintain the detailed control→item→test matrix alongside this file as the
implementation lands (owned by `doc-writer`; see `evaluation/README.md` §5).
