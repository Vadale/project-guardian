# ADR-0005 — Privacy data-handling: integrate PII tokenization + output-DLP; Guardian owns policy, vault custody, and audit

**Status:** Proposed (2026-06-29). Direction accepted; implementation deferred (roadmap).

## Context
The multi-suite evaluation made a scope boundary concrete (see `docs/threat-model.md`
§5.4/§7 and the AgentThreatBench finding in `evaluation/`): **Guardian mediates
*actions*, not the agent's *prose*.** Two residual exposures follow:

1. **The agent's accumulated context is sensitive.** The token broker (§5.6) keeps the
   *literal* secrets — credentials, card numbers, codice fiscale — out of the agent. But
   over a session the agent's context still fills with **derived/observed** data it read
   to do its job: balances, document contents, purchase details, and the activity
   timeline itself. If the agent is hijacked, or a non-owner converses with it, that
   context can be revealed.
2. **Exfiltration still needs a channel.** For any of that data to reach an attacker it
   must cross a message / network / file = an **action**, which Guardian already gates.
   "A non-owner talking to the agent" is the host app's authN/authZ, not Guardian's layer.

Three candidate mitigation layers were considered: (1) a **data broker / tokenization**
(generalize the credential broker so *any* carried sensitive value becomes an opaque
reference the agent holds but cannot read), (2) an **output-guard / DLP** (redact
sensitive patterns from the agent's responses), (3) **context-minimization** (scope/reset
the agent's working memory per task, using Guardian's log as durable recall).

A prior-art scan (Presidio, LLM Guard, data-privacy vaults) showed these are a **mature,
MIT-licensed, self-hosted** category — not something to reinvent.

## Decision
**Split the work by criticality** — own the simple, security-critical part in Rust;
delegate the hard, ML, advisory part to an off-the-shelf sidecar. Do **not** embed a
Python ML stack into the deterministic Rust core, and do **not** fork the engines.

1. **Vault + structured-PII tokenization → own it, in native Rust, inside Guardian.**
   This is the security-critical, *simple* part, and it is the **broker generalized** from
   credentials to any carried sensitive value. The values we tokenize are **carried
   identifiers** (IBAN, card, phone, email, account number, bank name) which are
   **structured / regex-detectable**, so a small native Rust module does it with **no
   Python**: tokenize at the inbound "sanitize tool results" hook (§5.1), hold the
   token↔value map in the broker's keychain-backed custody, detokenize **only** into the
   authorized egress action. This is exactly the "manage it directly in Guardian" we want.
2. **Fuzzy NER on free text + output-DLP → optional sidecar (do not build, do not embed).**
   Detecting names/PII in free-form prose is the hard ML part where the mature engines earn
   their keep — **Microsoft Presidio** (MIT; detection + reversible anonymization) and/or
   **LLM Guard** (MIT; `Anonymize`/`Deanonymize` + Vault). They are **Python**; Guardian is
   **Rust** → run them as a **sidecar** called over a process/HTTP boundary (no Rust
   dependency, no `cargo-deny` edge). This layer is **advisory**: a miss fails safe to the
   restrictive default + the deterministic secret-exfiltration **deny rule** backstop, so it
   must **not** live in the deterministic core. Extend them via their **plugin APIs**
   (Presidio recognizers, LLM Guard scanners/vault) rather than **forking** — a fork would
   saddle us with tracking their upstream security patches.
3. **Guardian owns what the libraries do not:** the **deterministic policy** deciding
   *when/what* to tokenize or detokenize, **trusted custody** of the token↔value vault and
   keys (the broker), **agent-agnostic interception**, and the **tamper-evident audit**.
   Guardian is the orchestrator + enforcement + audit + the Rust vault; the sidecar is only
   the fuzzy-detection engine. They are complementary, not competing.
4. **Scoping rule (load-bearing):** tokenize values that are **carried** (identifiers
   inserted into a form / message / call — name, IBAN, phone, email, bank name), **not**
   content the agent must **reason over** (a document to summarise, a decision input).
   Over-tokenizing breaks the agent; under-tokenizing leaks. (Industry mitigates with a
   semantic-boundary classifier; we inherit that problem, we do not escape it.)
5. **Context-window minimization is the agent/harness's job, not Guardian's.** Guardian
   does not own the model's context. Its contribution is (a) the inbound tokenization
   above and (b) its **append-only log as durable external memory** the integration may
   recall from. We will *not* try to make the model "forget," which conflicts with the
   agent's need to chain steps.

## Alternatives considered
- **Fork + embed the engines directly into Guardian.** Rejected for the *detection* part:
  Presidio/LLM Guard are Python, so "embedding" means either a full Rust reimplementation
  (years of NER work) or shipping a Python interpreter + hundreds of MB of ML models inside
  the deterministic Rust core (PyO3) — bloating the small, fast, auditable security boundary
  with a non-auditable ML dependency. A fork also means owning their upstream security
  patches. We instead **own the simple critical part (vault + structured tokenization) in
  native Rust** and treat the fuzzy detector as a replaceable advisory sidecar.
- **Make the model "forget" between actions.** Rejected: conflicts with the agent's need to
  chain steps; and Guardian does not own the model's context (it is the agent/harness's layer).

## Consequences
- **Right-sized ownership.** Guardian owns the *simple critical* part (vault + structured
  tokenization) in native Rust — auditable, fast, no Python — and does **not reinvent** the
  hard ML detection (delegated to a replaceable MIT sidecar). Aligns with README §9
  ("off-the-shelf backstops, not the primary control") and invariant #6 (user-space, thin
  core).
- **Invariant #1 preserved:** detection/redaction is advisory-grade and stays **off** the
  deterministic allow/deny path; the existing secret-exfiltration **deny rule remains the
  deterministic backstop**. Tokenization is "minimize what the agent holds" — the data
  twin of the broker ("you can't reveal what you only hold as a reference").
- **Costs / honest limits:**
  - Inherits the **classification problem** (false positives over-redact and break the
    agent; false negatives leak) — mitigated by the carried-vs-reasoned scoping, not solved.
  - The **reasoned-over residual remains**: content the agent legitimately must understand
    is seen in clear; no tool eliminates this. Bounded by least-privilege + channel-gating.
  - A sidecar adds an **operational dependency and latency on the data path**, so it is
    **opt-in / configurable** and never on the green fast-path of pure action decisions.
  - The **token↔value vault becomes a high-value asset** (same trust model as the broker).
- **Open questions:** exact placement of the inbound hook per adapter; reliable
  carried-vs-reasoned classification; per-session vs persistent vault.

See `docs/threat-model.md` §5.4/§5.6/§7 (output-leak row) and the build-vs-integrate
table in this decision; tracked on the roadmap.
