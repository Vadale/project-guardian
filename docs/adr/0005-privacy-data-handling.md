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
1. **Tokenization (data broker) and output-DLP → integrate, do not build.** Use
   off-the-shelf, self-hosted, MIT-licensed engines:
   - **LLM Guard** (Protect AI) — `Anonymize` input scanner (PII → placeholders, real
     values held in a Vault) + `Deanonymize` output scanner (restore at egress). This is
     the *Anonymize → agent → De-anonymize* pattern verbatim.
   - **Microsoft Presidio** — the underlying detection + reversible anonymization engine.
   - Optional persistent vault (beyond a session): **Databunker** / **Open Privacy Vault**.
   They run as a **sidecar service** (they are Python; Guardian is Rust) called over a
   process/HTTP boundary at Guardian's existing **inbound "sanitize tool results" hook**
   (§5.1, tokenize before the agent sees the data) and an **outbound output-guard**
   (redact before a response leaves). No Rust dependency, no `cargo-deny` license edge.
2. **Guardian owns what the libraries do not:** the **deterministic policy** deciding
   *when/what* to tokenize or detokenize, **trusted custody** of the token↔value vault
   and keys (the broker generalized), **agent-agnostic interception**, and the
   **tamper-evident audit**. Guardian is the orchestrator + enforcement + audit; the
   libraries are the detection/anonymization engine. They are complementary, not competing.
3. **Scoping rule (load-bearing):** tokenize values that are **carried** (identifiers
   inserted into a form / message / call — name, IBAN, phone, email, bank name), **not**
   content the agent must **reason over** (a document to summarise, a decision input).
   Over-tokenizing breaks the agent; under-tokenizing leaks. (Industry mitigates with a
   semantic-boundary classifier; we inherit that problem, we do not escape it.)
4. **Context-window minimization is the agent/harness's job, not Guardian's.** Guardian
   does not own the model's context. Its contribution is (a) the inbound tokenization
   above and (b) its **append-only log as durable external memory** the integration may
   recall from. We will *not* try to make the model "forget," which conflicts with the
   agent's need to chain steps.
5. **Build our own only as a fallback** if integration proves infeasible — and even then,
   thinly (the vault + a redaction shim), never reinventing NER.

## Consequences
- **No reinvention** of a mature, MIT category; Guardian stays the thin, auditable,
  deterministic core. Aligns with README §9 ("off-the-shelf backstops, not the primary
  control") and invariant #6.
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
