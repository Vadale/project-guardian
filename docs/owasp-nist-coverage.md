# Framework coverage: OWASP & NIST

How Guardian maps to recognized AI-security frameworks — honestly, including what
is **covered**, **partial**, **planned**, or **out of scope**. This is a living
document; "tested by" points at the check that exercises a control today.

> Guardian's scope is **mediating an agent's actions** at the tool boundary with a
> deterministic policy, a tamper-evident audit log, and human approval. It does
> not train models, manage prompts, or judge content truth — several framework
> items are therefore out of scope by design.

## OWASP Top 10 for LLM Applications (2025)

| Item | Guardian control | Status | Notes / residual risk | Tested by |
|---|---|---|---|---|
| **LLM01 Prompt Injection** | Evaluates the *real* intercepted action regardless of why the agent wants it; critical categories always `ask`/`deny`; deterministic boundary; Checker never treats agent prose as authority | **Covered (core)** | Coverage is only as complete as interception (raw `exec` needs sandbox/hook) | `guardian eval`, AgentDojo harness |
| **LLM02 Sensitive Information Disclosure** | `deny` exfiltration (secret in a POST to an untrusted host); credentials gated | **Partial** | Full body inspection needs the network proxy (Phase 2) | red-team suite |
| **LLM03 Supply Chain** | Signed policy packs; Guardian's own deps gated by `cargo-deny`/`cargo-audit` | **Partial / planned** | Pack signing is Phase 3 | `cargo deny` in CI |
| **LLM04 Data & Model Poisoning** | — | **Out of scope** | Guardian does not train or fine-tune models | — |
| **LLM05 Improper Output Handling** | Mediates the *actions* an output can trigger (not rendering) | **Partial** | Downstream rendering is the app's responsibility | — |
| **LLM06 Excessive Agency** | Least-privilege roles, capability caps, human approval, kill switch, fail-closed | **Covered (core)** | The central value proposition | `guardian eval`, AgentDojo |
| **LLM07 System Prompt Leakage** | — | **Out of scope** | Guardian doesn't manage system prompts | — |
| **LLM08 Vector & Embedding Weaknesses** | — | **Out of scope** | No RAG/vector store in Guardian | — |
| **LLM09 Misinformation** | — | **Out of scope** | Guardian doesn't assess content truth | — |
| **LLM10 Unbounded Consumption** | Amount caps; per-action review | **Partial / planned** | Rate/budget limits not yet implemented | red-team suite (caps) |

## OWASP Top 10 for Agentic Applications (2026)

| Risk | Guardian control | Status |
|---|---|---|
| Agent goal hijacking (via injection) | Action-level deterministic policy + approval | **Covered** |
| Tool misuse / exploitation | Every tool call is normalized and evaluated | **Covered** |
| Unsafe delegation / privilege | Token broker with macaroon/OAuth caveats | **Planned (Phase 3)** |
| Memory / context poisoning | Evaluates actions, not memory; partial | **Partial** |
| Insufficient oversight / traceability | Tamper-evident audit log + approval cockpit + report | **Covered** |

## NIST AI RMF

| Function | Guardian contribution |
|---|---|
| **Govern** | Declarative policies + roles define allowed agent behavior |
| **Map** | Capability classes + the threat model (`docs/threat-model.md`) |
| **Measure** | The hash-chained audit log + the AgentDojo / red-team evaluation |
| **Manage** | Human approval, fail-closed defaults, kill switch, periodic report |

## Honesty notes
- "Covered" means there is a control **and** a check that exercises it today, not
  that the risk is eliminated — completeness of interception is the standing
  caveat (see `docs/threat-model.md` §6).
- Legal/compliance claims (e.g. EU AI Act) are *assistance*, not certification:
  Guardian helps with transparency and traceability; it does not make a deployer
  compliant.
