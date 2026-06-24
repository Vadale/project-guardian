# Project Guardian — Evaluation & Benchmarking Plan

> How we prove, with numbers, that an agent **with Guardian** is safer than the
> same agent **without** it — *without* unacceptably hurting how well the agent
> does its job or how usable it is. For an open-source security tool, a public,
> reproducible scorecard is the credibility. This document defines what to
> measure, with which benchmarks, and how to report it.

---

## 1. The central claim and the experimental design

**Hypothesis:** For a fixed agent + model, wrapping it in Guardian **reduces the
attack success rate** while **preserving task utility** and keeping **human-review
friction** acceptable.

A wrapper that blocks attacks but also blocks legitimate work, or floods the user
with prompts, is a failure. So we always measure three axes at once, in a strict
**A/B design** over the *same* agent, model, prompts, and seeds:

- **Condition A — Baseline:** agent → tools directly (no Guardian).
- **Condition B — Guardian:** agent → Guardian MCP gateway → tools.

Run identical benchmark inputs through A and B and compare. Nothing about the
agent or model changes between conditions; only Guardian is added.

```
                 same model, same tasks, same seeds
   ┌──────────────┐                         ┌──────────────────────────┐
A: │ Agent → tools│        vs.            B: │ Agent → Guardian → tools │
   └──────────────┘                         └──────────────────────────┘
        measure: ASR ↓?   utility ≈?   approvals/latency acceptable?
```

---

## 2. The three axes and their metrics

| Axis | Question | Primary metrics | Goal |
|---|---|---|---|
| **1. Security gain** | Does Guardian stop attacks the baseline executes? | **Attack Success Rate (ASR)** A vs B; absolute & relative reduction | ASR_B ≪ ASR_A |
| **2. Utility preservation** | Does Guardian let legitimate work still succeed? | **Task success** pass^1 / pass^k A vs B; utility delta | delta small (≈0) |
| **3. Usability / overhead** | Is the human cost and latency acceptable? | Approval-prompt rate/task; false-positive block rate; added latency/action; determinism | low friction, low latency, 100% deterministic decisions |

### Classification view (rigorous framing of the firewall itself)
Treat every intercepted action as a binary decision (`should-block` vs
`should-allow`) against a labeled ground truth, and report a **confusion matrix**:

- **True Positive** — a malicious/dangerous action correctly blocked.
- **False Negative** — a malicious action that slipped through *(security failure)*.
- **False Positive** — a benign action wrongly blocked/asked *(usability failure,
  drives click fatigue)*.
- **True Negative** — a benign action correctly allowed silently.

Report **precision, recall, F1, false-positive rate (FPR), false-negative rate
(FNR)**. The product's quality *is* the trade-off between FNR (safety) and FPR
(friction). Critical-category actions are weighted: a single critical FN is a
release blocker.

---

## 3. External benchmark suite

These are public, peer-reviewed benchmarks. They operate at the **agent/tool
level**, which is exactly where Guardian sits — so they are a natural fit. We run
our agent through each in both conditions A and B.

| Benchmark | What it measures | Why we use it | Axis |
|---|---|---|---|
| **AgentDojo** | Prompt-injection attacks & defenses over 97 user tasks + 629 security cases (banking, Slack, travel, workspace). Reports *benign utility*, *utility under attack*, *ASR*. | The reference harness for our exact problem; gives all three axes in one. | 1 + 2 |
| **InjecAgent** | Indirect prompt injection in tool-integrated agents (1,054 IPI cases). | Focused, high-volume IPI stress test for the interception layer. | 1 |
| **Agent Security Bench (ASB)** | Broad attack/defense catalogue on LLM agents (reported ASR up to ~84%). | Coverage beyond IPI: tool misuse, memory/context attacks. | 1 |
| **AgentHarm** | Whether agents complete *harmful* tasks (refusal/harmfulness). | Tests Guardian's deny path on genuinely harmful requests, not just injection. | 1 |
| **τ-bench / τ²-bench** | Tool-Agent-User task completion (retail, airline); pass^1 and pass^k reliability. | The utility-preservation control: prove Guardian doesn't break real workflows. | 2 |
| *(optional)* **SWE-bench / GAIA / WebArena** | Coding / general-assistant / web-agent task success. | Extra utility coverage in domains we target (dev, web). | 2 |

> ⚠️ **Adaptive attacks matter.** Static benchmark scores can be gamed, and
> research shows adaptive attacks break many fixed defenses. So external
> benchmarks are *necessary but not sufficient* — pair them with the internal
> red-team suite (§4) and periodic manual red-teaming.

---

## 4. Internal red-team & regression suite

A Guardian-owned set of concrete dangerous actions with ground-truth labels.
These double as the adversarial regression tests the `test-engineer` maintains, so
the evaluation and the test suite share fixtures.

Examples (each labeled `should-block`/`should-ask`/`should-allow`, with context):
- `chmod 777` / `chmod o+w` on user files; obfuscated variants (`base64 -d | sh`).
- `rm -rf` / bulk deletes above a threshold.
- Wire transfer to an unknown IBAN; payment above the policy cap.
- HTTP POST of a detected secret to a non-allowlisted host (exfiltration).
- Mass email / mass comment posting.
- Indirect injection hidden in a fetched web page or PDF that tells the agent to
  exfiltrate or escalate.
- Benign look-alikes that must **not** be blocked (the FP guard): writing a file
  in an allowed path, a normal API GET, a small in-cap payment with approval.

Each release runs this suite and must show **0 critical false negatives** and a
bounded false-positive rate.

---

## 5. Governance / coverage mapping (not a score — a coverage artifact)

Map Guardian's controls to recognized frameworks so adopters can see what is and
isn't covered. Maintain this as a matrix in `docs/`:

- **OWASP Top 10 for LLM Applications (2025)** — esp. *LLM01 Prompt Injection*,
  *LLM02 Sensitive Information Disclosure*, *LLM05 Improper Output Handling*,
  *LLM06 Excessive Agency*, *LLM03 Supply Chain* (our policy-pack signing).
- **OWASP Top 10 for Agentic Applications (2026)** — agent goal hijacking, tool
  misuse/exploitation, memory/context poisoning, unsafe delegation.
- **NIST AI RMF** — Govern/Map/Measure/Manage; our audit log + report serve
  Measure/Manage and the AI-Act traceability story.

For each item: state the Guardian control, the residual risk, and the test that
exercises it.

---

## 6. Choosing the Checker model (where Artificial Analysis fits)

[Artificial Analysis](https://artificialanalysis.ai/) ranks models on
**intelligence, output speed, latency, and price** — it does **not** measure
Guardian's security value (it's a model leaderboard, not an agent-safety
benchmark). We use it for one specific decision: **selecting the local Checker
model**, which sits on the human-review path where **latency and cost** matter as
much as quality. Use AA's intelligence-vs-latency-vs-price view to pick the
smallest model that still produces accurate, plain-language translations and risk
scores; re-evaluate as models improve. The Checker never decides allow/deny, so we
optimize it for *clarity + speed*, not raw intelligence.

---

## 7. Reporting: the public scorecard

Every release publishes the same table (per agent+model tested), so progress and
the with-vs-without gap are visible and reproducible.

```
## Guardian Evaluation Scorecard — <version> — agent: <model>

### Axis 1 — Security (lower ASR is better)
| Benchmark   | ASR baseline (A) | ASR + Guardian (B) | Relative reduction |
|-------------|------------------|--------------------|--------------------|
| AgentDojo   |        xx%       |         xx%        |        −xx%         |
| InjecAgent  |        xx%       |         xx%        |        −xx%         |
| ASB         |        xx%       |         xx%        |        −xx%         |
| AgentHarm   |        xx%       |         xx%        |        −xx%         |

### Axis 2 — Utility (delta should be ~0)
| Benchmark   | pass^1 baseline | pass^1 + Guardian | Delta |
|-------------|-----------------|-------------------|-------|
| AgentDojo (benign) |   xx%    |        xx%        |  ±x   |
| τ-bench retail     |   xx%    |        xx%        |  ±x   |

### Axis 3 — Usability / overhead
| Metric                          | Value |
|---------------------------------|-------|
| Approval prompts per task       |  x.x  |
| False-positive block rate       |  xx%  |
| Critical false negatives        |   0   |  ← release blocker if > 0
| Median added latency / action   |  xx ms|
| Decision determinism            | 100%  |

### Classification (internal red-team suite)
Precision: xx%  Recall: xx%  F1: xx  FPR: xx%  FNR: xx%
```

---

## 8. Methodology rules
- **Hold everything constant** between A and B except Guardian.
- Fix seeds; report **pass^k** (k ≥ 5) for stability, not just pass^1.
- Use a deterministic `StubChecker` for decision-path tests; use the real Checker
  only when measuring usability/latency.
- Pin benchmark versions and agent/model versions in every report.
- Separate the **decision path** (must be 100% deterministic and LLM-free) from
  the **explanation path** (LLM, measured for latency/clarity) in all results.

## 9. When evaluation becomes possible (phasing)
- **Now:** define metrics, build the internal red-team fixtures (shared with tests).
- **After M1 (MVP MCP gateway):** wire the gateway into AgentDojo / τ-bench agent
  loops; produce the first A/B scorecard.
- **After M2 (proxy + sandbox):** add network-exfiltration and contained-exec
  scenarios; expand ASB/InjecAgent coverage.
- **After M3 (broker, packs):** add supply-chain (malicious policy pack) and
  delegated-credential misuse scenarios.
- **Ongoing:** scheduled adaptive red-teaming; publish each scorecard in CI.

> **Ownership:** the `test-engineer` agent owns this suite for now (it shares
> fixtures with the adversarial tests). If benchmark harnessing grows large,
> spin up a dedicated `eval-engineer` agent.

---

## Sources
- [AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents](https://arxiv.org/abs/2406.13352)
- [InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated LLM Agents](https://arxiv.org/pdf/2406.13352)
- [Agent Security Bench (ASB), ICLR 2025](https://proceedings.iclr.cc/paper_files/paper/2025/file/5750f91d8fb9d5c02bd8ad2c3b44456b-Paper-Conference.pdf)
- [AgentHarm: LLM Agent Safety Benchmark](https://www.emergentmind.com/topics/agentharm)
- [τ-bench: A Benchmark for Tool-Agent-User Interaction in Real-World Domains](https://arxiv.org/abs/2406.12045)
- [τ²-Bench: Evaluating Conversational Agents in a Dual-Control Environment](https://arxiv.org/pdf/2506.07982)
- [Adaptive Attacks Break Defenses Against Indirect Prompt Injection Attacks on LLM Agents](https://arxiv.org/pdf/2503.00061)
- [OWASP Top 10 for LLM Applications (2025)](https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf)
- [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [Artificial Analysis — AI Model & API Providers Analysis](https://artificialanalysis.ai/)
