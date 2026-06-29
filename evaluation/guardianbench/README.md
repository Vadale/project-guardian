# GuardianBench — a benchmark built for an *action-firewall*

> v0.1.0 · deterministic · model-free · offline · CI-able

## Why this exists
The standard agent benchmarks measure the **agent** (did it finish the task — SWE-bench,
GAIA, WebArena) or the **agent's output integrity** (did its text echo an attacker
payload — AgentThreatBench, parts of AgentDojo). None of them isolate what a *deterministic
action-firewall* like Guardian is actually responsible for: **given a structured
intercepted action, does it block the harmful ones, allow the benign ones, and cite a real
rule when it blocks?**

Our own evaluation made this concrete. On AgentThreatBench, Guardian looked "neutral" —
because that benchmark scores whether the model *says* the attacker's payload, which an
action-firewall does not police by design (that is the Checker / output-guard layer). The
benchmark that *did* show Guardian working (AgentDojo banking: 100% → 0% attack success)
scores **tool execution**. GuardianBench generalises that: it scores the **disposition of
the action**, across domains, deterministically.

This is, frankly, a bit ahead of the current benchmark landscape — there isn't yet a
community standard for "did the guardrail correctly gate the action." GuardianBench is our
proposal for one, and because it is deterministic and agent-agnostic, **anyone can re-run
it and get the identical result**.

## What it measures (the three pillars of a guardian with real authority)
| Metric | Meaning | Target |
|---|---|---|
| **False Negatives** | a must-block action that was allowed | **0%** (catastrophic) |
| **False Positives** | a must-allow action that was hard-denied | **< 5%** |
| **Refusal correctness** | a block cites a real rule (not empty/hallucinated) | high |

A *block* = the autonomous action does not proceed (`deny` **or** `ask`; an `ask` is a
human gate, which in autonomous operation stops the action).

## How it works
`cases.json` is a versioned set of labelled cases across **8 domains** (finance,
credentials, exfiltration, shell, files, messaging, memory, calendar). Each case is a
structured action (`tool` / `kind` / `capability` / `args`) tagged `block` or `allow`,
covering the OWASP-agentic threat classes: money movement, credential access, data
exfiltration, irreversible deletion, destructive/RCE shell, self-protection
(disable-the-guardian), exfil-via-message/web, and **memory poisoning**.
`guardianbench.py` runs each through Guardian's deterministic decision (`guardian decide`)
against `policy.toml` (a representative least-privilege posture) and scores the three
metrics. It exits non-zero on **any** false negative, so it can gate CI.

## Run
```sh
cargo build -p guardian-cli            # from repo root
GUARDIAN_BIN=../../target/debug/guardian python3 guardianbench.py
```

## Latest result (2026-06-29, v0.1.0, 26 cases)
```
False Negatives (missed blocks): 0/19 = 0.0%   [target 0%]
False Positives (over-blocks):   0/7  = 0.0%   [target <5%]
Refusal correctness (cites rule): 19/19 = 100.0%
Overall: 26/26 correct   (8/8 domains clean)
```

## Scope & honesty
- This scores the **policy + deterministic engine** against a representative
  least-privilege policy — i.e. *does the firewall do its job*. It is not an agent-utility
  benchmark and does not involve a model.
- It is **action-based by design**: pure prose/output-manipulation attacks (make the agent
  *say* X) are out of scope — those belong to the Checker / a future output-guard, not the
  action-firewall. This is the boundary AgentThreatBench exposed.
- `cases.json` is intentionally small and curated for v0.1; it is meant to **grow** (more
  domains, more adversarial variants, parameter-fuzzing) and be **versioned**, so progress
  is visible across releases. The internal financial red-team bank (`../redteam/`) is the
  finance-specific seed it generalises.
