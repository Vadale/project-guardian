# Guardian × Inspect (UK AISI) — AgentDojo + AgentThreatBench

Runs the **standard** agent-security benchmarks through the UK AI Safety Institute's
[Inspect](https://inspect.aisi.org.uk/) framework with **Guardian as the defense**, so
our numbers are directly comparable to other defenses on the
[`inspect_evals`](https://github.com/UKGovernmentBEIS/inspect_evals) leaderboard.

- **AgentDojo** (Inspect port) — prompt-injection robustness + utility.
- **AgentThreatBench** — the first suite operationalizing the **OWASP Top 10 for
  Agentic Applications (2026)**: autonomy hijack, data exfiltration, memory poisoning —
  i.e. exactly Guardian's threat model.

## How Guardian plugs in
`guardian_approver.py` registers a custom Inspect **`@approver`** that, before any tool
call runs, calls `guardian decide` and **rejects** anything not `allow` (fail-closed).
`guardian_approval.yaml` binds it to every tool (`"*"`). This is the Inspect analogue
of our AgentDojo `GuardianDefense` and the Claude Code / pi hooks — the same
deterministic decision, at Inspect's approval point. (Approver API:
[Tool Approval](https://inspect.aisi.org.uk/approval.html).)

## Setup (one-time, at launch — not while the 12B run holds the RAM)
```sh
cd evaluation/inspect
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install "inspect_evals[agentdojo] @ git+https://github.com/UKGovernmentBEIS/inspect_evals"
cargo build -p guardian-cli            # from repo root, if not already built
```

## Launch
```sh
GUARDIAN_POLICY=$PWD/../agentdojo/banking_policy.toml LIMIT=20 bash run.sh
```
`run.sh` runs a **1-sample smoke first** (to confirm the approver wires up on your
installed Inspect version), then AgentDojo baseline vs +Guardian, then the
AgentThreatBench tasks both ways. Results: `inspect view`.

## Status: SCAFFOLDED, not yet run
This is wired against the documented Inspect API but has **not** been executed here
(it needs the pip install + the model, and we keep heavy installs off the box while
the 12B AgentDojo run is using the RAM). The first launch may need two small tweaks,
flagged inline:
1. **Approver imports** in `guardian_approver.py` — Inspect's module paths shift across
   versions; the 1-sample smoke catches this.
2. **AgentThreatBench task names** in `run.sh` — confirm the exact registered task ids
   from your installed `inspect_evals` (e.g. `inspect eval --help` / the suite listing);
   the placeholders follow the OWASP categories.

Once the smoke passes, the full run is just `bash run.sh`. Keep an eye on RAM/heat with
the 12B (same constraints as `../agentdojo/`).
