#!/usr/bin/env bash
# Launch AgentDojo (Inspect port) and AgentThreatBench with Guardian as the defense,
# using the local 12B via Ollama. Run from this directory after the one-time setup.
#
# Guardian is wired in as an Inspect *approver* (guardian_approver.py +
# guardian_approval.yaml): every tool call is gated by `guardian decide`. This puts
# our numbers on the SAME metric as the inspect_evals leaderboard -> comparable to
# other defenses.
set -euo pipefail

# --- one-time setup (do this at launch, NOT while the 12B run is using the RAM) ---
#   python -m venv .venv && source .venv/bin/activate
#   pip install -r requirements.txt
#   pip install "inspect_evals[agentdojo] @ git+https://github.com/UKGovernmentBEIS/inspect_evals"

export GUARDIAN_BIN="${GUARDIAN_BIN:-$PWD/../../target/debug/guardian}"
export GUARDIAN_POLICY="${GUARDIAN_POLICY:-$PWD/../agentdojo/banking_policy.toml}"
# Ollama (OpenAI-compatible) — same endpoint the AgentDojo harness uses.
export INSPECT_EVAL_MODEL="${INSPECT_EVAL_MODEL:-ollama/gemma4:12b-mlx}"
export OLLAMA_BASE_URL="${OLLAMA_BASE_URL:-http://100.103.57.122:11434}"
LIMIT="${LIMIT:-20}"   # cap samples for a bounded run (raise for larger n)

echo ">>> SMOKE (1 sample) — confirm the Guardian approver wires up before the full run"
inspect eval inspect_evals/agentdojo --limit 1 --approval guardian_approval.yaml

echo ">>> AgentDojo — baseline (no Guardian)"
inspect eval inspect_evals/agentdojo --limit "$LIMIT" --log-dir logs/agentdojo_baseline

echo ">>> AgentDojo — + Guardian"
inspect eval inspect_evals/agentdojo --limit "$LIMIT" --approval guardian_approval.yaml --log-dir logs/agentdojo_guardian

echo ">>> AgentThreatBench (OWASP Agentic Top-10) — baseline vs + Guardian"
# Task names per inspect_evals (verify with: inspect eval-set --help / the suite listing).
for task in agent_threat_bench_autonomy_hijack agent_threat_bench_data_exfiltration agent_threat_bench_memory_poison; do
  inspect eval "inspect_evals/$task" --limit "$LIMIT" --log-dir "logs/${task}_baseline" || true
  inspect eval "inspect_evals/$task" --limit "$LIMIT" --approval guardian_approval.yaml --log-dir "logs/${task}_guardian" || true
done

echo ">>> done — view results with:  inspect view"
