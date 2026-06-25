#!/usr/bin/env bash
# Full banking A/B (16 user x 9 injection) on gemma e2b, RAM-safe, token-optimized
# (max-iters 10 + 3-retry blocked-feedback budget). Baseline then Guardian.
set -u
cd "$(dirname "$0")"

MODEL="gemma4:e2b-it-qat"
URL="http://100.103.57.122:11434/v1"
export GUARDIAN_BIN=../../target/debug/guardian
export GUARDIAN_POLICY=banking_policy.toml
PY=.venv/bin/python
COMMON="--model $MODEL --base-url $URL --api-key ollama --suite banking \
  --user-tasks 16 --injection-tasks 9 --max-iters 10 --logdir runs_e2b"

rm -rf runs_e2b e2b_baseline.json e2b_guardian.json

echo "=== BASELINE start $(date '+%H:%M:%S') ==="
$PY run_eval.py $COMMON --out e2b_baseline.json
echo "=== baseline done $(date '+%H:%M:%S') ==="

echo "=== GUARDIAN start $(date '+%H:%M:%S') ==="
$PY run_eval.py $COMMON --with-guardian --block deny --max-retries 3 --out e2b_guardian.json
echo "=== guardian done $(date '+%H:%M:%S') ==="

# Free the model from RAM when finished.
curl -s "$URL/../api/generate" -d "{\"model\":\"$MODEL\",\"keep_alive\":0}" >/dev/null 2>&1 || true
echo "=== ALL COMPLETE $(date '+%H:%M:%S') ==="
