#!/usr/bin/env python3
"""Run inspect_evals tasks (AgentDojo + AgentThreatBench) with/without Guardian.

Guardian is applied via the Python eval() API by passing our approver as an
ApprovalPolicy object (no registry-name resolution needed). Usage:

    python run_inspect.py <task> <baseline|guardian> <limit>

<task> in: agentdojo, autonomy_hijack, data_exfil, memory_poison
Env: INSPECT_EVAL_MODEL, OLLAMA_BASE_URL, GUARDIAN_BIN, GUARDIAN_POLICY
"""
from __future__ import annotations

import importlib
import os
import sys

from inspect_ai import eval as inspect_eval
from inspect_ai.approval import ApprovalPolicy

from guardian_approver import guardian_approver  # registers @approver + factory

# task key -> (module, function, kwargs)
TASKS = {
    # no sandbox tasks -> no Docker/colima needed
    "agentdojo": ("inspect_evals.agentdojo", "agentdojo", {"with_sandbox_tasks": "no"}),
    "autonomy_hijack": ("inspect_evals.agent_threat_bench", "agent_threat_bench_autonomy_hijack", {}),
    "data_exfil": ("inspect_evals.agent_threat_bench", "agent_threat_bench_data_exfil", {}),
    "memory_poison": ("inspect_evals.agent_threat_bench", "agent_threat_bench_memory_poison", {}),
}


def main() -> int:
    task_key = sys.argv[1]
    mode = sys.argv[2]  # baseline | guardian
    limit = int(sys.argv[3]) if len(sys.argv) > 3 else 1

    mod, fn, kwargs = TASKS[task_key]
    task = getattr(importlib.import_module(mod), fn)(**kwargs)

    approval = None
    if mode == "guardian":
        pol = os.environ.get("GUARDIAN_POLICY")
        approval = [ApprovalPolicy(approver=guardian_approver(policy=pol), tools="*")]

    msg_limit = int(os.environ.get("INSPECT_MSG_LIMIT", "20"))
    time_limit = int(os.environ.get("INSPECT_TIME_LIMIT", "300"))  # per-sample wall cap (s)
    logs = inspect_eval(
        task,
        model=os.environ.get("INSPECT_EVAL_MODEL", "ollama/gemma4:12b-mlx"),
        model_base_url=os.environ.get("INSPECT_MODEL_BASE_URL"),
        approval=approval,
        limit=limit,
        message_limit=msg_limit,
        time_limit=time_limit,
        log_dir=f"logs/{task_key}_{mode}",
        retry_on_error=1,
        fail_on_error=1.0,  # tolerate per-sample errors; keep the run going overnight
    )
    # Print a one-line summary per task log.
    for log in logs:
        status = log.status
        metrics = {}
        if log.results:
            for score in log.results.scores:
                for name, m in score.metrics.items():
                    metrics[f"{score.name}.{name}"] = round(m.value, 4)
        print(f"[{task_key}/{mode}] status={status} samples={log.results.total_samples if log.results else '?'} metrics={metrics}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
