"""Guardian defense element for AgentDojo.

A pipeline element placed *before* the ``ToolsExecutor`` in the tools-execution
loop. For each tool call the model wants to make, it consults Guardian's
deterministic policy via the ``guardian decide`` CLI and **drops any call Guardian
denies**, so the denied action never executes.

This measures Guardian's hard-deny layer: an injected malicious action that the
policy denies cannot run. By default only ``deny`` blocks; ``ask``/``allow`` pass
through (in an automated benchmark there is no human to resolve an ``ask`` — see
README.md for the experimental design and how to also treat ``ask`` as blocked).

Environment:
- ``GUARDIAN_BIN``    path to the `guardian` binary (default: ``guardian`` on PATH)
- ``GUARDIAN_POLICY`` optional path to a policy file for `guardian decide`

Note: AgentDojo's exact import paths/field names can vary by version; the helper
accessors below are defensive. Adjust imports if your installed version differs.
"""

from __future__ import annotations

import json
import os
import subprocess
from typing import Any

try:
    # The base element and runtime. Import paths may vary across AgentDojo versions.
    from agentdojo.agent_pipeline import BasePipelineElement
    from agentdojo.functions_runtime import FunctionsRuntime
except Exception:  # pragma: no cover - import shim for older/newer layouts
    from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement  # type: ignore
    from agentdojo.functions_runtime import FunctionsRuntime  # type: ignore

GUARDIAN_BIN = os.environ.get("GUARDIAN_BIN", "guardian")
GUARDIAN_POLICY = os.environ.get("GUARDIAN_POLICY")


def guardian_decide(tool: str, args: dict) -> str:
    """Return Guardian's verdict for a tool call: ``allow`` | ``ask`` | ``deny``.

    Fails closed (returns ``deny``) if Guardian cannot be reached or parsed.
    """
    payload = json.dumps({"tool": tool, "args": args})
    cmd = [GUARDIAN_BIN, "decide"]
    if GUARDIAN_POLICY:
        cmd += ["--policy", GUARDIAN_POLICY]
    try:
        proc = subprocess.run(
            cmd, input=payload, capture_output=True, text=True, timeout=15
        )
        return json.loads(proc.stdout).get("decision", "deny")
    except Exception:
        return "deny"


def _get(obj: Any, key: str) -> Any:
    """Read ``key`` from a dict-like or an attribute-style object."""
    if isinstance(obj, dict):
        return obj.get(key)
    return getattr(obj, key, None)


class GuardianDefense(BasePipelineElement):
    """Drops tool calls Guardian denies, before they reach the ToolsExecutor."""

    def __init__(self, block_decisions: tuple[str, ...] = ("deny",)) -> None:
        self.block_decisions = set(block_decisions)

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Any = None,
        messages: Any = (),
        extra_args: dict | None = None,
    ):
        extra_args = dict(extra_args or {})
        if messages:
            last = messages[-1]
            tool_calls = _get(last, "tool_calls") or []
            if tool_calls:
                kept = []
                blocked = list(extra_args.get("guardian_blocked", []))
                for call in tool_calls:
                    name = str(_get(call, "function") or "")
                    args = _get(call, "args") or {}
                    try:
                        args = dict(args)
                    except Exception:
                        args = {}
                    decision = guardian_decide(name, args)
                    if decision in self.block_decisions:
                        blocked.append({"tool": name, "decision": decision})
                    else:
                        kept.append(call)
                if len(kept) != len(tool_calls):
                    # Replace the last message with a copy whose denied calls are gone.
                    if isinstance(last, dict):
                        last = {**last, "tool_calls": kept}
                    else:  # pydantic-style message
                        last = last.model_copy(update={"tool_calls": kept})
                    messages = list(messages[:-1]) + [last]
                extra_args["guardian_blocked"] = blocked
        return query, runtime, env, messages, extra_args
