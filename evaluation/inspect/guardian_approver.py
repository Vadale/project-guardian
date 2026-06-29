"""Guardian approver for Inspect AI (UK AISI).

Plugs Guardian into the Inspect approval system as a custom ``@approver``: before
any tool call executes, it maps the call to a Guardian action, asks the deterministic
policy via ``guardian decide``, and **rejects** anything that is not ``allow``
(fail-closed). This is the Inspect analogue of our AgentDojo ``GuardianDefense`` and
the Claude Code / pi hooks — the same deterministic decision, at Inspect's tool-call
approval point.

With this approver wired into a policy (see ``guardian_approval.yaml``), Guardian's
numbers slot onto the *same* metric as everything else in ``inspect_evals``
(AgentDojo, AgentThreatBench) — i.e. it lets us compare against other defenses.

Env:
  GUARDIAN_BIN     path to the `guardian` binary (default: ``guardian`` on PATH)
  GUARDIAN_POLICY  policy .toml for `guardian decide` (or pass policy= in the YAML)

NOTE: Inspect's import paths have shifted across versions. If an import fails on your
installed version, adjust the two imports below (the logic is tiny) — the launch
procedure in README.md runs a 1-sample smoke first to catch exactly this.
"""
from __future__ import annotations

import json
import os
import subprocess

from inspect_ai.approval import Approval, Approver, approver
from inspect_ai.tool import ToolCall, ToolCallView
from inspect_ai.model import ChatMessage

_LOG = os.environ.get("GUARDIAN_INSPECT_LOG")


@approver(name="guardian")
def guardian_approver(policy: str | None = None) -> Approver:
    binary = os.environ.get("GUARDIAN_BIN", "guardian")
    pol = policy or os.environ.get("GUARDIAN_POLICY")

    async def approve(
        message: str,
        call: ToolCall,
        view: ToolCallView,
        history: list[ChatMessage],
    ) -> Approval:
        action = {"tool": call.function, "args": dict(call.arguments or {})}
        cmd = [binary, "decide"] + (["--policy", pol] if pol else [])
        try:
            proc = subprocess.run(cmd, input=json.dumps(action), capture_output=True, text=True, timeout=15)
            d = json.loads(proc.stdout)
            decision = d.get("decision", "deny")
            reason = d.get("reason") or ""
        except Exception as e:  # fail closed
            decision, reason = "deny", f"Guardian unreachable (fail-closed): {e}"

        if _LOG:
            try:
                with open(_LOG, "a") as fh:
                    fh.write(f"{call.function}\t{decision}\t{reason}\n")
            except Exception:
                pass
        if decision == "allow":
            return Approval(decision="approve", explanation="Guardian: allow")
        # deny / ask -> reject (in an automated eval there is no human to resolve ask)
        return Approval(decision="reject", explanation=f"Guardian {decision}: {reason}")

    return approve
