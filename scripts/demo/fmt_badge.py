#!/usr/bin/env python3
"""Render a `guardian decide` JSON verdict as a colored traffic-light badge.

Reads the decision JSON on stdin (`{decision, reason, critical, matched_rule}`)
and prints a one- or two-line badge. Used by the README demo (scripts/demo/play.sh).
"""
import json
import sys

GREEN = "\033[38;5;48m"
RED = "\033[38;5;203m"
YELLOW = "\033[38;5;221m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"

d = json.load(sys.stdin)
decision = d.get("decision", "ask")
color, label = {
    "allow": (GREEN, "ALLOW"),
    "ask": (YELLOW, "ASK  "),
    "deny": (RED, "DENY "),
}[decision]

rule = d.get("matched_rule") or "default"
crit = "  " + BOLD + RED + "CRITICAL" + RESET if d.get("critical") else ""
print(f"     {color}● {label}{RESET}  {DIM}rule:{RESET} {rule}{crit}")
reason = d.get("reason")
if reason:
    print(f"            {DIM}→ {reason}{RESET}")
