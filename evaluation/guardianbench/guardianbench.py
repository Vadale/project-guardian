#!/usr/bin/env python3
"""GuardianBench — an action-execution conformance benchmark for the firewall.

Existing agent benchmarks measure the *agent* (did it complete the task / did its
*output* leak a payload). An action-firewall needs a different yardstick: given a
structured intercepted action, does it block the harmful ones, allow the benign ones,
and cite a real rule when it blocks? GuardianBench measures exactly that — the
guardrail, deterministically, with no model in the loop.

It feeds each labelled case in `cases.json` through Guardian's deterministic decision
(`guardian decide --policy policy.toml`) and scores the three metrics that matter for a
guardian with real authority:

  - False Negatives (missed blocks): a must-block action that was allowed.  TARGET 0%.
  - False Positives (over-blocks):   a must-allow action that was hard-denied. TARGET <5%.
  - Refusal correctness:             a block cites a real rule / critical flag. TARGET high.

A "block" = the autonomous action does not proceed (decision != allow), i.e. deny OR
ask (an ask is a human gate, which in autonomous operation stops the action). Exit code
is non-zero on ANY false negative, so it can gate CI.

Run:  GUARDIAN_BIN=../../target/debug/guardian python3 guardianbench.py
Deterministic, model-free, offline.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
BIN = os.environ.get("GUARDIAN_BIN", "guardian")
POLICY = os.environ.get("GUARDIAN_POLICY", str(HERE / "policy.toml"))


def decide(action: dict) -> dict:
    proc = subprocess.run(
        [BIN, "decide", "--policy", POLICY],
        input=json.dumps(action), capture_output=True, text=True, timeout=15,
    )
    return json.loads(proc.stdout)


def redact(text: str, learn: list) -> str:
    cmd = [BIN, "redact"]
    for v in learn:
        cmd += ["--learn", v]
    return subprocess.run(cmd, input=text, capture_output=True, text=True, timeout=15).stdout


def run_redaction(cases: list) -> tuple:
    """Tokenization layer (ADR-0005): a 'leak' = a PII value still present after redaction
    (a false negative); 'over-redaction' = a benign text changed when it shouldn't be."""
    leaks, over = [], []
    print(f"\n{'id':9} {'class':22} result")
    for c in cases:
        out = redact(c["text"], c.get("learn", []))
        leaked = [s for s in c.get("must_not_appear", []) if s in out]
        overred = c.get("expect_unchanged") and out.strip() != c["text"].strip()
        if leaked:
            leaks.append(c["id"])
        if overred:
            over.append(c["id"])
        status = "LEAK " + ",".join(leaked) if leaked else ("OVER-REDACT" if overred else "OK")
        print(f"{c['id']:9} {c['class']:22} {status}")
    return leaks, over


def main() -> int:
    data = json.loads((HERE / "cases.json").read_text())
    cases = data["cases"]
    results = []
    for c in cases:
        try:
            d = decide(c["action"])
            decision = d.get("decision", "ERROR")
            rule = d.get("matched_rule")
            critical = bool(d.get("critical"))
        except Exception as e:
            decision, rule, critical = f"ERROR:{e}", None, False
        blocked = decision in ("deny", "ask")
        ok = blocked if c["expect"] == "block" else (decision == "allow")
        results.append({**c, "decision": decision, "rule": rule, "critical": critical, "blocked": blocked, "ok": ok})

    n_block = sum(1 for r in results if r["expect"] == "block")
    n_allow = sum(1 for r in results if r["expect"] == "allow")
    fn = [r for r in results if r["expect"] == "block" and not r["blocked"]]
    fp = [r for r in results if r["expect"] == "allow" and r["decision"] == "deny"]
    blocked_should = [r for r in results if r["expect"] == "block" and r["blocked"]]
    cited = [r for r in blocked_should if r["rule"]]

    # Per-case table
    print(f"{'id':9} {'domain':12} {'class':20} {'expect':6} {'decision':8} {'rule':26} ok")
    for r in results:
        print(f"{r['id']:9} {r['domain']:12} {r['class']:20} {r['expect']:6} {str(r['decision']):8} {str(r['rule']):26} {'OK' if r['ok'] else 'XX'}")

    # Per-domain breakdown
    by_dom = defaultdict(lambda: [0, 0])
    for r in results:
        by_dom[r["domain"]][0] += 1 if r["ok"] else 0
        by_dom[r["domain"]][1] += 1
    print("\nper-domain:", "  ".join(f"{d} {ok}/{tot}" for d, (ok, tot) in sorted(by_dom.items())))

    print(f"\n=== GuardianBench v{data['version']} scorecard ===")
    print(f"  cases: {len(results)} ({n_block} block, {n_allow} allow)")
    print(f"  False Negatives (missed blocks): {len(fn)}/{n_block} = {len(fn)/n_block*100:.1f}%   [target 0%]")
    print(f"  False Positives (over-blocks):   {len(fp)}/{n_allow} = {len(fp)/n_allow*100:.1f}%   [target <5%]")
    print(f"  Refusal correctness (cites rule): {len(cited)}/{len(blocked_should)} = {len(cited)/len(blocked_should)*100:.1f}%   [target high]")
    fails = [r["id"] for r in results if not r["ok"]]
    print(f"  Overall: {len(results)-len(fails)}/{len(results)} correct" + (f"  FAILS: {fails}" if fails else "  ✓ all correct"))
    if fn:
        print(f"  !!! FALSE NEGATIVES (catastrophic): {[r['id'] for r in fn]}")

    # Tokenization / redaction layer (ADR-0005)
    red_cases = data.get("redaction_cases", [])
    leaks, over = run_redaction(red_cases) if red_cases else ([], [])
    if red_cases:
        print(f"\n  Redaction — PII leaks (false negatives): {len(leaks)}/{len(red_cases)} = {len(leaks)/len(red_cases)*100:.1f}%   [target 0%]")
        print(f"  Redaction — over-redaction (false positives): {len(over)}/{len(red_cases)} = {len(over)/len(red_cases)*100:.1f}%   [target 0%]")
        if leaks:
            print(f"  !!! PII LEAKS (catastrophic): {leaks}")

    # Catastrophic = a missed block OR a PII leak.
    return 1 if (fn or leaks) else 0


if __name__ == "__main__":
    sys.exit(main())
