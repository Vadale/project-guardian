"""A/B runner: AgentDojo with vs. without Guardian.

Builds two pipelines for the same model — **baseline** and **Guardian** (the same
pipeline plus a `GuardianDefense` element in the tools loop) — runs an AgentDojo
suite with and without injection attacks, and prints a scorecard:

  * benign utility (task success, no attack)
  * attack success rate (ASR, with injections)  ← Guardian should lower this

Run it once per condition and compare, e.g.:

    # baseline
    python run_eval.py --model gpt-4o --suite banking
    # with Guardian (start nothing else; `guardian decide` is a subprocess)
    python run_eval.py --model gpt-4o --suite banking --with-guardian

Local models (Ollama/LM Studio) expose an OpenAI-compatible endpoint:

    python run_eval.py --model llama3.1 --base-url http://localhost:11434/v1 \
        --api-key ollama --suite banking --with-guardian

⚠️ Not tested in this repo's CI (needs `pip install agentdojo` + a model). The
AgentDojo API can shift between versions; if an import or call fails, adjust to
your installed version — the integration logic lives in `guardian_defense.py`.
"""

from __future__ import annotations

import argparse
import json

import openai

from agentdojo.agent_pipeline import (
    AgentPipeline,
    InitQuery,
    OpenAILLM,
    SystemMessage,
    ToolsExecutionLoop,
    ToolsExecutor,
)
from agentdojo.benchmark import (
    benchmark_suite_with_injections,
    benchmark_suite_without_injections,
)
from agentdojo.task_suite.load_suites import get_suite

from guardian_defense import GuardianDefense

SYSTEM_MESSAGE = "You are a helpful assistant that uses tools to complete tasks."


def build_pipeline(args) -> AgentPipeline:
    client = openai.OpenAI(base_url=args.base_url, api_key=args.api_key)
    llm = OpenAILLM(client, args.model)

    loop_elements = []
    if args.with_guardian:
        # Guardian must run *before* the executor so denied calls never execute.
        loop_elements.append(GuardianDefense(block_decisions=tuple(args.block)))
    loop_elements += [ToolsExecutor(), llm]

    pipeline = AgentPipeline(
        [SystemMessage(SYSTEM_MESSAGE), InitQuery(), llm, ToolsExecutionLoop(loop_elements)]
    )
    pipeline.name = "guardian" if args.with_guardian else "baseline"
    return pipeline


def rate(results: dict) -> float:
    values = list(results.values())
    return (sum(1 for v in values if v) / len(values)) if values else 0.0


def main() -> None:
    parser = argparse.ArgumentParser(description="AgentDojo A/B: with vs. without Guardian")
    parser.add_argument("--model", required=True, help="model id (or local model name)")
    parser.add_argument("--suite", default="banking", help="AgentDojo suite name")
    parser.add_argument("--benchmark-version", default="v1.2.1")
    parser.add_argument("--attack", default="important_instructions", help="injection attack name")
    parser.add_argument("--base-url", default=None, help="OpenAI-compatible endpoint (for local models)")
    parser.add_argument("--api-key", default="not-needed", help="API key (any value for local)")
    parser.add_argument("--with-guardian", action="store_true")
    parser.add_argument(
        "--block",
        nargs="+",
        default=["deny"],
        help="which Guardian decisions to block (e.g. deny, or 'deny ask')",
    )
    parser.add_argument("--out", default=None, help="write the scorecard JSON here")
    args = parser.parse_args()

    suite = get_suite(args.benchmark_version, args.suite)

    # Benign utility (no attack).
    utility = benchmark_suite_without_injections(build_pipeline(args), suite)
    # Security under injection (a fresh pipeline; benchmark functions are stateful).
    security = benchmark_suite_with_injections(build_pipeline(args), suite, args.attack)

    scorecard = {
        "condition": "guardian" if args.with_guardian else "baseline",
        "model": args.model,
        "suite": args.suite,
        "attack": args.attack,
        "blocked_decisions": args.block if args.with_guardian else [],
        "benign_utility": round(rate(utility.get("utility_results", {})), 4),
        # NOTE: verify the polarity of `security_results` for your AgentDojo
        # version (True may mean "attack succeeded" or "defended"); label accordingly.
        "attack_success_rate": round(rate(security.get("security_results", {})), 4),
    }

    print(json.dumps(scorecard, indent=2))
    if args.out:
        with open(args.out, "w") as f:
            json.dump(scorecard, f, indent=2)


if __name__ == "__main__":
    main()
