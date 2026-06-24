# Guardian × AgentDojo

Measures whether mediating an agent with Guardian **lowers the attack success
rate (ASR)** without tanking benign utility, using the
[AgentDojo](https://github.com/ethz-spylab/agentdojo) prompt-injection benchmark.

Guardian plugs in as a tools-loop element (`guardian_defense.py`): before each
tool call executes, it asks Guardian's deterministic policy (`guardian decide`)
and drops anything denied — so an injected malicious action that the policy denies
never runs.

## Files
- `guardian_defense.py` — the `GuardianDefense` AgentDojo pipeline element + the
  `guardian decide` bridge. **This is the integration; it's the part to trust.**
- `run_eval.py` — A/B runner (baseline vs Guardian) that prints a scorecard.
- `requirements.txt` — `agentdojo`, `openai`.

## Prerequisites
1. Build the Guardian CLI and point the shim at it:
   ```sh
   cargo build -p guardian-cli            # from the repo root
   export GUARDIAN_BIN="$PWD/target/debug/guardian"
   # optional: a specific policy file for decisions
   # export GUARDIAN_POLICY="$PWD/policies/default/personal-assistant.toml"
   guardian() { "$GUARDIAN_BIN" "$@"; }   # sanity: echo a call
   echo '{"tool":"shell.run","kind":"Exec"}' | "$GUARDIAN_BIN" decide
   ```
2. Install AgentDojo:
   ```sh
   python -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   ```
3. A model. Either an API model (set `OPENAI_API_KEY`) **or** a local
   OpenAI-compatible endpoint (Ollama `http://localhost:11434/v1`, LM Studio
   `http://localhost:1234/v1`). Local models must support tool/function calling.

## Run the A/B
```sh
# A — baseline (no Guardian)
python run_eval.py --model gpt-4o --suite banking --out baseline.json

# B — with Guardian (the same agent + the GuardianDefense element)
python run_eval.py --model gpt-4o --suite banking --with-guardian --out guardian.json
```
Local model example:
```sh
python run_eval.py --model llama3.1 --base-url http://localhost:11434/v1 \
    --api-key ollama --suite banking --with-guardian
```
Compare `attack_success_rate` (should drop with Guardian) and `benign_utility`
(should stay close). Feed the numbers into the scorecard in
[`../README.md`](../README.md) §7.

## Experimental design
- **Two conditions, everything else equal:** the only difference is the
  `GuardianDefense` element. Run both, compare ASR and utility.
- **Ask handling:** with no human in an automated benchmark, `ask` can't be
  resolved interactively. By default Guardian blocks only `deny` (`--block deny`),
  measuring the deterministic-deny layer. To model "a human always denies
  suspicious asks" (an upper bound on Guardian's effect), use
  `--block deny ask`. Report which you used.
- **Headline:** Guardian's block is deterministic and model-independent, so the
  ASR reduction is robust even with a weaker local model (utility, by contrast, is
  model-sensitive).

## Caveats (read before trusting numbers)
- **Not run in this repo's CI** — needs `pip install agentdojo` + a model. The
  `GuardianDefense` element is written against the documented AgentDojo API, but
  that API shifts between versions; if an import/call fails, adapt `run_eval.py`
  to your installed version (the core logic in `guardian_defense.py` is small).
- **Verify the polarity** of AgentDojo's `security_results` for your version
  (whether `True` means "attack succeeded" or "defended") and label the ASR
  accordingly — `run_eval.py` notes this inline.
- The default tool→policy classification is heuristic (Guardian infers kind from
  the tool name). For sharper results, tune the policy and/or have the shim pass
  explicit `kind`/`capability` per tool.
