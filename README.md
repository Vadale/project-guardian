# Project Guardian — An AI Guardian Firewall for Autonomous Agents

<p align="center">
  <img src="scripts/demo/assets/guardian-demo.gif" alt="Guardian mediating an agent's actions: a deterministic traffic light (allow / ask / deny) and a data vault that tokenizes your data so the agent never sees it." width="820">
</p>

> **Status:** working product, **v0.1.0 released**. Rust workspace, 196 tests green.
> Implemented through **Phase 4 (hardening)**: the deterministic policy engine, the
> tamper-evident audit log (optionally **sealed-key signed**), the advisory Checker,
> the MCP gateway + stdio transport, the daemon + control socket, the terminal
> approval cockpit (TUI), the AgentDojo eval harness, the **network proxy with TLS
> interception** (broker-injected credentials, exfiltration inspection, default-deny
> egress, cockpit `ask`-routing), the **OS exec sandbox**, the **token broker** (OS
> keychain + least-privilege caveats), **lightweight verifiable credentials**,
> **adaptive suggestions + safety report**, **ed25519-signed community policy
> packs**, and an **intrinsic critical-category floor** (money / credentials /
> exfiltration / irreversible deletion can never resolve to a silent `allow`, not even
> via a signed pack). Getting started: [`docs/user-guide.md`](docs/user-guide.md).
> Remaining for 1.0: signed/notarized **packaging** and the desktop GUI — see
> [`ROADMAP.md`](ROADMAP.md).
>
> **Evaluation:** on AgentDojo with a local 12B agent, Guardian cuts the prompt-injection
> attack-success rate on the banking suite from **100% → 0%** (deterministic deny on
> money-movement). Our own **[GuardianBench](evaluation/guardianbench/)** — a benchmark
> built *for an action-firewall* — scores **0% false-negatives, 0% false-positives, 100%
> refusal-correctness** across 8 domains, plus **0% PII leaks** in its tokenization layer
> (the data broker, ADR-0005). See [`evaluation/`](evaluation/) for the full,
> honestly-caveated scorecard (including where an action-firewall's scope ends — below).
>
> **License:** [Apache-2.0](LICENSE) · **Governance:** [CONTRIBUTING](CONTRIBUTING.md) ·
> [SECURITY](SECURITY.md) · [CODE_OF_CONDUCT](CODE_OF_CONDUCT.md) · [ADRs](docs/adr/)
>
> This README is the canonical spec (idea, full feature set, architecture, threat
> model). For *how* and *in what order* it's built, see `ROADMAP.md`; for what's
> landed, see `docs/changelog.md`.

---

## 1. What it is (one paragraph)

**Guardian** is a local, user-space "firewall" that sits between an autonomous
AI agent and the things it can touch — your files, your shell, the network, and
the online services you delegate to it. It does **not** trust the agent. Every
action the agent attempts is intercepted *as a structured action* at the
agent's tool/MCP boundary, evaluated by a **deterministic policy engine**, and
— when a decision needs a human — explained in plain language by a separate
"translator" model before you approve or deny it. Guardian is **agent-agnostic**
(it does not care whether the agent is driven by Claude, GPT, Llama, or anything
else) and **OS-friendly** (it never installs a kernel module or fights the
operating system for control).

## Quickstart

**Fastest — download a prebuilt binary** (no toolchain needed) from the
[latest release](https://github.com/Vadale/project-guardian/releases/latest).
It's unsigned, so the OS asks once: macOS → right-click → *Open*; Windows →
SmartScreen → *More info → Run anyway*; Linux → `chmod +x guardian`. Then `guardian --help`.
(Windows is experimental/untested — see [`docs/user-guide.md`](docs/user-guide.md).)

**Or build from source** — requires the [Rust toolchain](https://rustup.rs):

```sh
cargo build --release

# 1) see the traffic-light mediation end to end (scripted, no setup)
cargo run -p guardian-cli -- demo

# 2) the internal red-team scorecard (deterministic, no model needed)
cargo run -p guardian-cli -- eval
#    ...and GuardianBench, our action-firewall benchmark (FN 0% / FP 0% / refusal 100%):
GUARDIAN_BIN=target/release/guardian python3 evaluation/guardianbench/guardianbench.py

# 3) the full loop for a real agent — three terminals:
GUARDIAN_SOCK=/tmp/g.sock cargo run -p guardian-daemon       # the service
GUARDIAN_SOCK=/tmp/g.sock cargo run -p guardian-cli -- ui    # the approval cockpit (TUI)
# then point an MCP client (e.g. Claude Code) at:
#   guardian mcp --daemon /tmp/g.sock
```

Run the tests with `cargo test --workspace`. Measuring Guardian's effect on an
agent's attack-success rate: [`evaluation/`](evaluation/).

---

## 2. The problem

Agents went from "chatbots that talk" to "agents that act" — they read and
write files, run shell commands, browse, buy things, send email, and increasingly
touch sensitive accounts (banking, health records, public-administration portals).
That creates four concrete risks:

1. **Sensitive-data exposure & destructive mistakes.** Giving an agent direct
   access to accounts, email, and private documents exposes the user to privacy
   violations, hallucinated destructive actions, and external attacks.
2. **Prompt injection.** The dominant agent-security threat of this era: content
   the agent *reads* (a web page, a PDF, an email, a tool result) can contain
   instructions that hijack the agent into doing something the user never asked.
3. **Click fatigue / informed-consent failure.** System-level agents pop up
   approval requests for scripts and API calls. Non-technical users do not
   understand them and approve everything blindly, which nullifies the safety.
4. **No human-facing control surface and no traceability.** Existing tooling
   (raw harness permission prompts, Docker) is built for programmers. There is no
   intuitive "control room," and no easy way to keep a tamper-evident record of
   what an agent actually did (relevant for transparency obligations such as the
   EU AI Act, Art. 50).

---

## 3. Design principles (non-negotiable)

These are the rules that decide every later trade-off.

1. **The security boundary is deterministic. The LLM is never the boundary.**
   Enforcement (allow / ask / deny) is done by a rule engine whose behavior is
   predictable and testable. An LLM can be *wrong* and can be *attacked* via
   prompt injection, so it is used only to **translate and risk-score**, never to
   unlock.
2. **Intercept structured actions, not the agent's prose.** The policy engine
   and the translator look at the *real* intercepted action (the tool call and its
   arguments, the actual HTTP request, the file operation) — never at the agent's
   natural-language claim about what it intends to do. The claim is manipulable;
   the action is not.
3. **Agent-agnostic by construction.** Control is applied at the action boundary,
   which is identical regardless of which model produced the action.
4. **User-space, not kernel-space.** No kernel modules, no OS hooks that require
   vendor-granted entitlements. (See §4 — this is the central decision.)
5. **Local-first / privacy-first.** Policy evaluation, learning, and the audit
   log live on the user's machine. Sending anything to the cloud is opt-in and
   explicit.
6. **Defense in depth.** Mediation at the tool boundary is the primary control;
   OS sandboxing and a network proxy are containment backstops, not the plan A.
7. **Fail closed on the critical path, fail open on convenience.** A failure in
   the money/credential/exfiltration path blocks; a failure in a low-risk path
   degrades gracefully (logs, defers to existing harness defaults).
8. **Tamper-evident by default.** Everything Guardian decides is written to an
   append-only, hash-chained, signable audit log.

---

## 4. THE KEY DECISION: where Guardian acts

**Resolved: Guardian acts at the agent's action boundary — the harness /
tool-call / MCP layer — in user-space. It does NOT act in the OS kernel.**

### Why not the OS kernel / OS hooks
- Deep OS interception (Linux LSM/eBPF beyond user-space, macOS Endpoint Security
  & Network Extension, Windows minifilter/WFP kernel callouts) requires
  **vendor-granted entitlements, code-signing, notarization, and per-platform
  certification**. On macOS and Windows this is a wall for an open-source project
  and a solo/community maintainer.
- Kernel-level bugs crash the user's machine. The blast radius of a mistake is
  the whole OS.
- It is the wrong altitude: at the syscall level you see `write(fd, buf, n)`, not
  *"the agent is about to wire €4,000 to an unknown IBAN."* Intent is legible at
  the action boundary, not at the kernel.

### Why the harness/action boundary is the right choke point
Modern agent harnesses (Claude Code, Cursor, the OpenAI Agents runtime, and any
MCP-speaking client) already mediate **everything** the agent does through a
**tool-call interface**. The agent cannot touch the world except by calling a tool
the harness exposes. **The harness is already the choke point** — Guardian's job
is to *be*, *wrap*, or *plug into* that mediation layer instead of fighting the OS
for a second, redundant one.

This gives us, for free:
- **Structured actions** (tool name + typed arguments) instead of guessed intent.
- **Agnosticism** — the tool boundary looks the same under any model.
- **No entitlements, no kernel, no notarization headaches.**
- **Cross-platform parity** — the same logic runs on macOS, Windows, Linux.

### The honest caveat (and how we handle it)
Harness-level interception is only as complete as the harness's own mediation.
The hard case is a **raw `Bash`/exec tool**: once `bash` runs, its sub-behaviors
(subprocesses, interpreters, raw syscalls, `base64 -d | sh`) are *not* individually
mediated. Text-scanning the command is **not** a security boundary. We handle this
with a layered answer:

1. **Prefer structured tools over raw shell.** Where the harness allows it, expose
   mediated, typed tools (read_file, write_file, http_request, send_email) instead
   of a raw shell. Structured tools are fully policy-able.
2. **Contain the dangerous tools.** When raw `exec`/`shell`/network *must* exist,
   run that tool's execution inside an **off-the-shelf OS sandbox** (container,
   `sandbox-exec`/Seatbelt profile, bubblewrap, Windows AppContainer/Sandbox) and
   inside a **network proxy** (below). This is defense-in-depth using existing,
   user-space tooling — not custom kernel work.
3. **Mediate the network regardless.** A user-space **forward proxy with an
   installed CA** (mitmproxy-style) catches *all* HTTP(S) no matter how it was
   made, which is where network policy, header signaling, and content watermarking
   actually happen.

So the layered model is: **mediate at the tool boundary (plan A) → contain
high-risk tools in a sandbox + route all traffic through the proxy (backstop).**

---

## 5. Architecture

```
            ┌──────────────────────────────────────────────────────────┐
            │  Agent (any model: Claude / GPT / Llama / local / …)        │
            └──────────────────────────────────────────────────────────┘
                               │  structured action (tool call / MCP / HTTP)
                               ▼
   ┌───────────────────────────────────────────────────────────────────────┐
   │                            GUARDIAN CORE                                 │
   │                                                                          │
   │  ┌────────────────────┐   ┌──────────────────────┐  ┌────────────────┐  │
   │  │ 1. POLICY ENGINE    │   │ 2. CHECKER (LLM)      │  │ 3. AUDIT LOG    │  │
   │  │ deterministic       │──▶│ translator + risk     │  │ append-only,    │  │
   │  │ allow / ask / deny  │   │ score — ADVISORY ONLY │  │ hash-chained,   │  │
   │  │ (the boundary)      │   │ never unlocks         │  │ signable        │  │
   │  └────────────────────┘   └──────────────────────┘  └────────────────┘  │
   │           │ "ask"                                                         │
   │           ▼                                                               │
   │  ┌────────────────────┐   ┌──────────────────────┐  ┌────────────────┐  │
   │  │ 4. APPROVAL UI      │   │ 5. IDENTITY & TOKEN   │  │ 6. ADAPTIVE     │  │
   │  │ traffic-light       │   │ BROKER: scoped OAuth, │  │ LEARNING        │  │
   │  │ dashboard + report  │   │ macaroons, keychain/  │  │ (constrained,   │  │
   │  │                     │   │ Secure Enclave/TPM    │  │ local only)     │  │
   │  └────────────────────┘   └──────────────────────┘  └────────────────┘  │
   └───────────────────────────────────────────────────────────────────────┘
        │ filesystem            │ network                 │ credentials
        ▼ structured FS tools   ▼ forward proxy (MITM CA) ▼ broker injects creds
          + optional sandbox      + header/watermark        at proxy; agent never
          for raw exec            injection                  sees raw secrets
```

### 5.1 Interception adapters (how Guardian plugs into a harness)
In priority order from most to least agnostic:

- **(a) MCP gateway / proxy** — *primary, most agnostic.* Guardian runs as an MCP
  server that aggregates and re-exposes the user's real MCP servers and tools. The
  harness points at Guardian; every `tools/call` passes through the policy engine
  before being forwarded. Works with any MCP-speaking client.
- **(b) Native hook adapter** — for harnesses with a hook system (e.g. Claude
  Code's `PreToolUse`/`PostToolUse`). Guardian registers as the hook handler and
  returns allow/ask/deny per call. Lowest friction where available; gives a true
  deterministic deny.
- **(c) HTTP(S) forward proxy** — a user-space CONNECT proxy with a locally
  installed CA. Intercepts *all* outbound traffic for network policy, the
  agent-signaling header, and content watermarking. This is the only "system-ish"
  piece and it is still pure user-space (a proxy + a trusted cert).
- **(d) LLM gateway proxy** — *optional.* Proxy the model API itself to capture the
  raw request/response, strip injected instructions from tool results, and attach
  provenance. Useful but not required for MVP.

### 5.2 Policy engine (the actual boundary)
- Deterministic evaluation of declarative rules → exactly one of `allow` / `ask` /
  `deny` per action.
- Conditions over structured fields (tool name, arguments, target host, file path,
  amount, time, source) using a sandboxed, side-effect-free expression evaluator
  (candidate: **CEL** or an **OPA/Rego**-style evaluator — chosen for being
  decidable and testable, not Turing-complete scripting).
- **No network, no LLM, no I/O inside evaluation.** Pure function of (action,
  context, policy). This is what makes it auditable.

### 5.3 The Checker (translator + risk scorer) — advisory only
- Two jobs: (1) **translate** a pending action into plain language with its real
  impact (`chmod 777 ./data` → *"lets anyone on this machine read and modify these
  files"*); (2) emit a **risk score / rationale** to help rank the approval queue.
- **It never decides allow/deny.** Even a fully compromised Checker cannot unlock
  an action the policy engine denied.
- It reads the **structured intercepted action**, never the agent's prose.
- Model is **pluggable**: a small local guard model by default (privacy), with an
  *opt-in* escalation to a stronger model for ambiguous cases. This resolves the
  doc's old contradiction between "learns locally, no cloud" and "high-performance
  checker."

### 5.4 Approval UI / dashboard
- Cross-platform desktop app (candidate: **Tauri** — lightweight, Rust-friendly —
  over Electron).
- The **traffic-light** surface: a queue of `ask` items with the Checker's plain
  translation and a one-click allow/deny; a live activity view; the weekly/monthly
  **report** (the "safety service report") that summarizes silently-allowed actions,
  blocked threats, and rule suggestions to batch-confirm — the answer to click
  fatigue.

### 5.5 Audit log (tamper-evident)
- Append-only, **hash-chained** (each entry commits to the previous), optionally
  signed with a per-install key held in the OS keychain / Secure Enclave / TPM.
- Records: action, decision, matched rule, Checker rationale, user response, time.
- This is what makes "traceability" real rather than marketing.

### 5.6 Identity & token broker
- The agent **never sees raw credentials.** It asks the broker to perform an
  authenticated action; the broker injects credentials at the proxy layer.
- Mechanisms (replacing the old "ZKP" idea, which was the wrong primitive):
  - **Scoped OAuth 2.1 tokens** where the service supports them.
  - **Macaroons** — bearer tokens with attenuating *caveats* (expiry, max amount,
    allowed endpoints, source binding) — purpose-built for delegated, narrowable
    authority. This is the core mechanism for "let the agent do X but only X."
  - **Hardware-backed keys** (Secure Enclave / TPM) for signing and secret storage.
  - **W3C Verifiable Credentials / DIDs** for decentralized identity claims.
  - **PSD2 / Open Banking APIs** as the correct rail for EU banking (not screen-
    scraping a bank with a spoofed header).
- Design note: because the broker holds credentials, **Guardian itself becomes the
  highest-value target.** Its own hardening (signed policies, sealed keys,
  notarized builds) is a first-class requirement, not an afterthought.

### 5.7 Adaptive learning (deliberately constrained)
- May **suggest** downgrading a repeatedly-approved low-risk action to "auto-allow
  in this context," and may upgrade an action seen in anomalous context (odd hours,
  unknown destination) to "ask."
- **Hard rule: never auto-downgrade critical categories** — money movement,
  credential access, data exfiltration, irreversible deletions. Auto-habituation is
  exactly the vector an attacker would farm, so these always require explicit human
  action. Suggestions decay over time and are bound to the context in which they
  were learned.
- 100% local. No behavioral data leaves the machine.

### 5.8 Self-protection (the agent cannot disable its own guardian)
Guardian only works if the supervised agent cannot escape or switch it off:
- Guardian is the agent's **only** path to tools. If the daemon is unreachable,
  there is no decision, so there is no action — **fail closed**, not open.
- The agent process runs **without authority** to kill the Guardian daemon,
  remove/alter the proxy CA, or edit the active policy (separate privilege +
  sealed policy). A bypass attempt is recorded as a gap in the tamper-evident log.
- Supervised restart: if the daemon dies, the integration refuses to forward tool
  calls until Guardian is back.

### 5.9 Kill switch (panic button)
A one-action, always-available control that **immediately revokes all agent
authority**: pause every adapter, deny all pending and new actions, and freeze
brokered credentials. Reachable from the UI and the CLI (`guardian panic`), and
designed to work even if the Checker/UI is unresponsive.

### 5.10 Configuration & first run
- A single declarative config (TOML) selects the active role/policy pack, the
  Checker backend, and which adapters are enabled. Validated on load; invalid
  config fails closed.
- **Safe defaults:** first run starts in the most restrictive role (everything
  unknown → `ask`), egress allow-list empty, learning off. The user widens
  deliberately — never the reverse.

### 5.11 Data, storage, retention & privacy
- All state (audit log, learned suggestions, config) is stored **locally** under
  the OS user-data dir; secrets live in the OS keychain, never plaintext on disk.
- The audit log is append-only and hash-chained; retention is user-configurable
  and export is explicit. Nothing is transmitted unless the user opts into remote
  Checker escalation (the only network path), which is per-action and logged.

### 5.12 Localization
The Checker's plain-language explanations and all UI copy are **localizable** (the
audience is non-technical users worldwide). Decisions and logs stay in a stable
machine-readable form; only the human-facing presentation is translated.

---

## 6. Core features (the corrected feature set)

| # | Feature | What it does | Correction vs. the original idea |
|---|---------|--------------|----------------------------------|
| A | **Maker/Checker** | Maker = the third-party agent doing the task; Checker = local model that translates pending actions into plain language + risk score. | Checker is **advisory only** and reads structured actions, **not** the agent's prose. The deny decision is the deterministic engine's. |
| B | **Traffic-light permissions** | Green = silent allow; Yellow = pause + translated approval popup; Red = auto-block + notify. Roles (e.g. "Web Dev", "Tax Assistant") preload rule sets. | Enforcement is the deterministic **policy engine** (capability/attribute-based), with roles as presets. The traffic light is the UI on top. |
| C | **Adaptive security** | Learns to downgrade safe repeated actions and upgrade anomalous ones, locally. | **Never** auto-downgrades critical categories; context-bound; decaying; local-only. |
| D | **Reporting** | Batches low-risk auto-approvals into a periodic report; user confirms suggested rules. | Unchanged — this is good design and directly fights click fatigue. |
| E | **Provenance / watermarking** | Optional content footer on AI-generated email/comments/forms; optional agent-signaling HTTP header; everything logged. | The HTTP header is a **courtesy signal only — not security** (trivially spoofable, can trigger anti-bot blocks). Content marking helps the *user's* AI-Act transparency duty but does **not** by itself make anyone "compliant." Treat as opt-in, default-off for the header. |
| F | **Identity & tokens** | Broker holds credentials; agent gets scoped, time/amount-limited authority. | **Capability tokens / macaroons / scoped OAuth / hardware keys / VCs** — not ZKP (which was the wrong primitive for delegation). |

---

## 7. Threat model

| Adversary | Vector | Primary defense |
|-----------|--------|-----------------|
| **Hallucinating / misaligned agent** | Issues a destructive or wrong action in good faith | Deterministic policy engine; `ask` for anything irreversible; Checker translation so the human catches it |
| **Prompt injection** (the #1 threat) | Malicious instructions hidden in web pages, PDFs, emails, or tool results steer the agent | Policy evaluates the *real* action regardless of why the agent wants it; critical categories always `ask`/`deny`; optional LLM-gateway sanitization of tool results; Checker never reads attacker-controlled prose as authority |
| **Compromised / malicious MCP server or tool** | A tool lies about what it does, or exfiltrates | Guardian sees the actual call/args and the actual network egress (proxy), not the tool's self-description; egress allowlists |
| **Sensitive-data leak via the agent's *output*** | An injection makes the agent put account numbers, who-did-what, or secrets into its response/reasoning | For data to reach an attacker it must cross a *channel* (message / network / file) — which is an **action** Guardian gates; the **token broker** (§5.6) keeps credentials and full secrets **out of the agent entirely** (injected only into the authorized egress, so the agent cannot reveal what it never held); residual data the agent legitimately handled is bounded by least-privilege + a planned **output-guard** (Checker-side DLP redaction). The action-firewall does **not** police the agent's prose by design |
| **Malicious policy pack** (supply chain) | A community pack whitelists an exfiltration path | Signed packs, mandatory review, reputation, a "packs cannot widen critical-category permissions without explicit user opt-in" rule, **and an intrinsic runtime floor** — critical-category actions can never resolve to a silent `allow` regardless of any rule or pack |
| **Attack on Guardian itself** (it holds the keys) | Tamper with policy, steal brokered creds, forge the log | Sealed keys (Secure Enclave/TPM), signed/locked policy, hash-chained log, notarized builds, fail-closed |
| **Agent disables / bypasses its guardian** | Kill the daemon, remove the proxy CA, or route around the gateway to escape supervision | Guardian is the agent's *only* path to tools (no decision → no action = **fail closed**); the agent has no authority to stop the daemon or alter CA/policy; supervised restart; gaps flagged in the log. See §5.8 |
| **Habituation attack** | Train the adaptive layer to auto-allow, then strike | Never auto-downgrade critical categories; decay + context binding |
| **Malicious user** | Tries to use the agent + Guardian for harmful/abusive ends | Out of scope for "protect the user," but Guardian's provenance/logging makes misuse attributable |

> Full threat model — assets, trust boundaries, attack trees, residual risks, and
> the OWASP/NIST mapping — lives in [`docs/threat-model.md`](docs/threat-model.md).

---

## 8. Policy schema (concrete sketch)

Declarative, reviewable, version-controlled. Illustrative only — final schema TBD.

```yaml
# role: "personal-assistant"
version: 1
defaults:
  decision: ask            # unknown actions default to human review

rules:
  - id: read-project-files
    when: tool == "read_file" && path.startsWith("~/DOCUDESK/")
    decision: allow         # GREEN: silent

  - id: shell-anything
    when: tool == "exec"
    decision: ask           # YELLOW: pause + translate
    sandbox: true           # and run it contained, regardless of approval

  - id: chmod-world-writable
    when: tool == "exec" && args.cmd matches "chmod\\s+(777|o\\+w)"
    decision: ask
    explain: "Makes files modifiable by any user on this machine."

  - id: outbound-known-hosts
    when: tool == "http_request" && host in trusted_hosts
    decision: allow

  - id: money-movement
    when: capability == "payment"
    decision: ask
    critical: true          # may NEVER be auto-downgraded by learning
    cap: { amount_max: 200, currency: "EUR" }

  - id: bulk-delete
    when: tool == "delete" && args.count > 10
    decision: ask
    critical: true

  - id: data-exfiltration
    when: tool == "http_request"
            && method == "POST"
            && body.contains_secret
            && host not in trusted_hosts
    decision: deny          # RED: auto-block + notify
    critical: true
```

---

## 9. How agnosticism is achieved (and what we deliberately do NOT do)

**Achieved by:**
- Intercepting at the **action boundary** (MCP/tool/HTTP), which is identical
  under any model.
- A **pluggable Checker model** (local or remote, user's choice).
- **Per-harness adapters** that all feed the same policy engine.

**We deliberately do NOT:**
- ❌ Install kernel modules or use OS hooks requiring vendor entitlements.
- ❌ Let any LLM be the allow/deny boundary.
- ❌ Treat the spoofable `User-Agent` header as a security control.
- ❌ Use ZKP as the delegation primitive (use macaroons / scoped tokens / VCs).
- ❌ Auto-downgrade critical-category actions via learning.
- ❌ Claim Guardian "makes the user legally compliant" — it *helps* with
  transparency/traceability; legal sign-off is the user's.
- ❌ Send behavioral/learning data to the cloud (Checker escalation is the only
  network path, and it is opt-in).

**Out of scope (for now) — explicitly deferred, not forgotten:**
- Multi-agent / agent-to-agent supervision (an OWASP Agentic 2026 risk class) —
  the current model guards a single agent; multi-agent mediation is future work.
- Deep OS/kernel interception (see §4) — never in scope.
- Any proprietary/enterprise tier — this repo is fully open source.

---

## 10. Roadmap — everything to build

### Phase 0 — Foundations (week 1)
- [ ] Set up the Rust workspace (**Rust decided — ADR-0001**; see ROADMAP §0).
- [ ] Repo scaffolding, license (**Apache-2.0**, see `LICENSE`), CI, contribution guide.
- [ ] Define the **action model** (the canonical structured representation every
      adapter normalizes into).
- [ ] Write the formal **threat model** and **policy schema** as living specs.

### Phase 1 — MVP (the demonstrable core, ~weeks 2–8)
- [ ] **MCP gateway adapter** (primary) for one MCP-speaking harness.
- [ ] **Deterministic policy engine** with the declarative schema + CEL/Rego-style
      evaluator + a full test suite (golden cases per rule).
- [ ] **Checker** translator using a pluggable model; reads structured actions only.
- [ ] **Approval UI** (Tauri): traffic-light queue + plain-language explanation +
      allow/deny.
- [ ] **Tamper-evident audit log** (append-only, hash-chained).
- [ ] **One real demo scenario end-to-end** (e.g. agent edits files + makes an
      HTTP request; Guardian allows greens silently, pauses a yellow with a
      translated popup, blocks a red exfiltration attempt).

**MVP definition of done:** a non-technical user can watch an agent work, get a
*human-readable* approval prompt for one risky action, see one bad action blocked
automatically, and read a log of everything that happened — with **no LLM in the
deny path**.

### Phase 2 — Containment & network (post-MVP)
- [ ] **HTTP(S) forward proxy** with installed CA: network policy, egress
      allowlists, optional agent-signaling header, optional content watermark.
- [ ] **OS sandbox wrapper** for raw `exec` tools (Docker / sandbox-exec /
      bubblewrap / AppContainer) — defense in depth, off-the-shelf only.
- [ ] **Native hook adapter** (e.g. Claude Code `PreToolUse`).

### Phase 3 — Identity, learning, ecosystem
- [ ] **Identity & token broker**: scoped OAuth, macaroons, keychain/Secure
      Enclave/TPM storage; agent never sees raw secrets.
- [ ] **Constrained adaptive learning** + the periodic **report**.
- [ ] **Signed community policy packs** + the trust/review pipeline (this is the
      open-core community engine).
- [ ] Optional **LLM gateway proxy** with tool-result sanitization.
- [ ] Additional harness adapters (Cursor, OpenAI Agents runtime, generic MCP).

---

## 11. Suggested tech stack (proposals, not locked)

- **Core / policy engine / proxies:** Rust (security rigor, cross-platform) — Go is
  an acceptable alternative for proxy/MCP velocity.
- **Policy expressions:** CEL or an OPA/Rego-style evaluator (decidable, testable).
- **Desktop UI:** Tauri.
- **Audit log:** append-only hash-chained store (e.g. SQLite + chained hashes, or a
  purpose-built log); per-install signing key in OS keychain/Secure Enclave/TPM.
- **Network proxy:** user-space MITM proxy + locally trusted CA.
- **Sandbox backstops:** Docker / `sandbox-exec` (macOS) / bubblewrap (Linux) /
  AppContainer or Windows Sandbox (Windows) — all off-the-shelf.

---

## 12. Open questions (decide before/while building)

1. Which harness do we target **first** for the MCP gateway? (Drives the demo.)
2. Default local Checker model — which small model balances quality vs. footprint?
3. Policy expression language — CEL vs. Rego (DX, sandboxing, ecosystem)?
4. How do signed policy packs get reviewed at community scale without a bottleneck?
5. CA-installation UX for the proxy — how to make trusting a local CA safe and
   non-scary for non-technical users?
6. How much of the AI-Act transparency story do we promise vs. explicitly disclaim?
   (Get legal input before any compliance claim ships.)

---

## 13. Glossary

- **Harness** — the runtime that drives an agent and mediates its tool calls
  (e.g. Claude Code). Guardian plugs into this layer.
- **Maker** — the third-party agent performing the user's task.
- **Checker** — Guardian's local translator/risk-scorer model (advisory only).
- **MCP** — Model Context Protocol; the tool/server protocol Guardian proxies.
- **Macaroon** — a bearer credential that can be attenuated with contextual caveats.
- **Critical category** — money movement, credential access, data exfiltration,
  irreversible deletion; never auto-downgraded by learning.
