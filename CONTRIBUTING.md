# Contributing to Project Guardian

Thanks for your interest. Guardian is an open-source AI guardian firewall; its
value depends on being trustworthy, so contributions are held to a high bar for
correctness and clarity. Everything here is in **English**.

## Before you start
1. Read [`README.md`](README.md) (the spec), [`ROADMAP.md`](ROADMAP.md) (the build
   plan with per-task prompts), and [`CLAUDE.md`](CLAUDE.md) (the invariants and
   conventions). The architecture decisions are recorded in [`docs/adr/`](docs/adr/).
2. For anything security-related, also read [`SECURITY.md`](SECURITY.md) and
   [`docs/threat-model.md`](docs/threat-model.md).

## The hard invariants (a PR that violates these will not be merged)
1. **No LLM on any allow/deny path.** Enforcement is the deterministic policy
   engine. The Checker only translates and risk-scores.
2. **Evaluate structured actions, not the agent's prose.**
3. **`guardian-core` does no I/O and has no internal deps; the dependency graph
   stays acyclic.**
4. **Critical categories** (payment, credential access, data exfiltration,
   irreversible deletion) are never auto-downgraded by learning.
5. **Fail closed on the critical path.**
6. **No `unsafe`** outside a clearly-marked, reviewed FFI module.

## Development setup
- Install the Rust toolchain (stable; see `rust-toolchain.toml` once present) and
  `cargo-nextest`, `cargo-audit`, `cargo-deny`.
- Build/test: `cargo build`, `cargo nextest run`.
- Before opening a PR, all of these must pass: `cargo fmt --check`,
  `cargo clippy -- -D warnings`, `cargo nextest run`, `cargo deny check`.

## Quality expectations
- **Tests are not optional.** Every new policy rule or decision path needs golden
  (`insta`) and adversarial (`proptest`) tests. See [`evaluation/`](evaluation/)
  for how we benchmark security gain vs. utility.
- **Simplicity is a feature.** Prefer the simplest correct code; small pure
  functions; no speculative abstraction. If a reviewer can't quickly follow a
  decision path, that's a bug.
- **Document what you change.** Update `docs/architecture/<crate>.md` and add a
  `docs/changelog.md` entry describing the change.

## Contributing a policy pack
Policy packs (see [`policies/`](policies/)) are how the community covers new sites
and tools. Packs must be **signed**, must not widen a critical category without
explicit user opt-in, and must ship golden tests for their rules. See
[`docs/policy-schema.md`](docs/policy-schema.md).

## Pull requests
- Branch from `main`; keep PRs focused and small where possible.
- Write clear commit messages (imperative mood, English).
- Reference the ROADMAP task or issue you're addressing.
- Be ready for review by the project's reviewers (correctness + invariants) and,
  for sensitive areas, a security review.

## Reporting bugs vs. vulnerabilities
- Normal bugs → open a GitHub issue.
- Security vulnerabilities → **do not** open a public issue; follow
  [`SECURITY.md`](SECURITY.md).

## License of contributions
By contributing, you agree your contributions are licensed under the project's
[Apache-2.0](LICENSE) license. You also agree to abide by our
[Code of Conduct](CODE_OF_CONDUCT.md).
