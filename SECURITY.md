# Security Policy

Guardian is a security tool, so we hold its own security to a high bar and
welcome responsible disclosure. Thank you for helping keep users safe.

> ⚠️ Placeholders below marked `TODO` must be filled in before the first public
> release (contact channel, PGP key, response SLAs).

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

- **Preferred:** open a private GitHub Security Advisory — repository
  *Security* tab → *Report a vulnerability*.
- **Alternative:** email `TODO-security-contact` (PGP: `TODO-fingerprint`).

Include: the affected component and version/commit, reproduction steps, impact,
and any proof-of-concept.

## Especially in scope

Because Guardian's whole job is to mediate untrusted agent actions, we care most
about anything that breaks that mediation:

- **Interception gaps / bypass** — any way an agent reaches a tool, the network,
  or the filesystem **without** a Guardian decision.
- **Deny-path circumvention** — making a `deny`/`ask` action execute anyway.
- **Self-protection failures** — disabling or killing the daemon, removing/altering
  the proxy CA, or editing the active policy using only the supervised agent's
  privileges (see README §5.8).
- **Checker → decision influence** — any path where LLM/Checker output can change
  an allow/deny outcome. This must be impossible by design; a violation is critical.
- **Audit-log tampering** that `verify()` fails to detect.
- **Broker** leaking raw credentials to the agent, or bypassing macaroon/OAuth caveats.
- **Policy-pack supply chain** — loading an unsigned/altered pack, or a pack
  widening a critical category without explicit user opt-in.
- **Memory safety** in the JSON-RPC and HTTP-proxy parsers.

## Out of scope

- Social engineering of the human approver.
- Attacks that require an already-root local attacker (Guardian assumes the host
  is not already fully compromised).
- The spoofable agent-signaling HTTP header — documented as a courtesy signal,
  **not** a security control.

## Our commitment

- Acknowledge within `TODO` business days; initial triage and severity within `TODO`.
- Coordinated disclosure; public credit to reporters who want it.
- No bug bounty at this stage (volunteer open-source project).

## Supported versions

Pre-1.0: only the latest release and `main` are supported. This table will be
expanded at 1.0.
