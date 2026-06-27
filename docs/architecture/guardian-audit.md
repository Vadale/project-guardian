# guardian-audit

Append-only, hash-chained, tamper-evident audit log (ROADMAP Task 6.2).

## What it does
Records every Guardian decision as an `AuditEntry` and chains entries so that
edits, reordering, and deletions become *evident*. Backed by SQLite (rusqlite,
bundled).

## Public API
- `AuditEntry` — the recorded content: `timestamp_ms`, `action_id`,
  `action_kind`, `decision` (`allow`/`ask`/`deny`), and optional
  `decision_reason`, `matched_rule`, `checker_rationale`, `user_response`.
  `AuditEntry::for_decision(action, decision, ...)` builds one from the core types.
- `AuditLog::open(path)` / `open_in_memory()` — open/create the log.
- `AuditLog::append(&entry) -> seq` — extend the chain.
- `AuditLog::verify() -> Result<(), AuditError>` — walk and validate the chain.
- `len()` / `is_empty()`.

## How the chain works
Each row stores the serialized `content`, a `prev_hash`, and
`hash = blake3(prev_hash || content)`. The first entry chains from a genesis of
32 zero bytes. A single-row `audit_head` table records the latest `(seq, hash)`.

`verify()` walks rows ordered by `seq` and fails (`AuditError::Tampered`) on:
- a sequence gap/reorder (detects middle deletion or reordering),
- a `prev_hash` that doesn't match the previous row's hash (broken link),
- a recomputed `hash` that doesn't match the stored one (content edit),
- a final `(seq, hash)` that doesn't match `audit_head` (tail truncation).

## Invariants / limits
- The chain makes naive tampering evident. It does **not** stop a fully
  privileged attacker who rewrites every row *and* the head consistently — that
  requires signing the head with a sealed key, left behind the `signing` feature
  (ROADMAP Task 9.2). `#![forbid(unsafe_code)]`.
- `verify()` hashes the exact stored `content` bytes, so validation never depends
  on re-serialization being byte-identical.

## Tests
Clean chain and empty log verify; content mutation, tail truncation, and middle
deletion are each detected; `for_decision` records and chains correctly.

## Report & adaptive suggestions (`report` module, §8.3 + §8.2)
`report::build_report(&[AuditEntry]) -> Report` is pure, order-independent analysis
over a **recent window** of entries (the caller passes the window — that's the
"decaying" part). It returns allow/ask/deny counts, the **top blocked** rules, and
**suggestions**: a rule (grouped by `matched_rule`, else action kind — context-bound)
that was asked ≥3× and **approved every time** is surfaced as "consider allowing".

Suggestions are **advisory only** — Guardian never edits the policy — and a group is
**never suggested** if any of its entries was `critical` (invariant 4: critical
categories — money / credential / exfiltration / deletion — are never auto-downgraded).
This is why `AuditEntry` carries a `critical` flag. The CLI `guardian report` renders it.

## Sealed-key head signing (§9.2)
`AuditLog::open_signed(path, signing_key)` makes the log resist a **fully-privileged
rewrite**: on every append it ed25519-signs `seq || head_hash` (stored in
`audit_head_sig`). The hash-chain alone can't catch an attacker who rewrites every
row *and* the head consistently — but they can't forge the head signature without the
sealed key, so `verify()` fails. A read-only auditor (a different process, no secret)
checks the head against an **externally-supplied** trusted key via
`verify_with_pubkey(hex)` / `guardian log --verify-key <hex>` — the trusted key must
come from outside the DB so it can't be swapped in. Keep the signing key sealed (e.g.
the OS keychain). Without a key the log is the hash-chain only (still evident to
naive edits/reorder/truncation).
