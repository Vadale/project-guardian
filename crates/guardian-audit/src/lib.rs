//! `guardian-audit` — an append-only, hash-chained, tamper-evident audit log.
//!
//! Every Guardian decision is recorded as an [`AuditEntry`]. Entries are chained:
//! each row stores `prev_hash` and `hash = blake3(prev_hash || content)`, where
//! `content` is the exact serialized entry. A separate single-row `audit_head`
//! table records the latest `(seq, hash)` so [`AuditLog::verify`] can also detect
//! truncation of the tail — not just edits or reordering in the middle.
//!
//! **Tamper model.** The chain alone makes naive edits, reordering, and deletions
//! *evident*. To also stop a fully privileged attacker who rewrites every row *and*
//! the head consistently, open the log with [`AuditLog::open_signed`] (ROADMAP
//! §9.2): each append **ed25519-signs the head** (`seq || head_hash`) with a sealed
//! key, so a forged head fails [`AuditLog::verify`]. A read-only auditor checks the
//! head against an externally-supplied trusted key via [`AuditLog::verify_with_pubkey`].

#![forbid(unsafe_code)]

pub mod report;

use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use guardian_core::{Action, Decision};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The genesis `prev_hash` for the first entry (32 zero bytes).
const GENESIS: [u8; 32] = [0u8; 32];

/// One recorded decision. These are the only fields that are hashed; the
/// chaining columns (`seq`, `prev_hash`, `hash`) live alongside in the database.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp_ms: i64,
    pub action_id: String,
    pub action_kind: String,
    /// `"allow"`, `"ask"`, or `"deny"`.
    pub decision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checker_rationale: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_response: Option<String>,
    /// True if the decision was in a **critical category** (money / credential /
    /// exfiltration / irreversible deletion). Recorded so the report's adaptive
    /// suggestions can refuse to ever propose loosening a critical rule (invariant 4).
    #[serde(default)]
    pub critical: bool,
    /// Destination host, if the action had one (HTTP requests) — "where the agent
    /// went", for the activity archive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

impl AuditEntry {
    /// Build an entry from the core action/decision types.
    pub fn for_decision(
        action: &Action,
        decision: &Decision,
        matched_rule: Option<String>,
        checker_rationale: Option<String>,
        user_response: Option<String>,
        critical: bool,
    ) -> Self {
        let (decision, decision_reason) = match decision {
            Decision::Allow => ("allow".to_string(), None),
            Decision::Ask { reason } => ("ask".to_string(), Some(reason.clone())),
            Decision::Deny { reason } => ("deny".to_string(), Some(reason.clone())),
        };
        AuditEntry {
            timestamp_ms: action.context.timestamp_ms,
            action_id: action.id.as_str().to_string(),
            action_kind: format!("{:?}", action.kind),
            decision,
            decision_reason,
            matched_rule,
            checker_rationale,
            user_response,
            critical,
            host: action.context.host.clone(),
        }
    }
}

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("audit log tampering detected: {0}")]
    Tampered(String),
    #[error("bad signing/verifying key: {0}")]
    BadKey(String),
}

/// An append-only, hash-chained audit log backed by SQLite. Optionally **signs the
/// chain head** with ed25519 (§9.2): with a (sealed) signing key, each append signs
/// `seq || head_hash`, so an attacker who rewrites every row *and* the head still
/// can't produce a valid signature — `verify` then fails. Without a key it is the
/// hash-chain only (still evident to naive edits/reorder/truncation).
pub struct AuditLog {
    conn: Connection,
    /// When set, the head is signed on every append and checked by `verify`.
    signing_key: Option<SigningKey>,
}

impl AuditLog {
    /// Open (or create) a log at `path` (hash-chain only).
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        Self::from_conn(Connection::open(path)?, None)
    }

    /// Open (or create) a log at `path` whose head is **ed25519-signed** with
    /// `signing_key` (keep it sealed — e.g. the OS keychain).
    pub fn open_signed(
        path: impl AsRef<Path>,
        signing_key: SigningKey,
    ) -> Result<Self, AuditError> {
        Self::from_conn(Connection::open(path)?, Some(signing_key))
    }

    /// Open an in-memory log (useful for tests).
    pub fn open_in_memory() -> Result<Self, AuditError> {
        Self::from_conn(Connection::open_in_memory()?, None)
    }

    /// In-memory log with a signed head (for tests).
    pub fn open_in_memory_signed(signing_key: SigningKey) -> Result<Self, AuditError> {
        Self::from_conn(Connection::open_in_memory()?, Some(signing_key))
    }

    fn from_conn(conn: Connection, signing_key: Option<SigningKey>) -> Result<Self, AuditError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_log (
                 seq       INTEGER PRIMARY KEY,
                 content   TEXT NOT NULL,
                 prev_hash BLOB NOT NULL,
                 hash      BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS audit_head (
                 id        INTEGER PRIMARY KEY CHECK (id = 0),
                 last_seq  INTEGER NOT NULL,
                 last_hash BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS audit_head_sig (
                 id  INTEGER PRIMARY KEY CHECK (id = 0),
                 sig BLOB NOT NULL
             );",
        )?;
        // Ensure the head row exists (genesis state for an empty log).
        conn.execute(
            "INSERT OR IGNORE INTO audit_head (id, last_seq, last_hash) VALUES (0, 0, ?1)",
            params![GENESIS.to_vec()],
        )?;
        Ok(Self { conn, signing_key })
    }

    /// Append an entry, extending the chain. Returns the new sequence number.
    pub fn append(&mut self, entry: &AuditEntry) -> Result<u64, AuditError> {
        let content = serde_json::to_string(entry)?;
        let tx = self.conn.transaction()?;
        let (last_seq, last_hash): (i64, Vec<u8>) = tx.query_row(
            "SELECT last_seq, last_hash FROM audit_head WHERE id = 0",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let seq = last_seq + 1;
        let hash = chain_hash(&last_hash, content.as_bytes());
        tx.execute(
            "INSERT INTO audit_log (seq, content, prev_hash, hash) VALUES (?1, ?2, ?3, ?4)",
            params![seq, content, last_hash, hash.to_vec()],
        )?;
        tx.execute(
            "UPDATE audit_head SET last_seq = ?1, last_hash = ?2 WHERE id = 0",
            params![seq, hash.to_vec()],
        )?;
        // Sign the new head if a signing key is configured (§9.2). The signature
        // covers `seq || head_hash`, so the head can't be forged without the key.
        if let Some(key) = &self.signing_key {
            let sig = key.sign(&head_message(seq, &hash)).to_bytes().to_vec();
            tx.execute(
                "INSERT INTO audit_head_sig (id, sig) VALUES (0, ?1)
                 ON CONFLICT(id) DO UPDATE SET sig = ?1",
                params![sig],
            )?;
        }
        tx.commit()?;
        Ok(seq as u64)
    }

    /// Number of entries currently in the log.
    pub fn len(&self) -> Result<u64, AuditError> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM audit_log", [], |r| r.get(0))?;
        Ok(n as u64)
    }

    /// `true` if the log has no entries.
    pub fn is_empty(&self) -> Result<bool, AuditError> {
        Ok(self.len()? == 0)
    }

    /// The most recent `limit` entries with their sequence numbers, **oldest-first**
    /// (for chronological display). For browsing the log (e.g. `guardian log`).
    pub fn tail(&self, limit: usize) -> Result<Vec<(u64, AuditEntry)>, AuditError> {
        let mut stmt = self
            .conn
            .prepare("SELECT seq, content FROM audit_log ORDER BY seq DESC LIMIT ?1")?;
        let rows = stmt.query_map([limit as i64], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (seq, content) = row?;
            // Resilient: a single unparseable row (the case you reach for `tail`
            // precisely *when* the log looks corrupt) must not blank the listing —
            // render a placeholder. `verify()` is the authority on tampering.
            let entry = serde_json::from_str(&content).unwrap_or_else(|_| AuditEntry {
                timestamp_ms: 0,
                action_id: String::new(),
                action_kind: "<unreadable>".to_string(),
                decision: "?".to_string(),
                decision_reason: Some("row content is not valid JSON".to_string()),
                matched_rule: None,
                checker_rationale: None,
                user_response: None,
                critical: false,
                host: None,
            });
            out.push((seq as u64, entry));
        }
        out.reverse(); // most-recent-first from SQL → oldest-first for display
        Ok(out)
    }

    /// Walk the chain and confirm it is intact, **and** (if this log was opened with
    /// a signing key) confirm the head signature. Returns [`AuditError::Tampered`]
    /// on any inconsistency.
    pub fn verify(&self) -> Result<(), AuditError> {
        let (head_seq, head_hash) = self.verify_chain()?;
        if let Some(key) = &self.signing_key {
            self.verify_head_sig(head_seq, &head_hash, &key.verifying_key())?;
        }
        Ok(())
    }

    /// Verify the chain **and** the head signature against an **externally-supplied
    /// trusted public key** (hex), for a read-only verifier that doesn't hold the
    /// secret. The trusted key must come from outside the DB (e.g. sealed config),
    /// so an attacker who rewrites the DB can't also swap in their own key.
    pub fn verify_with_pubkey(&self, trusted_pubkey_hex: &str) -> Result<(), AuditError> {
        let bytes: [u8; 32] = hex::decode(trusted_pubkey_hex.trim())
            .map_err(|e| AuditError::BadKey(e.to_string()))?
            .try_into()
            .map_err(|_| AuditError::BadKey("public key must be 32 bytes".into()))?;
        let key =
            VerifyingKey::from_bytes(&bytes).map_err(|e| AuditError::BadKey(e.to_string()))?;
        let (head_seq, head_hash) = self.verify_chain()?;
        self.verify_head_sig(head_seq, &head_hash, &key)
    }

    /// Check the stored head signature against `key`.
    fn verify_head_sig(
        &self,
        head_seq: i64,
        head_hash: &[u8],
        key: &VerifyingKey,
    ) -> Result<(), AuditError> {
        let sig_bytes: Vec<u8> = self
            .conn
            .query_row("SELECT sig FROM audit_head_sig WHERE id = 0", [], |r| {
                r.get(0)
            })
            .map_err(|_| AuditError::Tampered("head signature is missing".into()))?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| AuditError::Tampered("head signature is malformed".into()))?;
        let sig = Signature::from_bytes(&sig_arr);
        key.verify(&head_message(head_seq, head_hash), &sig)
            .map_err(|_| AuditError::Tampered("head signature does not verify".into()))
    }

    /// Walk the chain and confirm it is intact (link/content/order/truncation),
    /// returning the verified `(head_seq, head_hash)`.
    fn verify_chain(&self) -> Result<(i64, Vec<u8>), AuditError> {
        let mut stmt = self
            .conn
            .prepare("SELECT seq, content, prev_hash, hash FROM audit_log ORDER BY seq ASC")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, Vec<u8>>(3)?,
            ))
        })?;

        let mut prev = GENESIS.to_vec();
        let mut last_seq = 0i64;
        let mut last_hash = GENESIS.to_vec();

        for (expected_seq, row) in (1i64..).zip(rows) {
            let (seq, content, prev_hash, hash) = row?;
            if seq != expected_seq {
                return Err(AuditError::Tampered(format!(
                    "expected seq {expected_seq}, found {seq} (gap, reorder, or deletion)"
                )));
            }
            if prev_hash != prev {
                return Err(AuditError::Tampered(format!(
                    "prev_hash mismatch at seq {seq} (broken chain link)"
                )));
            }
            let recomputed = chain_hash(&prev, content.as_bytes()).to_vec();
            if recomputed != hash {
                return Err(AuditError::Tampered(format!(
                    "hash mismatch at seq {seq} (entry content was modified)"
                )));
            }
            prev = hash.clone();
            last_seq = seq;
            last_hash = hash;
        }

        // Compare the chain tail against the recorded head: detects truncation.
        let (head_seq, head_hash): (i64, Vec<u8>) = self.conn.query_row(
            "SELECT last_seq, last_hash FROM audit_head WHERE id = 0",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if head_seq != last_seq || head_hash != last_hash {
            return Err(AuditError::Tampered(format!(
                "head mismatch: head records seq {head_seq} but chain ends at {last_seq} (tail truncation)"
            )));
        }
        Ok((last_seq, last_hash))
    }
}

/// The bytes signed for the head: `seq` (LE) followed by the head hash.
fn head_message(seq: i64, hash: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(8 + hash.len());
    m.extend_from_slice(&seq.to_le_bytes());
    m.extend_from_slice(hash);
    m
}

/// `blake3(prev || content)` — the chaining hash.
fn chain_hash(prev: &[u8], content: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(prev);
    hasher.update(content);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, decision: &str) -> AuditEntry {
        AuditEntry {
            timestamp_ms: 1_700_000_000_000,
            action_id: id.to_string(),
            action_kind: "Exec".to_string(),
            decision: decision.to_string(),
            decision_reason: None,
            matched_rule: None,
            checker_rationale: None,
            user_response: None,
            critical: false,
            host: None,
        }
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn signed_head_verifies_and_a_swapped_signature_is_rejected() {
        let mut log = AuditLog::open_in_memory_signed(signing_key()).unwrap();
        log.append(&entry("a", "allow")).unwrap();
        log.append(&entry("b", "deny")).unwrap();
        assert!(log.verify().is_ok());
        // External read-only verification with the trusted public key.
        let pubkey = hex::encode(signing_key().verifying_key().to_bytes());
        assert!(log.verify_with_pubkey(&pubkey).is_ok());
        // The wrong key must not verify.
        let other = hex::encode([9u8; 32]);
        assert!(log.verify_with_pubkey(&other).is_err());
        // Corrupting the stored signature is detected.
        log.conn
            .execute(
                "UPDATE audit_head_sig SET sig = ?1 WHERE id = 0",
                params![vec![0u8; 64]],
            )
            .unwrap();
        assert!(log.verify().is_err());
    }

    #[test]
    fn full_rewrite_without_the_key_fails_the_head_signature() {
        // The sealed-key property: an attacker rewrites the (single) row's content
        // AND re-chains the hash AND updates the head so the hash-chain is internally
        // consistent — but without the signing key the head signature no longer
        // matches the new head, so `verify` fails.
        let mut log = AuditLog::open_in_memory_signed(signing_key()).unwrap();
        log.append(&entry("a", "allow")).unwrap();

        let forged = serde_json::to_string(&entry("a", "deny")).unwrap(); // flip allow→deny
        let new_hash = chain_hash(&GENESIS, forged.as_bytes()).to_vec();
        log.conn
            .execute(
                "UPDATE audit_log SET content = ?1, hash = ?2 WHERE seq = 1",
                params![forged, new_hash],
            )
            .unwrap();
        log.conn
            .execute(
                "UPDATE audit_head SET last_hash = ?1 WHERE id = 0",
                params![new_hash],
            )
            .unwrap();
        // The hash-chain alone is now internally consistent…
        assert!(log.verify_chain().is_ok());
        // …but the head signature was over the original head → verify fails.
        assert!(matches!(log.verify(), Err(AuditError::Tampered(_))));
    }

    #[test]
    fn clean_chain_verifies() {
        let mut log = AuditLog::open_in_memory().unwrap();
        log.append(&entry("a", "allow")).unwrap();
        log.append(&entry("b", "ask")).unwrap();
        log.append(&entry("c", "deny")).unwrap();
        assert_eq!(log.len().unwrap(), 3);
        assert!(log.verify().is_ok());
    }

    #[test]
    fn tail_returns_recent_entries_oldest_first() {
        let mut log = AuditLog::open_in_memory().unwrap();
        log.append(&entry("a", "allow")).unwrap();
        log.append(&entry("b", "ask")).unwrap();
        log.append(&entry("c", "deny")).unwrap();
        let t = log.tail(2).unwrap();
        assert_eq!(t.len(), 2);
        assert_eq!((t[0].0, t[0].1.action_id.as_str()), (2, "b")); // oldest of the tail
        assert_eq!((t[1].0, t[1].1.action_id.as_str()), (3, "c"));
        // Asking for more than exist returns all, oldest-first.
        assert_eq!(log.tail(10).unwrap().len(), 3);
    }

    #[test]
    fn tail_is_resilient_to_an_unparseable_row() {
        let mut log = AuditLog::open_in_memory().unwrap();
        log.append(&entry("a", "allow")).unwrap();
        log.append(&entry("b", "deny")).unwrap();
        // Corrupt one row's content (private field reachable from the child test mod).
        log.conn
            .execute(
                "UPDATE audit_log SET content = 'not json' WHERE seq = 1",
                [],
            )
            .unwrap();
        let t = log.tail(10).unwrap(); // does NOT error — degrades to a placeholder
        assert_eq!(t.len(), 2);
        assert_eq!(t[0].1.action_kind, "<unreadable>");
        assert_eq!(t[1].1.action_id, "b");
    }

    #[test]
    fn empty_log_verifies() {
        let log = AuditLog::open_in_memory().unwrap();
        assert!(log.is_empty().unwrap());
        assert!(log.verify().is_ok());
    }

    #[test]
    fn content_mutation_is_detected() {
        let mut log = AuditLog::open_in_memory().unwrap();
        log.append(&entry("a", "allow")).unwrap();
        log.append(&entry("b", "deny")).unwrap();
        // Flip a past decision directly in the DB without recomputing the hash.
        log.conn
            .execute(
                "UPDATE audit_log SET content = replace(content, 'allow', 'deny') WHERE seq = 1",
                [],
            )
            .unwrap();
        assert!(matches!(log.verify(), Err(AuditError::Tampered(_))));
    }

    #[test]
    fn tail_truncation_is_detected() {
        let mut log = AuditLog::open_in_memory().unwrap();
        log.append(&entry("a", "allow")).unwrap();
        log.append(&entry("b", "ask")).unwrap();
        log.conn
            .execute("DELETE FROM audit_log WHERE seq = 2", [])
            .unwrap();
        assert!(matches!(log.verify(), Err(AuditError::Tampered(_))));
    }

    #[test]
    fn middle_deletion_is_detected() {
        let mut log = AuditLog::open_in_memory().unwrap();
        log.append(&entry("a", "allow")).unwrap();
        log.append(&entry("b", "ask")).unwrap();
        log.append(&entry("c", "deny")).unwrap();
        log.conn
            .execute("DELETE FROM audit_log WHERE seq = 2", [])
            .unwrap();
        assert!(matches!(log.verify(), Err(AuditError::Tampered(_))));
    }

    #[test]
    fn records_a_decision_from_core_types() {
        use guardian_core::{ActionContext, ActionId, ActionKind};

        let action = Action {
            id: ActionId::new("01ABC"),
            kind: ActionKind::Exec,
            tool: "shell.run".to_string(),
            args: serde_json::json!({ "cmd": "ls" }),
            capability: None,
            context: ActionContext {
                timestamp_ms: 42,
                source: "test".to_string(),
                session: None,
                host: None,
                principal: None,
                path: None,
                extra: serde_json::Map::new(),
            },
        };
        let decision = Decision::Deny {
            reason: "blocked".to_string(),
        };
        let e =
            AuditEntry::for_decision(&action, &decision, Some("exfil".into()), None, None, true);
        assert_eq!(e.decision, "deny");
        assert!(e.critical);
        assert_eq!(e.decision_reason.as_deref(), Some("blocked"));
        assert_eq!(e.action_kind, "Exec");
        assert_eq!(e.action_id, "01ABC");
        assert_eq!(e.matched_rule.as_deref(), Some("exfil"));

        // And it chains/verifies when appended.
        let mut log = AuditLog::open_in_memory().unwrap();
        log.append(&e).unwrap();
        assert!(log.verify().is_ok());
    }
}
