//! `guardian-audit` — an append-only, hash-chained, tamper-evident audit log.
//!
//! Every Guardian decision is recorded as an [`AuditEntry`]. Entries are chained:
//! each row stores `prev_hash` and `hash = blake3(prev_hash || content)`, where
//! `content` is the exact serialized entry. A separate single-row `audit_head`
//! table records the latest `(seq, hash)` so [`AuditLog::verify`] can also detect
//! truncation of the tail — not just edits or reordering in the middle.
//!
//! **Tamper model.** The chain makes naive edits, reordering, and deletions
//! *evident*: any such change breaks [`AuditLog::verify`]. It does **not** by
//! itself stop a fully privileged attacker who rewrites every row *and* the head
//! consistently — that requires signing the head with a sealed key. That hook is
//! intentionally left for later behind the `signing` feature (ROADMAP Task 9.2).

#![forbid(unsafe_code)]

use std::path::Path;

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
}

impl AuditEntry {
    /// Build an entry from the core action/decision types.
    pub fn for_decision(
        action: &Action,
        decision: &Decision,
        matched_rule: Option<String>,
        checker_rationale: Option<String>,
        user_response: Option<String>,
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
}

/// An append-only, hash-chained audit log backed by SQLite.
pub struct AuditLog {
    conn: Connection,
}

impl AuditLog {
    /// Open (or create) a log at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        Self::from_conn(Connection::open(path)?)
    }

    /// Open an in-memory log (useful for tests).
    pub fn open_in_memory() -> Result<Self, AuditError> {
        Self::from_conn(Connection::open_in_memory()?)
    }

    fn from_conn(conn: Connection) -> Result<Self, AuditError> {
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
             );",
        )?;
        // Ensure the head row exists (genesis state for an empty log).
        conn.execute(
            "INSERT OR IGNORE INTO audit_head (id, last_seq, last_hash) VALUES (0, 0, ?1)",
            params![GENESIS.to_vec()],
        )?;
        Ok(Self { conn })
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

    /// Walk the chain and confirm it is intact. Returns
    /// [`AuditError::Tampered`] on the first inconsistency (broken link,
    /// content edit, sequence gap/reorder, or tail truncation).
    pub fn verify(&self) -> Result<(), AuditError> {
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
        Ok(())
    }
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
        }
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
        let e = AuditEntry::for_decision(&action, &decision, Some("exfil".into()), None, None);
        assert_eq!(e.decision, "deny");
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
