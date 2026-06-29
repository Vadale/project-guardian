//! Data vault — tokenization of *carried* sensitive values (ADR-0005).
//!
//! The credential broker, generalized: any carried sensitive value the agent must not
//! hold (name, IBAN, account number, address, bank name, card number) is replaced with
//! an **opaque token** before the agent sees it, and restored only when Guardian writes
//! the authorized egress action. The agent works with placeholders — *it cannot reveal
//! what it never held*, the data twin of the broker's credential indirection.
//!
//! Detection is deliberately split per ADR-0005:
//! - **exact-match of known values** (`learn`) — high precision, no guessing; this is the
//!   part Guardian owns in Rust because it is simple and security-critical;
//! - a single built-in **Luhn-checked credit-card** detector as a high-confidence
//!   structured example;
//! - fuzzy free-text NER (names in prose) is **delegated to a sidecar** (Presidio / LLM
//!   Guard); its detected spans are fed back in via `learn`. We do not do NER here.

use std::collections::HashMap;

const PREFIX: &str = "[[GDN-";
const SUFFIX: &str = "]]";
/// Below this length, an exact-match value is ignored to avoid trivial, noisy hits.
const MIN_KNOWN_LEN: usize = 4;

/// Holds the token↔value mapping and tokenizes/detokenizes text at Guardian's boundary.
/// The map is the high-value asset (same trust model as the credential broker); it never
/// leaves Guardian, and the agent only ever sees the opaque tokens.
#[derive(Default)]
pub struct DataVault {
    known: Vec<String>,
    by_id: HashMap<String, String>,
    by_value: HashMap<String, String>,
    next: u64,
}

impl DataVault {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a sensitive value to tokenize whenever it appears (idempotent).
    pub fn learn(&mut self, value: &str) {
        let v = value.trim();
        if v.len() >= MIN_KNOWN_LEN && !self.known.iter().any(|k| k == v) {
            self.known.push(v.to_string());
        }
    }

    /// Mint (or reuse) a stable opaque token for `value`.
    fn token_for(&mut self, value: &str) -> String {
        if let Some(id) = self.by_value.get(value) {
            return format!("{PREFIX}{id}{SUFFIX}");
        }
        let id = format!("{:x}", self.next);
        self.next += 1;
        self.by_id.insert(id.clone(), value.to_string());
        self.by_value.insert(value.to_string(), id.clone());
        format!("{PREFIX}{id}{SUFFIX}")
    }

    /// Replace known sensitive values and Luhn-valid card numbers with opaque tokens.
    pub fn tokenize(&mut self, text: &str) -> String {
        // Longest known value first, so an overlapping value is tokenized whole.
        let mut known = self.known.clone();
        known.sort_by_key(|k| std::cmp::Reverse(k.len()));
        let mut out = text.to_string();
        for v in known {
            if out.contains(&v) {
                let tok = self.token_for(&v);
                out = out.replace(&v, &tok);
            }
        }
        self.tokenize_cards(&out)
    }

    /// Restore tokens to their real values — call **only** when writing the authorized
    /// egress action. An unknown token id is left untouched (fail safe: never invent data).
    pub fn detokenize(&self, text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(start) = rest.find(PREFIX) {
            out.push_str(&rest[..start]);
            let after = &rest[start + PREFIX.len()..];
            match after.find(SUFFIX) {
                Some(end) => {
                    let id = &after[..end];
                    match self.by_id.get(id) {
                        Some(v) => out.push_str(v),
                        None => {
                            // unknown id: leave the token verbatim
                            out.push_str(PREFIX);
                            out.push_str(id);
                            out.push_str(SUFFIX);
                        }
                    }
                    rest = &after[end + SUFFIX.len()..];
                }
                None => {
                    // no closing marker: emit the rest verbatim and stop
                    out.push_str(PREFIX);
                    out.push_str(after);
                    rest = "";
                }
            }
        }
        out.push_str(rest);
        out
    }

    /// Detect and tokenize maximal `[0-9 -]` runs that hold 13–19 digits and pass Luhn.
    fn tokenize_cards(&mut self, text: &str) -> String {
        let bytes = text.as_bytes();
        let mut out = String::with_capacity(text.len());
        let mut i = 0;
        while i < bytes.len() {
            let c = bytes[i];
            if c.is_ascii_digit() {
                // collect a maximal run of digits / single spaces / dashes
                let start = i;
                let mut j = i;
                while j < bytes.len()
                    && (bytes[j].is_ascii_digit() || bytes[j] == b' ' || bytes[j] == b'-')
                {
                    j += 1;
                }
                let run = &text[start..j];
                let digits: String = run.chars().filter(|c| c.is_ascii_digit()).collect();
                if (13..=19).contains(&digits.len()) && luhn_ok(&digits) {
                    let tok = self.token_for(run.trim());
                    // preserve any leading/trailing separator the trim removed
                    let lead = &run[..run.len() - run.trim_start().len()];
                    let trail = &run[run.trim_end().len()..];
                    out.push_str(lead);
                    out.push_str(&tok);
                    out.push_str(trail);
                } else {
                    out.push_str(run);
                }
                i = j;
            } else {
                // push this (possibly multi-byte) char unchanged
                let ch_len = utf8_len(c);
                out.push_str(&text[i..i + ch_len]);
                i += ch_len;
            }
        }
        out
    }
}

/// Byte length of a UTF-8 sequence given its leading byte.
fn utf8_len(b: u8) -> usize {
    match b {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}

/// Luhn checksum over an all-digit string.
fn luhn_ok(digits: &str) -> bool {
    let mut sum = 0u32;
    let mut double = false;
    for d in digits.bytes().rev() {
        let mut v = (d - b'0') as u32;
        if double {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
        double = !double;
    }
    sum % 10 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_values_round_trip_and_are_opaque() {
        let mut v = DataVault::new();
        v.learn("Mario Rossi");
        v.learn("IT60X0542811101000000123456"); // IBAN
        let clear = "Bonifico da Mario Rossi, IBAN IT60X0542811101000000123456, urgente.";
        let red = v.tokenize(clear);
        // the agent-facing text must contain neither the name nor the IBAN
        assert!(!red.contains("Mario Rossi"), "name leaked: {red}");
        assert!(
            !red.contains("IT60X0542811101000000123456"),
            "IBAN leaked: {red}"
        );
        assert!(red.contains("[[GDN-"), "expected tokens: {red}");
        // only Guardian, at egress, restores them
        assert_eq!(v.detokenize(&red), clear);
    }

    #[test]
    fn same_value_reuses_one_stable_token() {
        let mut v = DataVault::new();
        v.learn("ACME Bank");
        let red = v.tokenize("ACME Bank ... ACME Bank again");
        // both occurrences map to the same token id
        let first = red.split(SUFFIX).next().unwrap();
        assert_eq!(
            red.matches(first).count(),
            2,
            "token not stable/deduped: {red}"
        );
        assert_eq!(v.detokenize(&red), "ACME Bank ... ACME Bank again");
    }

    #[test]
    fn detects_and_tokenizes_a_luhn_valid_card() {
        let mut v = DataVault::new();
        for card in [
            "4111111111111111",
            "4111 1111 1111 1111",
            "4111-1111-1111-1111",
        ] {
            let red = v.tokenize(&format!("card: {card} ok"));
            assert!(!red.contains("4111"), "card leaked: {red}");
            assert!(red.contains("[[GDN-"));
            assert!(
                v.detokenize(&red).contains(card),
                "round-trip failed for {card}"
            );
        }
    }

    #[test]
    fn leaves_non_cards_and_plain_text_alone() {
        let mut v = DataVault::new();
        // an 11-digit phone is not a 13-19 digit card; small numbers are left alone
        let txt = "call 1-800-273-8255 about order 42 today";
        assert_eq!(
            v.tokenize(txt),
            txt,
            "must not tokenize non-card numbers / plain text"
        );
    }

    #[test]
    fn unknown_token_is_left_verbatim_on_detokenize() {
        let v = DataVault::new();
        assert_eq!(
            v.detokenize("hello [[GDN-deadbeef]] world"),
            "hello [[GDN-deadbeef]] world"
        );
    }

    #[test]
    fn short_values_are_not_learned() {
        let mut v = DataVault::new();
        v.learn("ab"); // too short
        assert_eq!(v.tokenize("ab cd"), "ab cd");
    }
}
