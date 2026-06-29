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

    /// Mint (or reuse) an opaque token for `value`. Ids are **random and
    /// unguessable** (128-bit CSPRNG) so a hijacked agent cannot enumerate or forge
    /// token references to make Guardian expand values it was never shown.
    fn token_for(&mut self, value: &str) -> String {
        if let Some(id) = self.by_value.get(value) {
            return format!("{PREFIX}{id}{SUFFIX}");
        }
        let id = random_id();
        self.by_id.insert(id.clone(), value.to_string());
        self.by_value.insert(value.to_string(), id.clone());
        format!("{PREFIX}{id}{SUFFIX}")
    }

    /// Replace known sensitive values (ASCII-case-insensitive) and Luhn-valid card
    /// numbers with opaque tokens. Single pass over **non-overlapping** spans of the
    /// original text, so a learned substring of a card can never leave a residual, and
    /// an inserted token can never be corrupted by a later replacement.
    pub fn tokenize(&mut self, text: &str) -> String {
        // Collect candidate spans on the *original* text.
        let mut spans: Vec<(usize, usize)> = Vec::new();
        for v in &self.known {
            spans.extend(find_all_ci(text, v));
        }
        spans.extend(find_card_spans(text));
        // Earliest start first; on a tie, the longer span wins (whole card over a
        // learned sub-span). Then greedily keep non-overlapping spans.
        spans.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
        let mut out = String::with_capacity(text.len());
        let mut pos = 0;
        for (s, e) in spans {
            if s < pos {
                continue; // overlaps an already-tokenized span
            }
            out.push_str(&text[pos..s]);
            let tok = self.token_for(&text[s..e]);
            out.push_str(&tok);
            pos = e;
        }
        out.push_str(&text[pos..]);
        out
    }

    /// Restore tokens to their real values — call **only** when writing the authorized
    /// egress action. An unknown token id is left untouched (fail safe: never invent data).
    ///
    /// SECURITY: token ids are random/unguessable, so the agent cannot *forge* a
    /// reference; but a value tokenized in one context could be *replayed* if the agent
    /// observed its token and the same vault is shared across sessions/principals.
    /// Before wiring this to a live egress path, the vault MUST be scoped per session
    /// (and ideally per action), so a token only resolves in the context that minted it
    /// (ADR-0005 open question — resolve to per-session). Do not feed agent-composed
    /// free text to a process-wide/persistent vault.
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

    /// Tokenize every string inside a JSON value (recursively) — used to redact a tool
    /// result before it reaches the agent.
    pub fn tokenize_json(&mut self, v: &serde_json::Value) -> serde_json::Value {
        use serde_json::Value;
        match v {
            Value::String(s) => Value::String(self.tokenize(s)),
            Value::Array(a) => Value::Array(a.iter().map(|x| self.tokenize_json(x)).collect()),
            Value::Object(o) => Value::Object(
                o.iter()
                    .map(|(k, x)| (k.clone(), self.tokenize_json(x)))
                    .collect(),
            ),
            other => other.clone(),
        }
    }

    /// Restore every token inside a JSON value (recursively) — used to detokenize an
    /// agent's outbound call args at the authorized egress. `&self`: never mints.
    pub fn detokenize_json(&self, v: &serde_json::Value) -> serde_json::Value {
        use serde_json::Value;
        match v {
            Value::String(s) => Value::String(self.detokenize(s)),
            Value::Array(a) => Value::Array(a.iter().map(|x| self.detokenize_json(x)).collect()),
            Value::Object(o) => Value::Object(
                o.iter()
                    .map(|(k, x)| (k.clone(), self.detokenize_json(x)))
                    .collect(),
            ),
            other => other.clone(),
        }
    }
}

/// A random, unguessable 128-bit token id (hex). Unforgeable so the agent cannot
/// enumerate ids; falls back to a non-secret marker only if the CSPRNG is unavailable
/// (never reuses a guessable counter).
fn random_id() -> String {
    let mut b = [0u8; 16];
    if getrandom::getrandom(&mut b).is_err() {
        // CSPRNG unavailable — extremely unlikely; use a clearly-marked unique-ish id.
        return format!("x{:p}", &b as *const _);
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Byte spans of every ASCII-case-insensitive occurrence of `needle` in `haystack`.
/// ASCII case-folding preserves byte length, so spans stay on char boundaries.
fn find_all_ci(haystack: &str, needle: &str) -> Vec<(usize, usize)> {
    let n = needle.len();
    if n == 0 || n > haystack.len() {
        return Vec::new();
    }
    let hb = haystack.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + n <= hb.len() {
        if hb[i..i + n].eq_ignore_ascii_case(needle.as_bytes())
            && haystack.is_char_boundary(i)
            && haystack.is_char_boundary(i + n)
        {
            out.push((i, i + n));
            i += n; // non-overlapping
        } else {
            i += 1;
        }
    }
    out
}

/// Byte spans of maximal `[0-9 -]` runs (trimmed to the digit extent) that hold 13–19
/// digits and pass Luhn — i.e. credit-card numbers.
fn find_card_spans(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut spans = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            let mut j = i;
            let mut last_digit = i;
            while j < bytes.len()
                && (bytes[j].is_ascii_digit() || bytes[j] == b' ' || bytes[j] == b'-')
            {
                if bytes[j].is_ascii_digit() {
                    last_digit = j;
                }
                j += 1;
            }
            let digits: String = text[start..j]
                .chars()
                .filter(|c| c.is_ascii_digit())
                .collect();
            if (13..=19).contains(&digits.len()) && luhn_ok(&digits) {
                spans.push((start, last_digit + 1));
            }
            i = j;
        } else {
            i += 1;
        }
    }
    spans
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
    fn known_value_match_is_case_insensitive() {
        let mut v = DataVault::new();
        v.learn("Mario Rossi");
        let red = v.tokenize("From MARIO ROSSI and mario rossi");
        assert!(
            !red.to_ascii_lowercase().contains("mario rossi"),
            "name leaked: {red}"
        );
        assert_eq!(v.detokenize(&red), "From MARIO ROSSI and mario rossi");
    }

    #[test]
    fn learning_a_card_substring_leaves_no_residual_digits() {
        // MEDIUM-1 regression: a learned sub-span of a card must not break the run and
        // leave the rest of the digits in clear — the whole card span wins.
        let mut v = DataVault::new();
        v.learn("4111"); // a prefix of the card below
        let red = v.tokenize("card 4111111111111111 end");
        assert!(!red.contains("4111"), "residual card digits leaked: {red}");
        assert_eq!(v.detokenize(&red), "card 4111111111111111 end");
    }

    #[test]
    fn token_ids_are_random_not_sequential() {
        let mut v = DataVault::new();
        v.learn("Alice Anderson");
        v.learn("Bob Brown");
        let red = v.tokenize("Alice Anderson and Bob Brown");
        // a hijacked agent must not be able to forge [[GDN-0]] / [[GDN-1]]
        assert!(
            !red.contains("[[GDN-0]]") && !red.contains("[[GDN-1]]"),
            "ids look sequential: {red}"
        );
        assert_eq!(
            v.detokenize("[[GDN-0]]"),
            "[[GDN-0]]",
            "guessed id must not resolve"
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
