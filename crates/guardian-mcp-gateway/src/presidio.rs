//! Presidio sidecar detector (ADR-0005) — **optional**, behind the `presidio` feature.
//!
//! Microsoft Presidio (MIT) detects fuzzy PII (names, locations, etc.) in free text. We
//! run it as a sidecar and call its `/analyze` HTTP endpoint; the detected spans are fed
//! to the gateway's data vault to be tokenized alongside the known values. This keeps the
//! hard ML detection out of the deterministic core (see ADR-0005). It is advisory: if the
//! sidecar is unreachable or returns nothing, detection falls back to known-values + the
//! Luhn card detector, and the secret-exfiltration deny rule remains the backstop.
//!
//! Run Presidio locally, e.g.:
//!   docker run -p 5002:3000 mcr.microsoft.com/presidio-analyzer
//! then build with `--features presidio` and:
//!   Gateway::new(..).with_pii_detector(Arc::new(HttpPiiDetector::new("http://localhost:5002/analyze")))

use crate::PiiDetector;

/// Calls a Presidio `analyzer` `/analyze` endpoint and returns the detected substrings.
pub struct HttpPiiDetector {
    endpoint: String,
    language: String,
    min_score: f64,
    client: reqwest::Client,
}

impl HttpPiiDetector {
    /// `endpoint` is the full analyze URL, e.g. `http://localhost:5002/analyze`.
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            language: "en".to_string(),
            min_score: 0.5,
            client: reqwest::Client::new(),
        }
    }

    /// Set the language code (default `"en"`).
    pub fn with_language(mut self, lang: impl Into<String>) -> Self {
        self.language = lang.into();
        self
    }

    /// Minimum confidence score to act on a detection (default 0.5).
    pub fn with_min_score(mut self, score: f64) -> Self {
        self.min_score = score;
        self
    }
}

#[async_trait::async_trait]
impl PiiDetector for HttpPiiDetector {
    async fn detect(&self, text: &str) -> Vec<String> {
        let body = serde_json::json!({ "text": text, "language": self.language });
        // Advisory: any failure (sidecar down, bad response) yields no detections.
        let resp = match self.client.post(&self.endpoint).json(&body).send().await {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        let entities: Vec<serde_json::Value> = match resp.json().await {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };
        // Presidio offsets are Python str indices = char offsets, so slice on chars.
        let chars: Vec<char> = text.chars().collect();
        entities
            .iter()
            .filter_map(|e| {
                let score = e.get("score").and_then(|v| v.as_f64()).unwrap_or(0.0);
                if score < self.min_score {
                    return None;
                }
                let start = e.get("start")?.as_u64()? as usize;
                let end = e.get("end")?.as_u64()? as usize;
                (start < end && end <= chars.len()).then(|| chars[start..end].iter().collect())
            })
            .collect()
    }
}
