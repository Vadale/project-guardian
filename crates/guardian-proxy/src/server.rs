//! The live forward proxy: wires the [mediation core](crate) onto real sockets
//! via `hudsucker`. Every request is normalized, **inspected** (the body is
//! buffered up to a cap and scanned for the user's own secrets; a WebSocket
//! upgrade is noted), run through the **deterministic policy**, recorded to the
//! **tamper-evident audit log**, and then either forwarded (with the broker's
//! `Authorization` attached for a brokered host) or answered with a `403` carrying
//! the block reason. The agent points `HTTP(S)_PROXY` at this server.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use guardian_audit::{AuditEntry, AuditLog};
use guardian_broker::Broker;
use guardian_core::Action;
use guardian_policy::{CompiledPolicy, EvalEnv, EvalOutcome};

use http::{header, HeaderValue, Request, Response, StatusCode};
use http_body_util::BodyExt;
use hudsucker::rustls::crypto::aws_lc_rs;
use hudsucker::{Body, HttpContext, HttpHandler, Proxy, RequestOrResponse};

use crate::ca::LocalCa;
use crate::{classify, to_action, HttpRequest, ProxyOutcome};

/// Largest request body the proxy buffers in memory for exfiltration inspection.
/// Bodies above this (or with no `Content-Length`) are forwarded without buffering
/// and reported as `inspected = false` to the policy.
const BODY_INSPECT_CAP: usize = 1024 * 1024;

/// What the proxy learned by looking at a request before deciding. Exposed to the
/// policy under `action.context.extra` so rules can act on it.
#[derive(Debug, Clone)]
struct RequestSignals {
    /// Whether the body was actually buffered and scanned.
    inspected: bool,
    /// Body length in bytes (from `Content-Length`, or the buffered size).
    len: usize,
    /// The body contains one of the broker's held secrets (exfiltration attempt).
    contains_known_secret: bool,
    /// The request is a WebSocket upgrade (`Upgrade: websocket`).
    is_websocket_upgrade: bool,
}

impl RequestSignals {
    /// Signals for a request whose body was not inspected (e.g. CONNECT, no body,
    /// or over the cap) — the conservative default.
    fn uninspected() -> Self {
        Self {
            inspected: false,
            len: 0,
            contains_known_secret: false,
            is_websocket_upgrade: false,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("CA error: {0}")]
    Ca(#[from] crate::ca::CaError),
    #[error("proxy error: {0}")]
    Hudsucker(#[from] hudsucker::Error),
}

/// The per-request handler. Cheap to clone (hudsucker clones it per connection):
/// the policy/broker are shared `Arc`s and the audit log is behind a `Mutex`.
#[derive(Clone)]
pub struct GuardianHandler {
    policy: Arc<CompiledPolicy>,
    env: Arc<EvalEnv>,
    broker: Arc<Broker>,
    audit: Arc<Mutex<AuditLog>>,
}

impl GuardianHandler {
    pub fn new(
        policy: Arc<CompiledPolicy>,
        env: Arc<EvalEnv>,
        broker: Arc<Broker>,
        audit: Arc<Mutex<AuditLog>>,
    ) -> Self {
        Self {
            policy,
            env,
            broker,
            audit,
        }
    }

    /// Buffer the request body (capped) so the policy can inspect it for
    /// exfiltration, and note a WebSocket upgrade. Rebuilds the request so it can
    /// still be forwarded. A body with no `Content-Length` or larger than the cap
    /// is left untouched and reported as `inspected = false` (CONNECT is never
    /// buffered — it has no payload). Async because reading the body is async.
    async fn inspect(&self, req: Request<Body>) -> (Request<Body>, RequestSignals) {
        let is_websocket_upgrade = req
            .headers()
            .get(header::UPGRADE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));

        let content_len = req
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok());
        let bufferable = req.method() != http::Method::CONNECT
            && matches!(content_len, Some(n) if n <= BODY_INSPECT_CAP);

        if !bufferable {
            return (
                req,
                RequestSignals {
                    len: content_len.unwrap_or(0),
                    is_websocket_upgrade,
                    ..RequestSignals::uninspected()
                },
            );
        }

        let (parts, body) = req.into_parts();
        match body.collect().await {
            Ok(collected) => {
                let bytes = collected.to_bytes();
                let contains_known_secret = std::str::from_utf8(&bytes)
                    .map(|s| self.broker.body_leaks_secret(s))
                    .unwrap_or(false); // non-UTF-8 body: skip the textual scan
                let signals = RequestSignals {
                    inspected: true,
                    len: bytes.len(),
                    contains_known_secret,
                    is_websocket_upgrade,
                };
                (Request::from_parts(parts, Body::from(bytes)), signals)
            }
            // Could not read the body: forward without it and let the policy decide
            // with inspected = false (it will, at worst, fall to the restrictive default).
            Err(_) => (
                Request::from_parts(parts, Body::empty()),
                RequestSignals {
                    is_websocket_upgrade,
                    ..RequestSignals::uninspected()
                },
            ),
        }
    }

    /// The whole decision, independent of hudsucker's (non-constructible) context,
    /// so it is unit-testable: normalize → evaluate → audit → forward-or-block.
    fn mediate_request(
        &self,
        mut req: Request<Body>,
        signals: &RequestSignals,
    ) -> RequestOrResponse {
        // A CONNECT asks for a tunnel to a host; the decrypted requests *inside* it
        // are mediated separately when hudsucker re-invokes us. We still police the
        // CONNECT **authority** itself, so an un-allowed host gets no tunnel at all
        // (default-deny egress). Otherwise a non-HTTP protocol spoken inside an
        // allowed-by-omission tunnel would be an unmediated channel to the world.
        let is_connect = req.method() == http::Method::CONNECT;

        let summary = summarize(&req);
        let mut action = to_action(&summary);
        action.context.timestamp_ms = now_ms();
        // Expose what inspection found to the policy (under `action.context.extra`),
        // so rules can deny e.g. an outbound body that carries one of the user's
        // secrets, or a WebSocket upgrade.
        let extra = &mut action.context.extra;
        extra.insert("body_inspected".into(), signals.inspected.into());
        extra.insert(
            "body_len".into(),
            serde_json::Value::from(signals.len as u64),
        );
        extra.insert(
            "body_contains_known_secret".into(),
            signals.contains_known_secret.into(),
        );
        if signals.is_websocket_upgrade {
            extra.insert("upgrade".into(), "websocket".into());
        }
        let outcome = self.policy.evaluate(&action, &self.env);

        // Record every decision before acting on it (invariant 7). This is the
        // network **egress** path — the critical path — so if the decision cannot
        // be durably recorded we **fail closed** rather than forward an unlogged
        // request (invariant 5).
        if !self.record(&action, &outcome) {
            tracing::error!(
                action_id = %action.id.as_str(),
                "audit append failed; failing closed on the proxy path"
            );
            return RequestOrResponse::Response(block_response(
                "Guardian audit log unavailable; request blocked (fail-closed)",
            ));
        }

        match classify(&action, &outcome, &self.broker) {
            ProxyOutcome::Forward { authorization } => {
                // Attach the broker credential to a real request only — never to the
                // CONNECT tunnel-setup (the credential belongs on the inner request).
                if !is_connect {
                    if let Some(auth) = authorization {
                        // The agent never supplied this; the broker did, post-allow.
                        if let Ok(value) = HeaderValue::from_str(&auth) {
                            req.headers_mut().insert(header::AUTHORIZATION, value);
                        }
                    }
                }
                RequestOrResponse::Request(req)
            }
            ProxyOutcome::Block { reason } => RequestOrResponse::Response(block_response(&reason)),
        }
    }

    /// Append the decision to the audit log. Returns `false` if it could not be
    /// durably recorded (poisoned lock or DB error) so the caller can fail closed.
    fn record(&self, action: &Action, outcome: &EvalOutcome) -> bool {
        let entry = AuditEntry::for_decision(
            action,
            &outcome.decision,
            outcome.matched_rule.clone(),
            None,
            None,
        );
        match self.audit.lock() {
            Ok(mut log) => log.append(&entry).is_ok(),
            Err(_) => false,
        }
    }
}

impl HttpHandler for GuardianHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        let (req, signals) = self.inspect(req).await;
        self.mediate_request(req, &signals)
    }
}

/// Start the proxy on `addr`, terminating until `shutdown` resolves. TLS leaf
/// certs are minted by the local CA; the upstream connector verifies real servers
/// against the webpki roots (Guardian does not weaken upstream TLS).
pub async fn run<F>(
    addr: SocketAddr,
    ca: &LocalCa,
    handler: GuardianHandler,
    shutdown: F,
) -> Result<(), ProxyError>
where
    F: Future<Output = ()> + Send + 'static,
{
    let authority = ca.authority()?;
    let proxy = Proxy::builder()
        .with_addr(addr)
        .with_ca(authority)
        .with_rustls_connector(aws_lc_rs::default_provider())
        .with_http_handler(handler)
        .with_graceful_shutdown(shutdown)
        .build()?;
    proxy.start().await?;
    Ok(())
}

/// Extract the policy-relevant parts of a request. The host comes from the URI
/// (absolute-form, plain-HTTP proxying) or the `Host` header (origin-form, after
/// TLS interception); `to_action` normalizes it.
fn summarize(req: &Request<Body>) -> HttpRequest {
    let host = req
        .uri()
        .host()
        .map(str::to_string)
        .or_else(|| {
            req.headers()
                .get(header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        })
        .unwrap_or_default();
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    HttpRequest {
        method: req.method().as_str().to_string(),
        host,
        path,
    }
}

fn block_response(reason: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("x-guardian-blocked", "1")
        .body(Body::from(format!(
            "Guardian blocked this request: {reason}"
        )))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const TOKEN: &str = "s3cret-token-abcdef"; // >= 8 bytes so exfil detection fires

    const POLICY: &str = r#"
version = 1
role = "web-bank"
[defaults]
decision = "ask"
[[rules]]
id = "allow-get"
when = 'action.kind == "HttpRequest" && action.args.method == "GET"'
decision = "allow"
[[rules]]
id = "deny-post-to-bank"
when = 'action.kind == "HttpRequest" && action.args.method == "POST" && action.context.host == "bank.local"'
decision = "deny"
explain = "Money movement on the bank is blocked."
[[rules]]
id = "allow-connect-bank"
when = 'action.args.method == "CONNECT" && action.context.host == "bank.local"'
decision = "allow"
[[rules]]
id = "deny-exfiltration"
when = 'action.context.extra.body_contains_known_secret == true'
decision = "deny"
explain = "Outbound request carries one of your stored credentials."
[[rules]]
id = "deny-websocket"
when = 'action.context.extra.upgrade == "websocket"'
decision = "deny"
explain = "WebSocket upgrades are not allowed by this policy."
"#;

    fn handler() -> GuardianHandler {
        let policy = CompiledPolicy::from_toml_str(POLICY).unwrap();
        let env = EvalEnv {
            user_home: "/h".to_string(),
            trusted_hosts: vec![],
        };
        let broker = Broker::new(HashMap::from([(
            "bank.local".to_string(),
            TOKEN.to_string(),
        )]));
        let audit = AuditLog::open_in_memory().unwrap();
        GuardianHandler::new(
            Arc::new(policy),
            Arc::new(env),
            Arc::new(broker),
            Arc::new(Mutex::new(audit)),
        )
    }

    fn request(method: &str, uri: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    }

    /// Default "nothing inspected" signals for the synchronous decision tests.
    fn sig() -> RequestSignals {
        RequestSignals::uninspected()
    }

    #[test]
    fn allowed_request_is_forwarded_with_brokered_authorization_and_audited() {
        let h = handler();
        let out = h.mediate_request(request("GET", "http://bank.local/balance"), &sig());
        match out {
            RequestOrResponse::Request(req) => {
                let auth = req
                    .headers()
                    .get(header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok());
                assert_eq!(auth, Some(format!("Bearer {TOKEN}").as_str()));
            }
            RequestOrResponse::Response(_) => panic!("expected forward, got block"),
        }
        // The decision was recorded.
        assert_eq!(h.audit.lock().unwrap().len().unwrap(), 1);
    }

    #[test]
    fn blocked_request_becomes_a_403_and_is_audited() {
        let h = handler();
        let out = h.mediate_request(request("POST", "http://bank.local/transfer"), &sig());
        match out {
            RequestOrResponse::Response(resp) => {
                assert_eq!(resp.status(), StatusCode::FORBIDDEN);
                assert!(resp.headers().contains_key("x-guardian-blocked"));
            }
            RequestOrResponse::Request(_) => panic!("expected block, got forward"),
        }
        assert_eq!(h.audit.lock().unwrap().len().unwrap(), 1);
    }

    #[test]
    fn connect_to_allowed_host_passes_through_without_a_credential() {
        // CONNECT to an allowed authority opens the tunnel (the decrypted inner
        // requests are mediated separately), but the broker credential must NOT be
        // attached to the tunnel-setup. The CONNECT is still a recorded decision.
        let h = handler();
        match h.mediate_request(request("CONNECT", "bank.local:443"), &sig()) {
            RequestOrResponse::Request(req) => {
                assert!(!req.headers().contains_key(header::AUTHORIZATION));
            }
            RequestOrResponse::Response(_) => panic!("CONNECT to allowed host must pass"),
        }
        assert_eq!(h.audit.lock().unwrap().len().unwrap(), 1);
    }

    #[test]
    fn connect_to_unlisted_host_is_blocked() {
        // Default-deny egress: a host with no allow rule gets no tunnel at all, so a
        // non-HTTP protocol can't be smuggled through an un-mediated CONNECT.
        let h = handler();
        match h.mediate_request(request("CONNECT", "evil.host:443"), &sig()) {
            RequestOrResponse::Response(resp) => assert_eq!(resp.status(), StatusCode::FORBIDDEN),
            RequestOrResponse::Request(_) => panic!("CONNECT to unlisted host must be blocked"),
        }
    }

    #[test]
    fn allowed_request_to_unbrokered_host_has_no_authorization() {
        let h = handler();
        let out = h.mediate_request(request("GET", "http://example.com/page"), &sig());
        match out {
            RequestOrResponse::Request(req) => {
                assert!(!req.headers().contains_key(header::AUTHORIZATION));
            }
            RequestOrResponse::Response(_) => panic!("expected forward"),
        }
    }

    #[test]
    fn agent_supplied_authorization_is_overwritten_by_broker_on_forward() {
        // Adversarial: the agent puts its own Authorization on a brokered host.
        // The broker's value must win (the agent must not control the credential).
        let h = handler();
        let mut req = request("GET", "http://bank.local/balance");
        req.headers_mut().insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer attacker"),
        );
        match h.mediate_request(req, &sig()) {
            RequestOrResponse::Request(req) => {
                let auth = req
                    .headers()
                    .get(header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok());
                assert_eq!(auth, Some(format!("Bearer {TOKEN}").as_str()));
            }
            RequestOrResponse::Response(_) => panic!("expected forward"),
        }
    }

    #[test]
    fn outbound_body_carrying_a_known_secret_is_blocked_as_exfiltration() {
        // Even an otherwise-allowed request (GET) is blocked when the body is found
        // to carry one of the user's stored credentials — most-restrictive wins.
        let h = handler();
        let signals = RequestSignals {
            inspected: true,
            len: 32,
            contains_known_secret: true,
            is_websocket_upgrade: false,
        };
        match h.mediate_request(request("GET", "http://example.com/collect"), &signals) {
            RequestOrResponse::Response(resp) => assert_eq!(resp.status(), StatusCode::FORBIDDEN),
            RequestOrResponse::Request(_) => panic!("exfiltration must be blocked"),
        }
    }

    #[test]
    fn websocket_upgrade_is_blocked_when_policy_denies_it() {
        let h = handler();
        let signals = RequestSignals {
            is_websocket_upgrade: true,
            ..RequestSignals::uninspected()
        };
        match h.mediate_request(request("GET", "http://example.com/ws"), &signals) {
            RequestOrResponse::Response(resp) => assert_eq!(resp.status(), StatusCode::FORBIDDEN),
            RequestOrResponse::Request(_) => panic!("WebSocket upgrade must be blocked"),
        }
    }

    #[tokio::test]
    async fn inspect_detects_a_known_secret_in_the_request_body() {
        let h = handler();
        let body = format!("note=hello&leak={TOKEN}");
        let req = Request::builder()
            .method("POST")
            .uri("http://example.com/collect")
            .header(header::CONTENT_LENGTH, body.len())
            .body(Body::from(body))
            .unwrap();
        let (_req, signals) = h.inspect(req).await;
        assert!(signals.inspected);
        assert!(signals.contains_known_secret);
    }

    #[tokio::test]
    async fn inspect_skips_bodies_without_a_content_length() {
        let h = handler();
        // No Content-Length → not buffered, reported as not inspected.
        let req = request("POST", "http://example.com/x");
        let (_req, signals) = h.inspect(req).await;
        assert!(!signals.inspected);
        assert!(!signals.contains_known_secret);
    }
}
