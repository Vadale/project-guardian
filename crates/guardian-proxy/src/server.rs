//! The live forward proxy: wires the [mediation core](crate) onto real sockets
//! via `hudsucker`. Every request is normalized, run through the **deterministic
//! policy**, recorded to the **tamper-evident audit log**, and then either
//! forwarded (with the broker's `Authorization` attached for a brokered host) or
//! answered with a `403` carrying the block reason. The agent points
//! `HTTP(S)_PROXY` at this server.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use guardian_audit::{AuditEntry, AuditLog};
use guardian_broker::Broker;
use guardian_core::Action;
use guardian_policy::{CompiledPolicy, EvalEnv, EvalOutcome};

use http::{header, HeaderValue, Request, Response, StatusCode};
use hudsucker::rustls::crypto::aws_lc_rs;
use hudsucker::{Body, HttpContext, HttpHandler, Proxy, RequestOrResponse};

use crate::ca::LocalCa;
use crate::{classify, to_action, HttpRequest, ProxyOutcome};

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

    /// The whole decision, independent of hudsucker's (non-constructible) context,
    /// so it is unit-testable: normalize → evaluate → audit → forward-or-block.
    fn mediate_request(&self, mut req: Request<Body>) -> RequestOrResponse {
        // A CONNECT asks for a tunnel to a host; the decrypted requests *inside* it
        // are mediated separately when hudsucker re-invokes us. We still police the
        // CONNECT **authority** itself, so an un-allowed host gets no tunnel at all
        // (default-deny egress). Otherwise a non-HTTP protocol spoken inside an
        // allowed-by-omission tunnel would be an unmediated channel to the world.
        let is_connect = req.method() == http::Method::CONNECT;

        let summary = summarize(&req);
        let mut action = to_action(&summary);
        action.context.timestamp_ms = now_ms();
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
        self.mediate_request(req)
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
"#;

    fn handler() -> GuardianHandler {
        let policy = CompiledPolicy::from_toml_str(POLICY).unwrap();
        let env = EvalEnv {
            user_home: "/h".to_string(),
            trusted_hosts: vec![],
        };
        let broker = Broker::new(HashMap::from([(
            "bank.local".to_string(),
            "s3cret".to_string(),
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

    #[test]
    fn allowed_request_is_forwarded_with_brokered_authorization_and_audited() {
        let h = handler();
        let out = h.mediate_request(request("GET", "http://bank.local/balance"));
        match out {
            RequestOrResponse::Request(req) => {
                let auth = req
                    .headers()
                    .get(header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok());
                assert_eq!(auth, Some("Bearer s3cret"));
            }
            RequestOrResponse::Response(_) => panic!("expected forward, got block"),
        }
        // The decision was recorded.
        assert_eq!(h.audit.lock().unwrap().len().unwrap(), 1);
    }

    #[test]
    fn blocked_request_becomes_a_403_and_is_audited() {
        let h = handler();
        let out = h.mediate_request(request("POST", "http://bank.local/transfer"));
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
        match h.mediate_request(request("CONNECT", "bank.local:443")) {
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
        match h.mediate_request(request("CONNECT", "evil.host:443")) {
            RequestOrResponse::Response(resp) => assert_eq!(resp.status(), StatusCode::FORBIDDEN),
            RequestOrResponse::Request(_) => panic!("CONNECT to unlisted host must be blocked"),
        }
    }

    #[test]
    fn allowed_request_to_unbrokered_host_has_no_authorization() {
        let h = handler();
        let out = h.mediate_request(request("GET", "http://example.com/page"));
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
        match h.mediate_request(req) {
            RequestOrResponse::Request(req) => {
                let auth = req
                    .headers()
                    .get(header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok());
                assert_eq!(auth, Some("Bearer s3cret"));
            }
            RequestOrResponse::Response(_) => panic!("expected forward"),
        }
    }
}
