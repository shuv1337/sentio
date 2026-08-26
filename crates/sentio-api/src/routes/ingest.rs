//! HTTP ingest into the inbound SMTP pipeline.
//!
//! `POST /v1/messages/ingest` is the HTTP equivalent of SMTP DATA completion:
//! the body is handed to the same `MessageProcessor` (`InboundPipeline::process`)
//! that SPF/DKIM/spam, mailbox delivery, and inbound routes already use.
//!
//! Authenticate with `Authorization: Bearer <token>`:
//! - a tenant API key with scope `messages:ingest`, `messages:send`, or `*`
//! - or the value of env `SENTIO_INGEST_TOKEN` (ingest-only; recipient
//!   domains are resolved globally, same as SMTP inbound)
//!
//! The API key's tenant must host every `envelope_to` domain
//! (`use_for_receiving`). `authenticated_user` is left unset so the pipeline
//! takes the inbound path rather than authenticated outbound submission.
//!
//! # JSON (`Content-Type: application/json`)
//!
//! ```json
//! {
//!   "envelope_from": "alice@example.com",
//!   "envelope_to": ["bob@example.com"],
//!   "raw": "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: hi\r\n\r\nHello\r\n",
//!   "client_ip": "203.0.113.10",
//!   "helo_domain": "mail.example.com"
//! }
//! ```
//!
//! `raw` is the RFC 822 message as a JSON string. Use `raw_base64` instead
//! when the message is not valid UTF-8. `client_ip` is the original SMTP peer
//! (used for SPF); if omitted, the HTTP client address is used.
//!
//! # Raw RFC 822 (`Content-Type: message/rfc822`)
//!
//! Body is the message bytes. Envelope fields are headers:
//! `X-Envelope-From`, `X-Envelope-To` (comma-separated), optional
//! `X-Client-Ip`, `X-Helo-Domain`.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use axum::body::Bytes;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap};
use axum::response::IntoResponse;
use base64::Engine;
use serde::{Deserialize, Serialize};

use sentio_core::error::SentioError;
use sentio_core::message::MessageId;
use sentio_core::traits::DomainRepository;
use sentio_smtp_server::{InboundMessage, MessageProcessor, ProcessingError};
use sentio_store::postgres::PgDomainRepository;

use crate::auth::AuthContext;
use crate::errors::{ApiError, ErrorResponse};
use crate::response::{data, DataResponse};
use crate::routes::messages::{extract_addr_spec, parse_from_domain, validate_email_field};
use crate::state::AppState;

#[derive(Deserialize, utoipa::ToSchema)]
pub struct IngestRequest {
    /// SMTP MAIL FROM. Empty string is the null sender `<>`.
    pub envelope_from: String,
    /// SMTP RCPT TO recipients. Every domain must be hosted by this tenant.
    pub envelope_to: Vec<String>,
    /// RFC 822 message as a JSON string.
    #[serde(default)]
    pub raw: Option<String>,
    /// Base64-encoded RFC 822 when `raw` is not valid UTF-8.
    #[serde(default)]
    pub raw_base64: Option<String>,
    /// Original SMTP peer IP for SPF. Defaults to the HTTP client address.
    #[serde(default)]
    pub client_ip: Option<String>,
    /// EHLO/HELO name from the original SMTP session, if known.
    #[serde(default)]
    pub helo_domain: Option<String>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct IngestResponse {
    id: MessageId,
    queue_id: String,
    status: String,
}

#[utoipa::path(
    post,
    path = "/v1/messages/ingest",
    tag = "Messages",
    security(("bearer" = [])),
    request_body(
        content = IngestRequest,
        description = "JSON envelope + RFC 822 body, or Content-Type: message/rfc822 with X-Envelope-* headers",
        content_type = "application/json",
    ),
    responses(
        (status = 200, body = DataResponse<IngestResponse>),
        (status = 401, body = ErrorResponse),
        (status = 422, body = ErrorResponse),
        (status = 503, body = ErrorResponse),
    ),
)]
pub async fn ingest_message(
    State(state): State<AppState>,
    auth: AuthContext,
    connect: ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, ApiError> {
    require_ingest_scope(&auth)?;

    let http_peer = Some(connect.0.ip());
    let parsed = parse_ingest_body(&headers, &body, http_peer)?;
    if parsed.raw.is_empty() {
        return Err(ApiError::Validation("raw message is empty".into()));
    }
    let max_recipients = state
        .config
        .server
        .inbound_limits
        .max_recipients_per_message as usize;
    reject_open_relay_shape(&parsed.envelope_from, &parsed.envelope_to, max_recipients)?;
    validate_hosted_recipients(&state, &auth, &parsed.envelope_to).await?;

    let max_bytes = (state.config.server.inbound_limits.max_message_size_mb as usize) * 1024 * 1024;
    if parsed.raw.len() > max_bytes {
        return Err(ApiError::Validation(format!(
            "message exceeds max size of {} MB",
            state.config.server.inbound_limits.max_message_size_mb
        )));
    }

    let processor = state.inbound_processor.as_ref().ok_or_else(|| {
        ApiError::Unavailable("inbound ingest is not configured on this process".into())
    })?;

    let msg = InboundMessage {
        raw_data: parsed.raw,
        envelope_from: parsed.envelope_from,
        envelope_to: parsed.envelope_to,
        peer_addr: parsed.peer_addr,
        client_domain: parsed.helo_domain,
        server_hostname: state.config.server.hostname.clone(),
        // Unset on purpose: a Some value would divert to outbound submission
        // and skip SPF/DKIM/spam. HTTP auth is the API bearer, not SMTP AUTH.
        authenticated_user: None,
        tls_active: false,
        max_received_headers: state.config.server.inbound_limits.max_received_headers,
        dsn_ret: None,
        dsn_envid: None,
        dsn_notify: HashMap::new(),
        dsn_orcpt: HashMap::new(),
    };

    let outcome = deliver_ingest(processor, msg).await?;
    Ok(data(IngestResponse {
        id: outcome.message_id,
        queue_id: outcome.queue_id,
        status: "accepted".into(),
    }))
}

fn require_ingest_scope(auth: &AuthContext) -> Result<(), ApiError> {
    if auth.require_scope("messages:ingest").is_ok() || auth.require_scope("messages:send").is_ok()
    {
        Ok(())
    } else {
        Err(ApiError::Auth(
            "missing required scope: messages:ingest".into(),
        ))
    }
}

#[derive(Debug)]
struct ParsedIngest {
    envelope_from: String,
    envelope_to: Vec<String>,
    raw: Vec<u8>,
    peer_addr: IpAddr,
    helo_domain: Option<String>,
}

fn parse_ingest_body(
    headers: &HeaderMap,
    body: &Bytes,
    http_peer: Option<IpAddr>,
) -> Result<ParsedIngest, ApiError> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json");
    let media = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
        .to_ascii_lowercase();

    match media.as_str() {
        "application/json" | "text/json" => parse_json_ingest(body, http_peer),
        "message/rfc822" => parse_rfc822_ingest(headers, body, http_peer),
        other => Err(ApiError::Validation(format!(
            "unsupported Content-Type '{other}': use application/json or message/rfc822"
        ))),
    }
}

fn parse_json_ingest(body: &Bytes, http_peer: Option<IpAddr>) -> Result<ParsedIngest, ApiError> {
    let req: IngestRequest = serde_json::from_slice(body)
        .map_err(|e| ApiError::Validation(format!("invalid JSON: {e}")))?;
    if req.raw.is_some() && req.raw_base64.is_some() {
        return Err(ApiError::Validation(
            "provide either raw or raw_base64, not both".into(),
        ));
    }
    let raw = match (req.raw, req.raw_base64) {
        (Some(text), None) => text.into_bytes(),
        (None, Some(b64)) => base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .map_err(|e| ApiError::Validation(format!("invalid raw_base64: {e}")))?,
        (None, None) => {
            return Err(ApiError::Validation("raw or raw_base64 is required".into()));
        }
        (Some(_), Some(_)) => unreachable!("checked above"),
    };
    Ok(ParsedIngest {
        envelope_from: extract_addr_spec(&req.envelope_from),
        envelope_to: req
            .envelope_to
            .iter()
            .map(|s| extract_addr_spec(s))
            .collect(),
        raw,
        peer_addr: parse_peer_addr(req.client_ip.as_deref(), http_peer)?,
        helo_domain: req.helo_domain.filter(|s| !s.is_empty()),
    })
}

fn parse_rfc822_ingest(
    headers: &HeaderMap,
    body: &Bytes,
    http_peer: Option<IpAddr>,
) -> Result<ParsedIngest, ApiError> {
    let envelope_from = header_str(headers, "x-envelope-from")
        .as_deref()
        .map(extract_addr_spec)
        .unwrap_or_default();
    let envelope_to = header_str(headers, "x-envelope-to")
        .map(|value| {
            value
                .split(',')
                .map(extract_addr_spec)
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let client_ip = header_str(headers, "x-client-ip");
    let helo_domain = header_str(headers, "x-helo-domain");
    Ok(ParsedIngest {
        envelope_from,
        envelope_to,
        raw: body.to_vec(),
        peer_addr: parse_peer_addr(client_ip.as_deref(), http_peer)?,
        helo_domain,
    })
}

fn header_str(headers: &HeaderMap, name: &'static str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn parse_peer_addr(client_ip: Option<&str>, http_peer: Option<IpAddr>) -> Result<IpAddr, ApiError> {
    if let Some(raw) = client_ip {
        return raw.parse::<IpAddr>().map_err(|_| {
            ApiError::Validation(format!("client_ip '{raw}' is not a valid IP address"))
        });
    }
    Ok(http_peer.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)))
}

/// Reject requests that look like an open relay before hitting the pipeline.
fn reject_open_relay_shape(
    envelope_from: &str,
    envelope_to: &[String],
    max_recipients: usize,
) -> Result<(), ApiError> {
    if envelope_to.is_empty() {
        return Err(ApiError::Validation(
            "envelope_to is required and must contain at least one recipient".into(),
        ));
    }
    if envelope_to.len() > max_recipients {
        return Err(ApiError::Validation(format!(
            "envelope_to exceeds {max_recipients} recipients"
        )));
    }
    if !envelope_from.is_empty() {
        validate_email_field("envelope_from", envelope_from)?;
    }
    for (i, rcpt) in envelope_to.iter().enumerate() {
        validate_email_field(&format!("envelope_to[{i}]"), rcpt)?;
    }
    Ok(())
}

async fn validate_hosted_recipients(
    state: &AppState,
    auth: &AuthContext,
    envelope_to: &[String],
) -> Result<(), ApiError> {
    let repo = PgDomainRepository::new(state.pool.clone());
    for rcpt in envelope_to {
        let domain = parse_from_domain(rcpt).ok_or_else(|| {
            ApiError::Validation(format!("invalid recipient '{rcpt}': missing domain"))
        })?;
        if auth.shared_ingest {
            // Same lookup SMTP inbound uses: hosted + use_for_receiving.
            let hosted = repo.find_by_domain_name(&domain).await?;
            if hosted.is_none() {
                return Err(ApiError::Validation(format!(
                    "recipient domain '{domain}' is not hosted for receiving"
                )));
            }
            continue;
        }
        let record = match repo.get_by_name(auth.tenant_id, &domain).await {
            Ok(record) => record,
            Err(SentioError::NotFound { .. }) => {
                return Err(ApiError::Validation(format!(
                    "recipient domain '{domain}' is not hosted by this tenant"
                )));
            }
            Err(e) => return Err(e.into()),
        };
        if !record.use_for_receiving {
            return Err(ApiError::Validation(format!(
                "domain '{domain}' is not enabled for receiving"
            )));
        }
    }
    Ok(())
}

pub(crate) async fn deliver_ingest(
    processor: &MessageProcessor,
    msg: InboundMessage,
) -> Result<sentio_smtp_server::ProcessingOutcome, ApiError> {
    processor(msg).await.map_err(processing_to_api)
}

fn processing_to_api(err: ProcessingError) -> ApiError {
    match err {
        ProcessingError::Reject { message, .. } => ApiError::Validation(message),
        ProcessingError::TempFail { message, .. } => ApiError::Unavailable(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use sentio_core::tenant::TenantId;
    use sentio_smtp_server::ProcessingOutcome;
    use std::sync::{Arc, Mutex};

    fn sample_eml() -> &'static str {
        "From: alice@example.com\r\nTo: bob@shuv.bot\r\nSubject: hi\r\n\r\nHello\r\n"
    }

    fn json_body(value: serde_json::Value) -> Bytes {
        Bytes::from(serde_json::to_vec(&value).unwrap())
    }

    #[test]
    fn json_ingest_parses_raw_and_envelope() {
        let headers = HeaderMap::from_iter([(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )]);
        let body = json_body(serde_json::json!({
            "envelope_from": "Alice <alice@example.com>",
            "envelope_to": ["bob@shuv.bot"],
            "raw": sample_eml(),
            "client_ip": "203.0.113.10",
            "helo_domain": "mail.example.com",
        }));
        let parsed = parse_ingest_body(&headers, &body, None).unwrap();
        assert_eq!(parsed.envelope_from, "alice@example.com");
        assert_eq!(parsed.envelope_to, vec!["bob@shuv.bot"]);
        assert_eq!(parsed.raw, sample_eml().as_bytes());
        assert_eq!(parsed.peer_addr, "203.0.113.10".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.helo_domain.as_deref(), Some("mail.example.com"));
    }

    #[test]
    fn json_ingest_accepts_raw_base64() {
        let headers = HeaderMap::from_iter([(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )]);
        let b64 = base64::engine::general_purpose::STANDARD.encode(sample_eml().as_bytes());
        let body = json_body(serde_json::json!({
            "envelope_from": "alice@example.com",
            "envelope_to": ["bob@shuv.bot"],
            "raw_base64": b64,
        }));
        let parsed =
            parse_ingest_body(&headers, &body, Some("192.0.2.1".parse().unwrap())).unwrap();
        assert_eq!(parsed.raw, sample_eml().as_bytes());
        assert_eq!(parsed.peer_addr, "192.0.2.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn rfc822_ingest_reads_envelope_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("message/rfc822"),
        );
        headers.insert(
            "x-envelope-from",
            HeaderValue::from_static("alice@example.com"),
        );
        headers.insert(
            "x-envelope-to",
            HeaderValue::from_static("bob@shuv.bot, carol@shuv.bot"),
        );
        headers.insert("x-client-ip", HeaderValue::from_static("198.51.100.9"));
        let body = Bytes::from(sample_eml().as_bytes().to_vec());
        let parsed = parse_ingest_body(&headers, &body, None).unwrap();
        assert_eq!(parsed.envelope_from, "alice@example.com");
        assert_eq!(
            parsed.envelope_to,
            vec!["bob@shuv.bot".to_string(), "carol@shuv.bot".to_string()]
        );
        assert_eq!(parsed.peer_addr, "198.51.100.9".parse::<IpAddr>().unwrap());
        assert_eq!(parsed.raw, sample_eml().as_bytes());
    }

    #[test]
    fn reject_empty_envelope_to() {
        let err = reject_open_relay_shape("alice@example.com", &[], 100).unwrap_err();
        match err {
            ApiError::Validation(msg) => assert!(msg.contains("envelope_to")),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn reject_recipient_without_domain() {
        let err =
            reject_open_relay_shape("alice@example.com", &["nobody".into()], 100).unwrap_err();
        match err {
            ApiError::Validation(msg) => assert!(msg.contains("envelope_to[0]")),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn reject_too_many_recipients() {
        let many: Vec<String> = (0..3).map(|i| format!("u{i}@shuv.bot")).collect();
        let err = reject_open_relay_shape("alice@example.com", &many, 2).unwrap_err();
        match err {
            ApiError::Validation(msg) => assert!(msg.contains("exceeds")),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn json_ingest_requires_raw() {
        let headers = HeaderMap::from_iter([(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )]);
        let body = json_body(serde_json::json!({
            "envelope_from": "alice@example.com",
            "envelope_to": ["bob@shuv.bot"],
        }));
        let err = parse_ingest_body(&headers, &body, None).unwrap_err();
        match err {
            ApiError::Validation(msg) => assert!(msg.contains("raw")),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn ingest_scope_accepts_send_or_ingest_or_star() {
        let send = AuthContext {
            tenant_id: TenantId(uuid::Uuid::nil()),
            scopes: vec!["messages:send".into()],
            shared_ingest: false,
        };
        let ingest = AuthContext {
            tenant_id: TenantId(uuid::Uuid::nil()),
            scopes: vec!["messages:ingest".into()],
            shared_ingest: false,
        };
        let star = AuthContext {
            tenant_id: TenantId(uuid::Uuid::nil()),
            scopes: vec!["*".into()],
            shared_ingest: false,
        };
        let none = AuthContext {
            tenant_id: TenantId(uuid::Uuid::nil()),
            scopes: vec!["messages:read".into()],
            shared_ingest: false,
        };
        assert!(require_ingest_scope(&send).is_ok());
        assert!(require_ingest_scope(&ingest).is_ok());
        assert!(require_ingest_scope(&star).is_ok());
        assert!(require_ingest_scope(&none).is_err());
    }

    #[tokio::test]
    async fn deliver_ingest_leaves_authenticated_user_unset() {
        let seen: Arc<Mutex<Option<InboundMessage>>> = Arc::new(Mutex::new(None));
        let processor: MessageProcessor = {
            let seen = Arc::clone(&seen);
            Arc::new(move |msg: InboundMessage| {
                let seen = Arc::clone(&seen);
                Box::pin(async move {
                    *seen.lock().unwrap() = Some(msg);
                    Ok(ProcessingOutcome {
                        queue_id: "TESTQUEUE".into(),
                        message_id: MessageId::new(),
                    })
                })
            })
        };

        let msg = InboundMessage {
            raw_data: sample_eml().as_bytes().to_vec(),
            envelope_from: "alice@example.com".into(),
            envelope_to: vec!["bob@shuv.bot".into()],
            peer_addr: "203.0.113.10".parse().unwrap(),
            client_domain: Some("mail.example.com".into()),
            server_hostname: "mx.example.com".into(),
            authenticated_user: None,
            tls_active: false,
            max_received_headers: 50,
            dsn_ret: None,
            dsn_envid: None,
            dsn_notify: HashMap::new(),
            dsn_orcpt: HashMap::new(),
        };
        let outcome = deliver_ingest(&processor, msg).await.unwrap();
        assert_eq!(outcome.queue_id, "TESTQUEUE");
        let captured = seen.lock().unwrap();
        let captured = captured.as_ref().expect("processor was not called");
        assert!(
            captured.authenticated_user.is_none(),
            "setting authenticated_user would skip SPF/DKIM/spam"
        );
        assert_eq!(captured.envelope_to, vec!["bob@shuv.bot"]);
    }

    #[test]
    fn processing_reject_is_validation() {
        let err = processing_to_api(ProcessingError::no_valid_recipient("evil.example"));
        match err {
            ApiError::Validation(msg) => assert!(msg.contains("evil.example")),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn processing_tempfail_is_unavailable() {
        let err = processing_to_api(ProcessingError::storage_unavailable());
        match err {
            ApiError::Unavailable(_) => {}
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }
}
