//! Outbound smart-host (relay) SMTP session.
//!
//! Completes TCP → (implicit TLS | EHLO + STARTTLS) → EHLO → AUTH so the
//! delivery engine can issue MAIL FROM. RFC 3207: after STARTTLS the server
//! does **not** send a new greeting; the client must EHLO immediately.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::BytesMut;
use sentio_core::error::{SentioError, SmtpError};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tracing::debug;

use crate::connection::{ConnectionConfig, SmtpConnection};
use crate::tls::{build_client_config, starttls_upgrade, TlsPolicy, TlsRequirement};

fn smtp_err(msg: impl Into<String>) -> SentioError {
    SentioError::Smtp(SmtpError {
        code: 0,
        enhanced: None,
        message: msg.into(),
    })
}

fn smtp_err_code(code: u16, msg: impl Into<String>) -> SentioError {
    SentioError::Smtp(SmtpError {
        code,
        enhanced: None,
        message: msg.into(),
    })
}

/// How the relay connection is protected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayTlsMode {
    StartTls,
    Implicit,
    None,
}

impl RelayTlsMode {
    pub(crate) fn from_config(value: Option<&str>) -> Self {
        match value.map(|s| s.to_ascii_lowercase()).as_deref() {
            Some("starttls") => Self::StartTls,
            Some("implicit") => Self::Implicit,
            Some("none") | None => Self::None,
            Some(_) => Self::None,
        }
    }
}

/// Parameters for opening a relay SMTP session.
#[derive(Debug, Clone)]
pub(crate) struct RelaySessionParams {
    pub hostname: String,
    pub ehlo_hostname: String,
    pub tls_mode: RelayTlsMode,
    pub auth_username: Option<String>,
    pub auth_password: Option<String>,
    pub conn_config: ConnectionConfig,
}

/// TCP or TLS I/O for a relay session.
pub(crate) enum RelayIo {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for RelayIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for RelayIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Open a relay session through greeting, TLS, EHLO, and AUTH.
///
/// The returned connection is ready for MAIL FROM.
pub(crate) async fn open_relay_session(
    tcp: TcpStream,
    params: &RelaySessionParams,
) -> Result<SmtpConnection<RelayIo>, SentioError> {
    if params.auth_username.is_some() && params.auth_password.is_none() {
        return Err(smtp_err(
            "relay AUTH username configured but password is missing",
        ));
    }

    let mut conn = match params.tls_mode {
        RelayTlsMode::Implicit => connect_implicit(tcp, params).await?,
        RelayTlsMode::StartTls => connect_starttls(tcp, params).await?,
        RelayTlsMode::None => connect_plain(tcp, params).await?,
    };

    if let (Some(username), Some(password)) = (&params.auth_username, &params.auth_password) {
        let resp = conn.authenticate(username, password).await?;
        if !resp.is_success() {
            return Err(smtp_err_code(
                resp.code,
                format!("AUTH failed: {} {}", resp.code, resp.full_text()),
            ));
        }
    }

    Ok(conn)
}

async fn connect_plain(
    tcp: TcpStream,
    params: &RelaySessionParams,
) -> Result<SmtpConnection<RelayIo>, SentioError> {
    let (mut conn, _greeting) = SmtpConnection::new(
        RelayIo::Plain(tcp),
        params.conn_config.clone(),
        params.hostname.clone(),
    )
    .await?;
    ehlo(&mut conn, &params.ehlo_hostname).await?;
    Ok(conn)
}

async fn connect_implicit(
    tcp: TcpStream,
    params: &RelaySessionParams,
) -> Result<SmtpConnection<RelayIo>, SentioError> {
    let tls_stream = wrap_tls(tcp, &params.hostname, params.conn_config.connect_timeout).await?;
    let (mut conn, _greeting) = SmtpConnection::new(
        RelayIo::Tls(Box::new(tls_stream)),
        params.conn_config.clone(),
        params.hostname.clone(),
    )
    .await?;
    ehlo(&mut conn, &params.ehlo_hostname).await?;
    Ok(conn)
}

async fn connect_starttls(
    tcp: TcpStream,
    params: &RelaySessionParams,
) -> Result<SmtpConnection<RelayIo>, SentioError> {
    let (mut conn, _greeting) = SmtpConnection::new(
        RelayIo::Plain(tcp),
        params.conn_config.clone(),
        params.hostname.clone(),
    )
    .await?;
    ehlo(&mut conn, &params.ehlo_hostname).await?;

    let caps = conn.capabilities.clone().unwrap_or_default();
    if !caps.starttls {
        return Err(smtp_err(
            "STARTTLS required but server did not advertise it",
        ));
    }

    let starttls_resp = conn.starttls().await?;
    if !starttls_resp.is_success() {
        return Err(smtp_err_code(
            starttls_resp.code,
            format!(
                "STARTTLS rejected: {} {}",
                starttls_resp.code,
                starttls_resp.full_text()
            ),
        ));
    }

    let (stream, _buf, conn_config, hostname) = conn.into_parts();
    let tcp = match stream {
        RelayIo::Plain(tcp) => tcp,
        RelayIo::Tls(_) => {
            return Err(smtp_err(
                "STARTTLS issued on an already-encrypted connection",
            ));
        }
    };

    let tls_stream = wrap_tls(tcp, &hostname, conn_config.connect_timeout).await?;
    // RFC 3207: the server does not send a new greeting after TLS. Using
    // SmtpConnection::new here would block until greeting_timeout (30s)
    // waiting for a 220 that never arrives.
    let mut conn = SmtpConnection::from_upgraded(
        RelayIo::Tls(Box::new(tls_stream)),
        BytesMut::new(),
        conn_config,
        hostname,
    );
    ehlo(&mut conn, &params.ehlo_hostname).await?;
    Ok(conn)
}

async fn ehlo(conn: &mut SmtpConnection<RelayIo>, hostname: &str) -> Result<(), SentioError> {
    let resp = conn.ehlo(hostname).await?;
    if !resp.is_success() {
        return Err(smtp_err_code(
            resp.code,
            format!("EHLO rejected: {} {}", resp.code, resp.full_text()),
        ));
    }
    Ok(())
}

async fn wrap_tls(
    tcp: TcpStream,
    server_name: &str,
    timeout: Duration,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, SentioError> {
    let tls_req = TlsRequirement {
        policy: TlsPolicy::Opportunistic,
        dane_records: vec![],
        mta_sts_mx_patterns: vec![],
    };
    let tls_config = Arc::new(build_client_config(&tls_req)?);
    let (stream, version) =
        tokio::time::timeout(timeout, starttls_upgrade(tcp, tls_config, server_name))
            .await
            .map_err(|_| smtp_err("TLS handshake timeout"))??;
    debug!(
        server = %server_name,
        tls_version = %version,
        "relay TLS handshake complete"
    );
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc as StdArc;
    use std::time::Duration;

    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::ServerConfig;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    const RELAY_USER: &str = "relay-user";
    const RELAY_PASS: &str = "relay-pass";

    struct MockLog {
        auth_seen: AtomicBool,
        mail_seen: AtomicBool,
        starttls_seen: AtomicBool,
    }

    impl MockLog {
        fn new() -> StdArc<Self> {
            StdArc::new(Self {
                auth_seen: AtomicBool::new(false),
                mail_seen: AtomicBool::new(false),
                starttls_seen: AtomicBool::new(false),
            })
        }
    }

    fn test_tls_identity() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let certified = rcgen::generate_simple_self_signed(vec!["mail.smtp2go.test".into()])
            .expect("self-signed cert");
        let cert_der = CertificateDer::from(certified.cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certified.signing_key.serialize_der(),
        ));
        (vec![cert_der], key_der)
    }

    fn tls13_acceptor() -> TlsAcceptor {
        let (certs, key) = test_tls_identity();
        let provider = StdArc::new(rustls::crypto::aws_lc_rs::default_provider());
        let server_config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3 supported")
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("valid test cert");
        TlsAcceptor::from(StdArc::new(server_config))
    }

    fn smtp2go_ehlo(with_starttls: bool) -> Vec<u8> {
        let mut lines = String::from(
            "250-mail.smtp2go.test Hello\r\n\
             250-SIZE 52428800\r\n\
             250-8BITMIME\r\n\
             250-PIPELINING\r\n\
             250-AUTH CRAM-MD5 PLAIN LOGIN\r\n",
        );
        if with_starttls {
            lines.push_str("250-STARTTLS\r\n");
        }
        lines.push_str("250 HELP\r\n");
        lines.into_bytes()
    }

    async fn write_all(stream: &mut (impl AsyncWrite + Unpin), data: &[u8]) {
        stream.write_all(data).await.unwrap();
        stream.flush().await.unwrap();
    }

    async fn read_line(stream: &mut (impl AsyncRead + Unpin), buf: &mut Vec<u8>) -> Option<String> {
        let mut tmp = [0u8; 1024];
        loop {
            if let Some(pos) = buf.windows(2).position(|w| w == b"\r\n") {
                let line = String::from_utf8_lossy(&buf[..pos]).into_owned();
                buf.drain(..pos + 2);
                return Some(line);
            }
            let n = match tokio::time::timeout(Duration::from_secs(3), stream.read(&mut tmp)).await
            {
                Ok(Ok(0)) | Err(_) => return None,
                Ok(Ok(n)) => n,
                Ok(Err(_)) => return None,
            };
            buf.extend_from_slice(&tmp[..n]);
        }
    }

    async fn drive_authenticated_smtp<S>(
        mut stream: S,
        log: StdArc<MockLog>,
        advertise_starttls: bool,
    ) where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut buf = Vec::new();
        let mut authenticated = false;
        loop {
            let Some(line) = read_line(&mut stream, &mut buf).await else {
                return;
            };
            let upper = line.to_ascii_uppercase();
            if upper.starts_with("EHLO") || upper.starts_with("HELO") {
                write_all(
                    &mut stream,
                    &smtp2go_ehlo(advertise_starttls && !authenticated),
                )
                .await;
            } else if upper.starts_with("AUTH PLAIN") {
                authenticated = true;
                log.auth_seen.store(true, Ordering::SeqCst);
                write_all(&mut stream, b"235 2.7.0 Authentication succeeded\r\n").await;
            } else if upper.starts_with("MAIL FROM") {
                if !authenticated {
                    write_all(&mut stream, b"530 5.7.0 Authentication required\r\n").await;
                    return;
                }
                log.mail_seen.store(true, Ordering::SeqCst);
                write_all(&mut stream, b"250 2.1.0 OK\r\n").await;
            } else if upper.starts_with("QUIT") {
                write_all(&mut stream, b"221 2.0.0 Bye\r\n").await;
                return;
            } else {
                write_all(&mut stream, b"500 Command not recognized\r\n").await;
            }
        }
    }

    async fn run_starttls_smarthost(
        listener: TcpListener,
        log: StdArc<MockLog>,
        acceptor: TlsAcceptor,
    ) {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = stream;
        write_all(&mut stream, b"220 mail.smtp2go.test ESMTP Exim 4.99.4\r\n").await;

        let mut buf = Vec::new();
        loop {
            let Some(line) = read_line(&mut stream, &mut buf).await else {
                return;
            };
            let upper = line.to_ascii_uppercase();
            if upper.starts_with("EHLO") || upper.starts_with("HELO") {
                write_all(&mut stream, &smtp2go_ehlo(true)).await;
            } else if upper.starts_with("STARTTLS") {
                log.starttls_seen.store(true, Ordering::SeqCst);
                write_all(&mut stream, b"220 TLS go ahead\r\n").await;
                let tls = acceptor
                    .accept(stream)
                    .await
                    .expect("TLS 1.3 STARTTLS handshake");
                // Intentionally no greeting after TLS (RFC 3207). A client that
                // calls SmtpConnection::new here waits until greeting_timeout.
                drive_authenticated_smtp(tls, log, false).await;
                return;
            } else {
                write_all(&mut stream, b"500 Command not recognized\r\n").await;
            }
        }
    }

    async fn run_implicit_smarthost(
        listener: TcpListener,
        log: StdArc<MockLog>,
        acceptor: TlsAcceptor,
    ) {
        let (stream, _) = listener.accept().await.unwrap();
        let mut tls = acceptor
            .accept(stream)
            .await
            .expect("TLS 1.3 implicit handshake");
        write_all(&mut tls, b"220 mail.smtp2go.test ESMTP Exim 4.99.4\r\n").await;
        drive_authenticated_smtp(tls, log, false).await;
    }

    fn session_params(tls_mode: RelayTlsMode) -> RelaySessionParams {
        RelaySessionParams {
            hostname: "mail.smtp2go.test".into(),
            ehlo_hostname: "sentio.example.com".into(),
            tls_mode,
            auth_username: Some(RELAY_USER.into()),
            auth_password: Some(RELAY_PASS.into()),
            conn_config: ConnectionConfig::default(),
        }
    }

    #[test]
    fn tls_mode_from_config() {
        assert_eq!(
            RelayTlsMode::from_config(Some("starttls")),
            RelayTlsMode::StartTls
        );
        assert_eq!(
            RelayTlsMode::from_config(Some("IMPLICIT")),
            RelayTlsMode::Implicit
        );
        assert_eq!(RelayTlsMode::from_config(Some("none")), RelayTlsMode::None);
        assert_eq!(RelayTlsMode::from_config(None), RelayTlsMode::None);
    }

    #[tokio::test]
    async fn starttls_tls13_reaches_auth_without_post_handshake_greeting() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let log = MockLog::new();
        let acceptor = tls13_acceptor();
        let server_log = StdArc::clone(&log);
        tokio::spawn(async move {
            run_starttls_smarthost(listener, server_log, acceptor).await;
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let params = session_params(RelayTlsMode::StartTls);
        let result =
            tokio::time::timeout(Duration::from_secs(5), open_relay_session(tcp, &params)).await;
        let mut conn = match result {
            Ok(Ok(conn)) => conn,
            Ok(Err(e)) => panic!("relay STARTTLS session failed before AUTH: {e}"),
            Err(_) => panic!(
                "relay STARTTLS timed out before AUTH (likely waiting for a post-TLS greeting that SMTP never sends)"
            ),
        };

        assert!(
            log.starttls_seen.load(Ordering::SeqCst),
            "STARTTLS command was not issued"
        );
        assert!(log.auth_seen.load(Ordering::SeqCst), "AUTH was not reached");

        let mail = conn.mail_from("sender@example.com", None).await.unwrap();
        assert!(mail.is_success(), "MAIL FROM after AUTH: {:?}", mail.lines);
        assert!(log.mail_seen.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn implicit_tls13_reaches_auth_without_plaintext_greeting_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let log = MockLog::new();
        let acceptor = tls13_acceptor();
        let server_log = StdArc::clone(&log);
        tokio::spawn(async move {
            run_implicit_smarthost(listener, server_log, acceptor).await;
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let params = session_params(RelayTlsMode::Implicit);
        let result =
            tokio::time::timeout(Duration::from_secs(5), open_relay_session(tcp, &params)).await;
        let mut conn = match result {
            Ok(Ok(conn)) => conn,
            Ok(Err(e)) => panic!("relay implicit TLS session failed before AUTH: {e}"),
            Err(_) => panic!(
                "relay implicit TLS timed out before AUTH (likely reading a plaintext greeting from a TLS socket)"
            ),
        };

        assert!(log.auth_seen.load(Ordering::SeqCst), "AUTH was not reached");

        let mail = conn.mail_from("sender@example.com", None).await.unwrap();
        assert!(mail.is_success(), "MAIL FROM after AUTH: {:?}", mail.lines);
        assert!(log.mail_seen.load(Ordering::SeqCst));
    }
}
