//! Network step: one TLS connection, WebPKI-validated, over which the
//! attestation document is fetched. Using a single hyper HTTP/1.1 connection
//! on top of the TLS stream guarantees that the document comes over the same
//! session whose certificate we captured.

use std::sync::Arc;
use std::time::Duration;

use attested_vw_common::ATTESTATION_PATH;
use attested_vw_common::report_data::Nonce;
use attested_vw_common::schema::MAX_DOCUMENT_BYTES;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Limited};
use hyper::Request;
use hyper::header::{ACCEPT, HOST};
use hyper_util::rt::TokioIo;
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, ServerName};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("invalid target URL: {0}")]
    Url(String),
    #[error("TCP connect to {0} failed: {1}")]
    Connect(String, String),
    #[error("TLS handshake failed: {0}")]
    Tls(String),
    #[error("server presented no certificate")]
    NoCert,
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("attestation endpoint returned HTTP {0}: {1}")]
    Status(u16, String),
    #[error("timed out: {0}")]
    Timeout(&'static str),
}

/// Parsed `https://host[:port][/]` target.
#[derive(Debug, Clone)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

impl Target {
    pub fn parse(url: &str) -> Result<Self, NetError> {
        let uri: hyper::Uri = url.parse().map_err(|e| NetError::Url(format!("{e}")))?;
        if uri.scheme_str() != Some("https") {
            return Err(NetError::Url("scheme must be https".into()));
        }
        let auth = uri
            .authority()
            .ok_or_else(|| NetError::Url("missing host".into()))?;
        if auth.as_str().contains('@') {
            return Err(NetError::Url("userinfo not allowed".into()));
        }
        if !matches!(uri.path(), "" | "/") || uri.query().is_some() {
            return Err(NetError::Url(
                "give only the origin, e.g. https://vault.example.com".into(),
            ));
        }
        Ok(Self {
            host: auth.host().to_owned(),
            port: auth.port_u16().unwrap_or(443),
        })
    }
}

/// Where the verifier's trust anchors come from.
#[derive(Debug, Clone)]
pub enum Roots {
    /// Mozilla's WebPKI roots (`webpki-roots`).
    WebPki,
    /// Only these certificates (local development CA).
    Custom(Vec<Vec<u8>>),
}

impl Roots {
    fn store(&self) -> Result<RootCertStore, NetError> {
        let mut store = RootCertStore::empty();
        match self {
            Roots::WebPki => store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
            Roots::Custom(ders) => {
                for der in ders {
                    store
                        .add(CertificateDer::from(der.clone()))
                        .map_err(|e| NetError::Tls(format!("bad custom root: {e}")))?;
                }
            }
        }
        Ok(store)
    }
}

/// What the network step produced.
#[derive(Debug)]
pub struct Fetched {
    /// DER of the TLS leaf certificate from *our* handshake.
    pub leaf_der: Vec<u8>,
    /// Negotiated TLS version, for the report.
    pub tls_version: String,
    /// Raw attestation document bytes.
    pub body: Vec<u8>,
}

/// Connect, validate TLS, fetch the attestation for `nonce` on the same
/// connection.
pub async fn fetch(target: &Target, roots: &Roots, nonce: &Nonce) -> Result<Fetched, NetError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| NetError::Tls(e.to_string()))?
        .with_root_certificates(roots.store()?)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(target.host.clone())
        .map_err(|e| NetError::Url(format!("host: {e}")))?;

    let addr = format!("{}:{}", target.host, target.port);
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(&addr))
        .await
        .map_err(|_| NetError::Timeout("TCP connect"))?
        .map_err(|e| NetError::Connect(addr.clone(), e.to_string()))?;
    let tls = tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(server_name, tcp))
        .await
        .map_err(|_| NetError::Timeout("TLS handshake"))?
        .map_err(|e| NetError::Tls(e.to_string()))?;

    let (_, conn) = tls.get_ref();
    let leaf_der = conn
        .peer_certificates()
        .and_then(|c| c.first())
        .map(|c| c.as_ref().to_vec())
        .ok_or(NetError::NoCert)?;
    let tls_version = conn
        .protocol_version()
        .map(|v| format!("{v:?}"))
        .unwrap_or_else(|| "unknown".into());

    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .map_err(|e| NetError::Http(e.to_string()))?;
    let driver = tokio::spawn(connection);

    let host_header = if target.port == 443 {
        target.host.clone()
    } else {
        format!("{}:{}", target.host, target.port)
    };
    let req = Request::get(format!("{ATTESTATION_PATH}?nonce={}", nonce.to_hex()))
        .header(HOST, host_header)
        .header(ACCEPT, "application/json")
        .body(Empty::<Bytes>::new())
        .map_err(|e| NetError::Http(e.to_string()))?;

    let result = tokio::time::timeout(REQUEST_TIMEOUT, async {
        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| NetError::Http(e.to_string()))?;
        let status = resp.status();
        let body = Limited::new(resp.into_body(), MAX_DOCUMENT_BYTES)
            .collect()
            .await
            .map_err(|e| NetError::Http(format!("reading body: {e}")))?
            .to_bytes();
        if !status.is_success() {
            let snippet: String = String::from_utf8_lossy(&body).chars().take(200).collect();
            return Err(NetError::Status(status.as_u16(), snippet));
        }
        Ok(body.to_vec())
    })
    .await
    .map_err(|_| NetError::Timeout("attestation request"))?;
    driver.abort();

    Ok(Fetched {
        leaf_der,
        tls_version,
        body: result?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_parsing() {
        let t = Target::parse("https://vault.example.com").unwrap();
        assert_eq!((t.host.as_str(), t.port), ("vault.example.com", 443));
        let t = Target::parse("https://localhost:8443/").unwrap();
        assert_eq!((t.host.as_str(), t.port), ("localhost", 8443));
        assert!(Target::parse("http://vault.example.com").is_err());
        assert!(Target::parse("https://vault.example.com/admin").is_err());
        assert!(Target::parse("https://u@vault.example.com").is_err());
        assert!(Target::parse("vault.example.com").is_err());
    }
}
