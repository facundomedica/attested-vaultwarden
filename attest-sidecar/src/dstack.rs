//! dstack guest-agent provider (Intel TDX).
//!
//! Uses the frozen v0 surface on the internal socket (`/var/run/dstack.sock`):
//! `POST /GetQuote` with `{"report_data": "<hex>"}` and `POST /Info`. The bare
//! paths exist on dstack 0.5.x and are aliases of `/v0/...` on 0.6.x
//! (dstack `docs/guest-api-v0.md`, "Transport and mounts"). `report_data` is
//! passed raw (≤ 64 bytes, zero-padded by the agent, never hashed); legacy
//! Tappd `TdxQuote`, which hashes its input, is deliberately not used.
//!
//! The sidecar only passes opaque bytes through: it never parses the quote.

use std::path::PathBuf;
use std::time::Duration;

use attested_vw_common::provider::{ProviderError, QuoteProvider};
use attested_vw_common::report_data::ReportData;
use attested_vw_common::schema::{Evidence, Platform};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::Request;
use hyper::header::{CONTENT_TYPE, HOST};
use hyper_util::rt::TokioIo;
use serde::Deserialize;

pub const DEFAULT_SOCKET: &str = "/var/run/dstack.sock";
const MAX_RESPONSE: usize = 4 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct Dstack {
    socket: PathBuf,
}

#[derive(Debug, Deserialize)]
struct GetQuoteResponse {
    quote: String,
    event_log: String,
    report_data: String,
    #[serde(default)]
    vm_config: Option<String>,
}

#[derive(Debug, Deserialize)]
struct InfoResponse {
    tcb_info: String,
}

#[derive(Debug, Deserialize)]
struct TcbInfo {
    app_compose: String,
}

impl Dstack {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
        }
    }

    async fn post(&self, path: &str, body: serde_json::Value) -> Result<Vec<u8>, ProviderError> {
        let call = async {
            let stream = tokio::net::UnixStream::connect(&self.socket)
                .await
                .map_err(|e| ProviderError::new("connect guest agent socket", e))?;
            let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
                .await
                .map_err(|e| ProviderError::new("guest agent handshake", e))?;
            let driver = tokio::spawn(conn);
            let req = Request::post(path)
                .header(HOST, "localhost")
                .header(CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(body.to_string())))
                .map_err(|e| ProviderError::new("build request", e))?;
            let resp = sender
                .send_request(req)
                .await
                .map_err(|e| ProviderError::new("guest agent request", e))?;
            let status = resp.status();
            let bytes = Limited::new(resp.into_body(), MAX_RESPONSE)
                .collect()
                .await
                .map_err(|e| ProviderError::new("guest agent response body", e))?
                .to_bytes();
            driver.abort();
            if !status.is_success() {
                let msg: String = String::from_utf8_lossy(&bytes).chars().take(300).collect();
                return Err(ProviderError::new(
                    "guest agent error",
                    format!("{path}: HTTP {status}: {msg}"),
                ));
            }
            Ok(bytes.to_vec())
        };
        tokio::time::timeout(TIMEOUT, call)
            .await
            .map_err(|_| ProviderError::new("guest agent", format!("{path} timed out")))?
    }

    /// The exact app-compose document dstack measured, from `Info.tcb_info`.
    /// Not evidence by itself: the verifier checks its hash against RTMR3.
    pub async fn app_compose(&self) -> Result<String, ProviderError> {
        let raw = self.post("/Info", serde_json::json!({})).await?;
        let info: InfoResponse =
            serde_json::from_slice(&raw).map_err(|e| ProviderError::new("parse Info", e))?;
        let tcb: TcbInfo = serde_json::from_str(&info.tcb_info)
            .map_err(|e| ProviderError::new("parse Info.tcb_info", e))?;
        Ok(tcb.app_compose)
    }
}

impl QuoteProvider for Dstack {
    fn platform(&self) -> Platform {
        Platform::Tdx
    }

    async fn get_evidence(&self, report_data: &ReportData) -> Result<Evidence, ProviderError> {
        let raw = self
            .post(
                "/GetQuote",
                serde_json::json!({ "report_data": report_data.to_hex() }),
            )
            .await?;
        let r: GetQuoteResponse =
            serde_json::from_slice(&raw).map_err(|e| ProviderError::new("parse GetQuote", e))?;
        // Sanity: the agent must have used our bytes unchanged.
        if !r.report_data.eq_ignore_ascii_case(&report_data.to_hex()) {
            return Err(ProviderError::new(
                "GetQuote",
                "agent echoed a different report_data",
            ));
        }
        let quote =
            hex::decode(&r.quote).map_err(|e| ProviderError::new("GetQuote quote hex", e))?;
        // The event log is passed through verbatim; the verifier replays it.
        serde_json::from_str::<serde_json::Value>(&r.event_log)
            .map_err(|e| ProviderError::new("GetQuote event_log", e))?;
        Ok(Evidence {
            quote: B64.encode(quote),
            event_log: Some(r.event_log),
            aux: None,
            vm_config: r.vm_config.filter(|v| !v.is_empty()),
        })
    }
}
