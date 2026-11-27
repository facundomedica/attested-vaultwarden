//! Google Cloud Confidential Space provider.
//!
//! Asks the Confidential Space launcher for a Google Cloud Attestation OIDC
//! token carrying our `report_data` as two custom nonces:
//!
//! ```text
//! POST http://localhost/v1/token      (unix socket /run/container_launcher/teeserver.sock)
//! {"audience": "<AUDIENCE>", "token_type": "OIDC", "nonces": ["<64 hex>", "<64 hex>"]}
//! ```
//!
//! The response body is the JWT itself. (Google: "Connect to external
//! resources", custom tokens; launcher source `launcher/teeserver`.)
//!
//! The audience is fixed and is never `https://sts.googleapis.com`: this
//! endpoint hands tokens to anyone, so they must be useless for workload
//! identity federation. The sidecar only sanity-checks the token (shape and
//! echoed nonces); it does not verify the signature. The verifier does.
//!
//! Google rate-limits token requests (5 per second per project and region
//! at the time of writing); keep `ATTEST_GLOBAL_RATE_PER_SEC` (the budget
//! for all clients together; its default of 40 is too high here) below that.

use std::path::PathBuf;
use std::time::Duration;

use attested_vw_common::gcp_cs::{AUDIENCE, TOKEN_PATH, eat_nonces};
use attested_vw_common::provider::{ProviderError, QuoteProvider};
use attested_vw_common::report_data::ReportData;
use attested_vw_common::schema::{Evidence, Platform};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::Request;
use hyper::header::{CONTENT_TYPE, HOST};
use hyper_util::rt::TokioIo;

const MAX_RESPONSE: usize = 64 * 1024;
const TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct GcpCs {
    socket: PathBuf,
}

impl GcpCs {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
        }
    }

    async fn request_token(&self, body: serde_json::Value) -> Result<Vec<u8>, ProviderError> {
        let call = async {
            let stream = tokio::net::UnixStream::connect(&self.socket)
                .await
                .map_err(|e| ProviderError::new("connect launcher socket", e))?;
            let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
                .await
                .map_err(|e| ProviderError::new("launcher handshake", e))?;
            let driver = tokio::spawn(conn);
            let req = Request::post(TOKEN_PATH)
                .header(HOST, "localhost")
                .header(CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(body.to_string())))
                .map_err(|e| ProviderError::new("build request", e))?;
            let resp = sender
                .send_request(req)
                .await
                .map_err(|e| ProviderError::new("launcher request", e))?;
            let status = resp.status();
            let bytes = Limited::new(resp.into_body(), MAX_RESPONSE)
                .collect()
                .await
                .map_err(|e| ProviderError::new("launcher response body", e))?
                .to_bytes();
            driver.abort();
            if !status.is_success() {
                let msg: String = String::from_utf8_lossy(&bytes).chars().take(300).collect();
                return Err(ProviderError::new(
                    "launcher error",
                    format!("{TOKEN_PATH}: HTTP {status}: {msg}"),
                ));
            }
            Ok(bytes.to_vec())
        };
        tokio::time::timeout(TIMEOUT, call)
            .await
            .map_err(|_| ProviderError::new("launcher", format!("{TOKEN_PATH} timed out")))?
    }
}

/// Shape check and nonce echo. Not a signature check.
fn sanity_check(token: &str, nonces: &[String; 2]) -> Result<(), &'static str> {
    let mut parts = token.split('.');
    let (Some(_), Some(payload), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("response is not a compact JWT");
    };
    let claims: serde_json::Value = B64URL
        .decode(payload)
        .ok()
        .and_then(|p| serde_json::from_slice(&p).ok())
        .ok_or("token payload is not base64url JSON")?;
    let echoed: Vec<String> = serde_json::from_value(claims["eat_nonce"].clone())
        .map_err(|_| "token has no eat_nonce list")?;
    if echoed != nonces {
        return Err("launcher returned a token with different nonces");
    }
    if claims["aud"] != AUDIENCE {
        return Err("launcher returned a token with a different audience");
    }
    Ok(())
}

impl QuoteProvider for GcpCs {
    fn platform(&self) -> Platform {
        Platform::GcpCs
    }

    async fn get_evidence(&self, report_data: &ReportData) -> Result<Evidence, ProviderError> {
        let nonces = eat_nonces(report_data);
        let raw = self
            .request_token(serde_json::json!({
                "audience": AUDIENCE,
                "token_type": "OIDC",
                "nonces": nonces,
            }))
            .await?;
        let token = String::from_utf8(raw)
            .map_err(|e| ProviderError::new("token", e))?
            .trim()
            .to_owned();
        sanity_check(&token, &nonces).map_err(|e| ProviderError::new("token", e))?;
        Ok(Evidence {
            quote: B64.encode(token),
            event_log: None,
            aux: None,
            vm_config: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use attested_vw_common::report_data::{Nonce, SpkiSha256, compute};
    use axum::Router;
    use axum::http::StatusCode;
    use axum::routing::post;
    use std::sync::{Arc, Mutex};

    /// What the fake launcher does with a token request.
    #[derive(Clone, Copy)]
    enum Mode {
        Honest,
        OtherNonces,
        StsAudience,
        NotAJwt,
        Error,
        Hang,
    }

    struct Fake {
        path: PathBuf,
        /// Request bodies the fake launcher received.
        seen: Arc<Mutex<Vec<serde_json::Value>>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for Fake {
        fn drop(&mut self) {
            self.task.abort();
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn jwt(claims: &serde_json::Value) -> String {
        // Unsigned stand-in: the sidecar never checks signatures.
        format!(
            "{}.{}.{}",
            B64URL.encode(r#"{"alg":"RS256","kid":"fake"}"#),
            B64URL.encode(claims.to_string()),
            B64URL.encode("signature")
        )
    }

    /// A stand-in for the launcher's teeserver on a real Unix socket. Like
    /// the real one it rejects unknown fields and requires `audience` and
    /// `token_type`, and answers with the bare token as the body.
    fn fake_launcher(mode: Mode) -> Fake {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "avw-tee-{}-{}.sock",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&path);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        let app = Router::new().route(
            TOKEN_PATH,
            post(move |body: String| async move {
                let Ok(req) = serde_json::from_str::<serde_json::Value>(&body) else {
                    return (StatusCode::BAD_REQUEST, "bad json".to_owned());
                };
                seen2.lock().unwrap().push(req.clone());
                let known = ["audience", "token_type", "nonces"];
                let fields_ok = req
                    .as_object()
                    .is_some_and(|o| o.keys().all(|k| known.contains(&k.as_str())));
                if !fields_ok || req["audience"] == "" || req["token_type"] != "OIDC" {
                    return (StatusCode::BAD_REQUEST, "bad request".to_owned());
                }
                let mut claims = serde_json::json!({
                    "iss": "https://confidentialcomputing.googleapis.com",
                    "aud": req["audience"],
                    "eat_nonce": req["nonces"],
                });
                match mode {
                    Mode::Honest => {}
                    Mode::OtherNonces => {
                        claims["eat_nonce"] = serde_json::json!(["00".repeat(32), "11".repeat(32)]);
                    }
                    Mode::StsAudience => {
                        claims["aud"] = serde_json::json!("https://sts.googleapis.com");
                    }
                    Mode::NotAJwt => return (StatusCode::OK, "<html>oops</html>".to_owned()),
                    Mode::Error => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "verifier down".to_owned(),
                        );
                    }
                    Mode::Hang => std::future::pending::<()>().await,
                }
                (StatusCode::OK, jwt(&claims))
            }),
        );
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Fake { path, seen, task }
    }

    fn rd() -> ReportData {
        compute(&Nonce([3; 32]), &SpkiSha256([4; 32]))
    }

    #[tokio::test]
    async fn requests_custom_nonce_token_and_wraps_it() {
        let fake = fake_launcher(Mode::Honest);
        let p = GcpCs::new(&fake.path);
        assert_eq!(p.platform().as_str(), "gcp-cs");
        let ev = p.get_evidence(&rd()).await.unwrap();

        // Exactly the documented request, with report_data split in two.
        let seen = fake.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        let hex = rd().to_hex();
        assert_eq!(
            seen[0],
            serde_json::json!({
                "audience": AUDIENCE,
                "token_type": "OIDC",
                "nonces": [&hex[..64], &hex[64..]],
            })
        );
        assert_ne!(AUDIENCE, "https://sts.googleapis.com");

        // The evidence is the token, byte for byte, base64-wrapped.
        let token = String::from_utf8(B64.decode(&ev.quote).unwrap()).unwrap();
        assert_eq!(token.split('.').count(), 3);
        let payload: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(token.split('.').nth(1).unwrap()).unwrap())
                .unwrap();
        assert_eq!(payload["eat_nonce"][0], &hex[..64]);
        assert_eq!(payload["eat_nonce"][1], &hex[64..]);
        assert!(ev.event_log.is_none() && ev.aux.is_none() && ev.vm_config.is_none());
    }

    #[tokio::test]
    async fn refuses_tokens_it_did_not_ask_for() {
        for mode in [
            Mode::OtherNonces,
            Mode::StsAudience,
            Mode::NotAJwt,
            Mode::Error,
        ] {
            let fake = fake_launcher(mode);
            let r = GcpCs::new(&fake.path).get_evidence(&rd()).await;
            assert!(r.is_err());
        }
    }

    #[tokio::test]
    async fn missing_socket_is_an_error() {
        let p = GcpCs::new(std::env::temp_dir().join("avw-no-such-launcher.sock"));
        let e = p.get_evidence(&rd()).await.unwrap_err();
        assert!(e.to_string().contains("connect launcher socket"));
    }

    #[tokio::test(start_paused = true)]
    async fn hung_launcher_times_out() {
        let fake = fake_launcher(Mode::Hang);
        let e = GcpCs::new(&fake.path)
            .get_evidence(&rd())
            .await
            .unwrap_err();
        assert!(e.to_string().contains("timed out"), "{e}");
    }
}
