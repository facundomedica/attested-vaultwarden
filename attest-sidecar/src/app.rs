//! HTTP handler for the attestation endpoint.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use attested_vw_common::compose;
use attested_vw_common::provider::QuoteProvider;
use attested_vw_common::report_data::{self, Nonce};
use attested_vw_common::schema::{AttestationResponse, ImageDigest, SCHEMA_VERSION};
use attested_vw_common::tls;
use axum::Router;
use axum::extract::{DefaultBodyLimit, RawQuery, State as AxState};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use tokio::sync::Semaphore;

/// Longest query string accepted (`nonce=` + 64 hex).
const MAX_QUERY_LEN: usize = 6 + 64;
/// Largest certificate bundle file read from the proxy's storage.
const MAX_CERT_FILE: u64 = 64 * 1024;
/// Upper bound on one evidence request to the platform.
const PROVIDER_TIMEOUT: Duration = Duration::from_secs(10);
/// Concurrent evidence requests.
const MAX_CONCURRENT: usize = 4;

/// Fixed-window global rate limiter. The sidecar sits behind the proxy, so
/// client IPs are not meaningful here; the budget protects the guest agent.
#[derive(Debug)]
struct RateLimiter {
    per_sec: u32,
    window: Mutex<(Instant, u32)>,
}

impl RateLimiter {
    fn new(per_sec: u32) -> Self {
        Self {
            per_sec,
            window: Mutex::new((Instant::now(), 0)),
        }
    }

    fn allow(&self) -> bool {
        let Ok(mut w) = self.window.lock() else {
            return false;
        };
        let now = Instant::now();
        if now.duration_since(w.0) >= Duration::from_secs(1) {
            *w = (now, 0);
        }
        if w.1 >= self.per_sec {
            return false;
        }
        w.1 += 1;
        true
    }
}

#[derive(Debug)]
pub struct State<P> {
    provider: P,
    cert_path: PathBuf,
    app_compose: String,
    images: Vec<ImageDigest>,
    limiter: RateLimiter,
    in_flight: Semaphore,
}

impl<P: QuoteProvider> State<P> {
    /// Fails if the app-compose document cannot be parsed: the sidecar
    /// refuses to start rather than serve a document it cannot describe.
    pub fn new(
        provider: P,
        cert_path: PathBuf,
        app_compose: String,
        per_sec: u32,
    ) -> Result<Self, compose::ComposeError> {
        let images = compose::images(&compose::docker_compose_file(&app_compose)?)?;
        Ok(Self {
            provider,
            cert_path,
            app_compose,
            images,
            limiter: RateLimiter::new(per_sec),
            in_flight: Semaphore::new(MAX_CONCURRENT),
        })
    }
}

pub fn router<P: QuoteProvider>(state: Arc<State<P>>) -> Router {
    Router::new()
        .route(attested_vw_common::ATTESTATION_PATH, get(handler::<P>))
        .layer(DefaultBodyLimit::max(0))
        .with_state(state)
}

fn error(status: StatusCode, msg: &'static str) -> Response {
    let mut r = (status, axum::Json(serde_json::json!({ "error": msg }))).into_response();
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

fn parse_nonce(query: Option<&str>) -> Result<Nonce, &'static str> {
    let q = query.ok_or("missing ?nonce=<64 hex>")?;
    if q.len() > MAX_QUERY_LEN {
        return Err("query too long");
    }
    let hex = q
        .strip_prefix("nonce=")
        .ok_or("expected exactly ?nonce=<64 hex>")?;
    hex.parse::<Nonce>()
        .map_err(|_| "nonce must be exactly 64 hex characters")
}

async fn current_spki(
    path: &PathBuf,
) -> Result<attested_vw_common::report_data::SpkiSha256, String> {
    let meta = tokio::fs::metadata(path).await.map_err(|e| e.to_string())?;
    if meta.len() > MAX_CERT_FILE {
        return Err("certificate file too large".into());
    }
    let pem = tokio::fs::read(path).await.map_err(|e| e.to_string())?;
    let der = tls::first_cert_der_from_pem(&pem).map_err(|e| e.to_string())?;
    tls::spki_sha256_from_der(&der).map_err(|e| e.to_string())
}

async fn handler<P: QuoteProvider>(
    AxState(st): AxState<Arc<State<P>>>,
    RawQuery(query): RawQuery,
) -> Response {
    let nonce = match parse_nonce(query.as_deref()) {
        Ok(n) => n,
        Err(msg) => return error(StatusCode::BAD_REQUEST, msg),
    };
    if !st.limiter.allow() {
        return error(StatusCode::TOO_MANY_REQUESTS, "rate limited");
    }
    let Ok(_permit) = st.in_flight.try_acquire() else {
        return error(
            StatusCode::TOO_MANY_REQUESTS,
            "too many concurrent requests",
        );
    };

    // Read the certificate on every request so renewals are picked up.
    let spki = match current_spki(&st.cert_path).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "attest-sidecar: cannot read TLS certificate {}: {e}",
                st.cert_path.display()
            );
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "TLS certificate not available",
            );
        }
    };
    let rd = report_data::compute(&nonce, &spki);
    let evidence = match tokio::time::timeout(PROVIDER_TIMEOUT, st.provider.get_evidence(&rd)).await
    {
        Ok(Ok(ev)) => ev,
        Ok(Err(e)) => {
            eprintln!("attest-sidecar: evidence error: {e}");
            return error(StatusCode::SERVICE_UNAVAILABLE, "evidence not available");
        }
        Err(_) => {
            eprintln!("attest-sidecar: evidence request timed out");
            return error(StatusCode::SERVICE_UNAVAILABLE, "evidence not available");
        }
    };
    let timestamp = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();

    let doc = AttestationResponse {
        version: SCHEMA_VERSION,
        platform: st.provider.platform(),
        evidence,
        nonce,
        spki_sha256: spki,
        report_data_construction: report_data::CONSTRUCTION.to_owned(),
        app_compose: st.app_compose.clone(),
        image_digests: st.images.clone(),
        timestamp,
    };
    let mut r = axum::Json(doc).into_response();
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::Mock;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    const D: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn state(per_sec: u32) -> Arc<State<Mock>> {
        let compose = serde_json::json!({
            "docker_compose_file": format!("services:\n  vw:\n    image: vaultwarden/server@sha256:{D}\n")
        })
        .to_string();
        let cert = PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../common/testdata/test-cert.pem"
        ));
        match State::new(Mock, cert, compose, per_sec) {
            Ok(s) => Arc::new(s),
            Err(e) => panic!("state: {e}"),
        }
    }

    async fn get(app: Router, uri: &str) -> (StatusCode, serde_json::Value) {
        let req = Request::builder().uri(uri).body(Body::empty());
        let Ok(req) = req else { panic!("request") };
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let body = resp
            .into_body()
            .collect()
            .await
            .map(|b| b.to_bytes())
            .unwrap_or_default();
        (status, serde_json::from_slice(&body).unwrap_or_default())
    }

    #[tokio::test]
    async fn serves_bound_document() {
        let app = router(state(5));
        let nonce = "ab".repeat(32);
        let (status, body) = get(app, &format!("/.well-known/tee-attestation?nonce={nonce}")).await;
        assert_eq!(status, StatusCode::OK);
        let doc: AttestationResponse = match serde_json::from_value(body) {
            Ok(d) => d,
            Err(e) => panic!("schema: {e}"),
        };
        assert_eq!(doc.nonce.to_hex(), nonce);
        let expected_spki = include_str!("../../common/testdata/test-cert.spki-sha256.hex");
        assert_eq!(doc.spki_sha256.to_hex(), expected_spki.trim());
        assert_eq!(doc.image_digests.len(), 1);
        assert_eq!(doc.platform.as_str(), "mock");
    }

    #[tokio::test]
    async fn rejects_bad_nonces() {
        for q in [
            "",
            "?nonce=",
            "?nonce=abc",
            &format!("?nonce={}", "zz".repeat(32)),
            &format!("?nonce={}&x=1", "ab".repeat(32)),
            &format!("?x=1&nonce={}", "ab".repeat(32)),
        ] {
            let (status, _) = get(
                router(state(5)),
                &format!("/.well-known/tee-attestation{q}"),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "query {q:?}");
        }
    }

    #[tokio::test]
    async fn other_paths_404() {
        let (status, _) = get(router(state(5)), "/").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn rate_limited() {
        let app = router(state(1));
        let uri = format!("/.well-known/tee-attestation?nonce={}", "ab".repeat(32));
        let (s1, _) = get(app.clone(), &uri).await;
        let (s2, _) = get(app, &uri).await;
        assert_eq!(s1, StatusCode::OK);
        assert_eq!(s2, StatusCode::TOO_MANY_REQUESTS);
    }
}
