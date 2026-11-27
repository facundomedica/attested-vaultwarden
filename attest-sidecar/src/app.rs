//! HTTP handler for the attestation endpoint.

use std::collections::HashMap;
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
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
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

/// Most client addresses tracked at once. When the table is full and no
/// entry has expired, further new clients share one bucket.
const MAX_TRACKED_CLIENTS: usize = 4096;

/// Request budgets per second.
#[derive(Debug, Clone, Copy)]
pub struct Rates {
    /// Per client address (as reported by the proxy).
    pub per_client: u32,
    /// All clients together; protects the guest agent.
    pub global: u32,
}

impl Rates {
    pub const DEFAULT: Rates = Rates {
        per_client: 5,
        global: 40,
    };
}

/// Fixed one-second window counter.
#[derive(Debug, Clone, Copy)]
struct Window {
    start: Instant,
    count: u32,
}

impl Window {
    fn new(now: Instant) -> Self {
        Self {
            start: now,
            count: 0,
        }
    }

    fn expired(&self, now: Instant) -> bool {
        now.duration_since(self.start) >= Duration::from_secs(1)
    }

    fn allow(&mut self, now: Instant, per_sec: u32) -> bool {
        if self.expired(now) {
            *self = Self::new(now);
        }
        if self.count >= per_sec {
            return false;
        }
        self.count += 1;
        true
    }
}

/// Two-level rate limiter: a budget per client address and a larger global
/// one. With only a global budget, one outsider sending a handful of
/// requests per second makes every honest verifier see HTTP 429.
///
/// The client address is the last element of `X-Forwarded-For`, which the
/// proxy (Caddy) writes itself from the TCP peer; nothing else can reach
/// the sidecar's port. Where every client arrives from the same address
/// (dstack gateway passthrough without PROXY protocol) they share one
/// per-client budget, as before; the verifier retries once on 429.
#[derive(Debug)]
struct RateLimiter {
    rates: Rates,
    state: Mutex<(Window, HashMap<String, Window>)>,
}

impl RateLimiter {
    fn new(rates: Rates) -> Self {
        Self {
            rates,
            state: Mutex::new((Window::new(Instant::now()), HashMap::new())),
        }
    }

    fn allow(&self, client: &str) -> bool {
        self.allow_at(client, Instant::now())
    }

    fn allow_at(&self, client: &str, now: Instant) -> bool {
        let Ok(mut guard) = self.state.lock() else {
            return false;
        };
        let (global, clients) = &mut *guard;
        if !clients.contains_key(client) && clients.len() >= MAX_TRACKED_CLIENTS {
            clients.retain(|_, w| !w.expired(now));
        }
        let key = if clients.contains_key(client) || clients.len() < MAX_TRACKED_CLIENTS {
            client
        } else {
            "(overflow)"
        };
        let w = clients
            .entry(key.to_owned())
            .or_insert_with(|| Window::new(now));
        // Per-client first, so a client over its own budget does not eat
        // the global one.
        w.allow(now, self.rates.per_client) && global.allow(now, self.rates.global)
    }
}

/// Longest client key kept (an IPv6 address is 39 characters).
const MAX_CLIENT_KEY: usize = 64;

/// The client address the proxy saw: the last `X-Forwarded-For` element.
/// Requests without the header (none in the published compose) share a key.
fn client_key(headers: &HeaderMap) -> String {
    headers
        .get_all("x-forwarded-for")
        .iter()
        .next_back()
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit(',').next())
        .map(str::trim)
        .filter(|v| !v.is_empty() && v.len() <= MAX_CLIENT_KEY)
        .unwrap_or("(none)")
        .to_owned()
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
        rates: Rates,
    ) -> Result<Self, compose::ComposeError> {
        let images = compose::images(&compose::docker_compose_file(&app_compose)?)?;
        Ok(Self {
            provider,
            cert_path,
            app_compose,
            images,
            limiter: RateLimiter::new(rates),
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
    headers: HeaderMap,
) -> Response {
    let nonce = match parse_nonce(query.as_deref()) {
        Ok(n) => n,
        Err(msg) => return error(StatusCode::BAD_REQUEST, msg),
    };
    if !st.limiter.allow(&client_key(&headers)) {
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
        match State::new(Mock, cert, compose, rates(per_sec)) {
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

    async fn get_from(app: Router, xff: &str) -> StatusCode {
        let uri = format!("/.well-known/tee-attestation?nonce={}", "ab".repeat(32));
        let req = Request::builder()
            .uri(uri)
            .header("x-forwarded-for", xff)
            .body(Body::empty())
            .unwrap();
        app.oneshot(req).await.unwrap().status()
    }

    /// One client exhausting its budget must not lock out another: the
    /// review found that 5 requests/s from anyone made every verifier fail.
    #[tokio::test]
    async fn one_client_cannot_starve_another() {
        let app = router(state(1));
        assert_eq!(get_from(app.clone(), "198.51.100.7").await, StatusCode::OK);
        for _ in 0..20 {
            assert_eq!(
                get_from(app.clone(), "198.51.100.7").await,
                StatusCode::TOO_MANY_REQUESTS
            );
        }
        assert_eq!(get_from(app.clone(), "203.0.113.9").await, StatusCode::OK);
        // Only the element the proxy appended counts: a client cannot get a
        // fresh budget by sending its own X-Forwarded-For prefix.
        assert_eq!(
            get_from(app, "10.0.0.1, 203.0.113.9").await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[test]
    fn limiter_budgets() {
        let l = RateLimiter::new(Rates {
            per_client: 2,
            global: 3,
        });
        let t0 = Instant::now();
        assert!(l.allow_at("a", t0) && l.allow_at("a", t0));
        assert!(!l.allow_at("a", t0), "per-client budget");
        assert!(l.allow_at("b", t0));
        assert!(!l.allow_at("c", t0), "global budget");
        // A rejected client did not consume the global budget meanwhile.
        let t1 = t0 + Duration::from_secs(1);
        assert!(l.allow_at("a", t1) && l.allow_at("c", t1));

        // The table is bounded; expired entries make room.
        let l = RateLimiter::new(Rates {
            per_client: 1,
            global: u32::MAX,
        });
        for i in 0..MAX_TRACKED_CLIENTS {
            assert!(l.allow_at(&format!("c{i}"), t0));
        }
        assert!(l.allow_at("overflow-1", t0));
        assert!(
            !l.allow_at("overflow-2", t0),
            "overflow clients share a bucket"
        );
        assert!(l.state.lock().unwrap().1.len() <= MAX_TRACKED_CLIENTS + 1);
        assert!(l.allow_at("late", t1));
        assert!(l.state.lock().unwrap().1.len() <= 2);
    }

    #[test]
    fn client_key_is_the_proxys_element() {
        let mut h = HeaderMap::new();
        assert_eq!(client_key(&h), "(none)");
        h.insert("x-forwarded-for", HeaderValue::from_static("1.2.3.4"));
        assert_eq!(client_key(&h), "1.2.3.4");
        h.insert(
            "x-forwarded-for",
            HeaderValue::from_static("9.9.9.9, 1.2.3.4 "),
        );
        assert_eq!(client_key(&h), "1.2.3.4");
        h.append("x-forwarded-for", HeaderValue::from_static("5.6.7.8"));
        assert_eq!(client_key(&h), "5.6.7.8");
        let long = "a".repeat(MAX_CLIENT_KEY + 1);
        h.insert("x-forwarded-for", HeaderValue::from_str(&long).unwrap());
        assert_eq!(client_key(&h), "(none)");
    }

    fn rates(per_client: u32) -> Rates {
        Rates {
            per_client,
            global: 40,
        }
    }
}
