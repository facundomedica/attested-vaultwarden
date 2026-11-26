//! Attestation sidecar.
//!
//! Serves `GET /.well-known/tee-attestation?nonce=<64 hex>` and nothing else.
//! The response binds the caller's nonce and the SPKI hash of the TLS leaf
//! certificate currently served by the proxy into the TEE `report_data`.
//!
//! Configuration (environment):
//!
//! | Variable | Meaning |
//! |----------|---------|
//! | `ATTEST_PLATFORM` | `mock` (INSECURE) or `dstack` (M3) |
//! | `ATTEST_INSECURE_MOCK` | must be `1` for `mock` to start |
//! | `ATTEST_LISTEN` | listen address, default `0.0.0.0:8081` |
//! | `ATTEST_CERT_PATH` | PEM file whose first certificate is the TLS leaf |
//! | `ATTEST_APP_COMPOSE_PATH` | measured app-compose document (mock only) |
//! | `ATTEST_RATE_PER_SEC` | global request budget per second, default 5 |

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::panic, clippy::unwrap_used, clippy::expect_used))]

mod app;
mod providers;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use attested_vw_common::INSECURE_MOCK_BANNER;

fn env(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("missing environment variable {name}"))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("attest-sidecar: fatal: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    let listen: SocketAddr = std::env::var("ATTEST_LISTEN")
        .unwrap_or_else(|_| "0.0.0.0:8081".to_owned())
        .parse()
        .map_err(|e| format!("ATTEST_LISTEN: {e}"))?;
    let rate: u32 = std::env::var("ATTEST_RATE_PER_SEC")
        .unwrap_or_else(|_| "5".to_owned())
        .parse()
        .map_err(|e| format!("ATTEST_RATE_PER_SEC: {e}"))?;
    let cert_path = PathBuf::from(env("ATTEST_CERT_PATH")?);

    let platform = env("ATTEST_PLATFORM")?;
    let router = match platform.as_str() {
        "mock" => {
            if std::env::var("ATTEST_INSECURE_MOCK").as_deref() != Ok("1") {
                return Err("ATTEST_PLATFORM=mock requires ATTEST_INSECURE_MOCK=1".into());
            }
            eprintln!("attest-sidecar: WARNING: {INSECURE_MOCK_BANNER}");
            let compose_path = env("ATTEST_APP_COMPOSE_PATH")?;
            let app_compose = std::fs::read_to_string(&compose_path)
                .map_err(|e| format!("reading {compose_path}: {e}"))?;
            let state = app::State::new(providers::Mock, cert_path, app_compose, rate)
                .map_err(|e| format!("app-compose: {e}"))?;
            app::router(Arc::new(state))
        }
        "dstack" => return Err("ATTEST_PLATFORM=dstack is not implemented yet (M3)".into()),
        other => return Err(format!("unknown ATTEST_PLATFORM `{other}`")),
    };

    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|e| format!("bind {listen}: {e}"))?;
    eprintln!("attest-sidecar: platform={platform} listening on {listen}");
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .map_err(|e| format!("serve: {e}"))
}
