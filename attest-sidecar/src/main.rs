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
//! | `ATTEST_PLATFORM` | `mock` (INSECURE), `dstack`, `sev-snp` (configfs-tsm; untested on hardware) or `gcp-cs` (never run on GCP) |
//! | `ATTEST_INSECURE_MOCK` | must be `1` for `mock` to start |
//! | `ATTEST_LISTEN` | listen address, default `0.0.0.0:8081` |
//! | `ATTEST_CERT_PATH` | PEM file whose first certificate is the TLS leaf |
//! | `ATTEST_APP_COMPOSE_PATH` | app-compose document (mock and sev-snp; dstack reads it from the guest agent). On sev-snp its SHA-256 must equal the guest's `HOST_DATA` or the sidecar refuses to start |
//! | `ATTEST_TSM_REPORT_DIR` | configfs-tsm report directory, default `/sys/kernel/config/tsm/report` |
//! | `ATTEST_DSTACK_SOCKET` | guest agent socket, default `/var/run/dstack.sock` |
//! | `ATTEST_GCP_CS_SOCKET` | Confidential Space launcher socket, default `/run/container_launcher/teeserver.sock` |
//! | `ATTEST_RATE_PER_SEC` | request budget per second and client address (last `X-Forwarded-For` element, written by the proxy), default 5 |
//! | `ATTEST_GLOBAL_RATE_PER_SEC` | request budget per second for all clients together, default 40 |

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::panic, clippy::unwrap_used, clippy::expect_used))]

mod app;
mod configfs_tsm;
mod dstack;
mod gcp_cs;
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
    let rate = |name: &str, default: u32| match std::env::var(name) {
        Ok(v) => v.parse::<u32>().map_err(|e| format!("{name}: {e}")),
        Err(_) => Ok(default),
    };
    let rates = app::Rates {
        per_client: rate("ATTEST_RATE_PER_SEC", app::Rates::DEFAULT.per_client)?,
        global: rate("ATTEST_GLOBAL_RATE_PER_SEC", app::Rates::DEFAULT.global)?,
    };
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
            let state = app::State::new(providers::Mock, cert_path, app_compose, rates)
                .map_err(|e| format!("app-compose: {e}"))?;
            app::router(Arc::new(state))
        }
        "dstack" => {
            let socket = std::env::var("ATTEST_DSTACK_SOCKET")
                .unwrap_or_else(|_| dstack::DEFAULT_SOCKET.to_owned());
            let provider = dstack::Dstack::new(socket);
            let app_compose = provider
                .app_compose()
                .await
                .map_err(|e| format!("reading app-compose from guest agent: {e}"))?;
            let state = app::State::new(provider, cert_path, app_compose, rates)
                .map_err(|e| format!("app-compose: {e}"))?;
            app::router(Arc::new(state))
        }
        "sev-snp" => {
            let dir = std::env::var("ATTEST_TSM_REPORT_DIR")
                .unwrap_or_else(|_| configfs_tsm::DEFAULT_REPORT_DIR.to_owned());
            let provider = configfs_tsm::ConfigfsTsm::new(dir);
            let compose_path = env("ATTEST_APP_COMPOSE_PATH")?;
            let app_compose = std::fs::read_to_string(&compose_path)
                .map_err(|e| format!("reading {compose_path}: {e}"))?;
            // Refuse to serve a config the host did not bind at launch. The
            // measured image must already have enforced this (docs/SNP.md).
            let host_data = provider
                .host_data()
                .await
                .map_err(|e| format!("reading HOST_DATA from an SNP report: {e}"))?;
            configfs_tsm::check_host_data(&host_data, &app_compose)?;
            let state = app::State::new(provider, cert_path, app_compose, rates)
                .map_err(|e| format!("app-compose: {e}"))?;
            app::router(Arc::new(state))
        }
        "gcp-cs" => {
            let socket = std::env::var("ATTEST_GCP_CS_SOCKET")
                .unwrap_or_else(|_| attested_vw_common::gcp_cs::DEFAULT_SOCKET.to_owned());
            // No compose document on this platform: the single workload
            // image is named by the token's claims.
            let state = app::State::without_compose(gcp_cs::GcpCs::new(socket), cert_path, rates);
            app::router(Arc::new(state))
        }
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
