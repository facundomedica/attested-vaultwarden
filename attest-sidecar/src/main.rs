//! Attestation sidecar.
//!
//! Serves `GET /.well-known/tee-attestation?nonce=<64 hex>` and nothing else.
//! The response binds the caller's nonce and the SPKI hash of the TLS leaf
//! certificate currently served by the proxy into the TEE `report_data`.
//!
//! M0 scaffold: Mock provider only; the TLS certificate source and the real
//! providers arrive in M1/M3.

#![forbid(unsafe_code)]

mod providers;

use std::net::SocketAddr;

use attested_vw_common::provider::QuoteProvider;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let provider = providers::Mock::new();
    let listen: SocketAddr = std::env::var("ATTEST_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:8081".to_owned())
        .parse()?;
    eprintln!(
        "attest-sidecar (platform={}) scaffold; listening on {listen} is not implemented yet",
        provider.platform().as_str()
    );
    Ok(())
}
