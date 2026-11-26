//! Dev tool (network): fetch Intel DCAP collateral for a TDX quote and store
//! it as JSON, so unit tests can verify the quote offline.
//!
//!   cargo run -p attested-vw-verify --example record_collateral -- \
//!       <getquote.json|quote.bin> <out.json> [pccs_url]
//!
//! Collateral is signed by Intel, so the source (Intel PCS or a PCCS cache)
//! affects availability only, not integrity.

use std::process::ExitCode;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: record_collateral <getquote.json|quote.bin> <out.json> [pccs_url]");
        return ExitCode::from(2);
    }
    let raw = match std::fs::read(&args[1]) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("read {}: {e}", args[1]);
            return ExitCode::from(1);
        }
    };
    let quote = match serde_json::from_slice::<serde_json::Value>(&raw) {
        Ok(v) => match v.get("quote").and_then(|q| q.as_str()).map(hex::decode) {
            Some(Ok(q)) => q,
            _ => {
                eprintln!("JSON input has no hex `quote` field");
                return ExitCode::from(1);
            }
        },
        Err(_) => raw,
    };
    let url = args
        .get(3)
        .cloned()
        .unwrap_or_else(|| "https://api.trustedservices.intel.com".to_owned());
    let client = match dcap_qvl::collateral::CollateralClient::with_default_http(url.clone()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("client: {e:#}");
            return ExitCode::from(1);
        }
    };
    let collateral = match client.fetch(&quote).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("fetch from {url}: {e:#}");
            return ExitCode::from(1);
        }
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let out = serde_json::json!({
        "recorded_at_unix": now,
        "source": url,
        "collateral": collateral,
    });
    match std::fs::write(
        &args[2],
        serde_json::to_vec_pretty(&out).unwrap_or_default(),
    ) {
        Ok(()) => {
            eprintln!("wrote {} (recorded_at_unix={now})", args[2]);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("write {}: {e}", args[2]);
            ExitCode::from(1)
        }
    }
}
