#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::panic, clippy::unwrap_used, clippy::expect_used))]

use std::path::PathBuf;
use std::process::ExitCode;

use attested_vw_common::policy::Policy;
use attested_vw_common::tls;
use attested_vw_verifier::{Options, Roots, verify};
use clap::Parser;

/// Verify that an Attested Vaultwarden deployment runs the published software
/// on genuine TEE hardware and that its TLS key lives inside that TEE.
///
/// Exit codes: 0 PASS, 1 FAIL, 2 every check passed but the evidence was the
/// INSECURE mock (proves nothing).
#[derive(Debug, Parser)]
#[command(version)]
struct Args {
    /// Deployment origin, e.g. https://vault.example.com
    url: String,
    /// Release policy file, e.g. policy/2026.11.0.toml
    #[arg(long)]
    policy: PathBuf,
    /// Print the report as JSON.
    #[arg(long)]
    json: bool,
    /// Accept INSECURE mock evidence (local development only). The result is
    /// never PASS; the exit code is 2 when every other check passed.
    #[arg(long)]
    allow_insecure_mock: bool,
    /// Trust ONLY the CA certificates in this PEM file instead of the WebPKI
    /// roots (local development).
    #[arg(long)]
    ca: Option<PathBuf>,
}

fn load(args: &Args) -> Result<(Policy, Roots), String> {
    let policy = std::fs::read_to_string(&args.policy)
        .map_err(|e| e.to_string())
        .and_then(|s| Policy::from_toml(&s).map_err(|e| e.to_string()))
        .map_err(|e| format!("cannot load policy {}: {e}", args.policy.display()))?;
    let roots = match &args.ca {
        None => Roots::WebPki,
        Some(p) => {
            let pem = std::fs::read(p).map_err(|e| format!("cannot read {}: {e}", p.display()))?;
            let ders = tls::all_cert_ders_from_pem(&pem)
                .map_err(|e| format!("cannot parse {}: {e}", p.display()))?;
            Roots::Custom(ders)
        }
    };
    Ok((policy, roots))
}

fn main() -> ExitCode {
    let args = Args::parse();
    let (policy, roots) = match load(&args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("FAIL: {e}");
            return ExitCode::from(1);
        }
    };
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("FAIL: cannot start runtime: {e}");
            return ExitCode::from(1);
        }
    };
    let opts = Options {
        allow_insecure_mock: args.allow_insecure_mock,
        roots,
    };
    let report = rt.block_on(verify(&args.url, &policy, &opts));
    if args.json {
        match serde_json::to_string_pretty(&report) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("FAIL: cannot serialize report: {e}");
                return ExitCode::from(1);
            }
        }
    } else {
        println!("{report}");
    }
    ExitCode::from(u8::try_from(report.exit_code()).unwrap_or(1))
}
