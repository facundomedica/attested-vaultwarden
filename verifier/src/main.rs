#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use attested_vw_common::policy::Policy;
use attested_vw_verifier::{Options, verify};
use clap::Parser;

/// Verify that an Attested Vaultwarden deployment runs the published software
/// on genuine TEE hardware and that its TLS key lives inside that TEE.
#[derive(Debug, Parser)]
#[command(version)]
struct Args {
    /// Deployment URL, e.g. https://vault.example.com
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
}

fn main() -> ExitCode {
    let args = Args::parse();
    let policy = match std::fs::read_to_string(&args.policy)
        .map_err(|e| e.to_string())
        .and_then(|s| Policy::from_toml(&s).map_err(|e| e.to_string()))
    {
        Ok(p) => p,
        Err(e) => {
            eprintln!("FAIL: cannot load policy {}: {e}", args.policy.display());
            return ExitCode::from(1);
        }
    };
    let report = verify(
        &args.url,
        &policy,
        &Options {
            allow_insecure_mock: args.allow_insecure_mock,
        },
    );
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
