//! Attested Vaultwarden verifier library.
//!
//! The CLI (`attested-vw-verify`) is a thin wrapper around [`verify`]. Every
//! step is fail-closed: an error at any point records a failed check and the
//! overall result is FAIL.
//!
//! M0 scaffold: the pipeline shape and report are in place; network, evidence
//! and measurement checks are implemented in M1 (mock) and M2 (TDX/SNP).

#![forbid(unsafe_code)]

pub mod report;

use attested_vw_common::policy::Policy;

pub use report::{Check, CheckId, Report};

/// Options controlling a verification run.
#[derive(Debug, Clone)]
pub struct Options {
    /// Accept the INSECURE mock platform (local development only). Even when
    /// set, a mock result never counts as PASS.
    pub allow_insecure_mock: bool,
}

/// Verify a deployment at `target` (an `https://` URL) against `policy`.
pub fn verify(target: &str, policy: &Policy, _opts: &Options) -> Report {
    let mut report = Report::new(target);
    report.policy_release = Some(policy.release.clone());
    report.fail(
        CheckId::Tls,
        "not implemented yet (M0 scaffold); refusing to report success",
    );
    report
}
