//! Verification report: an ordered list of checks, each pass or fail with a
//! reason. The overall result is PASS only if every check passed. There is
//! no "skipped" state: a check that cannot run is a failure.

use std::fmt;

use serde::Serialize;

/// Identifiers of the checks, in the order the verifier runs them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckId {
    /// TLS handshake with WebPKI validation; leaf SPKI captured.
    Tls,
    /// Attestation document fetched over the same connection and parsed.
    Fetch,
    /// `spki_sha256` in the document equals the SPKI of the TLS leaf.
    SpkiBinding,
    /// Nonce in the document equals the one we sent.
    Nonce,
    /// Evidence signature chain, TCB status, debug disabled.
    Evidence,
    /// `report_data` in the signed evidence equals our recomputation.
    ReportData,
    /// Platform measurements equal the policy.
    Measurements,
    /// RTMR3 event log replays to the quoted RTMR3 (TDX).
    EventLog,
    /// SEV-SNP: `HOST_DATA` is set and the pinned image enforces it.
    HostData,
    /// Hash of the measured compose document equals the policy.
    ComposeHash,
    /// The measured app-compose is self-contained: no launch scripts, no
    /// injected env, no variable interpolation (unless the policy allows).
    Config,
    /// Every image in the measured compose is digest-pinned and allowlisted.
    Images,
}

impl CheckId {
    pub fn label(&self) -> &'static str {
        match self {
            CheckId::Tls => "TLS connection, certificate validated",
            CheckId::Fetch => "Fetch attestation over same connection",
            CheckId::SpkiBinding => "TLS key bound to attestation",
            CheckId::Nonce => "Freshness nonce",
            CheckId::Evidence => "Hardware evidence signature, TCB, debug off",
            CheckId::ReportData => "report_data matches nonce + TLS key",
            CheckId::Measurements => "Firmware / OS measurements",
            CheckId::EventLog => "Runtime event log (RTMR3 replay)",
            CheckId::HostData => "Launch config binding (SNP HOST_DATA)",
            CheckId::ComposeHash => "Compose hash (published software)",
            CheckId::Config => "Measured config is self-contained",
            CheckId::Images => "Images pinned and allowlisted",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub id: CheckId,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub target: String,
    pub policy_release: Option<String>,
    pub platform: Option<String>,
    /// Set when the evidence is the INSECURE mock and the user allowed it.
    pub insecure_mock: bool,
    pub checks: Vec<Check>,
    /// Context lines (trust roots, retries). Not checks.
    pub notes: Vec<String>,
    /// Values read from the evidence and document, for drafting a policy
    /// from a live deployment. Hardware-backed only if the `evidence` check
    /// passed; never a substitute for independently computed measurements.
    pub observed: Observed,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Observed {
    pub tcb_status: Option<String>,
    pub advisory_ids: Vec<String>,
    pub pck_flags_set: Vec<String>,
    pub mrtd: Option<String>,
    pub rtmr0: Option<String>,
    pub rtmr1: Option<String>,
    pub rtmr2: Option<String>,
    pub rtmr3: Option<String>,
    pub compose_hash_measured: Option<String>,
    pub compose_hash_served: Option<String>,
    pub pre_launch_script_sha256: Option<String>,
    pub allowed_envs: Vec<String>,
    pub app_id: Option<String>,
    pub key_provider: Option<String>,
    pub images: Vec<(String, String)>,
    /// SEV-SNP launch measurement and HOST_DATA (hex), from the report.
    pub snp_measurement: Option<String>,
    pub snp_host_data: Option<String>,
    /// Host-declared dstack vm_config, if the server sent it (unmeasured).
    pub vm_config: Option<serde_json::Value>,
}

impl Report {
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            policy_release: None,
            platform: None,
            insecure_mock: false,
            checks: Vec::new(),
            notes: Vec::new(),
            observed: Observed::default(),
        }
    }

    pub fn pass(&mut self, id: CheckId, detail: impl Into<String>) {
        self.checks.push(Check {
            id,
            passed: true,
            detail: detail.into(),
        });
    }

    pub fn fail(&mut self, id: CheckId, detail: impl Into<String>) {
        self.checks.push(Check {
            id,
            passed: false,
            detail: detail.into(),
        });
    }

    /// PASS only if at least one check ran, all checks passed, and the
    /// evidence was not the insecure mock.
    pub fn passed(&self) -> bool {
        !self.checks.is_empty() && self.checks.iter().all(|c| c.passed) && !self.insecure_mock
    }

    /// Process exit code: 0 on PASS, 1 on FAIL, 2 on mock-only PASS.
    pub fn exit_code(&self) -> i32 {
        if self.passed() {
            0
        } else if self.insecure_mock && self.checks.iter().all(|c| c.passed) {
            2
        } else {
            1
        }
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.insecure_mock {
            writeln!(f, "!!! {} !!!", attested_vw_common::INSECURE_MOCK_BANNER)?;
        }
        writeln!(f, "Target:  {}", self.target)?;
        if let Some(r) = &self.policy_release {
            writeln!(f, "Policy:  release {r}")?;
        }
        if let Some(p) = &self.platform {
            writeln!(f, "Platform: {p}")?;
        }
        for n in &self.notes {
            writeln!(f, "  ({n})")?;
        }
        for c in &self.checks {
            let mark = if c.passed { "✓" } else { "✗" };
            writeln!(f, "  {mark} {}: {}", c.id.label(), c.detail)?;
        }
        let verdict = if self.passed() {
            "PASS"
        } else if self.exit_code() == 2 {
            "PASS (INSECURE MOCK, proves nothing)"
        } else {
            "FAIL"
        };
        write!(f, "Result:  {verdict}")?;
        if self.insecure_mock {
            write!(f, "\n!!! {} !!!", attested_vw_common::INSECURE_MOCK_BANNER)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_report_fails() {
        let r = Report::new("x");
        assert!(!r.passed());
        assert_eq!(r.exit_code(), 1);
    }

    #[test]
    fn any_failure_fails() {
        let mut r = Report::new("x");
        r.pass(CheckId::Tls, "ok");
        r.fail(CheckId::Fetch, "boom");
        assert!(!r.passed());
        assert_eq!(r.exit_code(), 1);
    }

    #[test]
    fn mock_never_passes() {
        let mut r = Report::new("x");
        r.insecure_mock = true;
        r.pass(CheckId::Tls, "ok");
        assert!(!r.passed());
        assert_eq!(r.exit_code(), 2);
        assert!(r.to_string().contains("INSECURE MOCK"));
    }
}
