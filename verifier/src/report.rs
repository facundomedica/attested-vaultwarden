//! Verification report: an ordered list of checks, each pass or fail with a
//! reason. The overall result is PASS only if every check passed. There is
//! no "skipped" state: a check that cannot run is a failure.
//!
//! Everything a server can influence reaches the user through a check
//! detail or a note, and both are sanitised on the way in and again on the
//! way out ([`sanitize`]), so a hostile server cannot draw its own
//! `Result:  PASS` line or hide the real one.

use std::collections::BTreeMap;
use std::fmt;

use serde::Serialize;

/// Longest check detail or note kept (characters).
pub const MAX_DETAIL_CHARS: usize = 2000;

/// Make untrusted text safe to print on a terminal and impossible to mistake
/// for report structure:
///
/// * every control character (C0 including `\n`, `\r`, `\t` and ESC; DEL;
///   C1), every Unicode bidi/format control (U+202A–202E, U+2066–2069 and
///   friends), line/paragraph separator and non-ASCII space is written as
///   `\u{..}`: a detail is always exactly one line and cannot move the
///   cursor, hide text or reorder it;
/// * the text is cut after `max` characters, with a visible marker.
///
/// Idempotent (apart from the truncation marker), so sanitising twice is
/// harmless.
pub fn sanitize(s: &str, max: usize) -> String {
    let mut out = String::with_capacity(s.len().min(max.saturating_mul(2)));
    for (n, c) in s.chars().enumerate() {
        if n >= max {
            out.push_str(" [truncated]");
            break;
        }
        if needs_escape(c) {
            out.push_str(&format!("\\u{{{:x}}}", u32::from(c)));
        } else {
            out.push(c);
        }
    }
    out
}

fn needs_escape(c: char) -> bool {
    c.is_control()
        || (c.is_whitespace() && c != ' ')
        || matches!(
            c,
            '\u{00ad}'                    // soft hyphen
            | '\u{061c}'                  // Arabic letter mark
            | '\u{180e}'                  // Mongolian vowel separator
            | '\u{200b}'..='\u{200f}'     // zero-width characters, LRM, RLM
            | '\u{2028}'..='\u{202f}'     // LS, PS, bidi embeddings and overrides
            | '\u{2060}'..='\u{206f}'     // word joiner, bidi isolates, format controls
            | '\u{feff}'                  // byte order mark
            | '\u{fff9}'..='\u{fffb}'     // interlinear annotation
            | '\u{e0000}'..='\u{e007f}'   // tag characters
        )
}

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
    /// The measured app-compose runs nothing the policy has not pinned (no
    /// unpinned launch script, injected env or interpolation) and gives no
    /// container host-level access (see `compose::hardening_problems`).
    /// Defence in depth: the compose hash already pins the whole document;
    /// this check is NOT a proof that the configuration is safe.
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
            CheckId::Config => "Measured config: known pitfalls absent",
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

/// Serialises (`--json`) with two extra leading fields, `result` (`PASS`,
/// `FAIL` or `INSECURE_MOCK`) and `exit_code`, so that a consumer never has
/// to derive the verdict from the checks.
#[derive(Debug, Clone)]
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
    /// Lower of the TCB info and QE identity `tcbEvaluationDataNumber` of the
    /// collateral the quote was judged against.
    pub tcb_eval_data_number: Option<u32>,
    pub advisory_ids: Vec<String>,
    pub pck_flags_set: Vec<String>,
    pub mrtd: Option<String>,
    pub rtmr0: Option<String>,
    pub rtmr1: Option<String>,
    pub rtmr2: Option<String>,
    pub rtmr3: Option<String>,
    /// TD report fields set by the host at launch (hex).
    pub mr_config_id: Option<String>,
    pub mr_owner: Option<String>,
    pub mr_owner_config: Option<String>,
    pub td_attributes: Option<String>,
    pub xfam: Option<String>,
    pub compose_hash_measured: Option<String>,
    pub compose_hash_served: Option<String>,
    pub pre_launch_script_sha256: Option<String>,
    pub allowed_envs: Vec<String>,
    /// Behaviour-affecting top-level flags of the measured app-compose
    /// (`public_logs`, `kms_enabled`, ...). A flag the document does not set
    /// is absent here.
    pub app_compose_flags: BTreeMap<String, serde_json::Value>,
    pub app_id: Option<String>,
    pub key_provider: Option<String>,
    /// Names of the replayed RTMR3 events, in order.
    pub rtmr3_events: Vec<String>,
    pub images: Vec<(String, String)>,
    /// SEV-SNP launch measurement and HOST_DATA (hex), from the report.
    pub snp_measurement: Option<String>,
    pub snp_host_data: Option<String>,
    /// Host-declared dstack vm_config, if the server sent it (unmeasured).
    pub vm_config: Option<serde_json::Value>,
    /// gcp-cs: claims read from the Google-signed token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gcp_cs: Option<serde_json::Value>,
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

    /// Record a passed check. `detail` is sanitised ([`sanitize`]).
    pub fn pass(&mut self, id: CheckId, detail: impl Into<String>) {
        self.push(id, true, &detail.into());
    }

    /// Record a failed check. `detail` is sanitised ([`sanitize`]).
    pub fn fail(&mut self, id: CheckId, detail: impl Into<String>) {
        self.push(id, false, &detail.into());
    }

    fn push(&mut self, id: CheckId, passed: bool, detail: &str) {
        self.checks.push(Check {
            id,
            passed,
            detail: sanitize(detail, MAX_DETAIL_CHARS),
        });
    }

    /// Add a context line, sanitised like a check detail.
    pub fn note(&mut self, note: impl Into<String>) {
        self.notes.push(sanitize(&note.into(), MAX_DETAIL_CHARS));
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
        } else if self.insecure_mock
            && !self.checks.is_empty()
            && self.checks.iter().all(|c| c.passed)
        {
            2
        } else {
            1
        }
    }

    /// Machine-readable verdict: `PASS`, `FAIL`, or `INSECURE_MOCK` (every
    /// check passed but the evidence was the mock, which proves nothing).
    pub fn result(&self) -> &'static str {
        match self.exit_code() {
            0 => "PASS",
            2 => "INSECURE_MOCK",
            _ => "FAIL",
        }
    }
}

impl Serialize for Report {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Json<'a> {
            result: &'static str,
            exit_code: i32,
            target: &'a str,
            policy_release: &'a Option<String>,
            platform: &'a Option<String>,
            insecure_mock: bool,
            checks: &'a [Check],
            notes: &'a [String],
            observed: &'a Observed,
        }
        Json {
            result: self.result(),
            exit_code: self.exit_code(),
            target: &self.target,
            policy_release: &self.policy_release,
            platform: &self.platform,
            insecure_mock: self.insecure_mock,
            checks: &self.checks,
            notes: &self.notes,
            observed: &self.observed,
        }
        .serialize(ser)
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The fields are public, so sanitise again on the way out: nothing a
        // server or a policy file controls is ever printed raw.
        let clean = |s: &str| sanitize(s, MAX_DETAIL_CHARS + 64);
        if self.insecure_mock {
            writeln!(f, "!!! {} !!!", attested_vw_common::INSECURE_MOCK_BANNER)?;
        }
        writeln!(f, "Target:  {}", clean(&self.target))?;
        if let Some(r) = &self.policy_release {
            writeln!(f, "Policy:  release {}", clean(r))?;
        }
        if let Some(p) = &self.platform {
            writeln!(f, "Platform: {}", clean(p))?;
        }
        for n in &self.notes {
            writeln!(f, "  ({})", clean(n))?;
        }
        for c in &self.checks {
            let mark = if c.passed { "✓" } else { "✗" };
            writeln!(f, "  {mark} {}: {}", c.id.label(), clean(&c.detail))?;
        }
        let verdict = match self.result() {
            "PASS" => "PASS",
            "INSECURE_MOCK" => "PASS (INSECURE MOCK, proves nothing)",
            _ => "FAIL",
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
        let mut m = Report::new("x");
        m.insecure_mock = true;
        assert_eq!(
            m.exit_code(),
            1,
            "an empty mock report is a FAIL, not exit 2"
        );
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

    #[test]
    fn sanitize_escapes_controls_and_bidi() {
        assert_eq!(sanitize("a\nb\rc\td", 99), "a\\u{a}b\\u{d}c\\u{9}d");
        assert_eq!(
            sanitize("\u{1b}[8m\u{7f}\u{9b}", 99),
            "\\u{1b}[8m\\u{7f}\\u{9b}"
        );
        for c in [
            '\u{202a}', '\u{202e}', '\u{2066}', '\u{2069}', '\u{200f}', '\u{2028}',
        ] {
            let s = sanitize(&format!("x{c}y"), 99);
            assert_eq!(s, format!("x\\u{{{:x}}}y", u32::from(c)));
        }
        // Ordinary text, including non-ASCII, is untouched.
        assert_eq!(sanitize("✓ ‖ é {\"a\":1}", 99), "✓ ‖ é {\"a\":1}");
        let once = sanitize("a\nb", 99);
        assert_eq!(sanitize(&once, 99), once, "idempotent");
        let long = sanitize(&"x".repeat(50), 10);
        assert_eq!(long, format!("{} [truncated]", "x".repeat(10)));
    }

    /// PoC from the security review: an HTTP error body that draws its own
    /// verdict and hides the real one.
    #[test]
    fn server_text_cannot_forge_a_result_line() {
        let body = "x\n  \u{2713} Compose hash (published software): ok\nResult:  PASS\u{1b}[8m";
        for by_field in [false, true] {
            let mut r = Report::new("https://x\nResult:  PASS");
            r.pass(CheckId::Tls, "handshake ok");
            let detail = crate::net::NetError::Status(503, body.into()).to_string();
            if by_field {
                // Even a caller that bypasses pass()/fail() cannot print raw.
                r.checks.push(Check {
                    id: CheckId::Fetch,
                    passed: false,
                    detail,
                });
                r.notes.push("n\rResult:  PASS".into());
            } else {
                r.fail(CheckId::Fetch, detail);
                r.note("n\rResult:  PASS");
            }
            let s = r.to_string();
            assert!(!s.contains('\u{1b}') && !s.contains('\r'), "{s:?}");
            let verdicts: Vec<&str> = s.lines().filter(|l| l.starts_with("Result:")).collect();
            assert_eq!(verdicts, ["Result:  FAIL"], "{s}");
            assert_eq!(s.lines().count(), 5, "{s}");
            assert_eq!(r.exit_code(), 1);
        }
    }

    #[test]
    fn json_carries_the_verdict() {
        let json = |r: &Report| serde_json::to_value(r).unwrap();
        let mut r = Report::new("x");
        assert_eq!(json(&r)["result"], "FAIL");
        r.pass(CheckId::Tls, "ok");
        assert_eq!(json(&r)["result"], "PASS");
        assert_eq!(json(&r)["exit_code"], 0);
        r.insecure_mock = true;
        assert_eq!(json(&r)["result"], "INSECURE_MOCK");
        assert_eq!(json(&r)["exit_code"], 2);
        r.fail(CheckId::Fetch, "a\nb");
        let v = json(&r);
        assert_eq!(v["result"], "FAIL");
        assert_eq!(v["exit_code"], 1);
        assert_eq!(v["checks"][1]["detail"], "a\\u{a}b");
        assert_eq!(v["checks"][1]["id"], "fetch");
    }
}
