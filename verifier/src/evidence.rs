//! Platform evidence verification dispatcher. Each platform returns the
//! hardware-signed `report_data` and measurements only after the evidence
//! signature chain and platform policy check out.

use attested_vw_common::policy::Policy;
use attested_vw_common::report_data::ReportData;
use attested_vw_common::schema::{Evidence, MOCK_MAGIC, Platform};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use dcap_qvl::QuoteCollateralV3;

use crate::{snp, tdx};

#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    #[error("evidence is not valid base64")]
    Base64,
    #[error("mock evidence is malformed")]
    MockMalformed,
    #[error(
        "platform is the INSECURE mock; refused (use --allow-insecure-mock for local development only)"
    )]
    MockRefused,
    #[error("policy has no `{0}` section")]
    PolicyMissing(&'static str),
    #[error("no Intel collateral available for this quote: {0}")]
    NoCollateral(String),
    #[error("no VCEK certificate available for this report: {0}")]
    NoVcek(String),
    #[error(transparent)]
    Tdx(#[from] tdx::TdxError),
    #[error(transparent)]
    Snp(#[from] snp::SnpError),
}

/// Inputs to evidence verification that do not come from the server.
#[derive(Debug, Clone)]
pub struct Context {
    pub allow_insecure_mock: bool,
    /// Verification time (unix seconds). Tests pin it; the CLI uses the clock.
    pub now_secs: u64,
    /// Intel collateral for the quote (fetched by the CLI, recorded in tests).
    pub tdx_collateral: Result<QuoteCollateralV3, String>,
    /// VCEK (DER) for the SNP report (from AMD KDS, or recorded in tests).
    pub snp_vcek_der: Result<Vec<u8>, String>,
}

impl Context {
    /// Context for the mock platform only.
    pub fn mock(allow_insecure_mock: bool) -> Self {
        Self {
            allow_insecure_mock,
            now_secs: 0,
            tdx_collateral: Err("not fetched".into()),
            snp_vcek_der: Err("not fetched".into()),
        }
    }
}

/// What verified evidence tells us.
#[derive(Debug)]
pub enum Measured {
    Mock,
    Tdx(Box<tdx::VerifiedQuote>),
    Snp(snp::VerifiedReport),
}

#[derive(Debug)]
pub struct Verified {
    /// `report_data` as signed by the platform.
    pub report_data: ReportData,
    /// Human-readable summary for the report.
    pub summary: String,
    pub measured: Measured,
}

pub fn decode_quote(ev: &Evidence) -> Result<Vec<u8>, EvidenceError> {
    B64.decode(&ev.quote).map_err(|_| EvidenceError::Base64)
}

/// VCEK from the SNP certificate table in `evidence.aux`, if present.
pub fn snp_aux_vcek(ev: &Evidence) -> Option<Vec<u8>> {
    let table = B64.decode(ev.aux.as_deref()?).ok()?;
    crate::snp_launch::vcek_from_cert_table(&table)
}

pub fn verify(
    platform: Platform,
    ev: &Evidence,
    policy: &Policy,
    ctx: &Context,
) -> Result<Verified, EvidenceError> {
    match platform {
        Platform::Mock => {
            if !ctx.allow_insecure_mock {
                return Err(EvidenceError::MockRefused);
            }
            let blob = decode_quote(ev)?;
            let rd = blob
                .strip_prefix(MOCK_MAGIC)
                .and_then(|r| <[u8; 64]>::try_from(r).ok())
                .ok_or(EvidenceError::MockMalformed)?;
            Ok(Verified {
                report_data: ReportData(rd),
                summary: "INSECURE MOCK: no hardware signature exists; anyone can forge this"
                    .into(),
                measured: Measured::Mock,
            })
        }
        Platform::Tdx => {
            let tp = policy
                .tdx
                .as_ref()
                .ok_or(EvidenceError::PolicyMissing("tdx"))?;
            let quote = decode_quote(ev)?;
            let coll = ctx
                .tdx_collateral
                .as_ref()
                .map_err(|e| EvidenceError::NoCollateral(e.clone()))?;
            let v = tdx::verify_quote(
                &quote,
                coll,
                ctx.now_secs,
                &tp.accepted_tcb_status,
                tdx::PlatformFlags::from_policy(tp),
            )?;
            let adv = if v.advisory_ids.is_empty() {
                String::new()
            } else {
                format!(", advisories: {}", v.advisory_ids.join(" "))
            };
            Ok(Verified {
                report_data: ReportData(v.report_data),
                summary: format!(
                    "Intel DCAP quote signature and collateral valid, TCB {}{adv}, TD debug off",
                    v.tcb_status
                ),
                measured: Measured::Tdx(Box::new(v)),
            })
        }
        Platform::SevSnp => {
            let sp = policy
                .sev_snp
                .as_ref()
                .ok_or(EvidenceError::PolicyMissing("sev_snp"))?;
            let report = decode_quote(ev)?;
            let vcek = ctx
                .snp_vcek_der
                .as_ref()
                .map_err(|e| EvidenceError::NoVcek(e.clone()))?;
            let now = i64::try_from(ctx.now_secs).unwrap_or(i64::MAX);
            let v = snp::verify_report(&report, vcek, now, sp)?;
            Ok(Verified {
                report_data: ReportData(v.report_data),
                summary: format!(
                    "AMD {} ARK→ASK→VCEK→report signatures valid, VCEK bound to TCB/chip, TCB {}, debug and migration off, VMPL {}",
                    v.product, v.reported_tcb, v.report.vmpl
                ),
                measured: Measured::Snp(v),
            })
        }
    }
}
