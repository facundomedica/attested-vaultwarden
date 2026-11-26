//! Platform evidence verification. Each platform returns the hardware-signed
//! `report_data` (and, from M2, the measurements) only after the evidence
//! signature chain checks out.

use attested_vw_common::report_data::ReportData;
use attested_vw_common::schema::{Evidence, MOCK_MAGIC, Platform};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EvidenceError {
    #[error("evidence is not valid base64")]
    Base64,
    #[error("mock evidence is malformed")]
    MockMalformed,
    #[error(
        "platform is the INSECURE mock; refused (use --allow-insecure-mock for local development only)"
    )]
    MockRefused,
    #[error("{0} evidence verification is not implemented yet (M2); refusing")]
    Unimplemented(&'static str),
}

/// What verified evidence tells us.
#[derive(Debug)]
pub struct Verified {
    /// `report_data` as signed by the platform.
    pub report_data: ReportData,
    /// Human-readable summary for the report.
    pub summary: String,
}

pub fn verify(
    platform: Platform,
    ev: &Evidence,
    allow_insecure_mock: bool,
) -> Result<Verified, EvidenceError> {
    match platform {
        Platform::Mock => {
            if !allow_insecure_mock {
                return Err(EvidenceError::MockRefused);
            }
            let blob = B64.decode(&ev.quote).map_err(|_| EvidenceError::Base64)?;
            let rd = blob
                .strip_prefix(MOCK_MAGIC)
                .and_then(|r| <[u8; 64]>::try_from(r).ok())
                .ok_or(EvidenceError::MockMalformed)?;
            Ok(Verified {
                report_data: ReportData(rd),
                summary: "INSECURE MOCK: no hardware signature exists; anyone can forge this"
                    .into(),
            })
        }
        Platform::Tdx => Err(EvidenceError::Unimplemented("TDX")),
        Platform::SevSnp => Err(EvidenceError::Unimplemented("SEV-SNP")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_ev(rd: &[u8]) -> Evidence {
        let mut b = MOCK_MAGIC.to_vec();
        b.extend_from_slice(rd);
        Evidence {
            quote: B64.encode(b),
            event_log: None,
            aux: None,
        }
    }

    #[test]
    fn mock_refused_by_default() {
        assert_eq!(
            verify(Platform::Mock, &mock_ev(&[0; 64]), false).err(),
            Some(EvidenceError::MockRefused)
        );
    }

    #[test]
    fn mock_parsed_when_allowed() {
        let v = verify(Platform::Mock, &mock_ev(&[7; 64]), true).unwrap();
        assert_eq!(v.report_data.0, [7; 64]);
    }

    #[test]
    fn mock_malformed() {
        assert_eq!(
            verify(Platform::Mock, &mock_ev(&[7; 63]), true).err(),
            Some(EvidenceError::MockMalformed)
        );
    }
}
