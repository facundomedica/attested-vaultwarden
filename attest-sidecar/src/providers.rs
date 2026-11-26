//! `QuoteProvider` implementations.
//!
//! * [`Mock`]: INSECURE, software only, for local development.
//! * `Dstack`: dstack guest agent over `/var/run/dstack.sock` (M3).
//! * `ConfigfsTsm`: Linux configfs-tsm, for plain SEV-SNP VMs (stretch).

use attested_vw_common::INSECURE_MOCK_BANNER;
use attested_vw_common::provider::{ProviderError, QuoteProvider};
use attested_vw_common::report_data::ReportData;
use attested_vw_common::schema::{Evidence, Platform};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

/// Magic prefix of mock evidence. The verifier recognises it and refuses it
/// unless explicitly told to accept insecure mock evidence.
pub const MOCK_MAGIC: &[u8] = b"ATTESTED-VW-INSECURE-MOCK-v1";

/// INSECURE software provider. Its "evidence" is the magic prefix followed by
/// `report_data`; anyone can forge it. It exists only so the whole pipeline
/// can be exercised without TEE hardware.
#[derive(Debug, Default)]
pub struct Mock;

impl Mock {
    pub fn new() -> Self {
        eprintln!("WARNING: {INSECURE_MOCK_BANNER}");
        Self
    }
}

impl QuoteProvider for Mock {
    fn platform(&self) -> Platform {
        Platform::Mock
    }

    async fn get_evidence(&self, report_data: &ReportData) -> Result<Evidence, ProviderError> {
        let mut blob = Vec::with_capacity(MOCK_MAGIC.len() + ReportData::LEN);
        blob.extend_from_slice(MOCK_MAGIC);
        blob.extend_from_slice(report_data.as_bytes());
        Ok(Evidence {
            quote: B64.encode(blob),
            event_log: None,
            aux: None,
        })
    }
}
