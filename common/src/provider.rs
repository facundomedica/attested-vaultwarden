//! Platform abstraction for obtaining evidence inside the TEE.
//!
//! Implementations live in the sidecar crate (`Dstack`, `ConfigfsTsm`,
//! `Mock`) so that this crate stays free of platform I/O.

use std::future::Future;

use crate::report_data::ReportData;
use crate::schema::{Evidence, Platform};

/// Error returned by a quote provider. Kept opaque on purpose: the sidecar
/// logs the detail and returns a generic error to clients.
#[derive(Debug, thiserror::Error)]
#[error("{context}: {source}")]
pub struct ProviderError {
    pub context: &'static str,
    #[source]
    pub source: Box<dyn std::error::Error + Send + Sync>,
}

impl ProviderError {
    pub fn new(
        context: &'static str,
        source: impl Into<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self {
            context,
            source: source.into(),
        }
    }
}

/// Produces hardware evidence over caller-supplied `report_data`.
pub trait QuoteProvider: Send + Sync + 'static {
    /// Which platform this provider produces evidence for.
    fn platform(&self) -> Platform;

    /// Obtain evidence whose signed `report_data` field equals `report_data`
    /// byte for byte. Implementations must not hash, truncate or prefix it.
    fn get_evidence(
        &self,
        report_data: &ReportData,
    ) -> impl Future<Output = Result<Evidence, ProviderError>> + Send;
}
