//! JSON document served at `GET /.well-known/tee-attestation?nonce=<64 hex>`.
//!
//! **Trust note.** Every field of this document is produced by the server
//! under test and is therefore *untrusted* until the verifier has checked it
//! against the hardware-signed evidence:
//!
//! * `nonce` and `spki_sha256` are only meaningful because they are hashed into
//!   `report_data`, which the TEE signs.
//! * `app_compose` is only meaningful because its hash is extended into a
//!   measurement register (RTMR3 on dstack) that the verifier replays.
//! * `image_digests` is informational. The verifier derives the image list
//!   from the measured `app_compose` document, never from this field.

use serde::{Deserialize, Serialize};

use crate::report_data::{Nonce, SpkiSha256};

/// Current schema version. Incremented on any breaking change.
pub const SCHEMA_VERSION: u32 = 1;

/// Maximum size the verifier will accept for an attestation document.
pub const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Platform {
    /// Intel TDX via dstack.
    Tdx,
    /// AMD SEV-SNP via Linux configfs-tsm.
    SevSnp,
    /// INSECURE software mock. Never accepted unless the verifier is
    /// explicitly told to allow it.
    Mock,
}

impl Platform {
    pub fn as_str(&self) -> &'static str {
        match self {
            Platform::Tdx => "tdx",
            Platform::SevSnp => "sev-snp",
            Platform::Mock => "mock",
        }
    }
}

/// Raw platform evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// Base64 (standard alphabet, padded) TDX quote, SEV-SNP attestation
    /// report, or mock blob.
    pub quote: String,
    /// dstack event log (JSON array as returned by the guest agent), used to
    /// replay RTMR3. Absent on platforms without one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_log: Option<String>,
    /// Base64 auxiliary blob (SEV-SNP: certificate table from configfs-tsm
    /// `auxblob`, if the host provides one). Absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aux: Option<String>,
}

/// An image reference as found in the compose file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageDigest {
    /// Compose service name.
    pub service: String,
    /// Full image reference, e.g. `docker.io/vaultwarden/server@sha256:...`.
    pub image: String,
}

/// The attestation document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationResponse {
    pub version: u32,
    pub platform: Platform,
    pub evidence: Evidence,
    pub nonce: Nonce,
    pub spki_sha256: SpkiSha256,
    pub report_data_construction: String,
    /// The exact document whose hash was measured (dstack: `app-compose.json`).
    pub app_compose: String,
    pub image_digests: Vec<ImageDigest>,
    /// RFC 3339 UTC time at which the sidecar produced the document.
    /// Informational only: freshness comes from the nonce.
    pub timestamp: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_serializes_as_spec() {
        let s = serde_json::to_string(&[Platform::Tdx, Platform::SevSnp, Platform::Mock])
            .unwrap_or_default();
        assert_eq!(s, r#"["tdx","sev-snp","mock"]"#);
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let doc = serde_json::json!({
            "version": 1, "platform": "mock",
            "evidence": {"quote": ""},
            "nonce": "00".repeat(32), "spki_sha256": "00".repeat(32),
            "report_data_construction": "", "app_compose": "",
            "image_digests": [], "timestamp": "1970-01-01T00:00:00Z",
            "verified": true
        });
        assert!(serde_json::from_value::<AttestationResponse>(doc).is_err());
    }
}
