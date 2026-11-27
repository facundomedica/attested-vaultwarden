//! Google Cloud Confidential Space (`platform = "gcp-cs"`): shared constants,
//! the `eat_nonce` encoding of `report_data`, and the `[gcp_cs]` policy
//! section. See `docs/GCP_CONFIDENTIAL_SPACE.md`.
//!
//! On this platform the evidence is not a raw hardware quote. The workload
//! asks the Confidential Space launcher for a Google Cloud Attestation OIDC
//! token (a JWT signed by Google) with *custom nonces*, and the verifier
//! checks Google's signature and the claims. The per-connection binding is
//! the same 64-byte value as on TDX:
//!
//! ```text
//! report_data = SHA-512("attested-vaultwarden/v1" || nonce || spki_sha256)
//! eat_nonce   = [ hex(report_data[0..32]), hex(report_data[32..64]) ]
//! ```
//!
//! Two nonces because Google accepts at most six nonces of 10 to 74 bytes
//! each, and 128 hex characters do not fit in one. Order is significant.

use serde::{Deserialize, Serialize};

use crate::policy::{ImagePolicy, PolicyError};
use crate::report_data::ReportData;

/// `iss` of Google Cloud Attestation tokens. The verifier pins it.
pub const ISSUER: &str = "https://confidentialcomputing.googleapis.com";

/// JWKS with Google Cloud Attestation's OIDC signing keys: the `jwks_uri` of
/// `https://confidentialcomputing.googleapis.com/.well-known/openid-configuration`
/// (read 2026-11-27). Pinned rather than discovered, so a tampered discovery
/// document cannot redirect the verifier to other keys.
pub const JWKS_URL: &str = "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com";

/// `aud` requested by the sidecar and required by the verifier. It is
/// deliberately not `https://sts.googleapis.com`: a token served to anyone
/// who asks must never be exchangeable at Google's Security Token Service
/// for access to resources (e.g. a KMS key gated on this workload).
pub const AUDIENCE: &str = "https://attested-vaultwarden.invalid/v1/tee-attestation";

/// Unix socket of the Confidential Space launcher's token server, as mounted
/// into the workload container.
pub const DEFAULT_SOCKET: &str = "/run/container_launcher/teeserver.sock";

/// Token endpoint on [`DEFAULT_SOCKET`] (`POST`, JSON body).
pub const TOKEN_PATH: &str = "/v1/token";

/// `dbgstat` of a production (non-debug) Confidential Space image.
pub const DBGSTAT_PRODUCTION: &str = "disabled-since-boot";

/// `swname` of Confidential Space.
pub const SWNAME: &str = "CONFIDENTIAL_SPACE";

/// `oemid` of Google (IANA private enterprise number).
pub const OEMID_GOOGLE: u64 = 11129;

/// `hwmodel` values Google documents for Confidential Space.
pub const KNOWN_HWMODELS: &[&str] = &["GCP_INTEL_TDX", "GCP_AMD_SEV", "GCP_AMD_SEV_ES"];

/// Support attributes a production image can carry.
pub const KNOWN_SUPPORT_ATTRIBUTES: &[&str] = &["LATEST", "STABLE", "USABLE"];

/// The two `eat_nonce` values that carry `report_data`, in order.
pub fn eat_nonces(rd: &ReportData) -> [String; 2] {
    let (a, b) = rd.as_bytes().split_at(32);
    [hex::encode(a), hex::encode(b)]
}

/// Inverse of [`eat_nonces`]. Strict: exactly two values of 64 lowercase hex
/// characters each.
pub fn report_data_from_eat_nonces(nonces: &[String]) -> Option<ReportData> {
    let [a, b] = nonces else { return None };
    let strict = |s: &str| {
        s.len() == 64
            && s.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    };
    if !strict(a) || !strict(b) {
        return None;
    }
    let mut out = [0u8; 64];
    hex::decode_to_slice(a, &mut out[..32]).ok()?;
    hex::decode_to_slice(b, &mut out[32..]).ok()?;
    Some(ReportData(out))
}

/// `[gcp_cs]` policy section. The workload image itself is the single entry
/// of the policy's `[[images]]` list, pinned by digest.
///
/// ```toml
/// platform = "gcp-cs"
///
/// [gcp_cs]
/// hwmodel = ["GCP_INTEL_TDX"]
/// support_attribute = "STABLE"
/// restart_policy = "Always"
///
/// [[images]]
/// service = "workload"
/// image = "europe-docker.pkg.dev/<project>/<repo>/attested-vw-gcp-cs@sha256:<64 hex>"
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpCsPolicy {
    /// Accepted `hwmodel` claims. `GCP_INTEL_TDX` is the only one where
    /// Google's verifier checks a CPU-signed quote; with `GCP_AMD_SEV` the
    /// root of trust is the Google-operated vTPM alone.
    pub hwmodel: Vec<String>,
    /// Support attribute the Confidential Space image must carry: `LATEST`,
    /// `STABLE` or `USABLE`. Default `STABLE`.
    #[serde(default = "default_support")]
    pub support_attribute: String,
    /// Lowest accepted Confidential Space image version (`swversion`, e.g.
    /// `260900`). Unset: any version carrying `support_attribute`.
    #[serde(default)]
    pub min_swversion: Option<u64>,
    /// Required launcher restart policy: `Never`, `OnFailure` or `Always`.
    pub restart_policy: String,
    /// If non-empty, the TDX claim `gcp_attester_tcb_status` must be one of
    /// these (only meaningful for `GCP_INTEL_TDX`). Empty: reported only.
    #[serde(default)]
    pub accepted_tdx_tcb_status: Vec<String>,
    /// If set, `submods.gce.project_id` must equal this.
    #[serde(default)]
    pub project_id: Option<String>,
}

fn default_support() -> String {
    "STABLE".to_owned()
}

impl GcpCsPolicy {
    pub(crate) fn validate(&self, images: &[ImagePolicy]) -> Result<(), PolicyError> {
        let invalid = |field: &str, reason: &str| PolicyError::Invalid {
            field: field.to_owned(),
            reason: reason.to_owned(),
        };
        if self.hwmodel.is_empty() {
            return Err(invalid("gcp_cs.hwmodel", "must not be empty"));
        }
        if let Some(h) = self
            .hwmodel
            .iter()
            .find(|h| !KNOWN_HWMODELS.contains(&h.as_str()))
        {
            return Err(invalid("gcp_cs.hwmodel", &format!("unknown hwmodel `{h}`")));
        }
        if !KNOWN_SUPPORT_ATTRIBUTES.contains(&self.support_attribute.as_str()) {
            return Err(invalid(
                "gcp_cs.support_attribute",
                "must be LATEST, STABLE or USABLE",
            ));
        }
        if !["Never", "OnFailure", "Always"].contains(&self.restart_policy.as_str()) {
            return Err(invalid(
                "gcp_cs.restart_policy",
                "must be Never, OnFailure or Always",
            ));
        }
        if images.len() != 1 {
            return Err(invalid(
                "images",
                "gcp-cs runs exactly one workload image: list exactly one",
            ));
        }
        Ok(())
    }
}

/// The `sha256:<hex>` digest of a digest-pinned image reference.
pub fn image_digest(image: &str) -> Option<&str> {
    let (_, d) = image.rsplit_once('@')?;
    d.starts_with("sha256:").then_some(d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;
    use crate::report_data::{Nonce, SpkiSha256, compute};

    const D: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn nonces_roundtrip_and_fit_googles_limits() {
        let rd = compute(&Nonce([7; 32]), &SpkiSha256([9; 32]));
        let n = eat_nonces(&rd);
        for s in &n {
            // Documented limits disagree (10..=74 vs 8..=88); 64 fits both.
            assert_eq!(s.len(), 64);
        }
        assert_eq!(format!("{}{}", n[0], n[1]), rd.to_hex());
        assert_eq!(report_data_from_eat_nonces(&n), Some(rd));
    }

    #[test]
    fn nonce_decoding_is_strict() {
        let rd = ReportData([0xab; 64]);
        let [a, b] = eat_nonces(&rd);
        assert!(report_data_from_eat_nonces(std::slice::from_ref(&a)).is_none());
        assert!(report_data_from_eat_nonces(&[a.clone(), b.clone(), b.clone()]).is_none());
        assert!(report_data_from_eat_nonces(&[a.to_uppercase(), b.clone()]).is_none());
        assert!(report_data_from_eat_nonces(&[a[..62].to_owned(), b.clone()]).is_none());
        assert!(report_data_from_eat_nonces(&[format!("{}zz", &a[..62]), b]).is_none());
    }

    fn policy(extra: &str, images: &str) -> String {
        format!(
            "schema = 1\nrelease = \"r\"\ndate = \"d\"\nplatform = \"gcp-cs\"\n\
             [gcp_cs]\nhwmodel = [\"GCP_INTEL_TDX\"]\nrestart_policy = \"Always\"\n{extra}\
             {images}"
        )
    }

    fn one_image() -> String {
        format!("[[images]]\nservice = \"workload\"\nimage = \"r.example/p/w@sha256:{D}\"\n")
    }

    #[test]
    fn policy_parses_with_defaults() {
        let p = Policy::from_toml(&policy("", &one_image())).expect("valid");
        let g = p.gcp_cs.expect("section");
        assert_eq!(g.support_attribute, "STABLE");
        assert!(g.min_swversion.is_none());
        assert_eq!(
            image_digest(&p.images[0].image),
            Some(format!("sha256:{D}").as_str())
        );
    }

    #[test]
    fn policy_rejects_bad_values() {
        let two = format!("{}{}", one_image(), one_image());
        assert!(Policy::from_toml(&policy("", &two)).is_err());
        let exp = policy("support_attribute = \"EXPERIMENTAL\"\n", &one_image());
        assert!(Policy::from_toml(&exp).is_err());
        assert!(Policy::from_toml(&policy("allow_debug = true\n", &one_image())).is_err());
        let bad_hw = policy("", &one_image()).replace("GCP_INTEL_TDX", "GCP_SHIELDED_VM");
        assert!(Policy::from_toml(&bad_hw).is_err());
        let bad_rp = policy("", &one_image()).replace("Always", "always");
        assert!(Policy::from_toml(&bad_rp).is_err());
        let no_section = policy("", &one_image()).replace("[gcp_cs]", "[mock]");
        assert!(Policy::from_toml(&no_section).is_err());
    }
}
