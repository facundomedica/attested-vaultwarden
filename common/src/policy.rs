//! Release policy format (`policy/<release>.toml`).
//!
//! A policy describes exactly one published release: which platform it runs
//! on, the expected measurements, the hash of the measured compose document
//! and the allowlist of container images. The verifier accepts a deployment
//! only if every check against the policy passes.
//!
//! Example (values are placeholders):
//!
//! ```toml
//! schema = 1
//! release = "2026.11.0"
//! date = "2026-11-26"
//! platform = "tdx"
//!
//! [tdx]
//! mrtd   = "<96 hex>"
//! rtmr0  = "<96 hex>"
//! rtmr1  = "<96 hex>"
//! rtmr2  = "<96 hex>"
//! compose_hash = "<64 hex>"
//! accepted_tcb_status = ["UpToDate"]
//!
//! [[images]]
//! service = "vaultwarden"
//! image = "docker.io/vaultwarden/server@sha256:<64 hex>"
//! ```

use serde::{Deserialize, Serialize};

use crate::schema::Platform;

pub const POLICY_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("policy is not valid TOML: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("unsupported policy schema {0} (expected {POLICY_SCHEMA_VERSION})")]
    Schema(u32),
    #[error("policy field `{field}` is invalid: {reason}")]
    Invalid { field: String, reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub schema: u32,
    /// Release identifier; matches the signed git tag.
    pub release: String,
    /// Release date (YYYY-MM-DD).
    pub date: String,
    pub platform: Platform,
    #[serde(default)]
    pub tdx: Option<TdxPolicy>,
    #[serde(default)]
    pub sev_snp: Option<SevSnpPolicy>,
    /// INSECURE local mock. Only the compose hash is checked, and nothing
    /// measured it: it exercises the pipeline, it proves nothing.
    #[serde(default)]
    pub mock: Option<MockPolicy>,
    /// Allowlisted images. Every image in the measured compose must appear
    /// here, pinned by `@sha256:` digest.
    #[serde(default)]
    pub images: Vec<ImagePolicy>,
    /// Accept a non-empty `pre_launch_script` / `init_script` in the
    /// app-compose. Default false: scripts can run code and pull images that
    /// the image allowlist never sees.
    #[serde(default)]
    pub allow_pre_launch_script: bool,
    /// Accept a non-empty `allowed_envs` and `$VAR` interpolation in the
    /// compose. Default false: injected env values are not measured.
    #[serde(default)]
    pub allow_env_injection: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TdxPolicy {
    /// Expected MRTD (48 bytes, hex).
    pub mrtd: String,
    pub rtmr0: String,
    pub rtmr1: String,
    pub rtmr2: String,
    /// Expected dstack `compose-hash` (SHA-256 of the measured app compose
    /// document, hex).
    pub compose_hash: String,
    /// TCB statuses accepted from quote verification. Default: `UpToDate`.
    /// Names as in Intel's TCB info (`UpToDate`, `SWHardeningNeeded`, ...).
    #[serde(default = "default_tcb")]
    pub accepted_tcb_status: Vec<String>,
    /// Accept platforms whose PCK certificate says SMT is enabled.
    /// Default false (dcap-qvl's strict default).
    #[serde(default)]
    pub allow_smt: bool,
    /// Accept PCK `dynamicPlatform = true` (CPU packages can be added or
    /// replaced). Default false.
    #[serde(default)]
    pub allow_dynamic_platform: bool,
    /// Accept PCK `cachedKeys = true` (platform root keys cached by Intel's
    /// registration service). Default false.
    #[serde(default)]
    pub allow_cached_keys: bool,
    /// If set, the RTMR3 `app-id` event payload (hex) must equal this.
    #[serde(default)]
    pub app_id: Option<String>,
    /// If set, the RTMR3 `key-provider` event payload (UTF-8 JSON as emitted
    /// by dstack, e.g. `{"name":"kms","id":"..."}`) must equal this exactly.
    #[serde(default)]
    pub key_provider: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SevSnpPolicy {
    /// Expected launch measurement (48 bytes, hex), as computed by
    /// `sev-snp-measure` for the published OVMF + UKI.
    pub measurement: String,
    /// Minimum acceptable reported TCB components.
    pub min_tcb: SnpMinTcb,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MockPolicy {
    /// SHA-256 of the app-compose document the local sidecar serves.
    pub compose_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnpMinTcb {
    pub bootloader: u8,
    pub tee: u8,
    pub snp: u8,
    pub microcode: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImagePolicy {
    pub service: String,
    /// Full reference pinned by digest.
    pub image: String,
}

fn default_tcb() -> Vec<String> {
    vec!["UpToDate".to_owned()]
}

fn check_hex(field: &str, value: &str, bytes: usize) -> Result<(), PolicyError> {
    let ok = value.len() == bytes * 2 && value.bytes().all(|b| b.is_ascii_hexdigit());
    if ok {
        Ok(())
    } else {
        Err(PolicyError::Invalid {
            field: field.to_owned(),
            reason: format!("expected {} hex characters", bytes * 2),
        })
    }
}

/// Returns true if `image` is pinned by a well-formed sha256 digest.
pub fn is_digest_pinned(image: &str) -> bool {
    match image.rsplit_once("@sha256:") {
        Some((name, digest)) => {
            // Reference name: registry/repo[:tag], conservative charset (no
            // `$`, braces or whitespace, so no compose interpolation).
            !name.is_empty()
                && name.bytes().all(|b| {
                    b.is_ascii_lowercase()
                        || b.is_ascii_digit()
                        || matches!(b, b'.' | b'/' | b':' | b'-' | b'_')
                })
                && digest.len() == 64
                && digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }
        None => false,
    }
}

impl Policy {
    /// Parse and validate a policy file. Fails closed on any structural
    /// problem so the verifier never runs against a half-specified policy.
    pub fn from_toml(s: &str) -> Result<Self, PolicyError> {
        let p: Policy = toml::from_str(s)?;
        p.validate()?;
        Ok(p)
    }

    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.schema != POLICY_SCHEMA_VERSION {
            return Err(PolicyError::Schema(self.schema));
        }
        let invalid = |field: &str, reason: &str| PolicyError::Invalid {
            field: field.to_owned(),
            reason: reason.to_owned(),
        };
        match self.platform {
            Platform::Tdx => {
                let t = self
                    .tdx
                    .as_ref()
                    .ok_or_else(|| invalid("tdx", "required when platform = \"tdx\""))?;
                check_hex("tdx.mrtd", &t.mrtd, 48)?;
                check_hex("tdx.rtmr0", &t.rtmr0, 48)?;
                check_hex("tdx.rtmr1", &t.rtmr1, 48)?;
                check_hex("tdx.rtmr2", &t.rtmr2, 48)?;
                check_hex("tdx.compose_hash", &t.compose_hash, 32)?;
                if t.accepted_tcb_status.is_empty() {
                    return Err(invalid("tdx.accepted_tcb_status", "must not be empty"));
                }
                if let Some(a) = &t.app_id {
                    check_hex("tdx.app_id", a, 20)?;
                }
            }
            Platform::SevSnp => {
                let s = self
                    .sev_snp
                    .as_ref()
                    .ok_or_else(|| invalid("sev_snp", "required when platform = \"sev-snp\""))?;
                check_hex("sev_snp.measurement", &s.measurement, 48)?;
            }
            Platform::Mock => {
                let m = self
                    .mock
                    .as_ref()
                    .ok_or_else(|| invalid("mock", "required when platform = \"mock\""))?;
                check_hex("mock.compose_hash", &m.compose_hash, 32)?;
            }
        }
        if self.images.is_empty() {
            return Err(invalid("images", "at least one image must be allowlisted"));
        }
        for (i, img) in self.images.iter().enumerate() {
            if !is_digest_pinned(&img.image) {
                return Err(invalid(
                    &format!("images[{i}].image"),
                    "must be pinned by @sha256:<64 lowercase hex>",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn digest_pinning() {
        assert!(is_digest_pinned(&format!("vaultwarden/server@sha256:{D}")));
        assert!(!is_digest_pinned("vaultwarden/server:latest"));
        assert!(!is_digest_pinned(&format!(
            "vaultwarden/server:1.0@sha256:{}",
            &D[1..]
        )));
        assert!(!is_digest_pinned(&format!("@sha256:{D}")));
        assert!(!is_digest_pinned(&format!(
            "x@sha256:{}",
            D.to_uppercase().replace('0', "A")
        )));
    }

    #[test]
    fn tdx_policy_requires_tdx_section() {
        let s = format!(
            "schema = 1\nrelease = \"r\"\ndate = \"2026-11-26\"\nplatform = \"tdx\"\n\
             [[images]]\nservice = \"vw\"\nimage = \"a@sha256:{D}\"\n"
        );
        assert!(matches!(
            Policy::from_toml(&s),
            Err(PolicyError::Invalid { field, .. }) if field == "tdx"
        ));
    }

    #[test]
    fn unpinned_image_rejected() {
        let s = format!(
            "schema = 1\nrelease = \"r\"\ndate = \"d\"\nplatform = \"mock\"\n\
             [mock]\ncompose_hash = \"{D}\"\n\
             [[images]]\nservice = \"vw\"\nimage = \"vaultwarden/server:latest\"\n"
        );
        assert!(matches!(
            Policy::from_toml(&s),
            Err(PolicyError::Invalid { field, .. }) if field == "images[0].image"
        ));
        let ok = s.replace(
            "vaultwarden/server:latest",
            &format!("vaultwarden/server@sha256:{D}"),
        );
        assert!(Policy::from_toml(&ok).is_ok());
    }

    #[test]
    fn unknown_keys_rejected() {
        let s = format!(
            "schema = 1\nrelease = \"r\"\ndate = \"d\"\nplatform = \"mock\"\nskip_checks = true\n\
             [[images]]\nservice = \"vw\"\nimage = \"a@sha256:{D}\"\n"
        );
        assert!(Policy::from_toml(&s).is_err());
    }
}
