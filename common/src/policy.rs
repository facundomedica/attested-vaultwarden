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
//! app_id = "<40 hex>"                              # required
//! key_provider = '{"name":"kms","id":"<hex>"}'     # required
//! accepted_tcb_status = ["UpToDate"]               # exact set
//! min_tcb_eval_data_number = 20
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
    /// SHA-256 (hex) of the only `pre_launch_script` accepted. Unset: the
    /// app-compose must have no pre-launch script. Scripts run code that the
    /// image allowlist never sees, so each one is pinned and reviewed.
    #[serde(default)]
    pub pre_launch_script_sha256: Option<String>,
    /// Exact set of encrypted env var NAMES the app-compose may allow
    /// (`allowed_envs`). Their values are not measured; list only values whose
    /// substitution cannot change what runs (e.g. a registry read token when
    /// every image is pinned by digest). Default: none.
    #[serde(default)]
    pub allowed_envs: Vec<String>,
    /// Pin of the app-compose `public_logs` flag (does the guest agent serve
    /// container logs to the outside?). If set, the measured document must
    /// have exactly this value (absent counts as false). If unset the flag
    /// is NOT enforced beyond the compose hash; the verifier then prints the
    /// observed value as a note. New policies should always set it.
    #[serde(default)]
    pub public_logs: Option<bool>,
    /// Host bind mounts the compose may contain, each exactly
    /// `"<service>:<source>:<target>[:<mode>]"` as written in the compose.
    /// `attest:/var/run/dstack.sock:/var/run/dstack.sock` is always allowed;
    /// every other host path is refused unless listed here. Default: none.
    #[serde(default)]
    pub allowed_bind_mounts: Vec<String>,
    /// Services that may set `entrypoint`, `command` or `healthcheck` (they
    /// run something other than what the image's own metadata says).
    /// Default: none.
    #[serde(default)]
    pub command_override_services: Vec<String>,
}

/// `tcbEvaluationDataNumber` of Intel's TDX TCB info when this verifier was
/// released (Intel PCS, standard set, 2026-11-26). The floor used when a
/// policy does not set `tdx.min_tcb_eval_data_number`. Without a floor,
/// whoever serves the collateral could replay an older, still-unexpired,
/// Intel-signed TCB info in which a since-patched platform is `UpToDate`.
pub const DEFAULT_MIN_TCB_EVAL_DATA_NUMBER: u32 = 20;

fn default_min_tcb_eval() -> u32 {
    DEFAULT_MIN_TCB_EVAL_DATA_NUMBER
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
    /// The EXACT set of TCB statuses accepted from quote verification
    /// (nothing is implied: a list without `UpToDate` rejects an up-to-date
    /// platform). Default: `["UpToDate"]`. Names as in Intel's TCB info
    /// (`UpToDate`, `SWHardeningNeeded`, ...). `Revoked` is never accepted
    /// and is an invalid entry.
    #[serde(default = "default_tcb")]
    pub accepted_tcb_status: Vec<String>,
    /// Lowest acceptable `tcbEvaluationDataNumber` of the collateral (the
    /// lower of TCB info and QE identity). Intel raises the number with
    /// every TCB recovery; pinning it stops a collateral source from rolling
    /// the TCB verdict back to an older Intel-signed data set. Default:
    /// [`DEFAULT_MIN_TCB_EVAL_DATA_NUMBER`]; a release should set the value
    /// observed when it was drafted.
    #[serde(default = "default_min_tcb_eval")]
    pub min_tcb_eval_data_number: u32,
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
    /// REQUIRED. The RTMR3 `app-id` event payload (40 hex) must equal this.
    /// Without it, any app of the same KMS running the same compose passes.
    /// (An `Option` only so that a policy without it gets a clear error from
    /// [`Policy::validate`]; the verifier also fails closed on `None`.)
    #[serde(default)]
    pub app_id: Option<String>,
    /// REQUIRED. The RTMR3 `key-provider` event payload (UTF-8 JSON as
    /// emitted by dstack, e.g. `{"name":"kms","id":"..."}`) must equal this
    /// exactly. The key provider decides who else can get the disk key.
    #[serde(default)]
    pub key_provider: Option<String>,
    /// Expected MRCONFIGID (96 hex). Unset: must be all-zero, or one of the
    /// values dstack derives from the already-pinned compose hash, app id and
    /// key provider (see `tdx::check_launch_fields`).
    #[serde(default)]
    pub mr_config_id: Option<String>,
    /// Expected MROWNER (96 hex). Unset: must be all-zero.
    #[serde(default)]
    pub mr_owner: Option<String>,
    /// Expected MROWNERCONFIG (96 hex). Unset: must be all-zero.
    #[serde(default)]
    pub mr_owner_config: Option<String>,
    /// Require the RTMR3 `storage-encrypted` event with payload `1` (dstack
    /// OS 0.6.5+ emits it when the data disk is LUKS-encrypted). Default
    /// true; set false only for OS images that predate the event. A payload
    /// of `0` always fails, whatever this says.
    #[serde(default = "default_true")]
    pub require_storage_encrypted: bool,
}

fn default_true() -> bool {
    true
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

/// TCB statuses a policy may list. `Revoked` is deliberately missing.
pub const TCB_STATUS_NAMES: &[&str] = &[
    "UpToDate",
    "SWHardeningNeeded",
    "ConfigurationNeeded",
    "ConfigurationAndSWHardeningNeeded",
    "OutOfDate",
    "OutOfDateConfigurationNeeded",
    "TDRelaunchAdvised",
    "TDRelaunchAdvisedConfigurationNeeded",
];

/// The `id` (lowercase hex, possibly empty) of a dstack `key-provider`
/// payload, which must be a JSON object with exactly the string fields
/// `name` and `id`.
pub fn key_provider_id(payload: &str) -> Result<String, String> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Kp {
        #[allow(dead_code)]
        name: String,
        id: String,
    }
    let kp: Kp = serde_json::from_str(payload)
        .map_err(|_| "not a JSON object with exactly the strings `name` and `id`".to_owned())?;
    if !kp.id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("`id` is not hex".into());
    }
    Ok(kp.id.to_ascii_lowercase())
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
                for s in &t.accepted_tcb_status {
                    if !TCB_STATUS_NAMES.contains(&s.as_str()) {
                        return Err(invalid(
                            "tdx.accepted_tcb_status",
                            &format!("`{s}` is not one of {TCB_STATUS_NAMES:?}"),
                        ));
                    }
                }
                let app_id = t.app_id.as_ref().ok_or_else(|| {
                    invalid(
                        "tdx.app_id",
                        "required (40 hex): without it any app of the same key provider \
                         running the same compose would pass. Policies written before this \
                         field became mandatory (2026.11.0, 2026.11.1) are no longer accepted",
                    )
                })?;
                check_hex("tdx.app_id", app_id, 20)?;
                let kp = t.key_provider.as_ref().ok_or_else(|| {
                    invalid(
                        "tdx.key_provider",
                        "required: the exact RTMR3 key-provider payload, e.g. \
                         {\"name\":\"kms\",\"id\":\"<hex>\"}",
                    )
                })?;
                key_provider_id(kp).map_err(|e| invalid("tdx.key_provider", &e))?;
                for (field, v) in [
                    ("tdx.mr_config_id", &t.mr_config_id),
                    ("tdx.mr_owner", &t.mr_owner),
                    ("tdx.mr_owner_config", &t.mr_owner_config),
                ] {
                    if let Some(v) = v {
                        check_hex(field, v, 48)?;
                    }
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
        if let Some(h) = &self.pre_launch_script_sha256 {
            check_hex("pre_launch_script_sha256", h, 32)?;
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

    fn tdx_policy() -> String {
        let z48 = "00".repeat(48);
        format!(
            "schema = 1\nrelease = \"r\"\ndate = \"d\"\nplatform = \"tdx\"\n\
             [tdx]\nmrtd = \"{z48}\"\nrtmr0 = \"{z48}\"\nrtmr1 = \"{z48}\"\nrtmr2 = \"{z48}\"\n\
             compose_hash = \"{D}\"\napp_id = \"{}\"\n\
             key_provider = '{{\"name\":\"kms\",\"id\":\"30ab\"}}'\n\
             [[images]]\nservice = \"vw\"\nimage = \"a@sha256:{D}\"\n",
            "00".repeat(20)
        )
    }

    fn invalid_field(s: &str) -> String {
        match Policy::from_toml(s) {
            Err(PolicyError::Invalid { field, .. }) => field,
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    /// Review PoC: a TDX policy without `app_id` / `key_provider` used to be
    /// valid, and the verifier then skipped both checks.
    #[test]
    fn tdx_pins_are_mandatory() {
        let s = tdx_policy();
        assert!(Policy::from_toml(&s).is_ok());
        let no_app = s.replace(&format!("app_id = \"{}\"\n", "00".repeat(20)), "");
        assert_eq!(invalid_field(&no_app), "tdx.app_id");
        let no_kp: String = s
            .lines()
            .filter(|l| !l.starts_with("key_provider"))
            .map(|l| format!("{l}\n"))
            .collect();
        assert_eq!(invalid_field(&no_kp), "tdx.key_provider");
        let bad_kp = s.replace("'{\"name\":\"kms\",\"id\":\"30ab\"}'", "'kms'");
        assert_eq!(invalid_field(&bad_kp), "tdx.key_provider");
    }

    #[test]
    fn tcb_policy_fields() {
        let s = tdx_policy();
        let t = Policy::from_toml(&s).unwrap().tdx.unwrap();
        assert_eq!(t.accepted_tcb_status, ["UpToDate"]);
        assert_eq!(t.min_tcb_eval_data_number, DEFAULT_MIN_TCB_EVAL_DATA_NUMBER);
        let with = |extra: &str| s.replace("[tdx]\n", &format!("[tdx]\n{extra}\n"));
        let t = Policy::from_toml(&with("min_tcb_eval_data_number = 23"))
            .unwrap()
            .tdx
            .unwrap();
        assert_eq!(t.min_tcb_eval_data_number, 23);
        for bad in ["[\"Revoked\"]", "[\"uptodate\"]", "[]"] {
            let p = with(&format!("accepted_tcb_status = {bad}"));
            assert_eq!(invalid_field(&p), "tdx.accepted_tcb_status", "{bad}");
        }
        assert_eq!(
            invalid_field(&with("mr_config_id = \"00\"")),
            "tdx.mr_config_id"
        );
    }

    /// The release policy that the live deployment is verified against must
    /// keep validating; the two older development policies predate the
    /// mandatory `app_id` and are rejected with a message that says so.
    #[test]
    fn published_policies() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../policy/");
        let read = |n: &str| std::fs::read_to_string(format!("{dir}{n}")).unwrap();
        let p = Policy::from_toml(&read("2026.11.2-phala-dev.toml")).unwrap();
        assert!(p.tdx.unwrap().app_id.is_some());
        for old in ["2026.11.0-phala-dev.toml", "2026.11.1-phala-dev.toml"] {
            let e = Policy::from_toml(&read(old)).unwrap_err().to_string();
            assert!(e.contains("tdx.app_id") && e.contains("required"), "{e}");
        }
    }

    #[test]
    fn storage_encryption_required_by_default() {
        let s = tdx_policy();
        let p = Policy::from_toml(&s).expect("valid");
        assert!(p.tdx.as_ref().is_some_and(|t| t.require_storage_encrypted));
        let off = s.replace("[tdx]\n", "[tdx]\nrequire_storage_encrypted = false\n");
        let p = Policy::from_toml(&off).expect("valid");
        assert!(p.tdx.as_ref().is_some_and(|t| !t.require_storage_encrypted));
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
