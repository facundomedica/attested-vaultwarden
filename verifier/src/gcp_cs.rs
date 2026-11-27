//! Google Cloud Confidential Space evidence: a Google Cloud Attestation OIDC
//! token (JWT, RS256) requested by the workload with custom nonces.
//!
//! What this proves is weaker than the raw-quote platforms and different in
//! kind: the verifier does not see a hardware quote. It checks that *Google's
//! attestation service* signed a statement that a Confidential Space VM runs
//! a given container image. See `docs/GCP_CONFIDENTIAL_SPACE.md`, "Trust".
//!
//! Everything fails closed:
//!
//! * `alg` must be exactly `RS256`; the key is looked up by `kid` in a JWKS
//!   that the caller obtained from the pinned Google URL (or, in tests only,
//!   from a test key). The token never names its own key source.
//! * `iss`, `aud`, `exp`, `nbf`, `iat` are all required and checked.
//! * `eat_nonce` must be exactly the two values that encode `report_data`.

use attested_vw_common::gcp_cs::{
    self as common, AUDIENCE, DBGSTAT_PRODUCTION, ISSUER, OEMID_GOOGLE, SWNAME,
};
use attested_vw_common::policy::Policy;
use attested_vw_common::report_data::ReportData;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::sha2::Sha256;
use rsa::signature::Verifier as _;
use rsa::{BigUint, RsaPublicKey};
use serde::{Deserialize, Deserializer};

use crate::report::{CheckId, Report};

/// Largest token accepted (Google's are a few kB).
const MAX_TOKEN_BYTES: usize = 64 * 1024;
/// Tolerated clock difference between this machine and Google.
const LEEWAY_SECS: u64 = 60;
/// Smallest RSA modulus accepted for a signing key.
const MIN_RSA_BITS: usize = 2048;

#[derive(Debug, thiserror::Error)]
pub enum GcpError {
    #[error("attestation token is not a compact JWT ({0})")]
    Malformed(&'static str),
    #[error("attestation token is too large")]
    TooLarge,
    #[error("token header: alg is `{0}`, only RS256 is accepted")]
    Alg(String),
    #[error("signing key set is unusable: {0}")]
    Jwks(String),
    #[error("token is signed by key `{0}`, which is not in Google's key set")]
    UnknownKey(String),
    #[error("token signature is invalid")]
    Signature,
    #[error("token claims are invalid: {0}")]
    Claims(String),
    #[error("token issuer is `{0}`, expected `{ISSUER}`")]
    Issuer(String),
    #[error("token audience is {0}, expected `{AUDIENCE}`")]
    Audience(String),
    #[error("token is expired (exp {exp}, now {now})")]
    Expired { exp: u64, now: u64 },
    #[error("token is not valid yet (nbf {nbf}, iat {iat}, now {now})")]
    NotYetValid { nbf: u64, iat: u64, now: u64 },
    #[error("token eat_nonce is not the two-value encoding of report_data")]
    Nonce,
}

fn null_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

#[derive(Debug, Deserialize)]
struct Header {
    alg: String,
    kid: String,
}

#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct Jwk {
    kty: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default, rename = "use")]
    use_: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
}

/// Claims of a Confidential Space token that the verifier reads. Unknown
/// claims are ignored (Google adds claims over time); every claim the policy
/// decision depends on is checked explicitly in [`check_claims`], and an
/// absent one fails its check.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub aud: serde_json::Value,
    pub exp: u64,
    pub iat: u64,
    pub nbf: u64,
    #[serde(default)]
    pub eat_nonce: serde_json::Value,
    #[serde(default)]
    pub dbgstat: Option<String>,
    #[serde(default)]
    pub swname: Option<String>,
    #[serde(default, deserialize_with = "null_default")]
    pub swversion: Vec<String>,
    #[serde(default)]
    pub hwmodel: Option<String>,
    #[serde(default)]
    pub oemid: Option<u64>,
    #[serde(default)]
    pub secboot: Option<bool>,
    #[serde(default, deserialize_with = "null_default")]
    pub submods: Submods,
    /// TDX-specific claims (`gcp_attester_tcb_status`, ...). Shape is not
    /// stable in Google's documentation, so it is read leniently.
    #[serde(default)]
    pub tdx: serde_json::Value,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Submods {
    #[serde(default, deserialize_with = "null_default")]
    pub confidential_space: ConfidentialSpace,
    #[serde(default, deserialize_with = "null_default")]
    pub container: Container,
    #[serde(default, deserialize_with = "null_default")]
    pub gce: Gce,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ConfidentialSpace {
    #[serde(default, deserialize_with = "null_default")]
    pub support_attributes: Vec<String>,
    #[serde(default, deserialize_with = "null_default")]
    pub monitoring_enabled: Monitoring,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Monitoring {
    #[serde(default, deserialize_with = "null_default")]
    pub memory: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Container {
    #[serde(default)]
    pub image_reference: Option<String>,
    #[serde(default)]
    pub image_digest: Option<String>,
    #[serde(default)]
    pub image_id: Option<String>,
    #[serde(default)]
    pub restart_policy: Option<String>,
    #[serde(default, deserialize_with = "null_default")]
    pub args: Vec<String>,
    #[serde(default, deserialize_with = "null_default")]
    pub cmd_override: Vec<String>,
    #[serde(default, deserialize_with = "null_default")]
    pub env_override: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Gce {
    #[serde(default)]
    pub project_id: Option<String>,
    #[serde(default)]
    pub zone: Option<String>,
    #[serde(default)]
    pub instance_name: Option<String>,
    #[serde(default)]
    pub instance_id: Option<String>,
}

impl Claims {
    /// `tdx.gcp_attester_tcb_status`, whether `tdx` is an object or a list.
    pub fn tdx_tcb_status(&self) -> Option<&str> {
        fn get(v: &serde_json::Value) -> Option<&str> {
            v.get("gcp_attester_tcb_status")
                .and_then(serde_json::Value::as_str)
        }
        match &self.tdx {
            serde_json::Value::Array(a) => a.iter().find_map(get),
            v => get(v),
        }
    }
}

/// A token whose signature, issuer, audience, validity window and nonce
/// encoding have been checked. The remaining claims are judged against the
/// policy by [`check_claims`].
#[derive(Debug, Clone)]
pub struct VerifiedToken {
    /// `report_data` reassembled from the signed `eat_nonce`.
    pub report_data: ReportData,
    pub claims: Claims,
    /// `kid` of the Google key that signed the token.
    pub kid: String,
}

fn b64url(part: &str, what: &'static str) -> Result<Vec<u8>, GcpError> {
    B64URL.decode(part).map_err(|_| GcpError::Malformed(what))
}

fn rsa_key(jwks_json: &str, kid: &str) -> Result<RsaPublicKey, GcpError> {
    let jwks: Jwks =
        serde_json::from_str(jwks_json).map_err(|e| GcpError::Jwks(format!("not a JWKS: {e}")))?;
    let mut matching = jwks.keys.iter().filter(|k| k.kid.as_deref() == Some(kid));
    let (Some(jwk), None) = (matching.next(), matching.next()) else {
        // Absent, or ambiguous: both are refused.
        return Err(GcpError::UnknownKey(kid.to_owned()));
    };
    if jwk.kty != "RSA"
        || jwk.alg.as_deref().is_some_and(|a| a != "RS256")
        || jwk.use_.as_deref().is_some_and(|u| u != "sig")
    {
        return Err(GcpError::Jwks(format!(
            "key `{kid}` is not an RS256 signing key"
        )));
    }
    let part = |v: &Option<String>| {
        v.as_deref()
            .and_then(|s| B64URL.decode(s).ok())
            .ok_or_else(|| GcpError::Jwks(format!("key `{kid}` has no usable n/e")))
    };
    let n = BigUint::from_bytes_be(&part(&jwk.n)?);
    let e = BigUint::from_bytes_be(&part(&jwk.e)?);
    if n.bits() < MIN_RSA_BITS {
        return Err(GcpError::Jwks(format!(
            "key `{kid}` is only {} bits",
            n.bits()
        )));
    }
    RsaPublicKey::new(n, e).map_err(|e| GcpError::Jwks(format!("key `{kid}`: {e}")))
}

/// Verify a Confidential Space OIDC token against `jwks_json` at time
/// `now_secs`. `jwks_json` is the trust anchor: production callers pass the
/// document fetched from [`common::JWKS_URL`] and nothing else.
pub fn verify_token(
    token: &[u8],
    jwks_json: &str,
    now_secs: u64,
) -> Result<VerifiedToken, GcpError> {
    if token.len() > MAX_TOKEN_BYTES {
        return Err(GcpError::TooLarge);
    }
    let token = std::str::from_utf8(token).map_err(|_| GcpError::Malformed("not UTF-8"))?;
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(GcpError::Malformed("expected three dot-separated parts"));
    };
    let header: Header = serde_json::from_slice(&b64url(h, "header is not base64url")?)
        .map_err(|_| GcpError::Malformed("header is not JSON with alg and kid"))?;
    // Pinned before any key is touched: no `none`, no HMAC with a public key
    // as secret, no algorithm chosen by the token.
    if header.alg != "RS256" {
        return Err(GcpError::Alg(header.alg));
    }
    let key = rsa_key(jwks_json, &header.kid)?;
    let sig = Signature::try_from(b64url(s, "signature is not base64url")?.as_slice())
        .map_err(|_| GcpError::Signature)?;
    let signed = &token.as_bytes()[..h.len() + 1 + p.len()];
    VerifyingKey::<Sha256>::new(key)
        .verify(signed, &sig)
        .map_err(|_| GcpError::Signature)?;

    // Only now is the payload trusted to be Google's.
    let claims: Claims = serde_json::from_slice(&b64url(p, "payload is not base64url")?)
        .map_err(|e| GcpError::Claims(e.to_string()))?;
    if claims.iss != ISSUER {
        return Err(GcpError::Issuer(claims.iss));
    }
    if claims.aud.as_str() != Some(AUDIENCE) {
        return Err(GcpError::Audience(claims.aud.to_string()));
    }
    if now_secs >= claims.exp.saturating_add(LEEWAY_SECS) {
        return Err(GcpError::Expired {
            exp: claims.exp,
            now: now_secs,
        });
    }
    let horizon = now_secs.saturating_add(LEEWAY_SECS);
    if claims.nbf > horizon || claims.iat > horizon {
        return Err(GcpError::NotYetValid {
            nbf: claims.nbf,
            iat: claims.iat,
            now: now_secs,
        });
    }
    let nonces: Vec<String> =
        serde_json::from_value(claims.eat_nonce.clone()).map_err(|_| GcpError::Nonce)?;
    let report_data = common::report_data_from_eat_nonces(&nonces).ok_or(GcpError::Nonce)?;
    Ok(VerifiedToken {
        report_data,
        claims,
        kid: header.kid,
    })
}

/// Judge the signed claims against the policy. Records the `measurements`
/// (Confidential Space image), `config` (launch parameters) and `images`
/// (workload image digest) checks.
pub fn check_claims(tok: &VerifiedToken, policy: &Policy, report: &mut Report) {
    let c = &tok.claims;
    let ct = &c.submods.container;
    let cs = &c.submods.confidential_space;
    report.observed.gcp_cs = Some(serde_json::json!({
        "hwmodel": c.hwmodel,
        "swname": c.swname,
        "swversion": c.swversion,
        "dbgstat": c.dbgstat,
        "support_attributes": cs.support_attributes,
        "tdx_tcb_status": c.tdx_tcb_status(),
        "image_reference": ct.image_reference,
        "image_digest": ct.image_digest,
        "image_id": ct.image_id,
        "restart_policy": ct.restart_policy,
        "project_id": c.submods.gce.project_id,
        "zone": c.submods.gce.zone,
        "instance_name": c.submods.gce.instance_name,
        "signing_kid": tok.kid,
    }));
    let Some(gp) = policy.gcp_cs.as_ref() else {
        report.fail(CheckId::Measurements, "policy has no gcp_cs section");
        return;
    };
    let show = |v: &Option<String>| v.clone().unwrap_or_else(|| "(absent)".to_owned());

    // 1. The platform and the Confidential Space image.
    let mut bad = Vec::new();
    if c.swname.as_deref() != Some(SWNAME) {
        bad.push(format!("swname is {} (need {SWNAME})", show(&c.swname)));
    }
    if c.dbgstat.as_deref() != Some(DBGSTAT_PRODUCTION) {
        bad.push(format!(
            "dbgstat is {} (need {DBGSTAT_PRODUCTION}): debug image, the operator has a root shell",
            show(&c.dbgstat)
        ));
    }
    if c.secboot != Some(true) {
        bad.push("secboot is not true".to_owned());
    }
    if c.oemid != Some(OEMID_GOOGLE) {
        bad.push(format!("oemid is {:?} (need {OEMID_GOOGLE})", c.oemid));
    }
    match c.hwmodel.as_deref() {
        Some(h) if gp.hwmodel.iter().any(|a| a == h) => {}
        _ => bad.push(format!(
            "hwmodel is {} (policy: {})",
            show(&c.hwmodel),
            gp.hwmodel.join(", ")
        )),
    }
    if cs.support_attributes.iter().any(|a| a == "EXPERIMENTAL")
        || !cs.support_attributes.contains(&gp.support_attribute)
    {
        bad.push(format!(
            "Confidential Space image support attributes are [{}] (need {})",
            cs.support_attributes.join(", "),
            gp.support_attribute
        ));
    }
    let version = match c.swversion.as_slice() {
        [v] => v.parse::<u64>().ok(),
        _ => None,
    };
    if let Some(min) = gp.min_swversion
        && version.is_none_or(|v| v < min)
    {
        bad.push(format!(
            "Confidential Space image version is [{}] (policy: at least {min})",
            c.swversion.join(", ")
        ));
    }
    if cs.monitoring_enabled.memory {
        bad.push("memory monitoring is enabled".to_owned());
    }
    if !gp.accepted_tdx_tcb_status.is_empty() {
        match c.tdx_tcb_status() {
            Some(s) if gp.accepted_tdx_tcb_status.iter().any(|a| a == s) => {}
            other => bad.push(format!(
                "TDX TCB status is {} (policy: {})",
                other.unwrap_or("(absent)"),
                gp.accepted_tdx_tcb_status.join(", ")
            )),
        }
    }
    if let Some(want) = &gp.project_id
        && c.submods.gce.project_id.as_ref() != Some(want)
    {
        bad.push(format!(
            "project is {} (policy: {want})",
            show(&c.submods.gce.project_id)
        ));
    }
    if bad.is_empty() {
        report.pass(
            CheckId::Measurements,
            format!(
                "Google attests: production Confidential Space image {} [{}] on {}, secure boot on, debug off{}",
                c.swversion.join(","),
                cs.support_attributes.join(","),
                show(&c.hwmodel),
                c.tdx_tcb_status()
                    .map(|s| format!(", TDX TCB {s}"))
                    .unwrap_or_default()
            ),
        );
    } else {
        report.fail(CheckId::Measurements, bad.join("; "));
    }

    // 2. Launch parameters the operator controls.
    let mut bad = Vec::new();
    if ct.restart_policy.as_deref() != Some(gp.restart_policy.as_str()) {
        bad.push(format!(
            "restart policy is {} (policy: {})",
            show(&ct.restart_policy),
            gp.restart_policy
        ));
    }
    if !ct.cmd_override.is_empty() {
        bad.push("the operator overrode the image command (cmd_override)".to_owned());
    }
    if !ct.env_override.is_empty() {
        let names: Vec<&str> = ct.env_override.keys().map(String::as_str).collect();
        bad.push(format!(
            "the operator overrode environment variables: {}",
            names.join(", ")
        ));
    }
    if bad.is_empty() {
        report.pass(
            CheckId::Config,
            format!(
                "restart policy {}, no command or environment overrides",
                gp.restart_policy
            ),
        );
    } else {
        report.fail(CheckId::Config, bad.join("; "));
    }

    // 3. The workload image.
    let want = policy.images.first();
    report.observed.images = vec![(
        want.map(|i| i.service.clone()).unwrap_or_default(),
        format!("{} ({})", show(&ct.image_reference), show(&ct.image_digest)),
    )];
    match want.and_then(|i| common::image_digest(&i.image)) {
        None => report.fail(CheckId::Images, "policy pins no workload image digest"),
        Some(d) if ct.image_digest.as_deref() == Some(d) => {
            if want.map(|i| i.image.as_str()) != ct.image_reference.as_deref() {
                report.notes.push(format!(
                    "note: image was pulled as {} (the digest, which is what matters, matches the policy)",
                    show(&ct.image_reference)
                ));
            }
            report.pass(
                CheckId::Images,
                format!("workload image digest {d} equals release {}", policy.release),
            );
        }
        Some(d) => report.fail(
            CheckId::Images,
            format!(
                "workload image digest is {} but release {} pins {d}: the server runs different software",
                show(&ct.image_digest),
                policy.release
            ),
        ),
    }
}
