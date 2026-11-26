//! Attested Vaultwarden verifier library.
//!
//! The CLI (`attested-vw-verify`) is a thin wrapper around [`verify`]. Every
//! step is fail-closed: an error at any point records a failed check and the
//! overall result is FAIL. [`check_document`] holds all checks that do not
//! need the network, so they can be unit-tested against recorded fixtures.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::panic, clippy::unwrap_used, clippy::expect_used))]

pub mod evidence;
pub mod fetch;
pub mod net;
pub mod report;
pub mod snp;
pub mod tdx;

use attested_vw_common::compose;
use attested_vw_common::policy::Policy;
use attested_vw_common::report_data::{self, Nonce, SpkiSha256};
use attested_vw_common::schema::{AttestationResponse, Platform, SCHEMA_VERSION};
use attested_vw_common::tls;

pub use net::Roots;
pub use report::{Check, CheckId, Observed, Report};

/// Options controlling a verification run.
#[derive(Debug, Clone)]
pub struct Options {
    /// Accept the INSECURE mock platform (local development only). Even when
    /// set, a mock result never counts as PASS.
    pub allow_insecure_mock: bool,
    /// Trust anchors for the TLS connection.
    pub roots: Roots,
    /// Where to fetch Intel DCAP collateral (Intel PCS by default). The
    /// collateral is Intel-signed, so the source affects availability only.
    pub pccs_url: String,
    /// AMD Key Distribution Service base URL (VCEK certificates).
    pub kds_url: String,
}

impl Options {
    pub fn new(roots: Roots) -> Self {
        Self {
            allow_insecure_mock: false,
            roots,
            pccs_url: fetch::INTEL_PCS_URL.to_owned(),
            kds_url: fetch::AMD_KDS_URL.to_owned(),
        }
    }
}

fn fresh_nonce() -> Result<Nonce, String> {
    let mut n = [0u8; 32];
    getrandom::fill(&mut n).map_err(|e| format!("OS random number generator failed: {e}"))?;
    Ok(Nonce(n))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Verify a deployment at `target` (an `https://` origin) against `policy`.
///
/// If the only problem is a TLS key mismatch, the run is repeated once on a
/// fresh connection, because a certificate renewal between our handshake and
/// the sidecar reading the certificate produces exactly that. A relay fails
/// both times.
pub async fn verify(target: &str, policy: &Policy, opts: &Options) -> Report {
    let first = verify_once(target, policy, opts).await;
    let failures: Vec<CheckId> = first
        .checks
        .iter()
        .filter(|c| !c.passed)
        .map(|c| c.id)
        .collect();
    let spki_only = !failures.is_empty()
        && failures
            .iter()
            .all(|id| matches!(id, CheckId::SpkiBinding | CheckId::ReportData));
    if !spki_only {
        return first;
    }
    let mut second = verify_once(target, policy, opts).await;
    second.notes.push(
        "first attempt failed on the TLS key binding; retried once on a new connection".into(),
    );
    second
}

async fn verify_once(target: &str, policy: &Policy, opts: &Options) -> Report {
    let mut report = Report::new(target);
    report.policy_release = Some(policy.release.clone());
    report.notes.push(match &opts.roots {
        Roots::WebPki => "TLS trust roots: Mozilla WebPKI (webpki-roots)".into(),
        Roots::Custom(_) => "TLS trust roots: custom CA file only (NOT WebPKI)".into(),
    });

    let t = match net::Target::parse(target) {
        Ok(t) => t,
        Err(e) => {
            report.fail(CheckId::Tls, e.to_string());
            return report;
        }
    };
    let nonce = match fresh_nonce() {
        Ok(n) => n,
        Err(e) => {
            report.fail(CheckId::Fetch, e);
            return report;
        }
    };
    let fetched = match net::fetch(&t, &opts.roots, &nonce).await {
        Ok(f) => f,
        Err(e @ (net::NetError::Status(..) | net::NetError::Http(_))) => {
            report.pass(CheckId::Tls, "handshake ok");
            report.fail(CheckId::Fetch, e.to_string());
            return report;
        }
        Err(e) => {
            report.fail(CheckId::Tls, e.to_string());
            return report;
        }
    };
    let spki = match tls::spki_sha256_from_der(&fetched.leaf_der) {
        Ok(s) => s,
        Err(e) => {
            report.fail(CheckId::Tls, format!("cannot parse leaf certificate: {e}"));
            return report;
        }
    };
    report.pass(
        CheckId::Tls,
        format!(
            "{} to {}:{}, certificate valid for host; leaf SPKI SHA-256 {spki}",
            fetched.tls_version, t.host, t.port
        ),
    );

    // Fetch platform endorsements (Intel collateral / AMD VCEK) for the
    // evidence. These are signed by the vendor and checked offline below.
    let mut ctx = evidence::Context::mock(opts.allow_insecure_mock);
    ctx.now_secs = unix_now();
    if let Ok(doc) = serde_json::from_slice::<AttestationResponse>(&fetched.body)
        && let Ok(quote) = evidence::decode_quote(&doc.evidence)
    {
        match doc.platform {
            Platform::Tdx => {
                ctx.tdx_collateral = fetch::tdx_collateral(&opts.pccs_url, &quote).await
            }
            Platform::SevSnp => ctx.snp_vcek_der = fetch::snp_vcek(&opts.kds_url, &quote).await,
            Platform::Mock => {}
        }
    }
    check_document(&fetched.body, &spki, &nonce, policy, &ctx, &mut report);
    report
}

fn hex_eq(expected: &str, got: &[u8]) -> bool {
    expected.eq_ignore_ascii_case(&hex::encode(got))
}

/// All checks after the network step. `our_spki` and `our_nonce` come from
/// the verifier's own handshake and RNG, never from the document.
pub fn check_document(
    body: &[u8],
    our_spki: &SpkiSha256,
    our_nonce: &Nonce,
    policy: &Policy,
    ctx: &evidence::Context,
    report: &mut Report,
) {
    // Fetch / parse.
    let doc: AttestationResponse = match serde_json::from_slice(body) {
        Ok(d) => d,
        Err(e) => {
            report.fail(
                CheckId::Fetch,
                format!("attestation document is invalid: {e}"),
            );
            return;
        }
    };
    if doc.version != SCHEMA_VERSION {
        report.fail(
            CheckId::Fetch,
            format!(
                "unsupported document version {} (expected {SCHEMA_VERSION})",
                doc.version
            ),
        );
        return;
    }
    if doc.report_data_construction != report_data::CONSTRUCTION {
        report.fail(
            CheckId::Fetch,
            format!(
                "server uses a different report_data construction: {:?}",
                doc.report_data_construction
            ),
        );
        return;
    }
    report.platform = Some(doc.platform.as_str().to_owned());
    if doc.platform != policy.platform {
        report.fail(
            CheckId::Fetch,
            format!(
                "server reports platform `{}`, policy requires `{}`",
                doc.platform.as_str(),
                policy.platform.as_str()
            ),
        );
        return;
    }
    report.pass(
        CheckId::Fetch,
        format!("same TLS connection, {} bytes", body.len()),
    );

    // TLS key binding (informative; the binding proper is the report_data check).
    if doc.spki_sha256 == *our_spki {
        report.pass(
            CheckId::SpkiBinding,
            "attested SPKI equals the certificate we received",
        );
    } else {
        report.fail(
            CheckId::SpkiBinding,
            format!(
                "attestation is for TLS key {} but this connection uses {our_spki}: the TLS endpoint is not the attested server (relay?) or the certificate just rotated",
                doc.spki_sha256
            ),
        );
    }

    if doc.nonce == *our_nonce {
        report.pass(CheckId::Nonce, "server echoed our fresh nonce");
    } else {
        report.fail(
            CheckId::Nonce,
            "document nonce differs from the one we sent (replay?)",
        );
    }

    // Evidence.
    let verified = match evidence::verify(doc.platform, &doc.evidence, policy, ctx) {
        Ok(v) => v,
        Err(e) => {
            report.fail(CheckId::Evidence, e.to_string());
            return;
        }
    };
    if doc.platform == Platform::Mock {
        report.insecure_mock = true;
    }
    report.pass(CheckId::Evidence, verified.summary.clone());

    // report_data recomputed from OUR values only.
    let expected = report_data::compute(our_nonce, our_spki);
    if verified.report_data == expected {
        report.pass(
            CheckId::ReportData,
            "signed report_data = SHA-512(tag ‖ our nonce ‖ our TLS SPKI)",
        );
    } else {
        report.fail(
            CheckId::ReportData,
            "signed report_data does not match our nonce and TLS key",
        );
    }

    // Measurements, event log and the measured compose hash.
    let got_compose = compose::compose_hash(doc.app_compose.as_bytes());
    report.observed.compose_hash_served = Some(hex::encode(got_compose));
    report.observed.vm_config = doc
        .evidence
        .vm_config
        .as_deref()
        .and_then(|v| serde_json::from_str(v).ok());
    report.observed.pre_launch_script_sha256 = compose::pre_launch_script_sha256(&doc.app_compose);
    report.observed.allowed_envs = serde_json::from_str::<serde_json::Value>(&doc.app_compose)
        .ok()
        .and_then(|v| v.get("allowed_envs").cloned())
        .and_then(|a| serde_json::from_value(a).ok())
        .unwrap_or_default();
    if let evidence::Measured::Tdx(q) = &verified.measured {
        let o = &mut report.observed;
        o.tcb_status = Some(q.tcb_status.clone());
        o.advisory_ids = q.advisory_ids.clone();
        o.pck_flags_set = q.pck_flags_set.iter().map(|s| s.to_string()).collect();
        o.mrtd = Some(hex::encode(q.mr_td));
        o.rtmr0 = Some(hex::encode(q.rt_mr[0]));
        o.rtmr1 = Some(hex::encode(q.rt_mr[1]));
        o.rtmr2 = Some(hex::encode(q.rt_mr[2]));
        o.rtmr3 = Some(hex::encode(q.rt_mr[3]));
    }
    let measured_compose: Option<[u8; 32]> = match &verified.measured {
        evidence::Measured::Mock => {
            report.pass(CheckId::Measurements, "INSECURE MOCK: nothing was measured");
            report.pass(CheckId::EventLog, "INSECURE MOCK: no event log");
            // Nothing measured it; compare the served document to the policy
            // only to exercise the pipeline.
            Some(got_compose)
        }
        evidence::Measured::Tdx(q) => check_tdx_measurements(q, &doc, policy, report),
        evidence::Measured::Snp(r) => {
            match policy.sev_snp.as_ref() {
                Some(sp) if hex_eq(&sp.measurement, &r.measurement) => report.pass(
                    CheckId::Measurements,
                    format!(
                        "launch measurement {} matches release {}",
                        hex::encode(r.measurement),
                        policy.release
                    ),
                ),
                Some(sp) => report.fail(
                    CheckId::Measurements,
                    format!(
                        "launch measurement {} but policy expects {}",
                        hex::encode(r.measurement),
                        sp.measurement
                    ),
                ),
                None => report.fail(CheckId::Measurements, "policy has no sev_snp section"),
            }
            report.fail(
                CheckId::EventLog,
                "SEV-SNP: binding the compose document to the launch measurement is not implemented yet (stretch goal)",
            );
            None
        }
    };

    let expected_hash = match policy.platform {
        Platform::Mock => policy.mock.as_ref().map(|m| m.compose_hash.as_str()),
        Platform::Tdx => policy.tdx.as_ref().map(|t| t.compose_hash.as_str()),
        Platform::SevSnp => None,
    };
    let got_hex = hex::encode(got_compose);
    match (expected_hash, measured_compose) {
        (None, _) => report.fail(CheckId::ComposeHash, "policy has no compose hash for this platform"),
        (Some(_), None) => report.fail(CheckId::ComposeHash, "no measured compose hash available"),
        (Some(e), Some(m)) if !hex_eq(e, &m) => report.fail(
            CheckId::ComposeHash,
            format!(
                "measured compose hash {} but release {} expects {e}: the server runs a different compose/config",
                hex::encode(m),
                policy.release
            ),
        ),
        (Some(_), Some(m)) if m != got_compose => report.fail(
            CheckId::ComposeHash,
            format!(
                "served app-compose hashes to {got_hex}, which is not the measured {}: the served document is not what runs",
                hex::encode(m)
            ),
        ),
        (Some(_), Some(_)) => report.pass(
            CheckId::ComposeHash,
            format!("measured = SHA-256(served app-compose) = {got_hex} = release {}", policy.release),
        ),
    }

    // Nothing outside the measured document may decide what runs.
    match compose::config_problems(
        &doc.app_compose,
        policy.pre_launch_script_sha256.as_deref(),
        &policy.allowed_envs,
    ) {
        Err(e) => report.fail(CheckId::Config, e.to_string()),
        Ok(p) if p.is_empty() => report.pass(
            CheckId::Config,
            "pre-launch script, init script and encrypted env names exactly as the policy pins; no variable interpolation",
        ),
        Ok(p) => report.fail(CheckId::Config, p.join("; ")),
    }

    // Images, derived from the (hash-checked) app-compose, never from
    // `image_digests`.
    let imgs = compose::docker_compose_file(&doc.app_compose).and_then(|y| compose::images(&y));
    match imgs {
        Err(e) => report.fail(CheckId::Images, e.to_string()),
        Ok(imgs) => {
            let allow: Vec<(String, String)> = policy
                .images
                .iter()
                .map(|i| (i.service.clone(), i.image.clone()))
                .collect();
            report.observed.images = imgs
                .iter()
                .map(|i| (i.service.clone(), i.image.clone()))
                .collect();
            let problems = compose::check_images(&imgs, &allow);
            if problems.is_empty() {
                report.pass(
                    CheckId::Images,
                    format!(
                        "{} services, all pinned by digest and allowlisted",
                        imgs.len()
                    ),
                );
            } else {
                let msg: Vec<String> = problems.iter().map(|p| p.to_string()).collect();
                report.fail(CheckId::Images, msg.join("; "));
            }
            if doc.image_digests != imgs {
                report.notes.push(
                    "note: informational `image_digests` field differs from the measured compose (ignored)".into(),
                );
            }
        }
    }
}

/// MRTD/RTMR0-2 against the policy, RTMR3 replay and RTMR3 facts. Returns
/// the compose hash measured into RTMR3 if the event log checks out.
fn check_tdx_measurements(
    q: &tdx::VerifiedQuote,
    doc: &AttestationResponse,
    policy: &Policy,
    report: &mut Report,
) -> Option<[u8; 32]> {
    let Some(tp) = policy.tdx.as_ref() else {
        report.fail(CheckId::Measurements, "policy has no tdx section");
        return None;
    };
    let regs = [
        ("MRTD", tp.mrtd.as_str(), &q.mr_td),
        ("RTMR0", tp.rtmr0.as_str(), &q.rt_mr[0]),
        ("RTMR1", tp.rtmr1.as_str(), &q.rt_mr[1]),
        ("RTMR2", tp.rtmr2.as_str(), &q.rt_mr[2]),
    ];
    let bad: Vec<String> = regs
        .iter()
        .filter(|(_, want, got)| !hex_eq(want, got.as_slice()))
        .map(|(n, want, got)| format!("{n} is {} (policy: {want})", hex::encode(got)))
        .collect();
    if bad.is_empty() {
        report.pass(
            CheckId::Measurements,
            format!(
                "MRTD, RTMR0-2 equal the values pinned by release {}",
                policy.release
            ),
        );
    } else {
        report.fail(
            CheckId::Measurements,
            format!("unknown firmware/OS measurement: {}", bad.join("; ")),
        );
    }

    let Some(log) = doc.evidence.event_log.as_deref() else {
        report.fail(CheckId::EventLog, "TDX evidence has no event log");
        return None;
    };
    let events = match tdx::check_rtmr3(log, &q.rt_mr[3]) {
        Ok(e) => e,
        Err(e) => {
            report.fail(CheckId::EventLog, e.to_string());
            return None;
        }
    };
    let facts = match tdx::rtmr3_facts(&events) {
        Ok(f) => f,
        Err(e) => {
            report.fail(CheckId::EventLog, e.to_string());
            return None;
        }
    };
    report.observed.compose_hash_measured = Some(hex::encode(facts.compose_hash));
    report.observed.app_id = Some(hex::encode(&facts.app_id));
    report.observed.key_provider = Some(facts.key_provider.clone());
    let mut problems = Vec::new();
    if let Some(want) = &tp.app_id
        && !hex_eq(want, &facts.app_id)
    {
        problems.push(format!(
            "app-id is {} (policy: {want})",
            hex::encode(&facts.app_id)
        ));
    }
    if let Some(want) = &tp.key_provider
        && *want != facts.key_provider
    {
        problems.push(format!(
            "key-provider is {} (policy: {want})",
            facts.key_provider
        ));
    }
    if problems.is_empty() {
        report.pass(
            CheckId::EventLog,
            format!(
                "{} RTMR3 events replay to the quoted RTMR3; app-id {}, key-provider {}, data disk {}",
                events.len(),
                hex::encode(&facts.app_id),
                facts.key_provider,
                match facts.storage_encrypted {
                    Some(true) => "encrypted",
                    _ => "encryption not reported by this OS image",
                }
            ),
        );
        Some(facts.compose_hash)
    } else {
        report.fail(CheckId::EventLog, problems.join("; "));
        None
    }
}

#[cfg(test)]
mod tdx_doc_tests;
#[cfg(test)]
mod tdx_tests;
#[cfg(test)]
mod tests;
