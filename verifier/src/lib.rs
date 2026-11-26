//! Attested Vaultwarden verifier library.
//!
//! The CLI (`attested-vw-verify`) is a thin wrapper around [`verify`]. Every
//! step is fail-closed: an error at any point records a failed check and the
//! overall result is FAIL. [`check_document`] holds all checks that do not
//! need the network, so they can be unit-tested against recorded fixtures.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::panic, clippy::unwrap_used, clippy::expect_used))]

pub mod evidence;
pub mod net;
pub mod report;

use attested_vw_common::compose;
use attested_vw_common::policy::Policy;
use attested_vw_common::report_data::{self, Nonce, SpkiSha256};
use attested_vw_common::schema::{AttestationResponse, Platform, SCHEMA_VERSION};
use attested_vw_common::tls;

pub use net::Roots;
pub use report::{Check, CheckId, Report};

/// Options controlling a verification run.
#[derive(Debug, Clone)]
pub struct Options {
    /// Accept the INSECURE mock platform (local development only). Even when
    /// set, a mock result never counts as PASS.
    pub allow_insecure_mock: bool,
    /// Trust anchors for the TLS connection.
    pub roots: Roots,
}

fn fresh_nonce() -> Result<Nonce, String> {
    let mut n = [0u8; 32];
    getrandom::fill(&mut n).map_err(|e| format!("OS random number generator failed: {e}"))?;
    Ok(Nonce(n))
}

/// Verify a deployment at `target` (an `https://` origin) against `policy`.
///
/// If the only problem is a TLS key mismatch, the run is repeated once on a
/// fresh connection, because a certificate renewal between our handshake and
/// the sidecar reading the certificate produces exactly that. A relay fails
/// both times.
pub async fn verify(target: &str, policy: &Policy, opts: &Options) -> Report {
    let first = verify_once(target, policy, opts).await;
    let spki_only = first
        .checks
        .iter()
        .filter(|c| !c.passed)
        .all(|c| matches!(c.id, CheckId::SpkiBinding | CheckId::ReportData));
    if first.passed() || !spki_only || first.checks.iter().all(|c| c.passed) {
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
    check_document(&fetched.body, &spki, &nonce, policy, opts, &mut report);
    report
}

/// All checks after the network step. `our_spki` and `our_nonce` come from
/// the verifier's own handshake and RNG, never from the document.
pub fn check_document(
    body: &[u8],
    our_spki: &SpkiSha256,
    our_nonce: &Nonce,
    policy: &Policy,
    opts: &Options,
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
    let verified = match evidence::verify(doc.platform, &doc.evidence, opts.allow_insecure_mock) {
        Ok(v) => v,
        Err(e) => {
            report.fail(CheckId::Evidence, e.to_string());
            return;
        }
    };
    if doc.platform == Platform::Mock {
        report.insecure_mock = true;
    }
    report.pass(CheckId::Evidence, verified.summary);

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
            "signed report_data does not match our nonce and TLS key".to_owned(),
        );
    }

    // Measurements.
    match doc.platform {
        Platform::Mock => report.pass(CheckId::Measurements, "INSECURE MOCK: nothing was measured"),
        _ => report.fail(CheckId::Measurements, "not implemented yet (M2)"),
    }

    // Compose hash.
    let expected_hash = match policy.platform {
        Platform::Mock => policy.mock.as_ref().map(|m| m.compose_hash.as_str()),
        Platform::Tdx => policy.tdx.as_ref().map(|t| t.compose_hash.as_str()),
        Platform::SevSnp => None,
    };
    let got = hex::encode(compose::compose_hash(doc.app_compose.as_bytes()));
    match expected_hash {
        Some(e) if e.eq_ignore_ascii_case(&got) => report.pass(
            CheckId::ComposeHash,
            format!("SHA-256(app-compose) = {got} matches release {}", policy.release),
        ),
        Some(e) => report.fail(
            CheckId::ComposeHash,
            format!("SHA-256(app-compose) = {got}, policy expects {e}: server runs a different compose/config than release {}", policy.release),
        ),
        None => report.fail(CheckId::ComposeHash, "policy has no compose hash for this platform"),
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

#[cfg(test)]
mod tests;
