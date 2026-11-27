//! Attested Vaultwarden verifier library.
//!
//! The CLI (`attested-vw-verify`) is a thin wrapper around [`verify`]. Every
//! step is fail-closed: an error at any point records a failed check and the
//! overall result is FAIL. [`check_document`] holds all checks that do not
//! need the network, so they can be unit-tested against recorded fixtures.
//!
//! Without the default `cli` feature the crate is only that pure,
//! synchronous core (no TLS client, no HTTP, no RNG, no clock), which also
//! builds for `wasm32-unknown-unknown`. A browser cannot read the TLS
//! certificate of its own connection, so there the caller uses
//! [`check_document_browser`] plus [`ct::check`] (Certificate Transparency)
//! instead of the per-connection TLS key check.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::panic, clippy::unwrap_used, clippy::expect_used))]

pub mod ct;
pub mod evidence;
#[cfg(feature = "cli")]
pub mod fetch;
pub mod gcp_cs;
#[cfg(feature = "cli")]
pub mod net;
#[cfg(feature = "cli")]
mod online;
pub mod registry;
pub mod report;
pub mod snp;
pub mod snp_launch;
pub mod tdx;

use attested_vw_common::compose;
use attested_vw_common::policy::Policy;
use attested_vw_common::report_data::{self, Nonce, SpkiSha256};
use attested_vw_common::schema::{AttestationResponse, Platform, SCHEMA_VERSION};

#[cfg(feature = "cli")]
pub use net::Roots;
#[cfg(feature = "cli")]
pub use online::{Options, REGISTRY_LOOKUP_BUDGET, verify};
pub use report::{Check, CheckId, Observed, Report};

fn hex_eq(expected: &str, got: &[u8]) -> bool {
    expected.eq_ignore_ascii_case(&hex::encode(got))
}

/// What the verifier knows about the TLS key of the connection the
/// document arrived on.
#[derive(Debug, Clone, Copy)]
enum TlsKey<'a> {
    /// The verifier did the handshake itself and hashed the leaf SPKI.
    Observed(&'a SpkiSha256),
    /// A web page: the browser validated the certificate but does not show
    /// it to scripts.
    Unobservable,
}

/// Note recorded on every browser-mode report.
pub const BROWSER_MODE_NOTE: &str = "browser mode: a web page cannot read the TLS certificate of its own connection, \
so the per-connection check \"TLS key bound to attestation\" is NOT done here; \
it is replaced by the Certificate Transparency check (every currently valid logged certificate for the name must have an attested key)";

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
    check_document_inner(
        body,
        TlsKey::Observed(our_spki),
        our_nonce,
        policy,
        ctx,
        report,
    );
}

/// The same checks for a verifier that cannot see the TLS certificate (a web
/// page). Differences from [`check_document`]:
///
/// * no `SpkiBinding` check is recorded (neither ✓ nor ✗); the report is
///   marked `browser_mode` and carries [`BROWSER_MODE_NOTE`];
/// * `report_data` is recomputed from our nonce and the SPKI hash **the
///   server reports** (`ReportDataClaimed`). That proves a genuine TEE with
///   this software vouches for that key, not that our connection uses it;
/// * if that holds, `report.attested_spki` is set, for [`ct::check`], which
///   must then be run on the same report: without a `CtBinding` check a
///   browser-mode report is never PASS.
pub fn check_document_browser(
    body: &[u8],
    our_nonce: &Nonce,
    policy: &Policy,
    ctx: &evidence::Context,
    report: &mut Report,
) {
    report.browser_mode = true;
    report.note(BROWSER_MODE_NOTE);
    check_document_inner(body, TlsKey::Unobservable, our_nonce, policy, ctx, report);
}

fn check_document_inner(
    body: &[u8],
    tls_key: TlsKey<'_>,
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
    match tls_key {
        TlsKey::Observed(_) => report.pass(
            CheckId::Fetch,
            format!("same TLS connection, {} bytes", body.len()),
        ),
        TlsKey::Unobservable => report.pass(
            CheckId::Fetch,
            format!(
                "fetched by the browser over HTTPS (certificate validated by the browser, not visible to this page), {} bytes",
                body.len()
            ),
        ),
    }

    // TLS key binding (informative; the binding proper is the report_data check).
    match tls_key {
        TlsKey::Observed(our_spki) if doc.spki_sha256 == *our_spki => report.pass(
            CheckId::SpkiBinding,
            "attested SPKI equals the certificate we received",
        ),
        TlsKey::Observed(our_spki) => report.fail(
            CheckId::SpkiBinding,
            format!(
                "attestation is for TLS key {} but this connection uses {our_spki}: the TLS endpoint is not the attested server (relay?) or the certificate just rotated",
                doc.spki_sha256
            ),
        ),
        // Deliberately no check line: nothing was compared.
        TlsKey::Unobservable => {}
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

    match tls_key {
        // report_data recomputed from OUR values only.
        TlsKey::Observed(our_spki) => {
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
        }
        // Our nonce, the SERVER's statement of its TLS key. Only a non-mock
        // platform can make that statement count.
        TlsKey::Unobservable => {
            let expected = report_data::compute(our_nonce, &doc.spki_sha256);
            if verified.report_data == expected {
                report.pass(
                    CheckId::ReportDataClaimed,
                    format!(
                        "signed report_data = SHA-512(tag ‖ our nonce ‖ SPKI {}): this key is attested; whether clients reach it is the Certificate Transparency check",
                        doc.spki_sha256
                    ),
                );
                if doc.platform != Platform::Mock {
                    report.attested_spki = Some(doc.spki_sha256.to_string());
                }
            } else {
                report.fail(
                    CheckId::ReportDataClaimed,
                    format!(
                        "signed report_data does not match our nonce and the TLS key the server reports ({})",
                        doc.spki_sha256
                    ),
                );
            }
        }
    }

    // Confidential Space: there is no compose document or event log; what
    // runs is one image, named by claims in the Google-signed token.
    if let evidence::Measured::GcpCs(tok) = &verified.measured {
        gcp_cs::check_claims(tok, policy, report);
        return;
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
    report.observed.allowed_envs = compose::parse_json_strict(&doc.app_compose)
        .ok()
        .and_then(|v| v.get("allowed_envs").cloned())
        .and_then(|a| serde_json::from_value(a).ok())
        .unwrap_or_default();
    report.observed.app_compose_flags =
        compose::app_compose_flags(&doc.app_compose).unwrap_or_default();
    if let evidence::Measured::Tdx(q) = &verified.measured {
        let o = &mut report.observed;
        o.tcb_status = Some(q.tcb_status.clone());
        o.tcb_eval_data_number = Some(q.tcb_eval_data_number);
        o.mr_config_id = Some(hex::encode(q.mr_config_id));
        o.mr_owner = Some(hex::encode(q.mr_owner));
        o.mr_owner_config = Some(hex::encode(q.mr_owner_config));
        o.td_attributes = Some(hex::encode(q.td_attributes));
        o.xfam = Some(hex::encode(q.xfam));
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
        evidence::Measured::Snp(r) => snp_launch::check_binding(r, policy, report),
        evidence::Measured::GcpCs(_) => None, // handled above
    };

    let expected_hash = match policy.platform {
        Platform::Mock => policy.mock.as_ref().map(|m| m.compose_hash.as_str()),
        Platform::Tdx => policy.tdx.as_ref().map(|t| t.compose_hash.as_str()),
        Platform::SevSnp => snp_launch::expected_compose_hash(policy),
        Platform::GcpCs => None,
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

    check_config(&doc.app_compose, policy, report);

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
            let clean = |s: &str| report::sanitize(s, report::MAX_DETAIL_CHARS);
            report.observed.images = imgs
                .iter()
                .map(|i| (clean(&i.service), clean(&i.image)))
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
            // One line per service with the full reference (a separate
            // field, so details stay single-line). Tag names are added
            // later, outside the core, and never affect the verdict.
            let lines = registry::sub_lines(&report.observed.images, &[]);
            report.set_sub(CheckId::Images, lines);
            if doc.image_digests != imgs {
                report.note(
                    "note: informational `image_digests` field differs from the measured compose (ignored)",
                );
            }
        }
    }
}

/// The `Config` check. Nothing outside the measured document may decide
/// what runs (launch scripts, injected env, interpolation), the compose
/// must not hand a container host-level access
/// ([`compose::hardening_problems`]), and `public_logs` must be what the
/// policy pins. These are known pitfalls, not a proof of a safe
/// configuration: the compose hash is what pins the document.
fn check_config(app_compose: &str, policy: &Policy, report: &mut Report) {
    let hardening = compose::Hardening {
        allowed_bind_mounts: &policy.allowed_bind_mounts,
        command_override_services: &policy.command_override_services,
    };
    let problems = compose::config_problems(
        app_compose,
        policy.pre_launch_script_sha256.as_deref(),
        &policy.allowed_envs,
    )
    .and_then(|mut p| {
        p.extend(compose::hardening_problems(app_compose, hardening)?);
        let logs = compose::flag(app_compose, "public_logs")?;
        match policy.public_logs {
            Some(want) if want != logs => p.push(format!(
                "app-compose has public_logs = {logs} (container logs {} served outside the CVM), policy pins {want}",
                if logs { "are" } else { "are not" }
            )),
            Some(_) => {}
            None => report.note(format!(
                "policy does not pin public_logs; the measured app-compose has public_logs = {logs}{}",
                if logs { ": container logs are readable from outside the CVM" } else { "" }
            )),
        }
        Ok((p, logs))
    });
    match problems {
        Err(e) => report.fail(CheckId::Config, e.to_string()),
        Ok((p, logs)) if p.is_empty() => report.pass(
            CheckId::Config,
            format!(
                "pre-launch script, init script and encrypted env names as the policy pins; no variable interpolation; no privileged, host-namespace, host-path or command-override settings; public_logs = {logs}"
            ),
        ),
        Ok((p, _)) => report.fail(CheckId::Config, p.join("; ")),
    }
}

/// The key provider recorded in RTMR3 against the policy pin and against
/// the `key_provider_id` the measured app-compose asks for.
fn key_provider_problems(
    measured: &str,
    pin: Option<&str>,
    app_compose: &str,
    problems: &mut Vec<String>,
) {
    match pin {
        None => problems.push("policy does not pin key_provider (required)".into()),
        Some(want) if want != measured => {
            problems.push(format!("key-provider is {measured} (policy: {want})"))
        }
        Some(_) => {}
    }
    let measured_id = attested_vw_common::policy::key_provider_id(measured);
    match (compose::key_provider_id(app_compose), measured_id) {
        (Err(e), _) => problems.push(e.to_string()),
        (_, Err(e)) => problems.push(format!("key-provider payload {measured}: {e}")),
        (Ok(None), Ok(_)) => {}
        (Ok(Some(want)), Ok(got)) if want == got => {}
        (Ok(Some(want)), Ok(got)) => problems.push(format!(
            "app-compose asks for key_provider_id {want} but the key provider measured in RTMR3 has id `{got}`"
        )),
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
    report.observed.key_provider = Some(report::sanitize(
        &facts.key_provider,
        report::MAX_DETAIL_CHARS,
    ));
    report.observed.rtmr3_events = events.iter().map(|e| e.name.clone()).collect();
    let mut problems = Vec::new();
    // Both pins are mandatory (Policy::validate); a policy built in code
    // without them fails here rather than skipping the check.
    match &tp.app_id {
        None => problems.push("policy does not pin app_id (required)".into()),
        Some(want) if !hex_eq(want, &facts.app_id) => problems.push(format!(
            "app-id is {} (policy: {want})",
            hex::encode(&facts.app_id)
        )),
        Some(_) => {}
    }
    key_provider_problems(
        &facts.key_provider,
        tp.key_provider.as_deref(),
        &doc.app_compose,
        &mut problems,
    );
    let (launch, launch_note) = tdx::check_launch_fields(q, tp, &facts.compose_hash);
    problems.extend(launch);
    if let Some(n) = launch_note {
        report.note(n);
    }
    if tp.require_storage_encrypted && facts.storage_encrypted != Some(true) {
        problems.push(
            "no `storage-encrypted` = 1 event: the OS does not report an encrypted data disk, \
             and the policy requires it (require_storage_encrypted)"
                .to_owned(),
        );
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
mod gcp_cs_tests;
#[cfg(test)]
mod snp_tests;
#[cfg(test)]
mod tdx_doc_tests;
#[cfg(test)]
mod tdx_tests;
#[cfg(test)]
mod tests;
