//! Offline tests of [`check_document`] using mock documents built in-process.

use super::*;
use attested_vw_common::policy::{ImagePolicy, MockPolicy};
use attested_vw_common::schema::{Evidence, ImageDigest, MOCK_MAGIC};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

const D: &str = "2222222222222222222222222222222222222222222222222222222222222222";

struct Fixture {
    nonce: Nonce,
    spki: SpkiSha256,
    app_compose: String,
    policy: Policy,
}

fn image() -> String {
    format!("vaultwarden/server@sha256:{D}")
}

fn fixture() -> Fixture {
    let app_compose = serde_json::json!({
        "name": "t",
        "docker_compose_file": format!("services:\n  vaultwarden:\n    image: {}\n", image()),
    })
    .to_string();
    let policy = Policy {
        schema: 1,
        release: "test".into(),
        date: "2026-11-26".into(),
        platform: Platform::Mock,
        tdx: None,
        sev_snp: None,
        mock: Some(MockPolicy {
            compose_hash: hex::encode(compose::compose_hash(app_compose.as_bytes())),
        }),
        images: vec![ImagePolicy {
            service: "vaultwarden".into(),
            image: image(),
        }],

        pre_launch_script_sha256: None,
        allowed_envs: vec![],
        public_logs: None,
        allowed_bind_mounts: vec![],
        command_override_services: vec![],
    };
    Fixture {
        nonce: Nonce([9; 32]),
        spki: SpkiSha256([5; 32]),
        app_compose,
        policy,
    }
}

/// An honest mock server's document for the given (server-side) nonce/SPKI.
fn doc(f: &Fixture, nonce: Nonce, spki: SpkiSha256, app_compose: &str) -> Vec<u8> {
    let rd = report_data::compute(&nonce, &spki);
    let mut blob = MOCK_MAGIC.to_vec();
    blob.extend_from_slice(&rd.0);
    let d = AttestationResponse {
        version: SCHEMA_VERSION,
        platform: Platform::Mock,
        evidence: Evidence {
            quote: B64.encode(blob),
            event_log: None,
            aux: None,
            vm_config: None,
        },
        nonce,
        spki_sha256: spki,
        report_data_construction: report_data::CONSTRUCTION.into(),
        app_compose: app_compose.into(),
        image_digests: vec![ImageDigest {
            service: "vaultwarden".into(),
            image: image(),
        }],
        timestamp: "2026-11-26T00:00:00Z".into(),
    };
    let _ = f;
    serde_json::to_vec(&d).unwrap()
}

fn run(f: &Fixture, body: &[u8], allow_mock: bool) -> Report {
    let mut r = Report::new("https://t");
    r.pass(CheckId::Tls, "test");
    check_document(
        body,
        &f.spki,
        &f.nonce,
        &f.policy,
        &evidence::Context::mock(allow_mock),
        &mut r,
    );
    r
}

fn failed(r: &Report) -> Vec<CheckId> {
    r.checks
        .iter()
        .filter(|c| !c.passed)
        .map(|c| c.id)
        .collect()
}

#[test]
fn honest_mock_all_checks_pass_but_result_is_not_pass() {
    let f = fixture();
    let r = run(&f, &doc(&f, f.nonce, f.spki, &f.app_compose), true);
    assert!(failed(&r).is_empty(), "{r}");
    assert!(!r.passed());
    assert_eq!(r.exit_code(), 2);
    assert!(r.to_string().contains("INSECURE MOCK"));
}

#[test]
fn mock_refused_without_flag() {
    let f = fixture();
    let r = run(&f, &doc(&f, f.nonce, f.spki, &f.app_compose), false);
    assert_eq!(failed(&r), vec![CheckId::Evidence]);
    assert_eq!(r.exit_code(), 1);
}

#[test]
fn relay_with_different_tls_key_fails() {
    // The attested server's key differs from the one in our handshake.
    let f = fixture();
    let r = run(
        &f,
        &doc(&f, f.nonce, SpkiSha256([6; 32]), &f.app_compose),
        true,
    );
    assert_eq!(failed(&r), vec![CheckId::SpkiBinding, CheckId::ReportData]);
    assert_eq!(r.exit_code(), 1);
}

#[test]
fn relay_lying_about_spki_still_fails_on_report_data() {
    // A relay rewrites `spki_sha256` to ours, but cannot change the signed
    // report_data (here: the mock blob computed over the real key).
    let f = fixture();
    let mut v: serde_json::Value =
        serde_json::from_slice(&doc(&f, f.nonce, SpkiSha256([6; 32]), &f.app_compose)).unwrap();
    v["spki_sha256"] = serde_json::Value::String(f.spki.to_hex());
    let r = run(&f, &serde_json::to_vec(&v).unwrap(), true);
    assert_eq!(failed(&r), vec![CheckId::ReportData]);
}

#[test]
fn replayed_nonce_fails() {
    let f = fixture();
    let r = run(&f, &doc(&f, Nonce([1; 32]), f.spki, &f.app_compose), true);
    assert_eq!(failed(&r), vec![CheckId::Nonce, CheckId::ReportData]);
}

#[test]
fn tampered_compose_fails_on_hash() {
    let f = fixture();
    let tampered = f.app_compose.replace("\"t\"", "\"t2\"");
    let r = run(&f, &doc(&f, f.nonce, f.spki, &tampered), true);
    assert_eq!(failed(&r), vec![CheckId::ComposeHash]);
}

#[test]
fn unpinned_image_fails() {
    let mut f = fixture();
    let ac = serde_json::json!({
        "docker_compose_file": "services:\n  vaultwarden:\n    image: vaultwarden/server:latest\n",
    })
    .to_string();
    f.policy.mock = Some(MockPolicy {
        compose_hash: hex::encode(compose::compose_hash(ac.as_bytes())),
    });
    let r = run(&f, &doc(&f, f.nonce, f.spki, &ac), true);
    assert_eq!(failed(&r), vec![CheckId::Images]);
    assert!(r.to_string().contains("not pinned"));
}

#[test]
fn platform_mismatch_fails() {
    let mut f = fixture();
    f.policy.platform = Platform::Tdx;
    let r = run(&f, &doc(&f, f.nonce, f.spki, &f.app_compose), true);
    assert_eq!(failed(&r), vec![CheckId::Fetch]);
}

#[test]
fn garbage_document_fails() {
    let f = fixture();
    let r = run(&f, b"<html>hello</html>", true);
    assert_eq!(failed(&r), vec![CheckId::Fetch]);
}

#[test]
fn pre_launch_script_fails_config_check() {
    let mut f = fixture();
    let ac = serde_json::json!({
        "docker_compose_file": format!("services:\n  vaultwarden:\n    image: {}\n", image()),
        "pre_launch_script": "docker run --rm evil/image",
    })
    .to_string();
    f.policy.mock = Some(MockPolicy {
        compose_hash: hex::encode(compose::compose_hash(ac.as_bytes())),
    });
    let r = run(&f, &doc(&f, f.nonce, f.spki, &ac), true);
    assert_eq!(failed(&r), vec![CheckId::Config], "{r}");
    f.policy.pre_launch_script_sha256 = compose::pre_launch_script_sha256(&ac);
    let r = run(&f, &doc(&f, f.nonce, f.spki, &ac), true);
    assert!(failed(&r).is_empty(), "{r}");
}
