//! Document-level tests with a REAL TDX quote and event log (dstack fixture).
//!
//! The fixture was captured upstream with `report_data = 0x42 × 64` and we do
//! not have its app-compose document, so an honest end-to-end PASS cannot be
//! built from it. Instead each test asserts exactly which checks fail and
//! why, which is what M2 is about: every failure is specific.

use super::*;
use crate::tdx_tests::{FIXTURE_FLAGS, dstack_fixture};
use attested_vw_common::policy::{ImagePolicy, TdxPolicy};
use attested_vw_common::schema::{Evidence, ImageDigest};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

const D: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const FIXTURE_COMPOSE_HASH: &str =
    "60618cd0c23d15d921b788b8fc3a0d024ac72295185da3ba41d5a065bc7aa833";

struct Case {
    doc: AttestationResponse,
    policy: Policy,
    ctx: evidence::Context,
    nonce: Nonce,
    spki: SpkiSha256,
}

fn case() -> Case {
    let f = dstack_fixture();
    let v = tdx::verify_quote(
        &f.quote,
        &f.collateral,
        f.now,
        &["UpToDate".into()],
        FIXTURE_FLAGS,
    )
    .unwrap();
    let image = format!("vaultwarden/server@sha256:{D}");
    let app_compose = serde_json::json!({
        "docker_compose_file": format!("services:\n  vaultwarden:\n    image: {image}\n"),
    })
    .to_string();
    let nonce = Nonce([7; 32]);
    let spki = SpkiSha256([8; 32]);
    let doc = AttestationResponse {
        version: SCHEMA_VERSION,
        platform: Platform::Tdx,
        evidence: Evidence {
            quote: B64.encode(&f.quote),
            event_log: Some(f.event_log.clone()),
            aux: None,
        },
        nonce,
        spki_sha256: spki,
        report_data_construction: report_data::CONSTRUCTION.into(),
        app_compose,
        image_digests: vec![ImageDigest {
            service: "vaultwarden".into(),
            image: image.clone(),
        }],
        timestamp: "2026-11-26T00:00:00Z".into(),
    };
    let policy = Policy {
        schema: 1,
        release: "fixture".into(),
        date: "2026-11-26".into(),
        platform: Platform::Tdx,
        tdx: Some(TdxPolicy {
            mrtd: hex::encode(v.mr_td),
            rtmr0: hex::encode(v.rt_mr[0]),
            rtmr1: hex::encode(v.rt_mr[1]),
            rtmr2: hex::encode(v.rt_mr[2]),
            compose_hash: FIXTURE_COMPOSE_HASH.into(),
            accepted_tcb_status: vec!["UpToDate".into()],
            allow_smt: FIXTURE_FLAGS.smt,
            allow_dynamic_platform: FIXTURE_FLAGS.dynamic_platform,
            allow_cached_keys: FIXTURE_FLAGS.cached_keys,
            app_id: None,
            key_provider: Some(r#"{"name":"none","id":""}"#.into()),
        }),
        sev_snp: None,
        mock: None,
        images: vec![ImagePolicy {
            service: "vaultwarden".into(),
            image,
        }],

        allow_pre_launch_script: false,
        allow_env_injection: false,
    };
    let ctx = evidence::Context {
        allow_insecure_mock: false,
        now_secs: f.now,
        tdx_collateral: Ok(f.collateral),
        snp_vcek_der: Err("n/a".into()),
    };
    Case {
        doc,
        policy,
        ctx,
        nonce,
        spki,
    }
}

fn run(c: &Case) -> Report {
    let mut r = Report::new("https://fixture");
    r.pass(CheckId::Tls, "test");
    let body = serde_json::to_vec(&c.doc).unwrap();
    check_document(&body, &c.spki, &c.nonce, &c.policy, &c.ctx, &mut r);
    r
}

fn failed(r: &Report) -> Vec<CheckId> {
    r.checks
        .iter()
        .filter(|c| !c.passed)
        .map(|c| c.id)
        .collect()
}

fn detail(r: &Report, id: CheckId) -> String {
    r.checks
        .iter()
        .find(|c| c.id == id)
        .map(|c| c.detail.clone())
        .unwrap_or_default()
}

#[test]
fn real_quote_baseline() {
    // Evidence, measurements and RTMR3 all verify; the quote was made for a
    // different nonce/TLS key (0x42…) and we lack its compose document.
    let c = case();
    let r = run(&c);
    assert_eq!(
        failed(&r),
        vec![CheckId::ReportData, CheckId::ComposeHash],
        "{r}"
    );
    assert!(detail(&r, CheckId::Evidence).contains("TCB UpToDate"));
    assert!(detail(&r, CheckId::EventLog).contains("9 RTMR3 events"));
    assert!(detail(&r, CheckId::ComposeHash).contains("not what runs"));
    assert_eq!(r.exit_code(), 1);
    // Observed values come from the signed quote and the replayed log.
    assert_eq!(
        r.observed.compose_hash_measured.as_deref(),
        Some(FIXTURE_COMPOSE_HASH)
    );
    assert_eq!(
        r.observed.key_provider.as_deref(),
        Some(r#"{"name":"none","id":""}"#)
    );
    assert_eq!(r.observed.tcb_status.as_deref(), Some("UpToDate"));
    assert_eq!(
        r.observed.pck_flags_set,
        vec!["smt", "dynamic_platform", "cached_keys"]
    );
}

#[test]
fn unknown_measurement_fails() {
    let mut c = case();
    if let Some(t) = c.policy.tdx.as_mut() {
        t.mrtd = "00".repeat(48);
    }
    let r = run(&c);
    assert!(failed(&r).contains(&CheckId::Measurements));
    assert!(detail(&r, CheckId::Measurements).contains("MRTD"));
}

#[test]
fn different_release_compose_hash_fails() {
    let mut c = case();
    if let Some(t) = c.policy.tdx.as_mut() {
        t.compose_hash = "11".repeat(32);
    }
    let r = run(&c);
    assert!(
        detail(&r, CheckId::ComposeHash).contains("different compose"),
        "{r}"
    );
}

#[test]
fn key_provider_pin_mismatch_fails() {
    let mut c = case();
    if let Some(t) = c.policy.tdx.as_mut() {
        t.key_provider = Some(r#"{"name":"kms","id":"x"}"#.into());
    }
    let r = run(&c);
    assert!(failed(&r).contains(&CheckId::EventLog));
    assert!(detail(&r, CheckId::EventLog).contains("key-provider"));
}

#[test]
fn tampered_event_log_fails() {
    let mut c = case();
    let mut v: Vec<serde_json::Value> =
        serde_json::from_str(c.doc.evidence.event_log.as_deref().unwrap()).unwrap();
    for e in v.iter_mut() {
        if e["event"] == "compose-hash" {
            let fake = [0xaa_u8; 32];
            e["event_payload"] = hex::encode(fake).into();
            e["digest"] = hex::encode(tdx::runtime_event_digest("compose-hash", &fake)).into();
        }
    }
    c.doc.evidence.event_log = Some(serde_json::to_string(&v).unwrap());
    let r = run(&c);
    assert!(
        detail(&r, CheckId::EventLog).contains("RTMR3 replay gives"),
        "{r}"
    );
}

#[test]
fn missing_event_log_fails() {
    let mut c = case();
    c.doc.evidence.event_log = None;
    let r = run(&c);
    assert!(failed(&r).contains(&CheckId::EventLog));
}

#[test]
fn bad_quote_signature_fails() {
    let mut c = case();
    let mut q = B64.decode(&c.doc.evidence.quote).unwrap();
    q[48 + 520] ^= 1;
    c.doc.evidence.quote = B64.encode(q);
    let r = run(&c);
    assert_eq!(failed(&r), vec![CheckId::Evidence]);
}

#[test]
fn no_collateral_fails() {
    let mut c = case();
    c.ctx.tdx_collateral = Err("network down".into());
    let r = run(&c);
    assert_eq!(failed(&r), vec![CheckId::Evidence]);
    assert!(detail(&r, CheckId::Evidence).contains("collateral"));
}

#[test]
fn quote_relabelled_as_mock_is_refused() {
    let mut c = case();
    c.doc.platform = Platform::Mock;
    let r = run(&c);
    // Policy says TDX: platform mismatch stops verification.
    assert_eq!(failed(&r), vec![CheckId::Fetch]);
}

#[test]
fn unpinned_image_fails_even_with_valid_quote() {
    let mut c = case();
    c.doc.app_compose = serde_json::json!({
        "docker_compose_file": "services:\n  vaultwarden:\n    image: vaultwarden/server:latest\n",
    })
    .to_string();
    let r = run(&c);
    assert!(failed(&r).contains(&CheckId::Images));
    assert!(detail(&r, CheckId::Images).contains("not pinned"));
}
