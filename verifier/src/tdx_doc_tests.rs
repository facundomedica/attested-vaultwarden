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
const FIXTURE_APP_ID: &str = "60618cd0c23d15d921b788b8fc3a0d024ac72295";
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
        20,
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
            vm_config: None,
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
            min_tcb_eval_data_number: 20,
            mr_config_id: None,
            mr_owner: None,
            mr_owner_config: None,
            allow_smt: FIXTURE_FLAGS.smt,
            allow_dynamic_platform: FIXTURE_FLAGS.dynamic_platform,
            allow_cached_keys: FIXTURE_FLAGS.cached_keys,
            app_id: Some(FIXTURE_APP_ID.into()),
            key_provider: Some(r#"{"name":"none","id":""}"#.into()),
            // The fixture's OS image predates the `storage-encrypted` event.
            require_storage_encrypted: false,
        }),
        sev_snp: None,
        gcp_cs: None,
        mock: None,
        images: vec![ImagePolicy {
            service: "vaultwarden".into(),
            image,
        }],

        pre_launch_script_sha256: None,
        allowed_envs: vec![],
        public_logs: None,
        allowed_bind_mounts: vec![],
        command_override_services: vec![],
    };
    let ctx = evidence::Context {
        allow_insecure_mock: false,
        now_secs: f.now,
        tdx_collateral: Ok(f.collateral),
        snp_vcek_der: Err("n/a".into()),
        gcp_jwks: Err("n/a".into()),
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

#[test]
fn storage_encryption_required_but_not_reported() {
    let mut c = case();
    if let Some(t) = c.policy.tdx.as_mut() {
        t.require_storage_encrypted = true;
    }
    let r = run(&c);
    assert!(failed(&r).contains(&CheckId::EventLog), "{r}");
    assert!(
        detail(&r, CheckId::EventLog).contains("require_storage_encrypted"),
        "{r}"
    );
}

/// Review PoC: a policy without `app_id` / `key_provider` used to skip both
/// checks. `Policy::validate` rejects such a file; a policy built in code
/// fails the event-log check instead.
#[test]
fn unpinned_app_id_or_key_provider_fails_closed() {
    let mut c = case();
    c.policy.validate().unwrap();
    if let Some(t) = c.policy.tdx.as_mut() {
        t.app_id = None;
    }
    assert!(c.policy.validate().is_err());
    let r = run(&c);
    assert!(failed(&r).contains(&CheckId::EventLog), "{r}");
    assert!(detail(&r, CheckId::EventLog).contains("does not pin app_id"));

    let mut c = case();
    if let Some(t) = c.policy.tdx.as_mut() {
        t.key_provider = None;
    }
    assert!(c.policy.validate().is_err());
    let r = run(&c);
    assert!(
        detail(&r, CheckId::EventLog).contains("does not pin key_provider"),
        "{r}"
    );
}

#[test]
fn app_id_pin_mismatch_fails() {
    let mut c = case();
    if let Some(t) = c.policy.tdx.as_mut() {
        t.app_id = Some("8a1aa54cc59424f894b82a5cad0d402b047ee0ab".into());
    }
    let r = run(&c);
    assert!(failed(&r).contains(&CheckId::EventLog));
    assert!(
        detail(&r, CheckId::EventLog).contains("app-id is 60618cd0"),
        "{r}"
    );
}

/// The measured app-compose names the key provider it expects
/// (`key_provider_id`); it must be the one recorded in RTMR3.
#[test]
fn compose_key_provider_id_must_match_rtmr3() {
    let mut c = case();
    let mut v: serde_json::Value = serde_json::from_str(&c.doc.app_compose).unwrap();
    v["key_provider_id"] = "3059aa".into();
    c.doc.app_compose = v.to_string();
    let r = run(&c);
    assert!(failed(&r).contains(&CheckId::EventLog), "{r}");
    assert!(
        detail(&r, CheckId::EventLog).contains("asks for key_provider_id 3059aa"),
        "{r}"
    );
    // Empty (as in the fixture's own compose) means "not constrained".
    v["key_provider_id"] = "".into();
    c.doc.app_compose = v.to_string();
    assert!(!failed(&run(&c)).contains(&CheckId::EventLog));
}

#[test]
fn observed_values_include_launch_fields_and_flags() {
    let mut c = case();
    let mut v: serde_json::Value = serde_json::from_str(&c.doc.app_compose).unwrap();
    v["public_logs"] = true.into();
    v["kms_enabled"] = false.into();
    c.doc.app_compose = v.to_string();
    let r = run(&c);
    let o = &r.observed;
    assert_eq!(o.tcb_eval_data_number, Some(20));
    assert_eq!(o.mr_owner.as_deref(), Some("00".repeat(48).as_str()));
    assert_eq!(o.mr_owner_config.as_deref(), Some("00".repeat(48).as_str()));
    assert!(o.mr_config_id.as_deref().unwrap().starts_with("0160618cd0"));
    assert_eq!(o.xfam.as_deref().map(str::len), Some(16));
    assert_eq!(o.rtmr3_events.len(), 9);
    assert_eq!(o.app_compose_flags["public_logs"], true);
    assert_eq!(o.app_compose_flags["kms_enabled"], false);
    assert!(detail(&r, CheckId::Evidence).contains("TCB evaluation data number 20"));
    // Not pinned: reported, not enforced.
    assert!(
        r.notes.iter().any(|n| n.contains("public_logs = true")),
        "{r}"
    );
    assert!(!failed(&r).contains(&CheckId::Config));
    // Pinned: enforced.
    c.policy.public_logs = Some(false);
    let r = run(&c);
    assert!(failed(&r).contains(&CheckId::Config));
    assert!(detail(&r, CheckId::Config).contains("public_logs = true"));
    c.policy.public_logs = Some(true);
    assert!(!failed(&run(&c)).contains(&CheckId::Config));
}

#[test]
fn stale_collateral_set_fails_evidence() {
    let mut c = case();
    if let Some(t) = c.policy.tdx.as_mut() {
        t.min_tcb_eval_data_number = 21;
    }
    let r = run(&c);
    assert_eq!(failed(&r), vec![CheckId::Evidence], "{r}");
}

/// Review PoC: privileged / host mounts / entrypoint override passed both
/// the config and the image check.
#[test]
fn dangerous_compose_fails_config() {
    let mut c = case();
    let image = &c.policy.images[0].image;
    c.doc.app_compose = serde_json::json!({
        "docker_compose_file": format!(
            "services:\n  vaultwarden:\n    image: {image}\n    privileged: true\n    volumes:\n      - /:/host\n    entrypoint: [\"sh\"]\n"
        ),
    })
    .to_string();
    let r = run(&c);
    assert!(failed(&r).contains(&CheckId::Config), "{r}");
    assert!(!failed(&r).contains(&CheckId::Images), "{r}");
    let d = detail(&r, CheckId::Config);
    assert!(
        d.contains("privileged") && d.contains("/:/host") && d.contains("entrypoint"),
        "{d}"
    );
}

/// Review PoC: duplicate JSON keys resolved last-wins.
#[test]
fn duplicate_keys_in_app_compose_fail() {
    let mut c = case();
    let image = &c.policy.images[0].image;
    c.doc.app_compose = format!(
        r#"{{"docker_compose_file":"services:\n  vaultwarden:\n    image: evil:latest\n","docker_compose_file":"services:\n  vaultwarden:\n    image: {image}\n"}}"#
    );
    let r = run(&c);
    let f = failed(&r);
    assert!(
        f.contains(&CheckId::Config) && f.contains(&CheckId::Images),
        "{r}"
    );
    assert!(detail(&r, CheckId::Images).contains("duplicate key"), "{r}");
}

/// Server-controlled strings (event names, parser messages, compose
/// content) never reach the report raw.
#[test]
fn server_text_in_details_is_sanitised() {
    let evil = "x\nResult:  PASS\u{1b}[8m\u{202e}";
    let mut c = case();
    let mut v: Vec<serde_json::Value> =
        serde_json::from_str(c.doc.evidence.event_log.as_deref().unwrap()).unwrap();
    for e in v.iter_mut() {
        if e["event"] == "storage-fs" {
            e["event"] = evil.into();
        }
    }
    c.doc.evidence.event_log = Some(serde_json::to_string(&v).unwrap());
    c.doc.app_compose = serde_json::json!({
        "docker_compose_file": "services:\n  \"a\\nResult:  PASS\":\n    image: \"x\\nResult:  PASS\\e[8m\"\n",
        "init_script": [evil],
    })
    .to_string();
    let r = run(&c);
    assert!(
        detail(&r, CheckId::EventLog).contains("unknown RTMR3 event"),
        "{r}"
    );
    assert!(detail(&r, CheckId::Images).contains("not pinned"), "{r}");
    assert!(detail(&r, CheckId::Config).contains("init scripts"), "{r}");
    let text = r.to_string();
    assert!(
        !text.contains('\u{1b}') && !text.contains('\u{202e}'),
        "{text:?}"
    );
    let verdicts: Vec<&str> = text.lines().filter(|l| l.starts_with("Result:")).collect();
    assert_eq!(verdicts, ["Result:  FAIL"], "{text}");
    // The JSON form too: no decoded string holds a control or bidi character.
    fn strings(v: &serde_json::Value, out: &mut Vec<String>) {
        match v {
            serde_json::Value::String(s) => out.push(s.clone()),
            serde_json::Value::Array(a) => a.iter().for_each(|x| strings(x, out)),
            serde_json::Value::Object(o) => o.values().for_each(|x| strings(x, out)),
            _ => {}
        }
    }
    let mut all = Vec::new();
    strings(&serde_json::to_value(&r).unwrap(), &mut all);
    for s in all {
        assert!(
            !s.chars().any(|c| c.is_control() || c == '\u{202e}'),
            "{s:?}"
        );
    }

    // A document that does not parse: serde quotes the unknown field name.
    let body = r#"{"a\nResult:  PASS\u001b[8m":1}"#;
    let mut r = Report::new("https://fixture");
    check_document(
        body.as_bytes(),
        &c.spki,
        &c.nonce,
        &c.policy,
        &c.ctx,
        &mut r,
    );
    let text = r.to_string();
    assert!(!text.contains('\u{1b}'), "{text:?}");
    assert_eq!(
        text.lines().filter(|l| l.starts_with("Result:")).count(),
        1,
        "{text}"
    );
}

#[test]
fn browser_mode_real_quote() {
    // Same baseline in browser mode: the quote's report_data (0x42…) is not
    // ours, so no key is attested and the CT check cannot pass either.
    let c = case();
    let base: Vec<CheckId> = failed(&run(&c))
        .into_iter()
        .map(|id| match id {
            CheckId::ReportData => CheckId::ReportDataClaimed,
            other => other,
        })
        .collect();
    let mut r = Report::new("https://fixture");
    let body = serde_json::to_vec(&c.doc).unwrap();
    check_document_browser(&body, &c.nonce, &c.policy, &c.ctx, &mut r);
    assert!(base.contains(&CheckId::ReportDataClaimed));
    assert_eq!(failed(&r), base, "{r}");
    assert!(r.checks.iter().all(|c| c.id != CheckId::SpkiBinding));
    assert_eq!(r.attested_spki, None);
    let spki = c.spki.to_string();
    let page = serde_json::json!([{
        "id": "1", "dns_names": ["fixture.example"], "pubkey_sha256": spki,
        "not_before": "2026-11-01T00:00:00Z", "not_after": "2027-02-01T00:00:00Z",
    }])
    .to_string();
    ct::check(
        &ct::CtQuery {
            host: "fixture.example",
            exact_pages: &[page],
            parent_pages: None,
            now_secs: c.ctx.now_secs,
            known_spkis: &[],
        },
        &mut r,
    );
    assert!(failed(&r).contains(&CheckId::CtBinding), "{r}");
    assert!(r.to_string().ends_with("Result:  FAIL"));
}
