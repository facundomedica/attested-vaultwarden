//! Offline TDX tests against recorded upstream fixtures (see testdata/SOURCES.md).
//! Negative cases mutate in-memory copies of real evidence.

use super::tdx::*;
use dcap_qvl::QuoteCollateralV3;

pub(crate) struct DstackFixture {
    pub quote: Vec<u8>,
    pub event_log: String,
    pub collateral: QuoteCollateralV3,
    /// Time the collateral was recorded (inside its validity window).
    pub now: u64,
}

pub(crate) fn dstack_fixture() -> DstackFixture {
    let gq: serde_json::Value =
        serde_json::from_str(include_str!("../testdata/dstack/tdx-lite-getquote.json")).unwrap();
    let rec: serde_json::Value =
        serde_json::from_str(include_str!("../testdata/dstack/tdx-lite-collateral.json")).unwrap();
    DstackFixture {
        quote: hex::decode(gq["quote"].as_str().unwrap()).unwrap(),
        event_log: gq["event_log"].as_str().unwrap().to_owned(),
        collateral: serde_json::from_value(rec["collateral"].clone()).unwrap(),
        now: rec["recorded_at_unix"].as_u64().unwrap(),
    }
}

/// The dstack fixture's PCK certificate has `dynamicPlatform`, `cachedKeys`
/// and `smtEnabled` all true, so its policy must opt in to all three.
pub(crate) const FIXTURE_FLAGS: PlatformFlags = PlatformFlags {
    smt: true,
    dynamic_platform: true,
    cached_keys: true,
};

fn up_to_date() -> Vec<String> {
    vec!["UpToDate".into()]
}

// Expected values read from the fixture with an independent script
// (python: parse the TD report body at the TDX quote v4 offsets).
const FIXTURE_MRTD: &str = "f2032d37d482f3aaa3b482e7df8cd917eb8641d99d51bab64cff6e549d15f58eb4dc7f207365fd424a84935c79b8cb74";

#[test]
fn dstack_quote_verifies_offline() {
    let f = dstack_fixture();
    let v = verify_quote(&f.quote, &f.collateral, f.now, &up_to_date(), FIXTURE_FLAGS).unwrap();
    assert_eq!(v.tcb_status, "UpToDate");
    assert_eq!(v.report_data, [0x42; 64]);
    assert_eq!(hex::encode(v.mr_td), FIXTURE_MRTD);
    check_td_attributes(&v.td_attributes).unwrap();
}

#[test]
fn bad_signature_fails() {
    let f = dstack_fixture();
    let mut q = f.quote.clone();
    // Flip one bit of report_data inside the signed TD report body
    // (header 48 bytes + report_data at offset 520 of the body).
    q[48 + 520] ^= 0x01;
    let e = verify_quote(&q, &f.collateral, f.now, &up_to_date(), FIXTURE_FLAGS).unwrap_err();
    assert!(matches!(e, TdxError::Quote(_)), "{e}");
}

#[test]
fn truncated_quote_fails() {
    let f = dstack_fixture();
    let e = verify_quote(
        &f.quote[..600],
        &f.collateral,
        f.now,
        &up_to_date(),
        FIXTURE_FLAGS,
    )
    .unwrap_err();
    assert!(matches!(e, TdxError::Quote(_)), "{e}");
}

#[test]
fn strict_platform_flags_reject_fixture() {
    let f = dstack_fixture();
    let e = verify_quote(
        &f.quote,
        &f.collateral,
        f.now,
        &up_to_date(),
        PlatformFlags::default(),
    )
    .unwrap_err();
    assert!(e.to_string().contains("not allowed by policy"), "{e}");
}

#[test]
fn expired_collateral_fails() {
    let f = dstack_fixture();
    let a_year_later = f.now + 365 * 24 * 3600;
    let e = verify_quote(
        &f.quote,
        &f.collateral,
        a_year_later,
        &up_to_date(),
        FIXTURE_FLAGS,
    )
    .unwrap_err();
    assert!(matches!(e, TdxError::Quote(_)), "{e}");
}

#[test]
fn collateral_from_another_platform_fails() {
    // dcap-qvl's sample collateral belongs to a different FMSPC.
    let f = dstack_fixture();
    let other: QuoteCollateralV3 = serde_json::from_str(include_str!(
        "../testdata/dcap-qvl/tdx_quote_collateral.json"
    ))
    .unwrap();
    assert!(verify_quote(&f.quote, &other, f.now, &up_to_date(), FIXTURE_FLAGS).is_err());
}

#[test]
fn outdated_tcb_rejected() {
    // dcap-qvl's "outdated" sample: its TCB matches no level in the recorded
    // TCB info, which dcap-qvl treats as a hard failure.
    let quote = include_bytes!("../testdata/dcap-qvl/tdx_quote_outdated");
    let coll: QuoteCollateralV3 = serde_json::from_str(include_str!(
        "../testdata/dcap-qvl/tdx_quote_outdated_collateral.json"
    ))
    .unwrap();
    // One day after the collateral's issueDate 2026-02-18T10:58:51Z.
    let now = 1_771_412_331 + 86_400;
    let flags = PlatformFlags {
        smt: true,
        dynamic_platform: true,
        cached_keys: true,
    };
    let e = verify_quote(quote, &coll, now, &up_to_date(), flags).unwrap_err();
    assert!(e.to_string().contains("TCB"), "{e}");
}

#[test]
fn dcap_qvl_sample_verifies() {
    let quote = include_bytes!("../testdata/dcap-qvl/tdx_quote");
    let coll: QuoteCollateralV3 = serde_json::from_str(include_str!(
        "../testdata/dcap-qvl/tdx_quote_collateral.json"
    ))
    .unwrap();
    // One day after issueDate 2025-06-19T10:16:03Z.
    let now = 1_750_328_163 + 86_400;
    let flags = PlatformFlags {
        smt: true,
        dynamic_platform: true,
        cached_keys: true,
    };
    let all: Vec<String> = [
        "UpToDate",
        "SWHardeningNeeded",
        "ConfigurationNeeded",
        "ConfigurationAndSWHardeningNeeded",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    verify_quote(quote, &coll, now, &all, flags).unwrap();
}

#[test]
fn unknown_tcb_status_in_policy_is_an_error() {
    let f = dstack_fixture();
    let e = verify_quote(
        &f.quote,
        &f.collateral,
        f.now,
        &["Fine".into()],
        FIXTURE_FLAGS,
    )
    .unwrap_err();
    assert!(matches!(e, TdxError::BadPolicyStatus(_)));
}

#[test]
fn debug_attribute_rejected() {
    // A genuine debug quote is not available as a fixture; dcap-qvl rejects
    // TUD.DEBUG itself, and this tests our own second check.
    assert!(matches!(
        check_td_attributes(&[0x01, 0, 0, 0, 0, 0, 0, 0]),
        Err(TdxError::Debug)
    ));
    assert!(check_td_attributes(&[0x00, 0, 0, 0, 0, 0, 0, 0x10]).is_ok());
}

#[test]
fn rtmr3_replay_matches_quote() {
    let f = dstack_fixture();
    let v = verify_quote(&f.quote, &f.collateral, f.now, &up_to_date(), FIXTURE_FLAGS).unwrap();
    let events = check_rtmr3(&f.event_log, &v.rt_mr[3]).unwrap();
    let names: Vec<&str> = events.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "system-preparing",
            "app-id",
            "compose-hash",
            "gpu-policy-hash",
            "instance-id",
            "boot-mr-done",
            "key-provider",
            "storage-fs",
            "system-ready"
        ]
    );
    let facts = rtmr3_facts(&events).unwrap();
    assert_eq!(
        hex::encode(facts.compose_hash),
        "60618cd0c23d15d921b788b8fc3a0d024ac72295185da3ba41d5a065bc7aa833"
    );
    assert_eq!(
        hex::encode(&facts.app_id),
        "60618cd0c23d15d921b788b8fc3a0d024ac72295"
    );
    assert_eq!(facts.key_provider, r#"{"name":"none","id":""}"#);
}

fn mutate_event(log: &str, name: &str, f: impl Fn(&mut serde_json::Value)) -> String {
    let mut v: Vec<serde_json::Value> = serde_json::from_str(log).unwrap();
    for e in v.iter_mut() {
        if e["event"] == name {
            f(e);
        }
    }
    serde_json::to_string(&v).unwrap()
}

#[test]
fn swapped_compose_hash_fails_replay() {
    // Attacker substitutes the published compose hash, with a consistent
    // digest field: RTMR3 no longer matches the signed quote.
    let f = dstack_fixture();
    let v = verify_quote(&f.quote, &f.collateral, f.now, &up_to_date(), FIXTURE_FLAGS).unwrap();
    let fake = [0xaa_u8; 32];
    let log = mutate_event(&f.event_log, "compose-hash", |e| {
        e["event_payload"] = hex::encode(fake).into();
        e["digest"] = hex::encode(runtime_event_digest("compose-hash", &fake)).into();
    });
    let e = check_rtmr3(&log, &v.rt_mr[3]).unwrap_err();
    assert!(matches!(e, TdxError::Rtmr3Mismatch { .. }), "{e}");
}

#[test]
fn inconsistent_digest_field_rejected() {
    let f = dstack_fixture();
    let log = mutate_event(&f.event_log, "compose-hash", |e| {
        e["event_payload"] = hex::encode([0xaa_u8; 32]).into();
    });
    let e = replay_rtmr3(&log).unwrap_err();
    assert!(e.to_string().contains("digest field"), "{e}");
}

#[test]
fn unknown_rtmr3_event_rejected() {
    let f = dstack_fixture();
    let log = mutate_event(&f.event_log, "storage-fs", |e| {
        e["event"] = "evil".into();
    });
    let e = replay_rtmr3(&log).unwrap_err();
    assert!(e.to_string().contains("unknown RTMR3 event"), "{e}");
}

#[test]
fn compose_hash_after_boot_rejected() {
    let ev = |n: &str, p: &[u8]| RuntimeEvent {
        name: n.into(),
        payload: p.to_vec(),
    };
    let events = vec![
        ev("app-id", &[1; 20]),
        ev("boot-mr-done", &[]),
        ev("compose-hash", &[2; 32]),
        ev("key-provider", b"{}"),
    ];
    assert!(rtmr3_facts(&events).is_err());
    let dup = vec![
        ev("app-id", &[1; 20]),
        ev("compose-hash", &[2; 32]),
        ev("compose-hash", &[3; 32]),
        ev("boot-mr-done", &[]),
        ev("key-provider", b"{}"),
    ];
    assert!(
        rtmr3_facts(&dup)
            .unwrap_err()
            .to_string()
            .contains("more than one")
    );
}
