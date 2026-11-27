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
    let v = verify_quote(
        &f.quote,
        &f.collateral,
        f.now,
        &up_to_date(),
        20,
        FIXTURE_FLAGS,
    )
    .unwrap();
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
    let e = verify_quote(&q, &f.collateral, f.now, &up_to_date(), 20, FIXTURE_FLAGS).unwrap_err();
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
        20,
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
        20,
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
        20,
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
    assert!(verify_quote(&f.quote, &other, f.now, &up_to_date(), 20, FIXTURE_FLAGS).is_err());
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
    let e = verify_quote(quote, &coll, now, &up_to_date(), 0, flags).unwrap_err();
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
    verify_quote(quote, &coll, now, &all, 17, flags).unwrap();
}

#[test]
fn unknown_tcb_status_in_policy_is_an_error() {
    let f = dstack_fixture();
    let e = verify_quote(
        &f.quote,
        &f.collateral,
        f.now,
        &["Fine".into()],
        20,
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
    let v = verify_quote(
        &f.quote,
        &f.collateral,
        f.now,
        &up_to_date(),
        20,
        FIXTURE_FLAGS,
    )
    .unwrap();
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
    let v = verify_quote(
        &f.quote,
        &f.collateral,
        f.now,
        &up_to_date(),
        20,
        FIXTURE_FLAGS,
    )
    .unwrap();
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

fn ev(n: &str, p: &[u8]) -> RuntimeEvent {
    RuntimeEvent {
        name: n.into(),
        payload: p.to_vec(),
    }
}

/// The sequence the live dstack 0.6.5 / Phala KMS deployment produces (11
/// events): the upstream fixture's nine plus `os-image-hash` and
/// `storage-encrypted`.
fn live_sequence() -> Vec<RuntimeEvent> {
    vec![
        ev("system-preparing", b""),
        ev("app-id", &[1; 20]),
        ev("compose-hash", &[2; 32]),
        ev("gpu-policy-hash", &[3; 32]),
        ev("instance-id", &[4; 20]),
        ev("boot-mr-done", b""),
        ev("os-image-hash", &[5; 32]),
        ev("key-provider", br#"{"name":"kms","id":"30"}"#),
        ev("storage-fs", b"zfs"),
        ev("storage-encrypted", b"1"),
        ev("system-ready", b""),
    ]
}

fn events_err(events: &[RuntimeEvent]) -> String {
    rtmr3_facts(events).unwrap_err().to_string()
}

fn without(events: &[RuntimeEvent], name: &str) -> Vec<RuntimeEvent> {
    events.iter().filter(|e| e.name != name).cloned().collect()
}

fn insert_after(events: &[RuntimeEvent], after: &str, new: RuntimeEvent) -> Vec<RuntimeEvent> {
    let mut v = events.to_vec();
    let i = v.iter().position(|e| e.name == after).unwrap();
    v.insert(i + 1, new);
    v
}

#[test]
fn rtmr3_exact_sequence_accepted() {
    let live = live_sequence();
    let f = rtmr3_facts(&live).unwrap();
    assert_eq!(f.compose_hash, [2; 32]);
    assert_eq!(f.app_id, [1; 20]);
    assert_eq!(f.key_provider, r#"{"name":"kms","id":"30"}"#);
    assert_eq!(f.storage_encrypted, Some(true));
    // Optional events may be absent; the two key events come in either order.
    for optional in ["gpu-policy-hash", "os-image-hash", "storage-encrypted"] {
        rtmr3_facts(&without(&live, optional)).unwrap();
    }
    let mut swapped = live.clone();
    swapped.swap(6, 7);
    rtmr3_facts(&swapped).unwrap();
    assert_eq!(
        rtmr3_facts(&without(&live, "storage-encrypted"))
            .unwrap()
            .storage_encrypted,
        None
    );
}

#[test]
fn rtmr3_required_events_and_order() {
    let live = live_sequence();
    for required in [
        "system-preparing",
        "app-id",
        "compose-hash",
        "instance-id",
        "boot-mr-done",
        "key-provider",
        "storage-fs",
        "system-ready",
    ] {
        assert!(
            rtmr3_facts(&without(&live, required)).is_err(),
            "{required}"
        );
    }
    // compose-hash measured after boot-mr-done (by something other than the
    // OS boot path).
    let mut late = without(&live, "compose-hash");
    late = insert_after(&late, "boot-mr-done", ev("compose-hash", &[2; 32]));
    assert!(
        events_err(&late).contains("where `instance-id` is expected")
            || events_err(&late).contains("expected")
    );
    // storage-encrypted must sit between storage-fs and system-ready.
    let mut moved = without(&live, "storage-encrypted");
    moved = insert_after(&moved, "boot-mr-done", ev("storage-encrypted", b"1"));
    assert!(rtmr3_facts(&moved).is_err());
    // Any two neighbours swapped (other than the two key events) is refused.
    for i in 0..live.len() - 1 {
        if i == 6 {
            continue;
        }
        let mut s = live.clone();
        s.swap(i, i + 1);
        assert!(rtmr3_facts(&s).is_err(), "swap {i}");
    }
    assert!(rtmr3_facts(&[]).is_err());
}

#[test]
fn rtmr3_events_after_system_ready_rejected() {
    let live = live_sequence();
    // A container extending RTMR3 through the guest agent after boot, even
    // with a known event name.
    for extra in [
        ev("key-provider", br#"{"name":"none","id":""}"#),
        ev("compose-hash", &[9; 32]),
        ev("storage-fs", b"zfs"),
        ev("system-ready", b""),
        ev("os-image-hash", &[9; 32]),
    ] {
        let mut v = live.clone();
        let name = extra.name.clone();
        v.push(extra);
        assert!(rtmr3_facts(&v).is_err(), "{name} after system-ready");
    }
    let mut v = without(&live, "os-image-hash");
    v.push(ev("os-image-hash", &[9; 32]));
    assert!(
        events_err(&v).contains("after `system-ready`"),
        "{}",
        events_err(&v)
    );
}

#[test]
fn rtmr3_duplicates_rejected() {
    let live = live_sequence();
    for e in &live {
        let dup = insert_after(&live, &e.name, e.clone());
        let msg = events_err(&dup);
        assert!(msg.contains("more than one"), "{}: {msg}", e.name);
    }
}

#[test]
fn rtmr3_refused_events() {
    let live = live_sequence();
    let init = insert_after(&live, "compose-hash", ev("init-script-hash", &[7; 32]));
    assert!(events_err(&init).contains("init script"));
    let gpu = insert_after(&live, "boot-mr-done", ev("gpu-attestation", &[7; 32]));
    assert!(events_err(&gpu).contains("GPU"));
    let mut marker = live.clone();
    marker[5].payload = b"x".to_vec();
    assert!(events_err(&marker).contains("carries a payload"));
    let mut short = live.clone();
    short[2].payload = vec![2; 31];
    assert!(events_err(&short).contains("32 bytes"));
}

#[test]
fn storage_encrypted_event() {
    let base = |enc: &[u8]| {
        let mut v = live_sequence();
        v[9].payload = enc.to_vec();
        v
    };
    assert_eq!(
        rtmr3_facts(&base(b"1")).unwrap().storage_encrypted,
        Some(true)
    );
    let e = rtmr3_facts(&base(b"0")).unwrap_err();
    assert!(e.to_string().contains("NOT encrypted"), "{e}");
    assert!(rtmr3_facts(&base(b"yes")).is_err());
}

/// TCB rollback through the collateral source: the same quote and the same
/// Intel-signed collateral (evaluation data number 20) must be refused by a
/// policy that requires a newer data set, and the number is reported.
#[test]
fn tcb_eval_data_number_floor() {
    let f = dstack_fixture();
    let v = verify_quote(
        &f.quote,
        &f.collateral,
        f.now,
        &up_to_date(),
        20,
        FIXTURE_FLAGS,
    )
    .unwrap();
    assert_eq!(v.tcb_eval_data_number, 20);
    let e = verify_quote(
        &f.quote,
        &f.collateral,
        f.now,
        &up_to_date(),
        21,
        FIXTURE_FLAGS,
    )
    .unwrap_err();
    assert!(matches!(e, TdxError::Quote(_)), "{e}");
    assert!(e.to_string().to_lowercase().contains("eval"), "{e}");
}

/// `accepted_tcb_status` is the exact set: dcap-qvl's strict policy always
/// adds UpToDate, so a list without it must still reject an UpToDate quote.
#[test]
fn accepted_tcb_status_is_exact() {
    let f = dstack_fixture();
    let only = vec!["SWHardeningNeeded".to_owned()];
    let e = verify_quote(&f.quote, &f.collateral, f.now, &only, 20, FIXTURE_FLAGS).unwrap_err();
    assert!(
        matches!(&e, TdxError::TcbStatus { status, .. } if status == "UpToDate"),
        "{e}"
    );
    let e = verify_quote(&f.quote, &f.collateral, f.now, &[], 20, FIXTURE_FLAGS).unwrap_err();
    assert!(matches!(e, TdxError::TcbStatus { .. }), "{e}");
    let e = verify_quote(
        &f.quote,
        &f.collateral,
        f.now,
        &["Revoked".to_owned()],
        20,
        FIXTURE_FLAGS,
    )
    .unwrap_err();
    assert!(matches!(e, TdxError::TcbStatus { .. }), "{e}");
}

fn tdx_policy() -> attested_vw_common::policy::TdxPolicy {
    attested_vw_common::policy::TdxPolicy {
        mrtd: String::new(),
        rtmr0: String::new(),
        rtmr1: String::new(),
        rtmr2: String::new(),
        compose_hash: String::new(),
        accepted_tcb_status: up_to_date(),
        min_tcb_eval_data_number: 20,
        allow_smt: true,
        allow_dynamic_platform: true,
        allow_cached_keys: true,
        app_id: None,
        key_provider: None,
        mr_config_id: None,
        mr_owner: None,
        mr_owner_config: None,
        require_storage_encrypted: false,
    }
}

#[test]
fn launch_fields() {
    let f = dstack_fixture();
    let base = verify_quote(
        &f.quote,
        &f.collateral,
        f.now,
        &up_to_date(),
        20,
        FIXTURE_FLAGS,
    )
    .unwrap();
    let ch = [0x22u8; 32];
    let tp = tdx_policy();
    // The real fixture quote carries a dstack v1 config id (0x01 ‖ its
    // compose hash): it passes for that compose hash and no other.
    let fixture_ch: [u8; 32] =
        hex::decode("60618cd0c23d15d921b788b8fc3a0d024ac72295185da3ba41d5a065bc7aa833")
            .unwrap()
            .try_into()
            .unwrap();
    assert_eq!(base.mr_config_id[0], 1);
    assert_eq!(check_launch_fields(&base, &tp, &fixture_ch), (vec![], None));
    assert_eq!(check_launch_fields(&base, &tp, &ch).0.len(), 1);

    let run = |edit: &dyn Fn(&mut VerifiedQuote), tp: &attested_vw_common::policy::TdxPolicy| {
        let mut q = base.clone();
        edit(&mut q);
        check_launch_fields(&q, tp, &ch)
    };
    // Zero everywhere: fine.
    let zero = |q: &mut VerifiedQuote| {
        q.mr_config_id = [0; 48];
        q.mr_owner = [0; 48];
        q.mr_owner_config = [0; 48];
    };
    assert_eq!(run(&zero, &tp), (vec![], None));
    // Non-zero MROWNER / MROWNERCONFIG: refused unless pinned.
    let owner = |q: &mut VerifiedQuote| {
        zero(q);
        q.mr_owner = [0xaa; 48];
    };
    assert_eq!(run(&owner, &tp).0.len(), 1);
    let mut pinned = tp.clone();
    pinned.mr_owner = Some("aa".repeat(48));
    assert!(run(&owner, &pinned).0.is_empty());
    assert_eq!(run(&zero, &pinned).0.len(), 1, "pin must match exactly");
    let owner_cfg = |q: &mut VerifiedQuote| {
        zero(q);
        q.mr_owner_config[47] = 1;
    };
    assert_eq!(run(&owner_cfg, &tp).0.len(), 1);

    // MRCONFIGID: dstack v1 = 0x01 ‖ compose hash, recomputed.
    let v1 = |q: &mut VerifiedQuote| {
        zero(q);
        q.mr_config_id[0] = 1;
        q.mr_config_id[1..33].copy_from_slice(&ch);
    };
    assert_eq!(run(&v1, &tp), (vec![], None));
    let v1_other = |q: &mut VerifiedQuote| {
        v1(q);
        q.mr_config_id[5] ^= 1;
    };
    assert_eq!(run(&v1_other, &tp).0.len(), 1);
    // v2 / v3: accepted by shape with a note; garbage refused.
    for ver in [2u8, 3] {
        let shaped = move |q: &mut VerifiedQuote| {
            zero(q);
            q.mr_config_id[0] = ver;
            q.mr_config_id[1..33].copy_from_slice(&[0x77; 32]);
        };
        let (p, note) = run(&shaped, &tp);
        assert!(p.is_empty() && note.is_some_and(|n| n.contains("not recomputed")));
        let padded = move |q: &mut VerifiedQuote| {
            shaped(q);
            q.mr_config_id[40] = 1;
        };
        assert_eq!(run(&padded, &tp).0.len(), 1);
        let mut pin = tp.clone();
        pin.mr_config_id = Some("00".repeat(48));
        assert_eq!(run(&shaped, &pin).0.len(), 1, "a pin is exact");
    }
    let junk = |q: &mut VerifiedQuote| {
        zero(q);
        q.mr_config_id = [0x55; 48];
    };
    assert_eq!(run(&junk, &tp).0.len(), 1);
    let mut pin = tp.clone();
    pin.mr_config_id = Some("55".repeat(48));
    assert_eq!(run(&junk, &pin), (vec![], None));
}
