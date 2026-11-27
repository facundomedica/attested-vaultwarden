//! SEV-SNP binding tests with SYNTHETIC reports.
//!
//! No real SNP report with a non-zero `HOST_DATA` is available to this
//! project, so these tests take the upstream Milan report (a real,
//! AMD-signed report with `HOST_DATA` = 0), overwrite fields in the raw
//! bytes and re-sign with the test "VCEK" in `testdata/sev-synthetic`. That
//! chain is not AMD's; the verifier accepts it only under `cfg(test)`
//! (`snp::roots`). The tests therefore prove the verifier's logic on the
//! documented report layout, not that any real platform produces such a
//! report.

use super::*;
use attested_vw_common::policy::{ImagePolicy, SevSnpPolicy, SnpComposeBinding, SnpMinTcb};
use attested_vw_common::schema::{Evidence, ImageDigest};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use p384::ecdsa::signature::Signer;
use sev::firmware::host::TcbVersion;

/// Synthetic root for `snp::roots` (test builds only).
pub(crate) const SYNTHETIC_ROOT: (&str, &[u8], &[u8]) = (
    "SYNTHETIC-NOT-AMD",
    include_bytes!("../testdata/sev-synthetic/ark.pem"),
    include_bytes!("../testdata/sev-synthetic/ask.pem"),
);
const SYN_VCEK: &[u8] = include_bytes!("../testdata/sev-synthetic/vcek.der");
const SYN_KEY_HEX: &str = include_str!("../testdata/sev-synthetic/vcek.key.hex");
const REAL_REPORT_HEX: &str = include_str!("../testdata/sev/report_milan.hex");
const REAL_VCEK: &[u8] = include_bytes!("../testdata/sev/vcek_milan.der");
/// 2027-01-15: inside the validity of the synthetic chain and the real VCEK.
const NOW: u64 = 1_800_000_000;
const D: &str = "3333333333333333333333333333333333333333333333333333333333333333";

// Offsets in ATTESTATION_REPORT (AMD SEV-SNP ABI spec 56860, table
// "ATTESTATION_REPORT Structure").
const OFF_POLICY: usize = 0x08;
const OFF_VMPL: usize = 0x30;
const OFF_PLAT_INFO: usize = 0x40;
const OFF_KEY_INFO: usize = 0x48;
const OFF_REPORT_DATA: usize = 0x50;
const OFF_MEASUREMENT: usize = 0x90;
const OFF_HOST_DATA: usize = 0xC0;
const OFF_ID_KEY_DIGEST: usize = 0xE0;
const OFF_AUTHOR_KEY_DIGEST: usize = 0x110;
const OFF_COMMITTED_TCB: usize = 0x1E0;
const OFF_LAUNCH_TCB: usize = 0x1F0;
const OFF_SIGNATURE: usize = 0x2A0;

/// A policy with strict defaults and placeholder pins, for `..` updates.
pub(crate) fn base_policy(min: SnpMinTcb) -> SevSnpPolicy {
    SevSnpPolicy {
        measurement: String::new(),
        min_tcb: min,
        compose_binding: SnpComposeBinding::HostData,
        host_data: String::new(),
        allowed_vmpl: vec![0],
        allow_smt: false,
        require_alias_check: true,
        id_key_digest: None,
        author_key_digest: None,
    }
}

fn real_report() -> Vec<u8> {
    hex::decode(REAL_REPORT_HEX.trim()).unwrap()
}

/// Sign `report[..0x2A0]` with the synthetic VCEK (ECDSA P-384 / SHA-384,
/// r and s little-endian, zero-padded to 72 bytes each).
fn sign(report: &mut [u8]) {
    let key =
        p384::ecdsa::SigningKey::from_slice(&hex::decode(SYN_KEY_HEX.trim()).unwrap()).unwrap();
    let sig: p384::ecdsa::Signature = key.sign(&report[..OFF_SIGNATURE]);
    let (r, s) = (sig.r().to_bytes(), sig.s().to_bytes());
    report[OFF_SIGNATURE..].fill(0);
    for (i, b) in r.iter().rev().enumerate() {
        report[OFF_SIGNATURE + i] = *b;
    }
    for (i, b) in s.iter().rev().enumerate() {
        report[OFF_SIGNATURE + 72 + i] = *b;
    }
}

struct Fx {
    nonce: Nonce,
    spki: SpkiSha256,
    app_compose: String,
    policy: Policy,
}

fn image() -> String {
    format!("vaultwarden/server@sha256:{D}")
}

const MEASUREMENT: [u8; 48] = [0x5a; 48];

fn fx() -> Fx {
    let app_compose = serde_json::json!({
        "name": "snp",
        "docker_compose_file": format!("services:\n  vaultwarden:\n    image: {}\n", image()),
    })
    .to_string();
    let sev_snp = SevSnpPolicy {
        measurement: hex::encode(MEASUREMENT),
        host_data: hex::encode(compose::compose_hash(app_compose.as_bytes())),
        ..base_policy(SnpMinTcb {
            fmc: None,
            bootloader: 3,
            tee: 0,
            snp: 8,
            microcode: 115,
        })
    };
    let policy = Policy {
        schema: 1,
        release: "snp-test".into(),
        date: "2026-11-27".into(),
        platform: Platform::SevSnp,
        tdx: None,
        sev_snp: Some(sev_snp),
        gcp_cs: None,
        mock: None,
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
    policy.validate().unwrap();
    Fx {
        nonce: Nonce([7; 32]),
        spki: SpkiSha256([8; 32]),
        app_compose,
        policy,
    }
}

/// A report as an honest deployment of `f` would produce: pinned
/// measurement, HOST_DATA = SHA-256(app-compose), SMT off, alias check done.
/// `edit` may change any signed byte before signing.
fn synth(f: &Fx, edit: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut r = real_report();
    r[OFF_POLICY..OFF_POLICY + 8].copy_from_slice(&0x2_0000u64.to_le_bytes());
    r[OFF_PLAT_INFO..OFF_PLAT_INFO + 8].copy_from_slice(&(1u64 << 5).to_le_bytes());
    r[OFF_REPORT_DATA..OFF_REPORT_DATA + 64]
        .copy_from_slice(&report_data::compute(&f.nonce, &f.spki).0);
    r[OFF_MEASUREMENT..OFF_MEASUREMENT + 48].copy_from_slice(&MEASUREMENT);
    r[OFF_HOST_DATA..OFF_HOST_DATA + 32]
        .copy_from_slice(&compose::compose_hash(f.app_compose.as_bytes()));
    edit(&mut r);
    sign(&mut r);
    r
}

fn doc(f: &Fx, report: &[u8], app_compose: &str) -> Vec<u8> {
    serde_json::to_vec(&AttestationResponse {
        version: SCHEMA_VERSION,
        platform: Platform::SevSnp,
        evidence: Evidence {
            quote: B64.encode(report),
            event_log: None,
            aux: None,
            vm_config: None,
        },
        nonce: f.nonce,
        spki_sha256: f.spki,
        report_data_construction: report_data::CONSTRUCTION.into(),
        app_compose: app_compose.into(),
        image_digests: vec![ImageDigest {
            service: "vaultwarden".into(),
            image: image(),
        }],
        timestamp: "2026-11-27T00:00:00Z".into(),
    })
    .unwrap()
}

fn run_with(f: &Fx, body: &[u8], vcek: &[u8]) -> Report {
    let mut ctx = evidence::Context::mock(false);
    ctx.now_secs = NOW;
    ctx.snp_vcek_der = Ok(vcek.to_vec());
    let mut r = Report::new("https://snp.test");
    r.pass(CheckId::Tls, "test");
    check_document(body, &f.spki, &f.nonce, &f.policy, &ctx, &mut r);
    r
}

fn run(f: &Fx, report: &[u8], app_compose: &str) -> Report {
    run_with(f, &doc(f, report, app_compose), SYN_VCEK)
}

fn failed(r: &Report) -> Vec<CheckId> {
    r.checks
        .iter()
        .filter(|c| !c.passed)
        .map(|c| c.id)
        .collect()
}

fn snp_mut(f: &mut Fx) -> &mut SevSnpPolicy {
    f.policy.sev_snp.as_mut().unwrap()
}

#[test]
fn production_roots_are_amd_only() {
    let names: Vec<&str> = snp::ROOTS.iter().map(|r| r.0).collect();
    assert_eq!(names, ["Milan", "Genoa", "Turin"]);
    for (_, ark, ask) in snp::ROOTS {
        assert_ne!(*ark, SYNTHETIC_ROOT.1);
        assert_ne!(*ask, SYNTHETIC_ROOT.2);
    }
}

#[test]
fn honest_synthetic_deployment_passes() {
    let f = fx();
    let r = run(&f, &synth(&f, |_| {}), &f.app_compose);
    assert!(failed(&r).is_empty(), "{r}");
    assert!(r.passed(), "{r}");
    assert_eq!(r.exit_code(), 0);
    let ids: Vec<CheckId> = r.checks.iter().map(|c| c.id).collect();
    assert!(ids.contains(&CheckId::HostData) && !ids.contains(&CheckId::EventLog));
    assert_eq!(
        r.observed.snp_host_data.as_deref(),
        f.policy.sev_snp.as_ref().map(|s| s.host_data.as_str())
    );
    assert_eq!(
        r.observed.compose_hash_measured,
        r.observed.compose_hash_served
    );
}

/// Regression: a real AMD-signed report with no HOST_DATA must never pass,
/// whatever document accompanies it.
#[test]
fn real_report_without_host_data_fails() {
    let mut f = fx();
    let real = real_report();
    // Make everything else about the old fixture acceptable to the policy.
    let s = snp_mut(&mut f);
    s.allow_smt = true;
    s.require_alias_check = false;
    s.measurement = hex::encode(&real[OFF_MEASUREMENT..OFF_MEASUREMENT + 48]);
    let r = run_with(&f, &doc(&f, &real, &f.app_compose), REAL_VCEK);
    assert_eq!(
        failed(&r),
        vec![CheckId::ReportData, CheckId::HostData, CheckId::ComposeHash],
        "{r}"
    );
    assert!(!r.passed());
    assert_eq!(r.exit_code(), 1);
}

#[test]
fn zero_host_data_fails() {
    let f = fx();
    let rep = synth(&f, |r| r[OFF_HOST_DATA..OFF_HOST_DATA + 32].fill(0));
    let r = run(&f, &rep, &f.app_compose);
    assert_eq!(
        failed(&r),
        vec![CheckId::HostData, CheckId::ComposeHash],
        "{r}"
    );
}

#[test]
fn host_launched_a_different_config() {
    // The host starts the pinned image with another config and serves that
    // config honestly: HOST_DATA = SHA-256(served) but not the release's.
    let f = fx();
    let other = f.app_compose.replace("\"snp\"", "\"evil\"");
    let h = compose::compose_hash(other.as_bytes());
    let rep = synth(&f, |r| {
        r[OFF_HOST_DATA..OFF_HOST_DATA + 32].copy_from_slice(&h)
    });
    let r = run(&f, &rep, &other);
    assert_eq!(failed(&r), vec![CheckId::ComposeHash], "{r}");
    assert!(r.to_string().contains("different compose/config"));
}

#[test]
fn served_compose_is_not_the_launched_one() {
    let f = fx();
    let other = f.app_compose.replace("\"snp\"", "\"evil\"");
    let r = run(&f, &synth(&f, |_| {}), &other);
    assert_eq!(failed(&r), vec![CheckId::ComposeHash], "{r}");
    assert!(r.to_string().contains("not what runs"));
}

#[test]
fn wrong_measurement_distrusts_host_data() {
    let f = fx();
    let rep = synth(&f, |r| r[OFF_MEASUREMENT] ^= 1);
    let r = run(&f, &rep, &f.app_compose);
    assert_eq!(
        failed(&r),
        vec![
            CheckId::Measurements,
            CheckId::HostData,
            CheckId::ComposeHash
        ],
        "{r}"
    );
}

#[test]
fn relay_fails_on_report_data() {
    let f = fx();
    let rep = synth(&f, |r| r[OFF_REPORT_DATA] ^= 1);
    let r = run(&f, &rep, &f.app_compose);
    assert_eq!(failed(&r), vec![CheckId::ReportData], "{r}");
}

#[test]
fn tampering_after_signing_fails_evidence() {
    let f = fx();
    for off in [OFF_HOST_DATA, OFF_MEASUREMENT, OFF_REPORT_DATA, OFF_POLICY] {
        let mut rep = synth(&f, |_| {});
        rep[off] ^= 1;
        let r = run(&f, &rep, &f.app_compose);
        assert_eq!(failed(&r), vec![CheckId::Evidence], "offset {off:#x}: {r}");
    }
}

#[test]
fn synthetic_report_with_real_vcek_and_vice_versa_fail() {
    let f = fx();
    let r = run_with(&f, &doc(&f, &synth(&f, |_| {}), &f.app_compose), REAL_VCEK);
    assert_eq!(failed(&r), vec![CheckId::Evidence], "{r}");
    let r = run_with(&f, &doc(&f, &real_report(), &f.app_compose), SYN_VCEK);
    assert_eq!(failed(&r), vec![CheckId::Evidence], "{r}");
}

#[test]
fn missing_vcek_or_section_fails() {
    let mut f = fx();
    let body = doc(&f, &synth(&f, |_| {}), &f.app_compose);
    let mut ctx = evidence::Context::mock(false);
    ctx.now_secs = NOW;
    let mut r = Report::new("t");
    check_document(&body, &f.spki, &f.nonce, &f.policy, &ctx, &mut r);
    assert_eq!(failed(&r), vec![CheckId::Evidence]);
    f.policy.sev_snp = None;
    let r = run_with(&f, &body, SYN_VCEK);
    assert_eq!(failed(&r), vec![CheckId::Evidence]);
}

/// Every launch-policy violation is an Evidence failure with a reason.
#[test]
fn launch_policy_violations_fail() {
    type Edit = fn(&mut Vec<u8>);
    let cases: [(&str, Edit); 9] = [
        ("guest policy allows SMT", |r| r[OFF_POLICY + 2] |= 0x01),
        ("platform has SMT enabled", |r| r[OFF_PLAT_INFO] |= 0x01),
        ("ALIAS_CHECK_COMPLETE", |r| r[OFF_PLAT_INFO] &= !0x20),
        ("committed TCB snp=7", |r| r[OFF_COMMITTED_TCB + 6] = 7),
        ("launch TCB microcode=1", |r| r[OFF_LAUNCH_TCB + 7] = 1),
        ("VMPL 1", |r| r[OFF_VMPL] = 1),
        ("key type 1", |r| r[OFF_KEY_INFO] |= 1 << 2),
        ("MASK_CHIP_KEY", |r| r[OFF_KEY_INFO] |= 1 << 1),
        ("debugging", |r| r[OFF_POLICY + 2] |= 0x08),
    ];
    for (needle, edit) in cases {
        let f = fx();
        let r = run(&f, &synth(&f, edit), &f.app_compose);
        assert_eq!(failed(&r), vec![CheckId::Evidence], "{needle}: {r}");
        assert!(r.to_string().contains(needle), "{needle}: {r}");
    }
}

#[test]
fn policy_knobs_relax_only_what_they_name() {
    let mut f = fx();
    let rep = synth(&f, |r| {
        r[OFF_POLICY + 2] |= 0x01;
        r[OFF_PLAT_INFO] = 0x01; // SMT on, alias check not reported
        r[OFF_VMPL] = 2;
    });
    assert_eq!(
        failed(&run(&f, &rep, &f.app_compose)),
        vec![CheckId::Evidence]
    );
    let s = snp_mut(&mut f);
    s.allow_smt = true;
    s.require_alias_check = false;
    assert_eq!(
        failed(&run(&f, &rep, &f.app_compose)),
        vec![CheckId::Evidence]
    );
    snp_mut(&mut f).allowed_vmpl = vec![2];
    let r = run(&f, &rep, &f.app_compose);
    assert!(r.passed(), "{r}");
}

#[test]
fn id_and_author_key_pins() {
    let mut f = fx();
    let id = [0x11u8; 48];
    let author = [0x22u8; 48];
    snp_mut(&mut f).id_key_digest = Some(hex::encode(id));
    // Report without an ID block: digest is zero.
    let r = run(&f, &synth(&f, |_| {}), &f.app_compose);
    assert_eq!(failed(&r), vec![CheckId::Evidence], "{r}");
    assert!(r.to_string().contains("ID_KEY_DIGEST"));
    let with_id = synth(&f, |r| {
        r[OFF_ID_KEY_DIGEST..OFF_ID_KEY_DIGEST + 48].copy_from_slice(&id)
    });
    assert!(run(&f, &with_id, &f.app_compose).passed());

    snp_mut(&mut f).author_key_digest = Some(hex::encode(author));
    // Digest present but AUTHOR_KEY_EN = 0: refused.
    let no_en = synth(&f, |r| {
        r[OFF_ID_KEY_DIGEST..OFF_ID_KEY_DIGEST + 48].copy_from_slice(&id);
        r[OFF_AUTHOR_KEY_DIGEST..OFF_AUTHOR_KEY_DIGEST + 48].copy_from_slice(&author);
    });
    let r = run(&f, &no_en, &f.app_compose);
    assert!(r.to_string().contains("AUTHOR_KEY_EN"), "{r}");
    let ok = synth(&f, |r| {
        r[OFF_ID_KEY_DIGEST..OFF_ID_KEY_DIGEST + 48].copy_from_slice(&id);
        r[OFF_AUTHOR_KEY_DIGEST..OFF_AUTHOR_KEY_DIGEST + 48].copy_from_slice(&author);
        r[OFF_KEY_INFO] |= 1;
    });
    assert!(run(&f, &ok, &f.app_compose).passed());
}

#[test]
fn tcb_layouts_fail_closed() {
    use sev::parser::ByteParser;
    let f = fx();
    let sp = f.policy.sev_snp.clone().unwrap();
    let mut rep = sev::firmware::guest::AttestationReport::from_bytes(&synth(&f, |_| {})).unwrap();
    assert!(snp_launch::launch_problems(&rep, &sp).is_empty());
    let good = rep.reported_tcb;
    // Turin-style TCB with an FMC SVN, policy has no minimum for it.
    rep.committed_tcb = TcbVersion {
        fmc: Some(1),
        ..good
    };
    let p = snp_launch::launch_problems(&rep, &sp);
    assert!(p.iter().any(|m| m.contains("no min_tcb.fmc")), "{p:?}");
    let mut sp2 = sp.clone();
    sp2.min_tcb.fmc = Some(2);
    let p = snp_launch::launch_problems(&rep, &sp2);
    assert!(p.iter().any(|m| m.contains("fmc=1 is below 2")), "{p:?}");
    sp2.min_tcb.fmc = Some(1);
    // A pinned FMC minimum is not met by a TCB that carries no FMC SVN
    // (reported and launch here).
    let p = snp_launch::launch_problems(&rep, &sp2);
    assert!(p.iter().any(|m| m.contains("carries no FMC SVN")), "{p:?}");
    let with_fmc = TcbVersion {
        fmc: Some(1),
        ..good
    };
    rep.reported_tcb = with_fmc;
    rep.launch_tcb = with_fmc;
    assert!(snp_launch::launch_problems(&rep, &sp2).is_empty());
    rep.reported_tcb = good;
    rep.launch_tcb = good;
    // A TCB without bootloader / microcode SVN is refused, not skipped.
    rep.committed_tcb = good;
    rep.reported_tcb = TcbVersion {
        bootloader: None,
        ..good
    };
    assert!(!snp_launch::launch_problems(&rep, &sp).is_empty());
    rep.reported_tcb = TcbVersion {
        microcode: None,
        ..good
    };
    assert!(!snp_launch::launch_problems(&rep, &sp).is_empty());
}

#[test]
fn vcek_from_certificate_table() {
    // Two entries (ASK, VCEK) and the zero terminator, then the blobs.
    const GUID_ASK: [u8; 16] = [
        0x79, 0xb3, 0xb7, 0x4a, 0xac, 0xbb, 0xe4, 0x4f, 0xa0, 0x2f, 0x05, 0xae, 0xf3, 0x27, 0xc7,
        0x82,
    ];
    const GUID_VCEK: [u8; 16] = [
        0x8d, 0x75, 0xda, 0x63, 0x64, 0xe6, 0x64, 0x45, 0xad, 0xc5, 0xf4, 0xb9, 0x3b, 0xe8, 0xac,
        0xcd,
    ];
    let ask = b"ask-bytes".to_vec();
    let mut t = Vec::new();
    let hdr = 24 * 3;
    for (g, off, len) in [
        (GUID_ASK, hdr, ask.len()),
        (GUID_VCEK, hdr + ask.len(), SYN_VCEK.len()),
    ] {
        t.extend_from_slice(&g);
        t.extend_from_slice(&u32::try_from(off).unwrap().to_le_bytes());
        t.extend_from_slice(&u32::try_from(len).unwrap().to_le_bytes());
    }
    t.extend_from_slice(&[0u8; 24]);
    t.extend_from_slice(&ask);
    t.extend_from_slice(SYN_VCEK);
    assert_eq!(
        snp_launch::vcek_from_cert_table(&t).as_deref(),
        Some(SYN_VCEK)
    );
    let ev = Evidence {
        quote: String::new(),
        event_log: None,
        aux: Some(B64.encode(&t)),
        vm_config: None,
    };
    assert_eq!(evidence::snp_aux_vcek(&ev).as_deref(), Some(SYN_VCEK));
    // Truncated, empty, VCEK-less and out-of-range tables yield nothing.
    assert!(snp_launch::vcek_from_cert_table(&t[..t.len() - 1]).is_none());
    assert!(snp_launch::vcek_from_cert_table(&[]).is_none());
    assert!(snp_launch::vcek_from_cert_table(&[0u8; 24]).is_none());
    assert!(snp_launch::vcek_from_cert_table(&t[..24 * 2]).is_none());
    let mut bad = t.clone();
    bad[24 + 20..24 + 24].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(snp_launch::vcek_from_cert_table(&bad).is_none());
}
