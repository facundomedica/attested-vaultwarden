//! SEV-SNP: launch-time checks beyond the signature chain, and the binding
//! of the app-compose document to the report (docs/SNP.md).
//!
//! Design (`compose_binding = "host-data"`):
//!
//! * `MEASUREMENT` is pinned by the policy. It covers OVMF, and with
//!   `kernel-hashes=on` the kernel, initrd and command line.
//! * `HOST_DATA` is chosen by the host at launch and signed in every report.
//!   The verifier requires `HOST_DATA` = policy `host_data` =
//!   SHA-256(served app-compose).
//! * The host could launch the pinned image with any `HOST_DATA`, so the
//!   binding holds only because the *measured* guest image refuses to run a
//!   config whose hash differs from its own `HOST_DATA`. That property is a
//!   review obligation on the image whose measurement the policy pins; the
//!   verifier cannot see it.
//!
//! Everything here fails closed: a field the report does not carry, or a TCB
//! layout this code does not understand, is a failure, never a skip.

use attested_vw_common::policy::{Policy, SevSnpPolicy, SnpComposeBinding};
use sev::firmware::guest::AttestationReport;
use sev::firmware::host::TcbVersion;

use crate::report::{CheckId, Report};
use crate::snp::VerifiedReport;

/// `SIGNING_KEY` values in the report's key-info field (ABI spec, table
/// "ATTESTATION_REPORT").
const SIGNING_KEY_VCEK: u32 = 0;

/// GHCB cert-table GUID of the VCEK (`63da758d-e664-4564-adc5-f4b93be8accd`),
/// in its on-the-wire mixed-endian form.
const GUID_VCEK: [u8; 16] = [
    0x8d, 0x75, 0xda, 0x63, 0x64, 0xe6, 0x64, 0x45, 0xad, 0xc5, 0xf4, 0xb9, 0x3b, 0xe8, 0xac, 0xcd,
];

fn hex_eq(expected: &str, got: &[u8]) -> bool {
    expected.eq_ignore_ascii_case(&hex::encode(got))
}

/// One TCB version against the policy minimum. `Err` names the problem.
fn tcb_at_least(which: &str, t: &TcbVersion, policy: &SevSnpPolicy, out: &mut Vec<String>) {
    let m = &policy.min_tcb;
    // Venice-style reports carry no bootloader/microcode SVN; the policy
    // format cannot express a minimum for them yet, so they are refused.
    let (Some(bl), Some(uc)) = (t.bootloader, t.microcode) else {
        out.push(format!(
            "{which} TCB has no bootloader/microcode SVN (unsupported TCB layout)"
        ));
        return;
    };
    match (t.fmc, m.fmc) {
        (None, None) => {}
        // Fail closed, as for the other components: a pinned minimum cannot
        // be met by a report that does not carry the value.
        (None, Some(min)) => out.push(format!(
            "{which} TCB carries no FMC SVN but the policy requires fmc >= {min}"
        )),
        (Some(got), Some(min)) if got >= min => {}
        (Some(got), Some(min)) => out.push(format!("{which} TCB fmc={got} is below {min}")),
        (Some(_), None) => out.push(format!(
            "{which} TCB carries an FMC SVN but the policy has no min_tcb.fmc"
        )),
    }
    for (name, got, min) in [
        ("bootloader", bl, m.bootloader),
        ("tee", t.tee, m.tee),
        ("snp", t.snp, m.snp),
        ("microcode", uc, m.microcode),
    ] {
        if got < min {
            out.push(format!("{which} TCB {name}={got} is below {min}"));
        }
    }
}

/// Policy checks on a signature-verified report that `snp::verify_report`
/// does not make itself. Returns every problem found.
pub fn launch_problems(r: &AttestationReport, policy: &SevSnpPolicy) -> Vec<String> {
    let mut p = Vec::new();

    if r.key_info.signing_key() != SIGNING_KEY_VCEK {
        p.push(format!(
            "report is signed with key type {} (only VCEK, 0, is accepted)",
            r.key_info.signing_key()
        ));
    }
    if r.key_info.mask_chip_key() {
        p.push("report has MASK_CHIP_KEY set (no chip-bound signature)".into());
    }
    if !policy.allowed_vmpl.contains(&r.vmpl) {
        p.push(format!(
            "report was requested at VMPL {} (policy allows {:?})",
            r.vmpl, policy.allowed_vmpl
        ));
    }

    // SMT: the guest policy bit says whether the host MAY use SMT, the
    // platform bit whether it does.
    if !policy.allow_smt {
        if r.policy.smt_allowed() {
            p.push("guest policy allows SMT, the release policy does not (allow_smt)".into());
        }
        if r.plat_info.smt_enabled() {
            p.push("platform has SMT enabled, the release policy does not allow it".into());
        }
    }
    if policy.require_alias_check && !r.plat_info.alias_check_complete() {
        p.push(
            "platform does not report ALIAS_CHECK_COMPLETE (memory aliasing / BadRAM check); \
             policy requires it (require_alias_check)"
                .into(),
        );
    }

    // The minimum applies to what the report claims (reported), to what the
    // host cannot roll back below (committed) and to the firmware that
    // launched the guest (launch). The VCEK only vouches for `reported`.
    tcb_at_least("reported", &r.reported_tcb, policy, &mut p);
    tcb_at_least("committed", &r.committed_tcb, policy, &mut p);
    tcb_at_least("launch", &r.launch_tcb, policy, &mut p);

    // ID block / author key, if the release pins them.
    if let Some(want) = &policy.id_key_digest
        && !hex_eq(want, &r.id_key_digest)
    {
        p.push(format!(
            "ID_KEY_DIGEST is {} (policy: {want})",
            hex::encode(r.id_key_digest)
        ));
    }
    if let Some(want) = &policy.author_key_digest {
        if !r.key_info.author_key_en() {
            p.push("policy pins an author key but the report has AUTHOR_KEY_EN = 0".into());
        } else if !hex_eq(want, &r.author_key_digest) {
            p.push(format!(
                "AUTHOR_KEY_DIGEST is {} (policy: {want})",
                hex::encode(r.author_key_digest)
            ));
        }
    }
    p
}

/// `Measurements` and `HostData` checks for an SNP report. Returns the
/// compose hash the launch is bound to (`HOST_DATA`) if the binding holds;
/// the caller then compares it with the policy and the served document.
pub fn check_binding(v: &VerifiedReport, policy: &Policy, report: &mut Report) -> Option<[u8; 32]> {
    let r = &v.report;
    report.observed.snp_measurement = Some(hex::encode(r.measurement));
    report.observed.snp_host_data = Some(hex::encode(r.host_data));

    let Some(sp) = policy.sev_snp.as_ref() else {
        report.fail(CheckId::Measurements, "policy has no sev_snp section");
        report.fail(CheckId::HostData, "policy has no sev_snp section");
        return None;
    };

    let mut problems = launch_problems(r, sp);
    if !hex_eq(&sp.measurement, &r.measurement) {
        problems.insert(
            0,
            format!(
                "launch measurement {} but policy expects {}",
                hex::encode(r.measurement),
                sp.measurement
            ),
        );
    }
    let measured_ok = problems.is_empty();
    if measured_ok {
        report.pass(
            CheckId::Measurements,
            format!(
                "launch measurement {} matches release {}; VMPL {}, TCB minimums hold for reported, committed and launch TCB",
                hex::encode(r.measurement),
                policy.release,
                r.vmpl
            ),
        );
    } else {
        report.fail(CheckId::Measurements, problems.join("; "));
    }

    match sp.compose_binding {
        SnpComposeBinding::HostData => {
            if r.host_data == [0u8; 32] {
                report.fail(
                    CheckId::HostData,
                    "HOST_DATA is all zero: the host launched the guest without a config hash",
                );
                return None;
            }
            if !measured_ok {
                // HOST_DATA means something only if the pinned image, which
                // enforces it, is what booted.
                report.fail(
                    CheckId::HostData,
                    "HOST_DATA is not trusted: the launch measurement / launch policy check failed, \
                     so nothing shows the guest enforces it",
                );
                return None;
            }
            report.observed.compose_hash_measured = Some(hex::encode(r.host_data));
            report.pass(
                CheckId::HostData,
                format!(
                    "HOST_DATA {} was fixed at launch and is signed in the report; the measured image is what enforces it",
                    hex::encode(r.host_data)
                ),
            );
            Some(r.host_data)
        }
    }
}

/// The policy's expected compose hash for SNP (`host_data`).
pub fn expected_compose_hash(policy: &Policy) -> Option<&str> {
    policy.sev_snp.as_ref().map(|s| match s.compose_binding {
        SnpComposeBinding::HostData => s.host_data.as_str(),
    })
}

/// VCEK (DER) from a GHCB certificate table (configfs-tsm `auxblob`), if the
/// host supplied one. The result is untrusted until `snp::verify_report`
/// checks it against the pinned AMD roots and the report's chip and TCB.
pub fn vcek_from_cert_table(table: &[u8]) -> Option<Vec<u8>> {
    const ENTRY: usize = 24;
    let mut off = 0usize;
    loop {
        let e = table.get(off..off.checked_add(ENTRY)?)?;
        let guid = e.get(..16)?;
        if guid.iter().all(|b| *b == 0) {
            return None;
        }
        let start = usize::try_from(u32::from_le_bytes(e.get(16..20)?.try_into().ok()?)).ok()?;
        let len = usize::try_from(u32::from_le_bytes(e.get(20..24)?.try_into().ok()?)).ok()?;
        if guid == GUID_VCEK {
            let data = table.get(start..start.checked_add(len)?)?;
            if data.starts_with(b"-----BEGIN") {
                return attested_vw_common::tls::first_cert_der_from_pem(data).ok();
            }
            return Some(data.to_vec());
        }
        off = off.checked_add(ENTRY)?;
    }
}
