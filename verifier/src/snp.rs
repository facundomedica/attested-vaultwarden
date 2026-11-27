//! AMD SEV-SNP evidence verification (stretch platform; never run against a
//! live SNP deployment, see docs/SNP.md).
//!
//! * Report parsing and signatures: VirTEE `sev` (`crypto_nossl`): ARK
//!   self-signed, ARK→ASK, ASK→VCEK, VCEK→report, against the crate's
//!   built-in Milan/Genoa/Turin ARK and ASK.
//! * Done here because `sev` does not: certificate validity periods, and
//!   binding the VCEK to *this* report: the VCEK's TCB extensions
//!   (`1.3.6.1.4.1.3704.1.3.{1,2,3,8}`) must equal `reported_tcb` and its
//!   `hwID` (`…1.4`) must equal `chip_id` (AMD VCEK spec 57230, ch. 3).
//!   Without that, a VCEK of an older, vulnerable TCB could sign a report
//!   claiming a newer TCB.
//! * Guest policy: debug and migration-agent bits must be off; VMPL 0.
//! * Not done: CRL / revocation checks against AMD KDS (documented gap).

use attested_vw_common::policy::SevSnpPolicy;
use sev::certs::snp::{Certificate, Chain, Verifiable, builtin, ca};
use sev::firmware::guest::AttestationReport;
use sev::parser::ByteParser;
use x509_parser::prelude::{FromDer, X509Certificate};

#[derive(Debug, thiserror::Error)]
pub enum SnpError {
    #[error("attestation report is malformed: {0}")]
    Report(String),
    #[error("VCEK certificate is malformed: {0}")]
    Vcek(String),
    #[error("VCEK is not signed by any built-in AMD root (Milan, Genoa, Turin)")]
    UnknownRoot,
    #[error("report signature does not verify with the VCEK: {0}")]
    Signature(String),
    #[error("certificate `{0}` is not valid at the verification time")]
    Validity(&'static str),
    #[error("VCEK does not belong to this report: {0}")]
    VcekMismatch(String),
    #[error("guest policy allows debugging: the host can read guest memory")]
    Debug,
    #[error("guest policy allows a migration agent")]
    MigrationAgent,
    #[error("report was requested at VMPL {0}, expected 0")]
    Vmpl(u32),
    #[error("reported TCB {got} is below the policy minimum {min}")]
    Tcb { got: String, min: String },
    #[error("launch policy: {0}")]
    Launch(String),
}

#[derive(Debug, Clone)]
pub struct VerifiedReport {
    pub product: &'static str,
    pub measurement: [u8; 48],
    pub report_data: [u8; 64],
    pub reported_tcb: String,
    /// The whole signature-verified report (HOST_DATA, ID key digests, ...).
    pub report: Box<AttestationReport>,
}

const OID_BL: &str = "1.3.6.1.4.1.3704.1.3.1";
const OID_TEE: &str = "1.3.6.1.4.1.3704.1.3.2";
const OID_SNP: &str = "1.3.6.1.4.1.3704.1.3.3";
const OID_UCODE: &str = "1.3.6.1.4.1.3704.1.3.8";
const OID_HWID: &str = "1.3.6.1.4.1.3704.1.4";

type Roots = (&'static str, &'static [u8], &'static [u8]);
pub(crate) const ROOTS: &[Roots] = &[
    ("Milan", builtin::milan::ARK, builtin::milan::ASK),
    ("Genoa", builtin::genoa::ARK, builtin::genoa::ASK),
    ("Turin", builtin::turin::ARK, builtin::turin::ASK),
];

fn check_validity(name: &'static str, der: &[u8], now: i64) -> Result<(), SnpError> {
    let (_, c) = X509Certificate::from_der(der).map_err(|e| SnpError::Vcek(e.to_string()))?;
    let v = c.validity();
    if now < v.not_before.timestamp() || now > v.not_after.timestamp() {
        return Err(SnpError::Validity(name));
    }
    Ok(())
}

fn pem_to_der(pem: &[u8]) -> Result<Vec<u8>, SnpError> {
    attested_vw_common::tls::first_cert_der_from_pem(pem).map_err(|e| SnpError::Vcek(e.to_string()))
}

/// Roots a VCEK may chain to: AMD's, as built into the `sev` crate. Test
/// builds (and only test builds) add the synthetic chain from
/// `testdata/sev-synthetic`, so that reports with chosen fields can be signed.
fn roots() -> Vec<Roots> {
    #[allow(unused_mut)]
    let mut v = ROOTS.to_vec();
    #[cfg(test)]
    v.push(crate::snp_tests::SYNTHETIC_ROOT);
    v
}

/// Integer value of a VCEK TCB extension (DER INTEGER).
fn ext_u8(c: &X509Certificate<'_>, oid: &str) -> Result<Option<u8>, SnpError> {
    for ext in c.extensions() {
        if ext.oid.to_id_string() == oid {
            let (_, obj) = x509_parser::der_parser::der::parse_der_integer(ext.value)
                .map_err(|e| SnpError::Vcek(format!("{oid}: {e}")))?;
            let v = obj
                .as_u32()
                .map_err(|e| SnpError::Vcek(format!("{oid}: {e}")))?;
            return u8::try_from(v)
                .map(Some)
                .map_err(|_| SnpError::Vcek(format!("{oid}: out of range")));
        }
    }
    Ok(None)
}

fn ext_hwid(c: &X509Certificate<'_>) -> Result<Option<Vec<u8>>, SnpError> {
    for ext in c.extensions() {
        if ext.oid.to_id_string() == OID_HWID {
            // Encoded as an OCTET STRING; accept raw bytes too.
            if let Ok((_, obj)) = x509_parser::der_parser::der::parse_der_octetstring(ext.value)
                && let Ok(b) = obj.as_slice()
            {
                return Ok(Some(b.to_vec()));
            }
            return Ok(Some(ext.value.to_vec()));
        }
    }
    Ok(None)
}

fn tcb_str(bl: Option<u8>, tee: u8, snp: u8, uc: Option<u8>) -> String {
    let o = |v: Option<u8>| v.map_or("-".to_owned(), |v| v.to_string());
    format!("bl={} tee={tee} snp={snp} ucode={}", o(bl), o(uc))
}

/// Guest policy and privilege checks on a (signature-verified) report, for
/// VMPL 0 only.
pub fn check_guest(report: &AttestationReport) -> Result<(), SnpError> {
    check_guest_vmpl(report, &[0])
}

/// As [`check_guest`], with the VMPLs the release policy allows.
pub fn check_guest_vmpl(report: &AttestationReport, allowed_vmpl: &[u32]) -> Result<(), SnpError> {
    if report.policy.debug_allowed() {
        return Err(SnpError::Debug);
    }
    if report.policy.migrate_ma_allowed() {
        return Err(SnpError::MigrationAgent);
    }
    if !allowed_vmpl.contains(&report.vmpl) {
        return Err(SnpError::Vmpl(report.vmpl));
    }
    Ok(())
}

/// Verify a raw 1184-byte SNP attestation report with its VCEK (DER) at
/// unix time `now`, against the policy.
pub fn verify_report(
    report_bytes: &[u8],
    vcek_der: &[u8],
    now: i64,
    policy: &SevSnpPolicy,
) -> Result<VerifiedReport, SnpError> {
    let report =
        AttestationReport::from_bytes(report_bytes).map_err(|e| SnpError::Report(e.to_string()))?;
    let vcek = Certificate::from_der(vcek_der).map_err(|e| SnpError::Vcek(e.to_string()))?;

    // Find the product whose ARK/ASK chain signs this VCEK.
    let mut found = None;
    for (name, ark_pem, ask_pem) in &roots() {
        let (Ok(ark), Ok(ask)) = (
            Certificate::from_pem(ark_pem),
            Certificate::from_pem(ask_pem),
        ) else {
            continue;
        };
        let chain = Chain {
            ca: ca::Chain { ark, ask },
            vek: vcek.clone(),
        };
        if (&chain).verify().is_ok() {
            found = Some((*name, *ark_pem, *ask_pem, chain));
            break;
        }
    }
    let (product, ark_pem, ask_pem, chain) = found.ok_or(SnpError::UnknownRoot)?;
    (&chain, &report)
        .verify()
        .map_err(|e| SnpError::Signature(e.to_string()))?;

    check_validity("ARK", &pem_to_der(ark_pem)?, now)?;
    check_validity("ASK", &pem_to_der(ask_pem)?, now)?;
    check_validity("VCEK", vcek_der, now)?;

    // Bind the VCEK to this report's TCB and chip.
    let (_, vc) = X509Certificate::from_der(vcek_der).map_err(|e| SnpError::Vcek(e.to_string()))?;
    let rt = report.reported_tcb;
    let cert_tcb = (
        ext_u8(&vc, OID_BL)?,
        ext_u8(&vc, OID_TEE)?,
        ext_u8(&vc, OID_SNP)?,
        ext_u8(&vc, OID_UCODE)?,
    );
    let rep_tcb = (rt.bootloader, Some(rt.tee), Some(rt.snp), rt.microcode);
    if cert_tcb != rep_tcb {
        return Err(SnpError::VcekMismatch(format!(
            "VCEK is for TCB {cert_tcb:?}, report says {rep_tcb:?}"
        )));
    }
    match ext_hwid(&vc)? {
        Some(h) if h == report.chip_id => {}
        Some(_) => return Err(SnpError::VcekMismatch("hwID differs from chip_id".into())),
        None => return Err(SnpError::VcekMismatch("VCEK has no hwID extension".into())),
    }

    check_guest_vmpl(&report, &policy.allowed_vmpl)?;
    let m = &policy.min_tcb;
    let below = rt.bootloader.is_some_and(|b| b < m.bootloader)
        || rt.tee < m.tee
        || rt.snp < m.snp
        || rt.microcode.is_some_and(|u| u < m.microcode);
    let got = tcb_str(rt.bootloader, rt.tee, rt.snp, rt.microcode);
    if below {
        return Err(SnpError::Tcb {
            got,
            min: tcb_str(Some(m.bootloader), m.tee, m.snp, Some(m.microcode)),
        });
    }

    // Fail-closed checks on everything else the release policy speaks about
    // (FMC, committed/launch TCB, SMT, signing key, ID/author key digests).
    let problems = crate::snp_launch::launch_problems(&report, policy);
    if !problems.is_empty() {
        return Err(SnpError::Launch(problems.join("; ")));
    }

    Ok(VerifiedReport {
        product,
        measurement: report.measurement,
        report_data: report.report_data,
        reported_tcb: got,
        report: Box::new(report),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use attested_vw_common::policy::SnpMinTcb;

    const REPORT_HEX: &str = include_str!("../testdata/sev/report_milan.hex");
    const VCEK: &[u8] = include_bytes!("../testdata/sev/vcek_milan.der");
    /// 2026-01-01T00:00:00Z: inside the VCEK's validity (2023-04-03 .. 2030-04-03).
    const NOW: i64 = 1_767_225_600;

    fn report() -> Vec<u8> {
        hex::decode(REPORT_HEX.trim()).unwrap()
    }

    fn policy(min: SnpMinTcb) -> SevSnpPolicy {
        // The upstream fixture is an old Milan report: SMT on, no alias check.
        SevSnpPolicy {
            allow_smt: true,
            require_alias_check: false,
            ..crate::snp_tests::base_policy(min)
        }
    }

    fn zero_min() -> SnpMinTcb {
        SnpMinTcb {
            fmc: None,
            bootloader: 0,
            tee: 0,
            snp: 0,
            microcode: 0,
        }
    }

    #[test]
    fn milan_fixture_verifies() {
        let v = verify_report(&report(), VCEK, NOW, &policy(zero_min())).unwrap();
        assert_eq!(v.product, "Milan");
    }

    #[test]
    fn bad_signature_fails() {
        let mut r = report();
        r[0x50] ^= 0x01; // inside report_data, covered by the signature
        let e = verify_report(&r, VCEK, NOW, &policy(zero_min())).unwrap_err();
        assert!(matches!(e, SnpError::Signature(_)), "{e}");
    }

    #[test]
    fn guest_policy_checks() {
        // Signed reports with these bits are not available as fixtures; the
        // bits are flipped on the decoded struct (after signature checks).
        let base = AttestationReport::from_bytes(&report()).unwrap();
        check_guest(&base).unwrap();
        let mut r = base;
        r.policy.set_debug_allowed(true);
        assert!(matches!(check_guest(&r), Err(SnpError::Debug)));
        let mut r = base;
        r.policy.set_migrate_ma_allowed(true);
        assert!(matches!(check_guest(&r), Err(SnpError::MigrationAgent)));
        let mut r = base;
        r.vmpl = 1;
        assert!(matches!(check_guest(&r), Err(SnpError::Vmpl(1))));
    }

    #[test]
    fn expired_vcek_fails() {
        // 2031-03-11, after the VCEK's notAfter (2030-04-03).
        let e = verify_report(&report(), VCEK, 1_931_000_000, &policy(zero_min())).unwrap_err();
        assert!(matches!(e, SnpError::Validity(_)), "{e}");
    }

    #[test]
    fn tcb_below_minimum_fails() {
        let min = SnpMinTcb {
            fmc: None,
            bootloader: 0,
            tee: 0,
            snp: 255,
            microcode: 0,
        };
        let e = verify_report(&report(), VCEK, NOW, &policy(min)).unwrap_err();
        assert!(matches!(e, SnpError::Tcb { .. }), "{e}");
    }

    #[test]
    fn wrong_length_fails() {
        let e = verify_report(&report()[..100], VCEK, NOW, &policy(zero_min())).unwrap_err();
        assert!(matches!(e, SnpError::Report(_)), "{e}");
    }

    #[test]
    fn non_amd_cert_fails() {
        let tls = attested_vw_common::tls::first_cert_der_from_pem(include_bytes!(
            "../../common/testdata/test-cert.pem"
        ))
        .unwrap();
        assert!(verify_report(&report(), &tls, NOW, &policy(zero_min())).is_err());
    }
}
