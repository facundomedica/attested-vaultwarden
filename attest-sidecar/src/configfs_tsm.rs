//! AMD SEV-SNP provider over Linux configfs-tsm (kernel ≥ 6.7).
//!
//! ABI (`Documentation/ABI/testing/configfs-tsm-report`): create a directory
//! under `/sys/kernel/config/tsm/report`, write up to 64 bytes to `inblob`,
//! read the signed report from `outblob` and, for `sev_guest`, the host's
//! certificate table from `auxblob`. `generation` counts writes to the
//! entry; it is compared before and after to detect interference.
//!
//! `report_data` is written unchanged, and the provider checks that the
//! report it gets back carries exactly those bytes and comes from the
//! `sev_guest` driver. The sidecar parses nothing else, with one exception:
//! [`ConfigfsTsm::host_data`] reads `HOST_DATA` so that the sidecar can
//! refuse to start when the config it serves is not the one the host bound
//! at launch (docs/SNP.md). That self-check is a convenience: the binding
//! the verifier relies on must be enforced earlier, by the measured image.
//!
//! UNTESTED on real hardware: exercised only against a fake directory.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use attested_vw_common::provider::{ProviderError, QuoteProvider};
use attested_vw_common::report_data::ReportData;
use attested_vw_common::schema::{Evidence, Platform};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

pub const DEFAULT_REPORT_DIR: &str = "/sys/kernel/config/tsm/report";

/// Size of an SNP `ATTESTATION_REPORT` (AMD SEV-SNP ABI spec 56860).
const REPORT_LEN: usize = 1184;
const OFF_REPORT_DATA: usize = 0x50;
const OFF_HOST_DATA: usize = 0xC0;
/// Upper bounds on what is read back from the kernel.
const MAX_OUTBLOB: u64 = 16 * 1024;
const MAX_AUXBLOB: u64 = 256 * 1024;
const PROVIDER: &str = "sev_guest";

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Test-only stand-in for the kernel side of configfs: plain files do not
/// react to `mkdir` or to a write, so tests supply what the kernel would do
/// at those two points. Always `None` outside tests.
#[derive(Debug, Clone, Copy)]
struct FakeKernel {
    on_mkdir: fn(&Path),
    on_write: fn(&Path),
}

#[derive(Debug, Clone)]
pub struct ConfigfsTsm {
    root: PathBuf,
    fake: Option<FakeKernel>,
}

/// Removes the report entry when dropped. In configfs, `rmdir` on an entry
/// works although it "contains" attribute files.
#[derive(Debug)]
struct Entry(PathBuf);

impl Drop for Entry {
    fn drop(&mut self) {
        if std::fs::remove_dir(&self.0).is_err() {
            // A plain directory (tests): remove the attribute files too.
            #[cfg(test)]
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

fn err(
    context: &'static str,
    e: impl Into<Box<dyn std::error::Error + Send + Sync>>,
) -> ProviderError {
    ProviderError::new(context, e)
}

fn read_limited(path: &Path, max: u64, context: &'static str) -> Result<Vec<u8>, ProviderError> {
    use std::io::Read as _;
    let f = std::fs::File::open(path).map_err(|e| err(context, e))?;
    let mut buf = Vec::new();
    f.take(max + 1)
        .read_to_end(&mut buf)
        .map_err(|e| err(context, e))?;
    if u64::try_from(buf.len()).unwrap_or(u64::MAX) > max {
        return Err(err(context, "blob larger than the limit"));
    }
    Ok(buf)
}

fn read_generation(dir: &Path) -> Result<u64, ProviderError> {
    let raw = read_limited(&dir.join("generation"), 64, "read tsm generation")?;
    String::from_utf8_lossy(&raw)
        .trim()
        .parse()
        .map_err(|e| err("parse tsm generation", e))
}

impl ConfigfsTsm {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            fake: None,
        }
    }

    /// One report over `report_data`: `(report, certificate table)`.
    fn report_blocking(&self, report_data: &[u8; 64]) -> Result<(Vec<u8>, Vec<u8>), ProviderError> {
        let name = format!(
            "attested-vw-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let dir = self.root.join(name);
        // Must not exist: a leftover or foreign entry is never reused.
        std::fs::create_dir(&dir).map_err(|e| err("create tsm report entry", e))?;
        let _entry = Entry(dir.clone());
        if let Some(k) = self.fake {
            (k.on_mkdir)(&dir);
        }

        let provider = read_limited(&dir.join("provider"), 64, "read tsm provider")?;
        let provider = String::from_utf8_lossy(&provider);
        if provider.trim() != PROVIDER {
            return Err(err(
                "tsm provider",
                format!("expected `{PROVIDER}`, kernel says `{}`", provider.trim()),
            ));
        }

        let before = read_generation(&dir)?;
        std::fs::write(dir.join("inblob"), report_data).map_err(|e| err("write tsm inblob", e))?;
        if let Some(k) = self.fake {
            (k.on_write)(&dir);
        }
        let report = read_limited(&dir.join("outblob"), MAX_OUTBLOB, "read tsm outblob")?;
        // Absent or empty when the host supplies no certificates.
        let aux = match read_limited(&dir.join("auxblob"), MAX_AUXBLOB, "read tsm auxblob") {
            Ok(a) => a,
            Err(e) => {
                let missing = e
                    .source
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound);
                if !missing {
                    return Err(e);
                }
                Vec::new()
            }
        };
        let after = read_generation(&dir)?;
        if after != before.wrapping_add(1) {
            return Err(err(
                "tsm generation",
                format!(
                    "entry was written {} times, expected once: someone else used it",
                    after.wrapping_sub(before)
                ),
            ));
        }

        if report.len() != REPORT_LEN {
            return Err(err(
                "tsm outblob",
                format!("report is {} bytes, expected {REPORT_LEN}", report.len()),
            ));
        }
        if report.get(OFF_REPORT_DATA..OFF_REPORT_DATA + 64) != Some(report_data.as_slice()) {
            return Err(err("tsm outblob", "report carries a different report_data"));
        }
        Ok((report, aux))
    }

    async fn report(&self, report_data: [u8; 64]) -> Result<(Vec<u8>, Vec<u8>), ProviderError> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || this.report_blocking(&report_data))
            .await
            .map_err(|e| err("tsm report task", e))?
    }

    /// `HOST_DATA` of this guest, from a fresh report (unverified: the
    /// sidecar cannot check AMD's signature and does not need to; a lying
    /// host only makes the sidecar's own start-up check pass or fail).
    pub async fn host_data(&self) -> Result<[u8; 32], ProviderError> {
        let (report, _) = self.report([0u8; 64]).await?;
        report
            .get(OFF_HOST_DATA..OFF_HOST_DATA + 32)
            .and_then(|s| <[u8; 32]>::try_from(s).ok())
            .ok_or_else(|| err("tsm outblob", "report too short"))
    }
}

impl QuoteProvider for ConfigfsTsm {
    fn platform(&self) -> Platform {
        Platform::SevSnp
    }

    async fn get_evidence(&self, report_data: &ReportData) -> Result<Evidence, ProviderError> {
        let mut rd = [0u8; 64];
        rd.copy_from_slice(report_data.as_bytes());
        let (report, aux) = self.report(rd).await?;
        Ok(Evidence {
            quote: B64.encode(report),
            event_log: None,
            aux: (!aux.is_empty()).then(|| B64.encode(aux)),
            vm_config: None,
        })
    }
}

/// Start-up check: the config this sidecar serves must hash to the guest's
/// `HOST_DATA`. Returns the reason if it does not.
pub fn check_host_data(host_data: &[u8; 32], app_compose: &str) -> Result<(), String> {
    let got = attested_vw_common::compose::compose_hash(app_compose.as_bytes());
    if host_data == &[0u8; 32] {
        return Err(
            "HOST_DATA is all zero: the host launched this guest without a config hash".into(),
        );
    }
    if *host_data != got {
        return Err(format!(
            "HOST_DATA is {} but the app-compose document hashes to {}",
            hex::encode(host_data),
            hex::encode(got)
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST_DATA: [u8; 32] = [0xA5; 32];

    fn fake_root(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "avw-tsm-{tag}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    // --- the fake kernel -------------------------------------------------

    fn mkdir_sev(dir: &Path) {
        std::fs::write(dir.join("provider"), "sev_guest\n").unwrap();
        std::fs::write(dir.join("generation"), "0\n").unwrap();
    }
    fn mkdir_tdx(dir: &Path) {
        std::fs::write(dir.join("provider"), "tdx_guest\n").unwrap();
        std::fs::write(dir.join("generation"), "0\n").unwrap();
    }
    fn bump(dir: &Path, by: u64) {
        let g: u64 = std::fs::read_to_string(dir.join("generation"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        std::fs::write(dir.join("generation"), format!("{}\n", g + by)).unwrap();
    }
    fn fake_report(dir: &Path) -> Vec<u8> {
        let inblob = std::fs::read(dir.join("inblob")).unwrap();
        assert_eq!(inblob.len(), 64, "inblob must be the raw 64 bytes");
        let mut r = vec![0u8; REPORT_LEN];
        r[OFF_REPORT_DATA..OFF_REPORT_DATA + 64].copy_from_slice(&inblob);
        r[OFF_HOST_DATA..OFF_HOST_DATA + 32].copy_from_slice(&HOST_DATA);
        r
    }
    fn write_ok(dir: &Path) {
        std::fs::write(dir.join("outblob"), fake_report(dir)).unwrap();
        std::fs::write(dir.join("auxblob"), b"cert-table").unwrap();
        bump(dir, 1);
    }
    fn write_no_aux(dir: &Path) {
        std::fs::write(dir.join("outblob"), fake_report(dir)).unwrap();
        bump(dir, 1);
    }
    fn write_empty_aux(dir: &Path) {
        std::fs::write(dir.join("outblob"), fake_report(dir)).unwrap();
        std::fs::write(dir.join("auxblob"), b"").unwrap();
        bump(dir, 1);
    }
    fn write_other_report_data(dir: &Path) {
        let mut r = fake_report(dir);
        r[OFF_REPORT_DATA] ^= 1;
        std::fs::write(dir.join("outblob"), r).unwrap();
        bump(dir, 1);
    }
    fn write_short(dir: &Path) {
        std::fs::write(dir.join("outblob"), &fake_report(dir)[..1000]).unwrap();
        bump(dir, 1);
    }
    fn write_huge(dir: &Path) {
        std::fs::write(dir.join("outblob"), vec![0u8; 20 * 1024]).unwrap();
        bump(dir, 1);
    }
    fn write_raced(dir: &Path) {
        std::fs::write(dir.join("outblob"), fake_report(dir)).unwrap();
        bump(dir, 2);
    }
    fn write_nothing(_: &Path) {}

    fn provider(tag: &str, on_mkdir: fn(&Path), on_write: fn(&Path)) -> ConfigfsTsm {
        ConfigfsTsm {
            root: fake_root(tag),
            fake: Some(FakeKernel { on_mkdir, on_write }),
        }
    }

    fn rd() -> ReportData {
        let mut b = [0u8; 64];
        for (i, x) in b.iter_mut().enumerate() {
            *x = u8::try_from(i).unwrap();
        }
        ReportData(b)
    }

    fn leftovers(p: &ConfigfsTsm) -> usize {
        std::fs::read_dir(&p.root).unwrap().count()
    }

    fn failure(p: &ConfigfsTsm) -> String {
        let e = p.report_blocking(&rd().0).unwrap_err();
        assert_eq!(leftovers(p), 0, "entry must be removed on failure");
        std::fs::remove_dir_all(&p.root).unwrap();
        e.to_string()
    }

    // --- tests -----------------------------------------------------------

    #[tokio::test]
    async fn evidence_carries_report_and_cert_table() {
        let p = provider("ok", mkdir_sev, write_ok);
        assert_eq!(p.platform(), Platform::SevSnp);
        let ev = p.get_evidence(&rd()).await.unwrap();
        let report = B64.decode(&ev.quote).unwrap();
        assert_eq!(report.len(), REPORT_LEN);
        assert_eq!(
            &report[OFF_REPORT_DATA..OFF_REPORT_DATA + 64],
            rd().as_bytes()
        );
        assert_eq!(B64.decode(ev.aux.unwrap()).unwrap(), b"cert-table");
        assert!(ev.event_log.is_none() && ev.vm_config.is_none());
        // Entries are unique per request and removed afterwards.
        p.get_evidence(&rd()).await.unwrap();
        assert_eq!(leftovers(&p), 0);
        std::fs::remove_dir_all(&p.root).unwrap();
    }

    #[tokio::test]
    async fn missing_or_empty_cert_table_is_not_an_error() {
        for w in [write_no_aux as fn(&Path), write_empty_aux] {
            let p = provider("noaux", mkdir_sev, w);
            let ev = p.get_evidence(&rd()).await.unwrap();
            assert!(ev.aux.is_none());
            std::fs::remove_dir_all(&p.root).unwrap();
        }
    }

    #[tokio::test]
    async fn host_data_is_read_from_a_report() {
        let p = provider("hd", mkdir_sev, write_ok);
        assert_eq!(p.host_data().await.unwrap(), HOST_DATA);
        std::fs::remove_dir_all(&p.root).unwrap();
    }

    #[test]
    fn failures_are_errors_and_clean_up() {
        type Case = (&'static str, fn(&Path), fn(&Path), &'static str);
        let cases: [Case; 7] = [
            ("tdx", mkdir_tdx, write_ok, "expected `sev_guest`"),
            (
                "rd",
                mkdir_sev,
                write_other_report_data,
                "different report_data",
            ),
            ("short", mkdir_sev, write_short, "1000 bytes"),
            ("huge", mkdir_sev, write_huge, "larger than the limit"),
            ("raced", mkdir_sev, write_raced, "someone else used it"),
            ("silent", mkdir_sev, write_nothing, "read tsm outblob"),
            ("noattr", write_nothing, write_ok, "read tsm provider"),
        ];
        for (tag, m, w, needle) in cases {
            let msg = failure(&provider(tag, m, w));
            assert!(msg.contains(needle), "{tag}: {msg}");
        }
    }

    #[test]
    fn missing_configfs_is_an_error() {
        let p = ConfigfsTsm::new("/nonexistent/avw/tsm/report");
        let e = p.report_blocking(&[0; 64]).unwrap_err();
        assert!(e.to_string().contains("create tsm report entry"), "{e}");
    }

    #[test]
    fn start_up_host_data_check() {
        let compose = r#"{"docker_compose_file":"services: {}"}"#;
        let h = attested_vw_common::compose::compose_hash(compose.as_bytes());
        check_host_data(&h, compose).unwrap();
        assert!(
            check_host_data(&[0; 32], compose)
                .unwrap_err()
                .contains("all zero")
        );
        assert!(
            check_host_data(&HOST_DATA, compose)
                .unwrap_err()
                .contains("hashes to")
        );
        assert!(check_host_data(&h, &format!("{compose} ")).is_err());
    }
}
