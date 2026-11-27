//! Network fetches of vendor endorsements (CLI only; never used by tests).
//!
//! Both are signed by the hardware vendor and verified offline afterwards,
//! so the source cannot forge them. It is NOT trusted for availability
//! only, though: the source chooses WHICH validly signed collateral we see.
//! Intel keeps older TCB evaluation data sets valid for months, so a
//! malicious or stale PCCS can serve one in which a platform with a
//! since-fixed vulnerability is still `UpToDate` (TCB rollback), or an old
//! CRL that predates a revocation. The verifier bounds this with the
//! policy's `tdx.min_tcb_eval_data_number` and the collateral's own
//! validity window; within those bounds the source is trusted for
//! freshness. Prefer Intel PCS (the default) over third-party caches.

use sev::firmware::guest::AttestationReport;
use sev::parser::ByteParser;

pub const INTEL_PCS_URL: &str = "https://api.trustedservices.intel.com";
pub const AMD_KDS_URL: &str = "https://kdsintf.amd.com";

/// Intel DCAP collateral for a TDX quote (PCK CRL, TCB info, QE identity).
///
/// `early` asks for Intel's `update=early` TCB evaluation data set (the
/// newest published one) instead of `update=standard` (the one Intel
/// currently enforces). Early is stricter: a platform can be `OutOfDate`
/// there weeks before it is under standard.
pub async fn tdx_collateral(
    pccs_url: &str,
    quote: &[u8],
    early: bool,
) -> Result<dcap_qvl::QuoteCollateralV3, String> {
    use dcap_qvl::collateral::TcbEvaluationDataSet as Set;
    let client = dcap_qvl::collateral::CollateralClient::with_default_http(pccs_url.to_owned())
        .map_err(|e| format!("{e:#}"))?
        .with_evaluation_data_set(if early { Set::Early } else { Set::Standard });
    client
        .fetch(quote)
        .await
        .map_err(|e| format!("fetching collateral from {pccs_url}: {e:#}"))
}

/// VCEK certificate (DER) for an SNP report from AMD KDS
/// (`/vcek/v1/{product}/{hwid}?blSPL=..&teeSPL=..&snpSPL=..&ucodeSPL=..`,
/// AMD spec 57230). The product is not encoded in older reports, so Milan
/// and Genoa are tried in turn. Turin (8-byte hwID, `fmcSPL`) is not yet
/// supported. UNCONFIRMED against a live SNP deployment.
pub async fn snp_vcek(kds_url: &str, report: &[u8]) -> Result<Vec<u8>, String> {
    let r = AttestationReport::from_bytes(report).map_err(|e| format!("report: {e}"))?;
    let t = r.reported_tcb;
    let (Some(bl), Some(uc)) = (t.bootloader, t.microcode) else {
        return Err("reported TCB lacks bootloader/microcode SVN (unsupported product)".into());
    };
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;
    let hwid = hex::encode(r.chip_id);
    let mut last = String::new();
    for product in ["Milan", "Genoa"] {
        let url = format!(
            "{kds_url}/vcek/v1/{product}/{hwid}?blSPL={bl:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={uc:02}",
            t.tee, t.snp
        );
        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                return resp
                    .bytes()
                    .await
                    .map(|b| b.to_vec())
                    .map_err(|e| e.to_string());
            }
            Ok(resp) => last = format!("{product}: HTTP {}", resp.status()),
            Err(e) => last = format!("{product}: {e}"),
        }
    }
    Err(format!("AMD KDS has no VCEK for this report ({last})"))
}
