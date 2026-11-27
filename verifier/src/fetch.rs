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

pub const INTEL_PCS_URL: &str = "https://api.trustedservices.intel.com";
pub use crate::snp::AMD_KDS_URL;

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

/// Google Cloud Attestation's OIDC signing keys (JWKS, JSON text).
///
/// Unlike the vendor collateral above, this document is NOT self-verifying:
/// it is the trust anchor for `gcp-cs`, authenticated only by WebPKI TLS to
/// the pinned URL. So the URL is a constant (no override), redirects are
/// refused and plain HTTP is impossible.
pub async fn gcp_jwks() -> Result<String, String> {
    const MAX: usize = 64 * 1024;
    let url = attested_vw_common::gcp_cs::JWKS_URL;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .https_only(true)
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("fetching {url}: {e}"))?;
    if resp.status() != reqwest::StatusCode::OK {
        return Err(format!("fetching {url}: HTTP {}", resp.status()));
    }
    let body = resp.bytes().await.map_err(|e| e.to_string())?;
    if body.len() > MAX {
        return Err(format!("{url}: response too large"));
    }
    String::from_utf8(body.to_vec()).map_err(|_| format!("{url}: not UTF-8"))
}

/// VCEK certificate (DER) for an SNP report from AMD KDS: the URLs of
/// [`crate::snp::kds_vcek_urls`], tried in turn. UNCONFIRMED against a live
/// SNP deployment.
pub async fn snp_vcek(kds_url: &str, report: &[u8]) -> Result<Vec<u8>, String> {
    let urls = crate::snp::kds_vcek_urls(kds_url, report)?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;
    let mut last = String::new();
    for (product, url) in urls {
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
