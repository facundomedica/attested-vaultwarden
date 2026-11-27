//! The networked verifier behind the CLI: TLS handshake, fetch over the same
//! connection, vendor collateral, then [`crate::check_document`]. Needs the
//! `cli` feature; the pure core does not.

use attested_vw_common::policy::Policy;
use attested_vw_common::report_data::Nonce;
use attested_vw_common::schema::{AttestationResponse, Platform};
use attested_vw_common::tls;

use crate::net::{self, Roots};
use crate::report::{CheckId, Report};
use crate::{check_document, evidence, fetch, registry};

/// Options controlling a verification run.
#[derive(Debug, Clone)]
pub struct Options {
    /// Accept the INSECURE mock platform (local development only). Even when
    /// set, a mock result never counts as PASS.
    pub allow_insecure_mock: bool,
    /// Trust anchors for the TLS connection.
    pub roots: Roots,
    /// Where to fetch Intel DCAP collateral (Intel PCS by default). The
    /// collateral is Intel-signed, so the source cannot forge it, but it
    /// picks which signed version we see: it can roll the TCB verdict back
    /// to an older evaluation data set unless the policy's
    /// `tdx.min_tcb_eval_data_number` forbids it (see [`fetch`]).
    pub pccs_url: String,
    /// Ask for Intel's `update=early` TCB evaluation data set.
    pub early_tcb: bool,
    /// AMD Key Distribution Service base URL (VCEK certificates).
    pub kds_url: String,
    /// Ask Docker Hub which tags currently point at each pinned digest and
    /// print them under the image list. Display only: never changes a
    /// check, the verdict or the exit code; at most
    /// [`REGISTRY_LOOKUP_BUDGET`] in total.
    pub registry_lookup: bool,
}

/// Total time allowed for all registry tag lookups of one run.
pub const REGISTRY_LOOKUP_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

impl Options {
    pub fn new(roots: Roots) -> Self {
        Self {
            allow_insecure_mock: false,
            roots,
            pccs_url: fetch::INTEL_PCS_URL.to_owned(),
            early_tcb: false,
            kds_url: fetch::AMD_KDS_URL.to_owned(),
            registry_lookup: true,
        }
    }
}

/// How long to wait before the single retry after an HTTP 429 from the
/// attestation endpoint (its rate limit is shared by all clients).
const RATE_LIMIT_BACKOFF: std::time::Duration = std::time::Duration::from_millis(1500);

/// One attempt, repeated once after a pause if the endpoint answered 429.
/// The retry uses a new connection and the same nonce (still ours, still
/// unused); the TLS key is re-read from the new handshake.
async fn fetch_with_retry(
    t: &net::Target,
    roots: &Roots,
    nonce: &Nonce,
    report: &mut Report,
) -> Result<net::Fetched, net::NetError> {
    match net::fetch(t, roots, nonce).await {
        Err(net::NetError::Status(429, _)) => {
            report.note("attestation endpoint was rate limited (HTTP 429); retried once");
            tokio::time::sleep(RATE_LIMIT_BACKOFF).await;
            net::fetch(t, roots, nonce).await
        }
        other => other,
    }
}

fn fresh_nonce() -> Result<Nonce, String> {
    let mut n = [0u8; 32];
    getrandom::fill(&mut n).map_err(|e| format!("OS random number generator failed: {e}"))?;
    Ok(Nonce(n))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Verify a deployment at `target` (an `https://` origin) against `policy`.
///
/// If the only problem is a TLS key mismatch, the run is repeated once on a
/// fresh connection, because a certificate renewal between our handshake and
/// the sidecar reading the certificate produces exactly that. A relay fails
/// both times.
pub async fn verify(target: &str, policy: &Policy, opts: &Options) -> Report {
    let first = verify_once(target, policy, opts).await;
    let failures: Vec<CheckId> = first
        .checks
        .iter()
        .filter(|c| !c.passed)
        .map(|c| c.id)
        .collect();
    let spki_only = !failures.is_empty()
        && failures
            .iter()
            .all(|id| matches!(id, CheckId::SpkiBinding | CheckId::ReportData));
    if !spki_only {
        return first;
    }
    let mut second = verify_once(target, policy, opts).await;
    second.note("first attempt failed on the TLS key binding; retried once on a new connection");
    second
}

async fn verify_once(target: &str, policy: &Policy, opts: &Options) -> Report {
    let mut report = Report::new(target);
    report.policy_release = Some(policy.release.clone());
    report.note(match &opts.roots {
        Roots::WebPki => "TLS trust roots: Mozilla WebPKI (webpki-roots)",
        Roots::Custom(_) => "TLS trust roots: custom CA file only (NOT WebPKI)",
    });

    let t = match net::Target::parse(target) {
        Ok(t) => t,
        Err(e) => {
            report.fail(CheckId::Tls, e.to_string());
            return report;
        }
    };
    let nonce = match fresh_nonce() {
        Ok(n) => n,
        Err(e) => {
            report.fail(CheckId::Fetch, e);
            return report;
        }
    };
    let fetched = match fetch_with_retry(&t, &opts.roots, &nonce, &mut report).await {
        Ok(f) => f,
        Err(e @ (net::NetError::Status(..) | net::NetError::Http(_))) => {
            report.pass(CheckId::Tls, "handshake ok");
            report.fail(CheckId::Fetch, e.to_string());
            return report;
        }
        Err(e) => {
            report.fail(CheckId::Tls, e.to_string());
            return report;
        }
    };
    let spki = match tls::spki_sha256_from_der(&fetched.leaf_der) {
        Ok(s) => s,
        Err(e) => {
            report.fail(CheckId::Tls, format!("cannot parse leaf certificate: {e}"));
            return report;
        }
    };
    report.pass(
        CheckId::Tls,
        format!(
            "{} to {}:{}, certificate valid for host; leaf SPKI SHA-256 {spki}",
            fetched.tls_version, t.host, t.port
        ),
    );

    // Fetch platform endorsements (Intel collateral / AMD VCEK) for the
    // evidence. These are signed by the vendor and checked offline below.
    let mut ctx = evidence::Context::mock(opts.allow_insecure_mock);
    ctx.now_secs = unix_now();
    if let Ok(doc) = serde_json::from_slice::<AttestationResponse>(&fetched.body)
        && let Ok(quote) = evidence::decode_quote(&doc.evidence)
    {
        match doc.platform {
            Platform::Tdx => {
                if opts.pccs_url != fetch::INTEL_PCS_URL {
                    report.note(format!(
                        "TDX collateral from {} (not Intel PCS): it can serve older Intel-signed TCB data, down to the policy's minimum evaluation data number",
                        opts.pccs_url
                    ));
                }
                ctx.tdx_collateral =
                    fetch::tdx_collateral(&opts.pccs_url, &quote, opts.early_tcb).await
            }
            Platform::SevSnp => {
                // The VCEK is AMD-signed and checked offline against the report,
                // so the sidecar's certificate table is as good a source as KDS.
                ctx.snp_vcek_der = match evidence::snp_aux_vcek(&doc.evidence) {
                    Some(v) => Ok(v),
                    None => fetch::snp_vcek(&opts.kds_url, &quote).await,
                }
            }
            Platform::GcpCs => ctx.gcp_jwks = fetch::gcp_jwks().await,
            Platform::Mock => {}
        }
    }
    check_document(&fetched.body, &spki, &nonce, policy, &ctx, &mut report);
    if opts.registry_lookup {
        annotate_images(&mut report).await;
    }
    report
}

/// Display-only: add "which tags point here" lines under the image list.
/// Every failure becomes a "lookup failed" line; nothing else changes.
async fn annotate_images(report: &mut Report) {
    let images = report.observed.images.clone();
    if images.is_empty() {
        return;
    }
    let deadline = tokio::time::Instant::now() + REGISTRY_LOOKUP_BUDGET;
    let client = reqwest::Client::builder()
        .timeout(REGISTRY_LOOKUP_BUDGET)
        .build();
    let lookups = images.iter().map(|(_, image)| {
        let client = &client;
        async move {
            let url = registry::hub_tags_url(image)?;
            let body = async {
                let c = client.as_ref().map_err(|e| e.to_string())?;
                let resp = c.get(&url).send().await.map_err(|e| e.to_string())?;
                if !resp.status().is_success() {
                    return Err(format!("HTTP {}", resp.status().as_u16()));
                }
                resp.text().await.map_err(|e| e.to_string())
            };
            Some(match tokio::time::timeout_at(deadline, body).await {
                Ok(r) => r,
                Err(_) => Err(format!(
                    "no answer within {} s",
                    REGISTRY_LOOKUP_BUDGET.as_secs()
                )),
            })
        }
    });
    let results = futures_util::future::join_all(lookups).await;
    let notes: Vec<Option<String>> = images
        .iter()
        .zip(&results)
        .map(|((_, image), r)| {
            registry::annotation(
                image,
                r.as_ref().map(|r| r.as_deref().map_err(String::as_str)),
            )
        })
        .collect();
    report.set_sub(CheckId::Images, registry::sub_lines(&images, &notes));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Network (Docker Hub); run by hand:
    /// `cargo test -p attested-vw-verify registry_lookup_live -- --ignored --nocapture`
    #[tokio::test]
    #[ignore = "needs network"]
    async fn registry_lookup_live() {
        let policy =
            Policy::from_toml(include_str!("../../policy/2026.11.2-phala-dev.toml")).unwrap();
        let mut r = Report::new("x");
        r.observed.images = policy
            .images
            .iter()
            .map(|i| (i.service.clone(), i.image.clone()))
            .collect();
        r.pass(CheckId::Images, "3 services");
        let t = std::time::Instant::now();
        annotate_images(&mut r).await;
        assert!(t.elapsed() < REGISTRY_LOOKUP_BUDGET + std::time::Duration::from_secs(1));
        println!("{r}");
        assert!(r.passed());
        assert!(r.checks[0].sub.len() >= 3);
    }
}
