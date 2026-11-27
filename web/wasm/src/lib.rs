//! Browser build of the Attested Vaultwarden verifier.
//!
//! [`verify_json`] is the whole verification, pure and synchronous: the page
//! (`web/src/app.js`) does every network request and passes the raw
//! responses in; nothing in the verdict is computed in JavaScript. The
//! `js` module (wasm32 only) is the thin `wasm-bindgen` surface plus the one
//! asynchronous helper, Intel collateral assembly, which reuses dcap-qvl's
//! own logic over the page's `fetch`.
//!
//! Trust material per platform ([`plan`] tells the page what to fetch):
//!
//! * `tdx`: Intel collateral from a PCCS mirror, Intel-signed, checked here.
//! * `gcp-cs`: Google's JWKS, fetched live by the page from the URL pinned
//!   in `attested_vw_common::gcp_cs::JWKS_URL`. It is the trust anchor, as
//!   for the CLI, authenticated only by the browser's WebPKI TLS to Google.
//! * `sev-snp`: the VCEK from the evidence's certificate table, else from
//!   AMD KDS. Either way it must chain to the AMD roots built into the `sev`
//!   crate and match the report, so neither source is trusted.
//!
//! Research prototype. See `web/README.md` for what a PASS here means and
//! how it is weaker than the command-line verifier.

#![cfg_attr(test, allow(clippy::panic, clippy::unwrap_used, clippy::expect_used))]

use std::collections::BTreeMap;

use attested_vw_common::policy::Policy;
use attested_vw_common::report_data::Nonce;
use attested_vw_common::schema::{AttestationResponse, Platform};
use attested_vw_verifier::report::{CheckId, Report};
use attested_vw_verifier::{check_document_browser, ct, evidence, registry, snp};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};

#[cfg(target_arch = "wasm32")]
mod js;

/// Everything the page collected. Text fields are raw response bodies.
#[derive(Debug, Deserialize)]
pub struct Input {
    /// DNS name the user entered.
    pub host: String,
    /// The page's own fresh nonce (64 hex), sent in the request.
    pub nonce: String,
    /// Release policy (TOML), from the bundle built into the page.
    pub policy_toml: String,
    /// Current time, unix seconds (the browser's clock).
    pub now_secs: u64,
    /// Attestation document as received, or why there is none.
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub fetch_error: Option<String>,
    /// Intel collateral (dcap-qvl `QuoteCollateralV3` JSON), or why not.
    #[serde(default)]
    pub collateral: Option<String>,
    #[serde(default)]
    pub collateral_error: Option<String>,
    /// `gcp-cs`: Google's JWKS as fetched from the pinned URL, or why not.
    #[serde(default)]
    pub gcp_jwks: Option<String>,
    #[serde(default)]
    pub gcp_jwks_error: Option<String>,
    /// `sev-snp`: VCEK (DER, base64) fetched from AMD KDS, or why not. Only
    /// used when the evidence's own certificate table has no VCEK.
    #[serde(default)]
    pub snp_vcek: Option<String>,
    #[serde(default)]
    pub snp_vcek_error: Option<String>,
    /// Cert Spotter responses.
    #[serde(default)]
    pub ct: CtInput,
    /// Previously attested SPKI SHA-256 hashes (hex) bundled with the page.
    #[serde(default)]
    pub known_spkis: Vec<String>,
    /// Display only: Docker Hub tag responses per image reference.
    #[serde(default)]
    pub hub: BTreeMap<String, HubAnswer>,
}

#[derive(Debug, Default, Deserialize)]
pub struct CtInput {
    #[serde(default)]
    pub exact_pages: Vec<String>,
    #[serde(default)]
    pub parent_pages: Option<Vec<String>>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct HubAnswer {
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Output {
    pub passed: bool,
    /// The report exactly as the CLI would print it.
    pub text: String,
    pub report: Report,
    /// Labels for `report.checks`, same order.
    pub labels: Vec<&'static str>,
    pub ct_certs: Vec<ct::CtCert>,
}

/// Run every check. Always returns a report; anything that could not be
/// fetched or parsed is a failed check, never a skipped one.
pub fn verify(input: &Input) -> Output {
    let mut report = Report::new(format!("https://{}", input.host));
    let ct_certs = run(input, &mut report);
    Output {
        passed: report.passed(),
        text: report.to_string(),
        labels: report.checks.iter().map(|c| report.label(c.id)).collect(),
        report,
        ct_certs,
    }
}

fn run(input: &Input, report: &mut Report) -> Vec<ct::CtCert> {
    // The report must say "browser mode" even if we stop early.
    report.browser_mode = true;
    let policy = match Policy::from_toml(&input.policy_toml) {
        Ok(p) => p,
        Err(e) => {
            report.fail(
                CheckId::Fetch,
                format!("cannot load the bundled policy: {e}"),
            );
            return Vec::new();
        }
    };
    report.policy_release = Some(policy.release.clone());
    let nonce: Nonce = match input.nonce.parse() {
        Ok(n) => n,
        Err(e) => {
            report.fail(CheckId::Fetch, format!("internal error: bad nonce: {e}"));
            return Vec::new();
        }
    };
    let Some(body) = input.body.as_deref() else {
        report.note(attested_vw_verifier::BROWSER_MODE_NOTE);
        report.fail(
            CheckId::Fetch,
            input
                .fetch_error
                .clone()
                .unwrap_or_else(|| "no attestation document".to_owned()),
        );
        return Vec::new();
    };

    let tdx_collateral = match (&input.collateral, &input.collateral_error) {
        (Some(c), _) => {
            serde_json::from_str(c).map_err(|e| format!("collateral is malformed: {e}"))
        }
        (None, Some(e)) => Err(e.clone()),
        (None, None) => Err("not fetched".to_owned()),
    };
    let gcp_jwks = match (&input.gcp_jwks, &input.gcp_jwks_error) {
        (Some(j), _) => Ok(j.clone()),
        (None, Some(e)) => Err(e.clone()),
        (None, None) => Err("not fetched".to_owned()),
    };
    let ctx = evidence::Context {
        // Never in a browser: a mock "PASS" on a public page helps nobody.
        allow_insecure_mock: false,
        now_secs: input.now_secs,
        tdx_collateral,
        snp_vcek_der: snp_vcek(input, body, report),
        gcp_jwks,
    };
    if doc_platform(body) == Some(Platform::GcpCs) && input.gcp_jwks.is_some() {
        report.note(format!(
            "Google's token signing keys were fetched by this page from {} (the trust anchor on this platform; authenticated by the browser's TLS to Google only)",
            attested_vw_common::gcp_cs::JWKS_URL
        ));
    }
    check_document_browser(body.as_bytes(), &nonce, &policy, &ctx, report);

    // Display only; the verdict is already determined by the checks.
    let notes: Vec<Option<String>> = report
        .observed
        .images
        .iter()
        .map(|(_, image)| {
            let answer = input.hub.get(image).map(|a| match (&a.body, &a.error) {
                (Some(b), _) => Ok(b.as_str()),
                (None, e) => Err(e.as_deref().unwrap_or("no answer")),
            });
            registry::annotation(image, answer)
        })
        .collect();
    if !report.observed.images.is_empty() {
        let lines = registry::sub_lines(&report.observed.images, &notes);
        report.set_sub(CheckId::Images, lines);
    }

    if let Some(e) = &input.ct.error {
        report.fail(
            CheckId::CtBinding,
            format!("could not get the certificate list from the CT monitor: {e}"),
        );
        return Vec::new();
    }
    ct::check(
        &ct::CtQuery {
            host: &input.host,
            exact_pages: &input.ct.exact_pages,
            parent_pages: input.ct.parent_pages.as_deref(),
            now_secs: input.now_secs,
            known_spkis: &input.known_spkis,
        },
        report,
    )
}

fn doc_platform(body: &str) -> Option<Platform> {
    serde_json::from_str::<AttestationResponse>(body)
        .ok()
        .map(|d| d.platform)
}

/// The VCEK to judge an SNP report with: the one in the evidence's
/// certificate table if there is one (as the CLI does), else the one the
/// page fetched from AMD KDS. Its source does not matter for the verdict:
/// `snp::verify_report` accepts it only if it chains to a built-in AMD root
/// and matches the report's chip and TCB.
fn snp_vcek(input: &Input, body: &str, report: &mut Report) -> Result<Vec<u8>, String> {
    let doc = serde_json::from_str::<AttestationResponse>(body)
        .ok()
        .filter(|d| d.platform == Platform::SevSnp);
    let Some(doc) = doc else {
        return Err("not an SEV-SNP document".to_owned());
    };
    if let Some(v) = evidence::snp_aux_vcek(&doc.evidence) {
        if v.len() > snp::MAX_VCEK_BYTES {
            return Err("VCEK in the server's certificate table is too large".to_owned());
        }
        report.note("VCEK taken from the certificate table the server sent (checked against the built-in AMD roots)");
        return Ok(v);
    }
    match (&input.snp_vcek, &input.snp_vcek_error) {
        (Some(b64), _) => {
            let v = B64
                .decode(b64)
                .map_err(|_| "internal error: fetched VCEK is not base64".to_owned())?;
            if v.len() > snp::MAX_VCEK_BYTES {
                return Err("VCEK from AMD KDS is too large".to_owned());
            }
            report.note(format!(
                "VCEK fetched by this page from AMD KDS ({}) and checked against the built-in AMD roots",
                snp::AMD_KDS_URL
            ));
            Ok(v)
        }
        (None, Some(e)) => Err(format!(
            "the evidence carries no VCEK in its certificate table, and {e}"
        )),
        (None, None) => Err(
            "the evidence carries no VCEK in its certificate table and none was fetched".to_owned(),
        ),
    }
}

/// What the page must fetch before [`verify`] can judge this document.
#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct Plan {
    /// Platform the document claims (`""` if it does not parse; [`verify`]
    /// then reports why).
    pub platform: String,
    /// `tdx`: Intel collateral is needed (`fetch_collateral`).
    pub tdx_collateral: bool,
    /// `gcp-cs`: the pinned JWKS URL to fetch.
    pub gcp_jwks_url: Option<&'static str>,
    /// `sev-snp` without a VCEK in the certificate table: AMD KDS URLs to
    /// try in turn until one answers 200.
    pub snp_vcek_urls: Vec<KdsUrl>,
    /// `sev-snp`: why there is nothing to fetch although no VCEK came with
    /// the evidence.
    pub snp_vcek_error: Option<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct KdsUrl {
    pub product: &'static str,
    pub url: String,
}

/// Decide which trust material the page fetches for `body`. Reads only the
/// document's platform and (for SNP) the unsigned report bytes; every URL is
/// a constant host. Nothing here affects the verdict: missing material is a
/// failed evidence check in [`verify`].
pub fn plan(body: &str) -> Plan {
    let Ok(doc) = serde_json::from_str::<AttestationResponse>(body) else {
        return Plan::default();
    };
    let mut plan = Plan {
        platform: doc.platform.as_str().to_owned(),
        ..Plan::default()
    };
    match doc.platform {
        Platform::Tdx => plan.tdx_collateral = true,
        Platform::GcpCs => plan.gcp_jwks_url = Some(attested_vw_common::gcp_cs::JWKS_URL),
        Platform::SevSnp => {
            if evidence::snp_aux_vcek(&doc.evidence).is_none() {
                let urls = evidence::decode_quote(&doc.evidence)
                    .map_err(|e| e.to_string())
                    .and_then(|q| snp::kds_vcek_urls(snp::AMD_KDS_URL, &q));
                match urls {
                    Ok(u) => {
                        plan.snp_vcek_urls = u
                            .into_iter()
                            .map(|(product, url)| KdsUrl { product, url })
                            .collect();
                    }
                    Err(e) => plan.snp_vcek_error = Some(e),
                }
            }
        }
        Platform::Mock => {}
    }
    plan
}

/// [`plan`] as JSON.
pub fn plan_json(body: &str) -> String {
    serde_json::to_string(&plan(body)).unwrap_or_else(|_| "{}".to_owned())
}

/// JSON in, JSON out (see [`Input`], [`Output`]).
pub fn verify_json(input: &str) -> String {
    let out = match serde_json::from_str::<Input>(input) {
        Ok(i) => serde_json::to_string(&verify(&i)),
        Err(e) => return error_json(&format!("internal error: bad verifier input: {e}")),
    };
    out.unwrap_or_else(|e| error_json(&format!("internal error: cannot serialize report: {e}")))
}

fn error_json(msg: &str) -> String {
    serde_json::json!({ "passed": false, "error": msg }).to_string()
}

/// The raw quote bytes inside an attestation document, for the collateral
/// request (which needs the platform's FMSPC from the quote's PCK chain).
pub fn quote_of(body: &str) -> Result<Vec<u8>, String> {
    let doc: AttestationResponse =
        serde_json::from_str(body).map_err(|e| format!("attestation document is invalid: {e}"))?;
    if doc.platform != Platform::Tdx {
        return Err(format!(
            "platform `{}` has no Intel collateral",
            doc.platform.as_str()
        ));
    }
    evidence::decode_quote(&doc.evidence).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests;
