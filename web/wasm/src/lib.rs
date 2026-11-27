//! Browser build of the Attested Vaultwarden verifier.
//!
//! [`verify_json`] is the whole verification, pure and synchronous: the page
//! (`web/src/app.js`) does every network request and passes the raw
//! responses in; nothing in the verdict is computed in JavaScript. The
//! `js` module (wasm32 only) is the thin `wasm-bindgen` surface plus the one
//! asynchronous helper, Intel collateral assembly, which reuses dcap-qvl's
//! own logic over the page's `fetch`.
//!
//! Research prototype. See `web/README.md` for what a PASS here means and
//! how it is weaker than the command-line verifier.

#![cfg_attr(test, allow(clippy::panic, clippy::unwrap_used, clippy::expect_used))]

use std::collections::BTreeMap;

use attested_vw_common::policy::Policy;
use attested_vw_common::report_data::Nonce;
use attested_vw_verifier::report::{CheckId, Report};
use attested_vw_verifier::{check_document_browser, ct, evidence, registry};
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
        labels: report.checks.iter().map(|c| c.id.label()).collect(),
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
        report
            .notes
            .push(attested_vw_verifier::BROWSER_MODE_NOTE.to_owned());
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
    let ctx = evidence::Context {
        // Never in a browser: a mock "PASS" on a public page helps nobody.
        allow_insecure_mock: false,
        now_secs: input.now_secs,
        tdx_collateral,
        snp_vcek_der: Err("SEV-SNP is not supported in the browser verifier".to_owned()),
    };
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
    let doc: attested_vw_common::schema::AttestationResponse =
        serde_json::from_str(body).map_err(|e| format!("attestation document is invalid: {e}"))?;
    if doc.platform != attested_vw_common::schema::Platform::Tdx {
        return Err(format!(
            "platform `{}` has no Intel collateral",
            doc.platform.as_str()
        ));
    }
    evidence::decode_quote(&doc.evidence).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests;
