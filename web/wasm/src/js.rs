//! `wasm-bindgen` surface. Strings in, strings out; no logic of its own
//! beyond adapting the page's `fetch` to dcap-qvl's `HttpClient`.

use std::collections::BTreeMap;

use attested_vw_verifier::{ct, registry};
use dcap_qvl::collateral::CollateralClient;
use dcap_qvl::configs::DefaultConfig;
use dcap_qvl::http::{HttpClient, HttpResponse};
use js_sys::{Function, Object, Promise, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

/// Run every check on what the page collected. See `Input` / `Output`.
#[wasm_bindgen]
pub fn verify(input_json: &str) -> String {
    crate::verify_json(input_json)
}

/// Lower-cased DNS name, or `undefined` if the text is not one.
#[wasm_bindgen]
pub fn normalize_host(host: &str) -> Option<String> {
    ct::normalize_host(host)
}

/// The name to query for `*.parent` wildcard certificates, if any.
#[wasm_bindgen]
pub fn ct_parent(host: &str) -> Option<String> {
    ct::wildcard_parent(host)
}

/// Docker Hub URL listing the tags of an image's repository (display only).
#[wasm_bindgen]
pub fn hub_tags_url(image: &str) -> Option<String> {
    registry::hub_tags_url(image)
}

fn js_err(what: &str, e: JsValue) -> anyhow::Error {
    let msg = e
        .as_string()
        .or_else(|| {
            Reflect::get(&e, &"message".into())
                .ok()
                .and_then(|m| m.as_string())
        })
        .unwrap_or_else(|| "unknown error".to_owned());
    anyhow::anyhow!("{what}: {msg}")
}

/// dcap-qvl HTTP transport backed by a JavaScript function
/// `(url) => Promise<{status: number, headers: {name: value}, body: Uint8Array}>`.
struct JsHttp(Function);

impl HttpClient for JsHttp {
    async fn get(&self, url: &str) -> anyhow::Result<HttpResponse> {
        let promise = self
            .0
            .call1(&JsValue::NULL, &JsValue::from_str(url))
            .map_err(|e| js_err(url, e))?;
        let v = JsFuture::from(Promise::resolve(&promise))
            .await
            .map_err(|e| js_err(url, e))?;
        let field = |name: &str| Reflect::get(&v, &name.into()).map_err(|e| js_err(name, e));
        let status = field("status")?
            .as_f64()
            .filter(|s| (100.0..600.0).contains(s))
            .ok_or_else(|| anyhow::anyhow!("{url}: response has no status"))?
            as u16;
        let mut headers = BTreeMap::new();
        let h = field("headers")?;
        if h.is_object() {
            for entry in Object::entries(&Object::from(h)).iter() {
                let k = Reflect::get_u32(&entry, 0).ok().and_then(|k| k.as_string());
                let val = Reflect::get_u32(&entry, 1).ok().and_then(|x| x.as_string());
                if let (Some(k), Some(val)) = (k, val) {
                    headers.insert(k, val);
                }
            }
        }
        let body = field("body")?;
        if !body.is_instance_of::<Uint8Array>() {
            anyhow::bail!("{url}: response body is not bytes");
        }
        Ok(HttpResponse {
            status,
            headers,
            body: Uint8Array::from(body).to_vec(),
        })
    }
}

/// Fetch the Intel DCAP collateral for the quote in `document` from a PCCS
/// (`pccs_url`) through `fetcher`, and return it as JSON for `verify`.
///
/// Which requests to make and how to assemble the answers is dcap-qvl's own
/// code. The collateral is signed by Intel and checked in `verify`; the PCCS
/// is trusted only to answer, and to answer with something recent.
#[wasm_bindgen]
pub async fn fetch_collateral(
    document: String,
    pccs_url: String,
    fetcher: Function,
) -> Result<String, JsError> {
    let quote = crate::quote_of(&document).map_err(|e| JsError::new(&e))?;
    let client = CollateralClient::<DefaultConfig, JsHttp>::new(JsHttp(fetcher), pccs_url);
    let collateral = client
        .fetch(&quote)
        .await
        .map_err(|e| JsError::new(&format!("{e:#}")))?;
    serde_json::to_string(&collateral).map_err(|e| JsError::new(&e.to_string()))
}
