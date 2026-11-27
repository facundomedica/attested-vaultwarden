//! Native tests of the browser entry point against recorded evidence: the
//! real TDX quote, event log and Intel collateral in `verifier/testdata`
//! (see its SOURCES.md), and, if present, a full recorded live run in
//! `web/testdata/live-*.json`. No network.

use super::*;

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const NONCE: &str = "0707070707070707070707070707070707070707070707070707070707070707";
const HOST: &str = "vault.fixture.example";

fn read(rel: &str) -> String {
    std::fs::read_to_string(format!("{ROOT}/{rel}")).unwrap()
}

/// The upstream dstack quote wrapped in our document format, with a policy
/// that pins its real measurements. Its report_data is 0x42 × 64 and we do
/// not have its compose document, so `report_data` and the compose hash
/// fail; everything else about the hardware evidence verifies.
fn fixture_input() -> serde_json::Value {
    let gq: serde_json::Value =
        serde_json::from_str(&read("verifier/testdata/dstack/tdx-lite-getquote.json")).unwrap();
    let rec: serde_json::Value =
        serde_json::from_str(&read("verifier/testdata/dstack/tdx-lite-collateral.json")).unwrap();
    let quote = hex_to_b64(gq["quote"].as_str().unwrap());
    let image = format!("docker.io/vaultwarden/server@sha256:{}", "3".repeat(64));
    let body = serde_json::json!({
        "version": 1, "platform": "tdx",
        "evidence": {"quote": quote, "event_log": gq["event_log"]},
        "nonce": NONCE, "spki_sha256": A,
        "report_data_construction": attested_vw_common::report_data::CONSTRUCTION,
        "app_compose": serde_json::json!({
            "docker_compose_file": format!("services:\n  vaultwarden:\n    image: {image}\n"),
        }).to_string(),
        "image_digests": [{"service": "vaultwarden", "image": image}],
        "timestamp": "2026-11-26T00:00:00Z",
    });
    // MRTD, RTMR0-2 straight from the quote bytes (v4 quote: 48-byte header,
    // TD report body with MRTD at +136 and the RTMRs from +328, 48 bytes each).
    let qh = gq["quote"].as_str().unwrap();
    let mr = |off: usize| &qh[2 * off..2 * (off + 48)];
    let mrs = [mr(184), mr(376), mr(424), mr(472)];
    let policy = format!(
        r#"schema = 1
release = "fixture"
date = "2026-11-26"
platform = "tdx"
[tdx]
mrtd = "{}"
rtmr0 = "{}"
rtmr1 = "{}"
rtmr2 = "{}"
compose_hash = "60618cd0c23d15d921b788b8fc3a0d024ac72295185da3ba41d5a065bc7aa833"
accepted_tcb_status = ["UpToDate"]
allow_smt = true
allow_dynamic_platform = true
allow_cached_keys = true
require_storage_encrypted = false
app_id = "60618cd0c23d15d921b788b8fc3a0d024ac72295"
key_provider = '{{"name":"none","id":""}}'
min_tcb_eval_data_number = 20
[[images]]
service = "vaultwarden"
image = "{image}"
"#,
        mrs[0], mrs[1], mrs[2], mrs[3]
    );
    let cert = serde_json::json!([{
        "id": "1", "dns_names": [HOST], "pubkey_sha256": A,
        "not_before": "2026-11-01T00:00:00Z", "not_after": "2027-02-01T00:00:00Z",
        "issuer": {"friendly_name": "Test CA"},
    }]);
    serde_json::json!({
        "host": HOST, "nonce": NONCE, "policy_toml": policy,
        "now_secs": rec["recorded_at_unix"],
        "body": body.to_string(),
        "collateral": rec["collateral"].to_string(),
        "ct": {"exact_pages": [cert.to_string()], "parent_pages": ["[]"]},
    })
}

fn hex_to_b64(h: &str) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes: Vec<u8> = (0..h.len() / 2)
        .map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap())
        .collect();
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for (i, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            if i <= c.len() {
                out.push(T[(n >> shift) as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn run(input: &serde_json::Value) -> serde_json::Value {
    serde_json::from_str(&verify_json(&input.to_string())).unwrap()
}

fn marks(out: &serde_json::Value) -> Vec<(String, bool)> {
    out["report"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                c["id"].as_str().unwrap().to_owned(),
                c["passed"].as_bool().unwrap(),
            )
        })
        .collect()
}

#[test]
fn recorded_quote_in_browser_mode() {
    let out = run(&fixture_input());
    let text = out["text"].as_str().unwrap();
    let m: Vec<(&str, bool)> = marks(&out).iter().map(|(a, b)| (leak(a), *b)).collect();
    assert_eq!(
        m,
        [
            ("fetch", true),
            ("nonce", true),
            ("evidence", true),
            ("report_data_claimed", false),
            ("measurements", true),
            ("event_log", true),
            ("compose_hash", false),
            ("config", true),
            ("images", true),
            ("ct_binding", false),
        ],
        "{text}"
    );
    assert_eq!(out["passed"], false);
    assert!(
        text.contains("TCB UpToDate") && text.contains("TD debug off"),
        "{text}"
    );
    assert!(text.contains("9 RTMR3 events replay to the quoted RTMR3"));
    assert!(!text.contains("TLS key bound to attestation:"));
    assert!(text.contains("browser mode: a web page cannot read the TLS certificate"));
    assert!(text.ends_with("Result:  FAIL"));
    // Image list: full digest, no lookup attempted.
    assert!(text.contains(&format!(
        "\n      vaultwarden  docker.io/vaultwarden/server@sha256:{}\n",
        "3".repeat(64)
    )));
    assert_eq!(out["labels"].as_array().unwrap().len(), 10);
}

fn leak(s: &str) -> &'static str {
    Box::leak(s.to_owned().into_boxed_str())
}

#[test]
fn hub_answers_only_change_the_image_lines() {
    let base = run(&fixture_input());
    let image = format!("docker.io/vaultwarden/server@sha256:{}", "3".repeat(64));
    let hub_body = serde_json::json!({"results": [
        {"name": "1.37.5", "digest": format!("sha256:{}", "3".repeat(64))}
    ]})
    .to_string();
    for (answer, expect) in [
        (
            serde_json::json!({"body": hub_body}),
            "        = vaultwarden/server:1.37.5 (Docker Hub, as of now; tags can move)\n",
        ),
        (
            serde_json::json!({"error": "blocked by the browser"}),
            "        (Docker Hub tag lookup failed: blocked by the browser)\n",
        ),
        (
            serde_json::json!({}),
            "        (Docker Hub tag lookup failed: no answer)\n",
        ),
    ] {
        let mut input = fixture_input();
        input["hub"] = serde_json::json!({ image.clone(): answer });
        let out = run(&input);
        assert!(
            out["text"].as_str().unwrap().contains(expect),
            "{}",
            out["text"]
        );
        assert_eq!(marks(&out), marks(&base));
        assert_eq!(out["passed"], base["passed"]);
    }
}

#[test]
fn missing_inputs_fail_closed() {
    // No document (e.g. CORS blocked the request).
    let mut i = fixture_input();
    i["body"] = serde_json::Value::Null;
    i["fetch_error"] = "the browser blocked the request".into();
    let out = run(&i);
    assert_eq!(marks(&out), [("fetch".to_owned(), false)]);
    assert!(
        out["text"]
            .as_str()
            .unwrap()
            .contains("the browser blocked the request")
    );
    assert_eq!(out["passed"], false);

    // No collateral.
    let mut i = fixture_input();
    i["collateral"] = serde_json::Value::Null;
    i["collateral_error"] = "PCCS unreachable".into();
    let out = run(&i);
    assert!(marks(&out).contains(&("evidence".to_owned(), false)));
    assert!(out["text"].as_str().unwrap().contains("PCCS unreachable"));

    // Stale collateral time: a year later the TCB info has expired.
    let mut i = fixture_input();
    i["now_secs"] = (i["now_secs"].as_u64().unwrap() + 365 * 86_400).into();
    assert!(marks(&run(&i)).contains(&("evidence".to_owned(), false)));

    // CT monitor unreachable.
    let mut i = fixture_input();
    i["ct"] = serde_json::json!({"error": "HTTP 429"});
    let out = run(&i);
    assert!(marks(&out).contains(&("ct_binding".to_owned(), false)));
    assert!(out["text"].as_str().unwrap().contains("HTTP 429"));

    // Mock platform is refused outright.
    let mut i = fixture_input();
    let mut body: serde_json::Value = serde_json::from_str(i["body"].as_str().unwrap()).unwrap();
    body["platform"] = "mock".into();
    i["body"] = body.to_string().into();
    assert_eq!(run(&i)["passed"], false);

    // Garbage in.
    let out: serde_json::Value = serde_json::from_str(&verify_json("{")).unwrap();
    assert_eq!(out["passed"], false);
    assert!(
        out["error"]
            .as_str()
            .unwrap()
            .contains("bad verifier input")
    );
    let mut i = fixture_input();
    i["policy_toml"] = "nope".into();
    assert_eq!(run(&i)["passed"], false);
    let mut i = fixture_input();
    i["nonce"] = "abc".into();
    assert_eq!(run(&i)["passed"], false);
}

#[test]
fn quote_extraction() {
    let i = fixture_input();
    let q = quote_of(i["body"].as_str().unwrap()).unwrap();
    assert!(q.len() > 4000);
    assert!(quote_of("{}").is_err());
}

/// Every recorded live run (`web/testdata/live-*.json`, an `Input` plus
/// `expect_text`) must reproduce its recorded report exactly.
#[test]
fn recorded_live_runs_replay() {
    let dir = format!("{ROOT}/web/testdata");
    let mut n = 0;
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        if !(name.starts_with("live-") && name.ends_with(".json")) {
            continue;
        }
        let rec: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        let out = run(&rec["input"]);
        assert_eq!(out["text"], rec["expect_text"], "{name}");
        assert_eq!(out["passed"], rec["expect_passed"], "{name}");
        n += 1;
    }
    eprintln!("replayed {n} recorded live run(s)");
}

// ---- Google Cloud Confidential Space: the recorded real token ------------

const GCP_HOST: &str = "vault.gcp.facundo.dev";
/// `iat` of the recorded token (verifier/src/gcp_cs_tests.rs) + 60 s.
const GCP_NOW: u64 = 1_795_775_236 + 60;

fn ct_one(host: &str, key: &str) -> serde_json::Value {
    let cert = serde_json::json!([{
        "id": "1", "dns_names": [host], "pubkey_sha256": key,
        "not_before": "2026-11-01T00:00:00Z", "not_after": "2027-02-01T00:00:00Z",
        "issuer": {"friendly_name": "Test CA"},
    }]);
    serde_json::json!({"exact_pages": [cert.to_string()], "parent_pages": ["[]"]})
}

fn gcp_input() -> serde_json::Value {
    let body = read("verifier/testdata/gcp-cs/live-2026-11-27.document.json");
    let doc: serde_json::Value = serde_json::from_str(&body).unwrap();
    serde_json::json!({
        "host": GCP_HOST, "nonce": doc["nonce"],
        "policy_toml": read("policy/2026.11.0-gcp-cs-dev.toml"),
        "now_secs": GCP_NOW,
        "body": body,
        "gcp_jwks": read("verifier/testdata/gcp-cs/google-jwks-2026-11-27.json"),
        "ct": ct_one(GCP_HOST, doc["spki_sha256"].as_str().unwrap()),
    })
}

fn failed(out: &serde_json::Value) -> Vec<String> {
    marks(out)
        .into_iter()
        .filter(|(_, ok)| !ok)
        .map(|(id, _)| id)
        .collect()
}

#[test]
fn gcp_cs_recorded_token_passes_in_browser_mode() {
    let out = run(&gcp_input());
    let text = out["text"].as_str().unwrap();
    let ids: Vec<String> = marks(&out).into_iter().map(|(id, _)| id).collect();
    assert_eq!(
        ids,
        [
            "fetch",
            "nonce",
            "evidence",
            "report_data_claimed",
            "measurements",
            "config",
            "images",
            "ct_binding"
        ],
        "{text}"
    );
    assert!(failed(&out).is_empty(), "{text}");
    assert_eq!(out["passed"], true, "{text}");
    assert!(text.ends_with("Result:  PASS (browser mode: CT-based binding)"));
    assert!(text.contains("RS256 signature valid under Google key"));
    assert!(text.contains("no raw hardware quote is seen by this verifier"));
    assert!(text.contains(
        "Google's token signing keys were fetched by this page from https://www.googleapis.com/"
    ));
    assert!(!text.contains("TLS key bound to attestation:"));
}

#[test]
fn gcp_cs_fails_closed() {
    // No key set: Google unreachable, or the browser blocked the request.
    let mut i = gcp_input();
    i["gcp_jwks"] = serde_json::Value::Null;
    i["gcp_jwks_error"] = "could not fetch the keys".into();
    let out = run(&i);
    assert_eq!(failed(&out), ["evidence", "ct_binding"]);
    let text = out["text"].as_str().unwrap();
    assert!(
        text.contains("Google's signing keys are not available: could not fetch the keys"),
        "{text}"
    );
    // Neither a key set nor an error: still a failure, never a skip.
    let mut i = gcp_input();
    i["gcp_jwks"] = serde_json::Value::Null;
    assert_eq!(failed(&run(&i)), ["evidence", "ct_binding"]);

    // A key set that is not Google's (e.g. one the server would like us to
    // use): the page has no input through which a server could supply it,
    // and if it got there anyway the real token does not verify under it.
    let keys: serde_json::Value = serde_json::from_str(&read(
        "verifier/testdata/gcp-cs/TEST-ONLY-signing-keys.json",
    ))
    .unwrap();
    let mut i = gcp_input();
    i["gcp_jwks"] = keys.to_string().into();
    assert_eq!(failed(&run(&i)), ["evidence", "ct_binding"]);
    let mut i = gcp_input();
    i["gcp_jwks"] = "<html>not json".into();
    assert_eq!(failed(&run(&i)), ["evidence", "ct_binding"]);

    // Expired (token lifetime is one hour) and not yet valid.
    for now in [GCP_NOW + 3600, GCP_NOW - 300] {
        let mut i = gcp_input();
        i["now_secs"] = now.into();
        assert_eq!(failed(&run(&i)), ["evidence", "ct_binding"], "{now}");
    }

    // Replay under another nonce.
    let mut i = gcp_input();
    i["nonce"] = NONCE.into();
    assert_eq!(
        failed(&run(&i)),
        ["nonce", "report_data_claimed", "ct_binding"]
    );

    // The server reports a TLS key the token does not sign.
    let mut i = gcp_input();
    let mut body: serde_json::Value = serde_json::from_str(i["body"].as_str().unwrap()).unwrap();
    body["spki_sha256"] = A.into();
    i["body"] = body.to_string().into();
    i["ct"] = ct_one(GCP_HOST, A);
    assert_eq!(failed(&run(&i)), ["report_data_claimed", "ct_binding"]);

    // A valid certificate for the name with a key that was never attested.
    let mut i = gcp_input();
    i["ct"] = ct_one(GCP_HOST, A);
    assert_eq!(failed(&run(&i)), ["ct_binding"]);

    // The recorded debug-image token: Google's signature is fine, the
    // policy refuses the image.
    let mut i = gcp_input();
    let body = read("verifier/testdata/gcp-cs/live-debug-2026-11-27.document.json");
    let doc: serde_json::Value = serde_json::from_str(&body).unwrap();
    i["nonce"] = doc["nonce"].clone();
    i["ct"] = ct_one(GCP_HOST, doc["spki_sha256"].as_str().unwrap());
    i["body"] = body.into();
    i["now_secs"] = (1_795_775_581u64 + 60).into();
    let out = run(&i);
    assert_eq!(
        failed(&out),
        ["measurements", "ct_binding"],
        "{}",
        out["text"]
    );

    // A TDX policy against a gcp-cs server.
    let mut i = gcp_input();
    i["policy_toml"] = fixture_input()["policy_toml"].clone();
    assert_eq!(failed(&run(&i)), ["fetch", "ct_binding"]);
}

// ---- SEV-SNP ---------------------------------------------------------------
//
// This crate is built without `cfg(test)` of the verifier core, so it knows
// only AMD's roots, exactly like the page. The one real AMD-signed report
// available (virtee/sev's Milan fixture) has HOST_DATA = 0 and somebody
// else's report_data: the signature chain verifies and the binding checks
// fail. A passing SNP run exists only with the synthetic chain, in the core's
// own tests (verifier/src/snp_tests.rs, browser_mode_*). No real SNP
// deployment has ever been verified.

fn snp_report() -> Vec<u8> {
    let h = read("verifier/testdata/sev/report_milan.hex");
    let h = h.trim();
    (0..h.len() / 2)
        .map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn vcek(rel: &str) -> Vec<u8> {
    std::fs::read(format!("{ROOT}/{rel}")).unwrap()
}

/// A GHCB certificate table holding only a VCEK.
fn cert_table(vcek: &[u8]) -> Vec<u8> {
    const GUID_VCEK: [u8; 16] = [
        0x8d, 0x75, 0xda, 0x63, 0x64, 0xe6, 0x64, 0x45, 0xad, 0xc5, 0xf4, 0xb9, 0x3b, 0xe8, 0xac,
        0xcd,
    ];
    let mut t = GUID_VCEK.to_vec();
    t.extend_from_slice(&48u32.to_le_bytes());
    t.extend_from_slice(&u32::try_from(vcek.len()).unwrap().to_le_bytes());
    t.extend_from_slice(&[0u8; 24]);
    t.extend_from_slice(vcek);
    t
}

fn snp_input(aux: Option<&[u8]>, fetched: Option<&[u8]>) -> serde_json::Value {
    let report = snp_report();
    let image = format!("docker.io/vaultwarden/server@sha256:{}", "3".repeat(64));
    let compose = serde_json::json!({
        "name": "snp",
        "docker_compose_file": format!("services:\n  vaultwarden:\n    image: {image}\n"),
    })
    .to_string();
    let mut evidence = serde_json::json!({"quote": B64.encode(&report)});
    if let Some(t) = aux {
        evidence["aux"] = B64.encode(t).into();
    }
    let body = serde_json::json!({
        "version": 1, "platform": "sev-snp", "evidence": evidence,
        "nonce": NONCE, "spki_sha256": A,
        "report_data_construction": attested_vw_common::report_data::CONSTRUCTION,
        "app_compose": compose,
        "image_digests": [{"service": "vaultwarden", "image": image}],
        "timestamp": "2026-11-27T00:00:00Z",
    });
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    // Everything about the old fixture is accepted except what it cannot
    // have: our report_data and a HOST_DATA.
    let policy = format!(
        r#"schema = 1
release = "snp-fixture"
date = "2026-11-27"
platform = "sev-snp"
[sev_snp]
measurement = "{}"
compose_binding = "host-data"
host_data = "{}"
allow_smt = true
require_alias_check = false
[sev_snp.min_tcb]
bootloader = 0
tee = 0
snp = 0
microcode = 0
[[images]]
service = "vaultwarden"
image = "{image}"
"#,
        hex(&report[0x90..0xC0]),
        "ab".repeat(32),
    );
    let mut i = serde_json::json!({
        "host": HOST, "nonce": NONCE, "policy_toml": policy,
        "now_secs": 1_800_000_000u64,
        "body": body.to_string(),
        "ct": ct_one(HOST, A),
    });
    if let Some(v) = fetched {
        i["snp_vcek"] = B64.encode(v).into();
    }
    i
}

#[test]
fn snp_real_report_with_vcek_from_kds_or_certificate_table() {
    let real = vcek("verifier/testdata/sev/vcek_milan.der");
    let table = cert_table(&real);
    let other = vcek("verifier/testdata/sev-synthetic/vcek.der");
    for (name, input, source) in [
        (
            "kds",
            snp_input(None, Some(&real)),
            "fetched by this page from AMD KDS",
        ),
        (
            "table",
            snp_input(Some(&table), None),
            "taken from the certificate table",
        ),
        // The table wins over whatever was fetched.
        (
            "both",
            snp_input(Some(&table), Some(&other)),
            "taken from the certificate table",
        ),
    ] {
        let out = run(&input);
        let text = out["text"].as_str().unwrap();
        let m = marks(&out);
        assert!(m.contains(&("evidence".to_owned(), true)), "{name}: {text}");
        assert!(
            text.contains("AMD Milan ARK→ASK→VCEK→report signatures valid"),
            "{name}: {text}"
        );
        assert!(text.contains(source), "{name}: {text}");
        // Not our nonce, no HOST_DATA: never a PASS.
        assert_eq!(
            failed(&out),
            [
                "report_data_claimed",
                "host_data",
                "compose_hash",
                "ct_binding"
            ],
            "{name}: {text}"
        );
        assert_eq!(out["passed"], false);
        assert!(!text.contains("TLS key bound to attestation:"));
    }
}

#[test]
fn snp_fails_closed() {
    let real = vcek("verifier/testdata/sev/vcek_milan.der");
    // No VCEK anywhere.
    let mut i = snp_input(None, None);
    let out = run(&i);
    assert_eq!(failed(&out), ["evidence", "ct_binding"]);
    assert!(out["text"].as_str().unwrap().contains(
        "no VCEK certificate available for this report: the evidence carries no VCEK in its certificate table and none was fetched"
    ));
    i["snp_vcek_error"] = "AMD KDS gave no VCEK for this report (Milan: HTTP 404)".into();
    let out = run(&i);
    assert_eq!(failed(&out), ["evidence", "ct_binding"]);
    assert!(
        out["text"]
            .as_str()
            .unwrap()
            .contains("and AMD KDS gave no VCEK for this report (Milan: HTTP 404)")
    );

    // The synthetic test chain is not a root in this (non-test) build.
    let syn = vcek("verifier/testdata/sev-synthetic/vcek.der");
    for i in [
        snp_input(None, Some(&syn)),
        snp_input(Some(&cert_table(&syn)), Some(&real)),
    ] {
        let out = run(&i);
        assert_eq!(failed(&out), ["evidence", "ct_binding"]);
        assert!(
            out["text"]
                .as_str()
                .unwrap()
                .contains("not signed by any built-in AMD root")
        );
    }

    // Garbage and oversized "certificates".
    let mut i = snp_input(None, None);
    i["snp_vcek"] = "!!!".into();
    assert_eq!(failed(&run(&i)), ["evidence", "ct_binding"]);
    let big = vec![0x30u8; attested_vw_verifier::snp::MAX_VCEK_BYTES + 1];
    for i in [
        snp_input(None, Some(&big)),
        snp_input(Some(&cert_table(&big)), Some(&real)),
        snp_input(None, Some(b"not a certificate")),
    ] {
        assert_eq!(failed(&run(&i)), ["evidence", "ct_binding"]);
    }

    // Tampered report.
    let mut i = snp_input(None, Some(&real));
    let mut body: serde_json::Value = serde_json::from_str(i["body"].as_str().unwrap()).unwrap();
    let mut r = snp_report();
    r[0x90] ^= 1;
    body["evidence"]["quote"] = B64.encode(&r).into();
    i["body"] = body.to_string().into();
    assert_eq!(failed(&run(&i)), ["evidence", "ct_binding"]);

    // VCEK past its notAfter (2030-04-03).
    let mut i = snp_input(None, Some(&real));
    i["now_secs"] = 1_931_000_000u64.into();
    assert_eq!(failed(&run(&i)), ["evidence", "ct_binding"]);
}

#[test]
fn plan_names_the_trust_material_to_fetch() {
    let tdx = fixture_input();
    let p = plan(tdx["body"].as_str().unwrap());
    assert!(p.tdx_collateral && p.gcp_jwks_url.is_none() && p.snp_vcek_urls.is_empty());
    assert_eq!(p.platform, "tdx");

    let p = plan(gcp_input()["body"].as_str().unwrap());
    assert_eq!(
        p.gcp_jwks_url,
        Some(
            "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com"
        )
    );
    assert!(!p.tdx_collateral && p.snp_vcek_urls.is_empty());

    // SNP without a certificate table: KDS, Milan then Genoa.
    let p = plan(snp_input(None, None)["body"].as_str().unwrap());
    let products: Vec<&str> = p.snp_vcek_urls.iter().map(|u| u.product).collect();
    assert_eq!(products, ["Milan", "Genoa"]);
    assert!(p.snp_vcek_urls.iter().all(|u| {
        u.url.starts_with("https://kdsintf.amd.com/vcek/v1/")
            && u.url
                .ends_with("?blSPL=03&teeSPL=00&snpSPL=08&ucodeSPL=115")
    }));
    // With one: nothing to fetch.
    let real = vcek("verifier/testdata/sev/vcek_milan.der");
    let p = plan(
        snp_input(Some(&cert_table(&real)), None)["body"]
            .as_str()
            .unwrap(),
    );
    assert!(p.snp_vcek_urls.is_empty() && p.snp_vcek_error.is_none());
    // A report that cannot be parsed: an error, no request.
    let mut body: serde_json::Value =
        serde_json::from_str(snp_input(None, None)["body"].as_str().unwrap()).unwrap();
    body["evidence"]["quote"] = "AAAA".into();
    let p = plan(&body.to_string());
    assert!(p.snp_vcek_urls.is_empty() && p.snp_vcek_error.is_some());

    // Mock and garbage: nothing to fetch.
    body["platform"] = "mock".into();
    let p = plan(&body.to_string());
    assert_eq!(p.platform, "mock");
    assert!(!p.tdx_collateral && p.gcp_jwks_url.is_none() && p.snp_vcek_urls.is_empty());
    assert_eq!(plan("{"), Plan::default());
    let v: serde_json::Value = serde_json::from_str(&plan_json("{")).unwrap();
    assert_eq!(v["platform"], "");
}
