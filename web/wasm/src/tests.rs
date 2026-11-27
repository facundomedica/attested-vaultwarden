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
