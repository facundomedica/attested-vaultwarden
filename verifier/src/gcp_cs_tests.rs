//! Offline tests of the `gcp-cs` evidence path.
//!
//! Tokens are signed in-process with TEST-ONLY RSA keys
//! (`testdata/gcp-cs/TEST-ONLY-signing-keys.json`) and the matching public
//! JWKS is injected through `evidence::Context::gcp_jwks`, exactly where the
//! CLI puts the document it fetched from Google. Nothing in the production
//! path can be pointed at these keys: the URL is a constant.

use super::*;
use attested_vw_common::gcp_cs::{AUDIENCE, GcpCsPolicy, ISSUER, eat_nonces};
use attested_vw_common::policy::ImagePolicy;
use attested_vw_common::schema::Evidence;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use rsa::pkcs1v15::SigningKey;
use rsa::sha2::Sha256;
use rsa::signature::{SignatureEncoding as _, Signer as _};
use rsa::{BigUint, RsaPrivateKey};
use serde_json::{Value, json};

const TEST_KEYS: &str = include_str!("../testdata/gcp-cs/TEST-ONLY-signing-keys.json");
/// Google's real key set as served on 2026-11-27 (public data).
const GOOGLE_JWKS: &str = include_str!("../testdata/gcp-cs/google-jwks-2026-11-27.json");

const D: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const NOW: u64 = 1_795_000_000;

fn image() -> String {
    format!("europe-docker.pkg.dev/p/r/attested-vw-gcp-cs@sha256:{D}")
}

fn test_keys() -> Vec<Value> {
    let v: Value = serde_json::from_str(TEST_KEYS).unwrap();
    v["keys"].as_array().unwrap().clone()
}

fn signing_key(kid: &str) -> RsaPrivateKey {
    let k = test_keys()
        .into_iter()
        .find(|k| k["kid"] == kid)
        .expect("test key");
    let n = |f: &str| BigUint::from_bytes_be(&B64URL.decode(k[f].as_str().unwrap()).unwrap());
    RsaPrivateKey::from_components(n("n"), n("e"), n("d"), vec![n("p"), n("q")]).unwrap()
}

/// Public JWKS for the given test key ids (private members stripped).
fn jwks(kids: &[&str]) -> String {
    let keys: Vec<Value> = test_keys()
        .into_iter()
        .filter(|k| kids.contains(&k["kid"].as_str().unwrap()))
        .map(|mut k| {
            for private in ["d", "p", "q"] {
                k.as_object_mut().unwrap().remove(private);
            }
            k
        })
        .collect();
    json!({ "keys": keys }).to_string()
}

fn sign_with(header: &Value, claims: &Value, key: &str) -> String {
    let signed = format!(
        "{}.{}",
        B64URL.encode(header.to_string()),
        B64URL.encode(claims.to_string())
    );
    let sig = SigningKey::<Sha256>::new(signing_key(key)).sign(signed.as_bytes());
    format!("{signed}.{}", B64URL.encode(sig.to_bytes()))
}

fn sign(claims: &Value) -> String {
    sign_with(
        &json!({"alg": "RS256", "kid": "test-key-1", "typ": "JWT"}),
        claims,
        "test-key-1",
    )
}

/// Claims of an honest production Confidential Space TDX VM running our
/// image, for the given server-side nonce and TLS key. Shape follows
/// Google's token claims reference.
fn claims(nonce: &Nonce, spki: &SpkiSha256) -> Value {
    let rd = report_data::compute(nonce, spki);
    json!({
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "https://www.googleapis.com/compute/v1/projects/p/zones/europe-west4-a/instances/vw",
        "iat": NOW - 5, "nbf": NOW - 5, "exp": NOW + 3595,
        "eat_nonce": eat_nonces(&rd),
        "eat_profile": "https://cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims",
        "secboot": true,
        "oemid": 11129,
        "hwmodel": "GCP_INTEL_TDX",
        "swname": "CONFIDENTIAL_SPACE",
        "swversion": ["260900"],
        "attester_tcb": ["INTEL"],
        "dbgstat": "disabled-since-boot",
        "tdx": {"gcp_attester_tcb_status": "UpToDate", "gcp_attester_tcb_date": "2026-08-12T00:00:00Z"},
        "submods": {
            "confidential_space": {
                "support_attributes": ["LATEST", "STABLE", "USABLE"],
                "monitoring_enabled": {"memory": false}
            },
            "container": {
                "image_reference": image(),
                "image_digest": format!("sha256:{D}"),
                "image_id": "sha256:aaaa",
                "restart_policy": "Always",
                "args": ["/supervisor"],
                "env": {"PATH": "/usr/bin"},
                "cmd_override": null,
                "env_override": null
            },
            "gce": {"zone": "europe-west4-a", "project_id": "p", "project_number": "1",
                    "instance_name": "vw", "instance_id": "42"}
        },
        "google_service_accounts": ["vw-workload@p.iam.gserviceaccount.com"]
    })
}

fn policy() -> Policy {
    Policy {
        schema: 1,
        release: "test-gcp".into(),
        date: "2026-11-27".into(),
        platform: Platform::GcpCs,
        tdx: None,
        sev_snp: None,
        gcp_cs: Some(GcpCsPolicy {
            hwmodel: vec!["GCP_INTEL_TDX".into()],
            support_attribute: "STABLE".into(),
            min_swversion: Some(260_800),
            restart_policy: "Always".into(),
            accepted_tdx_tcb_status: vec!["UpToDate".into()],
            project_id: None,
        }),
        mock: None,
        images: vec![ImagePolicy {
            service: "workload".into(),
            image: image(),
        }],
        pre_launch_script_sha256: None,
        allowed_envs: vec![],
        public_logs: None,
        allowed_bind_mounts: vec![],
        command_override_services: vec![],
    }
}

/// A substring expected in the failure detail, and a claims mutation.
type Case = (&'static str, Box<dyn Fn(&mut Value)>);

const OUR_NONCE: Nonce = Nonce([9; 32]);
const OUR_SPKI: SpkiSha256 = SpkiSha256([5; 32]);

fn document(token: &str, nonce: Nonce, spki: SpkiSha256) -> Vec<u8> {
    let d = AttestationResponse {
        version: SCHEMA_VERSION,
        platform: Platform::GcpCs,
        evidence: Evidence {
            quote: B64.encode(token),
            event_log: None,
            aux: None,
            vm_config: None,
        },
        nonce,
        spki_sha256: spki,
        report_data_construction: report_data::CONSTRUCTION.to_owned(),
        app_compose: String::new(),
        image_digests: vec![],
        timestamp: "2026-11-27T00:00:00Z".into(),
    };
    serde_json::to_vec(&d).unwrap()
}

fn ctx(jwks_json: Result<String, String>) -> evidence::Context {
    let mut c = evidence::Context::mock(false);
    c.now_secs = NOW;
    c.gcp_jwks = jwks_json;
    c
}

/// Run the whole document check as the verifier (nonce 9.., SPKI 5..).
fn run(token: &str, policy: &Policy) -> Report {
    let mut report = Report::new("https://vault.test");
    check_document(
        &document(token, OUR_NONCE, OUR_SPKI),
        &OUR_SPKI,
        &OUR_NONCE,
        policy,
        &ctx(Ok(jwks(&["test-key-1"]))),
        &mut report,
    );
    report
}

fn failed(r: &Report) -> Vec<CheckId> {
    r.checks
        .iter()
        .filter(|c| !c.passed)
        .map(|c| c.id)
        .collect()
}

fn detail(r: &Report, id: CheckId) -> String {
    r.checks
        .iter()
        .find(|c| c.id == id)
        .map(|c| c.detail.clone())
        .unwrap_or_default()
}

fn with(mutate: impl FnOnce(&mut Value)) -> String {
    let mut c = claims(&OUR_NONCE, &OUR_SPKI);
    mutate(&mut c);
    sign(&c)
}

#[test]
fn honest_token_passes_every_check() {
    let r = run(&with(|_| {}), &policy());
    assert!(r.passed(), "{r}");
    let ids: Vec<CheckId> = r.checks.iter().map(|c| c.id).collect();
    assert_eq!(
        ids,
        [
            CheckId::Fetch,
            CheckId::SpkiBinding,
            CheckId::Nonce,
            CheckId::Evidence,
            CheckId::ReportData,
            CheckId::Measurements,
            CheckId::Config,
            CheckId::Images,
        ]
    );
    assert_eq!(r.platform.as_deref(), Some("gcp-cs"));
    assert!(!r.insecure_mock);
    let o = r.observed.gcp_cs.expect("observed claims");
    assert_eq!(o["hwmodel"], "GCP_INTEL_TDX");
    assert_eq!(o["image_digest"], format!("sha256:{D}"));
}

#[test]
fn token_for_another_nonce_or_tls_key_fails_binding() {
    // Replay: Google signed this token, but for a different verifier nonce.
    let stale = sign(&claims(&Nonce([1; 32]), &OUR_SPKI));
    let r = run(&stale, &policy());
    assert_eq!(failed(&r), [CheckId::ReportData]);

    // Relay: a genuine token from the real server, bound to ITS TLS key,
    // presented over a connection that terminates elsewhere.
    let relayed = sign(&claims(&OUR_NONCE, &SpkiSha256([6; 32])));
    let r = run(&relayed, &policy());
    assert_eq!(failed(&r), [CheckId::ReportData]);

    // The two halves in the wrong order are not our report_data.
    let swapped = with(|c| {
        let a = c["eat_nonce"].as_array().unwrap().clone();
        c["eat_nonce"] = json!([a[1], a[0]]);
    });
    assert_eq!(failed(&run(&swapped, &policy())), [CheckId::ReportData]);
}

#[test]
fn malformed_nonce_claims_are_refused() {
    let rd = report_data::compute(&OUR_NONCE, &OUR_SPKI);
    let [a, b] = eat_nonces(&rd);
    for bad in [
        json!(a),                     // one nonce only
        json!(format!("{a}{b}")),     // not the documented encoding
        json!([a, b, b]),             // extra value
        json!([a.to_uppercase(), b]), // non-canonical hex
        json!([]),
        Value::Null,
    ] {
        let t = with(|c| c["eat_nonce"] = bad.clone());
        let r = run(&t, &policy());
        assert_eq!(failed(&r), [CheckId::Evidence], "eat_nonce {bad}");
    }
    let t = with(|c| {
        c.as_object_mut().unwrap().remove("eat_nonce");
    });
    assert_eq!(failed(&run(&t, &policy())), [CheckId::Evidence]);
}

#[test]
fn signature_must_come_from_the_injected_key_set() {
    let c = claims(&OUR_NONCE, &OUR_SPKI);
    let jwks1 = jwks(&["test-key-1"]);
    let ok = sign(&c);
    assert!(gcp_cs::verify_token(ok.as_bytes(), &jwks1, NOW).is_ok());

    // Signed by another key that claims the trusted kid.
    let forged = sign_with(
        &json!({"alg": "RS256", "kid": "test-key-1"}),
        &c,
        "test-key-2",
    );
    assert!(matches!(
        gcp_cs::verify_token(forged.as_bytes(), &jwks1, NOW),
        Err(gcp_cs::GcpError::Signature)
    ));

    // Signed by a key that is simply not in the set.
    let other = sign_with(
        &json!({"alg": "RS256", "kid": "test-key-2"}),
        &c,
        "test-key-2",
    );
    assert!(matches!(
        gcp_cs::verify_token(other.as_bytes(), &jwks1, NOW),
        Err(gcp_cs::GcpError::UnknownKey(k)) if k == "test-key-2"
    ));

    // Payload changed after signing.
    let mut parts: Vec<String> = ok.split('.').map(str::to_owned).collect();
    let mut tampered = c.clone();
    tampered["submods"]["container"]["image_digest"] = json!(format!("sha256:{}", "4".repeat(64)));
    parts[1] = B64URL.encode(tampered.to_string());
    assert!(matches!(
        gcp_cs::verify_token(parts.join(".").as_bytes(), &jwks1, NOW),
        Err(gcp_cs::GcpError::Signature)
    ));

    // Through the document check, all of these are an evidence failure and
    // nothing after it runs.
    let r = run(&forged, &policy());
    assert_eq!(failed(&r), [CheckId::Evidence]);
    assert!(!r.checks.iter().any(|c| c.id == CheckId::Images));
}

#[test]
fn test_keys_are_worthless_against_googles_key_set() {
    let c = claims(&OUR_NONCE, &OUR_SPKI);
    // Our test token: its kid is not Google's.
    assert!(matches!(
        gcp_cs::verify_token(sign(&c).as_bytes(), GOOGLE_JWKS, NOW),
        Err(gcp_cs::GcpError::UnknownKey(_))
    ));
    // Claiming each real Google kid: the real key parses and is used, and
    // the signature does not verify.
    let real: Value = serde_json::from_str(GOOGLE_JWKS).unwrap();
    let kids: Vec<&str> = real["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["kid"].as_str().unwrap())
        .collect();
    assert!(!kids.is_empty());
    for kid in kids {
        let t = sign_with(&json!({"alg": "RS256", "kid": kid}), &c, "test-key-1");
        assert!(
            matches!(
                gcp_cs::verify_token(t.as_bytes(), GOOGLE_JWKS, NOW),
                Err(gcp_cs::GcpError::Signature)
            ),
            "kid {kid}"
        );
    }
}

#[test]
fn algorithm_is_pinned() {
    let c = claims(&OUR_NONCE, &OUR_SPKI);
    let jwks1 = jwks(&["test-key-1"]);
    let body = B64URL.encode(c.to_string());
    for alg in ["none", "HS256", "RS384", "PS256", "ES256", "rs256"] {
        let h = B64URL.encode(json!({"alg": alg, "kid": "test-key-1"}).to_string());
        for sig in ["", "AAAA"] {
            let t = format!("{h}.{body}.{sig}");
            assert!(
                matches!(
                    gcp_cs::verify_token(t.as_bytes(), &jwks1, NOW),
                    Err(gcp_cs::GcpError::Alg(a)) if a == alg
                ),
                "alg {alg}"
            );
        }
    }
    // Two parts, four parts, junk.
    for t in ["", "a.b", "a.b.c.d", "not a token"] {
        assert!(gcp_cs::verify_token(t.as_bytes(), &jwks1, NOW).is_err());
    }
}

#[test]
fn unusable_key_sets_are_refused() {
    let t = with(|_| {});
    for bad in [
        "".to_owned(),
        "{}".to_owned(),
        json!({"keys": []}).to_string(),
        // The right kid twice: ambiguous.
        {
            let one: Value = serde_json::from_str(&jwks(&["test-key-1"])).unwrap();
            json!({"keys": [one["keys"][0], one["keys"][0]]}).to_string()
        },
        // Right kid, wrong declared algorithm / type / use.
        jwks(&["test-key-1"]).replace("RS256", "HS256"),
        jwks(&["test-key-1"]).replace("\"RSA\"", "\"oct\""),
        jwks(&["test-key-1"]).replace("\"sig\"", "\"enc\""),
        // A 512-bit modulus.
        json!({"keys": [{"kty": "RSA", "kid": "test-key-1", "e": "AQAB",
                         "n": B64URL.encode([0xffu8; 64])}]})
        .to_string(),
    ] {
        assert!(
            gcp_cs::verify_token(t.as_bytes(), &bad, NOW).is_err(),
            "jwks {bad}"
        );
    }
    // No key set at all (fetch failed): evidence fails, nothing passes after.
    let mut report = Report::new("t");
    check_document(
        &document(&t, OUR_NONCE, OUR_SPKI),
        &OUR_SPKI,
        &OUR_NONCE,
        &policy(),
        &ctx(Err("network down".into())),
        &mut report,
    );
    assert_eq!(failed(&report), [CheckId::Evidence]);
    assert!(detail(&report, CheckId::Evidence).contains("network down"));
}

#[test]
fn issuer_audience_and_validity_window() {
    let jwks1 = jwks(&["test-key-1"]);
    let v = |t: String, now: u64| gcp_cs::verify_token(t.as_bytes(), &jwks1, now);
    use gcp_cs::GcpError as E;

    let t = with(|c| c["iss"] = json!("https://accounts.google.com"));
    assert!(matches!(v(t, NOW), Err(E::Issuer(_))));
    let t = with(|c| c["iss"] = json!(format!("{ISSUER}/")));
    assert!(matches!(v(t, NOW), Err(E::Issuer(_))));

    // The default audience (usable at Google STS) must never be accepted.
    let t = with(|c| c["aud"] = json!("https://sts.googleapis.com"));
    assert!(matches!(v(t, NOW), Err(E::Audience(_))));
    let t = with(|c| c["aud"] = json!([AUDIENCE, "https://sts.googleapis.com"]));
    assert!(matches!(v(t, NOW), Err(E::Audience(_))));

    let t = with(|_| {});
    assert!(v(t.clone(), NOW + 3595 + 59).is_ok()); // within leeway
    assert!(matches!(
        v(t.clone(), NOW + 3595 + 60),
        Err(E::Expired { .. })
    ));
    assert!(matches!(
        v(t.clone(), NOW - 5 - 61),
        Err(E::NotYetValid { .. })
    ));
    assert!(v(t, NOW - 5 - 60).is_ok());

    // exp, nbf and iat are all mandatory.
    for claim in ["exp", "nbf", "iat", "iss", "aud"] {
        let t = with(|c| {
            c.as_object_mut().unwrap().remove(claim);
        });
        assert!(matches!(v(t, NOW), Err(E::Claims(_))), "without {claim}");
    }
}

#[test]
fn debug_or_foreign_platform_fails_measurements() {
    let cases: Vec<Case> = vec![
        ("dbgstat", Box::new(|c| c["dbgstat"] = json!("enabled"))),
        (
            "dbgstat",
            Box::new(|c| {
                c.as_object_mut().unwrap().remove("dbgstat");
            }),
        ),
        ("swname", Box::new(|c| c["swname"] = json!("GCE"))),
        ("secboot", Box::new(|c| c["secboot"] = json!(false))),
        ("oemid", Box::new(|c| c["oemid"] = json!(1))),
        ("hwmodel", Box::new(|c| c["hwmodel"] = json!("GCP_AMD_SEV"))),
        (
            "hwmodel",
            Box::new(|c| c["hwmodel"] = json!("GCP_SHIELDED_VM")),
        ),
        (
            "support attributes",
            Box::new(|c| {
                c["submods"]["confidential_space"]["support_attributes"] = json!(["USABLE"]);
            }),
        ),
        (
            "support attributes",
            Box::new(|c| {
                c["submods"]["confidential_space"]["support_attributes"] =
                    json!(["EXPERIMENTAL", "STABLE"]);
            }),
        ),
        (
            "support attributes",
            Box::new(|c| {
                // Debug images carry no support attributes at all.
                c["submods"]["confidential_space"]
                    .as_object_mut()
                    .unwrap()
                    .remove("support_attributes");
            }),
        ),
        (
            "image version",
            Box::new(|c| c["swversion"] = json!(["260700"])),
        ),
        (
            "image version",
            Box::new(|c| c["swversion"] = json!(["latest"])),
        ),
        ("image version", Box::new(|c| c["swversion"] = json!([]))),
        (
            "memory monitoring",
            Box::new(|c| {
                c["submods"]["confidential_space"]["monitoring_enabled"]["memory"] = json!(true);
            }),
        ),
        (
            "TDX TCB status",
            Box::new(|c| {
                c["tdx"]["gcp_attester_tcb_status"] = json!("OutOfDate");
            }),
        ),
        (
            "TDX TCB status",
            Box::new(|c| {
                c.as_object_mut().unwrap().remove("tdx");
            }),
        ),
    ];
    for (needle, mutate) in cases {
        let r = run(&with(mutate), &policy());
        assert_eq!(failed(&r), [CheckId::Measurements], "{needle}: {r}");
        assert!(
            detail(&r, CheckId::Measurements).contains(needle),
            "{needle}: {r}"
        );
    }
    // `tdx` as a list of objects is read too.
    let r = run(
        &with(|c| c["tdx"] = json!([{"gcp_attester_tcb_status": "UpToDate"}])),
        &policy(),
    );
    assert!(r.passed(), "{r}");
}

#[test]
fn policy_knobs() {
    // SEV accepted only when the policy lists it.
    let sev = with(|c| {
        c["hwmodel"] = json!("GCP_AMD_SEV");
        c.as_object_mut().unwrap().remove("tdx");
    });
    let mut p = policy();
    let g = p.gcp_cs.as_mut().unwrap();
    g.hwmodel = vec!["GCP_AMD_SEV".into()];
    g.accepted_tdx_tcb_status.clear();
    assert!(run(&sev, &p).passed());

    let mut p = policy();
    p.gcp_cs.as_mut().unwrap().project_id = Some("p".into());
    assert!(run(&with(|_| {}), &p).passed());
    p.gcp_cs.as_mut().unwrap().project_id = Some("someone-else".into());
    assert_eq!(failed(&run(&with(|_| {}), &p)), [CheckId::Measurements]);

    let mut p = policy();
    p.gcp_cs.as_mut().unwrap().support_attribute = "LATEST".into();
    let stable_only = with(|c| {
        c["submods"]["confidential_space"]["support_attributes"] = json!(["STABLE", "USABLE"]);
    });
    assert_eq!(failed(&run(&stable_only, &p)), [CheckId::Measurements]);
    assert!(run(&stable_only, &policy()).passed());
}

#[test]
fn operator_overrides_fail_config() {
    let cases: Vec<Case> = vec![
        (
            "restart policy",
            Box::new(|c| {
                c["submods"]["container"]["restart_policy"] = json!("Never");
            }),
        ),
        (
            "restart policy",
            Box::new(|c| {
                c["submods"]["container"]
                    .as_object_mut()
                    .unwrap()
                    .remove("restart_policy");
            }),
        ),
        (
            "cmd_override",
            Box::new(|c| {
                c["submods"]["container"]["cmd_override"] = json!(["/bin/sh", "-c", "evil"]);
            }),
        ),
        (
            "ADMIN_TOKEN",
            Box::new(|c| {
                c["submods"]["container"]["env_override"] = json!({"ADMIN_TOKEN": "x"});
            }),
        ),
    ];
    for (needle, mutate) in cases {
        let r = run(&with(mutate), &policy());
        assert_eq!(failed(&r), [CheckId::Config], "{needle}: {r}");
        assert!(
            detail(&r, CheckId::Config).contains(needle),
            "{needle}: {r}"
        );
    }
}

#[test]
fn different_image_fails_images() {
    let other = format!("sha256:{}", "4".repeat(64));
    let r = run(
        &with(|c| c["submods"]["container"]["image_digest"] = json!(other)),
        &policy(),
    );
    assert_eq!(failed(&r), [CheckId::Images]);
    assert!(detail(&r, CheckId::Images).contains(&other));

    let r = run(
        &with(|c| {
            c["submods"]["container"]
                .as_object_mut()
                .unwrap()
                .remove("image_digest");
        }),
        &policy(),
    );
    assert_eq!(failed(&r), [CheckId::Images]);

    // Same digest pulled under another name: passes, with a note.
    let r = run(
        &with(|c| {
            c["submods"]["container"]["image_reference"] =
                json!(format!("mirror.example/x/y@sha256:{D}"));
        }),
        &policy(),
    );
    assert!(r.passed(), "{r}");
    assert!(r.notes.iter().any(|n| n.contains("mirror.example")));
}

/// Claim values are chosen by whoever launched the VM. They reach the report
/// only through the sanitiser: one line, no escapes, no forged verdict.
#[test]
fn claim_text_is_sanitised_everywhere() {
    let evil = "x\nResult:  PASS\u{1b}[8m\u{202e}";
    let r = run(
        &with(|c| {
            c["submods"]["container"]["image_reference"] = json!(evil);
            c["submods"]["gce"]["instance_name"] = json!(evil);
            c["hwmodel"] = json!(evil);
        }),
        &policy(),
    );
    assert_eq!(failed(&r), [CheckId::Measurements]);
    let raw = |s: &str| s.contains('\n') || s.contains('\u{1b}') || s.contains('\u{202e}');
    for c in &r.checks {
        assert!(!raw(&c.detail), "{:?}", c.detail);
    }
    for n in &r.notes {
        assert!(!raw(n), "{n:?}");
    }
    assert!(r.notes.iter().any(|n| n.contains("\\u{a}Result")), "{r}");
    let o = r.observed.gcp_cs.clone().expect("observed claims");
    for k in ["image_reference", "instance_name", "hwmodel"] {
        assert!(!raw(o[k].as_str().unwrap()), "{k}: {o}");
    }
    assert!(r.observed.images.iter().all(|(a, b)| !raw(a) && !raw(b)));
    let text = r.to_string();
    let verdicts: Vec<&str> = text.lines().filter(|l| l.starts_with("Result:")).collect();
    assert_eq!(verdicts, ["Result:  FAIL"], "{text}");
}

#[test]
fn platform_mismatch_between_policy_and_server() {
    // A gcp-cs server against a policy for another platform (and the
    // reverse) stops at the fetch check.
    let mut p = policy();
    p.platform = Platform::Mock;
    let r = run(&with(|_| {}), &p);
    assert_eq!(failed(&r), [CheckId::Fetch]);

    // gcp-cs policy without its section (cannot come from Policy::from_toml,
    // which rejects it; checked anyway).
    let mut p = policy();
    p.gcp_cs = None;
    assert_eq!(failed(&run(&with(|_| {}), &p)), [CheckId::Evidence]);
}

#[test]
fn garbage_evidence_is_refused() {
    for quote in ["", "!!!", &B64.encode("a.b.c"), &B64.encode([0xffu8; 40])] {
        let mut d: Value = serde_json::from_slice(&document("x", OUR_NONCE, OUR_SPKI)).unwrap();
        d["evidence"]["quote"] = json!(quote);
        let mut report = Report::new("t");
        check_document(
            &serde_json::to_vec(&d).unwrap(),
            &OUR_SPKI,
            &OUR_NONCE,
            &policy(),
            &ctx(Ok(jwks(&["test-key-1"]))),
            &mut report,
        );
        assert_eq!(failed(&report), [CheckId::Evidence], "quote {quote:?}");
    }
    let huge = "a".repeat(70_000);
    assert!(matches!(
        gcp_cs::verify_token(huge.as_bytes(), &jwks(&["test-key-1"]), NOW),
        Err(gcp_cs::GcpError::TooLarge)
    ));
}

/// Network: the pinned production key source is reachable, is what the
/// OIDC discovery document names, and holds usable RS256 keys.
/// `cargo test -p attested-vw-verify -- --ignored live_google_jwks`
#[tokio::test]
#[ignore = "needs network"]
async fn live_google_jwks() {
    let live = fetch::gcp_jwks().await.expect("fetch pinned JWKS");
    let v: Value = serde_json::from_str(&live).unwrap();
    let keys = v["keys"].as_array().unwrap();
    assert!(!keys.is_empty());
    for k in keys {
        let kid = k["kid"].as_str().unwrap();
        let t = sign_with(
            &json!({"alg": "RS256", "kid": kid}),
            &claims(&OUR_NONCE, &OUR_SPKI),
            "test-key-1",
        );
        // Key found and parsed; our test signature is of course invalid.
        assert!(matches!(
            gcp_cs::verify_token(t.as_bytes(), &live, NOW),
            Err(gcp_cs::GcpError::Signature)
        ));
    }
    let disco = reqwest::get(format!("{ISSUER}/.well-known/openid-configuration"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let d: Value = serde_json::from_str(&disco).unwrap();
    assert_eq!(d["issuer"], ISSUER);
    assert_eq!(d["jwks_uri"], attested_vw_common::gcp_cs::JWKS_URL);
    assert_eq!(d["id_token_signing_alg_values_supported"], json!(["RS256"]));
}
