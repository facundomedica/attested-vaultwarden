// Headless test of the built page (web/dist/index.html) in Node: the same
// wasm, glue and page script the browser runs, extracted from the artifact.
//
//   node web/test/run.mjs                    offline tests (recorded evidence, mock network)
//   node web/test/run.mjs --live <host> [--policy <name>] [--known <spki>]... [--record <file>]
//                                            one real run; prints the report
//
// Node's fetch does not enforce CORS, so a live run here does not prove a
// browser may read the responses; check the headers separately (README).
import assert from "node:assert/strict";
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const web = join(dirname(fileURLToPath(import.meta.url)), "..");
const root = join(web, "..");
const html = readFileSync(join(web, "dist", "index.html"), "utf8");

function block(id) {
  const m = html.match(new RegExp(`<script type="[^"]+" id="${id}">([\\s\\S]*?)</script>`));
  assert(m, `no ${id} block in the page`);
  return m[1];
}
const inline = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
assert.equal(inline.length, 2, "expected exactly two inline scripts (glue, app)");
const bundle = JSON.parse(block("avw-bundle"));
const wasmBytes = Buffer.from(block("avw-wasm").trim(), "base64");

const wasm = new Function(`${inline[0]}\nreturn wasm_bindgen;`)();
await wasm({ module_or_path: wasmBytes });
const AVW = new Function("wasm_bindgen", `${inline[1]}\nreturn AVW;`)(wasm);

const env = (fetchFn, nowMs) => ({
  wasm,
  fetch: fetchFn,
  now: () => nowMs ?? Date.now(),
  randomBytes: (n) => crypto.getRandomValues(new Uint8Array(n)),
});
const marks = (out) => out.report.checks.map((c) => `${c.passed ? "+" : "-"}${c.id}`);

// ------------------------------------------------------------------ live
const args = process.argv.slice(2);
if (args[0] === "--live") {
  const host = args[1];
  const opt = (name) => args.flatMap((a, i) => (a === name ? [args[i + 1]] : []));
  const names = Object.keys(bundle.policies).sort();
  const policy = opt("--policy")[0] || names[names.length - 1];
  assert(bundle.policies[policy], `no bundled policy ${policy}; have ${names.join(", ")}`);
  const known = [
    ...bundle.known_spkis.filter((k) => k.host === host).map((k) => k.spki),
    ...opt("--known"),
  ];
  const e = env((u, o) => fetch(u, o));
  const { input, output } = await AVW.run(e, {
    host,
    policyToml: bundle.policies[policy],
    knownSpkis: known,
    onProgress: (m) => console.error(`… ${m}`),
  });
  const withTags = output.report ? await AVW.lookupTags(e, input, output) : null;
  console.log((withTags || output).text || `FAIL: ${output.error}`);
  for (const c of output.ct_certs || []) {
    console.log(`  CT ${c.status}  ${c.not_before} → ${c.not_after}  ${c.issuer}  ${c.dns_names.join(",")}  ${c.pubkey_sha256}`);
  }
  const rec = opt("--record")[0];
  if (rec) {
    // The verdict-relevant inputs only (no Docker Hub answers), so the
    // replay is exactly what the verifier saw.
    writeFileSync(
      rec,
      JSON.stringify({ policy, input, expect_passed: output.passed, expect_text: output.text }, null, 1) + "\n",
    );
    console.error(`recorded ${rec}`);
  }
  process.exit(output.passed ? 0 : 1);
}

// --------------------------------------------------------------- offline
// Recorded evidence: the upstream dstack TDX quote + event log and the
// Intel collateral we recorded for it (verifier/testdata/SOURCES.md),
// served by a mock network shaped like the real services.
const gq = JSON.parse(readFileSync(join(root, "verifier/testdata/dstack/tdx-lite-getquote.json"), "utf8"));
const rec = JSON.parse(readFileSync(join(root, "verifier/testdata/dstack/tdx-lite-collateral.json"), "utf8"));
const col = rec.collateral;
const HOST = "vault.fixture.example";
const KEY = "a".repeat(64);
const image = `docker.io/vaultwarden/server@sha256:${"3".repeat(64)}`;
const mr = (off) => gq.quote.slice(2 * off, 2 * (off + 48));
const policyToml = `schema = 1
release = "fixture"
date = "2026-11-26"
platform = "tdx"
[tdx]
mrtd = "${mr(184)}"
rtmr0 = "${mr(376)}"
rtmr1 = "${mr(424)}"
rtmr2 = "${mr(472)}"
compose_hash = "60618cd0c23d15d921b788b8fc3a0d024ac72295185da3ba41d5a065bc7aa833"
accepted_tcb_status = ["UpToDate"]
allow_smt = true
allow_dynamic_platform = true
allow_cached_keys = true
require_storage_encrypted = false
app_id = "60618cd0c23d15d921b788b8fc3a0d024ac72295"
key_provider = '{"name":"none","id":""}'
min_tcb_eval_data_number = 20
[[images]]
service = "vaultwarden"
image = "${image}"
`;

const requests = [];
function mockNetwork({ cors = true, up = true, ct = "ok", pccs = true } = {}) {
  const res = (status, body, headers = {}) => new Response(body, { status, headers });
  return async (url, opts = {}) => {
    const u = new URL(url);
    requests.push(`${opts.mode === "no-cors" ? "(no-cors) " : ""}${u.origin}${u.pathname}`);
    assert.equal(opts.credentials, "omit", "requests must not carry credentials");
    if (u.host === HOST) {
      if (!up) throw new TypeError("fetch failed");
      if (!cors && opts.mode !== "no-cors") throw new TypeError("Failed to fetch");
      if (opts.mode === "no-cors") return res(200, "");
      assert.equal(u.pathname, "/.well-known/tee-attestation");
      assert.equal(opts.redirect, "error");
      const nonce = u.searchParams.get("nonce");
      assert.match(nonce, /^[0-9a-f]{64}$/);
      return res(
        200,
        JSON.stringify({
          version: 1,
          platform: "tdx",
          evidence: { quote: Buffer.from(gq.quote, "hex").toString("base64"), event_log: gq.event_log },
          nonce,
          spki_sha256: KEY,
          report_data_construction: 'SHA-512("attested-vaultwarden/v1" || nonce[32] || spki_sha256[32])',
          app_compose: JSON.stringify({
            docker_compose_file: `services:\n  vaultwarden:\n    image: ${image}\n`,
          }),
          image_digests: [{ service: "vaultwarden", image }],
          timestamp: "2026-11-26T00:00:00Z",
        }),
      );
    }
    if (u.host === "pccs.phala.network") {
      if (!pccs) return res(503, "down");
      const enc = encodeURIComponent;
      if (u.pathname.endsWith("/pckcrl")) {
        return res(200, Buffer.from(col.pck_crl, "hex"), { "SGX-PCK-CRL-Issuer-Chain": enc(col.pck_crl_issuer_chain) });
      }
      if (u.pathname.endsWith("/tcb")) {
        return res(
          200,
          `{"tcbInfo":${col.tcb_info},"signature":"${col.tcb_info_signature}"}`,
          { "TCB-Info-Issuer-Chain": enc(col.tcb_info_issuer_chain) },
        );
      }
      if (u.pathname.endsWith("/qe/identity")) {
        return res(
          200,
          `{"enclaveIdentity":${col.qe_identity},"signature":"${col.qe_identity_signature}"}`,
          { "SGX-Enclave-Identity-Issuer-Chain": enc(col.qe_identity_issuer_chain) },
        );
      }
      if (u.pathname.endsWith("/rootcacrl")) return res(200, col.root_ca_crl);
      return res(404, "");
    }
    if (u.host === "api.certspotter.com") {
      if (ct === "429") return res(429, '{"code":"rate_limited"}');
      const domain = u.searchParams.get("domain");
      if (u.searchParams.get("after")) return res(200, "[]");
      const cert = (id, names, key) => ({
        id, dns_names: names, pubkey_sha256: key,
        not_before: "2026-11-01T00:00:00Z", not_after: "2027-02-01T00:00:00Z",
        issuer: { friendly_name: "Test CA" },
      });
      if (domain === HOST) return res(200, JSON.stringify([cert("1", [HOST], KEY)]));
      if (domain === "fixture.example") {
        return res(200, JSON.stringify(ct === "wildcard" ? [cert("2", ["*.fixture.example"], "b".repeat(64))] : []));
      }
      return res(200, "[]");
    }
    if (u.host === "hub.docker.com") throw new TypeError("Failed to fetch"); // no CORS
    throw new Error(`unexpected request to ${url}`);
  };
}

const NOW = rec.recorded_at_unix * 1000;
const go = (net) => AVW.run(env(mockNetwork(net), NOW), { host: HOST, policyToml, knownSpkis: [] });
let n = 0;
const test = async (name, f) => {
  await f();
  n++;
  console.log(`ok ${n} - ${name}`);
};

// The dstack fixture's collateral must be in the shape dcap-qvl serialises.
assert(typeof col.tcb_info === "string" && /^[0-9a-f]+$/.test(col.pck_crl), "collateral fixture shape");

await test("recorded TDX evidence through the page's whole pipeline", async () => {
  requests.length = 0;
  const { input, output } = await go();
  // Collateral was fetched by dcap-qvl (in wasm) through our fetch, and the
  // Intel signatures over it verified: evidence passes.
  assert.deepEqual(marks(output), [
    "+fetch", "+nonce", "+evidence",
    "-report_data_claimed", // fixture quote was made for report_data 0x42…, not our nonce
    "+measurements", "+event_log",
    "-compose_hash", // upstream fixture's compose document is not available
    "+config", "+images",
    "-ct_binding", // no key was attested, so nothing can match
  ], output.text);
  assert.equal(output.passed, false);
  assert.match(output.text, /TCB UpToDate.*TD debug off/);
  assert.match(output.text, /9 RTMR3 events replay to the quoted RTMR3/);
  assert.doesNotMatch(output.text, /TLS key bound to attestation:/);
  assert.match(output.text, /browser mode: a web page cannot read the TLS certificate/);
  assert.match(output.text, /Result: {2}FAIL$/);
  assert(output.text.includes(`\n      vaultwarden  ${image}\n`), "image line with full digest");
  for (const want of [
    `https://${HOST}/.well-known/tee-attestation`,
    "https://pccs.phala.network/sgx/certification/v4/pckcrl",
    "https://pccs.phala.network/tdx/certification/v4/tcb",
    "https://pccs.phala.network/tdx/certification/v4/qe/identity",
    "https://pccs.phala.network/sgx/certification/v4/rootcacrl",
    "https://api.certspotter.com/v1/issuances",
  ]) assert(requests.includes(want), `expected a request to ${want}; got ${requests.join(", ")}`);
  assert.equal(JSON.parse(input.collateral).tcb_info, col.tcb_info);

  // Display-only tag lookup: blocked like in a browser; verdict untouched.
  const again = await AVW.lookupTags(env(mockNetwork(), NOW), input, output);
  assert.deepEqual(marks(again), marks(output));
  assert.match(again.text, /\n {8}\(Docker Hub tag lookup failed: blocked by the browser/);
});

await test("server without CORS (release before 2026.11.3): clear error", async () => {
  const { output } = await go({ cors: false });
  assert.deepEqual(marks(output), ["-fetch"]);
  assert.match(output.text, /sends no Access-Control-Allow-Origin header \(releases before 2026\.11\.3 do not\)/);
  assert.match(output.text, /use the command-line verifier/);
  assert.match(output.text, /Result: {2}FAIL$/);
});

await test("unreachable server", async () => {
  const { output } = await go({ up: false });
  assert.deepEqual(marks(output), ["-fetch"]);
  assert.match(output.text, /could not reach https:\/\/vault\.fixture\.example/);
});

await test("PCCS mirror down: evidence fails, no fallback", async () => {
  const { output } = await go({ pccs: false });
  assert(marks(output).includes("-evidence"), output.text);
  assert.match(output.text, /no Intel collateral available.*pccs\.phala\.network/);
});

await test("Cert Spotter rate limit: CT check fails", async () => {
  const { output } = await go({ ct: "429" });
  assert(marks(output).includes("-ct_binding"));
  assert.match(output.text, /Cert Spotter answered HTTP 429/);
});

await test("unattested wildcard certificate of the parent is listed", async () => {
  const { output } = await go({ ct: "wildcard" });
  assert(marks(output).includes("-ct_binding"));
  const w = output.ct_certs.find((c) => c.wildcard);
  assert.equal(w.status, "never_attested");
  assert.match(output.text, /\*\.fixture\.example/);
});

await test("not a domain name", async () => {
  const { output } = await AVW.run(env(mockNetwork(), NOW), { host: "https://x y", policyToml, knownSpkis: [] });
  assert.equal(output.passed, false);
  assert.match(output.error, /not a domain name/);
});

await test("bundle: policies load in the verifier, or are refused with a reason", async () => {
  const names = Object.keys(bundle.policies).sort();
  assert(names.length > 0);
  const load = (name) =>
    JSON.parse(
      wasm.verify(JSON.stringify({ host: HOST, nonce: "0".repeat(64), policy_toml: bundle.policies[name], now_secs: 1, fetch_error: "x" })),
    );
  for (const name of names) {
    const out = load(name);
    // Old policy formats (before app_id became mandatory) are refused.
    if (out.report.policy_release === null) assert.match(out.text, /cannot load the bundled policy/, name);
    else assert.equal(out.report.policy_release, name);
  }
  // The newest one, which the page selects by default, must load.
  assert.equal(load(names[names.length - 1]).report.policy_release, names[names.length - 1]);
});

// ---------------------------------------------- gcp-cs and sev-snp
// A small mock network for the other two platforms: the attestation
// endpoint serves `doc(nonce)`, Cert Spotter lists one certificate with
// `ctKey`, and `routes` maps exact URL prefixes to responses.
const ctCert = (host, key) =>
  JSON.stringify([{
    id: "1", dns_names: [host], pubkey_sha256: key,
    not_before: "2026-11-01T00:00:00Z", not_after: "2027-02-01T00:00:00Z",
    issuer: { friendly_name: "Test CA" },
  }]);
function platformNetwork({ host, doc, ctKey, routes }) {
  return async (url, opts = {}) => {
    const u = new URL(url);
    requests.push(String(url).split("?")[0]);
    assert.equal(opts.credentials, "omit", "requests must not carry credentials");
    assert.equal(opts.referrerPolicy, "no-referrer");
    if (u.host === host) return new Response(doc(u.searchParams.get("nonce")), { status: 200 });
    if (u.host === "api.certspotter.com") {
      const first = !u.searchParams.get("after") && u.searchParams.get("domain") === host;
      return new Response(first ? ctCert(host, ctKey) : "[]", { status: 200 });
    }
    for (const [prefix, answer] of Object.entries(routes)) {
      if (String(url).startsWith(prefix)) {
        assert.equal(opts.redirect, "error", "trust material must not follow redirects");
        return answer(url);
      }
    }
    throw new Error(`unexpected request to ${url}`);
  };
}
const fromHex = (h) => Uint8Array.from(h.match(/../g), (b) => parseInt(b, 16));

// Google Cloud Confidential Space: the document a real Confidential Space
// VM served on 2026-11-27, Google's real key set of that day, the committed
// release policy, and the clock pinned inside the token's hour.
const gcpDoc = readFileSync(join(root, "verifier/testdata/gcp-cs/live-2026-11-27.document.json"), "utf8");
const gcpJwks = readFileSync(join(root, "verifier/testdata/gcp-cs/google-jwks-2026-11-27.json"), "utf8");
const gcp = JSON.parse(gcpDoc);
const GCP_HOST = "vault.gcp.facundo.dev";
const GCP_POLICY = "2026.11.0-gcp-cs-dev";
const GCP_NOW = (1795775236 + 60) * 1000;
const goGcp = ({ jwks = () => new Response(gcpJwks, { status: 200 }), ctKey = gcp.spki_sha256, now = GCP_NOW, nonce = gcp.nonce, policy = bundle.policies[GCP_POLICY] } = {}) => {
  requests.length = 0;
  const e = env(
    platformNetwork({
      host: GCP_HOST,
      // The recorded answer, whatever nonce is asked for (a replay if the
      // page's nonce differs).
      doc: () => gcpDoc,
      ctKey,
      routes: { [AVW.GCP_JWKS_URL]: jwks },
    }),
    now,
  );
  // The page's "random" nonce is the one the recorded token was made for.
  e.randomBytes = () => fromHex(nonce);
  return AVW.run(e, { host: GCP_HOST, policyToml: policy, knownSpkis: [] });
};

await test("gcp-cs: recorded real token, JWKS fetched live by the page: PASS (browser mode)", async () => {
  assert(bundle.policies[GCP_POLICY], "gcp-cs policy is bundled");
  const { input, output } = await goGcp();
  assert.deepEqual(marks(output), [
    "+fetch", "+nonce", "+evidence", "+report_data_claimed",
    "+measurements", "+config", "+images", "+ct_binding",
  ], output.text);
  assert.equal(output.passed, true);
  assert.match(output.text, /Result: {2}PASS \(browser mode: CT-based binding\)$/);
  assert.match(output.text, /RS256 signature valid under Google key/);
  assert.match(output.text, /Google's token signing keys were fetched by this page from https:\/\/www\.googleapis\.com\//);
  assert.doesNotMatch(output.text, /TLS key bound to attestation:/);
  assert.equal(input.gcp_jwks, gcpJwks);
  assert.equal(
    AVW.GCP_JWKS_URL,
    "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com",
  );
  assert.equal(JSON.parse(wasm.plan(gcpDoc)).gcp_jwks_url, AVW.GCP_JWKS_URL, "page and verifier pin the same URL");
  assert(requests.includes(AVW.GCP_JWKS_URL), requests.join(", "));
  // Nothing Intel- or AMD-related is asked for, and nothing from the server
  // but the attestation document.
  assert(!requests.some((r) => /pccs|kdsintf/.test(r)), requests.join(", "));
  assert.equal(requests.filter((r) => r.includes(GCP_HOST)).length, 1);
});

await test("gcp-cs: fails closed (keys unavailable, foreign keys, expiry, replay, unattested certificate)", async () => {
  let r = await goGcp({ jwks: () => { throw new TypeError("Failed to fetch"); } });
  assert.deepEqual(marks(r.output).filter((m) => m[0] === "-"), ["-evidence", "-ct_binding"], r.output.text);
  assert.match(r.output.text, /Google's signing keys are not available: could not fetch https:\/\/www\.googleapis\.com/);

  r = await goGcp({ jwks: () => new Response("nope", { status: 503 }) });
  assert.match(r.output.text, /Google's signing keys are not available: .* answered HTTP 503/);
  assert.equal(r.output.passed, false);

  const testKeys = readFileSync(join(root, "verifier/testdata/gcp-cs/TEST-ONLY-signing-keys.json"), "utf8");
  r = await goGcp({ jwks: () => new Response(testKeys, { status: 200 }) });
  assert.deepEqual(marks(r.output).filter((m) => m[0] === "-"), ["-evidence", "-ct_binding"], r.output.text);

  r = await goGcp({ jwks: () => new Response("x".repeat(70000), { status: 200 }) });
  assert.match(r.output.text, /response too large/);

  r = await goGcp({ now: GCP_NOW + 3600 * 1000 });
  assert.match(r.output.text, /token is expired/);
  assert.equal(r.output.passed, false);

  r = await goGcp({ nonce: "07".repeat(32) });
  assert.deepEqual(marks(r.output).filter((m) => m[0] === "-"), ["-nonce", "-report_data_claimed", "-ct_binding"]);

  r = await goGcp({ ctKey: "c".repeat(64) });
  assert.deepEqual(marks(r.output).filter((m) => m[0] === "-"), ["-ct_binding"], r.output.text);

  // A TDX policy selected for a Confidential Space server.
  r = await goGcp({ policy: policyToml });
  assert.match(r.output.text, /server reports platform `gcp-cs`, policy requires `tdx`/);
  assert.equal(r.output.passed, false);
});

// SEV-SNP. The built page knows AMD's roots only. The one real AMD-signed
// report available (virtee/sev's Milan fixture) was made for somebody
// else's report_data and has no HOST_DATA, so: the signature chain must
// verify, and the run must FAIL on the bindings. A passing SNP run exists
// only with the synthetic test chain, in `cargo test -p attested-vw-verify`.
const snpReport = Buffer.from(readFileSync(join(root, "verifier/testdata/sev/report_milan.hex"), "utf8").trim(), "hex");
const snpVcek = readFileSync(join(root, "verifier/testdata/sev/vcek_milan.der"));
const synVcek = readFileSync(join(root, "verifier/testdata/sev-synthetic/vcek.der"));
const SNP_HOST = "snp.fixture.example";
const certTable = (vcek) => {
  const head = Buffer.alloc(48);
  Buffer.from("8d75da6364e66445adc5f4b93be8accd", "hex").copy(head);
  head.writeUInt32LE(48, 16);
  head.writeUInt32LE(vcek.length, 20);
  return Buffer.concat([head, vcek]);
};
const snpPolicy = `schema = 1
release = "snp-fixture"
date = "2026-11-27"
platform = "sev-snp"
[sev_snp]
measurement = "${snpReport.subarray(0x90, 0xc0).toString("hex")}"
compose_binding = "host-data"
host_data = "${"ab".repeat(32)}"
allow_smt = true
require_alias_check = false
[sev_snp.min_tcb]
bootloader = 0
tee = 0
snp = 0
microcode = 0
[[images]]
service = "vaultwarden"
image = "${image}"
`;
const snpDoc = (aux) => (nonce) =>
  JSON.stringify({
    version: 1,
    platform: "sev-snp",
    evidence: { quote: snpReport.toString("base64"), ...(aux ? { aux: aux.toString("base64") } : {}) },
    nonce,
    spki_sha256: KEY,
    report_data_construction: 'SHA-512("attested-vaultwarden/v1" || nonce[32] || spki_sha256[32])',
    app_compose: JSON.stringify({ docker_compose_file: `services:\n  vaultwarden:\n    image: ${image}\n` }),
    image_digests: [{ service: "vaultwarden", image }],
    timestamp: "2026-11-27T00:00:00Z",
  });
const kdsUrls = [];
const goSnp = ({ aux, kds } = {}) => {
  requests.length = 0;
  kdsUrls.length = 0;
  return AVW.run(
    env(
      platformNetwork({
        host: SNP_HOST,
        doc: snpDoc(aux),
        ctKey: KEY,
        routes: {
          [AVW.AMD_KDS_PREFIX]: (url) => {
            kdsUrls.push(url);
            return kds(url);
          },
        },
      }),
      1800000000 * 1000,
    ),
    { host: SNP_HOST, policyToml: snpPolicy, knownSpkis: [] },
  );
};
const bad = (out) => marks(out).filter((m) => m[0] === "-");
const SNP_BINDING_FAILURES = ["-report_data_claimed", "-host_data", "-compose_hash", "-ct_binding"];

await test("sev-snp: real AMD-signed report, VCEK fetched from AMD KDS by the page", async () => {
  // Milan has no VCEK for this chip in the mock; Genoa answers. (For the
  // real fixture it is the other way round; the order of tries is what is
  // tested.) The chain is then found by the verifier, not by the URL.
  const { input, output } = await goSnp({
    kds: (url) => (url.includes("/Milan/") ? new Response("", { status: 404 }) : new Response(snpVcek, { status: 200 })),
  });
  assert(marks(output).includes("+evidence"), output.text);
  assert.match(output.text, /AMD Milan ARK→ASK→VCEK→report signatures valid, VCEK bound to TCB\/chip/);
  assert.match(output.text, /VCEK fetched by this page from AMD KDS/);
  assert.deepEqual(bad(output), SNP_BINDING_FAILURES, output.text);
  assert.equal(output.passed, false);
  const hwid = snpReport.subarray(0x1a0, 0x1e0).toString("hex");
  assert.deepEqual(kdsUrls, ["Milan", "Genoa"].map(
    (p) => `https://kdsintf.amd.com/vcek/v1/${p}/${hwid}?blSPL=03&teeSPL=00&snpSPL=08&ucodeSPL=115`,
  ));
  assert.equal(Buffer.from(input.snp_vcek, "base64").compare(snpVcek), 0);
  assert(!requests.some((r) => /pccs|googleapis/.test(r)), requests.join(", "));
});

await test("sev-snp: VCEK from the evidence's certificate table: no request to AMD", async () => {
  const { input, output } = await goSnp({ aux: certTable(snpVcek), kds: () => assert.fail("KDS must not be asked") });
  assert(marks(output).includes("+evidence"), output.text);
  assert.match(output.text, /VCEK taken from the certificate table the server sent/);
  assert.deepEqual(bad(output), SNP_BINDING_FAILURES, output.text);
  assert.equal(input.snp_vcek, undefined);
  assert.deepEqual(kdsUrls, []);
});

await test("sev-snp: fails closed (KDS has nothing, KDS blocked, non-AMD chain)", async () => {
  let r = await goSnp({ kds: () => new Response("", { status: 404 }) });
  assert.deepEqual(bad(r.output), ["-evidence", "-ct_binding"], r.output.text);
  assert.match(r.output.text, /no VCEK certificate available for this report: the evidence carries no VCEK in its certificate table, and AMD KDS \(https:\/\/kdsintf\.amd\.com\/vcek\/v1\/\) gave no VCEK for this report \(Milan: HTTP 404; Genoa: HTTP 404\)/);

  r = await goSnp({ kds: () => { throw new TypeError("Failed to fetch"); } });
  assert.deepEqual(bad(r.output), ["-evidence", "-ct_binding"], r.output.text);
  assert.match(r.output.text, /Milan: network error, or the browser blocked the request/);

  r = await goSnp({ kds: () => new Response("", { status: 429 }) });
  assert.match(r.output.text, /HTTP 429 \(rate limit; try again later\)/);

  // The synthetic test chain (accepted only by the core's own unit tests)
  // is refused by the built page, from KDS or from the certificate table.
  r = await goSnp({ kds: () => new Response(synVcek, { status: 200 }) });
  assert.deepEqual(bad(r.output), ["-evidence", "-ct_binding"], r.output.text);
  assert.match(r.output.text, /VCEK is not signed by any built-in AMD root/);
  r = await goSnp({ aux: certTable(synVcek), kds: () => assert.fail("KDS must not be asked") });
  assert.match(r.output.text, /VCEK is not signed by any built-in AMD root/);
  assert.equal(r.output.passed, false);
});

// Recorded live runs replay to exactly the recorded report.
const dir = join(web, "testdata");
for (const f of readdirSync(dir).filter((f) => /^live-.*\.json$/.test(f)).sort()) {
  await test(`replay ${f}`, async () => {
    const r = JSON.parse(readFileSync(join(dir, f), "utf8"));
    const out = JSON.parse(wasm.verify(JSON.stringify(r.input)));
    assert.equal(out.text, r.expect_text);
    assert.equal(out.passed, r.expect_passed);
  });
}

console.log(`${n} tests passed (page sha256 in web/build.sh output; wasm ${bundle.build.wasm_sha256})`);
