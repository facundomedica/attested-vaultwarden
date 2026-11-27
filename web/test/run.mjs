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
