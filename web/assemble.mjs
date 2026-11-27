// Assemble web/dist/index.html: one self-contained file with the verifier
// wasm, its wasm-bindgen glue, the page script, the release policies and the
// list of previously attested TLS keys inlined. Deterministic: the output
// depends only on its inputs (no timestamps, sorted keys).
//
//   node web/assemble.mjs <glue.js> <verifier_bg.wasm> <commit> <out.html>
import { createHash } from "node:crypto";
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const [glueJsPath, wasmPath, commit, outPath] = process.argv.slice(2);
if (!outPath) {
  console.error("usage: assemble.mjs <glue.js> <bg.wasm> <commit> <out.html>");
  process.exit(2);
}
const web = dirname(fileURLToPath(import.meta.url));
const root = join(web, "..");
const sha256 = (data, enc) => createHash("sha256").update(data).digest(enc);

// Release policies: every policy/*.toml, by file name.
const policyDir = join(root, "policy");
const policies = {};
for (const f of readdirSync(policyDir).sort()) {
  if (f.endsWith(".toml")) policies[f.replace(/\.toml$/, "")] = readFileSync(join(policyDir, f), "utf8");
}
if (Object.keys(policies).length === 0) throw new Error("no policy/*.toml found");

// Previously attested keys: "<host> <spki sha-256 hex> [comment]" per line.
const known_spkis = [];
for (const [i, raw] of readFileSync(join(web, "attested-spkis.txt"), "utf8").split("\n").entries()) {
  const line = raw.replace(/#.*/, "").trim();
  if (!line) continue;
  const [host, spki] = line.split(/\s+/);
  if (!/^[a-z0-9.-]+$/.test(host) || !/^[0-9a-f]{64}$/.test(spki || "")) {
    throw new Error(`attested-spkis.txt line ${i + 1}: expected "<host> <64 hex>"`);
  }
  known_spkis.push({ host, spki });
}

const wasm = readFileSync(wasmPath);
const config = JSON.parse(readFileSync(join(web, "config.json"), "utf8"));
const bundle = {
  build: { commit, wasm_sha256: sha256(wasm, "hex") },
  default_host: config.default_host,
  known_spkis,
  policies,
};

const glueJs = readFileSync(glueJsPath, "utf8");
const appJs = readFileSync(join(web, "src", "app.js"), "utf8");
for (const [name, js] of [["glue", glueJs], ["app", appJs]]) {
  if (/<\/script/i.test(js)) throw new Error(`${name} script contains "</script"`);
}
// Only these two inline scripts may run, and wasm may be compiled; nothing
// can be loaded from anywhere. connect-src must allow any https host,
// because the domain to verify is the user's choice.
const hash = (js) => `'sha256-${sha256(js, "base64")}'`;
const csp = [
  "default-src 'none'",
  `script-src ${hash(glueJs)} ${hash(appJs)} 'wasm-unsafe-eval'`,
  "style-src 'unsafe-inline'",
  "connect-src https:",
  "base-uri 'none'",
  "form-action 'none'",
].join("; ");

const parts = {
  CSP: csp,
  // "<" escaped so nothing in a policy file can close the script element.
  BUNDLE: JSON.stringify(bundle).replace(/</g, "\\u003c"),
  WASM_BASE64: wasm.toString("base64"),
  GLUE_JS: glueJs,
  APP_JS: appJs,
};
const template = readFileSync(join(web, "src", "index.template.html"), "utf8");
const html = template.replace(/\{\{([A-Z_0-9]+)\}\}/g, (_, k) => {
  if (!(k in parts)) throw new Error(`unknown placeholder ${k}`);
  return parts[k];
});
writeFileSync(outPath, html);
console.log(`${outPath}: ${html.length} bytes, sha256 ${sha256(html, "hex")}`);
console.log(`  wasm sha256 ${bundle.build.wasm_sha256}; ${Object.keys(policies).length} policies; ${known_spkis.length} known keys`);
