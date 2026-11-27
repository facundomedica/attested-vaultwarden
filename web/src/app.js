// Attested Vaultwarden browser verifier: network requests and page rendering.
//
// Nothing in this file decides PASS or FAIL. It collects raw responses and
// hands them to the WebAssembly verifier (web/wasm), which is the same Rust
// code as the command-line verifier's core, and then displays its report.
"use strict";

const AVW = (() => {
  const PCCS_URL = "https://pccs.phala.network";
  const CT_API = "https://api.certspotter.com/v1/issuances";
  const ATTESTATION_PATH = "/.well-known/tee-attestation";
  const MAX_DOCUMENT_BYTES = 1 << 20;
  const MAX_CT_PAGES = 20;
  const REGISTRY_BUDGET_MS = 5000;

  const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

  // fetch with a deadline; never sends cookies or other credentials.
  async function get(env, url, ms, extra) {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), ms);
    try {
      return await env.fetch(url, {
        cache: "no-store",
        credentials: "omit",
        referrerPolicy: "no-referrer",
        signal: ctl.signal,
        ...extra,
      });
    } finally {
      clearTimeout(timer);
    }
  }

  async function fetchAttestation(env, host, nonce) {
    const url = `https://${host}${ATTESTATION_PATH}?nonce=${nonce}`;
    let resp;
    try {
      // redirect: "error" so the answer can only come from this very name.
      resp = await get(env, url, 30000, { redirect: "error" });
    } catch (e) {
      // A failed cross-origin fetch looks the same to a page whether the
      // server is down or merely sends no CORS header. A no-cors probe
      // tells the two apart (its body stays unreadable).
      let reachable = false;
      try {
        await get(env, url, 15000, { mode: "no-cors" });
        reachable = true;
      } catch (_) {
        /* unreachable */
      }
      return {
        fetch_error: reachable
          ? `${host} answered, but the browser did not let this page read ${ATTESTATION_PATH}: the server sends no Access-Control-Allow-Origin header (releases before 2026.11.3 do not), or it redirected. A web page cannot verify such a server; use the command-line verifier`
          : `could not reach https://${host}${ATTESTATION_PATH} (${e && e.name === "AbortError" ? "timed out" : "network or TLS error; the browser gives a page no detail"})`,
      };
    }
    if (resp.status !== 200) {
      return { fetch_error: `https://${host}${ATTESTATION_PATH} answered HTTP ${resp.status}` };
    }
    const body = await resp.text();
    if (body.length > MAX_DOCUMENT_BYTES) {
      return { fetch_error: `attestation document is too large (${body.length} bytes)` };
    }
    return { body };
  }

  // The transport handed to dcap-qvl's collateral client (in wasm). Only the
  // PCCS mirror is allowed: Intel's own PCS sends no CORS headers.
  function pccsFetcher(env) {
    return async (url) => {
      if (!String(url).startsWith(PCCS_URL + "/")) {
        throw new Error(`refusing to fetch collateral from ${url}`);
      }
      const r = await get(env, url, 30000);
      const headers = {};
      r.headers.forEach((v, k) => {
        headers[k] = v;
      });
      return { status: r.status, headers, body: new Uint8Array(await r.arrayBuffer()) };
    };
  }

  async function fetchCtPages(env, name) {
    const pages = [];
    let after = null;
    for (let i = 0; i < MAX_CT_PAGES; i++) {
      let url = `${CT_API}?domain=${encodeURIComponent(name)}&expand=dns_names&expand=issuer`;
      if (after !== null) url += `&after=${encodeURIComponent(after)}`;
      const r = await get(env, url, 30000);
      if (r.status !== 200) {
        throw new Error(
          `Cert Spotter answered HTTP ${r.status} for ${name}` +
            (r.status === 429 ? " (rate limit; try again later)" : ""),
        );
      }
      const text = await r.text();
      pages.push(text);
      let list;
      try {
        list = JSON.parse(text);
      } catch (_) {
        return pages; // the verifier reports the malformed page
      }
      if (!Array.isArray(list) || list.length === 0) return pages;
      const last = list[list.length - 1];
      if (!last || typeof last.id !== "string") return pages;
      after = last.id;
    }
    throw new Error(`more than ${MAX_CT_PAGES} pages of certificates for ${name}`);
  }

  async function fetchCt(env, host) {
    try {
      const parent = env.wasm.ct_parent(host);
      const [exact, parentPages] = await Promise.all([
        fetchCtPages(env, host),
        parent ? fetchCtPages(env, parent) : Promise.resolve(null),
      ]);
      return { exact_pages: exact, parent_pages: parentPages };
    } catch (e) {
      return { error: String((e && e.message) || e) };
    }
  }

  // One verification run. Returns {input, output}; output is the wasm
  // verifier's JSON (passed, text, report, labels, ct_certs).
  async function run(env, { host: rawHost, policyToml, knownSpkis, onProgress }) {
    const say = onProgress || (() => {});
    const host = env.wasm.normalize_host(rawHost);
    if (!host) {
      return { input: null, output: { passed: false, error: `"${rawHost}" is not a domain name` } };
    }
    const nonce = hex(env.randomBytes(32));
    const input = {
      host,
      nonce,
      policy_toml: policyToml,
      known_spkis: knownSpkis || [],
      now_secs: 0,
      ct: {},
    };

    say(`Asking ${host} for a fresh attestation…`);
    Object.assign(input, await fetchAttestation(env, host, nonce));

    if (input.body !== undefined) {
      say("Fetching Intel collateral (via the Phala PCCS mirror) and the certificate list (Cert Spotter)…");
      const collateral = env.wasm
        .fetch_collateral(input.body, PCCS_URL, pccsFetcher(env))
        .then(
          (c) => ({ collateral: c }),
          (e) => ({ collateral_error: `from ${PCCS_URL}: ${(e && e.message) || e}` }),
        );
      const [c, ct] = await Promise.all([collateral, fetchCt(env, host)]);
      Object.assign(input, c);
      input.ct = ct;
    }

    say("Verifying…");
    input.now_secs = Math.floor(env.now() / 1000);
    return { input, output: JSON.parse(env.wasm.verify(JSON.stringify(input))) };
  }

  // Display only: ask Docker Hub which tags point at the pinned digests and
  // re-render the report with those lines. Same inputs otherwise, so the
  // checks and the verdict cannot change. Returns null if nothing to ask.
  async function lookupTags(env, input, output) {
    const images = (output.report && output.report.observed.images) || [];
    const wanted = images
      .map(([, image]) => [image, env.wasm.hub_tags_url(image)])
      .filter(([, url]) => url);
    if (!input || wanted.length === 0) return null;
    const hub = {};
    const deadline = Date.now() + REGISTRY_BUDGET_MS;
    await Promise.all(
      wanted.map(async ([image, url]) => {
        try {
          const r = await get(env, url, Math.max(1, deadline - Date.now()));
          hub[image] = r.status === 200 ? { body: await r.text() } : { error: `HTTP ${r.status}` };
        } catch (e) {
          hub[image] = {
            error:
              e && e.name === "AbortError"
                ? `no answer within ${REGISTRY_BUDGET_MS / 1000} s`
                : "blocked by the browser (Docker Hub does not allow cross-origin requests); the command-line verifier can do this lookup",
          };
        }
      }),
    );
    const again = JSON.parse(env.wasm.verify(JSON.stringify({ ...input, hub })));
    // Belt and braces: never let a display lookup change the result.
    return again.passed === output.passed && again.report ? again : null;
  }

  // ---------------------------------------------------------------- page

  const el = (tag, attrs, ...kids) => {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === "class") n.className = v;
      else n.setAttribute(k, v);
    }
    for (const k of kids) n.append(k); // strings become text nodes, never HTML
    return n;
  };

  function renderChecks(output) {
    const list = el("ol", { class: "checks" });
    output.report.checks.forEach((c, i) => {
      const li = el(
        "li",
        { class: c.passed ? "ok" : "bad" },
        el("span", { class: "mark", "aria-hidden": "true" }, c.passed ? "✓" : "✗"),
        el("span", { class: "sr" }, c.passed ? "Passed: " : "Failed: "),
        el("strong", {}, output.labels[i]),
        ": ",
        el("span", { class: "detail" }, c.detail),
      );
      if (c.sub && c.sub.length) {
        li.append(el("pre", { class: "sub" }, c.sub.join("\n")));
      }
      list.append(li);
    });
    return list;
  }

  const CT_STATUS = {
    attested_now: ["✓", "key attested now"],
    attested_before: ["✓", "key attested before (bundled list)"],
    never_attested: ["✗", "key never attested"],
    expired: ["–", "expired, ignored"],
  };

  function renderCt(certs) {
    const wrap = el("div", { class: "scroll" });
    const table = el(
      "table",
      {},
      el("caption", {}, "Certificates in Certificate Transparency logs valid for this name"),
      el(
        "thead",
        {},
        el(
          "tr",
          {},
          ...["Status", "Valid from", "Valid until", "Issuer", "Names", "Key (SPKI SHA-256)"].map((h) =>
            el("th", { scope: "col" }, h),
          ),
        ),
      ),
    );
    const body = el("tbody");
    for (const c of certs) {
      const [mark, text] = CT_STATUS[c.status] || ["?", c.status];
      body.append(
        el(
          "tr",
          { class: c.status },
          el("td", {}, `${mark} ${text}`),
          el("td", {}, c.not_before),
          el("td", {}, c.not_after),
          el("td", {}, c.issuer),
          el("td", {}, c.dns_names.join(", ")),
          el("td", { class: "mono" }, c.pubkey_sha256),
        ),
      );
    }
    table.append(body);
    wrap.append(table);
    return wrap;
  }

  function render(root, output) {
    root.replaceChildren();
    if (output.error) {
      root.append(el("p", { class: "verdict bad" }, `FAIL: ${output.error}`));
      return;
    }
    const r = output.report;
    const verdict = output.text.split("\n").find((l) => l.startsWith("Result:")) || "Result:  FAIL";
    root.append(
      el("p", { class: `verdict ${output.passed ? "ok" : "bad"}` }, verdict.replace(/^Result:\s+/, "")),
      el(
        "p",
        { class: "meta" },
        `Target ${r.target}` +
          (r.policy_release ? ` · policy release ${r.policy_release}` : "") +
          (r.platform ? ` · platform ${r.platform}` : ""),
      ),
    );
    for (const n of r.notes) root.append(el("p", { class: "note" }, n));
    root.append(renderChecks(output));
    if (output.ct_certs && output.ct_certs.length) root.append(renderCt(output.ct_certs));
    root.append(
      el(
        "details",
        {},
        el("summary", {}, "Report as plain text (same format as the command-line verifier)"),
        el("pre", { class: "raw" }, output.text),
      ),
    );
  }

  async function loadWasm() {
    const b64 = document.getElementById("avw-wasm").textContent.trim();
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    await wasm_bindgen({ module_or_path: bytes });
    return wasm_bindgen;
  }

  async function startPage() {
    const bundle = JSON.parse(document.getElementById("avw-bundle").textContent);
    const form = document.getElementById("form");
    const domain = document.getElementById("domain");
    const policy = document.getElementById("policy");
    const status = document.getElementById("status");
    const result = document.getElementById("result");
    const button = document.getElementById("go");

    const names = Object.keys(bundle.policies).sort();
    for (const name of names) policy.append(el("option", { value: name }, name));
    if (names.length) policy.value = names[names.length - 1];
    domain.value = bundle.default_host || "";
    document.getElementById("build").textContent =
      `Build: commit ${bundle.build.commit}; verifier wasm SHA-256 ${bundle.build.wasm_sha256}; ` +
      `${names.length} bundled policies; ${bundle.known_spkis.length} previously attested keys.`;

    let wasm;
    try {
      wasm = await loadWasm();
    } catch (e) {
      status.textContent = `This browser could not start the verifier (WebAssembly): ${e.message || e}`;
      return;
    }
    const env = {
      wasm,
      fetch: (u, o) => fetch(u, o),
      now: () => Date.now(),
      randomBytes: (n) => crypto.getRandomValues(new Uint8Array(n)),
    };
    button.disabled = false;
    status.textContent = "Ready.";

    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      button.disabled = true;
      result.replaceChildren();
      try {
        const host = domain.value.trim().replace(/^https:\/\//i, "").replace(/\/.*$/, "");
        const known = bundle.known_spkis
          .filter((k) => k.host === host.toLowerCase())
          .map((k) => k.spki);
        const { input, output } = await run(env, {
          host,
          policyToml: bundle.policies[policy.value] || "",
          knownSpkis: known,
          onProgress: (m) => {
            status.textContent = m;
          },
        });
        render(result, output);
        status.textContent = output.passed ? "Done: PASS." : "Done: FAIL.";
        const withTags = output.report ? await lookupTags(env, input, output) : null;
        if (withTags) render(result, withTags);
      } catch (e) {
        render(result, { passed: false, error: `unexpected error: ${(e && e.message) || e}` });
        status.textContent = "Done: FAIL.";
      } finally {
        button.disabled = false;
      }
    });
  }

  return { run, lookupTags, startPage, PCCS_URL, CT_API };
})();

if (typeof document !== "undefined") {
  AVW.startPage();
}
