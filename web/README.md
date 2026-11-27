# Browser verifier

> **Research prototype**, like the rest of this repository. Not
> production-ready. A PASS from this page is weaker than a PASS from the
> command-line verifier (see "What a PASS means").

A static page where you enter a domain and get the same ✓/✗ lines and
PASS/FAIL as `attested-vw-verify`, without installing anything. It is one
self-contained file, `web/dist/index.html` (about 3.2 MB): the verifier core
compiled to WebAssembly, every `policy/*.toml`, and the list of previously
attested TLS keys are inlined. No external script, style, font or CDN. Open
it from disk or put it on any static host.

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.130 --locked
web/build.sh              # writes web/dist/index.html, prints its SHA-256
node web/test/run.mjs     # headless test of that file (no network)
```

`web/dist/` is not committed: the page embeds the policies, so it is rebuilt
whenever a policy is added.

## What a PASS means

The checks on the attestation itself are the CLI's, same Rust code
(`verifier/` built without its `cli` feature). For TDX: Intel quote
signature and collateral, TCB status, debug off, MRTD/RTMR0-2 against the
policy, RTMR3 event-log replay, compose hash against the policy and against
SHA-256(served app-compose), config pins, image allowlist, nonce echo. For
the other two platforms see "Platforms" below; what their evidence proves is
in [docs/GCP_CONFIDENTIAL_SPACE.md](../docs/GCP_CONFIDENTIAL_SPACE.md)
("Trust") and [docs/SNP.md](../docs/SNP.md), and is not the same as TDX.

One check is different, because **a web page cannot read the TLS certificate
of its own connection**:

| | CLI | Browser page |
|---|---|---|
| Which TLS key is in `report_data`? | the key of the certificate the verifier itself received in the handshake | the key **the server reports** (`spki_sha256`) |
| "TLS key bound to attestation" | checked, per connection | **never printed** (neither ✓ nor ✗) |
| Instead | | "Certificate Transparency: every valid certificate has an attested key" |
| Result line | `PASS` | `PASS (browser mode: CT-based binding)` |

This is the same on all three platforms: `report_data` (on Confidential
Space, the token's two `eat_nonce` values) is recomputed from the page's
nonce and the SPKI hash the server reports.

So in the browser the quote proves: *a genuine TD running the release vouches
for TLS key K, freshly (our nonce)*. It does not prove that the connection
the browser used ends at K. A relay could forward the genuine VM's answer.
The page closes that gap through Certificate Transparency: it asks Cert
Spotter for every certificate valid for the name, including `*.parent`
wildcards (the parent is queried and filtered for `*.parent`, as
`demo/live/ct-check.sh` does), drops expired ones, and requires

* every remaining certificate's `pubkey_sha256` to be K or a key in
  `web/attested-spkis.txt` (previously attested, same host), and
* at least one of them to be K itself (an empty answer never passes).

Claim on PASS: **every currently valid publicly logged certificate for this
name has a key that was attested inside the VM, so clients that enforce CT
(current browsers) can only reach an attested VM under this name**, modulo:

* **Log delay: detection, not prevention.** A certificate issued minutes ago
  may not be logged or indexed yet. Whoever controls the domain has that
  window. (The other direction also happens: right after a deployment or a
  renewal the page FAILS with "may be too new for the CT monitor" until
  Cert Spotter has the new certificate.)
* **Cert Spotter is trusted** to return every issuance. The page cannot check
  completeness and asks no second monitor. Unauthenticated requests are rate
  limited (HTTP 429 → the CT check fails; try later).
* **Old attested keys still count** for as long as their certificates are
  valid, even if the VM that held them is gone. Revocation is ignored.
* **Clients that do not enforce CT** (many non-browser HTTP stacks, possibly
  the Bitwarden desktop/mobile apps) get no protection from this argument.
* **The page itself.** Whoever serves the page controls its verdict. Build it
  yourself or get it from a source you trust, and never from the server being
  verified. The CLI remains the reference.

Other differences from the CLI:

* **Collateral from a mirror.** Intel PCS sends no CORS headers, so the page
  fetches collateral from Phala's PCCS mirror, `https://pccs.phala.network`.
  The collateral is Intel-signed and verified in the wasm against the Intel
  root built into dcap-qvl. The mirror cannot forge it, but it chooses which
  signed version the page sees: it can serve older TCB data, down to the
  policy's `tdx.min_tcb_eval_data_number`. There is no fallback.
* **Servers before release 2026.11.4 cannot be verified**: their attestation
  endpoint sends no `Access-Control-Allow-Origin` (2026.11.4 is the first
  published release whose endpoint sends it; no 2026.11.3 was published). The page says so
  (it distinguishes "answered but unreadable" from "unreachable" with a
  `no-cors` probe).
* **The mock platform is always refused.**
* **Old policies.** Every `policy/*.toml` is bundled, but the verifier now
  refuses policies without `tdx.app_id` (2026.11.0, 2026.11.1); selecting one
  gives a FAIL that says so.
* **The clock is the browser's.** Collateral validity and certificate expiry
  are judged against it.
* **Image tags** (display only): the page tries the same Docker Hub lookup
  as the CLI, but Docker Hub sends no CORS headers, so in a browser the line
  reads "(Docker Hub tag lookup failed: blocked by the browser …)". It never
  affects the result.

## Platforms

The page asks the verifier (wasm `plan`) which trust material a document
needs, fetches it **live** at each run, and hands it to `verify`. Nothing is
bundled as a snapshot. Missing or unusable material is a failed "Hardware
evidence" check, never a skipped one.

| Platform | Trust material | Fetched from | What anchors it |
|---|---|---|---|
| `tdx` | Intel collateral | `pccs.phala.network` (mirror; Intel PCS has no CORS) | Intel root built into dcap-qvl |
| `gcp-cs` | Google Cloud Attestation JWKS | the URL pinned in `common/src/gcp_cs.rs` (`www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign…`) | **nothing but the browser's TLS to Google** |
| `sev-snp` | VCEK certificate | the evidence's certificate table (`evidence.aux`); if it has none, `kdsintf.amd.com/vcek/v1/{Milan,Genoa}/…` | AMD ARK/ASK built into the `sev` crate; VCEK bound to the report's chip and TCB |

**Confidential Space (`gcp-cs`).** Same checks as the CLI: RS256 only, key
by `kid` from the JWKS, issuer, audience, validity window, `eat_nonce`, then
the claims against the policy. The JWKS is the trust anchor and it is not
self-verifying: the page fetches exactly the pinned URL (any other URL is
refused, redirects are refused, 64 kB cap), so its authenticity rests on the
browser's WebPKI connection to `www.googleapis.com`, as the CLI's rests on
its own. The server being verified has no way to supply keys: there is no
field for them in the attestation document, and the page takes none from
it. The discovery document
(`confidentialcomputing.googleapis.com/.well-known/openid-configuration`) is
not readable from a page (no CORS) and is not needed, because the
`jwks_uri` is pinned, not discovered. If Google moves the keys, the page
fails until the constant is updated. As on the CLI, the page sees no
hardware quote: a PASS means Google's attestation service signed the
statement. PKI tokens (`token_type: PKI`, `x5c` chain to a pinned Google
root) were the planned fallback had the JWKS not been readable; since it
is, they are **not implemented**, and the sidecar still requests OIDC
tokens.

**SEV-SNP (`sev-snp`). No real SNP deployment exists; nothing here has run
against one.** The VCEK is taken from the certificate table the server
sends when there is one (as the CLI does), otherwise from AMD KDS. Its
source is not trusted either way: the verifier accepts it only if it is
signed by a built-in AMD ASK/ARK (Milan, Genoa, Turin) and its TCB and
hwID extensions equal the report's. The ASK and ARK are never fetched and
never taken from the server. KDS URLs are built in the verifier from the
report's `chip_id` and `reported_tcb` (`snp::kds_vcek_urls`, shared with the
CLI), Milan then Genoa; the page refuses any URL outside
`https://kdsintf.amd.com/vcek/v1/` and any redirect, 16 kB cap. Turin
reports (FMC SVN) are not fetched from KDS: without a VCEK in the
certificate table they fail with a message saying so. AMD rate-limits KDS
(HTTP 429 → evidence fails; try later). Revocation (AMD CRL) is not
checked, as on the CLI.

### Cross-origin access, as measured (2026-11-27)

From a page served at `http://127.0.0.1:8765` in the Claude desktop
browser pane (Chromium-based), `fetch(url, {credentials: "omit",
referrerPolicy: "no-referrer", cache: "no-store"})`, and the response
headers of the same request made with `curl -H 'Origin: http://127.0.0.1:8765'`:

| URL | In the browser | CORS headers |
|---|---|---|
| `https://confidentialcomputing.googleapis.com/.well-known/openid-configuration` | **blocked** ("No 'Access-Control-Allow-Origin' header is present"); reachable with `no-cors` (opaque) | none (`content-type: text/html`, `vary: Accept-Encoding`) |
| `https://confidentialcomputing.googleapis.com/.well-known/confidential_space_root.crt` (root for PKI tokens) | **blocked**, same message | none |
| `https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com` | 200, readable, 1033 bytes JSON | `access-control-allow-origin: http://127.0.0.1:8765` (the request's Origin, echoed), `access-control-expose-headers: date,vary,vary,vary,content-encoding,server,content-length`, `vary: Origin,Accept-Encoding` |
| `https://kdsintf.amd.com/vcek/v1/Milan/cert_chain` | 200, readable, 4602 bytes PEM | `Access-Control-Allow-Origin: *`, `Access-Control-Expose-Headers: Access-Control-Allow-Origin,Access-Control-Allow-Credentials` |
| `https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain` | 200, readable, 4602 bytes | same |
| `https://kdsintf.amd.com/vcek/v1/Turin/cert_chain` | 200, readable, 4676 bytes | same |
| `https://kdsintf.amd.com/vcek/v1/Milan/<hwID of the virtee/sev fixture>?blSPL=03&teeSPL=00&snpSPL=08&ucodeSPL=115` | 200, readable, 1369 bytes DER | same, `Content-Type: application/octet-stream` |

With `Origin: null` (a page opened from disk) the JWKS endpoint answers
`access-control-allow-origin: null` (curl only; opening the page from
`file://` and running a `gcp-cs` verification was not tried). Without an
`Origin` header it sends no CORS header at all. These are observations of
one day; neither Google nor AMD documents them as a contract.

## Maintaining the key list

`web/attested-spkis.txt` holds `<host> <spki sha-256 hex>` lines. Caddy
generates a new key at every renewal, and the old certificate stays valid for
weeks. From the first renewal on, the page FAILS ("key never attested")
unless the old key is listed. After each verifier PASS on a new key, add the
key (the CLI prints `leaf SPKI SHA-256 <hex>`; the page prints it in the
`report_data` line) and rebuild. Only add keys from a PASS you trust: every
listed key is treated as living in an attested VM. This is a manual step and
the weakest part of the design; an operator who forgets it gets a failing
page, not a false PASS.

## Layout

| Path | What |
|------|------|
| `wasm/` | crate `attested-vw-web`: `verify_json` (pure; all checks), `plan` (which trust material a document needs) and the `wasm-bindgen` surface; collateral assembly reuses dcap-qvl's `CollateralClient` over the page's `fetch` |
| `src/app.js` | network requests and rendering; decides nothing |
| `src/index.template.html` | page, styles, explanatory text |
| `assemble.mjs`, `build.sh` | build the single file; CSP with script hashes |
| `attested-spkis.txt`, `config.json` | bundled key list; default domain |
| `test/run.mjs` | headless test of the built file; `--live` for a real run |
| `testdata/live-*.json` | recorded live runs, replayed by both test suites |

The page's Content-Security-Policy allows only its two inline scripts (by
hash), WebAssembly compilation, and `connect-src https:` (any HTTPS host,
because the domain is the user's choice). Requests carry no credentials and
no referrer; the attestation request refuses redirects.

## Tests

* `cargo test -p attested-vw-verify`: core unit tests, including browser
  mode (`check_document_browser`), the CT check (`ct`), image lines and tag
  formatting (`registry`), on mock documents and on the recorded real TDX
  quote in `verifier/testdata`. Browser mode on the other platforms:
  `gcp_cs_tests::recorded_live_token_in_browser_mode` (the recorded real
  token) and `snp_tests::browser_mode_*` (**synthetic** reports signed by
  the test-only chain, which only `cfg(test)` builds of the core accept;
  this is the only place an SNP run passes).
* `cargo test -p attested-vw-web`: the browser entry point natively, on the
  recorded TDX quote, event log and Intel collateral, plus a byte-exact
  replay of every `testdata/live-*.json`; the recorded Confidential Space
  token with Google's recorded key set at a pinned clock (PASS, and the
  failures: no keys, foreign keys, expiry, replay, another TLS key,
  unattested certificate, debug image); the real AMD-signed Milan report
  with its VCEK supplied as "fetched" or in a certificate table (signature
  chain verifies, bindings fail, see below), the synthetic chain refused,
  oversized and garbage VCEKs.
* `node web/test/run.mjs`: the **built artifact** (wasm + glue + page script
  extracted from `dist/index.html`) in Node with a mock network shaped like
  the real services: attestation endpoint, PCCS (dcap-qvl in wasm fetches and
  assembles the collateral through the page's fetch), Cert Spotter. Covers the
  no-CORS error, unreachable server, PCCS down, rate limit, unattested
  wildcard, and the live replays. For `gcp-cs`: the mock server answers
  with the document recorded from the real Confidential Space VM
  (`verifier/testdata/gcp-cs/live-2026-11-27.document.json`), the mock
  Google endpoint with the recorded key set, the page's nonce and clock are
  pinned to the recording, and the bundled `2026.11.0-gcp-cs-dev` policy
  gives `PASS (browser mode: CT-based binding)`; plus the failures. For
  `sev-snp`: the Milan report with a mock KDS (Milan 404, Genoa 200; URLs
  asserted), with a certificate table (no KDS request), KDS down, blocked
  and rate limited, and the synthetic chain refused by the built wasm.
* CI job `web` runs clippy for the featureless core and the wasm crate,
  `web/build.sh` and the Node test.

The recorded upstream quote was made for `report_data = 0x42…` and its
compose document is not available, so on that fixture `report_data` and the
compose hash fail by construction (the tests assert exactly that). A full
PASS exists only as a recorded live run.

The same holds for SNP in the wasm and Node suites: the only real
AMD-signed report available (virtee/sev's Milan fixture) has `HOST_DATA` = 0
and another `report_data`, so there the AMD signature chain verifies and
`report_data`, `HOST_DATA` and the compose hash fail by construction. The
built page cannot be made to accept the synthetic chain.

## Test record (2026-11-27)

What was run, on macOS arm64, rustc 1.97.1, wasm-bindgen 0.2.130, node 22:

* `web/build.sh --check`: two builds in separate target directories are
  byte-identical (`reproducible: two independent builds are byte-identical`).
  Not compared across machines or operating systems.
* `node web/test/run.mjs`: 8 tests pass on the built file (again after merging
  `integrate/2026-11-27`).
* The built page in a real browser (Chromium-based, served from
  `http://127.0.0.1`): loads under its CSP, starts the wasm, renders at
  phone and desktop width, light and dark. From that page's context:
  `pccs.phala.network` answers 200 with the issuer-chain response header
  readable (it is listed in `Access-Control-Expose-Headers`),
  `api.certspotter.com` answers 200, `hub.docker.com` is blocked (no CORS),
  as the page expects.
* A run against a name that does not answer
  (`vault.facundo.dev` before the deployment was up) gives one
  `✗ Fetch attestation: could not reach …` line and FAIL.

### Confidential Space and SEV-SNP in the page (2026-11-27)

Run on macOS arm64, rustc 1.97.1, wasm-bindgen 0.2.130, node 22:

* `cargo test --workspace`: 132 core tests (2 ignored: network), 10
  `attested-vw-web` tests, all pass. (Later the same day, after the SNP
  `measured-cmdline` work was merged: 141 core tests, 2 ignored, and 10
  `attested-vw-web` tests; 205 in the workspace with `common` and the
  sidecar.) `node web/test/run.mjs`: 14 tests pass
  on the built file.
* In a real browser (the built page served from `http://127.0.0.1:8765`,
  under its own CSP), driving the page's own `AVW.run` with a `fetch` that
  answers only the attestation request locally and passes everything else
  to the network:
  * `gcp-cs`: recorded document of the real VM, clock and nonce pinned to
    the recording, **JWKS fetched live from Google by the page** (1033
    bytes, key ids `1be6ff72…`, `c691621e…`), certificate list live from
    Cert Spotter. Every attestation line ✓ ("RS256 signature valid under
    Google key 1be6ff72…"). The run ends in **FAIL on the Certificate
    Transparency line**: three Let's Encrypt certificates are valid for
    `vault.gcp.facundo.dev`, one with the attested key `a08c741c…` and two
    with keys of the earlier boots of that test (`c29d9cf7…`, `f67ea472…`),
    which are not in `attested-spkis.txt`. That is the check working as
    designed, not a PASS.
  * `sev-snp`: the Milan fixture report served locally, **VCEK fetched
    live from AMD KDS by the page** (`…/vcek/v1/Milan/<hwID>?…`, 200, 1369
    bytes): "AMD Milan ARK→ASK→VCEK→report signatures valid, VCEK bound to
    TCB/chip"; FAIL on `report_data`, `HOST_DATA`, compose hash and CT, as
    the fixture must.

Not tested:

* **No live `gcp-cs` run from the page.** The test VM was deleted before
  this was written; nothing was deployed for this work. The server's CORS
  header on `gcp-cs` was observed during the CLI live run
  (docs/GCP_CONFIDENTIAL_SPACE.md) but never by this page. No browser-mode
  PASS with live CT data has been seen for this platform.
* **No SNP deployment exists.** No real report with `HOST_DATA`, no real
  certificate table (the table parser is tested on hand-built tables
  only), no Genoa or Turin report, no KDS answer for a chip other than the
  fixture's.
* A key rotation at Google between the token's issue and the JWKS fetch
  (the old `kid` disappearing) gives "not in Google's key set": expected to
  be rare, not simulated beyond the unknown-`kid` unit tests.
* The page opened from `file://` on these two platforms; browsers other
  than the Chromium-based one above.

### Live run against a real deployment (TDX): done, ends in FAIL on the CT line

Run on 2026-11-27 against `https://vault.facundo.dev` (release
`2026.11.4-phala-dev`, dstack on Intel TDX), in Node and in a real browser,
and recorded in `testdata/live-2026-11-27-vault.facundo.dev.json`, which
both test suites replay offline. Every line is ✓ (fetch through the CORS
header, nonce, Intel DCAP quote and collateral, `report_data`, measurements,
RTMR3 replay) **except Certificate Transparency**, so the overall result is
FAIL. That is the expected outcome on this domain, not a bug: Cloudflare
wildcard certificates for `*.facundo.dev`, issued before 2026-11-27 with
keys held outside the VM, stay valid until 2027-01-31
([docs/VERIFY.md](../docs/VERIFY.md), DECISIONS D-052). **No browser-mode
overall PASS has been observed on a real TDX deployment**, and none can be
on this name before those certificates expire.

To repeat it against a running server whose policy is in `policy/`:

```bash
web/build.sh
# 1. the endpoint must be readable cross-origin:
curl -s -D - -o /dev/null -H 'Origin: https://example.org' \
  "https://vault.facundo.dev/.well-known/tee-attestation?nonce=$(openssl rand -hex 32)" \
  | grep -i access-control-allow-origin
# 2. headless, real network (Node does not enforce CORS, hence step 1):
node web/test/run.mjs --live vault.facundo.dev \
  --record web/testdata/live-<date>-<host>.json
# 3. the recording now replays offline in both suites:
node web/test/run.mjs && cargo test -p attested-vw-web
# 4. in a browser: open web/dist/index.html, press Verify.
```

Also expect a FAIL on the CT line for the first minutes after a new certificate
is issued (Cert Spotter has not indexed it yet).

The user-facing description is in [docs/VERIFY.md](../docs/VERIFY.md) ("Verify from a browser") and the top-level README.
