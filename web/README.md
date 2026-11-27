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
(`verifier/` built without its `cli` feature): Intel quote signature and
collateral, TCB status, debug off, MRTD/RTMR0-2 against the policy, RTMR3
event-log replay, compose hash against the policy and against
SHA-256(served app-compose), config pins, image allowlist, nonce echo.

One check is different, because **a web page cannot read the TLS certificate
of its own connection**:

| | CLI | Browser page |
|---|---|---|
| Which TLS key is in `report_data`? | the key of the certificate the verifier itself received in the handshake | the key **the server reports** (`spki_sha256`) |
| "TLS key bound to attestation" | checked, per connection | **never printed** (neither ✓ nor ✗) |
| Instead | | "Certificate Transparency: every valid certificate has an attested key" |
| Result line | `PASS` | `PASS (browser mode: CT-based binding)` |

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
* **Servers before release 2026.11.3 cannot be verified**: their attestation
  endpoint sends no `Access-Control-Allow-Origin`. The page says so
  (it distinguishes "answered but unreadable" from "unreachable" with a
  `no-cors` probe).
* **TDX only.** The mock platform is always refused. SEV-SNP and
  Confidential Space (`gcp-cs`) documents fail the evidence check with "not
  supported in the browser verifier": the page fetches no VCEK and no Google
  JWKS (whether those services allow cross-origin reads was not examined).
* **Old policies.** Every `policy/*.toml` is bundled, but the verifier now
  refuses policies without `tdx.app_id` (2026.11.0, 2026.11.1); selecting one
  gives a FAIL that says so.
* **The clock is the browser's.** Collateral validity and certificate expiry
  are judged against it.
* **Image tags** (display only): the page tries the same Docker Hub lookup
  as the CLI, but Docker Hub sends no CORS headers, so in a browser the line
  reads "(Docker Hub tag lookup failed: blocked by the browser …)". It never
  affects the result.

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
| `wasm/` | crate `attested-vw-web`: `verify_json` (pure; all checks) and the `wasm-bindgen` surface; collateral assembly reuses dcap-qvl's `CollateralClient` over the page's `fetch` |
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
  quote in `verifier/testdata`.
* `cargo test -p attested-vw-web`: the browser entry point natively, on the
  recorded TDX quote, event log and Intel collateral, plus a byte-exact
  replay of every `testdata/live-*.json`.
* `node web/test/run.mjs`: the **built artifact** (wasm + glue + page script
  extracted from `dist/index.html`) in Node with a mock network shaped like
  the real services: attestation endpoint, PCCS (dcap-qvl in wasm fetches and
  assembles the collateral through the page's fetch), Cert Spotter. Covers the
  no-CORS error, unreachable server, PCCS down, rate limit, unattested
  wildcard, and the live replays.
* CI job `web` runs clippy for the featureless core and the wasm crate,
  `web/build.sh` and the Node test.

The recorded upstream quote was made for `report_data = 0x42…` and its
compose document is not available, so on that fixture `report_data` and the
compose hash fail by construction (the tests assert exactly that). A full
PASS exists only as a recorded live run.

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

### Live run against a real deployment: NOT DONE

`https://vault.facundo.dev` (release 2026.11.3, the first with CORS on
the attestation endpoint) never answered while this was written (the gateway
accepted the TCP connection and closed it; the VM was reported stopped), and
`policy/2026.11.3-phala-dev.toml` did not exist. So **no browser-mode PASS
has been observed**, in Node or in a browser: the only real TDX quote
available offline was made for a different `report_data`. Everything up to
that is tested; the end-to-end PASS, and the claim that a 2026.11.3 server's
CORS header is sufficient for a real browser, are not.

To do it once the server is up and the policy is in `policy/`:

```bash
web/build.sh
# 1. the endpoint must be readable cross-origin:
curl -s -D - -o /dev/null -H 'Origin: https://example.org' \
  "https://vault.facundo.dev/.well-known/tee-attestation?nonce=$(openssl rand -hex 32)" \
  | grep -i access-control-allow-origin
# 2. headless, real network (Node does not enforce CORS, hence step 1):
node web/test/run.mjs --live vault.facundo.dev \
  --record web/testdata/live-2026.11.3.json
# 3. the recording now replays offline in both suites:
node web/test/run.mjs && cargo test -p attested-vw-web
# 4. in a browser: open web/dist/index.html, press Verify.
```

Expect a FAIL on the CT line for the first minutes after a new certificate
is issued (Cert Spotter has not indexed it yet).

The user-facing description is in [docs/VERIFY.md](../docs/VERIFY.md) ("Verify from a browser") and the top-level README.
