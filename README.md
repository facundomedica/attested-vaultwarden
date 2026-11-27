# Attested Vaultwarden

> **Status: research prototype, finished as a prototype.** It ran live on
> Phala Cloud (Intel TDX) for four releases and verified end to end, with
> relay and tamper demos; one run on Google Cloud Confidential Space; an
> AMD SEV-SNP path that has never touched SNP hardware. There is no
> permanent deployment (the demo VM is stopped, so `vault.facundo.dev` is
> usually offline), and there is **one open finding** that a PASS does not
> cover ([Known issues](#known-issues)).
> Nothing here is production-ready and nothing here is "secure for your
> passwords". The [threat model](docs/THREAT_MODEL.md) says exactly what is
> and is not protected; [docs/OVERVIEW.md](docs/OVERVIEW.md) is the full
> write-up of what was built, verified, abandoned and left open.

Attested Vaultwarden runs **unmodified upstream
[Vaultwarden](https://github.com/dani-garcia/vaultwarden)** (a
Bitwarden-compatible password manager server) inside a confidential VM and
lets anyone check, from their own machine, that:

1. the server is a genuine TEE guest: vendor-signed evidence, TCB status
   acceptable, debug off;
2. it was started from exactly a published release: the measured compose
   document, every container image referenced by digest, no launch scripts
   or injected settings beyond what the release pins, and firmware/OS
   measurements recomputed from the published OS image;
3. **the TLS connection you are on terminates inside that same VM**, so
   nobody can relay a genuine VM's attestation in front of another server.

## Why

Scarlata, Torrisi, Backendal and Paterson, *Zero Knowledge (About)
Encryption* (ETH Zurich / USI, USENIX Security 2026,
<https://eprint.iacr.org/2026/058>), present 12 attacks against Bitwarden
by a **malicious server**: substituting organisation keys, downgrading KDF
parameters, swapping ciphertext fields, and more. Vaultwarden speaks the
same protocol to the same clients, so a Vaultwarden operator who decides to
deviate can mount them too.

Every one of those attacks needs the server to send data that honest server
code never sends. A TEE plus remote attestation changes the question from
"what could this server do?" to "what does the published code do?". It does
**not** fix the client-side weaknesses the paper describes, and it does
**not** make the official Bitwarden apps check anything (they don't). What
it aims to remove is the operator's ability to run *different* code behind
the attested endpoint without anyone who runs the verifier noticing; how
far that holds, and the conditions on it, are in the limitations below. The
[threat model](docs/THREAT_MODEL.md#4-mapping-the-eth-zurich--usi-attacks)
maps each attack to "constrained" or "not addressed".

## How it works

```
 your machine                Phala gateway          confidential VM (Intel TDX, dstack OS)
┌─────────────────┐  TLS   ┌──────────────┐  raw  ┌───────────────────────────────────────────┐
│ attested-vw-    │───────▶│ SNI routing, │──TLS─▶│ Caddy: TLS key generated HERE,            │
│ verify          │        │ passthrough  │       │        Let's Encrypt cert via TLS-ALPN-01 │
│                 │        │ (ciphertext  │       │   /                     → Vaultwarden     │
│ 1 handshake:    │        │  only)       │       │   /.well-known/tee-attestation → sidecar  │
│   leaf SPKI     │        └──────────────┘       │                                           │
│ 2 GET ?nonce=N  │  same TLS connection          │ sidecar: reads the served cert, asks the  │
│ 3 verify quote  │◀──────────────────────────────│   guest agent for a TDX quote over        │
│   + event log   │  quote, event log, compose    │   SHA-512(tag ‖ N ‖ SHA-256(SPKI))        │
└─────────────────┘                               └───────────────────────────────────────────┘
```

The verifier recomputes `report_data` from **its own** nonce and **its own**
view of the TLS key, verifies the quote against Intel's root with fresh
collateral, replays the RTMR3 event log, and checks the measured compose
hash, the config pins and the image allowlist against a release policy
(`policy/<release>.toml`). Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Platform status

| Platform | Status | Evidence the verifier checks | Where |
|----------|--------|------------------------------|-------|
| **Phala Cloud, dstack, Intel TDX** | **Run live**, four releases (2026.11.0, .1, .2, .4) on 2026-11-26/27. Latest: `2026.11.4-phala-dev`, PASS on `vault.facundo.dev`. VM stopped, not deleted | Intel-signed TDX quote, RTMR3 event log, measured compose | [docs/PHALA.md](docs/PHALA.md), [policy/](policy/README.md) |
| **Google Cloud Confidential Space, TDX** | **Run live once** (2026-11-27): PASS, and FAIL for a wrong digest, a relay and the debug image. Torn down. No persistence: every restart is an empty vault | A token signed by **Google's attestation service**, not a hardware quote; Google is also the host | [docs/GCP_CONFIDENTIAL_SPACE.md](docs/GCP_CONFIDENTIAL_SPACE.md) |
| **AMD SEV-SNP** | **Never run on SNP hardware.** Verifier and sidecar tested with one public AMD-signed sample and synthetic reports; a reproducible guest image for Servury Blackbox is built and boot-tested in QEMU without SNP; its expected measurement was never compared with a real report | AMD-signed report, pinned launch measurement, compose hash via `HOST_DATA` or the measured kernel command line | [docs/SNP.md](docs/SNP.md), [docs/SNP_SERVURY.md](docs/SNP_SERVURY.md) |
| **Self-hosted dstack, TDX** | **Documented only.** Runbook written, never executed on hardware | as Phala | [docs/SELF_HOSTING.md](docs/SELF_HOSTING.md) |

## What a PASS proves

On the TDX platform, `Result: PASS` means that at the moment of the run,
and assuming Intel's attestation root and TDX itself are not broken:

* **TLS key bound.** The key of the certificate *your* connection received
  is in the signed `report_data`, so the connection ends inside the VM.
* **Fresh.** The evidence carries a 32-byte nonce the verifier just chose.
* **Genuine hardware, debug off,** TCB status as the policy accepts.
* **Measured OS reproduced.** MRTD and RTMR0-2 equal the policy's values,
  and for every Phala release those values were recomputed from the
  published dstack image with `dstack-mr` (`policy/*.reproduce.txt`).
* **Compose hash.** The RTMR3 event log replays to the quoted RTMR3, and
  its `compose-hash` equals the release's and the SHA-256 of the served
  document; pre-launch script, env names, app id and key provider are
  pinned.
* **Pinned images.** Every service's image is referenced by `@sha256:`
  digest and is on the release's list; the report prints each digest.

What it does **not** prove is the subject of
[Honest limitations](#honest-limitations). The plain-language version is
[docs/VERIFY.md](docs/VERIFY.md).

## Verify it yourself

```bash
cargo run --release -p attested-vw-verify -- \
  https://vault.example.com --policy policy/<release>.toml
```

Exit code 0 only for PASS; every ✗ is a FAIL. Useful flags: `--json`,
`--early-tcb`, `--pccs-url`, `--no-registry-lookup`.

Recorded output of the latest release, 2026-11-27
([demo/live/verify-2026.11.4.expected.txt](demo/live/verify-2026.11.4.expected.txt),
long values shortened):

```
Platform: tdx
  ✓ TLS connection, certificate validated: TLSv1_3 … leaf SPKI SHA-256 a8ecc85c…
  ✓ Fetch attestation over same connection: same TLS connection, 26025 bytes
  ✓ TLS key bound to attestation: attested SPKI equals the certificate we received
  ✓ Freshness nonce: server echoed our fresh nonce
  ✓ Hardware evidence signature, TCB, debug off: Intel DCAP quote … TCB UpToDate (TCB evaluation data number 20, policy minimum 20), TD debug off
  ✓ report_data matches nonce + TLS key: signed report_data = SHA-512(tag ‖ our nonce ‖ our TLS SPKI)
  ✓ Firmware / OS measurements: MRTD, RTMR0-2 equal the values pinned by release 2026.11.4-phala-dev
  ✓ Runtime event log (RTMR3 replay): 11 RTMR3 events replay to the quoted RTMR3; app-id 8a1aa54c…, key-provider {"name":"kms",…}, data disk encrypted
  ✓ Compose hash (published software): measured = SHA-256(served app-compose) = 65a901cb… = release 2026.11.4-phala-dev
  ✓ Measured config: known pitfalls absent: pre-launch script, init script and encrypted env names as the policy pins; … public_logs = true
  ✓ Images pinned and allowlisted: 3 services, all pinned by digest and allowlisted
      attest  ghcr.io/facundomedica/attest-sidecar@sha256:00055017…
      proxy  docker.io/library/caddy@sha256:003a9780…
      vaultwarden  docker.io/vaultwarden/server@sha256:4fe17f41…
Result:  PASS
```

### Three demos, recorded live on Phala

| Demo | What was done | Result | Transcript |
|------|---------------|--------|------------|
| **Relay** | A proxy with its own TLS key in front of the real server (release 2026.11.0, 2026-11-26) | Hardware evidence genuine, but `✗ TLS key bound to attestation` and `✗ report_data matches nonce + TLS key` → **FAIL**, exit 1 | [demo/relay/relay-live.expected.txt](demo/relay/relay-live.expected.txt) |
| **Tamper** | The operator sets `SIGNUPS_ALLOWED` to `"true"` and redeploys (release 2026.11.1, 2026-11-26) | Same hardware, OS and TLS key, but `✗ Compose hash` → **FAIL**; restoring the published compose → **PASS** | [demo/tamper/tamper.expected.txt](demo/tamper/tamper.expected.txt) |
| **Restart** | `phala cvms restart` (release 2026.11.4, 2026-11-27) | **PASS** before and after, with a different TLS key (`a8ecc85c…` → `e7496d20…`): the key lives in memory only | [before](demo/live/verify-2026.11.4.expected.txt), [after](demo/live/verify-2026.11.4-after-restart.expected.txt) |

Even turning Phala's container logs on changes the compose hash
(DECISIONS D-046). All recorded outputs: [demo/README.md](demo/README.md).

### Browser verifier

No toolchain at hand? `web/` builds a single-file page
(`web/build.sh` → `web/dist/index.html`) that runs the same checks in
WebAssembly for TDX, Confidential Space and SEV-SNP documents, fetching the
vendor material (Intel collateral, Google's signing keys, the AMD VCEK) at
each run. A page cannot see its own TLS certificate, so the per-connection
key check is replaced by a Certificate Transparency check over every valid
certificate for the name: `PASS (browser mode: CT-based binding)`. That is
weaker than the CLI: detection with a log-delay window, one CT monitor
(Cert Spotter) trusted to be complete, nothing for clients that do not
enforce CT, and whoever serves the page controls its verdict. On the demo
domain it ends in FAIL on the CT line (next section); no browser-mode
overall PASS has been observed on a real deployment. Details and the
recorded live run: [web/README.md](web/README.md).

### CT and CAA checks for the domain

* `demo/live/caa-check.sh` **passes** for `vault.facundo.dev`
  ([recorded](demo/live/caa-check-vault.facundo.dev.expected.txt)): the
  name's own CAA set allows only Let's Encrypt, only the ACME account that
  lives in the CVM, only TLS-ALPN-01; the zone apex forbids wildcards.
* `demo/live/ct-check.sh` **fails** until 2027-01-31
  ([recorded](demo/live/ct-check.expected.txt)): five Cloudflare wildcard
  certificates for `*.facundo.dev`, issued before Universal SSL was turned
  off for the zone and with keys never attested, stay valid until they
  expire. The per-connection verifier still catches a server using one.

CAA and CT constrain and expose the operator; they do not remove the
operator's control of DNS (THREAT_MODEL R2).

## Known issues

* **OPEN, found 2026-11-27, not fixed: a PASS does not prove the image
  bytes.** Docker's image store lives on the persistent disk. Docker
  verifies digests on pull but trusts images already present locally, so a
  compose nobody published, run once under the same app id, could alter
  stored image layers; the next boot of the published compose would run
  them under the correct digest, and the verifier would report PASS.
  Planned fix, not deployed: the measured pre-launch script removes all
  local images at boot so every image is pulled again and digest-checked
  (slower boot). [THREAT_MODEL §7](docs/THREAT_MODEL.md#7-known-issues).

## Honest limitations

* **Persistent-state precondition.** The disk key depends on the app id,
  not on the compose hash, so the verifier cannot see what earlier composes
  of the same app id left on the data disk. From 2026.11.4 the TLS key and
  certificate live in memory only and Vaultwarden ignores a planted
  `config.json`, but the vault database, the token-signing key, the ACME
  account key and the image store (above) are on that disk
  ([THREAT_MODEL §1](docs/THREAT_MODEL.md#1-what-this-project-claims)). The
  ways to close this, including a memory-only design that was examined and
  not built, are compared in [docs/KEEPER.md](docs/KEEPER.md).
* **The Bitwarden apps don't verify.** Attestation is checked by running
  this tool, periodically or by hand. Between checks, whoever controls DNS
  could point some clients at a non-attested server.
* **Phala's KMS is trusted** to release the disk key only to this app; the
  data disk has no rollback protection.
* **Development releases.** All published policies accept the PCK flags
  SMT, dynamic platform and cached keys, and every release except 2026.11.0
  runs with container logs public (they contain client IPs). The first two
  policies (2026.11.0, 2026.11.1) are no longer accepted by the verifier,
  which now requires a pinned `app_id` ([policy/README.md](policy/README.md)).
* **The sidecar image is private** on GHCR. A verifier cannot pull it, but
  can rebuild it reproducibly from the commit named in the policy header
  and compare digests (`attest-sidecar/reproducible-build.sh <commit>`).
* **Physical attacks** on TEE memory (TEE.fail, DDRop and similar
  interposers) are out of scope, and they can forge quotes.
* **The code can be wrong.** Attestation proves *which* code was started,
  not that it is good. An internal review found and fixed several
  fail-open paths in the verifier (DECISIONS D-049); there has been no
  external audit.
* **Other platforms prove less.** Confidential Space trusts Google, which
  is also the host, and keeps no data across restarts. SEV-SNP has never
  run on hardware, and its only image keeps the vault in memory. See the
  status table.
* **Demo-domain state:** the CT check fails until 2027-01-31, and with it
  the browser verifier (above).

The complete list, with what each one means for the claims:
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Repository

| Path | What |
|------|------|
| `common/` | `report_data` construction, attestation schema, policy format, compose checks |
| `attest-sidecar/` | Small Rust service serving `/.well-known/tee-attestation` (dstack, configfs-tsm, Confidential Space, mock); reproducible image build and publish scripts |
| `verifier/` | `attested-vw-verify` CLI and library: dcap-qvl for TDX, VirTEE `sev` for SEV-SNP, Google-signed token for Confidential Space; CT check; test fixtures |
| `web/` | Single-file browser verifier (verifier core as WebAssembly, CT-based TLS binding), build script, headless test, recorded live run |
| `policy/` | Release policies, their reviewed app-compose documents, measurement transcripts and tooling |
| `demo/` | Live smoke, policy bootstrap, CT and CAA checks, relay and tamper demos, with recorded outputs |
| `deploy/dstack/` | dstack compose template, `render.sh`, measured pre-launch scripts, simulator test |
| `deploy/local/` | INSECURE mock stack + end-to-end test (no TEE needed) |
| `deploy/gcp-cs/` | Confidential Space: single workload image, `build.sh`, `deploy.sh` (prints commands, runs nothing) |
| `deploy/sev-snp/` | SEV-SNP guest image for Servury Blackbox: reproducible build, offline measurement, QEMU boot test |
| `docs/` | [Overview and results](docs/OVERVIEW.md), [threat model](docs/THREAT_MODEL.md), [architecture](docs/ARCHITECTURE.md), [verification guide](docs/VERIFY.md), platform runbooks, [related work](docs/RELATED_WORK.md), [decision log](docs/DECISIONS.md), [keeper design option](docs/KEEPER.md) |
| `scripts/` | `check-links.py`: relative-link check over the Markdown files |

## Running things

```bash
cargo test --workspace            # unit tests on recorded fixtures, no network
deploy/local/e2e.sh               # whole stack on an INSECURE mock platform (Docker)
deploy/dstack/simulator/e2e.sh    # sidecar against dstack's guest-agent simulator (Docker)
web/build.sh && node web/test/run.mjs   # browser verifier and its headless test
scripts/check-links.py --backticks      # documentation links
```

The mock run never prints a plain PASS: the verifier reports
"PASS (INSECURE MOCK, proves nothing)" with exit 2, refuses the mock
without `--allow-insecure-mock`, and fails against a relay and against a
wrong compose hash. How to reproduce the recorded live results:
[docs/OVERVIEW.md §8](docs/OVERVIEW.md#8-how-to-reproduce-the-results).

Deploying: [Phala Cloud](docs/PHALA.md) ·
[self-hosted dstack](docs/SELF_HOSTING.md) (never executed) ·
[Confidential Space](docs/GCP_CONFIDENTIAL_SPACE.md) (weaker trust
statement, no persistence) · [SEV-SNP](docs/SNP.md) and
[Servury Blackbox](docs/SNP_SERVURY.md) (never run on SNP hardware).

## Security

Report problems privately, see [SECURITY.md](SECURITY.md).

## Licence

Dual-licensed under either of [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE), at your option.
