# Attested Vaultwarden

> **Status: research prototype.** It has run live on Phala Cloud (Intel
> TDX) for three releases and verified end to end, with relay and tamper
> demos; there is no permanent deployment (the demo VM is stopped, so
> `vault.facundo.dev` is usually offline).
> Nothing here is production-ready and nothing here is "secure for your
> passwords". The [threat model](docs/THREAT_MODEL.md) says exactly what is
> and is not protected.

Attested Vaultwarden runs **unmodified upstream
[Vaultwarden](https://github.com/dani-garcia/vaultwarden)** (a
Bitwarden-compatible password manager server) inside an Intel TDX
confidential VM via [dstack](https://github.com/Dstack-TEE/dstack), and lets
anyone check, from their own machine, that:

1. the server is a genuine TDX guest: Intel-signed quote, TCB status
   acceptable, debug off;
2. it runs exactly a published release: the measured compose document,
   every container image pinned by digest, no launch scripts or env
   injection beyond what the release pins, and the firmware/OS measurements
   the release lists, recomputed from the published dstack OS image;
3. **the TLS connection you are on terminates inside that same VM**, so
   nobody can relay a genuine VM's attestation in front of another server.

## Why

Scarlata, Torrisi, Backendal and Paterson, *Zero Knowledge (About)
Encryption* (USENIX Security 2026, <https://eprint.iacr.org/2026/058>),
present 12 attacks against Bitwarden by a **malicious server**: substituting
organisation keys, downgrading KDF parameters, swapping ciphertext fields,
and more. Vaultwarden speaks the same protocol to the same clients, so a
Vaultwarden operator who decides to deviate can mount them too.

Every one of those attacks needs the server to send data that honest server
code never sends. A TEE plus remote attestation changes the question from
"what could this server do?" to "what does the published code do?". It does
**not** fix the client-side weaknesses the paper describes, and it does
**not** make the official Bitwarden apps check anything (they don't). What
it removes is the operator's ability to run *different* code through the
attested endpoint without that being detectable by anyone who runs the
verifier. The [threat model](docs/THREAT_MODEL.md#4-mapping-the-eth-zurich--usi-attacks)
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

## Verify it yourself

```bash
cargo run --release -p attested-vw-verify -- \
  https://vault.example.com --policy policy/<release>.toml
```

Recorded output from the live run on 2026-11-26
([demo/live/verify.expected.txt](demo/live/verify.expected.txt), long values shortened):

```
Platform: tdx
  ✓ TLS connection, certificate validated: TLSv1_3 … leaf SPKI SHA-256 bcc603a6…
  ✓ Fetch attestation over same connection: same TLS connection, 19320 bytes
  ✓ TLS key bound to attestation: attested SPKI equals the certificate we received
  ✓ Freshness nonce: server echoed our fresh nonce
  ✓ Hardware evidence signature, TCB, debug off: Intel DCAP quote … TCB UpToDate, TD debug off
  ✓ report_data matches nonce + TLS key
  ✓ Firmware / OS measurements: MRTD, RTMR0-2 equal the values pinned by release 2026.11.0-phala-dev
  ✓ Runtime event log (RTMR3 replay): 11 RTMR3 events …, key-provider {"name":"kms",…}, data disk encrypted
  ✓ Compose hash (published software): measured = SHA-256(served app-compose) = 17129f0b… = release …
  ✓ Measured config is self-contained: pre-launch script, init script and encrypted env names exactly as pinned
  ✓ Images pinned and allowlisted: 3 services
Result:  PASS
```

The same server seen through a relay with a different TLS key fails
([demo/relay/relay-live.expected.txt](demo/relay/relay-live.expected.txt)):
the hardware evidence is genuine, but `✗ TLS key bound to attestation` and
`✗ report_data matches nonce + TLS key` → **FAIL**, exit 1.

An operator who changes one setting (`SIGNUPS_ALLOWED` to `"true"`) and
redeploys is caught the same way
([demo/tamper/tamper.expected.txt](demo/tamper/tamper.expected.txt)): same
hardware, same OS, same TLS key, but `✗ Compose hash` → **FAIL**; restoring
the published compose → PASS. Even turning Phala's container logs on
changes the compose hash (DECISIONS D-046).

Step-by-step for non-experts: [docs/VERIFY.md](docs/VERIFY.md).

## Honest limitations

* **The Bitwarden apps don't verify.** Attestation is checked by running
  this tool, periodically or by hand. Between checks, whoever controls DNS
  could point some clients at a non-attested server.
* **OS measurements depend on the VM shape.** The MRTD in dstack's release
  notes does not match a Phala VM (different QEMU page-add behaviour), so
  each release's MRTD/RTMR0-2 are recomputed with `dstack-mr` from the
  published image for the exact VM shape (`policy/measure/`). For both
  live releases all four reproduced exactly
  ([2026.11.0](policy/2026.11.0-phala-dev.reproduce.txt),
  [2026.11.1](policy/2026.11.1-phala-dev.reproduce.txt),
  [2026.11.2](policy/2026.11.2-phala-dev.reproduce.txt)).
* **Phala's KMS is trusted** to release the disk key only to this app; the
  data disk has no rollback protection.
* **The sidecar image is private** on GHCR in the current deployment; a
  verifier can rebuild it reproducibly from source, at the commit named in
  the policy header (not the release tag), and compare digests
  (`attest-sidecar/reproducible-build.sh <commit>`), but cannot pull it.
* **SEV-SNP is verifier-only.** The verifier checks SNP reports (signature
  chain, TCB, guest policy), but there is no SNP deployment, no SNP
  sidecar provider, and an SNP target always FAILs the compose binding
  check, which is not implemented.
* **Development releases.** All published policies accept the PCK flags
  SMT, dynamic platform and cached keys, and run with container logs on
  except 2026.11.0. From 2026.11.2 policies pin the dstack `app_id` and
  require the encrypted-disk event.
* **The demo domain fails the CT check.** `facundo.dev` is on Cloudflare,
  whose wildcard `*.facundo.dev` certificates are also valid for
  `vault.facundo.dev` and were never attested
  ([demo/live/ct-check.expected.txt](demo/live/ct-check.expected.txt)).
  The verifier still catches a server using them on your connection, but
  "every certificate for this name is attested" needs a domain with no
  outside wildcard (THREAT_MODEL R2).
* **Physical attacks** on TDX memory (TEE.fail, DDRop and similar
  interposers) are out of scope, and they can forge quotes.
* The published code itself can be wrong. Attestation proves *which* code
  runs, not that it is good.

## Repository

| Path | What |
|------|------|
| `attest-sidecar/` | Small Rust service serving `/.well-known/tee-attestation`; reproducible image build and publish scripts |
| `verifier/` | `attested-vw-verify` CLI and library (dcap-qvl for TDX; VirTEE `sev` for SEV-SNP report checks, no SNP deployment yet) |
| `common/` | `report_data` construction, attestation schema, policy format, compose checks |
| `deploy/local/` | INSECURE mock stack + e2e test (no TEE needed) |
| `deploy/dstack/` | dstack compose template, `render.sh`, simulator test |
| `policy/` | Release policies, their reviewed app-compose documents, measurement tooling |
| `demo/` | Live smoke, policy bootstrap, relay and tamper demos with recorded outputs |
| `docs/` | Threat model, architecture, Phala and self-hosting runbooks, verification guide, related work, decision log |

## Try it without a TEE

```bash
deploy/local/e2e.sh
```

runs the whole stack on an INSECURE mock platform: the verifier reports the
mock (exit 2, printed as "PASS (INSECURE MOCK, proves nothing)", never a plain PASS), refuses it without `--allow-insecure-mock`, and
fails against a relay and against a wrong compose hash.

## Deploying

* Phala Cloud (managed dstack, TDX): [docs/PHALA.md](docs/PHALA.md)
* Self-hosted dstack: [docs/SELF_HOSTING.md](docs/SELF_HOSTING.md)

## Security

Report problems privately, see [SECURITY.md](SECURITY.md).

## Licence

Dual-licensed under either of [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE), at your option.
