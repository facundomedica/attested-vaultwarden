# Attested Vaultwarden: overview and results

> State on 2026-11-27. **Research prototype.** This is the write-up of what
> was set out to do, what was built, what was verified against real
> hardware (with dates and recorded outputs), what was tried and dropped,
> and what remains open. It is not a claim that the system is ready for
> real passwords: it is not, and [§7](#7-open-problems-and-future-work)
> starts with a finding that a verifier PASS does not cover.
>
> Shorter: [README](../README.md). Precise claims and limits:
> [THREAT_MODEL.md](THREAT_MODEL.md). Every decision and external fact with
> its source: [DECISIONS.md](DECISIONS.md) (entries cited here as D-0xx).

## 1. Goal

Scarlata, Torrisi, Backendal and Paterson (ETH Zurich / USI), *Zero
Knowledge (About) Encryption*, USENIX Security 2026
(<https://eprint.iacr.org/2026/058>), describe 12 attacks on Bitwarden that
a **malicious server** can mount on unmodified clients. Vaultwarden
implements the same protocol, so its operator can mount them too. Each
attack requires the server to send something honest server code never
sends.

The project asks: can an operator of an **unmodified** Vaultwarden be
prevented from running anything other than published code, in a way a user
can check from their own machine, without changing the clients?

Goals, as set at the start:

1. Run upstream Vaultwarden, unmodified, in a confidential VM.
2. A standalone verifier anyone can build, which fails closed, and whose
   PASS means: genuine TEE, published software, and **this TLS connection
   ends inside that TEE** (so a genuine attestation cannot be relayed in
   front of another server).
3. A public threat model that says what attestation constrains in the
   paper's attacks and what it does not
   ([THREAT_MODEL §4](THREAT_MODEL.md#4-mapping-the-eth-zurich--usi-attacks)).
4. Live results, recorded, including the failures an attacker would cause.
5. Honest statements of every limit found on the way.

Non-goals: fixing the client weaknesses of the paper; making the Bitwarden
apps verify anything; defending against physical attacks on the host.

## 2. Design, and the decisions behind it

```
verifier ── TLS 1.3 ──▶ gateway (SNI passthrough, ciphertext only) ──▶ Caddy in the CVM (TLS key generated there)
   │  nonce N                                                             ├─ /                              → Vaultwarden (upstream image by digest)
   └─ GET /.well-known/tee-attestation?nonce=N  (same connection) ───────▶└─ /.well-known/tee-attestation   → sidecar → TEE quote
                                                                              over SHA-512(tag ‖ N ‖ SHA-256(SPKI of the served cert))
```

| Decision | Why | Record |
|----------|-----|--------|
| TLS terminates **inside** the CVM (gateway passthrough, Caddy, TLS-ALPN-01) | Otherwise the key the user sees is the gateway's, and "the connection ends in the attested VM" is false by construction | D-009, D-039, [ARCHITECTURE §2](ARCHITECTURE.md#2-tls-termination-the-critical-decision) |
| `report_data = SHA-512(tag ‖ nonce ‖ SHA-256(SPKI))`, recomputed by the verifier from **its own** nonce and handshake | Freshness and the TLS binding in one signed value; works through an unmodified proxy | D-003, D-015 |
| Own small sidecar instead of dstack-ingress or the dstack SDK | Existing evidence endpoints bind neither a nonce nor the TLS key; the sidecar only passes opaque bytes | D-005, D-009 |
| `dcap-qvl` for TDX, own RTMR3 replay with every event digest recomputed | Offline-testable with recorded fixtures and a pinned clock | D-006, D-010, D-028 |
| Every behaviour-affecting setting literal in the measured compose; admin panel off | dstack does not measure encrypted env values; the admin panel is operator access to metadata and runtime config | D-008, D-012 |
| Policies with **mandatory** pins and no opt-outs; exact pins for pre-launch script and env names | A check that can be switched off in the policy is a check the operator can switch off | D-042, D-049 |
| OS measurements recomputed from the published image for the VM shape | The MRTD in dstack's release notes does not match a Phala VM (QEMU page-add order) | D-045 |
| Reproducible sidecar image | Users must be able to tie the pinned digest to source without trusting our CI, the more so while the image is private | D-021, D-035, D-042 |
| TLS key and Vaultwarden `config.json` in memory only; measured pre-launch cleanup of containers | The data disk is readable by any compose of the same app id | D-049 |
| Browser verifier binds through Certificate Transparency | A page cannot read its own TLS certificate | [web/README.md](../web/README.md) |
| Confidential Space and SEV-SNP as extra platforms behind one schema | To see what the binding looks like where the platform gives less (Google-signed token) or different evidence (launch measurement only) | D-050, D-051, D-055 |

Components: `common/` (report_data, schema, policy, compose rules),
`attest-sidecar/`, `verifier/` (library + `attested-vw-verify`), `web/`
(the verifier core as WebAssembly). About 13,000 lines of Rust including
tests.

## 3. What was verified, where, and when

"Live" means against a real TEE over the public internet. Everything else
is a unit test on recorded or synthetic data, or a local run, and is
labelled so.

### 3.1 Platform status

| Platform | Status | Record |
|----------|--------|--------|
| Phala Cloud (dstack 0.6.5, Intel TDX, `tdx.small`) | **Live**, four releases, 2026-11-26 and 2026-11-27. Latest `2026.11.4-phala-dev`: PASS on `vault.example.com`. CVM stopped, not deleted | D-043, D-046, D-048, D-052 |
| Google Cloud Confidential Space (TDX, `c3-standard-4`, image 261100) | **Live once**, 2026-11-27, about 18 minutes of VM time; PASS and three kinds of FAIL; VM deleted. No persistence | D-053, [GCP_CONFIDENTIAL_SPACE §10](GCP_CONFIDENTIAL_SPACE.md#10-live-test-2026-11-27) |
| AMD SEV-SNP | **Never on SNP hardware.** Verifier and sidecar in code; reproducible guest image for Servury Blackbox, boot-tested in QEMU without SNP; expected measurement computed offline, never compared with a real report | D-050, D-055, [SNP.md](SNP.md), [SNP_SERVURY.md](SNP_SERVURY.md) |
| Self-hosted dstack (TDX) | **Documented only**: runbook, never executed | [SELF_HOSTING.md](SELF_HOSTING.md) |

### 3.2 Phala releases

All on the same OS image and VM shape; 2026.11.1 to 2026.11.4 on the same
CVM and app id (`8a1aa54c…`). All are development releases.

| Release | Date | What changed | Live results | Recorded |
|---------|------|--------------|--------------|----------|
| `2026.11.0-phala-dev` | 2026-11-26 | First deployment; logs off | PASS (11 checks); relay → FAIL; smoke test clean | [verify](../demo/live/verify.expected.txt), [relay](../demo/relay/relay-live.expected.txt), [smoke](../demo/live/smoke.expected.txt), [reproduce](../policy/2026.11.0-phala-dev.reproduce.txt) |
| `2026.11.1-phala-dev` | 2026-11-26 | New CVM; logs on (which changes the compose hash) | PASS; tamper (`SIGNUPS_ALLOWED=true`) → FAIL on the compose hash; restore → PASS | [verify](../demo/live/verify-2026.11.1.expected.txt), [tamper](../demo/tamper/tamper.expected.txt), [reproduce](../policy/2026.11.1-phala-dev.reproduce.txt) |
| `2026.11.2-phala-dev` | 2026-11-27 | Sidecar rebuilt; policy pins `app_id`, requires the encrypted-disk event | PASS; same policy with another `app_id` → FAIL | [verify](../demo/live/verify-2026.11.2.expected.txt), [reproduce](../policy/2026.11.2-phala-dev.reproduce.txt) |
| `2026.11.4-phala-dev` | 2026-11-27 | TLS key and `config.json` on tmpfs; measured pre-launch cleanup; CORS for the browser verifier; pins `public_logs`, `min_tcb_eval_data_number`, `mr_config_id` | PASS; wrong `app_id` → FAIL; restart → PASS with a **different TLS key**; pre-launch cleanup seen in the serial log; browser verifier run | [verify](../demo/live/verify-2026.11.4.expected.txt), [after restart](../demo/live/verify-2026.11.4-after-restart.expected.txt), [reproduce](../policy/2026.11.4-phala-dev.reproduce.txt), [browser run](../web/testdata/live-2026-11-27-phala.json) |

There is no release numbered 2026.11.3 in `policy/` (it was prepared for
`vault.warden.example.com`, which Phala never routed, and never published).
The first published release whose attestation route sends a CORS header,
and so the first a browser can verify, is 2026.11.4.

The first two policies no longer load in the current verifier (they have
no `app_id`, which D-049 made mandatory). They are historical records and
were not edited; their recorded outputs are from the verifier of that day
([policy/README.md](../policy/README.md)).

### 3.3 Claims and the evidence for each

| Claim (THREAT_MODEL §1) | Shown by | Not shown |
|-------------------------|----------|-----------|
| C1 genuine TDX guest, debug off, TCB acceptable | Intel DCAP verification with live collateral in every recorded PASS; unit tests on real quotes, including an outdated-TCB quote and mutated negatives | Only one host (Phala prod5). All policies accept SMT, dynamic platform and cached keys because that host has them |
| C2 the OS image whose measurements the policy pins, and that this is the published dstack 0.6.5 | `dstack-mr` recomputation from the published tarball, all four registers equal, for every release ([transcripts](../policy/2026.11.4-phala-dev.reproduce.txt)) | The image was not rebuilt from source; `vm_config` (the VM shape) is host-declared and only parameterises the recomputation |
| C3 started from the published compose, images referenced by digest | RTMR3 replay and compose-hash check in every PASS; the tamper demo fails on exactly that line | **That the image bytes on disk match the digests (open finding, §7.1)**; anything about state left on the disk |
| C4 the TLS key of this connection is held by the guest | `report_data` check in every PASS; relay demos fail on it (Phala and Confidential Space); the restart test shows the key is not kept on disk in 2026.11.4 | That nobody copied a key written to the disk by an *earlier* release (usable until that certificate expires) |
| C5 freshness | Nonce check; smoke test shows a bad nonce is refused | |

### 3.4 Negative results that were supposed to be negative

| Case | Where | Result | Recorded |
|------|-------|--------|----------|
| Relay with its own TLS key | live, Phala 2026.11.0 | FAIL: TLS key binding, `report_data` | [relay-live.expected.txt](../demo/relay/relay-live.expected.txt) |
| Relay | live, Confidential Space | FAIL, same two lines | [relay-live-gcp-cs.expected.txt](../demo/relay/relay-live-gcp-cs.expected.txt) |
| One changed setting | live, Phala 2026.11.1 | FAIL: compose hash | [tamper.expected.txt](../demo/tamper/tamper.expected.txt) |
| Logs flag changed | live, 2026.11.1 against the 2026.11.0 policy | FAIL: compose hash | D-046 (not kept as a file) |
| Wrong `app_id` in the policy | live, 2026.11.2 and 2026.11.4 | FAIL | D-048, D-052 (not kept as files) |
| Wrong digest, wrong project, restart policy, minimum image version; debug image family | live, Confidential Space | FAIL | [GCP_CONFIDENTIAL_SPACE §10](GCP_CONFIDENTIAL_SPACE.md#10-live-test-2026-11-27); debug token kept as a [fixture](../verifier/testdata/gcp-cs/live-debug-2026-11-27.document.json) |
| Simulator quote (patched `report_data`, cannot be re-signed) | local, dstack simulator | FAIL on the quote signature | D-034, `deploy/dstack/simulator/e2e.sh` |
| Mock platform | local | never a plain PASS (exit 2); refused without a flag | `deploy/local/e2e.sh` |

### 3.5 Domain-level checks (DNS, CAA, Certificate Transparency)

| Check | State for `vault.example.com` | Recorded |
|-------|-------------------------------|----------|
| CAA (`demo/live/caa-check.sh`) | **PASS** since 2026-11-27: the name has its own set (Let's Encrypt, the in-CVM ACME account, TLS-ALPN-01, no wildcard) and the apex has `issuewild ";"` | [caa-check-vault.expected.txt](../demo/live/caa-check-vault.expected.txt) |
| CT (`demo/live/ct-check.sh`) | **FAIL until 2027-01-31**: 8 certificates valid for the name, 3 with attested keys, 5 Cloudflare Universal SSL wildcards (`*.example.com`) whose keys Cloudflare holds. Universal SSL is off for the zone since 2026-11-27, so no new ones; the old ones run out | [ct-check.expected.txt](../demo/live/ct-check.expected.txt) |
| Browser verifier | Every line ✓ except Certificate Transparency, so **FAIL**, for the same five certificates. No browser-mode overall PASS has been observed on any real deployment | [recorded run](../web/testdata/live-2026-11-27-phala.json), [web/README.md](../web/README.md) |

A note on one historical record: the header of
`policy/2026.11.4-phala-dev.toml` says the apex has no CAA record and that
the CAA check fails. That was true when the policy was written; the apex
record was added later the same day (D-052). Policy files are not edited
after publication.

### 3.6 Confidential Space (one live run)

PASS on the production image family
([verify-gcp-cs.expected.txt](../demo/live/verify-gcp-cs.expected.txt),
policy [`2026.11.0-gcp-cs-dev`](../policy/2026.11.0-gcp-cs-dev.toml)); the
FAIL cases of §3.4; a real token and a real debug-image token kept as
fixtures with Google's key set of that day
(`verifier/testdata/gcp-cs/`, provenance in
[SOURCES.md](../verifier/testdata/SOURCES.md)). Confirmed live: nothing
survives a restart, and a crashed process reboots the whole VM. The trust
statement is different in kind: the verifier sees a token signed by
Google, who also runs the host, and no hardware quote
([GCP_CONFIDENTIAL_SPACE §5](GCP_CONFIDENTIAL_SPACE.md#5-trust-what-a-pass-means-here)).
The VM behind the test name `vault.gcp.example.com` was deleted; nothing
is served there.

### 3.7 SEV-SNP (no hardware)

What exists: report verification tested against one public AMD-signed
Milan report; both compose bindings (`HOST_DATA`, measured command line)
tested with synthetic reports signed by a chain that only test builds
accept; a sidecar provider tested against a fake configfs directory; a
guest image for Servury Blackbox built twice with identical output and
booted in QEMU without SNP; its expected measurement computed with
`sev-snp-measure`. What does not exist: any run on an SNP host, any real
report with our `report_data`, any comparison of the computed measurement
with a real one. The example policy is marked unverified.

### 3.8 Tests

`cargo test --workspace` on 2026-11-27 (macOS arm64, this tree): **205
tests pass, 2 ignored** (the two need the network): 141 in the verifier
library, 36 in `common`, 18 in the sidecar, 10 in the browser crate. The
Node test of the built page (`node web/test/run.mjs`, 14 tests when last
run, [web/README.md](../web/README.md)) and the Docker-based end-to-end
tests were not re-run for this write-up. CI runs fmt, clippy with
warnings denied, the tests, the web build and its test, a double build of
the sidecar that must give one digest, `cargo deny` and `cargo audit`.

## 4. The security review and what it changed

An internal review on 2026-11-27, with proof-of-concept tests, looked for
ways to get a PASS the documentation did not justify. It found several,
all in the direction of the verifier accepting too much. Each was fixed
fail-closed with a regression test (D-049):

* `app_id` and `key_provider` were optional pins; they are mandatory.
* `accepted_tcb_status` was not the exact set (the library always accepted
  `UpToDate`); it is re-checked on the verified claims.
* A collateral cache could serve old, still validly signed TCB data; the
  policy now pins a minimum TCB evaluation data number. The earlier
  statement that the collateral source "affects availability only" was
  wrong and was corrected.
* MRCONFIGID, MROWNER and MROWNERCONFIG were ignored; they are checked or
  pinned.
* The RTMR3 log is matched against the exact dstack boot sequence, not a
  set of allowed names.
* Compose rules became an allowlist of reviewed service keys.
* Server-controlled strings reach the report only through a sanitiser.
* The sidecar's rate limit is per client under a global budget, and the
  verifier retries once.

The same review led to the 2026.11.4 template: it is where the
**persistent-state precondition** was understood (the disk key follows the
app id, not the compose), and where a stale container was seen live
serving an old Caddyfile under a new compose hash. Both are described in
[THREAT_MODEL §1](THREAT_MODEL.md#1-what-this-project-claims). The review
was internal; nobody outside the project has audited the code.

## 5. Tried and abandoned

| What | What happened | Why dropped | Record |
|------|---------------|-------------|--------|
| `vault.warden.example.com`: a dedicated parent label so that CAA and wildcards could be pinned one level below the zone | DNS, CAA and the Phala binding were set up; Phala reported the domain verified, but connections never reached the CVM | Phala did not route a name two labels below the zone; cause unknown, not confirmed with Phala. The plain name got its own CAA set instead | D-052, [PHALA.md §5](PHALA.md#5-bind-the-domain-and-publish-dns), [caa-check record](../demo/live/caa-check.expected.txt) |
| "Keeper": vault in memory only, handed between VMs after mutual attestation | Designed in full and compared with the alternatives | Complexity out of proportion; turns a confidentiality assumption into a risk of losing the vault; no data-preserving upgrade; does not remove the precondition (image store, ACME key) | D-054, [KEEPER.md](KEEPER.md) |
| dstack on-chain KMS with a compose-hash allowlist | Identified as the most direct fix for the precondition on Phala | Not adopted: not evaluated against the contracts, and it moves trust to the contract's governance. It remains the first thing to evaluate (§7.2) | D-054, [KEEPER.md §2](KEEPER.md#2-the-options-side-by-side) |
| Self-hosted TDX on rented bare metal | Researched; runbook written | Cost (around €600/month plus a setup fee); Phala chosen for the live runs | D-036 |
| SEV-SNP via `HOST_DATA` on a host we control | Verifier and sidecar implemented | No hardware and no guest image; the second mode (measured command line) was built for a host that can be rented cheaply, and not run either | D-050, D-055 |
| Persistence on Confidential Space through Cloud KMS | Considered | The operator administers the KMS key, and a remote user cannot see that; it would add nothing a verifier can tell a user | D-051 |
| Depending on atlas-rs or dstack-sdk | Read as references | Not usable offline with injected time and collateral; large dependency tree inside the TEE | D-005, D-007 |

DNS leftovers of abandoned experiments, still in the zone on 2026-11-27
(checked with dig): the `vault.warden` CNAME/TXT and the CAA set at
`warden` (D-052) are harmless. The `vault.gcp` A record still points at
the released GCP address `34.178.235.11` (CAA at `gcp` allows any Let's
Encrypt account): whoever is assigned that address could obtain a valid
certificate for `vault.gcp.example.com`. It is not a name any release
uses, but it should be deleted.

## 6. What a PASS is worth today

On TDX: at the moment of the run, this connection ends in a genuine TDX
guest that booted the published dstack image and was started from the
published compose, under the pinned app id and key provider, with images
referenced by the published digests. **Provided** that nothing but
published composes ever ran under that app id, which nobody outside can
check, and which today also has to cover the image bytes on disk.

On Confidential Space: Google states that a production Confidential Space
VM runs the pinned image and that the workload asked for this nonce.

On SEV-SNP: nothing yet, because nothing ran.

## 7. Open problems and future work

Ordered by how much they limit the claims.

### 7.1 OPEN FINDING: the image store is on the persistent disk (found 2026-11-27, not fixed)

Docker's image store lives on the persistent data disk. Docker verifies an
image's digest when it pulls it and trusts images already present locally.
A compose nobody published, run once under the same app id, could alter
the stored layers of an allowlisted image; the next boot of the published
compose would run the altered layers under the correct digest, and **the
verifier would report PASS**. This defeats C3 for whoever controls the
app, on every dstack release so far.

Planned fix, **not deployed**: the measured pre-launch script removes all
local images at boot, so every image is pulled again and digest-checked
before it runs. Cost: a slower boot and a registry dependency at each
boot. It needs a new release. Full description:
[THREAT_MODEL §7, K1](THREAT_MODEL.md#7-known-issues).

### 7.2 The persistent-state precondition

The general form of 7.1: the disk key is tied to the app id, so the vault
database, the token-signing key and the ACME account key are readable and
writable by any compose of the same app. 2026.11.4 took the TLS key and
`config.json` off the disk; the rest is a stated assumption. Options, in
the order they should be evaluated: on-chain KMS with a compose-hash
allowlist (needs checking against the actual contracts and their
governance); the verifier printing the storage mode it reads from the
compose, so users see which promises apply; the others in
[KEEPER.md §2](KEEPER.md#2-the-options-side-by-side).

### 7.3 Clients do not verify

The Bitwarden apps and browsers check nothing. Between manual runs,
whoever controls DNS can send clients elsewhere. CAA and CT expose that
after the fact; they do not prevent it. Per-connection verification in a
client or browser extension (as Revelio does,
[RELATED_WORK.md](RELATED_WORK.md)) is the real answer and is not started.

### 7.4 Things claimed only as far as they were tested

* SEV-SNP on real hardware: the first real report decides whether the
  computed measurement, the certificate table handling and the sidecar are
  right ([SNP_SERVURY §6](SNP_SERVURY.md#6-checks-on-the-first-real-report)).
  No revocation (CRL) check for AMD certificates.
* A browser-mode overall PASS: none observed; on the demo domain none is
  possible before 2027-01-31.
* That a planted `config.json` is ignored was tested on the pinned image
  locally, not on the live deployment; a deliberately planted container
  was not staged live (the cleanup was seen removing the previous
  release's containers).
* Self-hosted dstack: never executed.
* Confidential Space image reproducibility across two builds: not
  established.
* Certificate renewal over weeks, and anything longer than a few hours of
  uptime: not observed.

### 7.5 Smaller items

* A release meant for anyone to rely on would need: logs off, the sidecar
  image public, a host whose PCK flags need no exceptions (or a reasoned
  acceptance of them), and an app id with a clean, public history.
* Disk rollback (R6) has no mitigation.
* Phala's KMS decides which composes get keys (R10).
* `docker compose up --force-recreate` in dstack itself would replace the
  container-cleanup script; worth proposing upstream (D-049).
* Check labels are shared across platforms and read oddly for a
  Google-signed token.
* Binding the TLS session (exporter) instead of the certificate key, as
  atlas-rs does (D-003).
* No external audit.

## 8. How to reproduce the results

Without any TEE:

```bash
cargo test --workspace                    # 205 tests on recorded and synthetic evidence
deploy/local/e2e.sh                       # mock stack: exit 2, relay FAIL, wrong compose hash FAIL (Docker)
deploy/dstack/simulator/e2e.sh            # sidecar ↔ dstack guest-agent simulator (Docker)
web/build.sh && node web/test/run.mjs     # browser verifier, replays the recorded live run
```

The pinned artifacts, from published inputs:

```bash
# Sidecar image digest of a release (commit is in the policy header; 9f723df for 2026.11.4):
attest-sidecar/reproducible-build.sh 9f723df
# OS measurements (630 MB download from the dstack GitHub release mkosi-os-v0.6.5):
docker build -t avw-dstack-mr:350a0a7 policy/measure
policy/measure/measure-tdx.sh dstack-0.6.5.tar.gz <sha256> <os_image_hash> \
  --cpu 1 --memory 2G --qemu-version 8.2.2 \
  --policy policy/2026.11.4-phala-dev.toml -- --hotplug-off false
# SEV-SNP image and its expected measurement (never compared with hardware):
deploy/sev-snp/build.sh snp.example.org --ip dhcp --public-logs --check
deploy/sev-snp/measure.sh deploy/sev-snp/.generated/snp.example.org
```

Exact values for `<sha256>` and `<os_image_hash>` are in
[policy/README.md](../policy/README.md) and each
`policy/*.reproduce.txt`.

Against the live deployment (the CVM is stopped; its owner has to start
it):

```bash
cargo run --release -p attested-vw-verify -- \
  https://vault.example.com --policy policy/2026.11.4-phala-dev.toml      # expect PASS, exit 0
demo/relay/relay-live.sh vault.example.com policy/2026.11.4-phala-dev.toml   # expect FAIL, exit 1
demo/live/caa-check.sh vault.example.com https://acme-v02.api.letsencrypt.org/acme/acct/4048885521   # expect PASS
demo/live/ct-check.sh vault.example.com                                   # expect exit 1 until 2027-01-31
```

The TLS key in a new PASS will differ from the recorded ones: 2026.11.4
generates one at every boot, and each boot spends one of Let's Encrypt's
five identical certificates per week. The tamper demo
(`demo/tamper/tamper.sh`) redeploys the CVM twice and needs the owner's
Phala account. A deployment of your own: [PHALA.md](PHALA.md).

## 9. Document map

| Document | For |
|----------|-----|
| [README](../README.md) | Five-minute summary |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Claims, adversaries, residual risks, the paper's attacks, known issues |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Components, TLS termination, attestation flow, what is measured |
| [VERIFY.md](VERIFY.md) | Checking a server, for non-experts |
| [PHALA.md](PHALA.md), [SELF_HOSTING.md](SELF_HOSTING.md) | dstack runbooks (executed / not executed) |
| [GCP_CONFIDENTIAL_SPACE.md](GCP_CONFIDENTIAL_SPACE.md) | The Confidential Space platform and its one live run |
| [SNP.md](SNP.md), [SNP_SERVURY.md](SNP_SERVURY.md) | SEV-SNP design; image and first-boot runbook for Servury |
| [KEEPER.md](KEEPER.md) | The memory-only design that was not built, and the alternatives |
| [RELATED_WORK.md](RELATED_WORK.md) | Comparable systems, physical attacks |
| [DECISIONS.md](DECISIONS.md) | Dated log of decisions and verified facts |
| [policy/README.md](../policy/README.md), [demo/README.md](../demo/README.md), [web/README.md](../web/README.md) | Releases; demos and recorded outputs; browser verifier |
