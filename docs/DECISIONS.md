# Decisions and verified facts

Running log. Every external fact the code or docs rely on gets a line here
with its source and the date it was checked. Decisions that need the
maintainer's review are marked **OPEN**. The M0 recommendations (D-001,
D-004, D-005, D-008, D-010) were accepted on 2026-11-26.

Entries are kept as written on their day: a later entry supersedes an
earlier one, and the earlier text is not rewritten. Where an old entry now
reads as a contradiction of the current state, a line starting *Later:*
points at the entry that changed it. For the current state in one place see
[OVERVIEW.md](OVERVIEW.md); for open findings, the end of this file and
[THREAT_MODEL.md §7](THREAT_MODEL.md#7-known-issues).

Pinned source abbreviations (all checked 2026-11-26):

* **D** = <https://github.com/Dstack-TEE/dstack/blob/v0.6.6/> (commit `c873038`, released 2026-11-20)
* **E** = <https://github.com/Dstack-TEE/dstack-examples/blob/9fc0b26/>
* **Q** = <https://github.com/Phala-Network/dcap-qvl/blob/f56d9ff/>
* **VW** = <https://github.com/dani-garcia/vaultwarden/blob/main/.env.template> (main, 2026-11-26)

Research was done by reading docs, published crate sources and repository
files. Items marked UNCONFIRMED were not found in a primary source and must be
re-checked before code depends on them.

---

## Decisions

### D-001 Licence: MIT (was MIT OR Apache-2.0)
Proposed in the task and in the M0 plan. Applied in M0 (`LICENSE-MIT`,
`LICENSE-APACHE`, `license` in `Cargo.toml`). Accepted with the M0 review (2026-11-26).
**Changed 2026-11-27** before the repository went public: MIT only, at the
owner's choice (`LICENSE`, `license = "MIT"`). Fixtures under
`verifier/testdata/` copied from Apache-2.0 projects keep their own
`LICENSE` files.

### D-002 Workspace layout and toolchain
Three crates as in the task: `common` (lib), `attest-sidecar` (bin),
`verifier` (lib `attested_vw_verifier` + bin `attested-vw-verify`). Rust
edition 2024, MSRV 1.85 (driven by `sev` 9.0.0's MSRV). `unsafe_code =
"forbid"` workspace-wide; clippy `unwrap_used`/`expect_used`/`panic` warned,
CI runs with `-D warnings`.

### D-003 `report_data` construction
`SHA-512("attested-vaultwarden/v1" ‖ nonce[32] ‖ SHA-256(SPKI DER)[32])`,
exactly 64 bytes, placed raw. Fixed-length inputs make concatenation
unambiguous; the tag provides domain separation from dstack's own uses of
`report_data` (`sha512("ratls-cert:" ‖ pubkey)`, `sha512("zt-cert:" ‖ …)`,
D/dstack/dstack-attest/src/attestation.rs) and from Tinfoil/atlas schemes.
Known-answer vector in `common/testdata/report_data_kat.hex`, generated with
`shasum -a 512` independently of the Rust code.

Comparison: Tinfoil hashes nonce + SHA-256(SPKI) (+ device evidence) into the
first 32 bytes (tinfoil-go `verify/document/document.go:304`); atlas-rs binds
TLS EKM (RFC 9266) instead of SPKI. SPKI binding works through an unmodified
proxy; EKM binding is stronger (per session) but needs the sidecar inside the
TLS stack (stretch goal, see D-015).

### D-004 dstack guest-agent API version (accepted: v0 GetQuote first)
dstack 0.6.0 introduced `/v1`, where `GetQuote` is gone and `Attest` returns a
MessagePack blob (D/docs/guest-api-v1.md). The frozen v0 API (`/GetQuote`,
`/v0/GetQuote`) still exists in 0.6.x and is the only one on 0.5.x OS images.

* v0 `GetQuote`: request `{"report_data": "<hex ≤64 bytes>"}`, zero-padded,
  **no hashing by the agent**; response `{quote (hex), event_log (JSON
  string), report_data, vm_config (JSON string)}` (D/sdk/curl/api.md §3).
* v1 `Attest`: `{"report_data", "include_boottime_gpu_evidence"}` → hex
  MessagePack `{version, platform:{kind:"tdx", data:{quote, event_log}},
  stack:{data:{report_data}}}`; >64 bytes is an error (D/docs/guest-api-v1.md#attestation).
* Legacy Tappd `TdxQuote` **did** hash (`sha512("app-data:" ‖ data)`): must
  not be used (D/sdk/curl/api-tappd.md).

Proposal: implement v0 `GetQuote` first (works on 0.5.x and 0.6.x, plain
JSON), add v1 when we know the target node's OS version. Verifier treats the
quote's `report_data` as authoritative either way.

### D-005 Guest-agent client implementation (accepted: option b)
`dstack-sdk` 0.6.0 (crates.io, MIT) provides `DstackClientV0::get_quote` and
`DstackClient::attest` (D/sdk/rust/src/lib.rs), but pulls reqwest and alloy
(Ethereum tooling) into the sidecar, which runs inside the TEE and should be
small. Options:

* (a) depend on `dstack-sdk`: less code of ours, much larger dependency tree
  in the trusted sidecar;
* (b) a ~50-line client: HTTP/1.1 POST over the Unix socket with `hyper` +
  `hyper-util` (already needed for serving), JSON via serde. Not crypto, not
  quote parsing: the sidecar only passes opaque bytes through.

Recommendation: (b), with `dstack-sdk-types` (0.6.0) for the response types if
it is light. Socket path `/var/run/dstack.sock` (D/sdk/rust/src/dstack_client_v0.rs
also tries `/run/dstack.sock` and `/var/run/dstack/dstack.sock`).

### D-006 TDX quote verification: `dcap-qvl` 0.7.1
crates.io, MIT, released 2026-11-03, actively maintained (Q).

* `dcap_qvl::verify::verify(raw_quote, &QuoteCollateralV3, now_secs) -> VerifiedReport`;
  `QuoteVerifier::new_prod().verify_with_policy(.., &QuotePolicy)` for TCB policy (Q/src/verify.rs, Q/docs/policy.md).
* Offline with stored collateral and caller-supplied time: yes; collateral is
  serde-serialisable (Q/src/lib.rs:102). This makes recorded-fixture unit
  tests possible.
* Checks TD debug, profiling, migratable, reserved bits and
  `SEPT_VE_DISABLE` itself unless `allow_debug` (Q/src/verify.rs:1596-1618).
  We additionally check the debug bit ourselves (cheap, explicit).
* Features: `default-features = false, features = ["std", "rustcrypto",
  "default-x509"]` for the verify path (pure Rust); collateral fetching
  (`report` feature, reqwest 0.13 + rustls) only in the CLI.
* Collateral source: `INTEL_PCS_URL` directly by default (one fewer trusted
  party than Phala's PCCS); configurable.
* `TcbStatus` values: UpToDate, SWHardeningNeeded, ConfigurationNeeded,
  ConfigurationAndSWHardeningNeeded, OutOfDate, OutOfDateConfigurationNeeded,
  Revoked, TDRelaunchAdvised, TDRelaunchAdvisedConfigurationNeeded
  (Q/src/tcb_info.rs:270). Policy default accepts only `UpToDate`. Note that
  cloud TDX hosts frequently report `SWHardeningNeeded`; the policy can list
  it explicitly, with advisory IDs printed.

### D-007 atlas-rs: reference, not dependency
atlas-rs 0.3.0 (MIT, 2026-11-19, <https://github.com/concrete-security/atlas>)
does dstack TDX verification with RTMR replay, compose-hash and bootchain
checks, but: pins dcap-qvl ^0.4.1 and dstack-sdk-types ^0.1.2; uses
`SystemTime::now()` and online collateral internally (no time/collateral
injection found); binds via TLS EKM with its own `/tdx_quote` protocol. Not
usable for offline fixture tests or our SPKI binding. We follow its
verification order and checks.

### D-008 Vaultwarden admin panel: disabled (accepted)
The task asks for `ADMIN_TOKEN` as an Argon2 hash injected as an encrypted
secret. Two findings argue against enabling it in attested releases:

1. dstack encrypted env values are **not measured**; only the
   `allowed_envs` names are (D/docs/encrypted-env-spec.md#security-considerations).
   Anyone with VMM access (operator, host) can substitute `ADMIN_TOKEN` with a
   hash of a token they know.
2. The admin panel shows account metadata (emails, orgs, item counts, last
   activity), can delete/deauthorise/invite users, and can change
   configuration at runtime, persisted to `/data/config.json`, which overrides
   env and is not measured (VW; wiki "Enabling admin page").

Proposal: leave `ADMIN_TOKEN` unset (panel disabled) in attested releases;
users are onboarded via org invitations. If an admin panel is needed, put the
Argon2 hash **literally in the measured compose** (it is a hash, not a
secret; the threat is offline guessing of the token, so use a high-entropy
token) and document every capability as operator power. Also consider
`DISABLE_ADMIN_TOKEN` stays `false`.

Hash generation if used: `vaultwarden hash` (default m=64MiB, t=3, p=4;
`--preset owasp` m=19MiB, t=2, p=1); escape `$` as `$$` in compose
(VW wiki "Enabling admin page").

### D-009 TLS termination: gateway passthrough to in-CVM Caddy
See [ARCHITECTURE.md §2](ARCHITECTURE.md). Facts:

* dstack-gateway terminates TLS in the gateway CVM by default and forwards
  over WireGuard (D/docs/tutorials/gateway-service-setup.md).
* URL format `<app_id|instance_id>[-<port>][s|g].<base_domain>`; `s` =
  TLS passthrough, `-s` alone = port 443 (D/docs/dstack-gateway.md#url-format).
* Custom-domain passthrough: TXT `_dstack-app-address.<domain> = <app_id>:<port>`
  (D/docs/rc-testing-runbook.md).
* dstack-ingress 2.8 (E/custom-domain/dstack-ingress/README.md): HAProxy +
  certbot in the app CVM, dns-01 or tls-alpn-01, `SET_CAA=true` pins
  `accounturi`; its `/evidences/` report_data is `sha256(sha256sum.txt) ‖ 0^32`
  (no nonce, no TLS key binding). DNS API token is unmeasured env.
* Phala gateway domain attestation: `/.dstack/acme-info`, `report_data =
  SHA-512("zt-cert:" ‖ pubkey)`, key in the *gateway* CVM
  (<https://docs.phala.com/phala-cloud/networking/domain-attestation>).

UNCONFIRMED, to test in M3: TLS-ALPN-01 (`acme-tls/1`) through gateway SNI
passthrough. *Later: confirmed live on Phala, D-043.*

### D-010 RTMR3 replay implementation (accepted: option b)
No crates.io crate replays dstack's RTMR3: `cc-eventlog` (which has
`runtime_events::replay_events`, D/dstack/cc-eventlog/src/runtime_events.rs:179)
is git-only; `dstack-sdk-types` 0.6.0 has the `EventLog` type but no replay
function found (atlas used `replay_rtmrs()` from 0.1.x).

Formula (D/dstack/cc-eventlog/src/runtime_events.rs):
* start `mr = 0^48`; for each event with `imr == 3`: `mr = SHA-384(mr ‖ digest)`;
* event digest V1 (default): `SHA-384(u32_le(0x08000001) ‖ ":" ‖ name ‖ ":" ‖ payload)`;
* V2 (if app-compose `event_log_version: 2`): `SHA-384(JCS({"name", "payload": hex, "type": 134217729}))`.

Options: (a) git dependency on `cc-eventlog` pinned to a commit (needs a
cargo-deny `allow-git` entry; pulls dstack workspace deps); (b) implement the
~40-line replay ourselves using `sha2`, and **recompute every event digest
from its name/payload** (never trust the `digest` field for RTMR3 events),
tested against the real fixture (must reproduce the quote's RTMR3).
Recommendation: (b). It uses library hashing, not a home-grown primitive, and
keeps the verifier offline-testable. Expected RTMR3 event order:
`system-preparing, app-id, compose-hash, [init-script-hash…],
[gpu-policy-hash], instance-id, boot-mr-done, [gpu-attestation],
[os-image-hash], key-provider, storage-fs, system-ready`
(D/dstack/dstack-util/src/system_setup.rs ~L3192). The verifier requires
exactly one `compose-hash` event and rejects unknown event names.

### D-011 Expected MRTD / RTMR0-2
* MRTD = OVMF; RTMR0 = virtual hardware + ACPI; RTMR1 = kernel; RTMR2 = kernel
  cmdline (incl. rootfs verity hash) + initrd; RTMR3 = runtime events
  (D/docs/attestation-tdx.md).
* Reproducible: `make os-image`, then `dstack-mr measure -c <cpus> -m <mem>
  metadata.json` (D/docs/attestation-tdx.md §2.2). RTMR0-2 depend on vCPU and
  memory, so the policy pins a VM size.
* Release notes for `mkosi-os-v0.6.6` publish `os_image_hash`, git revision
  and MRTD (`83baf004…706e97`), not RTMR0-2
  (<https://github.com/Dstack-TEE/dstack/releases/tag/mkosi-os-v0.6.6>).
* `dstack-verifier` downloads `https://download.dstack.org/os-images/mr_{OS_IMAGE_HASH}.tar.gz`
  (D/dstack/verifier/dstack-verifier.toml).

Plan for M3: compute RTMR0-2 with `dstack-mr` from the published image for
our VM size, cross-check with the live quote, record both in the policy.

### D-012 Measured vs unmeasured inputs on dstack
* `compose-hash` = SHA-256 of the exact `app-compose.json` bytes (wrapper with
  `docker_compose_file`, `pre_launch_script`, `allowed_envs`, `kms_enabled`,
  `gateway_enabled`, `key_provider`, …), not of docker-compose.yml. Hash the
  served bytes; never re-serialise (D/docs/guest-api-v1.md#info,
  D/dstack/dstack-types/src/lib.rs).
* Encrypted env values not measured (D/docs/encrypted-env-spec.md).
* Consequence: every behaviour-affecting setting is literal in the compose.

### D-013 SEV-SNP (stretch): VirTEE `sev` 9.0.0
crates.io, Apache-2.0, 2026-11-13. `default-features = false, features =
["snp", "crypto_nossl"]` (pure Rust). `AttestationReport::from_bytes`,
`report.policy.debug_allowed()`, `Chain::from_der(ark, ask, vek)`,
`(&chain).verify()`, `(&chain, &report).verify()`
(src/certs/snp/chain.rs). The nossl path checks signatures only: certificate
validity dates and CRL must be checked by us. Built-in ARK/ASK for Milan,
Genoa, Turin. Launch digest: `sev::measurement::snp::snp_calc_launch_digest`
(Rust port) or Python `sev-snp-measure` 0.0.13; UKI support UNCONFIRMED.
dstack's `sev-snp-qvl` (git-only) is good reference code.

### D-014 configfs-tsm (stretch)
`/sys/kernel/config/tsm/report/<name>/{inblob,outblob,auxblob,provider,generation}`;
TDX and SNP providers since Linux **6.7**
(<https://github.com/torvalds/linux/blob/master/Documentation/ABI/testing/configfs-tsm-report>).
The `configfs-tsm` crate is AGPL-3.0: do not use. `tsm-report` 0.1.0 is MIT
OR Apache-2.0. The interface is a few file writes/reads; plan to write it
ourselves (no parsing involved).

### D-015 Verifier TLS stack
rustls 0.23.x with `default-features = false, features = ["ring", "std",
"tls12"]` (avoids aws-lc-rs cmake build), tokio-rustls 0.26, hyper 1.x client
over a single connection (`hyper::client::conn::http1::handshake`) so the
attestation is fetched on the same TLS session whose certificate was checked.
Peer chain via `TlsStream::get_ref().1.peer_certificates()`. SPKI DER via
`x509-parser` `public_key().raw`. Trust roots: `webpki-roots` by default,
`--ca <pem>` for the local mock CA (M1). EKM (`export_keying_material`) is
available for the stretch goal.

### D-016 Simulator for integration tests
`dstack-simulator` (crate `dstack-guest-agent-simulator`, `sdk/simulator/build.sh`)
serves `dstack.sock` with a recorded quote whose `report_data` is patched in,
so its signature does **not** verify (D/dstack/guest-agent-simulator/src/simulator.rs).
Docker image `phalanetwork/dstack-simulator` not found on Docker Hub;
`phala simulator start` exists (unstable). Use: test the sidecar's `Dstack`
provider wire protocol in M3. M1 integration uses `Mock`.

### D-017 Test fixtures (M2)
* `D/dstack/verifier/fixtures/tdx-lite-getquote.json`: real v0 GetQuote
  response (quote + 29-event log + vm_config, image `dstack-0.6.0-rc0-v4`,
  2 vCPU / 2 GB). dstack's own test asserts it verifies. Need collateral for
  it (record once with network, store as JSON).
* `Q/sample/tdx_quote` + `tdx_quote_collateral.json`, `tdx_quote_outdated`
  (+ collateral): quote-only (no event log).
* VirTEE `sev` `tests/certs_data/report_milan.hex`, `vcek_milan.der`,
  `cert_chain_milan`.
* Licences (checked against the LICENSE files): dstack Apache-2.0, dcap-qvl MIT, sev Apache-2.0. Copied with attribution
  in `verifier/testdata/SOURCES.md`.
* Negative cases (debug quote, bad signature) are derived by mutating real
  fixtures; documented per file.

### D-018 Vaultwarden configuration facts
Vaultwarden 1.37.5 (2026-11-01, bundles web vault 2026.10.1;
<https://github.com/dani-garcia/vaultwarden/releases/tag/1.37.5>). From VW:

* `SIGNUPS_ALLOWED`, `INVITATIONS_ALLOWED`, `ORG_CREATION_USERS`,
  `PASSWORD_HINTS_ALLOWED`, `SHOW_PASSWORD_HINT`, `LOG_LEVEL`, `DOMAIN`,
  `DATA_FOLDER`, `IP_HEADER` (+ new `IP_HEADER_TRUSTED_PROXIES`).
* `DISABLE_ICON_DOWNLOAD=true` must be paired with `ICON_CACHE_TTL=0`;
  `ICON_SERVICE` external values make clients' browsers contact a third
  party. Clients still request `/icons/<domain>/icon.png` from the server;
  only a per-client setting stops that.
* `PUSH_ENABLED` default false; relay `push.bitwarden.com`.
* WebSockets on the main port (`ENABLE_WEBSOCKET`), port 3012 removed in 1.31.0.
* SSO (OIDC) merged in 1.35.0: keep `SSO_ENABLED=false`.
* `EXPERIMENTAL_CLIENT_FEATURE_FLAGS`: some flags irreversibly migrate
  accounts; leave empty.
* Images: `docker.io/vaultwarden/server`, `ghcr.io/dani-garcia/vaultwarden`,
  `quay.io/vaultwarden/server`. GitHub artifact attestations (Sigstore build
  provenance) since 1.33.0, pushed to registries
  (.github/workflows/release.yml). Verification via `gh attestation verify
  oci://… --repo dani-garcia/vaultwarden` (GitHub docs; exact usage
  UNCONFIRMED by Vaultwarden).

### D-019 Caddy facts
Caddy 2.11.9 (2026-11-05), image `caddy`. Data dir `/data/caddy` in the
official image (`XDG_DATA_HOME=/data`). Leaf certs at
`/data/caddy/certificates/<issuer>/<domain>/<domain>.crt`; issuer dirs
`acme-v02.api.letsencrypt.org-directory`, `acme.zerossl.com-v2-dv90`,
`local` for `tls internal`; local root at
`/data/caddy/pki/authorities/local/root.crt`
(certmagic storage.go, acmeissuer.go; caddy internalissuer.go, caddypki/ca.go).
Default issuers: Let's Encrypt then ZeroSSL fallback. For attested releases
we pin a single issuer so the sidecar knows which directory to read.

### D-020 Phala Cloud and self-hosted dstack: support both (decided 2026-11-26)
Both run the same dstack OS and guest agent, so the sidecar and verifier are
shared. What differs and therefore lives in the per-release policy, never in
code:

* OS image (MRTD, RTMR0-2) and VM size: each deployment target gets its own
  policy file;
* key provider recorded in RTMR3 (`key-provider` event: e.g. Phala's KMS vs a
  self-hosted KMS or local key provider), optionally pinned by the policy;
* `app-id` (Phala may assign it; self-hosted defaults to a prefix of the
  compose hash), optionally pinned;
* gateway base domain and TLS passthrough setup (ARCHITECTURE §2);
* guest-agent API version (v0 vs v1, D-004).

Deployment docs will have one section per target.

---

## M1 decisions (2026-11-26)

### D-021 Pinned images and local build path
Digests resolved 2026-11-26 with `docker buildx imagetools inspect`:

| Image | Tag | Digest (index) |
|-------|-----|----------------|
| `docker.io/vaultwarden/server` | 1.37.5 | `sha256:4fe17f415f90087377d37c755e0ea3cf189dcc6794e49cdd2a9adbb4937d9e1f` |
| `docker.io/library/caddy` | 2.11.9-alpine | `sha256:003a97808e781aa9f7e75cc2f43d34d461099031faf5e20faefb9f61126836f0` |
| `docker.io/library/registry` | 3 | `sha256:82f6ff4a7f982960c8aa51617fea3aabc485df6e55cce80d22deb1de36f1bc3c` (local dev only) |
| `docker.io/library/rust` | 1.97-slim-bookworm | `sha256:2775a09d208ff0d7c1f50490c45b62db929e87ba1dcbc3f2132ac71a704bcdd3` (sidecar build stage) |
| `gcr.io/distroless/cc-debian12` | nonroot | `sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f` (sidecar runtime) |

The locally built sidecar has no registry digest, and the image check
requires one, so `deploy/local/up.sh` pushes it to a throwaway registry on
`127.0.0.1:5001` and pins `localhost:5001/attest-sidecar@sha256:…`. This
mirrors M3, where the sidecar must be pushed to a public registry.

**Decided 2026-11-26 (maintainer delegated the choice):** users must be able
to tie the sidecar digest to source. Primary: a **reproducible build**
(digest-pinned toolchain and runtime images, `cargo --locked`,
`SOURCE_DATE_EPOCH` from the release commit, path remapping, BuildKit
`rewrite-timestamp`), so anyone can rebuild a tag and compare digests without
trusting our CI. Secondary: GitHub artifact attestations (Sigstore build
provenance) on the published image, the same mechanism Vaultwarden uses, so
the verifier's optional provenance step treats our image like upstream's.
Implemented in M3; CI builds twice and fails if digests differ. Publishing
the image needs the maintainer's OK.

### D-022 Caddyfile embedded via compose `configs.content`
Keeps the proxy configuration inside the measured compose document. Docker
Compose supports inline `content` configs (used here with Compose v5.1.1).
**UNCONFIRMED** that dstack's compose runner supports it; check in M3,
fallback: `command:` with the config passed inline, or a config baked into a
digest-pinned image. *Later: works on dstack 0.6.5 (every live Phala
release embeds the Caddyfile this way, D-043). One consequence found live:
compose keeps a container when only the inline content changes, D-049.*

### D-023 Sidecar runs as uid 0 with no capabilities
It must read Caddy's certificate store, written by Caddy running as root.
Running as uid 0 with `cap_drop: [ALL]` (no `CAP_DAC_OVERRIDE` /
`CAP_DAC_READ_SEARCH`), `read_only: true` and `no-new-privileges` limits it
to files owned by uid 0 or world-readable, on a read-only volume mount.
Alternative for later: run Caddy as a dedicated uid and the sidecar in its
group.

### D-024 Compose image extraction restrictions
To avoid parser differentials between our YAML reading and Docker's, the
verifier and sidecar reject compose documents with YAML anchors/aliases/merge
keys (lexical, over-strict), top-level `include`/`extends`, services with
`build`/`extends`, or services without a literal `image`. Image references
must match `[a-z0-9./:_-]+@sha256:[0-9a-f]{64}` (excludes `${…}`
interpolation) and appear verbatim, with their service name, in the policy.
YAML parser: `serde_yaml_ng` 0.10 (MIT).

### D-025 Sidecar limits
Global fixed-window rate limit (default 5 req/s; behind the proxy client IPs
are not meaningful), at most 4 concurrent evidence requests, 10 s provider
timeout, query string must be exactly `nonce=<64 hex>`, empty body limit,
certificate file ≤ 64 KiB re-read on every request so renewals are picked up.
Errors to clients are generic; details go to the sidecar log only.

### D-026 Verifier behaviour
* One TCP+TLS connection, hyper HTTP/1.1 client handshake on that stream
  (D-015); ALPN `http/1.1`; 15 s connect, 30 s request timeouts; body limit
  1 MiB.
* `--ca <pem>` replaces (does not extend) the WebPKI roots, and the report
  says so.
* Retry: exactly once, only if the sole failures are the SPKI binding and
  the dependent report_data check (certificate rotation race). A relay fails
  both attempts (see e2e case C).
* Exit codes: 0 PASS, 1 FAIL, 2 "all checks passed but INSECURE MOCK".
* MSRV raised to 1.88 because `time` ≥ 0.3.47 (fix for RUSTSEC-2026-0009,
  pulled in via `x509-parser` → `asn1-rs`) requires it.

---

## M2 decisions (2026-11-26)

### D-027 TDX verification pipeline
* `dcap_qvl::verify::QuoteVerifier::new_prod().verify_with_policy(quote,
  collateral, now, &QuotePolicy)`; `QuotePolicy::strict(now)` plus the
  policy's `accepted_tcb_status` and PCK platform flags. Report body via
  `claims.report.as_td10()` (TD 1.0 and the TD 1.5 base).
* **Finding:** the real dstack fixture's PCK certificate has `smtEnabled`,
  `dynamicPlatform` and `cachedKeys` all true, and dcap-qvl's strict policy
  rejects each. Policy fields `allow_smt`, `allow_dynamic_platform`,
  `allow_cached_keys` (default false) make accepting them an explicit,
  reviewable release decision. Expect real Phala / cloud hosts to need them.
* Expected values were cross-checked with an independent Python parse of the
  TD report body (MRTD at body offset 136, report_data at 520).
* Collateral fetched at verification time from Intel PCS by default
  (`--pccs-url` to change). Signed by Intel, so the source affects
  availability only.
* The collateral client (dcap-qvl `report` feature → reqwest 0.13 rustls)
  pulls `aws-lc-rs` (C build). Accepted for the CLI; replacing it with our
  hyper+ring stack via dcap-qvl's `HttpClient` trait is possible later.

### D-028 RTMR3 rules (implements D-010)
Every RTMR3 entry: `event_type == 0x08000001`, name in the known dstack boot
set (D/dstack/dstack-util/src/system_setup.rs), digest **recomputed** (V1
formula) and must equal the log's `digest` field, then replayed; result must
equal the quoted RTMR3. Exactly one `compose-hash` (32 bytes), `app-id`,
`key-provider`, `boot-mr-done`, with `compose-hash` before `boot-mr-done`.
Event-log V2 is refused (not yet implemented). Unknown names, including
application events emitted later via the guest agent, are refused: the
published compose emits none. Optional policy pins: `app_id`,
`key_provider` (exact payload).

The compose check is two-sided: measured `compose-hash` == policy, **and**
SHA-256(served `app_compose`) == measured; the second catches a server that
runs the published compose but serves a different document for the image
check.

### D-029 SEV-SNP verification (verifier side, stretch platform)
* `sev` 9.0.0 (`crypto_nossl`): report parse (exact length), ARK self-sig,
  ARK→ASK→VCEK, VCEK→report, built-in Milan/Genoa/Turin ARK+ASK.
* **Finding:** `sev` does not bind the VCEK to the report. We check the VCEK
  TCB extensions `1.3.6.1.4.1.3704.1.3.{1,2,3,8}` equal `reported_tcb` and
  `hwID` (`…1.4`) equals `chip_id` (AMD spec 57230), plus validity periods
  of ARK, ASK and VCEK. Confirmed on the real Milan fixture.
* Guest policy: debug and migration-agent bits must be 0, VMPL 0.
* Gaps: no CRL/revocation check; KDS fetch tries Milan then Genoa, Turin
  unsupported; live KDS fetch untested (no SNP host). Binding the compose
  document to the SNP launch measurement is not designed yet, so the SNP
  path **always FAILs** the event-log/compose checks today, by design.
  *Later: bindings designed and implemented in D-050 (`HOST_DATA`) and
  D-055 (measured command line); still never run on SNP hardware.*

### D-030 Dependency advisories accepted with justification
`RUSTSEC-2023-0071` (rsa 0.9, Marvin) and `RUSTSEC-2026-0387` (crypto-bigint
0.5 timing) both arrive only via `sev`, used solely to verify public
signatures over public data; there is no secret for a timing channel to
leak. Ignored in `deny.toml` and `.cargo/audit.toml` with that reason;
re-evaluate when `sev` updates. `option-ext` (MPL-2.0, via sev→dirs) allowed
as a single-crate licence exception.

---

## M3 prep decisions (2026-11-26)

### D-031 Self-hosted routing: direct port mapping, no gateway
On a self-hosted dstack host, `vmm-cli.py deploy --port tcp:0.0.0.0:443:443`
forwards raw TCP from the host to the CVM (D/dstack/vmm/src/vmm-cli.py,
`--port protocol[:address]:from:to`). TLS terminates in Caddy inside the CVM;
no dstack-gateway is involved, and `gateway_enabled = false` in the
app-compose. On Phala Cloud the equivalent is gateway TLS passthrough (D-009).

### D-032 Key provider for the first self-hosted deployment
Facts (D/dstack/dstack-util/src/system_setup.rs `request_app_keys`):
`none` → random seed per boot ("generating temporary app keys"), so the
encrypted data disk is unreadable after a CVM restart; `local` → SGX sealing
key from the host's local key provider (its measurement goes into the
RTMR3 `key-provider` event); `tpm` → vTPM seed, which on a self-hosted QEMU
host is host-emulated and therefore excluded; `kms` → dstack KMS.
Plan: first live run with `none` (data loss on restart, said loudly), then
`local` if the rented host has SGX. The policy pins the exact `key-provider`
payload either way. *Later: no self-hosted run took place; the live runs
were on Phala Cloud with its KMS (D-036, D-040, D-043).*

### D-033 app-compose for dstack
`deploy/dstack/render.sh` writes the same manifest-v2 structure as
`vmm-cli.py compose` (`create_app_compose`: `manifest_version`, `name`,
`runner`, `docker_compose_file`, `kms_enabled`, `gateway_enabled`,
`local_key_provider_enabled`, `key_provider_id`, `public_logs`,
`public_sysinfo`, `allowed_envs`, `no_instance_id`, `secure_time`,
`key_provider`), serialised with `json.dumps(indent=4)`. Byte-exact
equality with vmm-cli output is not required: dstack hashes whatever file
it is given, and the policy pins that hash. `public_logs = false` so
container logs (client IPs, icon domains) are not exported by the guest's
external API. The sidecar reads the measured document from `Info.tcb_info`
(`app_compose` field, D/docs/guest-api-v0.md "Info").

### D-034 Simulator results
dstack's guest-agent simulator (crate `dstack-guest-agent-simulator`, commit
`73b10c6`) builds in Docker (`deploy/dstack/simulator/Dockerfile`, with
`rust-toolchain.toml` removed to use our pinned Rust 1.97 image). Through
it, the sidecar's v0 `/Info` and `/GetQuote` calls work end to end; the
verifier fetches live Intel collateral for the recorded quote and FAILs with
"ISV enclave report signature is invalid", because the simulator patches
`report_data` into a quote it cannot re-sign. That is the expected and
desired outcome. The upstream `phalanetwork/dstack-simulator` Docker image
was not used (not found on Docker Hub, D-016).

### D-035 Reproducible sidecar build (implements D-021)
`attest-sidecar/reproducible-build.sh [--check] [commit]`: context =
`git archive <commit>`; `SOURCE_DATE_EPOCH` = commit time; `RUSTFLAGS`
remap `/src` and `/usr/local/cargo` and strip symbols; `cargo --locked`;
`docker buildx --no-cache --provenance=false --sbom=false --output
type=oci,rewrite-timestamp=true`; digest = first manifest in the OCI
`index.json`. Release target is `linux/amd64` (CI job); local checks on an
ARM Mac use `PLATFORM=linux/arm64` because amd64 would run under emulation.
Uses a dedicated `docker-container` buildx builder with BuildKit pinned
(`moby/buildkit:v0.29.0@sha256:0039c1d4…`); the default `docker` driver
cannot export OCI archives. **Result 2026-11-26:** two clean arm64 builds of
commit `d81a855` gave the same digest
`sha256:495d22d097c0d5b88def4f8aa2a6a811021cba3616a046eee9ea5993c64dd545`.
amd64: see the addendum (checked later the same day).

**Addendum (2026-11-26, written during the M3 Phala work).** amd64
reproducibility confirmed: two clean `linux/amd64` builds (under emulation)
of commit `a25547a` gave
`sha256:02f03ab9d9ec65c7366ee4a770401f92be8e4e9160cc5f350fcfc6482cfd3f28`.
`publish.sh` pushes with OCI media types so the registry digest matches
`reproducible-build.sh`.

### D-036 Host choice for the first live run. **Resolved: Phala Cloud** (below)
Research 2026-11-26 (sources in SELF_HOSTING §1): rentable bare-metal TDX
starts around €560-630/month plus a setup fee of about one month (OVHcloud
Advance-5 / Scale-i1 2026, Hetzner EX131), and no provider documents TDX
enablement explicitly. Servury (suggested by the maintainer) sells VMs only;
its "Blackbox" line is an AMD SEV-SNP *guest* with bring-your-own UKI and a
fixed provider OVMF (about $20/month, pre-order): unusable for dstack, but a
match for the SEV-SNP stretch target (configfs-tsm + sev-snp-measure).
Cheaper TDX alternative: dstack's `dstack-cloud` on a GCP C3 confidential VM
(the dstack guest runs as the cloud CVM; different firmware measurements and
a vTPM half that GetQuote does not carry).
*Later: the Servury offering was read again for D-055; the plans seen then
were $4.99 and $9.99 per month (SNP_SERVURY.md §1). An image for it was
built, never booted there.*

---

## M3 Phala decisions (2026-11-26)

Maintainer decided: Phala Cloud first (cost), own domain, sidecar image on
GHCR pushed by hand. Facts below from Phala docs and the CLI source
(Phala-Network/phala-cloud, CLI v1.2.9) and dstack `next`, read 2026-11-26.

### D-037 Phala writes the app-compose; the policy pins Phala's hash
`phala deploy --app-compose` exists behind a feature flag, but "the deployed
bytes and compose hash follow its canonical form, not the file's bytes"
(cli/docs/deploy.md). So for Phala the policy's `compose_hash` is the value
Phala reports (`--prepare-only`, provision API, or `phala cvms get
--include-compose`), and the verifier keeps checking SHA-256(served
app-compose) against it. `render.sh ... phala` writes only the compose file.

### D-038 No pre-launch script, no env injection: verifier `Config` check
Phala injects a default `pre_launch_script` unless `--no-pre-launch-script`
(registry login, image prune, env exports;
dstack-examples/phala-cloud-prelaunch-script). Scripts and injected env can
run code or change config that the image allowlist never sees, and env
values are unmeasured. New fail-closed verifier check `Config`: rejects a
non-empty `pre_launch_script`/`init_script`, a non-empty `allowed_envs`, and
any `$` interpolation in `docker_compose_file` (`$$` literal allowed),
unless the policy sets `allow_pre_launch_script` / `allow_env_injection`.
*Superseded by D-042: exact pins instead of booleans.*

### D-039 Custom-domain TLS passthrough on Phala
Gateway reads TXT `_dstack-app-address.<sni>` (fallback
`_dstack-app-address-wildcard.<parent>`, legacy `_tapp-address`), value
`<id>:<port>`, and forwards raw TLS (dstack
`gateway/src/proxy/tls_passthough.rs`). dstack-ingress documents
TLS-ALPN-01 through it with CNAME → gateway domain and TXT →
**instance ID**:443 (Let's Encrypt multi-vantage validation vs.
per-app load balancing). Port 80 is not routable on Phala
(networking/specifications.md), hence HTTP-01 disabled. Caddy (rather
than lego) for TLS-ALPN-01 behind the gateway: **confirmed 2026-11-26**
(D-043).

### D-040 Phala KMS and storage
RTMR3 `key-provider` payload: `{"name":"kms","id":"<hex KMS root pubkey>"}`
(dstack `system_setup.rs`). With Phala's own KMS, Phala's operations decide
which compose hashes get keys; on-chain KMS (Ethereum/Base) moves that to a
contract. The data disk is LUKS with a KMS-derived key, persists across
restarts, has no integrity/rollback protection (dstack
docs/security/security-model.md). Policy pins the payload exactly.

### D-041 Measurements on Phala
Phala publishes no per-size MRTD/RTMR tables; they depend on the image plus
`vm_config` (cpu_count, memory_size, qemu_version, …; dstack-types
`VmConfig`). Plan: compute with `dstack-mr` from the OS image Phala runs and
the CVM's `vm_config`. If a first run takes values from the live quote, the
policy file and docs must say so and must not claim C2 for that release.

### D-042 Private sidecar image on Phala (maintainer's choice, 2026-11-26)
The maintainer kept the GHCR package private. Facts (dstack
`os/common/rootfs/app-compose.sh`, `app-compose.service`): the app-compose
`pre_launch_script` is `source`d by bash under `set -euo pipefail` in a
process started with `dstack-util exec-with-env --env-file
/dstack/.host-shared/.decrypted-env.json`; `docker compose up` then runs in
the same environment. Design:

* our own measured script (`deploy/dstack/pre-launch-ghcr.sh.template`):
  `docker login ghcr.io --username <user>` with `GHCR_READ_TOKEN` from
  encrypted env; registry and user literal;
* policy replaces the D-038 booleans with exact pins:
  `pre_launch_script_sha256` (absent ⇒ no script allowed) and
  `allowed_envs` (exact set of names, default empty); `$` interpolation in
  the compose is always rejected;
* token: GitHub classic PAT, `read:packages` only, short expiry, created and
  stored by the maintainer in a gitignored env file; never handled by the
  assistant.

Cost: one unmeasured value (substitution can only break the pull because
images are pinned by digest), root code before the containers (pinned and
reviewed), and verifiers cannot pull the image (they can rebuild it: the
pushed digest `sha256:bf0734c5…` of commit `fa874ea` was reproduced
independently on 2026-11-26).

---

## M3 live run (2026-11-26)

### D-043 First live deployment on Phala: what actually happened
CVM `0b862054-77c4-436f-bb58-6a1d77f68dbe`, app ID
`5d1ee425c4437fe253becff6ebc96b7ca0d7146a`, `tdx.small`, `dstack-0.6.5`
(os_image_hash `4771a29e…`), node prod5, Phala KMS, $0.0608/h.

1. **Phala CLI 1.2.9 broken** on npm (imports `@noble/curves/ed25519`, pins
   2.4.0 which only exports `./ed25519.js`); 1.2.8 works.
2. **CLI injects your SSH key**: with a pre-launch script and without
   `--no-dev-os`, it reads `~/.ssh/id_*.pub` into encrypted env
   `DSTACK_AUTHORIZED_KEYS`. Our `Config` check would reject that env name.
3. **First boot failed**: `docker login` → `mkdir /root/.docker: read-only
   file system`. Fix: `export DOCKER_CONFIG=/tmp/.docker` in the script (as
   Phala's default script does). A failed CVM stays stopped after an
   update; `phala cvms start`.
4. **Custom domain**: TXT must be `<app-id>:443` and the domain must be bound
   with `phala domains add`; without the binding the front proxy closes the
   connection after the ClientHello. With it, raw TLS reaches Caddy and Let's
   Encrypt issued `CN=vault.example.com` (issuer YE2) via TLS-ALPN-01 within
   a minute. Confirms D-009/D-039 on Phala.
5. **New RTMR3 event `storage-encrypted`** (dstack 0.6.5): payload `1` if
   the data disk is LUKS-encrypted, `0` if not (dstack
   docs/tutorials/attestation-verification.md). The verifier failed closed
   on the unknown name; it now requires `1` when present and fails on `0`.
6. **Phala app-compose is manifest v3**: `init_script` is a list (empty);
   `features: ["kms","tproxy-net"]`, `port_policy` 443 + 8090 (guest agent),
   `storage_fs: zfs`, `public_tcbinfo: true`. The served compose and
   pre-launch script are byte-identical to our rendered files.
7. **PCK flags** on this Phala host: SMT, dynamic platform and cached keys
   all set (as on the dstack fixture), TCB UpToDate.
8. **Result**: `attested-vw-verify https://vault.example.com --policy
   policy/2026.11.0-phala-dev.toml` → PASS (all 11 checks); the live relay
   demo → FAIL on the TLS key binding (both attempts). Outputs in
   `demo/live/*.expected.txt`, `demo/relay/relay-live.expected.txt`.

Caveat recorded at the time: MRTD/RTMR0-2 were taken from the live quote,
not reproduced with `dstack-mr`, so the release did not yet support claim
C2. **Superseded by D-045**: all four were reproduced later that day. Logs are off on this deployment; future dev deployments enable
them (maintainer's preference).

### D-044 Teardown (2026-11-26)
After the live run the maintainer asked to stop the CVM and delete its disk:
`phala cvms stop` then `phala cvms delete --yes` (deleting the CVM removes
its data disk). Afterwards `phala cvms list` and `phala domains ls` are
empty, so the domain binding went with the app. Left in place: the
Cloudflare CNAME/TXT records for `vault.example.com` (they point at the
gateway and a now-unbound app ID; a new deployment gets a new app ID, so the
TXT value must be updated anyway), the private GHCR image, and the
maintainer's read-only GHCR token in the gitignored `registry.env`.

### D-045 Reproducing MRTD/RTMR0-2 (claim C2) for dstack 0.6.5
* Release notes `mkosi-os-v0.6.5`: os_image_hash `4771a29e…` (same as the
  Phala image), git revision `350a0a73ffdb6041bda69118f13d81591870b565`,
  published TDX MRTD `83baf004…706e97`.
* **Finding:** the live Phala CVM's MRTD was `2a674327…deec2b70`, not the
  published value, for the same os_image_hash. dstack's own fixture notes
  say MRTD depends on QEMU's page-add ordering (it differs between QEMU
  8.2.2 and 10.2.1), so a published MRTD cannot verify a VM on another QEMU
  setup; it has to be recomputed for the VM's `vm_config`.
* The live RTMR0 (`68102e7b…f07ffe96`) equals the value dstack's fixture
  README lists for `--cpu 1 --memory 2G --qemu-version 8.2.2` (RTMR0 is
  virtual hardware + ACPI, image-independent): strong hint that Phala's
  `tdx.small` is that shape.
* Tooling: `policy/measure/Dockerfile` builds `dstack-mr` (CLI crate
  `dstack-mr-cli`) at the image's git revision; `measure-tdx.sh` checks the
  tarball sha256 against the release notes and os_image_hash =
  SHA-256(sha256sum.txt), checks every file, runs `dstack-mr measure` with
  no network, and compares with a policy.
* The sidecar now forwards the guest agent's `vm_config` in the evidence
  (unmeasured, host-declared; it only parameterises the recomputation), and
  the verifier reports it under `observed.vm_config`.
* **Result 2026-11-26** (maintainer approved the download):
  `dstack-0.6.5.tar.gz` from the GitHub release, 630,600,346 bytes, sha256
  `f33965e0…` = release notes; os_image_hash = SHA-256(sha256sum.txt) =
  `4771a29e…`; every file matches. `dstack-mr measure -c 1 -m 2G
  --qemu-version 8.2.2` reproduced MRTD, RTMR1 and RTMR2 of the live quote
  exactly; RTMR0 matched once `--hotplug-off false` was set (dstack-mr's
  default is true; the dstack fixture's vm_config also had
  `hotplug_off: false`). So the live CVM booted the published 0.6.5 image;
  the release policy's header was updated and claims C2. The VM-shape
  parameters were inferred (tdx.small spec + fixture), not read from the
  live `vm_config`; future runs get it from the evidence. MRTD, RTMR1 and
  RTMR2 (the image-dependent registers) matched under the first guess.

### D-046 Second live deployment, release 2026.11.1-phala-dev, tamper demo (2026-11-26)
* New CVM `73eb5a7e-b94b-4cdb-8a71-e10e2bebaf6c`, app ID
  `8a1aa54cc59424f894b82a5cad0d402b047ee0ab`, created with
  `--node prod5 --image dstack-0.6.5` (same gateway, so the CNAME stayed;
  same OS image and `tdx.small` shape, so the reproduced MRTD/RTMR0-2 stayed)
  and **logs on** (`--public-logs`, the maintainer's choice for development).
  The rendered compose and pre-launch script were byte-identical to
  2026.11.0.
* The new app ID meant a new TXT value. The CVM booted before DNS changed,
  so Caddy's first TLS-ALPN-01 attempts failed (`Error getting validation
  data`); it backed off, switched to LE staging for retries as certmagic
  does, and got a production certificate about 10 minutes after the TXT
  change. No intervention needed.
* **Logs flag is measured.** Against the 2026.11.0 policy the new
  deployment passes every check except `✗ Compose hash` (`5a5e2870…` vs
  `17129f0b…`): the only difference in the app-compose is
  `"public_logs": true`. So a policy also tells verifiers whether container
  logs are exported, and turning logs on for a release users rely on is
  visible.
* Release `2026.11.1-phala-dev` drafted with `bootstrap-policy.sh`;
  `measure-tdx.sh` reproduced all four registers against it
  ([transcript](../policy/2026.11.1-phala-dev.reproduce.txt)); live verify
  → PASS (`demo/live/verify-2026.11.1.expected.txt`).
* **Tamper demo** (`demo/tamper/tamper.sh`, logs flag now matches the
  release): `SIGNUPS_ALLOWED` "false" → "true" via a Phala update; verifier
  → hardware evidence, measurements, RTMR3 replay, TLS binding all ✓,
  `✗ Compose hash` (`04bd5e87…`), FAIL exit 1. Restoring the original
  compose → PASS exit 0. Transcript: `demo/tamper/tamper.expected.txt`.
  An operator change to one Vaultwarden setting is thus visible to anyone
  running the verifier, even though the TLS key, the hardware and the OS
  are unchanged.
* **Paused, not deleted** (2026-11-26, maintainer asked to "kill the VM"):
  `phala cvms stop 73eb5a7e…` → status `stopped`. Compute billing stops;
  the 20 GB disk keeps being billed (≈ $2/month), and the app ID, data and
  domain binding stay, so `phala cvms start 73eb5a7e-b94b-4cdb-8a71-e10e2bebaf6c`
  brings release 2026.11.1-phala-dev back with no DNS change.
  `phala cvms delete` would remove all of it (D-044).

### D-047 History rewritten to the GitHub noreply address (2026-11-26)
Before the first push the maintainer asked for the GitHub noreply author
address. All commits were rewritten (`git filter-branch`, author and
committer email only) and re-signed; trees and author/committer timestamps
are unchanged, so `SOURCE_DATE_EPOCH` and therefore the reproducible
sidecar digests are unchanged. Commit IDs changed; references in this log
and in the policy headers use the new IDs (e.g. the deployed sidecar
`bf0734c5…` was built from what is now `fa874ea`, previously `f2636a0`).

### D-048 Release 2026.11.2-phala-dev; CAA blocked; CT check covers wildcards (2026-11-27)
* Sidecar rebuilt from `93761ab` and published (private GHCR,
  `sha256:19cd2eef…`). The rewritten `fa874ea` still rebuilds to the
  deployed `sha256:bf0734c5…` (D-047 holds). The local builds had stalled
  in `load metadata` because Docker Desktop's credential helper hung on a
  locked keychain; public base images build fine with a credential-free
  `DOCKER_CONFIG`.
* CVM `73eb5a7e…` updated in place (`phala deploy --cvm-id`, same flags as
  2026.11.1, logs on), so the app ID and DNS stayed. The only compose change
  is the sidecar digest (compose hash `06416521…`). Policy drafted with
  `bootstrap-policy.sh`, now pinning `app_id = 8a1aa54c…` and
  `require_storage_encrypted = true`; `measure-tdx.sh` reproduced MRTD and
  RTMR0-2 again, for the shape the sidecar now serves in `vm_config`
  ([transcript](../policy/2026.11.2-phala-dev.reproduce.txt)). Live verify
  → PASS (`demo/live/verify-2026.11.2.expected.txt`); the same policy with
  a different `app_id` → FAIL. VM stopped afterwards (not deleted).
* **CAA `accounturi` pinning is not possible on this domain.** The in-CVM
  account is `https://acme-v02.api.letsencrypt.org/acme/acct/4048885521`
  (Caddy log). But `vault.example.com` is a CNAME to the Phala gateway,
  which forbids other records at the name; CAA lookup follows the CNAME (no
  CAA there) and climbs to `example.com`, where a record would govern every
  other name of the zone. And it would not help: wildcard issuance for
  `*.example.com` follows `example.com`'s CAA, and existing wildcards stay
  valid. *Later: done after all in D-052, by making the name an A record
  with its own CAA set and adding `issuewild ";"` at the apex.*
* **CT check fixed to include wildcards.** Cert Spotter's exact-domain query
  omits `*.parent` certificates. With them, `vault.example.com` has 7
  valid-for-name certificates; 5 are Cloudflare Universal SSL wildcards
  (Google Trust Services, Sectigo; keys held by Cloudflare) and were never
  attested, so `ct-check.sh` now exits 1
  (`demo/live/ct-check.expected.txt`). The per-connection verifier is
  unaffected (it binds the key of the connection it is on). The domain-wide
  claim needs a dedicated domain without outside wildcards, ideally with
  CAA pinned at its apex and the name served via A records.

### D-049 Security review fixes: fail-closed verifier, 2026.11.4 template (2026-11-27)

An internal security review (with proof-of-concept tests) found places where
the verifier accepted more than the documentation claimed. All fixed fail
closed, each with a regression test. Choices that were not forced:

* **Mandatory pins instead of opt-outs.** `tdx.app_id` and
  `tdx.key_provider` are required; there is no `"any"` value. Consequence:
  `policy/2026.11.0-phala-dev.toml` and `2026.11.1-phala-dev.toml`, which
  predate `app_id`, no longer validate (clear error naming the field).
  They are release artifacts and were left untouched; `policy/README.md`
  records it. `2026.11.2-phala-dev.toml` validates unchanged. The policy
  schema number stays 1: every new field is optional with a safe default.
* **`accepted_tcb_status` is the exact set.** dcap-qvl's
  `QuotePolicy::strict` always accepts `UpToDate`; the set is re-checked on
  the verified claims. `Revoked` and unknown names are invalid in a policy.
* **TCB rollback through the collateral source.** New
  `tdx.min_tcb_eval_data_number`, default 20 (Intel PCS, TDX, standard set,
  2026-11-26, as recorded in `verifier/testdata/dstack/tdx-lite-collateral.json`),
  passed to dcap-qvl 0.7.1 `QuotePolicy::min_tcb_eval_data_number` (which
  compares the lower of TCB info and QE identity). The observed number is
  in the report. `update=early` is available as `--early-tcb` but is not
  the default: under the early set a platform can be `OutOfDate` while it
  is still within Intel's own update window, which would turn the live
  deployment's PASS into a FAIL through no fault of the operator. Earlier
  statements that the collateral source "affects availability only" were
  wrong and are corrected.
* **MRCONFIGID / MROWNER / MROWNERCONFIG.** Recorded in the report.
  MROWNER and MROWNERCONFIG must be zero unless pinned (dstack never sets
  them). MRCONFIGID is set by the dstack VMM (`use_mrconfigid`): version 1
  is `0x01 ‖ compose_hash` (the upstream fixture quote has exactly that, and
  the verifier recomputes it); with a `key_provider_id` in the app-compose,
  as on Phala, the VMM uses version 2 (Keccak-256) or 3 (SHA-256 over a
  host-generated JSON document). No live Phala quote was available when
  this was written (the deployment was being replaced), and the verifier
  has neither Keccak nor the v3 document, so versions 2 and 3 are accepted
  **by shape only, with a note**, unless `tdx.mr_config_id` pins the value.
  Justification: the measured dstack OS refuses to boot when a non-zero
  MRCONFIGID disagrees with the compose hash, app id and key provider it
  measured, and the verifier checks those three directly. TODO: pin
  `mr_config_id` in the next policy from the observed value. *Later: done
  in 2026.11.4 (version 3 form, pinned by value), D-052.*
* **RTMR3 is the exact dstack boot sequence** (D-010, D-028 tightened):
  `system-preparing, app-id, compose-hash, [gpu-policy-hash], instance-id,
  boot-mr-done, {[os-image-hash], key-provider}, storage-fs,
  [storage-encrypted], system-ready`. No duplicates, nothing after
  `system-ready`, no `init-script-hash`, no `gpu-attestation`. The live
  log's 11 events are the fixture's 9 plus `os-image-hash` and
  `storage-encrypted`; the relative order of `os-image-hash` and
  `key-provider` was not observable offline, so both orders are accepted.
* **Compose rules are an allowlist of service keys** plus value checks,
  not only a deny-list: a key the verifier has not reviewed is refused, so
  a future compose feature cannot slip through. The check is described as
  what it is: known pitfalls, not a proof of safety. `public_logs` can be
  pinned (`public_logs = true|false`); when a policy does not pin it the
  value is printed as a note and not enforced, because 2026.11.2 has
  `public_logs = true` and no pin, and must keep passing.
* **Rate limit.** Per client address (last `X-Forwarded-For` element,
  written by Caddy) under a global budget of 40/s, and the verifier retries
  once after a 429. Behind the Phala gateway every client arrives from the
  gateway's address, so there the per-client budget is shared and the
  improvement is the retry only. Verification fails closed either way.

**Template for 2026.11.4** (`deploy/dstack/docker-compose.template.yml`;
not deployed, no policy yet; *later: deployed as release
2026.11.4-phala-dev on 2026-11-27, D-052*):

* `caddy_certs`, a tmpfs-backed named volume (`driver_opts: type=tmpfs`),
  mounted at `/data/caddy/certificates` in `proxy` and read-only at
  `/certs` in `attest`. Tested with Docker 29.4 and the pinned Caddy image:
  both containers see the same tmpfs; the key survives a restart of the
  proxy alone and is regenerated once every container using the volume has
  stopped. Caddy re-issues at start. Limit: Let's Encrypt issues at most 5
  identical certificates per week.
* `attest` no longer mounts `caddy_data`. It still runs as uid 0 (all
  capabilities dropped): Caddy writes `0600 root` files in `0700`
  directories, and a non-root uid gets "Permission denied" (tested).
  Running Caddy as the same non-root uid would work for new deployments
  but would lock an existing deployment out of its root-owned ACME account.
* Vaultwarden: `CONFIG_FILE=/run/vaultwarden/config.json` on a tmpfs.
  Tested on the pinned 1.37.5: a planted `/data/config.json` overrides the
  environment by default, and is ignored with `CONFIG_FILE` set.
* `rsa_key.pem` stays on `/data`. Moving it to a tmpfs would give a new
  signing key at every start, invalidating all access tokens (and, in
  current Vaultwarden, refresh tokens and invitation/verification links,
  which are JWTs signed with the same key): every user signed out at each
  restart. What a copied key gives an attacker is session forgery against
  the attested server (encrypted vaults and metadata, not plaintext).
  Accepted for now; the real fix is the KMS policy below.
* Not solved by the template: THREAT_MODEL §1 (precondition of C3/C4). The
  fix is a key provider that releases the disk key only to allowlisted
  compose hashes.
* **Stale Docker state under a new compose hash (seen live, 2026-11-27).**
  After a Phala compose update that changed only the inline Caddyfile,
  `docker compose up` did not recreate the proxy container, and Caddy kept
  the old configuration while the CVM measured the new compose. Containers
  live on the persistent data disk and are not measured. A revision suffix
  on the config name (deploy agent's change to `render.sh`/template) forces
  recreation for honest updates. The general gap (any container, network
  or materialised config left by an earlier compose of the same app id)
  needs the launcher to start from nothing. Options considered:
  1. `docker compose up --force-recreate`: the right tool, but the flag is
     set in dstack's `app-compose.sh` inside the measured OS image, which
     an app cannot change. Worth proposing upstream.
  2. **Chosen:** a measured pre-launch script
     (`deploy/dstack/pre-launch-clean.sh.template`) that runs
     `docker rm -f -v` on every container and `docker network prune -f`,
     then aborts the boot if a container is left. dstack sources the
     script under `set -euo pipefail` right before `docker compose up`.
     Named volumes are kept. `render.sh` writes it for every target
     (`phala`, `phala-private` with the GHCR login appended, and into
     `app-compose.json` for self-hosted targets) and prints the hash for
     `pre_launch_script_sha256`. On Phala this means
     `--pre-launch-script pre-launch.sh --no-dev-os` for both targets
     (`--no-pre-launch-script` gave no script; omitting both flags gives
     Phala's unpinned default script, which the verifier refuses).
  3. `docker system prune -a --volumes` or deleting the Docker data root:
     would also drop the image store, but named volumes hold the vault.
  Not verified on dstack (no deployment from this branch). Open points to
  check on first use: the Docker daemon must be running when the script is
  sourced; old containers with a restart policy run from daemon start
  until the script removes them; whether dstack rewrites
  `docker-compose.yaml` in its work directory on every boot.
  *Later (D-052): ran on Phala for 2026.11.4; the daemon was up and the
  serial log shows the old containers removed. The other two points were
  not looked at. The script does not touch the image store: see "Open
  findings" at the end of this file.*

### D-050 SEV-SNP: compose bound through HOST_DATA; verified in code, never run on hardware (2026-11-27)

Design and sources: [SNP.md](SNP.md).

* **Binding.** `sev_snp.compose_binding = "host-data"` (the only mode, no
  default): `HOST_DATA` = policy `host_data` = SHA-256(served app-compose),
  with `MEASUREMENT` pinned. The host chooses `HOST_DATA`, so the binding
  holds only because the measured guest image refuses a config whose hash
  differs; that is a review obligation on the image the policy pins
  (SNP.md §3.3). The image does not exist yet. `HOST_DATA` is not trusted
  when the measurement or launch-policy check failed, and all zero fails.
  *Later: D-055 adds a second mode, `measured-cmdline`, with an image;
  there is still no image for `host-data`.*
* **Mandatory pins, no opt-outs** (as D-049 for TDX): `measurement`,
  `min_tcb`, `compose_binding`, `host_data`. Defaults are the strict ones
  (`allowed_vmpl = [0]`, `allow_smt = false`, `require_alias_check = true`).
* **TCB, merged with the D-049 fail-closed fixes.** The VCEK is bound to
  the report only if every component is present on both sides and equal,
  including the FMC extension; a component the report lacks counts as
  below the minimum. `min_tcb` applies to the reported, committed and
  launch TCB. FMC: D-049 refused every report with an FMC SVN because no
  minimum could be pinned; with `min_tcb.fmc` that refusal became "fails
  unless `min_tcb.fmc` is set and met", and a policy that sets it fails a
  TCB that carries none.
* Only VCEK-signed reports (no VLEK, `MASK_CHIP_KEY` clear). The VCEK comes
  from the sidecar's certificate table or AMD KDS and is untrusted until
  the chain and chip/TCB binding check out. No CRL check.
* **Sidecar**: configfs-tsm only (`ATTEST_PLATFORM=sev-snp`); no
  `/dev/sev-guest` ioctl, which would need `unsafe`. It refuses to start if
  the app-compose does not hash to `HOST_DATA` (a guard, not the
  enforcement point).
* **Status.** Tested against one real AMD-signed Milan report and synthetic
  reports signed by a test-only chain that exists only in `cfg(test)`
  builds. Never run on SNP hardware; `policy/measure/measure-snp.sh` is
  untested.

### D-051 Google Cloud Confidential Space: implemented, never run on GCP (2026-11-27)

Design and sources: [GCP_CONFIDENTIAL_SPACE.md](GCP_CONFIDENTIAL_SPACE.md).

* **Evidence is Google's OIDC attestation token**, not a hardware quote.
  `report_data` travels in two `eat_nonce` values. The verifier pins RS256,
  issuer and audience, and takes the signing keys only from Google's JWKS
  URL (fetched over WebPKI TLS on every run; no CLI override).
* **Trust statement is weaker and different in kind**: Google runs the
  host, built the guest image, verifies the evidence and signs the result.
  A PASS holds against the workload operator and outsiders, not against
  Google. THREAT_MODEL claims about a malicious infrastructure provider do
  not carry over. The example policy accepts `GCP_INTEL_TDX` only.
* **No persistence.** Confidential Space has no verifiable persistent
  disk; KMS-released keys would be under the operator's own IAM control,
  which a remote user cannot inspect, so they are not implemented. Every
  restart is an empty vault: a demonstration of the binding, not a usable
  deployment.
* **Policy** (`[gcp_cs]`): `hwmodel`, `restart_policy` and exactly one
  digest-pinned image are mandatory; debug image, command or environment
  overrides, memory monitoring and `EXPERIMENTAL` images always fail.
  `min_swversion`, `accepted_tdx_tcb_status` and `project_id` are optional;
  an empty `accepted_tdx_tcb_status` only reports the status (the claim's
  shape is unconfirmed until a live token is seen).
* **Merged with D-049**: claim values reach details, notes and `observed`
  only through the report sanitiser. The sidecar's per-client/global rate
  limit applies; `deploy/gcp-cs/supervisor.sh` sets 2/s per client and 4/s
  in total, under Google's quota of 5 tokens per second.
* One image with three processes (Vaultwarden, Caddy, sidecar) under a
  small supervisor; `deploy/gcp-cs/deploy.sh` prints commands and runs
  nothing. Unconfirmed until a live run: socket path, nonce order, the
  shape of the `tdx` claim, networking.
* *Later: run live once on 2026-11-27 and torn down, D-053; those four
  points were confirmed there (GCP_CONFIDENTIAL_SPACE.md §10).*

### D-052 example.com: Pages off the Cloudflare proxy, Universal SSL off, CAA on the vault name; release 2026.11.4-phala-dev (2026-11-27)

Goal: stop certificates for `vault.example.com` from existing outside the
CVM (D-048: Cloudflare's Universal SSL wildcards cover the name).

* **GitHub Pages moved to DNS only.** `example.com` (Pages repository
  `knowledgebase`, custom domain) was a proxied CNAME; it is now four A and
  four AAAA records to GitHub Pages, and `www` a CNAME to
  `<user>.github.io`, all DNS only. GitHub issued its own Let's
  Encrypt certificate for `example.com` + `www.example.com` (after removing
  and re-adding the custom domain through the API; about a minute), and
  "enforce HTTPS" is on. `www` had been answering 526 behind Cloudflare and
  works again.
* **Universal SSL turned off** for the zone, after the site served
  GitHub's certificate. Cloudflare issues no further `*.example.com`
  certificates. The five existing wildcards are not affected by this in CT
  terms: they stay valid until they expire, the last on 2027-01-31, and
  `ct-check.sh` and the browser verifier keep failing until then.
  **Side effect, accepted by the owner:** seven other proxied names of the
  zone (`editor`, `home`, `ipfs`, and the tunnels `ethos`, `local`, `skip`,
  `skipapi`) no longer have an edge certificate and do not work over HTTPS.
  Their records were left unchanged.
* **Vault name: A record + CAA at the name.** `vault` is an A record to
  the gateway's address (66.220.6.105) instead of a CNAME, which allows a
  CAA set at the name: `issue "letsencrypt.org; accounturi=…/acct/4048885521;
  validationmethods=tls-alpn-01"` and `issuewild ";"`. Caddy obtained
  certificates under it twice. Cloudflare's dashboard showed no warning and
  added no records of its own at `vault` or the apex (checked at the
  authoritative servers). **Not achieved:** `caa-check.sh` still FAILs,
  because a wildcard `*.example.com` is governed by the apex, which has no
  CAA. An apex `issuewild ";"` would close that but also forbids wildcard
  certificates for every other name without its own set (`*.apps` exists
  in the zone); left for the owner to decide.
* **Apex `issuewild ";"` added (2026-11-27, later the same day).** The
  owner decided to add it: `example.com. CAA 0 issuewild ";"`, the only
  CAA record at the apex (no `issue` record, so exact-name issuance for
  the apex and for names without their own set is unchanged; the GitHub
  Pages site at the apex still serves). Cloudflare added no CAA records of
  its own (checked at the authoritative servers, 1.1.1.1 and 8.8.8.8).
  `caa-check.sh` now PASSes on both lines
  (`demo/live/caa-check-vault.expected.txt`). Cost: no CA may
  issue a wildcard for any name of the zone without its own CAA set,
  `*.apps` included. **Remaining exposure:** only the five already-issued
  Cloudflare wildcard certificates, until they expire (the last on
  2027-01-31); and the operator still controls DNS, so can change or
  remove CAA, which is visible to anyone polling the records.
* **`vault.warden.example.com` abandoned.** The dedicated-parent layout
  (CAA at `warden.example.com`, D-048's suggestion) was set up, but Phala
  did not route the two-label name (cause unknown). Its CNAME, TXT and the
  two CAA records at `warden` are still in the zone and harmless, as is
  the Phala domain binding.
* **Release 2026.11.4-phala-dev**, the D-049 template, deployed in place
  on CVM `73eb5a7e…` (same app id). Sidecar from commit `9f723df`,
  `sha256:00055017…`, reproduced with `reproducible-build.sh`. Compose hash
  `65a901cb…`. MRTD/RTMR0-2 reproduced again with `dstack-mr`. First live
  run of the D-049 checks, none needed loosening: the RTMR3 sequence is the
  expected one with `gpu-policy-hash` present and `os-image-hash` before
  `key-provider`; MRCONFIGID is the version 3 form (`0x03 ‖ 32 bytes`) and
  is now pinned by value; TCB evaluation data number 20. The policy also
  pins `public_logs = true` and `min_tcb_eval_data_number = 20`.
  `bootstrap-policy.sh` had stopped working with D-049 (its placeholder
  policy lacked the mandatory `app_id` / `key_provider`, and with zero
  placeholders the event-log gate fails); it now runs a second pass with
  the two observed values pinned and emits the new fields.
* Results: verify → PASS; wrong `app_id` → FAIL; CORS header present;
  after `phala cvms restart` → PASS with a different leaf key (`a8ecc85c…`
  → `e7496d20…`), confirming the tmpfs key store; the pre-launch cleanup
  removed the three old containers (serial log); smoke test clean. Browser
  verifier (merged from its branch, built at this tree): every line ✓
  except Certificate Transparency, in Node and in a real browser
  (`web/testdata/live-2026-11-27-phala.json`). Let's Encrypt
  budget for the name: 4 of 5 identical certificates used this week.
  CVM stopped afterwards (not deleted).

### D-053 Google Cloud Confidential Space: one live run (2026-11-27)

Merged from the GCP branch (details and transcripts in
[GCP_CONFIDENTIAL_SPACE.md](GCP_CONFIDENTIAL_SPACE.md),
`policy/2026.11.0-gcp-cs-dev.toml`, `demo/live/verify-gcp-cs.expected.txt`):
the workload ran once on the production Confidential Space image 261100 and
verified PASS; the negative cases FAIL; that nothing persists across a
restart was confirmed. The instance was torn down; the GCP project
`attested-vw-test-6976` was kept, with the workload image in its registry.
The attestation route now sends the CORS header there too, and
`ATTEST_GLOBAL_RATE_PER_SEC=4` from the integration stays. DNS leftovers of
that test in `example.com` (`vault.gcp` A record to a released address, two
CAA records at `gcp`) were to be deleted; see the open items of the
2026-11-27 session if they are still present.

### D-054 RAM-only data key with attested handoff ("keeper"): documented, not built (2026-11-27)

* **Question.** The persistent-state precondition (THREAT_MODEL §1): on
  dstack every key derives from the app id, not from the compose hash, so
  a compose nobody published can read and modify the vault on the data
  disk, and the published compose then verifies. 2026.11.4 took the TLS
  keys and `config.json` off the disk; the vault data stayed.
* **Option examined.** Keep no key for vault data at all: `/data` on a
  tmpfs, and a "keeper" that hands the vault to another VM only after both
  have verified each other with the verifier library; a standby that
  follows and takes over; optionally encrypted snapshots on untrusted
  storage with the data key escrowed as Shamir shares to recovery keys
  pinned in the measured compose. Full design, protocol, comparison with
  the other fixes and residual risks: [KEEPER.md](KEEPER.md).
* **Decision: not built.** A throwaway prototype (protocol, service,
  snapshot via SQLite's backup API, recovery formats; about 4,000 lines of
  Rust with tests) was written to test the design and passed its unit and
  localhost tests on the INSECURE mock platform; a container-level test was
  started and not completed. It was then removed from the tree on the
  owner's decision. Nothing of it ran on a TEE. No code, policy field,
  template or verifier output from it remains.
* **Reasons.** (1) Complexity out of proportion for this prototype: the
  keeper would be the largest and most security-critical component, a new
  protocol plus a second always-on VM, a two-pass deployment and one
  policy per node and role. (2) It turns a confidentiality assumption into
  an availability hazard: all replicas restarting at once destroys the
  vault unless the recovery machinery is built as well. (3) The set of
  releases that may hold the vault has to be fixed in the measured compose
  (two releases that list each other cannot name each other by compose
  hash, and any "trust what key X signs" rule hands the vault to the holder
  of X), so there is no data-preserving upgrade. (4) It does not remove
  the precondition: the Docker image store and the ACME account key stay
  on the persistent disk.
* **What stands instead.** The precondition remains a documented
  assumption; TLS keys in memory, `CONFIG_FILE` on a tmpfs and the measured
  pre-launch cleanup (D-049) narrow it. For a Phala deployment that needs
  the vault-data channel closed, the on-chain KMS with a compose-hash
  allowlist is the option to evaluate first (trust moves to the contract's
  governance; details in KEEPER.md §2 are as reported, not checked against
  the contracts).
* **Worth keeping from the exercise** (none implemented): the verifier
  could print the storage mode it reads from the measured compose
  (persistent disk, ephemeral) so that users see which promises apply; and
  the image store on the persistent disk deserves its own check, since it
  undermines every variant.

### D-055 SEV-SNP on a rented host: compose hash on the measured command line; image for Servury Blackbox, never booted on SNP (2026-11-27)

Details: [SNP_SERVURY.md](SNP_SERVURY.md), [SNP.md](SNP.md) §3.5.

* **Why a second mode.** D-050 binds the compose through `HOST_DATA`, which
  needs a host the guest owner controls. Servury's "Blackbox" VMs (QEMU
  direct boot, `kernel-hashes=on`, a published `AmdSevX64` OVMF) accept a
  customer kernel, initrd and command line but expose neither `HOST_DATA`
  nor an ID block. Everything the customer supplies is in `MEASUREMENT`.
* **Binding.** `sev_snp.compose_binding = "measured-cmdline"`: the document
  is in the measured initrd, its SHA-256 on the measured command line
  (`avw.compose_sha256=`), and `/init` powers the guest off on a mismatch.
  The verifier checks `MEASUREMENT` = `measurement`, SHA-256(served
  document) = `compose_hash` (new, mandatory in this mode, refused in
  `host-data` mode), and every D-050 launch check. `host-data` is
  unchanged.
* **What the verifier does not establish.** The report carries no compose
  hash in this mode. The pair (`measurement`, `compose_hash`) is a policy
  statement, reproducible with `deploy/sev-snp/build.sh --check` and
  `measure.sh --policy`. Accepted because the initrd holds the whole root
  file system: `MEASUREMENT` already fixes every byte, and the document
  hash only makes the configuration visible to the existing checks.
* **`HOST_DATA` is compared, not ignored**: it must equal `host_data`, and
  all zero when the policy has none. The image never reads it, so it
  cannot change behaviour; an unexpected value is still a launch nobody
  reviewed, and failing costs nothing. Alternative rejected: ignoring it
  (one less thing to break on the first boot, but a silent difference).
* **SMT.** Servury's guest policy is `0x30000` (SMT allowed). No default
  changes: the policy for that host must say `allow_smt = true`, and the
  documents say what that accepts.
* **Image: three processes, no container runtime** (as D-051's single
  image). One static busybox, a short `/init`, the unmodified Vaultwarden
  1.37.5 and Caddy 2.11.9 binaries copied from the digest-pinned images,
  the sidecar from source, Debian's kernel package (the one Servury's own
  release boots, pinned by SHA-256). A runtime would dominate the measured
  code for no gain; the cost is no isolation between the three beyond
  separate uids for Vaultwarden and Caddy. The compose-shaped document is
  kept so the Images and Config checks work unchanged; service
  environments and the Caddyfile are generated from it at build time.
* **No inputs but the measured command line and the network**: no SSH,
  getty, cloud-init, block driver or debug path. `avw.selftest=1` (boot
  tests) is a command-line word and so a different measurement.
* **State in memory only**: vault and TLS key on tmpfs; every stop or
  restart of the VM loses both, and each start requests a new certificate
  (5 per week per name at Let's Encrypt). A disk encrypted with an SNP
  derived key was considered and not built (SNP_SERVURY.md §2.3: untestable
  without hardware, loses data on every release, no rollback protection).
  No ACME account
  survives a boot, so CAA `accounturi` pinning is not possible for this
  deployment; CAA can pin the CA and the validation method only.
* **Sidecar.** `ATTEST_SNP_BINDING=measured-cmdline`: checks the document
  against `/proc/cmdline`; a missing SNP report at start-up is a warning
  and requests fail with 503, so the image can be boot-tested without
  hardware.
* **Status.** Verifier mode: unit tests with synthetic reports. Image:
  built twice with identical output; boots in QEMU 11.1.1 without SNP
  (split and UKI shapes; refuses a tampered command line). Expected
  measurement: computed with `sev-snp-measure` 0.0.13 and Servury's
  firmware (downloaded, hash as published, not rebuilt). **Nothing was run
  on SNP hardware; no account, no purchase.** The example policy
  `policy/2026.11.0-sev-snp-servury-dev.example.toml` is marked unverified.

---

## Open findings

Not decisions: things found and not yet fixed. The description of record is
[THREAT_MODEL.md §7](THREAT_MODEL.md#7-known-issues).

* **K1 Image store on the persistent disk (found 2026-11-27, OPEN).**
  Docker's image store is on the data disk; Docker checks digests on pull
  and trusts images already present locally. A compose nobody published,
  run once under the same app id, can alter stored image layers, and the
  next boot of the published compose runs them under the correct digest
  with a verifier PASS. Affects every dstack release so far (2026.11.0 to
  2026.11.4). Planned fix, not deployed: the measured pre-launch script
  (D-049) also removes all local images at boot, so every image is pulled
  again and digest-checked; slower boot, and a new release because the
  script is measured. D-049 option 3 and D-054 ("the image store ...
  deserves its own check") had named the gap without closing it.
