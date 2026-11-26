# Decisions and verified facts

Running log. Every external fact the code or docs rely on gets a line here
with its source and the date it was checked. Decisions that need the
maintainer's review are marked **OPEN**. The M0 recommendations (D-001,
D-004, D-005, D-008, D-010) were accepted on 2026-11-26.

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

### D-001 Licence: MIT OR Apache-2.0
Proposed in the task and in the M0 plan. Applied in M0 (`LICENSE-MIT`,
`LICENSE-APACHE`, `license` in `Cargo.toml`). Accepted with the M0 review (2026-11-26).

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
passthrough.

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
digest-pinned image.

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
payload either way.

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
commit `8c8ffae` gave the same digest
`sha256:495d22d097c0d5b88def4f8aa2a6a811021cba3616a046eee9ea5993c64dd545`.
amd64 not yet checked (CI job `reproducible-sidecar`).

### D-036 Host choice for the first live run. **OPEN**
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
than lego) for TLS-ALPN-01 behind the gateway is UNCONFIRMED until the live
run.

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

### D-035 addendum
amd64 reproducibility confirmed 2026-11-26: two clean `linux/amd64` builds
(under emulation) of commit `10bbc2b` gave
`sha256:02f03ab9d9ec65c7366ee4a770401f92be8e4e9160cc5f350fcfc6482cfd3f28`.
`publish.sh` pushes with OCI media types so the registry digest matches
`reproducible-build.sh`.

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
pushed digest `sha256:bf0734c5…` of commit `f2636a0` was reproduced
independently on 2026-11-26).
