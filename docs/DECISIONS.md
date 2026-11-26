# Decisions and verified facts

Running log. Every external fact the code or docs rely on gets a line here
with its source and the date it was checked. Decisions that need the
maintainer's review are marked **OPEN**.

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
`LICENSE-APACHE`, `license` in `Cargo.toml`). **OPEN: confirm.**

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

### D-004 dstack guest-agent API version. **OPEN**
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

### D-005 Guest-agent client implementation. **OPEN**
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

### D-008 Vaultwarden admin panel: proposal to disable. **OPEN**
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

### D-010 RTMR3 replay implementation. **OPEN**
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
* Licences: dstack MIT, dcap-qvl MIT, sev Apache-2.0. Copy with attribution
  in `testdata/SOURCES.md`.
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

### D-020 Phala Cloud vs self-hosted dstack. **OPEN**
Needs maintainer decision (cost, TDX hardware). Also determines OS image
version (D-004).
