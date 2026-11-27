# Google Cloud Confidential Space (`platform = "gcp-cs"`)

> Status: **research prototype, run live once** (written 2026-11-27, live
> test the same day: [section 10](#10-live-test-2026-11-27)). One TDX
> Confidential Space VM ran the workload image for about 18 minutes in a
> throwaway project; the verifier returned PASS against the production image
> family and FAIL for a wrong digest, a relay and the debug image family.
> The VM was then deleted. Items below are marked **CONFIRMED (live)**,
> **REFUTED (live)** or still **UNCONFIRMED**. This is not a usable
> deployment (no persistence, section 4) and not production-ready. Do not
> store real passwords.
>
> Sources were read on 2026-11-27 and are listed in [section 9](#9-sources).
> Google's documentation pages carry no visible revision date; the date
> given is the day they were read.

This adds a second platform next to dstack/Intel TDX ([PHALA.md](PHALA.md)):
the same three roles (unmodified Vaultwarden, Caddy terminating TLS inside
the TEE with a key generated there, our attestation endpoint) and the same
per-connection binding, but a **different and weaker trust statement**. Read
[section 5](#5-trust-what-a-pass-means-here) before anything else.

## 1. What Confidential Space is

* A **Confidential VM** (AMD SEV or Intel TDX; with TDX optionally an NVIDIA
  GPU) booted from Google's hardened **Confidential Space image**
  (Container-Optimized OS, dm-verity root, no SSH on the production image,
  measured boot into the vTPM and, on TDX, into RTMRs). [S1][S7]
* On boot the image's **launcher** (open source, `google/go-tpm-tools`
  `launcher/`) reads VM metadata, pulls **one container image**
  (`tee-image-reference`), measures it, and runs it. One container per VM:
  there is no compose file and no second container. [S3][S8]
* **Image families**: `confidential-space` (production) and
  `confidential-space-debug` (SSH and root for the operator; `dbgstat` is
  `enabled`). Images are named `confidential-space-YYMMNN` and carry support
  attributes `LATEST` (about a month), `STABLE` (about six months), `USABLE`
  (older, unsupported); preview images carry `EXPERIMENTAL`. [S6]
* **Technologies**: Google Cloud Attestation supports AMD SEV and Intel TDX
  for Confidential Space; Intel Trust Authority supports TDX only.
  **SEV-SNP is not offered for Confidential Space** (the documented
  `hwmodel` values are `GCP_AMD_SEV`, `GCP_AMD_SEV_ES`, `GCP_INTEL_TDX`,
  `GCP_SHIELDED_VM`). [S1][S2] TDX machine types: `c3-standard-*`,
  `c4-standard-*` (no live migration); SEV: N2D, C2D, C3D, C4D. [S5]
* **Two levers for whoever does not operate the VM**:
  * *Launch policy*: `LABEL tee.launch_policy.*` in the workload image
    decides what the operator may change through metadata (command,
    environment, log redirection, capabilities, mounts). Defaults are
    restrictive: no command override, no env override, logs only on the
    debug image. The labels are in the image config, so the image digest
    covers them. [S4]
  * *Attestation token claims*: who runs what, signed by Google.

### Metadata the operator sets (`tee-*`) [S3][S8]

`tee-image-reference` (required), `tee-restart-policy`
(`Never`/`OnFailure`/`Always`), `tee-container-log-redirect`, `tee-env-*`,
`tee-cmd`, `tee-mount` (**tmpfs only**), `tee-dev-shm-size-kb`,
`tee-added-capabilities`, `tee-cgroup-ns`, `tee-monitoring-memory-enable`,
`tee-signed-image-repos`, `tee-impersonate-service-accounts`,
`tee-nonroot-container`. The launcher source also reads `gca-service-env`
(prod/staging attestation service) and `test-fake-verifier`; either makes
the launcher obtain tokens that are not signed by Google's production key,
which our verifier rejects.

## 2. Attestation options

### (a) Google Cloud Attestation OIDC token: what we use

The launcher sends evidence (TDX: TD quote, CCEL and the launcher's
canonical event log; SEV: vTPM quote and event logs) to Google Cloud
Attestation, which returns a JWT. [S2][S9]

* Issuer `https://confidentialcomputing.googleapis.com`; discovery document
  at `/.well-known/openid-configuration`; `jwks_uri`
  `https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com`;
  only `RS256`. Fetched 2026-11-27: two RSA-2048 keys,
  `Cache-Control: max-age=22750`. (Snapshot:
  `verifier/testdata/gcp-cs/google-jwks-2026-11-27.json`.)
* Claims we rely on [S2]:

  | Claim | Meaning | Required value |
  |---|---|---|
  | `iss`, `aud`, `exp`, `nbf`, `iat` | standard | pinned issuer, our audience, valid now |
  | `eat_nonce` | nonces chosen by the workload | exactly our two values |
  | `dbgstat` | `disabled-since-boot` on production, `enabled` on debug | `disabled-since-boot` |
  | `swname` | `CONFIDENTIAL_SPACE` or `GCE` | `CONFIDENTIAL_SPACE` |
  | `swversion` | `["YYMMNN"]` image version | at least `min_swversion` if set |
  | `hwmodel` | `GCP_INTEL_TDX`, `GCP_AMD_SEV`, ... | in the policy list |
  | `secboot`, `oemid` | secure boot, Google = 11129 | `true`, `11129` |
  | `submods.confidential_space.support_attributes` | `LATEST`/`STABLE`/`USABLE`/`EXPERIMENTAL` | contains the policy's, no `EXPERIMENTAL` |
  | `submods.container.image_digest` | digest of the workload image | the policy's pinned digest |
  | `submods.container.image_reference` | where it was pulled from | reported (a note if it differs) |
  | `submods.container.restart_policy` | `Never`/`OnFailure`/`Always` | the policy's |
  | `submods.container.cmd_override`, `env_override` | operator overrides | empty |
  | `submods.confidential_space.monitoring_enabled.memory` | memory monitoring | `false` |
  | `tdx.gcp_attester_tcb_status` | Google's view of the TDX TCB | in the policy list, if the policy has one |

* **Custom nonce: yes.** The workload asks the launcher over a Unix socket
  mounted into the container [S1][S9]:

  ```
  POST http://localhost/v1/token   (unix socket /run/container_launcher/teeserver.sock)
  {"audience": "<string>", "token_type": "OIDC", "nonces": ["...", "..."]}
  ```

  The response body is the JWT. `token_type` is `OIDC`, `PKI` or
  `AWS_PRINCIPALTAGS`; the launcher rejects unknown JSON fields and a
  missing `audience` or `token_type`. Documented limits: up to six nonces,
  each 10 to 74 bytes, audience at most 512 bytes [S1]; the claims reference
  says 8 to 88 bytes [S2]. **Observed live: the service enforces 8 to 88
  bytes and at most six nonces** (`INVALID_NONCE_LENGTH`,
  `INVALID_NONCE_COUNT`); a 513-byte audience was accepted. We use two
  nonces of 64. Rate limit: 5 requests per second per project per region
  [S1] (not measured).
* `GET /v1/token`, and a token file the launcher keeps refreshed in
  `/run/container_launcher/attestation_verifier_claims_token` (name
  **CONFIRMED (live)**, mode 0644), give the *default* token: audience
  `https://sts.googleapis.com`, no custom nonce. That one is for workload
  identity federation. **It must never be served to clients**, and we never
  request it.
* **PKI tokens** (`token_type: "PKI"`): the same claims, signed by a leaf
  certificate whose chain is in the `x5c` header and ends in Google's
  Confidential Space root (`/.well-known/attestation-pki-root`, 10-year
  rotation). They verify offline against a stored root instead of a JWKS
  fetched per run. [S1] Not implemented; a candidate for removing the live
  JWKS fetch. **CONFIRMED (live)** that the launcher returns one (`alg`
  RS256, three certificates in `x5c`); the chain was not validated.

### (b) Intel Trust Authority token (TDX only)

`POST /v1/intel/token` on the same socket returns a token issued by
`https://portal.trustauthority.intel.com` instead of Google. [S1][S9] It
needs an ITA subscription and API key, which the operator passes in VM
metadata (`ita-api-key`, `ita-region`; gated behind a launcher experiment in
the source read [S8]). The appeal is a verifier that is not the cloud
provider. Not implemented; **UNCONFIRMED** end to end. Observed live without
a key: HTTP 500 "no ITA verifier client present" (the launcher's
`EnableItaVerifier` experiment was on).

### (c) Raw evidence from inside the workload

The launcher source at `main` also serves `POST /v1/evidence` with a
`challenge`, returning a `VmAttestation` whose quote is, on TDX, the TD
quote plus CCEL and launcher event logs, with TDX `report_data` =
SHA-512(label ‖ SHA-512(challenge ‖ ...)). [S9][S10] This is not in Google's
product documentation. **REFUTED (live) for image 261100**: the route
exists but answers HTTP 500 "attestation evidence is disabled" (launcher
experiment `EnableAttestationEvidence:false`, which the operator cannot
set). It would let
our own DCAP verifier check an Intel-signed quote, but the verifier would
then need reference values for Google's firmware and for the Confidential
Space image, which third parties cannot reproduce. The container cannot
reach a TPM or TDX guest device directly (**observed live**: its `/dev` has
no `tpm*` or `tdx_guest`, and it runs without `CAP_SYS_ADMIN`), so the
launcher socket is the only route to evidence. Left as future work ([section 8](#8-open-questions-and-future-work)).

## 3. Binding the token to the TLS connection

Unchanged from TDX in what is bound:

```
report_data = SHA-512("attested-vaultwarden/v1" || nonce[32] || spki_sha256[32])
eat_nonce   = [ hex(report_data[0..32]), hex(report_data[32..64]) ]
aud         = "https://attested-vaultwarden.invalid/v1/tee-attestation"
```

* 128 hex characters do not fit one nonce (74 bytes), so the 64 bytes are
  split into two nonces of 64 hex characters, in order. The verifier
  requires **exactly** these two values and reassembles them into the same
  `ReportData` type the TDX path compares; the comparison code is shared.
* The verifier computes `report_data` from **its own** nonce and the SPKI of
  the certificate **it** received in the handshake. A token relayed from the
  real server over another TLS endpoint, or replayed from an earlier run,
  fails `report_data matches nonce + TLS key`.
* The audience is fixed and is not `https://sts.googleapis.com`, so a token
  handed to any client cannot be exchanged at Google STS for access to
  cloud resources gated on this workload.
* The served document is the existing schema: `platform: "gcp-cs"`,
  `evidence.quote` = base64 of the JWT, `app_compose: ""`,
  `image_digests: []`.

## 4. Design: one image, three processes

Confidential Space runs one container, so `deploy/gcp-cs/Dockerfile` builds
one image:

| Piece | Source | Pin |
|---|---|---|
| Base and Vaultwarden | `docker.io/vaultwarden/server` 1.37.5, unmodified | `@sha256:4fe17f41…` (same as dstack) |
| Caddy | binary copied from `docker.io/library/caddy` 2.11.9 | `@sha256:003a9780…` (same as dstack) |
| Sidecar | built from this repository, recipe of `attest-sidecar/Dockerfile` | Rust image by digest, `--locked` |
| Supervisor | `deploy/gcp-cs/supervisor.sh` (about 50 lines of bash) | in repo |
| Caddyfile | `deploy/gcp-cs/Caddyfile.template`, domain filled at build | in repo |

* **Supervisor**: starts the three processes with explicit environments
  (`env -i`), waits for the first one to exit (`wait -n`), then exits, so
  the launcher's `tee-restart-policy=Always` brings the whole set back (by
  rebooting the VM, see "Storage"). No
  process manager dependency.
* **The digest is the policy.** Domain, Caddyfile, Vaultwarden settings and
  launch policy labels are all in the image; the verifier additionally
  refuses any token showing a command or environment override. So each
  domain has its own image digest, as each domain has its own compose hash
  on dstack.
* **Reproducibility**: `deploy/gcp-cs/build.sh` builds from `git archive` of
  one commit with the pinned BuildKit, `SOURCE_DATE_EPOCH` and
  `rewrite-timestamp=true`, and prints the OCI manifest digest; `--check`
  builds twice. The image was built locally (linux/amd64, emulated on an
  arm64 Mac); whether two builds, or two machines, give the same digest has
  **not** been established. The digest printed by `build.sh` is the digest
  the registry stored and the `image_digest` claim (**CONFIRMED (live)**;
  the launcher accepted the OCI-format manifest).
* **Launch policy labels** in the image: no cmd override, no env override,
  no added capabilities, no cgroup namespace, memory monitoring `never`,
  `log_redirect=debugonly` (build with `LOG_REDIRECT=always` for a
  development image whose logs can reach Cloud Logging; that is a different
  digest, and Vaultwarden logs contain client IPs and e-mail addresses).

### Networking

A root workload container **shares the VM's network namespace**, and the
launcher opens in the VM's own firewall exactly the ports the image
`EXPOSE`s (iptables INPUT rules, TCP or UDP). [S8] So with `EXPOSE 443/tcp`,
an external IPv4 address on the VM and a VPC firewall rule for `tcp:443`,
**raw TCP 443 reaches Caddy**: no Google load balancer, no TLS termination
outside the VM, and Caddy can complete **TLS-ALPN-01** itself. Vaultwarden
(127.0.0.1:8080) and the sidecar (127.0.0.1:8081) listen on loopback only.
**CONFIRMED (live)**: the container is in the VM's network namespace, the
VM's INPUT chain is DROP with ACCEPT for tcp 443 and 80 (plus 22 on the
debug image only), and Let's Encrypt validated TLS-ALPN-01 directly against
Caddy about two seconds after Caddy started. Caddy also opens HTTP/3 on UDP
443, which neither firewall lets through.

The Vaultwarden base image declares `EXPOSE 80`, and a Dockerfile cannot
remove an inherited port, so the image config lists `80/tcp` next to
`443/tcp` and the launcher will open both in the VM firewall. Nothing
listens on 80: Vaultwarden is moved to loopback, and Caddy's HTTP-to-HTTPS
redirect listener is turned off (`auto_https disable_redirects`). The VPC
firewall rule in `deploy.sh` allows 443 only.

### Local smoke test (2026-11-27, Docker, no network, no launcher)

The built image was run with `--network none`: Vaultwarden answered
`/alive` on 127.0.0.1:8080, the sidecar answered 503 "TLS certificate not
available" (no certificate can be issued offline) and 400 for a bad nonce,
Caddy listened on 443, each process had only the environment the supervisor
gives it, and killing Caddy stopped the container. That exercises the
supervisor and the wiring, nothing about Confidential Space.

### Storage: there is no verifiable persistence

This is the largest functional gap against dstack.

* The container's writable layer and temporary data live on a partition
  encrypted with dm-crypt under an **ephemeral per-boot key**; `tee-mount`
  offers tmpfs only; the launcher has no persistent-disk mount. [S7][S8]
  **Vaultwarden's `/data` and Caddy's key and certificate are lost on every
  VM restart.** (Vaultwarden itself refuses to start in a container without
  a persistent volume; the supervisor sets `I_REALLY_WANT_VOLATILE_STORAGE`,
  which is exactly the situation.) TDX VMs do not live-migrate, so host maintenance restarts
  the VM and wipes the vault. **CONFIRMED (live)**: the stateful partition
  is dm-crypt `aes-gcm-random` over dm-integrity, a file written to it was
  gone after a reboot, and Caddy obtained a new certificate.
* **A container restart within one boot does not exist (the earlier
  assumption is REFUTED (live)).** `tee-restart-policy`
  does not restart the container in place. When the workload exits the
  launcher exits too, and its `ExecStopPost` script **reboots the whole VM
  after two minutes** (`shutdown --reboot +2`; power-off for the other
  policies). So one crashed process means at least two minutes of downtime,
  an empty vault, a new TLS key and one more certificate. On the debug
  image the launcher instead stops and holds the VM (exit status 4), which
  is what we saw after killing Caddy there.
* A new TLS key per boot means a new certificate per boot. Let's Encrypt
  allows 5 certificates per identical name set per week; repeated restarts
  exhaust it. Use the staging directory (`ACME_HOST=`) while testing.
* The Google-documented pattern for durable secrets is: keep the data
  encrypted in Cloud Storage, the key in **Cloud KMS**, and release the key
  through **Workload Identity Federation** with an attribute condition on
  the token (`swname`, `support_attributes`, `image_digest`). [S11]
  That protects data owners *who control the KMS key* from the operator. In
  our setting the operator **is** the KMS key's administrator and can grant
  themselves decrypt at any time, and a remote user cannot inspect the
  key's IAM policy. So KMS-bound persistence adds **nothing** to what the
  verifier can tell a user, and we do not implement it. On dstack the
  equivalent trust is the KMS named in the measured `key-provider` event.
* What would work: persistence under a key the *user* holds (not designed
  here), or accepting an in-memory vault for demonstrations.

Until that is solved, **gcp-cs is a demonstration of the attestation
binding, not a usable deployment**: every restart is an empty server.

## 5. Trust: what a PASS means here

| | dstack / Intel TDX (`tdx`) | Confidential Space (`gcp-cs`) |
|---|---|---|
| Who signs what the verifier checks | Intel (quote), checked locally with Intel collateral | **Google's attestation service** (JWT) |
| Hardware quote seen by the verifier | yes | **no** |
| Guest OS | dstack image, MRTD/RTMR0-2 recomputed from published source | **Google's Confidential Space image, identified only by `swname`/`swversion`/support attributes in the token**; not reproducible by us |
| What runs | compose hash replayed from the RTMR3 event log | `image_digest` claim |
| Host operator vs attestation verifier | different parties | **the same company** |
| TLS key bound per connection | `report_data` in the quote | `eat_nonce` in the token (same value) |
| Encrypted persistent data | LUKS, key from the pinned key provider | none |

Consequences, stated plainly:

1. **Google is fully trusted.** Google runs the host, built the guest image,
   operates the vTPM, verifies the evidence and signs the result. A PASS
   says "Google states that a production Confidential Space VM runs this
   image and that the workload asked for this nonce". Against Google
   itself, or anyone holding Google's token-signing key, it proves nothing.
   The threat-model claims about a malicious *infrastructure provider*
   ([THREAT_MODEL.md](THREAT_MODEL.md)) do **not** carry over.
2. **What it does cover**: the *workload operator* (whoever owns the Google
   Cloud project and created the VM) and outsiders. On the production image
   the operator has no shell; changing the image, the command, the
   environment or using the debug image all change claims the verifier
   checks.
3. **The trust anchor is fetched, not embedded.** The verifier downloads
   Google's JWKS over WebPKI TLS from a pinned URL on every run. Whoever can
   forge a certificate for `www.googleapis.com` to the verifier can forge
   attestations. (PKI tokens against a stored root would remove this.)
4. **`GCP_AMD_SEV` is weaker again**: no CPU-signed report is involved, only
   the Google-operated vTPM. The example policy accepts `GCP_INTEL_TDX`
   only.
5. **Image freshness is Google's call.** `support_attribute = "STABLE"`
   accepts any image Google still marks stable; pin `min_swversion` to
   refuse older ones.
6. **The token is public.** It names the project, zone, instance and
   service account. Anyone who can reach the endpoint can read them.
7. **Availability**: the attestation endpoint depends on Google Cloud
   Attestation being reachable and on a quota of 5 tokens per second per
   project and region, which a client can exhaust. The sidecar caps itself
   at 2 per second and client address and 4 per second in total
   (`ATTEST_RATE_PER_SEC`, `ATTEST_GLOBAL_RATE_PER_SEC` in `supervisor.sh`).

## 6. What is implemented

| Part | Where | Tested how |
|---|---|---|
| Platform id `gcp-cs`, `[gcp_cs]` policy, nonce encoding, constants | `common/src/gcp_cs.rs` (+ small additions in `schema.rs`, `policy.rs`) | unit tests |
| JWT verification, claim checks | `verifier/src/gcp_cs.rs` | `verifier/src/gcp_cs_tests.rs`: tokens signed with test-only keys, JWKS injected through `evidence::Context::gcp_jwks`; plus two recorded real tokens under Google's recorded key set |
| Live JWKS fetch (pinned URL, HTTPS only, no redirects) | `verifier/src/fetch.rs::gcp_jwks` | ignored network test `live_google_jwks` |
| Sidecar provider | `attest-sidecar/src/gcp_cs.rs`, `ATTEST_PLATFORM=gcp-cs` | fake launcher on a real Unix socket |
| Workload image, build and (printed) deploy commands | `deploy/gcp-cs/` | built, pushed and run once on Google Cloud (section 10); `deploy.sh` only prints commands and was followed by hand with the differences listed there |

Verifier properties: `alg` must be `RS256` before any key is looked at; the
key comes only from the injected key set, selected by `kid`, and must be an
RSA signing key of at least 2048 bits; `iss`, `aud`, `exp`, `nbf`, `iat` are
mandatory (60 s leeway); there is no CLI option to change the key source.
Claim values are chosen by whoever launched the VM; like every other
server-controlled string they reach check details, notes and the `observed`
block only through the report sanitiser (single line, control and bidi
characters escaped).
TDX, SEV-SNP and mock behaviour are unchanged: the gcp-cs branch returns
before the compose and event-log checks, and reports these checks instead:

```
✓ Hardware evidence signature, TCB, debug off: Google Cloud Attestation token: RS256 signature valid under Google key …
✓ report_data matches nonce + TLS key
✓ Firmware / OS measurements: Google attests: production Confidential Space image … on GCP_INTEL_TDX …
✓ Measured config: known pitfalls absent: restart policy Always, no command or environment overrides
✓ Images pinned and allowlisted: workload image digest sha256:… equals release …
```

(The check labels are shared with TDX and read oddly here; the first one in
particular is a signature by Google, not hardware evidence. Renaming them
was left out to keep changes to shared files small.)

### Policy

```toml
schema = 1
release = "…"
date = "…"
platform = "gcp-cs"

[gcp_cs]
hwmodel = ["GCP_INTEL_TDX"]        # accepted hwmodel claims
support_attribute = "STABLE"        # LATEST | STABLE | USABLE (default STABLE)
restart_policy = "Always"           # Never | OnFailure | Always
# min_swversion = 260900
# accepted_tdx_tcb_status = ["UpToDate"]
# project_id = "my-project"

[[images]]                          # exactly one
service = "workload"
image = "<registry>/<repo>/attested-vw-gcp-cs@sha256:<64 hex>"
```

See `deploy/gcp-cs/policy.example.toml`.

## 7. Runbook (executed once, see section 10)

Steps marked **(you)** need your Google Cloud project, money or DNS. The
scripts never call `gcloud`.

1. **Build** the image for your domain and note the digest:

   ```bash
   ACME_HOST=acme-staging-v02.api.letsencrypt.org LOG_REDIRECT=always \
     deploy/gcp-cs/build.sh vault.example.org             # development
   deploy/gcp-cs/build.sh vault.example.org HEAD --check   # release: built twice
   ```

   It builds from `git archive` of the given ref (default `HEAD`), so
   commit first.
2. **Print the commands**: `PROJECT=<id> deploy/gcp-cs/deploy.sh
   vault.example.org sha256:<digest> [dev]`. Read them.
3. **(you)** Run steps 0 to 4 of the printed output: enable APIs, create the
   Artifact Registry repository and push the image (check the pushed digest
   equals the built one), create the service account with
   `roles/confidentialcomputing.workloadUser` and
   `roles/artifactregistry.reader`, reserve a static address, open
   `tcp:443`.
4. **(you) DNS**, before the VM exists:

   ```
   vault.example.org.  300  IN  A    <static address>
   vault.example.org.  300  IN  CAA  0 issue "letsencrypt.org; validationmethods=tls-alpn-01"
   ```

   No `AAAA` record unless the VM has IPv6. No TXT record is needed (there
   is no gateway to route by SNI, unlike Phala).
5. **(you)** Create the VM (printed step 6): `--confidential-compute-type=TDX`,
   `--machine-type=c3-standard-4`, `--maintenance-policy=TERMINATE`,
   `--shielded-secure-boot`, `--image-project=confidential-space-images`,
   `--image-family=confidential-space`,
   `--metadata="^~^tee-image-reference=<image>@sha256:<digest>~tee-restart-policy=Always"`.
6. Copy `deploy/gcp-cs/policy.example.toml` to `policy/<release>.toml`, set
   the image line, and run
   `attested-vw-verify https://vault.example.org --policy policy/<release>.toml`.
   With the staging ACME directory add `--ca <staging roots PEM>`.
7. **Teardown**: delete the VM (this destroys the vault, which lives only in
   the VM), then the firewall rule and the address (billed while reserved).

### Cost (estimate, us-central1 list prices, not verified in a console)

| Item | Estimate |
|---|---|
| `c3-standard-4` (4 vCPU, 16 GB; smallest C3) | about $0.21/h |
| Confidential VM surcharge, TDX on C3: $0.0034/vCPU-h + $0.00046/GiB-h [S12] | about $0.021/h |
| Static external IPv4 in use | about $0.005/h |
| 20 GB boot disk | about $2/month |
| **Total** | **about $0.235/h, roughly $175/month** running continuously |

Confidential Space and Google Cloud Attestation have no separate charge
that we found. Possibly cheaper, **UNCONFIRMED**: `c4-standard-2` (2 vCPU,
TDX-capable per [S5]; whether the Confidential Space image boots on it was
not checked), roughly half. `n2d-standard-2` with SEV is cheaper still but
is the weaker `GCP_AMD_SEV`. Check the pricing calculator before creating
anything, and delete the VM when done.

## 8. Open questions and future work

* Done on 2026-11-27 (section 10): a live run, and a real token recorded
  as a fixture with a pinned clock.
* Not measured: Google's 5 tokens/second quota, certificate renewal,
  behaviour over more than a few minutes, a second build of the same
  digest, `c4-standard-2`, SEV.
* The launcher socket is mode 0777 inside the container and every process
  there is root, so Vaultwarden itself could ask for a token with any
  audience, including `https://sts.googleapis.com` (the launcher issued one
  with a custom nonce when asked). Nothing is gated on such a token in this
  design, but it is a reason never to add KMS release to it.
* An 88-byte nonce would hold all of `report_data` as base64 in one value.
  We keep two hex nonces; a single nonce comes back as a JSON string, not a
  list, which the verifier refuses.
* PKI tokens with an embedded root instead of a live JWKS fetch.
* Intel Trust Authority tokens, for a verifier other than the cloud
  provider (TDX only, needs an ITA key).
* `/v1/evidence`: verify the TD quote ourselves and replay the launcher
  event log, reducing Google's role to host, firmware and guest image
  publisher.
* Persistence under a user-held key.
* Check labels that read correctly for a token-based platform.

## 9. Sources

All read 2026-11-27.

* [S1] Google Cloud, "Connect to external resources" (custom tokens, socket,
  nonce and audience limits, rate limit, OIDC and PKI verification):
  <https://docs.cloud.google.com/confidential-computing/confidential-space/docs/connect-external-resources>
* [S2] Google Cloud, "Attestation token claims":
  <https://docs.cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims>
* [S3] Google Cloud, "Workload metadata variables":
  <https://docs.cloud.google.com/confidential-computing/confidential-space/docs/reference/metadata-variables>
* [S4] Google Cloud, "Launch policies":
  <https://docs.cloud.google.com/confidential-computing/confidential-space/docs/reference/launch-policies>
* [S5] Google Cloud, "Confidential VM supported configurations":
  <https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/supported-configurations>
* [S6] Google Cloud, "Confidential Space images":
  <https://docs.cloud.google.com/confidential-computing/confidential-space/docs/confidential-space-images>;
  "Deploy workloads":
  <https://docs.cloud.google.com/confidential-computing/confidential-space/docs/deploy-workloads>;
  overview:
  <https://docs.cloud.google.com/confidential-computing/confidential-space/docs/confidential-space-overview>
* [S7] Google Cloud, "Confidential Space security overview":
  <https://docs.cloud.google.com/docs/security/confidential-space>
* [S8] `google/go-tpm-tools`, branch `main`, `launcher/spec/launch_spec.go`
  and `launcher/container_runner.go`:
  <https://github.com/google/go-tpm-tools/tree/main/launcher>
* [S9] `google/go-tpm-tools`, branch `main`,
  `launcher/teeserver/tee_server.go` (endpoints `/v1/token`,
  `/v1/intel/token`, `/v1/evidence`).
* [S10] `google/go-tpm-tools`, branch `main`, `agent/agent.go` (evidence
  sent for tokens; nonce derivation for `/v1/evidence`).
* [S11] Google Cloud, "Create and grant access to confidential resources":
  <https://docs.cloud.google.com/confidential-computing/confidential-space/docs/create-grant-access-confidential-resources>
* [S12] Google Cloud, "Confidential VM pricing" (TDX surcharge figures as
  quoted in search results; the page itself could not be read in full):
  <https://cloud.google.com/confidential-computing/confidential-vm/pricing>
* Fetched directly: `https://confidentialcomputing.googleapis.com/.well-known/openid-configuration`
  and the `jwks_uri` it names.

The launcher sources were read at the tip of `main` without recording a
commit hash; released Confidential Space images may lag behind it.

## 10. Live test (2026-11-27)

One run, by an automated agent, in a throwaway project
(`attested-vw-test-6976`, europe-west4-a, `c3-standard-4`, Intel TDX). The
VM, its address and its firewall rule were deleted afterwards; the project,
the Artifact Registry repository and the DNS records were left for the
owner to remove.

| | |
|---|---|
| Workload image | commit `9ba7038`, `LOG_REDIRECT=always`, Let's Encrypt production; `sha256:9ac03456ee9998ee9d9d30c39e1d987b2b9d0a1da31b1c9092aadf354dd90517` |
| Confidential Space image | `confidential-space-261100` (family `confidential-space`), launcher `build_commit=2e7294e` |
| Policy | [`policy/2026.11.0-gcp-cs-dev.toml`](../policy/2026.11.0-gcp-cs-dev.toml) |
| VM time | about 8 minutes on the production image, about 10 on the debug image |

Timeline of the production-image VM: created 10:23:35 UTC, boot complete
19 s later, launcher fetched its own token at 10:24:27, workload started at
10:24:28, certificate obtained at 10:24:34, first verifier PASS at 10:25.

### Results

* **PASS** on the production image:
  [`demo/live/verify-gcp-cs.expected.txt`](../demo/live/verify-gcp-cs.expected.txt).
  No verifier change was needed; the claim shapes assumed from the
  documentation were right.
* **FAIL, wrong image digest in the policy** (`Images pinned and
  allowlisted`), and FAIL for a wrong project, restart policy and minimum
  image version (`Firmware / OS measurements`, `Measured config`).
* **FAIL, relay** (`demo/relay/relay-live.sh`): `TLS key bound to
  attestation` and `report_data matches nonce + TLS key` fail, everything
  Google signed still passes:
  [`demo/relay/relay-live-gcp-cs.expected.txt`](../demo/relay/relay-live-gcp-cs.expected.txt).
* **FAIL, debug image family** (same workload digest, VM recreated on
  `confidential-space-debug` only to look at the launcher): `dbgstat is
  enabled`, and that image carries no support attributes at all.
* Fixtures: `verifier/testdata/gcp-cs/live-2026-11-27.document.json` and
  `live-debug-2026-11-27.document.json` (served documents with the real
  tokens; public data), checked in `gcp_cs_tests.rs` against Google's key
  set of the same day at a pinned clock.

### Real token, as observed

* Header `{"alg":"RS256","kid":"…","typ":"JWT"}`; `exp - iat` = 3600.
* `eat_nonce` is a list in request order for two or more nonces, a plain
  string for one, absent for none.
* `tdx` is an object: `gcp_attester_tcb_status` ("UpToDate"),
  `gcp_attester_tcb_date`, `tcb_evaluation_data_number`.
* `submods.container` has `image_reference` (exactly the
  `tee-image-reference` metadata value), `image_digest`, `image_id` (the
  config digest), `restart_policy`, `args` (`["/supervisor.sh"]`) and `env`
  (the image's environment plus `HOSTNAME`). **`cmd_override` and
  `env_override` are absent** when the operator set none.
* Also present: `sub` (the instance URL), `attester_tcb: ["INTEL"]`,
  `submods.gce` (zone, project id and number, instance name and id),
  `google_service_accounts`.

### Launcher, as observed (debug image, through the host side of the socket)

| Request | Answer |
|---|---|
| `POST /v1/token`, OIDC, one nonce of 8, 9, 10, 64, 74, 75, 88 bytes | 200 |
| one nonce of 7 or 89 bytes | 400 `INVALID_NONCE_LENGTH` ("between 8 bytes and 88 bytes") |
| 2 or 6 nonces of 64 | 200; 7 nonces: 400 `INVALID_NONCE_COUNT` |
| no `nonces` | 200, token without `eat_nonce` |
| audience of 512 and of 513 bytes | 200 both |
| audience `https://sts.googleapis.com` with a custom nonce | 200 |
| no `audience` / no `token_type` / unknown field | 400 each |
| `token_type: "PKI"` | 200, RS256, `x5c` with three certificates |
| `token_type: "AWS_PRINCIPALTAGS"` | no answer within 20 s |
| `GET /v1/token` | 200, default token (audience STS, no nonce) |
| `POST /v1/evidence` | 500 "attestation evidence is disabled" |
| `POST /v1/intel/token` | 500, no ITA key configured |

Inside the container: `/run/container_launcher/` is a read-only tmpfs with
`teeserver.sock` (0777), `attestation_verifier_claims_token` and
`experiment_data`. The supervisor's processes had only the environment it
gives them. Each `/v1/token` call took about 0.7 s end to end; eight
parallel requests to the public endpoint gave two 200s and six 429s (the
sidecar's own limit of 2 per second).

### Differences from the runbook as written

* `tee-container-log-redirect=true` was used (serial console and Cloud
  Logging); `deploy.sh` prints `cloud_logging`, which was not tried. Logs
  appeared in the log `confidential-space-launcher`.
* The image was pushed with `skopeo copy --preserve-digests` run from a
  container, authenticated with a short-lived access token in a temporary
  auth file, not with `gcloud auth configure-docker`.
* The service account also got `roles/logging.logWriter`.
* DNS: the `CAA` records were put on `gcp.facundo.dev` (covering names
  below it), with `issuewild ";"`.
* CORS: `/.well-known/tee-attestation` answers
  `Access-Control-Allow-Origin: *` on GET; an OPTIONS preflight gets 405
  from the sidecar, which a simple GET from a browser does not need.
* Three Let's Encrypt certificates were issued for the name (first boot,
  debug boot, one reboot), out of five allowed per week.

