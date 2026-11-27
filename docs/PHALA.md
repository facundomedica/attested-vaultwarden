# Deploying on Phala Cloud (managed dstack, Intel TDX)

> Status: **executed on 2026-11-26 and 2026-11-27** (releases
> `2026.11.0-phala-dev`, `2026.11.1-phala-dev` and `2026.11.2-phala-dev`,
> see [DECISIONS.md](DECISIONS.md) D-043, D-046, D-048).
> Research prototype: do not store real passwords. Phala facts checked
> 2026-11-26 (Phala docs, CLI v1.2.9 source; v1.2.8 used, see below; dstack
> `next`); D-037–D-041. The deployed OS image is dstack 0.6.5.
> Steps marked **(you)** need your Phala account, money or DNS.

Cost: `tdx.small` (1 vCPU, 2 GB) ≈ $0.06/h, `tdx.medium` ≈ $0.12/h, billed
per running minute; disk ≈ $0.10/GB/month keeps being billed while stopped.
Delete the CVM when done.

## 0. Trust on Phala vs self-hosted

* Phala runs the host and the gateway. TDX isolates the CVM from both; with
  TLS passthrough the gateway only sees ciphertext (availability only).
* **Phala's KMS is trusted**: it releases the disk key. With the "Phala"
  KMS, Phala's operations decide which code may get keys; the on-chain KMS
  options (Ethereum/Base) move that decision to a contract you control.
  The RTMR3 `key-provider` event records which KMS (`{"name":"kms","id":"<KMS
  root public key>"}`), and the policy pins it.
* The data disk persists across restarts (LUKS, key from the KMS), but has
  no rollback protection (THREAT_MODEL R6).

## 1. Publish the sidecar image (you)

```bash
docker login ghcr.io        # token with write:packages
attest-sidecar/publish.sh ghcr.io/<github-user>/attest-sidecar
```

Prints `pin as: ghcr.io/<github-user>/attest-sidecar@sha256:…`. Then make the
package **public** (GitHub → Packages → attest-sidecar → Package settings →
Change visibility). Anyone can confirm the digest with
`attest-sidecar/reproducible-build.sh <commit>`; write that commit into the
release policy's header, because the release tag may contain later sidecar
changes.

## 1b. Private image variant (what this deployment uses)

The maintainer chose to keep the sidecar package private. The CVM then
needs its own read token (your Phala/GitHub login does not reach inside the
CVM):

1. **(you)** Create a GitHub **classic** token with only `read:packages`
   and a short expiry: <https://github.com/settings/tokens/new?scopes=read:packages&description=phala-attested-vaultwarden>
2. **(you)** Put it in `deploy/dstack/.generated/registry.env` (gitignored),
   one line: `GHCR_READ_TOKEN=<token>`. Nobody else needs to see it.
3. Render with `phala-private`: this also writes `pre-launch.sh`, a two-line
   measured script that runs `docker login ghcr.io --username <user>` with
   the token from encrypted env, and prints its SHA-256.
4. Deploy (from `deploy/dstack/.generated/`, as in step 3) with
   `--pre-launch-script pre-launch.sh -e registry.env --no-dev-os` instead of
   `--no-pre-launch-script`. **`--no-dev-os` is required**: with a
   pre-launch script, CLI 1.2.8 otherwise reads `~/.ssh/id_*.pub` and adds
   it as encrypted env `DSTACK_AUTHORIZED_KEYS` (and the verifier's
   `Config` check then rejects the extra env name).

What this costs in assurance, and why it is acceptable here:

* `allowed_envs = ["GHCR_READ_TOKEN"]`: the value is unmeasured, so the host
  could substitute it. Every image is pinned by digest, so a substituted
  token can only make the pull fail; it cannot change what runs.
* The pre-launch script runs as root before the containers. It is pinned in
  the policy (`pre_launch_script_sha256`) and reviewed.
* `$` interpolation in the compose stays forbidden, because the decrypted
  env is also in `docker compose`'s environment.
* Verifiers cannot pull the image to inspect it; they can still rebuild the
  commit named in the policy header with `attest-sidecar/reproducible-build.sh`
  and compare digests.
* A classic `read:packages` token can read *all* of the account's private
  packages, not just this one.

## 2. Render the compose

```bash
deploy/dstack/render.sh vault.<your-domain> \
  ghcr.io/<github-user>/attest-sidecar@sha256:<digest> phala
```

writes `deploy/dstack/.generated/docker-compose.yml`. Everything is literal;
no env vars are used.

## 3. Deploy the CVM (you)

```bash
npm install -g phala@1.2.8   # Phala Cloud CLI (1.2.9 is broken, see below)
phala login
cd deploy/dstack/.generated
phala deploy -n attested-vaultwarden -c docker-compose.yml \
  -t tdx.small --kms phala --disk-size 20G \
  --node prod5 --image dstack-0.6.5 \
  --no-pre-launch-script --public-logs --no-public-sysinfo --wait
```

(The exact command of the second live run, with the private-image variant
of step 1b: replace `--no-pre-launch-script` by `--pre-launch-script
pre-launch.sh -e registry.env --no-dev-os`.)

* `--image`: pin the dstack OS release, so the OS measurements are the
  ones reproduced for the release (`policy/measure/`). `--node`: keeps the
  same gateway (and CNAME) across redeployments.

* `--no-pre-launch-script`: otherwise Phala injects its default script
  (registry login, image prune, env exports), which runs outside our image
  allowlist and which the verifier refuses by default (`Config` check).
* `--public-logs` / `--no-public-logs`: measured into the app-compose, so
  it is part of the release. The CLI describes it as making CVM logs
  *publicly* accessible. Development releases keep logs **on** (with logs
  off even the owner cannot read container logs); a release meant for real
  users must turn them off (logs contain client IPs).
  `--no-public-sysinfo` always.
* Phala writes the app-compose itself (its canonical form, not ours), so the
  **compose hash to pin is the one Phala reports**: `phala cvms get <id>
  --include-compose --json`, or the verifier's observed values (step 6).

CLI notes from the live run: use **phala CLI 1.2.8**; the 1.2.9 npm package
crashes at startup (`ERR_PACKAGE_PATH_NOT_EXPORTED` for `@noble/curves/ed25519`).
`--prepare-only` exists only for *updates*.

## 4. Note the IDs

`phala deploy` prints the CVM ID and the **app ID**; `phala cvms get <id>
--json` shows the gateway base domain. Every new CVM gets a new app ID, so
the TXT record of step 5 changes on every redeployment (an *update* with
`--cvm-id` keeps it).

## 5. Bind the domain and publish DNS

```bash
phala domains add vault.<your-domain> --cvm-id <cvm-id>
```

prints the records. **(you)** at your DNS provider:

| Record | Name | Value |
|--------|------|-------|
| CNAME | `vault.<your-domain>` | `gateway.<gateway base domain>` (e.g. `gateway.dstack-pha1-prod5.phala.network`); Cloudflare: **DNS only** |
| TXT | `_dstack-app-address.vault.<your-domain>` | `<app-id>:443` |

then `phala domains verify vault.<your-domain> --cvm-id <cvm-id>`.

Observed on the 2026-11-26 run (D-043):
* Without `phala domains add` the front proxy (`ssl_backend_*`) closes the
  connection right after the ClientHello: the TXT record alone is not enough.
* The TXT value is the **app ID**, not the instance ID.
* With the domain bound, the gateway passes raw TLS to Caddy in the CVM, and
  Caddy obtained its Let's Encrypt certificate via **TLS-ALPN-01** about a
  minute later. Phala never sees the private key.
* On the second run the TXT record still held the old app ID when the CVM
  booted, so Caddy's first TLS-ALPN-01 attempts failed (`Error getting
  validation data`); it retried by itself and got the certificate once the
  new TXT value had propagated. Update DNS right after `phala deploy`.
* `domains check` suggests a CAA `0 issue "letsencrypt.org"` record;
  optional (and later: pin `accounturi` to the CVM's ACME account).

## 6. Write the release policy

Collect:

* `compose_hash`: from step 3.
* `key_provider`: the exact RTMR3 payload; the verifier prints it in the
  event-log line when the pin is absent.
* MRTD, RTMR0-2: should be computed independently with `dstack-mr` from the
  OS image Phala runs and the CVM's `vm_config` (vCPU, memory, QEMU version,
  …). For a first prototype run they may be taken from the live quote, **but
  the policy must then say so** (`# observed from live quote, not
  independently reproduced`) and docs must not claim C2 for that release.
* TCB / PCK flags: the verifier names any it rejects; accept them only
  deliberately.

```bash
attested-vw-verify https://vault.<your-domain> --policy policy/<release>.toml
```

## 7. Pause or tear down (you)

* `phala cvms stop <id>`: stops compute billing; the disk (≈ $0.10/GB/month),
  the app ID and the domain binding stay, so `phala cvms start <id>` brings
  the same release back with no DNS change.
* `phala cvms delete <id>`: stops all billing, and also deletes the data
  disk, the app (its ID) and the domain binding.
