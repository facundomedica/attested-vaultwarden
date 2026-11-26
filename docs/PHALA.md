# Deploying on Phala Cloud (managed dstack, Intel TDX)

> Status: **runbook draft (M3)**, not executed yet. Research prototype: do
> not store real passwords. Phala facts checked 2026-11-26 (Phala docs, CLI
> source v1.2.9, dstack `next`); see [DECISIONS.md](DECISIONS.md) D-037–D-041.
> Steps marked **(you)** need your account, money or DNS; I don't do them.

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
`attest-sidecar/reproducible-build.sh <commit>`.

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
4. Deploy with `--pre-launch-script deploy/dstack/.generated/pre-launch.sh
   -e deploy/dstack/.generated/registry.env` instead of
   `--no-pre-launch-script`.

What this costs in assurance, and why it is acceptable here:

* `allowed_envs = ["GHCR_READ_TOKEN"]`: the value is unmeasured, so the host
  could substitute it. Every image is pinned by digest, so a substituted
  token can only make the pull fail; it cannot change what runs.
* The pre-launch script runs as root before the containers. It is pinned in
  the policy (`pre_launch_script_sha256`) and reviewed.
* `$` interpolation in the compose stays forbidden, because the decrypted
  env is also in `docker compose`'s environment.
* Verifiers cannot pull the image to inspect it; they can still rebuild the
  commit with `attest-sidecar/reproducible-build.sh` and compare digests.
* A classic `read:packages` token can read *all* of the account's private
  packages, not just this one.

## 2. Render the compose

```bash
deploy/dstack/render.sh vault.<your-domain> \
  ghcr.io/<github-user>/attest-sidecar@sha256:<digest> phala
```

writes `deploy/dstack/.generated/docker-compose.yml`. Everything is literal;
no env vars are used.

## 3. Prepare the CVM and read the compose hash (you)

```bash
npm install -g phala       # Phala Cloud CLI
phala login
phala deploy -c deploy/dstack/.generated/docker-compose.yml \
  -t tdx.small --kms phala --disk-size 20G \
  --no-pre-launch-script --no-public-logs --no-public-sysinfo \
  --prepare-only
```

* `--no-pre-launch-script`: otherwise Phala injects its default script
  (registry login, image prune, env exports), which runs outside our image
  allowlist and which the verifier refuses by default (`Config` check).
* `--no-public-logs --no-public-sysinfo`: container logs (client IPs) must
  not be exported. These flags are measured into the app-compose.
* Phala writes the app-compose itself (its canonical form, not ours), so the
  **compose hash to pin is the one Phala reports**. `--prepare-only` reports
  it before anything runs. After deploying, `phala cvms get <id>
  --include-compose --json` shows the exact document.

Flag names come from the CLI source (UNCONFIRMED until run: if any is
rejected, paste me the error).

## 4. Deploy (you)

Re-run step 3 without `--prepare-only` (or commit the prepared deployment as
the CLI suggests). Note the **instance ID** and the **gateway domain** shown
by `phala cvms get <id> --json` / the dashboard.

## 5. DNS for the custom domain (you)

| Record | Name | Value |
|--------|------|-------|
| CNAME | `vault.<your-domain>` | `<gateway-domain>` (e.g. `gateway.dstack-prod5.phala.network`, from the dashboard) |
| TXT | `_dstack-app-address.vault.<your-domain>` | `<instance-id>:443` |
| CAA (optional) | `vault.<your-domain>` | `0 issue "letsencrypt.org; validationmethods=tls-alpn-01"` |

* The TXT record tells the gateway to forward raw TLS for this SNI to the
  CVM's port 443 (dstack `gateway/src/proxy/tls_passthough.rs`).
* Use the **instance ID**, not the app ID: Let's Encrypt validates from
  several vantage points at once, and with an app ID the gateway may spread
  those connections across instances (dstack-ingress README). Redo the
  record whenever the instance is replaced.
* Wait about 30 s for the gateway's TXT cache. Caddy then obtains the
  certificate with TLS-ALPN-01 from inside the CVM; port 80 is not routable
  on Phala, so HTTP-01 is disabled in the Caddyfile.

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

## 7. Tear down (you)

`phala cvms delete <id>` stops all billing including disk.
