# Self-hosting on dstack (Intel TDX)

> Status: **runbook draft (M3 prep)**. Not yet executed on real hardware;
> all live runs were on Phala Cloud ([PHALA.md](PHALA.md)). Steps that
> changed after this was written (the measured pre-launch script that
> `render.sh` now writes for every target, D-049) were never tried here.
> Research prototype: do not store real passwords. Upstream facts are from
> dstack commit `73b10c6` (2026-11-26); see [DECISIONS.md](DECISIONS.md).

This deploys one confidential VM (CVM) on a TDX host you control, running
Vaultwarden + Caddy + the attestation sidecar, with TLS terminating inside
the CVM. The Phala Cloud variant differs only in how the CVM is created and
routed (D-020); see [PHALA.md](PHALA.md).

## 0. What you trust and what you don't

* **Not trusted:** the host OS, `dstack-vmm`, QEMU, the host's network and
  disk. They see only ciphertext and can only deny service or roll back disk
  snapshots (THREAT_MODEL R5, R6).
* **Trusted:** Intel TDX, the dstack OS image (pinned by MRTD/RTMR0-2), the
  guest agent in it, and the key provider (§3).

## 1. Host requirements

From dstack's docs on `next` (checked 2026-11-26): `docs/deployment.md`,
`docs/hardware-enablement.md`, `docs/tutorials/tdx-bios-configuration.md`,
`docs/tutorials/tdx-hardware-verification.md`,
`docs/tutorials/tdx-sgx-verification.md`.

* **Bare metal** (or real TDX host access). Cloud TDX VMs are TDX *guests*:
  Azure documents nested virtualisation as unsupported on DCesv5/DCesv6, AWS
  has no TDX. They cannot run `dstack-vmm`.
* **CPU:** 5th-gen Xeon (Emerald Rapids) or Xeon 6 (Granite Rapids). Most
  4th-gen (Sapphire Rapids) SKUs only got TDX for selected cloud providers;
  avoid them.
* **Memory:** at least 2 channels populated per socket with identical DIMMs
  (Phala: "8 RAM slots filled"); ≥ 16 GB RAM, 100 GB disk, public IPv4.
* **BIOS:** 46-bit physical address limit off; TME on, TME-MT on, TME-MT
  integrity off, TDX key split ≥ 1; TDX on; SEAM loader on; **SGX on with
  SGX Auto MP Registration on** (dstack marks it critical). Needs KVM/IPMI
  BIOS access from the provider.
* **Host OS:** Ubuntu 24.04 (25.04 OK) with Canonical's TDX stack
  (`canonical/tdx`), Intel kernel (e.g. `6.8.0-1028-intel`),
  `kvm_intel.tdx=Y`, TDX-capable QEMU, `/dev/sgx_enclave` and
  `/dev/sgx_provision` present (needed by dstack's local key provider).
* **Platform registration:** register the platform with Intel PCS and run a
  PCCS/qgsd; an unregistered platform makes CVMs boot-loop (dstack issue
  #334). A previously "indirectly" registered rented box may need an SGX
  factory reset.
* **Known pitfalls:** Xeon 6 with TDX module 2.0 needed a dstack fix in the
  local key provider (issue #1462, PR #1498, closed 2026-10-28), so use a
  build that includes it; rented hosts often run old firmware, so the TCB may
  be `OutOfDate` and cannot be fixed by us (policy must then either refuse
  or explicitly accept it).

Candidate hosts (prices seen 2026-11-26, ex VAT, all monthly terms):

| Host | CPU | Price | TDX evidence |
|------|-----|-------|--------------|
| OVHcloud Advance-5 Intel | Xeon 6527P | €572.99/mo + setup ≈ 1 month | likely (KVM BIOS access; a dstack user reports this CPU working; OVH does not state TDX for this line) |
| OVHcloud Scale-i1 2026 | Xeon 6517P | €599.99/mo + €599.99 setup | OVH's Scale Intel page names SGX/TDX for Xeon 6 |
| Hetzner EX131 | Xeon Gold 6731P | €560.70/mo + €559 setup | unknown (no TDX or BIOS-change statement) |

Ask the provider to confirm the BIOS options above **before** paying a
setup fee.

## 2. Build or fetch the dstack OS image, compute expected measurements

1. Use a released image (e.g. `mkosi-os-v0.6.6`) or build it reproducibly
   (`make os-image` at the release revision; dstack
   `docs/building-guest-os.md`).
2. Compute MRTD and RTMR0-2 for **the exact VM shape you will deploy**
   (RTMR0 depends on vCPU count, memory and QEMU version):

   ```bash
   cargo run --manifest-path dstack/Cargo.toml --bin dstack-mr measure \
     -c 2 -m 4G "dstack-<version>/metadata.json"
   ```

3. Do **not** rely on the MRTD in the release notes: it depends on the
   QEMU version and differs on other setups (D-045). `policy/measure/measure-tdx.sh`
   wraps steps 1-2 (checks the tarball and image hashes, runs `dstack-mr`
   offline, compares with a policy); for Phala's `tdx.small` RTMR0 also
   needed `--hotplug-off false`.

These values go into `policy/<release>.toml` (`[tdx] mrtd, rtmr0-2`). They
come from the published image, never from the running server.

## 3. Choose a key provider (disk persistence)

| `key_provider` | Disk key | Data survives CVM restart | Extra trust | Use |
|----------------|----------|---------------------------|-------------|-----|
| `none` | random per boot (dstack `system_setup.rs`, "generating temporary app keys") | **no** | none | first demo |
| `local` | SGX sealing key from the host's local key provider enclave; its measurement is recorded in the RTMR3 `key-provider` event | yes | Intel SGX on the host, the key-provider enclave | persistent prototype |
| `kms` | dstack KMS (itself a CVM) | yes | the KMS deployment and its governance | later |

`tpm` is not offered: on a self-hosted QEMU host the vTPM is host-emulated,
so the host could unseal the key.

The policy pins the exact `key-provider` payload (`[tdx] key_provider`).

## 4. Build and publish the sidecar image

```bash
attest-sidecar/reproducible-build.sh --check <release-commit>
```

prints the image digest; two clean builds must agree. Publish the image to a
registry the CVM can pull from (needs the maintainer's OK), and record the
digest, and the commit it was built from, in the policy header. Anyone can
re-run the script on that commit and compare.

## 5. Render the deployment

```bash
deploy/dstack/render.sh vault.example.com \
  ghcr.io/<owner>/attest-sidecar@sha256:<digest> none deploy/dstack/.generated
```

writes `docker-compose.yml`, `pre-launch.sh` (embedded in the document)
and `app-compose.json`, and prints `compose_hash` and
`pre_launch_script_sha256`, which go into the policy. Every Vaultwarden setting is
literal in the compose: no encrypted env is used (`allowed_envs = []`).

## 6. DNS

Point an `A`/`AAAA` record for the domain at the host's public IP. Port 443
must reach the CVM; port 80 is not needed (Caddy uses TLS-ALPN-01).
Optional hardening, later: CAA record with `accounturi` pinned to the
CVM's ACME account (THREAT_MODEL R1/R2).

## 7. Deploy the CVM

On the host, with `dstack-vmm` running:

```bash
./vmm-cli.py deploy --name attested-vaultwarden \
  --image dstack-<version> \
  --compose deploy/dstack/.generated/app-compose.json \
  --vcpu 2 --memory 4G --disk 20G \
  --port tcp:0.0.0.0:443:443
```

The port mapping forwards raw TCP: TLS terminates in Caddy inside the CVM
(ARCHITECTURE §2), so no dstack-gateway is needed for self-hosting. No
`--env-file` (it would require KMS and is unmeasured anyway).

## 8. Write the policy, then verify

1. Create `policy/<release>.toml` with the measurements (§2), the compose
   hash (§5), the key provider (§3), the image allowlist and the TCB/PCK
   flags the host needs (D-027). Commit with a signed tag.
2. Run

   ```bash
   attested-vw-verify https://vault.example.com --policy policy/<release>.toml
   ```

3. Cross-check: if MRTD/RTMR0-2 from the live quote differ from §2, do not
   "fix" the policy from the quote; find out why (VM shape, QEMU version,
   image).

## Simulator test (no hardware)

`deploy/dstack/simulator/e2e.sh` runs the sidecar against dstack's guest-agent
simulator (built from a pinned commit inside Docker). The simulator serves a
recorded real quote with patched `report_data`, so the verifier must FAIL on
the quote signature; the test checks exactly that plus the wire protocol.
