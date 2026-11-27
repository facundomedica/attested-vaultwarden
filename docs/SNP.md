# AMD SEV-SNP: design, status and research notes

Status on 2026-11-27: **designed and implemented in the verifier and the
sidecar, tested only with synthetic reports and a fake configfs directory.
Never run on SNP hardware.** No guest image exists yet. This is a research
prototype; nothing here is ready for real secrets.

What is and is not established:

| Piece | State |
|-------|-------|
| Report signature chain, VCEK bound to chip and TCB, guest policy | Tested against one real AMD-signed Milan report (upstream `sev` fixture) |
| `HOST_DATA` binding, launch-policy checks, `[sev_snp]` policy schema | Tested with **synthetic** reports signed by a test-only chain (`verifier/testdata/sev-synthetic`). No real report with a non-zero `HOST_DATA` was available |
| Sidecar `ConfigfsTsm` provider | Tested against a fake directory with a scripted "kernel". Never run on a kernel with `sev_guest` |
| `policy/measure/measure-snp.sh` | Written from the `sev-snp-measure` README. Never run against real OVMF/kernel inputs; never compared with a real report |
| Guest image (OVMF + kernel + initrd that enforces `HOST_DATA`) | **Does not exist.** Requirements in §3.3 |
| AMD KDS fetch | Untested live; Milan and Genoa only. Turin needs the VCEK from the certificate table |
| Revocation (AMD CRL) | Not checked |

## 1. The problem

A TDX deployment on dstack binds the compose document through RTMR3: dstack
extends `compose-hash` into a runtime register and the verifier replays the
event log. SNP has no runtime registers. A report carries one launch
`MEASUREMENT` and a handful of launch-time fields; anything decided after
launch is invisible unless the measured code makes it visible.

Report fields that can carry a binding (AMD SEV-SNP ABI spec 56860,
`ATTESTATION_REPORT`):

| Field | Set by | When | In `MEASUREMENT`? |
|-------|--------|------|-------------------|
| `MEASUREMENT` (48 B) | firmware, over the launch pages | launch | n/a |
| `HOST_DATA` (32 B) | host, `SNP_LAUNCH_FINISH` | launch, immutable | no |
| `ID_KEY_DIGEST`, `AUTHOR_KEY_DIGEST`, `FAMILY_ID`, `IMAGE_ID` | guest owner via the signed ID block | launch | no (firmware refuses to launch if the ID block's digest/policy differ) |
| `REPORT_DATA` (64 B) | guest, per report | request | no |

`REPORT_DATA` is taken: it binds the nonce and the TLS key
(`SHA-512(tag ‖ nonce ‖ SHA-256(SPKI))`), as on TDX.

## 2. Platforms compared

Researched 2026-11-27. "UNCONFIRMED" means no primary source stated it on
that day. Prices are list prices seen that day and will drift.

| Platform | Can we set `HOST_DATA`? | `MEASUREMENT` covers | Trusted beyond AMD | Rough cost |
|----------|-------------------------|----------------------|--------------------|-----------|
| (a) Self-hosted QEMU/KVM | Yes (`host-data`), plus ID block | OVMF, and with `kernel-hashes=on` kernel + initrd + cmdline, plus vCPU state; recomputable | Nothing for integrity; the host operator for availability | A dedicated EPYC server: from about €200/month (Hetzner AX162, SNP enablement UNCONFIRMED) to about $2,800/month (Latitude.sh `rs4.metal.xlarge`, advertised with SNP attestation) |
| (b) GCP N2D SNP VM | No (not exposed; UNCONFIRMED as a stated "no") | Google's UEFI firmware only | Google's firmware (signed endorsement), and Google's **host-run vTPM** for everything above firmware | SNP premium about $6/month on an `n2d-standard-2`; total about $60-70/month (UNCONFIRMED) |
| (c1) Azure ACI confidential containers | Indirectly: `HOST_DATA` = SHA-256 of *your* CCE (Rego) policy | Microsoft's utility VM | Microsoft's UVM image and its COSE signing key | UNCONFIRMED |
| (c2) Azure confidential VMs | No | Microsoft's paravisor (with vTPM) + UEFI | The paravisor; OS and app only via vTPM PCRs; `REPORT_DATA` is not ours | UNCONFIRMED |
| (d) dstack on bare-metal SNP | Yes, by dstack: "MrConfigV3" incl. `compose_hash` | Firmware, kernel, initramfs, cmdline | dstack OS image, its KMS and TCB lists | Your hardware |
| (e) Edgeless Contrast (bare metal) | Yes, by Contrast: Kata policy digest | Kernel, initrd, cmdline (ID block) | Contrast runtime image, Coordinator manifest | Your hardware; BUSL licence for production |

### (a) Self-hosted QEMU/KVM

* Host support is upstream: KVM SNP guests since Linux 6.11, QEMU
  `sev-snp-guest` since 9.1, OVMF from `edk2-stable202405`; measured direct
  boot needs the `AmdSevX64` OVMF build
  ([QEMU `qapi/qom.json`][qom], [QEMU SEV docs][qemu-sev],
  [AMDESE/AMDSEV][amdsev], [Phoronix on 6.11, 2024-07][phoronix]).
* `sev-snp-guest` properties ([qom.json][qom], master on 2026-11-27):
  `policy` (default `0x30000`), `host-data` (base64 of 32 bytes, default
  zero, passed to `SNP_LAUNCH_FINISH`), `id-block` (base64, 96 bytes),
  `id-auth` (base64, 4096 bytes), `author-key-enabled`, `vcek-disabled`,
  and `kernel-hashes` from `sev-common`.
* `MEASUREMENT` is built over the pages added with `SNP_LAUNCH_UPDATE`:
  OVMF, the metadata pages (zero, secrets, CPUID), the kernel-hashes page
  and one VMSA per vCPU ([`sev` 9.0.0 `measurement/snp.rs`][sev-measure]).
  It is therefore a function of the OVMF binary, kernel, initrd, command
  line, vCPU count, vCPU model and guest SEV features, and of nothing else.
  `HOST_DATA` and the ID block are not in it; they are separate report
  fields ([KVM SNP uAPI][kvm-snp], ABI spec 56860 rev 1.58, May 2025;
  section numbers UNCONFIRMED, the PDF did not load on the research day).
* Tools: virtee `sev-snp-measure` 0.0.13 (PyPI, 2026-05-22) computes the
  digest offline and ships `snp-create-id-block` ([repo][ssm]); the Rust
  `sev` crate has the same as `measurement::snp::snp_calc_launch_digest`;
  virtee `snpguest` 0.11.0 (2026-10-26) fetches and verifies reports in a
  guest, including `verify attestation --host-data` ([repo][snpguest]).
* Guest side: Linux configfs-tsm (`/sys/kernel/config/tsm/report`, since
  6.7): write `inblob`, read `outblob` and, for `sev_guest`, `auxblob`, the
  GHCB certificate table ([kernel ABI doc][tsm]).
* Hardware: what matters is control of the BIOS and host kernel (SMEE,
  IOMMU, RMP coverage, SEV-SNP, a non-zero SEV-ES ASID limit;
  [Contrast bare-metal guide][contrast-bm]). Latitude.sh advertises SNP
  attestation on an EPYC 9554P server ([page][latitude], vendor marketing).
  Hetzner's AX162 (EPYC 9454P, [launch note][hetzner]) and OVH's EPYC
  ranges do not document SNP; "ask support for the BIOS toggle" is hearsay.

### (b) GCP

SNP is offered on N2D (Milan) in a few regions
([supported configurations][gcp-conf]). The customer cannot choose firmware
or boot a kernel directly, and no document exposes `HOST_DATA`.
`MEASUREMENT` covers Google's UEFI firmware, for which Google publishes
signed launch endorsements ([verify firmware][gcp-fw],
[gce-tcb-verifier][gce-tcb]). Bootloader, kernel and userspace are measured
only into the Shielded VM vTPM, which the host hypervisor runs
([attestation overview][gcp-att]); it is outside the SNP trust boundary.
For this project that means: the claim "this compose runs" would rest on
Google's vTPM, i.e. on the cloud operator the design is meant not to trust.
Confidential Space is being evaluated separately in this repository.

### (c) Azure

* **ACI confidential containers**: `az confcom` generates a CCE policy; its
  SHA-256 is the report's `HOST_DATA`; `MEASUREMENT` is Microsoft's utility
  VM, endorsed by a COSE_Sign1 document (did:x509 issuer, feed
  `ContainerPlat-AMD-UVM`, minimum SVN)
  ([overview, 2026-10-26][aci], [scheme][aci-scheme]). A verifier would
  check the VCEK chain, the COSE endorsement, `HOST_DATA` = hash of the
  expected CCE policy, and `REPORT_DATA`. Usable, but the trusted base
  includes Microsoft's UVM, and the binding is a container policy, not our
  compose document.
* **Confidential VMs**: the report is read from the vTPM (NV index
  `0x01400001`); `REPORT_DATA` is the hash of Microsoft's runtime claims
  (vTPM keys, user data), so our 64 bytes are bound only indirectly; the
  hardware report covers the paravisor and UEFI, the OS only via vTPM PCRs
  ([design, updated 2026-10-04][azure-cvm]). The paravisor runs at VMPL0
  and the guest at VMPL2 ([kernel docs][hv-coco]).
* **AKS confidential containers** (Kata): retirement was announced for
  March 2026 ([notice AZ502044, 2025-10-16][aks-retire]).

### (d) dstack

Bare-metal SNP moved to "Available" in [PR #1641][dstack-pr] (merged
2026-11-24 into `next`), for Milan, Genoa and Turin, with dstack OS 0.6.6
or later ([release v0.6.6, 2026-11-20][dstack-rel]). Its verifier recomputes
`MEASUREMENT` from firmware, kernel, initramfs and cmdline, and `HOST_DATA`
carries a "MrConfigV3" binding that includes `compose_hash`
([docs/amd-sev-snp.md][dstack-snp]; the byte layout is not documented
there, UNCONFIRMED). There is no RTMR or event-log equivalent, cloud SNP is
not supported, and VLEK is rejected. Phala Cloud's SNP offering:
UNCONFIRMED, treat as not offered.

### (e) Edgeless

Contrast is maintained (docs v1.26) and targets bare-metal SNP and TDX on
Kubernetes. `MEASUREMENT` covers kernel, initrd and cmdline, enforced with
an ID block; `HOST_DATA` is the Kata policy digest; `REPORT_DATA` is a hash
over nonce and TLS key ([architecture, v1.10][contrast-snp]). Licence is
BUSL. Constellation is archived (2026-01-22) with Contrast as successor
([repo][constellation]). Confidential Containers use the same idea: the
initdata digest goes into `HOST_DATA` ([initdata, 2026-08-26][coco]).

**Observation.** Every stack where the guest owner controls the launch
(dstack, Contrast, CoCo, ACI) converged on the same shape: pin
`MEASUREMENT`, put a config digest in `HOST_DATA`, have the measured guest
enforce it. That is the design adopted here.

## 3. Design for this project

**Recommended: (a), self-hosted QEMU/KVM, `HOST_DATA` = SHA-256(app-compose).**
It is the only option where nothing but AMD and the published image has to
be trusted, the measurement is recomputable from published inputs, and the
verifier needs no vendor-specific endorsement format.

**Fallback: (d), dstack on bare-metal SNP.** It keeps the deployment model
of the existing TDX releases (same compose, same guest agent) and already
has an image and a KMS. It needs the same hardware as (a), plus a verifier
adapter for dstack's `HOST_DATA` layout, which this repository does not
have. No public cloud offers the binding without adding the cloud's own
firmware or vTPM to the trusted base; (c1) ACI is the nearest, at the price
of trusting Microsoft's UVM.

### 3.1 What the verifier checks (`platform = "sev-snp"`)

1. **Evidence** (`snp.rs`, `snp_launch.rs`): ARK→ASK→VCEK→report
   signatures against the AMD roots built into the `sev` crate; validity
   periods; VCEK TCB extensions and hwID equal the report's reported TCB
   and chip; debug and migration agent off; VMPL in `allowed_vmpl`; the
   report is signed by a VCEK (not VLEK) and `MASK_CHIP_KEY` is clear; SMT
   off in both the guest policy and the platform unless `allow_smt`;
   `ALIAS_CHECK_COMPLETE` unless `require_alias_check = false`; reported,
   committed **and** launch TCB at or above `min_tcb`; a TCB that carries
   an FMC SVN fails unless `min_tcb.fmc` is set, and with `min_tcb.fmc`
   set a TCB without one fails; the VCEK's FMC extension must equal the
   reported FMC SVN (absent on both sides before Turin); a TCB component
   missing on either side is a mismatch; a TCB without bootloader
   or microcode SVN fails; `ID_KEY_DIGEST` / `AUTHOR_KEY_DIGEST` equal the
   policy if pinned.
2. **report_data**: `REPORT_DATA` = SHA-512(tag ‖ our nonce ‖ our TLS SPKI).
3. **Measurements**: `MEASUREMENT` = policy `measurement`.
4. **Launch config binding**: `HOST_DATA` is non-zero, and is trusted only
   if check 3 passed.
5. **Compose hash**: `HOST_DATA` = policy `host_data` = SHA-256(served
   app-compose).
6. **Config** and **Images**: as on TDX, from the hash-checked document.

There is no event-log check on SNP. Every check is fail-closed: an absent
policy field is a policy load error, an absent report field is a FAIL.

The VCEK comes from the certificate table the sidecar forwards
(`evidence.aux`) when the host supplied one, otherwise from AMD KDS. Either
way it is untrusted input until the chain and the chip/TCB binding check
out.

### 3.2 Policy

```toml
schema = 1
release = "2027.x.y-snp"
date = "2027-01-01"
platform = "sev-snp"

[sev_snp]
measurement = "<96 hex>"            # sev-snp-measure over OVMF+kernel+initrd+cmdline
compose_binding = "host-data"       # required; the only mode
host_data = "<64 hex>"              # SHA-256(app-compose.json)
# allowed_vmpl = [0]                # default
# allow_smt = false                 # default
# require_alias_check = true        # default
# id_key_digest = "<96 hex>"        # optional: SHA-384 of the ID public key
# author_key_digest = "<96 hex>"    # optional

[sev_snp.min_tcb]
bootloader = 0
tee = 0
snp = 0
microcode = 0
# fmc = 0                           # required for Turin-style reports

[[images]]
service = "vaultwarden"
image = "docker.io/vaultwarden/server@sha256:<64 hex>"
```

`min_tcb` must be chosen per CPU generation from AMD's security bulletins;
the zeros above are placeholders, not a recommendation. An ID block is
optional: the verifier already pins `MEASUREMENT`, so the ID block adds
only that the firmware refuses a wrong launch earlier, and an identity
(`id_key_digest`) that survives image upgrades.

Reproducing the two pins (`policy/measure/measure-snp.sh`, **untested**):

```sh
pip install sev-snp-measure==0.0.13
policy/measure/measure-snp.sh --ovmf OVMF.fd --kernel vmlinuz --initrd initrd.img \
  --append "<exact cmdline>" --vcpus 2 --vcpu-type EPYC-Milan-v2 \
  --compose app-compose.json --policy policy/<release>.toml
```

The digest depends on the vCPU count and model, so a policy is for one VM
shape, as with `dstack-mr` on TDX. `--guest-features` must match the guest
kernel (the tool's default is `0x1`; its README says `0x21` for guest
kernels 6.6 and later).

### 3.3 What the guest image must do (not built)

`HOST_DATA` is chosen by the host. The host can launch the pinned image
with any value. The binding therefore exists only if the **measured** code
enforces it, and the policy's `measurement` is a statement that someone
reviewed an image which does all of the following:

1. Boot only through `kernel-hashes=on` with the `AmdSevX64` OVMF, so
   kernel, initrd and command line are in `MEASUREMENT`.
2. Have its entire root filesystem covered by the measurement: inside the
   initrd, or on a dm-verity device whose root hash is on the measured
   command line.
3. In the initrd, before starting anything from the config: request a
   report, read `HOST_DATA`, read the app-compose document from the
   (unmeasured) config disk, and halt unless SHA-256(document) =
   `HOST_DATA`. Then run exactly that document and take no other input
   from the host: no cloud-init, no SSH, no debug shell, no unmeasured
   kernel parameters.
4. Derive the data-disk key from the SNP derived key **mixed with
   `HOST_DATA`**. `SNP_GET_DERIVED_KEY` can mix in the measurement and
   guest policy but has no selector for `HOST_DATA`
   (`GuestFieldSelect` in the `sev` crate), so a key derived from the
   firmware alone would be handed to the same image launched with a
   different config. The verifier would report that launch as FAIL, but
   the vault data would already be exposed to it.
5. Expose `/sys/kernel/config/tsm/report` to the sidecar only.

The sidecar repeats check 3 at start-up (`ATTEST_PLATFORM=sev-snp`): it
refuses to serve when the document it was given does not hash to
`HOST_DATA`. This catches mistakes; it is not the enforcement point,
because the sidecar is started by the config it would be checking.

Key and upgrade management (how a new release gets the old data) is not
designed. dstack answers it with a KMS; that is the main argument for the
fallback.

### 3.4 Sidecar

`attest-sidecar/src/configfs_tsm.rs`. One directory per request under
`/sys/kernel/config/tsm/report` (never reused), `provider` must be
`sev_guest`, the 64 bytes are written raw to `inblob`, `outblob` must be a
1184-byte report carrying the same 64 bytes, `generation` must have
advanced by exactly one, `auxblob` is forwarded as `evidence.aux`. No
`/dev/sev-guest` ioctl fallback: it would need `unsafe` (forbidden in this
workspace) or one more dependency inside the TEE.

## 4. Threat-model notes specific to SNP

* The physical and firmware attacks listed in THREAT_MODEL.md apply. Named
  for SNP as of late 2026: BadRAM (memory aliasing; the reason for
  `require_alias_check`), Battering RAM ([AMD-SB-3024][sb3024], DDR4
  interposer, no mitigation planned), DDR5 fault injection
  ([AMD-SB-3048][sb3048]), RMPocalypse ([AMD-SB-3020][sb3020]), Heracles
  ([AMD-SB-3021][sb3021]), StackWarp ([CISPA, 2026-01][stackwarp]),
  CacheWarp, and the November 2026 disclosures reported as "Mior" and
  "Skyfall" (press only: [The Hacker News][mior]). Bulletin-to-CVE mappings
  were not all confirmed against AMD's pages on the research day. Where a
  fix is a firmware or microcode level, it reaches the verifier only
  through `min_tcb`, which each release must set deliberately.
* No revocation check: a VCEK that AMD revoked still verifies.
* A VCEK identifies a chip. The policy does not pin `chip_id`, so the
  report proves "a genuine SNP CPU", not "the operator's CPU".
* `HOST_DATA` is visible to, and chosen by, the host; it is a commitment,
  not a secret.
* No rollback protection for the data disk, as on TDX.

## 5. Deploying it later

1. Rent or own an EPYC (Milan or Genoa) server with BIOS access; enable
   SNP; host kernel 6.11 or later, QEMU 9.1 or later.
2. Build the guest image of §3.3 reproducibly (OVMF `AmdSevX64`, kernel,
   initrd with the launcher, container runtime, the compose from
   `deploy/`). This is the largest missing piece.
3. Compute `measurement` and `host_data` with `measure-snp.sh`; write the
   policy; have a second person reproduce both.
4. Launch: `-object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1,
   policy=0x20000,kernel-hashes=on,host-data=<base64>` with `-bios`,
   `-kernel`, `-initrd`, `-append` exactly as measured (`policy=0x20000`:
   SMT disallowed; requires SMT off on the host, otherwise `0x30000` and
   `allow_smt = true`).
5. Run `attested-vw-verify https://<host> --policy policy/<release>.toml`
   and record the first real report as a test fixture. Until that fixture
   exists, treat every statement in this document about real hardware as
   unverified.

## 6. Sources

All fetched 2026-11-27 unless a date is given.

[qom]: https://raw.githubusercontent.com/qemu/qemu/master/qapi/qom.json
[qemu-sev]: https://www.qemu.org/docs/master/system/i386/amd-memory-encryption.html
[amdsev]: https://github.com/AMDESE/AMDSEV
[phoronix]: https://www.phoronix.com/news/Linux-6.11-KVM
[sev-measure]: https://docs.rs/crate/sev/latest/source/src/measurement/snp.rs
[kvm-snp]: https://docs.kernel.org/virt/kvm/x86/amd-memory-encryption.html
[ssm]: https://github.com/virtee/sev-snp-measure
[snpguest]: https://github.com/virtee/snpguest
[tsm]: https://www.kernel.org/doc/Documentation/ABI/testing/configfs-tsm-report
[contrast-bm]: https://docs.edgeless.systems/contrast/howto/cluster-setup/bare-metal
[latitude]: https://www.latitude.sh/solutions/confidential-compute
[hetzner]: https://www.hetzner.com/news/new-ax162
[gcp-conf]: https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/supported-configurations
[gcp-fw]: https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/verify-firmware
[gce-tcb]: https://github.com/google/gce-tcb-verifier
[gcp-att]: https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/attestation-overview
[aci]: https://learn.microsoft.com/en-us/azure/container-instances/container-instances-confidential-overview
[aci-scheme]: https://github.com/microsoft/confidential-aci-examples/blob/main/docs/Confidential_ACI_SCHEME.md
[azure-cvm]: https://learn.microsoft.com/en-us/azure/confidential-computing/guest-attestation-confidential-virtual-machines-design
[hv-coco]: https://kernel.org/doc/html/v7.1-rc5/virt/hyperv/coco.html
[aks-retire]: https://mc.merill.net/message/AZ502044
[dstack-pr]: https://github.com/Dstack-TEE/dstack/pull/1641
[dstack-rel]: https://github.com/Dstack-TEE/dstack/releases/tag/v0.6.6
[dstack-snp]: https://github.com/Dstack-TEE/dstack/blob/master/docs/amd-sev-snp.md
[contrast-snp]: https://docs.edgeless.systems/contrast/1.10/architecture/snp
[constellation]: https://github.com/edgelesssys/constellation
[coco]: https://confidentialcontainers.org/docs/features/initdata/
[sb3024]: https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3024.html
[sb3048]: https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3048.html
[sb3020]: https://www.amd.com/en/resources/product-security/bulletin/AMD-SB-3020.html
[sb3021]: https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3021.html
[stackwarp]: https://cispa.de/en/stackwarp
[mior]: https://thehackernews.com/2026/11/new-mior-and-skyfall-attacks-let-rogue.html

AMD SEV-SNP ABI specification 56860 (rev 1.58, May 2025):
<https://www.amd.com/content/dam/amd/en/documents/developer/56860.pdf>.
Report field offsets used by the tests and the sidecar (`REPORT_DATA`
0x50, `MEASUREMENT` 0x90, `HOST_DATA` 0xC0, signature 0x2A0) were checked
against the `sev` 9.0.0 encoder and the real Milan fixture, not against the
PDF.
