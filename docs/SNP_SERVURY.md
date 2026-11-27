# SEV-SNP on Servury Blackbox: image, measurement and first-boot runbook

Status on 2026-11-27: **everything on this page that can be done without
hardware has been done; nothing has run on SEV-SNP hardware.** The guest
image builds reproducibly and boots in QEMU without SNP; the expected
measurement was computed offline; the verifier mode is tested with
synthetic reports. No Servury account exists and no VM was bought. This is
a research prototype and is not ready for real secrets.

| Piece | State |
|-------|-------|
| Servury's launch parameters, API and prices | Read from their public documentation on 2026-11-27 (§1). Not observed on a VM |
| Servury's firmware `OVMF.amdsev.fd` | Downloaded; SHA-256 equals the published `8731846c…`. Not rebuilt from edk2 by this project |
| Guest image (`deploy/sev-snp/`) | Built twice, the second time without cache: identical files (§3). Boot-tested in QEMU 11.1.1 **without SNP** (§3.3) |
| Expected `MEASUREMENT` | Computed with `sev-snp-measure` 0.0.13 for 1 and 2 vCPUs (§4). **Never compared with a real report** |
| Verifier mode `measured-cmdline` | Unit tests with synthetic reports signed by a test-only chain (`verifier/src/snp_tests.rs`) |
| Sidecar on a real `sev_guest` kernel | Never run. In the QEMU boot the kernel has no SNP, and the sidecar says so |
| Certificate issuance from inside the guest | Never run (an emulated guest is not reachable by Let's Encrypt) |

Background and the other SNP design (`HOST_DATA`): [SNP.md](SNP.md).
Decision record: DECISIONS D-055.

## 1. What Servury offers, as documented

Source: <https://servury.com/docs/guides/measured-boot/> and the Blackbox
API page (<https://servury.com/docs/?api=blackbox>), both read on
2026-11-27. Everything in this section is their statement.

* A "Blackbox" VM with measured boot is launched by QEMU with direct kernel
  boot and `kernel-hashes=on`. The firmware is the `AmdSevX64` build of
  OVMF, which refuses a kernel, initrd or command line whose hash is not in
  the measured hash table and cannot boot from disk.
* Firmware: one file, `OVMF.amdsev.fd`, built from `edk2-stable202505`
  (`OvmfPkg/AmdSev/AmdSevX64.dsc`, `-b RELEASE -D FD_SIZE_4MB`) in a pinned
  Debian snapshot. The same SHA-256,
  `8731846cdbcbb6aa5c624238b839544b1553f4c5af874450f043321b3ef8958b`, is
  listed for all five releases (2026.09 to 2026.11.3). The build scripts
  are published (`blackbox-images-<release>.tar.gz`).
* Launch parameters (`RELEASE.json`, `measurement_parameters`): vCPU type
  `EPYC-v4`, guest features `0x1`, guest policy `0x30000`, VMM QEMU. The
  vCPU count is the plan's (1 on Nano, 2 on Core).
* "Bring your own image": a UKI, or a bzImage with an initramfs and a
  command line, given to the panel (Manage, Boot image) or the API
  (`POST ?action=boot-image` with `url`, `sha256`, optionally `initrd_url`,
  `initrd_sha256`, `cmdline`) as an http(s) URL and a SHA-256. Kernel file
  128 KiB to 1 GiB, command line passed verbatim, at most 4096 bytes. The
  node re-hashes the files at every start. `release: true` goes back to
  Servury's own image.
* Expected measurement for a UKI, from their page:
  `sev-snp-measure --mode snp --vcpus N --vcpu-type EPYC-v4 --guest-features 0x1 --ovmf OVMF.amdsev.fd --kernel <uki> --append ''`.
* The guest gets `/dev/sev-guest` (their own initramfs uses it). Nothing in
  the documentation lets the customer set `HOST_DATA` or an ID block.
* Network: static. The API returns `network.ipv4`, `gateway4`, the
  interface name and a `suggested_cmdline` (`console=ttyS0,115200
  ip=<ip>::<gateway>:<netmask>:<host>:ens18:off`).
* Their note that an SNP guest "cannot reset itself on this stack": a
  reboot from inside the guest does not come back. This image powers off on
  failure and is started again from the panel.
* Plans seen on the front page: Blackbox Nano (1 vCPU, 2 GB) $4.99/month,
  Blackbox Core (2 vCPU, 4 GB) $9.99/month; some locations were listed as
  pre-order. The 7-day minimum term and "data deleted 24 hours after the
  term ends" come from earlier research the same day and were not re-read.

Not stated anywhere we found, to be observed on the first boot (§6): the
CPU generation, the TCB levels, whether SMT is on, whether the host passes a
certificate table with the VCEK, and what `HOST_DATA` contains.

## 2. Design

### 2.1 Binding the config without `HOST_DATA`

The design in [SNP.md](SNP.md) puts SHA-256(app-compose) into `HOST_DATA`.
Servury does not expose it. What the customer does control is the kernel,
the initrd and the command line, and all three are in the launch
`MEASUREMENT`. So the hash goes on the command line:

```
console=ttyS0,115200 panic=-1 ip=<network> avw.compose_sha256=<SHA-256 of app-compose.json>
```

* The document is a file inside the initrd. `/init` (PID 1) hashes it
  before it does anything else and powers the guest off unless the hash is
  the one on the command line. The sidecar repeats the comparison when it
  starts.
* The verifier (`compose_binding = "measured-cmdline"`) checks: report
  signature chain and launch policy as for any SNP report; `MEASUREMENT` =
  policy `measurement`; SHA-256(served document) = policy `compose_hash`;
  `HOST_DATA` = policy `host_data`, which means all zero when the policy
  has none.
* The report has no field that shows the hash. The verifier takes
  `compose_hash` from the policy, and it means something only together with
  the `measurement` pin: the policy states "the image with this measurement
  carries this document". Anyone can check that statement by rebuilding the
  image (`build.sh`, `measure.sh --policy`); the verifier cannot.

Since the whole root file system is in the initrd, `MEASUREMENT` alone
already fixes every byte that runs. The separate document hash is there so
that the verifier can show and check what the configuration is (images,
settings, `public_logs`) with the same code as on TDX, and so that the
served document is tied to the launch.

**`HOST_DATA`: compared, not ignored.** The image never reads `HOST_DATA`,
so no value of it can change what runs. The verifier still requires it to
be what the policy author saw (all zero by default, or the pinned
`host_data`): an unexpected value means the launch differs from the
reviewed one in a way nobody looked at, and refusing it costs nothing. If
Servury turns out to put something there, pin that value after the first
boot.

**SMT.** Servury's guest policy `0x30000` has the SMT bit set: the host may
run the guest on a core whose sibling thread runs something else. The
verifier refuses that unless the release policy says `allow_smt = true`,
and the Servury policy has to say it. This accepts the class of
cross-thread side channels that the default (`allow_smt = false`) rules
out; it is a property of the offering and cannot be changed by the
customer.

### 2.2 The guest image

`deploy/sev-snp/`. One static busybox, a `/init` of about 140 lines, three
service binaries with the shared libraries they link, their configuration,
and eight kernel modules (virtio-net and two Intel NIC drivers, configfs,
tsm, sev-guest, and what those depend on).

* **No container runtime.** Vaultwarden, Caddy and the sidecar are three
  processes started by `/init`, as in the Confidential Space image
  (`deploy/gcp-cs`). A runtime would be the largest and least reviewable
  part of the measured image and would add nothing here: the binaries come
  unmodified from the digest-pinned upstream images (Vaultwarden 1.37.5,
  Caddy 2.11.9, the same digests as the dstack release) and the sidecar is
  built from this repository. What is lost is the isolation between the
  three: they share one kernel and one file system. Vaultwarden runs as uid
  1000 and Caddy as uid 1001; the sidecar runs as root because configfs-tsm
  and Caddy's certificate files are root-only.
* **Kernel**: Debian's `linux-image-6.12.115+deb13.1-amd64` 6.12.115-2,
  extracted unmodified from the package, pinned by SHA-256
  (`6aa130b0…`). It is the package Servury's own release 2026.11.3 uses
  (same hash in their `RELEASE.json`), so it is known to boot on their
  hosts with guest features `0x1`.
* **Inputs it accepts**: the command line (measured) and the network. No
  SSH, no getty or shell on any console, no cloud-init, no block-device or
  file-system driver (the disk Servury attaches cannot be read), no debug
  switch. `avw.selftest=1` makes `/init` print a self-test and power off;
  it is part of the command line and therefore of the measurement, and no
  policy pins an image built with it.
* **State**: all in memory. `/data` (the vault) and `/run` (Caddy's ACME
  account, certificates and TLS private keys) are tmpfs. **Every stop,
  restart or crash of the VM destroys the vault data and the TLS key.**
  Every start therefore begins with an empty Vaultwarden and requests a new
  certificate; Let's Encrypt issues at most 5 certificates per week for the
  same set of names, so the sixth start within a week leaves the service
  without a certificate until the limit refills. This is acceptable for a
  7-day demonstration and for nothing else. Persistence is not built
  (§2.3).
* **Network**: `ip=dhcp`, or the kernel's static form as Servury's panel
  suggests it. The first non-loopback interface is used, whatever name the
  line gives. Vaultwarden and the sidecar listen on 127.0.0.1; Caddy
  listens on 443 (TCP, and UDP for HTTP/3) and obtains the certificate
  with TLS-ALPN-01. Nothing listens on 80 or on any other port.
* **Logs**: service output goes to the serial console only if the document
  has `public_logs = true` (build with `--public-logs`); the host reads
  that console. `/init`'s own lines and the sidecar's start-up lines are
  always printed; they contain no user data.
* **The document** (`app-compose.json`) has the shape the verifier already
  reads: a `docker_compose_file` member with the two upstream images and
  their settings. No runtime interprets it. `gen-config.py` generates each
  service's environment file and the Caddyfile from that same text at build
  time, and `/init` starts the services with exactly those files. The
  sidecar (no image digest: built from source) is described in a `sidecar`
  member with its commit and binary hash. The verifier's Images check
  therefore reports the upstream digests the build copied from; that the
  bytes in the initrd really are those is established by rebuilding the
  image, not by the check.

### 2.3 Persistence: not built

A persistent disk is possible on this platform but was left out. The
shape it would take: an encrypted volume on the disk Servury attaches (or
one written with their "bring your own disk"), opened in `/init` with a
key from `SNP_GET_DERIVED_KEY` with the measurement and guest policy
mixed in. A different image or command line then derives a different key
and cannot open the volume. Why it is not in this image:

* it needs a block driver, dm-crypt and a key-derivation helper in the
  measured image (the sidecar's configfs-tsm path does not expose derived
  keys; `/dev/sev-guest` ioctls need code this workspace forbids as
  `unsafe` or a new dependency), all of it security-critical and none of
  it testable without hardware;
* a key bound to the measurement means **every new release loses the
  data**, unless a migration path between measurements is designed, which
  is the hard part and is not designed;
* the disk is host-controlled: the host can roll it back to an older
  state or delete it, and the guest cannot tell (THREAT_MODEL R6);
* a TLS key on disk would re-open the question of who else could have
  derived that key, which the in-memory design avoids.

What a reviewer of a measurement has to read: `deploy/sev-snp/Dockerfile`,
`init`, `udhcpc.script`, `gen-config.py`, `mkcpio.py`, `modules.txt`,
`manifest.template.yml`, and `initrd.files.txt` from the build (every file
in the initrd with its SHA-256).

## 3. Building

Needs Docker (linux/amd64 emulation on an ARM Mac is fine) and git.

```sh
deploy/sev-snp/build.sh snp.facundo.dev \
    --ip '<ip>::<gateway>:<netmask>:avw:ens18:off' \
    --public-logs --check
```

`--check` builds a second time without cache and fails unless all seven
output files are byte-identical. The build uses a `git archive` of `HEAD`
(or `--ref`), never the working tree. Output, in
`deploy/sev-snp/.generated/<domain>/`:

| File | What |
|------|------|
| `attested-vw.efi` | The UKI: systemd-stub 257.13, kernel, initrd, command line. This is what Servury boots |
| `vmlinuz`, `initrd.img`, `cmdline.txt` | The same three parts separately (the alternative upload shape) |
| `app-compose.json` | The document the sidecar serves; `compose_hash` is its SHA-256 |
| `initrd.files.txt`, `build-info.json` | Every file in the initrd with its hash; the build's inputs and output hashes |

The domain, the ACME directory, the IP configuration, `--public-logs`, and
the commit are all measured. A change in any of them changes
`MEASUREMENT`; the IP configuration and the commit also have to be decided
before a policy can be written. That is why the policy can only be final
after the VM exists (§5).

### 3.1 Pins

| Input | Pin |
|-------|-----|
| Rust toolchain image, Caddy image, Vaultwarden image, Debian base image | `@sha256:` digests in the Dockerfile |
| Build tools (kmod, zstd, ukify, python) | Debian snapshot `20261123T000000Z` (the one the base image was built from) |
| Kernel package | SHA-256 `6aa130b0864e58c7102b53ab9c2be4071fae62394f57c80bf4e1912f4c9b3b2a` |
| `busybox-static` 1.37.0-6+b9 | SHA-256 `598a3fd92bdafc34cd81196b2952ad36e910e47a4ecf162f8ce5e8e262598e53` |
| `systemd-boot-efi` 257.13-1~deb13u1 (the UKI stub) | SHA-256 `390ecdcef9bbb753f51bb6d8f696bdae2f1dbedde7239c49ccb2512f137a8933` |
| Sidecar | built from the commit, `--locked`, `SOURCE_DATE_EPOCH` = commit time |
| BuildKit | v0.29.0 by digest, as for the sidecar image |

The build downloads from Docker Hub, `snapshot.debian.org` and crates.io.

### 3.2 Reproducibility result

Run on 2026-11-27 on an ARM Mac (Docker 29.4.0, BuildKit v0.29.0,
linux/amd64 emulation), commit `0b975a6`, `snp.facundo.dev`,
`ip=dhcp`, `--public-logs --check`. The second build ran with `--no-cache`
(sidecar recompiled, packages downloaded again). Both gave:

| File | SHA-256 |
|------|---------|
| `attested-vw.efi` | `2637c19d1a9b6c80b79031c937e9ce2213e3523391dff3a6c1698a7a6fa51db5` |
| `vmlinuz` | `96758c40859c94163e5cf81399a107d679e984e251cb4e13aba4e7d92f5d14f2` |
| `initrd.img` | `f32c41e025b69948855a164d637baa6561ee3fa255e9884e54a44885091b1586` |
| `app-compose.json` | `3ab541ee11ff2f131f496db1211a1d58c3eb8ba5c02083b1abd5f7147f129e58` |

`vmlinuz` has the same hash as the `vmlinuz` of Servury's release
2026.11.3, as it should: both are the file inside the same Debian package.

Not shown by this: reproducibility on another machine, on a native amd64
host, or at a later date (it then depends on `snapshot.debian.org` and the
registries still serving the pinned inputs).

### 3.3 Boot test without SNP

```sh
deploy/sev-snp/build.sh snp.facundo.dev --public-logs --selftest --out deploy/sev-snp/.generated/selftest
deploy/sev-snp/boot-test.sh deploy/sev-snp/.generated/selftest split
deploy/sev-snp/boot-test.sh deploy/sev-snp/.generated/selftest uki
deploy/sev-snp/boot-test.sh deploy/sev-snp/.generated/selftest tamper
```

Run on 2026-11-27 with QEMU 11.1.1 (TCG emulation, `-cpu max`, 2 vCPUs,
3 GB, virtio-net with user-mode networking), on the self-test image built
from the same commit. Its `initrd.img` and `vmlinuz` are byte-identical to
the ones of §3.2 (`f32c41e0…`, `96758c40…`); only the command line, and
with it the UKI, differs by the word `avw.selftest=1`. All three PASS:

* `split` and `uki`: `/init` accepts the document, DHCP gives an address,
  the three services start, Vaultwarden answers `/alive`, the sidecar
  answers 400 without a nonce and 503 with one, and the only sockets
  listening on a non-loopback address are TCP and UDP 443. The UKI was
  booted through QEMU's bundled edk2, not Servury's firmware.
* `tamper` (one digit of `avw.compose_sha256` changed): `/init` prints
  `FATAL: app-compose.json hashes to …, the command line says …` and powers
  off before configuring the network or starting anything.
* The image without the self-test (the one measured in §4) was booted the
  same way and stayed up for a minute with all three services running.

The sidecar's console lines in these boots are the expected ones for a
machine without SNP:

```
attest-sidecar: WARNING: NO SNP REPORT AVAILABLE (create tsm report entry: No such device or address (os error 6)). This is not an SEV-SNP guest with the sev-guest driver; every attestation request will fail with 503.
attest-sidecar: platform=sev-snp listening on 127.0.0.1:8081
```

What these boots do not show: anything involving SEV-SNP (`insmod
sev-guest.ko` fails with "No such device" here), Servury's firmware,
their network, or certificate issuance.

## 4. Expected measurement

```sh
deploy/sev-snp/measure.sh deploy/sev-snp/.generated/snp.facundo.dev
deploy/sev-snp/measure.sh deploy/sev-snp/.generated/snp.facundo.dev --policy policy/<release>.toml
```

The script downloads `OVMF.amdsev.fd` from Servury's release directory,
checks its SHA-256, and runs `sev-snp-measure` 0.0.13 (wheel pinned by
hash) in a container with Servury's parameters, for two upload shapes:

* `uki`: kernel = `attested-vw.efi`, no initrd, empty command line (the
  UKI's own `.cmdline` applies);
* `split`: kernel = `vmlinuz`, initrd = `initrd.img`, command line =
  `cmdline.txt`.

Result for the build of §3.2 (example values: `ip=dhcp`, which is not what
a Servury VM will use):

| Shape | vCPUs | Expected `MEASUREMENT` |
|-------|-------|------------------------|
| uki | 1 | `334ad3b66ceb4a41f46a5584146ae0b4a193b78c12afe7b56a04d8f5fae382602d57cbc97118f9e4c3001e806e5403f9` |
| uki | 2 | `b2082539373d7f411476d19a1aacfac03f6d624e11ab6294aeb12e6dfbea7e876609daf79e3deee53373e71e83e7ff69` |
| split | 1 | `50276a5b2de9c5f4da1db4d9e177e23cda46d02bad2c90a5c688259055ade0b15104aeb9c99ba8e82c2cf069930b371b` |
| split | 2 | `e32208f5bf9c487924496fda390033686e06b464016ba71024008b2cf03a97b6d643386317923388a4f7b45c50b46c90` |

`policy/2026.11.0-sev-snp-servury-dev.example.toml` holds those example
values. It is an **example**: marked unverified, built with `ip=dhcp`, and
to be replaced by the values of the image actually uploaded.

What the arithmetic does not settle: whether Servury's QEMU really launches
with these parameters and lays out the pages the way `sev-snp-measure`
models them for a UKI. If the first report shows another `MEASUREMENT`,
see §6.3.

## 5. Runbook

Nothing below has been run. Steps that cost money or change DNS are marked.

### 5.1 Buy (costs money)

Blackbox **Core** (2 vCPU, 4 GB, $9.99/month as listed), any location
listed as available, with **confidential computing (SNP) and measured
boot** selected at order time. They are build-time properties of the
machine (the API's `reinstall` takes `snp` and `measured`); a machine
ordered without them has to be reinstalled. Measured boot requires an SSH
key at order time: give any key; this image does not use it, and from the
first start with our image nothing of Servury's runs in the guest. The
operating system chosen does not matter either.

Nano (1 vCPU, 2 GB) may be enough; it was not sized. The initrd unpacks to
about 290 MB of RAM, and the vault tmpfs is capped at 1 GB.

From the panel or `GET ?action=boot-image&id=<server>` note:
`network.ipv4`, `gateway4`, `suggested_cmdline`, and the vCPU count.

### 5.2 DNS (changes the zone)

Pick a name that has never pointed anywhere else, for example
`snp.facundo.dev`:

* `A snp.facundo.dev -> <the VM's IPv4>`, DNS only (not proxied), no AAAA.
* CAA on that name. The zone apex has `0 issuewild ";"` and no `issue`
  record, so without a set of its own the name inherits "any CA may issue a
  non-wildcard certificate". Recommended set:

  ```
  snp.facundo.dev. CAA 0 issue "letsencrypt.org; validationmethods=tls-alpn-01"
  snp.facundo.dev. CAA 0 issuewild ";"
  ```

  This restricts issuance to Let's Encrypt and to the challenge that only
  the holder of port 443 can answer. It **cannot** carry an `accounturi`:
  the ACME account is created in memory at every boot, so there is no
  stable account to pin. Compared with `vault.facundo.dev` (which pins its
  account) this is weaker: whoever controls the IP address or the route to
  it (Servury, their upstream) can obtain a certificate for the name from
  Let's Encrypt with an account of their own. Such a certificate has a
  different key, so the verifier's `report_data` check fails against it;
  a browser without the verifier would not notice. Certificate
  Transparency shows it afterwards.

### 5.3 Build for the machine

```sh
deploy/sev-snp/build.sh snp.facundo.dev \
    --ip '<ipv4>::<gateway4>:<netmask>:avw:ens18:off' --public-logs --check
deploy/sev-snp/measure.sh deploy/sev-snp/.generated/snp.facundo.dev --vcpus 2
```

Take the address part of Servury's `suggested_cmdline` for `--ip`; the
netmask is dotted (`255.255.255.0` for a `/24`). Two resolvers may be
appended (`...:off:<dns0>:<dns1>`); without them the guest uses 9.9.9.9 and
1.1.1.1. While testing, add `--acme-host
acme-staging-v02.api.letsencrypt.org`: every start requests a new
certificate, and the production limit is 5 per week for the same name.
A staging certificate does not chain to a WebPKI root, so the verifier's
TLS check fails against it; staging is for checking that the image boots
and obtains a certificate, and the recorded run needs a production build
(a different measurement, since the ACME host is in the image).

`--public-logs` is for development: Vaultwarden's and Caddy's output then
reaches the serial console, which Servury can read.

Copy `policy/2026.11.0-sev-snp-servury-dev.example.toml` to a new policy
file and replace `measurement` (the `uki vcpus=2` line), `compose_hash`
and the header. Leave `min_tcb` at zero for the first run only (§6.2).

### 5.4 Upload (acts on the Servury account)

1. Put `attested-vw.efi` on any http(s) server (it contains no secret; it
   is about 72 MB). Note its SHA-256 from the build output.
2. Panel: Manage, Boot image: the URL and the SHA-256, **command line left
   empty**. Or the API:
   `POST ?action=boot-image&id=<server>` with
   `{"url": "...", "sha256": "..."}`; poll `GET` until `download.state` is
   `ready` and `image.sha256` is yours.
3. Restart (`?action=power`, `restart`; if the machine sits at Servury's
   passphrase prompt it ignores ACPI and needs `forcestop`, then `start`).
4. Compare the "expected measurement" on the panel's Overview card with the
   `uki vcpus=N` line of `measure.sh`. They are computed independently
   from the same inputs; a difference at this point is about parameters,
   not about hardware.

Fallback if the UKI does not boot: upload `vmlinuz` as the kernel,
`initrd.img` as the initramfs, and paste the content of `cmdline.txt`
exactly (no trailing newline) as the command line; the policy then pins the
`split vcpus=N` measurement.

### 5.5 First boot: watch the console

The serial console (panel) should show, in order: the kernel's boot lines,
`avw-init: app-compose.json sha256 … matches the kernel command line`,
`avw-init: network up on …`, `avw-init: clock (host-supplied): …`,
`avw-init: started vaultwarden, caddy and the attestation sidecar`, and
`attest-sidecar: platform=sev-snp listening on 127.0.0.1:8081` **without**
the line `WARNING: NO SNP REPORT AVAILABLE`. With `--public-logs`, Caddy's
lines about obtaining the certificate follow.

| Console shows | Meaning |
|---------------|---------|
| nothing after the firmware | The UKI did not start: try the split upload |
| `FATAL: app-compose.json hashes to …` | The command line is not the one built (panel field not empty, or edited) |
| `FATAL: no network interface` | The NIC is not virtio, e1000 or e1000e: add its module to `modules.txt` |
| `FATAL: cannot add the default route` and similar | The `--ip` line is wrong |
| `WARNING: NO SNP REPORT AVAILABLE (…)` | No `sev_guest` provider under configfs-tsm; the text in brackets says which step failed |
| `FATAL: a service exited` | With `--public-logs`, the service's last lines are above it |

## 6. Checks on the first real report

```sh
cargo run -p attested-vw-verify -- https://snp.facundo.dev \
    --policy policy/<release>.toml --json > first-run.json
```

and the same without `--json` for the readable report. Go through the
following in order; each is something this project has not seen yet.

### 6.1 What must hold

1. **`MEASUREMENT` equals the offline value** (`uki vcpus=2`). This is the
   central result: it shows that Servury launches what its documentation
   says, with the image we built. If it differs: §6.3.
2. **The command line is verbatim.** A `MEASUREMENT` match already proves
   it for the measured bytes. Cross-check on the console: `/init` prints
   the hash it found.
3. **`HOST_DATA` is all zero** (observed value in the report output). If it
   is not, read it, decide whether it is a constant (boot twice), and pin
   it as `host_data`.
4. **Guest policy is `0x30000`**, debug off, no migration agent; VMPL 0.
5. **`report_data`** binds the nonce and the certificate's key (the
   ReportData check passes over the real TLS connection).

### 6.2 What to record and then pin

* **Chip generation and TCB.** The report output shows the reported,
  committed and launch TCB (bootloader, TEE, SNP, microcode, and FMC on
  Turin). Compare with AMD's current bulletins for that generation and set
  `[sev_snp.min_tcb]` to the levels you require; a first policy with zeros
  proves nothing about firmware age. On Turin `min_tcb.fmc` is mandatory.
* **Certificate table.** Whether `evidence.aux` is present (the host
  supplies the VCEK) or the verifier had to fetch it from AMD KDS. KDS
  lookups work for Milan and Genoa only; on Turin without a certificate
  table the verifier cannot get the VCEK.
* **Signing key.** The verifier accepts VCEK only. If Servury's hosts sign
  with a VLEK the Evidence check fails and says so; that would need a
  design decision, not a flag.
* **SMT and alias check.** `PLATFORM_INFO`: SMT on or off;
  `ALIAS_CHECK_COMPLETE` must be set (the policy requires it).
* **The vCPU model.** Only indirectly: a `MEASUREMENT` match confirms
  `EPYC-v4`.

### 6.3 If `MEASUREMENT` differs

The digest has no partial matches, so work from the inputs:

1. Panel's expected value vs. `measure.sh`: if those two differ, the
   inputs differ (file hash, command line field, vCPU count, firmware
   release). If they agree and the report differs, Servury's launch does
   not match its own documentation: report it to them.
2. Try the other vCPU count line, and the `split` line if the split shape
   was uploaded.
3. A command line that was not left empty changes the UKI measurement.
4. `sev-snp-measure --guest-features`: Servury documents `0x1`.

### 6.4 Record the fixture

Save the raw document and add it to the tests, as was done for TDX and
Confidential Space:

```sh
nonce=$(openssl rand -hex 32)
curl -s "https://snp.facundo.dev/.well-known/tee-attestation?nonce=$nonce" \
    > verifier/testdata/sev-servury/attestation.json
openssl s_client -connect snp.facundo.dev:443 -servername snp.facundo.dev </dev/null 2>/dev/null \
    | openssl x509 -outform der > verifier/testdata/sev-servury/leaf.der
```

plus the policy, `app-compose.json`, `build-info.json`, the VCEK if it came
from KDS, and the verifier's text output under `demo/live/`. A test in
`verifier/src/snp_tests.rs` then replays the document against the policy
with the real AMD roots (the existing Milan test shows the pattern). Until
that fixture exists, the status table at the top of this page stands.

Also run the negative cases: a policy with one hex digit of `measurement`
changed, one with `compose_hash` changed, one with `allow_smt = false`:
each must FAIL on the named check.

### 6.5 Tear down

`POST ?action=boot-image` with `release: true` returns the machine to
Servury's image; cancelling the plan is separate. Remove the `A` and `CAA`
records for the name. Stopping the VM destroys the vault and the TLS key
(both were only in memory).

## 7. Trust statement

A PASS against a Servury policy would mean: an AMD CPU signed a report
saying that a guest was launched with debug off, at VMPL 0, with exactly
the firmware, kernel, initrd and command line whose measurement the policy
pins, and the TLS key of this connection was generated inside that guest.

What it rests on, beyond AMD and the code in this repository:

* **Servury's firmware.** `OVMF.amdsev.fd` runs inside the guest before
  our kernel and is part of the measurement. We trust that binary. It is
  claimed to be reproducible from `edk2-stable202505` with their published
  scripts; this project downloaded it and checked its hash against their
  manifest, and did **not** rebuild it. Until someone does, "the firmware
  is plain edk2" is Servury's claim.
* **Launch parameters are the host's.** vCPU count and model, guest
  features and the guest policy are chosen by Servury. All of them are in
  the measurement or in the signed report, so a change is detected, not
  prevented. The guest policy allows SMT.
* **No ID block, no `HOST_DATA`.** The firmware does not refuse a wrong
  launch on our behalf; only the verifier's `MEASUREMENT` comparison does.
  A user who does not run the verifier gets no protection from any of this.
* **The clock, the network, DNS answers and entropy outside RDRAND** come
  from the host. A wrong clock can make the guest accept an expired
  certificate chain from the ACME server or fail to get a certificate; it
  cannot change what is measured.
* **Availability and data.** Servury can stop the VM at any time, and a
  stop destroys the vault. There is no persistence, hence also no rollback
  question, in this image.
* **The WebPKI gap** of §5.2: no ACME account pinning.
* **The company.** Servury is a small, young provider (earlier research
  the same day: one person; not re-checked). Their documentation is
  unusually precise and their build is public, but there is no track
  record, no audit, and the measured-boot feature is months old. Their
  stated retention is deletion 24 hours after the term ends; with this
  image nothing of ours is on their disk in the first place.
* **Physical attacks and SNP's own weaknesses** as in
  [THREAT_MODEL.md](THREAT_MODEL.md) and [SNP.md](SNP.md) §4. The host
  operator has physical access to the machine.
