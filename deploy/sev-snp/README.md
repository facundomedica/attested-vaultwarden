# AMD SEV-SNP guest image (Servury Blackbox, measured direct boot)

Status: **built and boot-tested without SNP; never booted on SEV-SNP
hardware.** Research prototype, not for real secrets.

This directory builds the guest for the `measured-cmdline` binding
(DECISIONS D-055): a kernel, an initrd holding the whole system, and a
command line that carries the SHA-256 of the app-compose document, packed
as one UKI. Design, trust statement and the step-by-step runbook for a
first deployment: [../../docs/SNP_SERVURY.md](../../docs/SNP_SERVURY.md).
There is still no image for the `HOST_DATA` design of
[../../docs/SNP.md](../../docs/SNP.md) (D-050).

| File | Purpose |
|------|---------|
| `build.sh` | Reproducible build from a git commit, in Docker (`--check` builds twice and compares) |
| `Dockerfile` | The recipe: pinned inputs, assembly of the initrd and the UKI |
| `init` | PID 1 of the guest: document hash check, modules, network, three services, power off on failure |
| `manifest.template.yml` | Images and settings; becomes `docker_compose_file` of app-compose.json |
| `gen-config.py` | Renders the template into app-compose.json and the files `init` reads |
| `mkcpio.py` | Deterministic cpio writer |
| `modules.txt`, `udhcpc.script` | Kernel modules to load; DHCP event handler |
| `measure.sh` | Expected `MEASUREMENT` with `sev-snp-measure` and Servury's firmware and parameters |
| `boot-test.sh` | Boots the image in QEMU without SNP and checks the console |

```sh
deploy/sev-snp/build.sh snp.example.org --ip dhcp --public-logs --check
deploy/sev-snp/measure.sh deploy/sev-snp/.generated/snp.example.org
deploy/sev-snp/build.sh snp.example.org --public-logs --selftest --out deploy/sev-snp/.generated/selftest
deploy/sev-snp/boot-test.sh deploy/sev-snp/.generated/selftest split   # also: uki, tamper
```

The vault lives in memory: stopping the VM destroys it.
