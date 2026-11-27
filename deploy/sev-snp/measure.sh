#!/usr/bin/env bash
# Expected SEV-SNP launch MEASUREMENT of an image built by build.sh, for
# Servury Blackbox measured boot, computed offline with virtee's
# sev-snp-measure. Nothing here talks to a VM.
#
#   deploy/sev-snp/measure.sh <build output dir> [--vcpus "1 2"] [--ovmf <file>] [--policy <toml>]
#
# Launch parameters are Servury's published ones (RELEASE.json of their
# release 2026.11.3, `measurement_parameters`, read 2026-11-27):
#   firmware        OVMF.amdsev.fd, SHA-256 8731846c… (the same file in all
#                   five releases they list), downloaded from servury.com
#                   unless --ovmf is given, and checked against that hash
#   vcpu type       EPYC-v4
#   guest features  0x1
#   vmm             QEMU, kernel-hashes=on
#
# Two shapes are printed for each vCPU count, because Servury accepts both:
#   uki    kernel = attested-vw.efi, no initrd, empty command line
#   split  kernel = vmlinuz, initrd = initrd.img, command line = cmdline.txt
#
# NEVER COMPARED WITH A REAL REPORT. The arithmetic is sev-snp-measure's; that
# Servury's hosts launch with exactly these parameters is their documentation,
# not something this project has observed. The digest depends on every input
# byte, on the vCPU count and on the vCPU model: a mismatch in any of them
# gives a different digest, never a "close" one.
#
# With --policy: exit 1 unless the policy's sev_snp.measurement is one of the
# printed values and sev_snp.compose_hash is SHA-256(app-compose.json).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
dir="${1:?usage: measure.sh <build output dir> [--vcpus \"1 2\"] [--ovmf <file>] [--policy <toml>]}"
shift
vcpus="1 2"; ovmf=""; policy=""
while [ $# -gt 0 ]; do
  case "$1" in
    --vcpus) vcpus="$2"; shift 2;;
    --ovmf) ovmf="$2"; shift 2;;
    --policy) policy="$2"; shift 2;;
    *) echo "unknown argument $1" >&2; exit 2;;
  esac
done
dir="$(cd "$dir" && pwd)"
for f in vmlinuz initrd.img cmdline.txt attested-vw.efi app-compose.json; do
  [ -f "$dir/$f" ] || { echo "$dir/$f is missing (run build.sh)" >&2; exit 1; }
done

OVMF_URL="https://servury.com/downloads/blackbox/2026.11.3/OVMF.amdsev.fd"
OVMF_SHA256="8731846cdbcbb6aa5c624238b839544b1553f4c5af874450f043321b3ef8958b"
if [ -z "$ovmf" ]; then
  ovmf="$here/.generated/ovmf/OVMF.amdsev.fd"
  if [ ! -f "$ovmf" ]; then
    mkdir -p "$(dirname "$ovmf")"
    curl -fsSL -o "$ovmf.part" "$OVMF_URL"
    mv "$ovmf.part" "$ovmf"
  fi
fi
got="$(shasum -a 256 "$ovmf" | cut -d' ' -f1)"
[ "$got" = "$OVMF_SHA256" ] || { echo "$ovmf has SHA-256 $got, expected $OVMF_SHA256" >&2; exit 1; }
ovmf="$(cd "$(dirname "$ovmf")" && pwd)/$(basename "$ovmf")"

# sev-snp-measure 0.0.13, wheel pinned by hash; its one dependency by version.
PY_IMAGE="docker.io/library/python:3.13-slim-bookworm@sha256:f0fa218d5b06f9b9235024fa061cde2cb141f726de52134471053d2d9b5324a3"
SSM_REQ="sev-snp-measure==0.0.13 --hash=sha256:feda1aebe69dcbf38e9c636ed1d082bb7dc741fc6969f197d39faddb72b2762d"
measure='
set -eu
pip install -q --root-user-action=ignore --disable-pip-version-check cryptography==50.0.2 >&2
echo "$SSM_REQ" > /tmp/req.txt
pip install -q --root-user-action=ignore --disable-pip-version-check --no-deps --require-hashes -r /tmp/req.txt >&2
common="--mode snp --vmm-type QEMU --vcpu-type EPYC-v4 --guest-features 0x1 --ovmf /ovmf/OVMF.amdsev.fd --output-format hex"
for n in $VCPUS; do
  echo "uki   vcpus=$n $(sev-snp-measure $common --vcpus "$n" --kernel /in/attested-vw.efi --append "")"
  echo "split vcpus=$n $(sev-snp-measure $common --vcpus "$n" --kernel /in/vmlinuz --initrd /in/initrd.img --append "$(cat /in/cmdline.txt)")"
done
'
echo "inputs:"
echo "  OVMF.amdsev.fd   $OVMF_SHA256"
(cd "$dir" && shasum -a 256 attested-vw.efi vmlinuz initrd.img app-compose.json | sed 's/^\([0-9a-f]*\)  \(.*\)$/  \2  \1/')
echo "  cmdline          $(cat "$dir/cmdline.txt")"
echo "parameters: vcpu-type EPYC-v4, guest-features 0x1, vmm QEMU"
result="$(docker run --rm --network=bridge -e "VCPUS=$vcpus" -e "SSM_REQ=$SSM_REQ" \
  -v "$dir:/in:ro" -v "$(dirname "$ovmf"):/ovmf:ro" "$PY_IMAGE" sh -c "$measure")"
compose_hash="$(shasum -a 256 "$dir/app-compose.json" | cut -d' ' -f1)"
echo "measurements (sev_snp.measurement):"
echo "$result" | sed 's/^/  /'
echo "compose_hash (sev_snp.compose_hash) = \"$compose_hash\""

if [ -n "$policy" ]; then
  get() { awk -v k="$1" '/^\[sev_snp\]/{s=1;next} /^\[/{s=0} s && $1==k {gsub(/"/,"",$3); print $3}' "$policy"; }
  fails=0
  m="$(get measurement)"
  if echo "$result" | grep -q " $m\$"; then
    echo "✓ policy measurement is: $(echo "$result" | grep " $m\$" | sed 's/ [0-9a-f]*$//' | tr -s ' ')"
  else
    echo "✗ policy measurement $m is none of the values above" >&2; fails=1
  fi
  if [ "$(get compose_hash)" = "$compose_hash" ]; then
    echo "✓ policy compose_hash is SHA-256(app-compose.json)"
  else
    echo "✗ policy compose_hash is $(get compose_hash)" >&2; fails=1
  fi
  exit "$fails"
fi
