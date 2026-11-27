#!/usr/bin/env bash
# Compute the expected SEV-SNP launch MEASUREMENT for a self-hosted QEMU guest
# (OVMF AmdSev build + kernel + initrd + cmdline, `kernel-hashes=on`) and the
# HOST_DATA for an app-compose document, independently of any running VM, and
# optionally compare both with a policy.
#
#   policy/measure/measure-snp.sh --ovmf OVMF.fd --kernel vmlinuz --initrd initrd.img \
#       --append "console=ttyS0 ..." --vcpus 2 --vcpu-type EPYC-Milan-v2 \
#       --compose app-compose.json [--guest-features 0x1] [--policy policy/<release>.toml]
#
# UNTESTED: written from the sev-snp-measure 0.0.13 README; this project has
# no SNP host, so this script has never produced a value that was compared
# with a real report. See docs/SNP.md.
#
# Needs virtee's sev-snp-measure (pip install sev-snp-measure==0.0.13).
# The measurement depends on EVERY input here: the exact OVMF binary, kernel,
# initrd, the command line byte for byte, the vCPU count, the vCPU model
# QEMU exposes (-cpu) and the guest SEV features. A mismatch in any of them
# gives a different digest, never a "close" one.
set -euo pipefail
ovmf=""; kernel=""; initrd=""; append=""; vcpus=""; vcpu_type=""; compose=""; policy=""; features="0x1"
while [ $# -gt 0 ]; do
  case "$1" in
    --ovmf) ovmf="$2"; shift 2;; --kernel) kernel="$2"; shift 2;;
    --initrd) initrd="$2"; shift 2;; --append) append="$2"; shift 2;;
    --vcpus) vcpus="$2"; shift 2;; --vcpu-type) vcpu_type="$2"; shift 2;;
    --compose) compose="$2"; shift 2;; --policy) policy="$2"; shift 2;;
    --guest-features) features="$2"; shift 2;;
    *) echo "unknown arg $1" >&2; exit 2;;
  esac
done
for v in ovmf kernel initrd vcpus vcpu_type compose; do
  [ -n "${!v}" ] || { echo "missing --${v//_/-}" >&2; exit 2; }
done
for f in "$ovmf" "$kernel" "$initrd" "$compose"; do
  echo "input $(shasum -a 256 "$f")"
done
measurement="$(sev-snp-measure --mode snp --vmm-type QEMU \
  --vcpus "$vcpus" --vcpu-type "$vcpu_type" --guest-features "$features" \
  --ovmf "$ovmf" --kernel "$kernel" --initrd "$initrd" --append "$append" \
  --output-format hex)"
host_data="$(shasum -a 256 "$compose" | cut -d' ' -f1)"
echo "measurement = \"$measurement\""
echo "host_data   = \"$host_data\""
# QEMU wants HOST_DATA as base64 of the 32 raw bytes.
echo "qemu: -object sev-snp-guest,...,kernel-hashes=on,host-data=$(printf '%s' "$host_data" | xxd -r -p | base64)"
if [ -n "$policy" ]; then
  fails=0
  for kv in "measurement=$measurement" "host_data=$host_data"; do
    k="${kv%%=*}"; v="${kv#*=}"
    want="$(awk -v k="$k" '/^\[sev_snp\]/{s=1;next} /^\[/{s=0} s && $1==k {gsub(/"/,"",$3); print $3}' "$policy")"
    if [ "$want" = "$v" ]; then echo "✓ $k matches $policy"; else echo "✗ $k: policy has $want" >&2; fails=1; fi
  done
  exit "$fails"
fi
