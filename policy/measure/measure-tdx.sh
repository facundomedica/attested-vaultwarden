#!/usr/bin/env bash
# Compute expected MRTD / RTMR0-2 for a dstack OS image and VM shape with
# dstack-mr, independently of any running CVM, and compare with a policy.
#
#   policy/measure/measure-tdx.sh <dstack-X.Y.Z.tar.gz> <tarball_sha256> <os_image_hash> \
#       --cpu 1 --memory 2G --qemu-version 8.2.2 [--policy policy/<release>.toml] [-- extra dstack-mr args]
#
# The tarball sha256 and os_image_hash come from the dstack release notes
# (e.g. https://github.com/Dstack-TEE/dstack/releases/tag/mkosi-os-v0.6.5).
# Needs the dstack-mr image: docker build -t avw-dstack-mr:350a0a7 policy/measure
set -euo pipefail
tarball="${1:?image tarball}"; want_tar="${2:?tarball sha256}"; want_img="${3:?os_image_hash}"; shift 3
cpu=1; mem=2G; qemu=""; policy=""; extra=()
while [ $# -gt 0 ]; do
  case "$1" in
    --cpu) cpu="$2"; shift 2;; --memory) mem="$2"; shift 2;;
    --qemu-version) qemu="$2"; shift 2;; --policy) policy="$2"; shift 2;;
    --) shift; extra=("$@"); break;; *) echo "unknown arg $1" >&2; exit 2;;
  esac
done
got_tar="$(shasum -a 256 "$tarball" | cut -d' ' -f1)"
[ "$got_tar" = "$want_tar" ] || { echo "tarball sha256 $got_tar != release notes $want_tar" >&2; exit 1; }
echo "✓ tarball sha256 matches release notes"
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
tar -xzf "$tarball" -C "$work"
meta="$(find "$work" -maxdepth 3 -name metadata.json | head -1)"
[ -n "$meta" ] || { echo "no metadata.json in tarball" >&2; exit 1; }
dir="$(dirname "$meta")"
# os_image_hash = SHA-256 of the image's sha256sum.txt, whose lines must
# match the files (dstack verifier/src/verification.rs).
got_img="$(shasum -a 256 "$dir/sha256sum.txt" | cut -d' ' -f1)"
[ "$got_img" = "$want_img" ] || { echo "os_image_hash $got_img != $want_img" >&2; exit 1; }
(cd "$dir" && shasum -a 256 -c sha256sum.txt --quiet) || { echo "image files do not match sha256sum.txt" >&2; exit 1; }
echo "✓ os_image_hash $got_img, all files match sha256sum.txt"
args=(measure -c "$cpu" -m "$mem" --json)
[ -n "$qemu" ] && args+=(--qemu-version "$qemu")
out="$(docker run --rm --network none -v "$dir:/img:ro" avw-dstack-mr:350a0a7 "${args[@]}" ${extra[@]+"${extra[@]}"} /img/metadata.json)"
echo "$out" | jq '{mrtd, rtmr0, rtmr1, rtmr2}' | tee "$work/mr.json"
if [ -n "$policy" ]; then
  fails=0
  for k in mrtd rtmr0 rtmr1 rtmr2; do
    want="$(sed -n "s/^$k = \"\(.*\)\"/\1/p" "$policy")"; got="$(jq -r ".$k" "$work/mr.json")"
    if [ "$want" = "$got" ]; then echo "✓ $k matches $policy"; else echo "✗ $k: computed $got, policy $want"; fails=$((fails+1)); fi
  done
  exit "$fails"
fi
