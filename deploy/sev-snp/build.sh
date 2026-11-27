#!/usr/bin/env bash
# Build the SEV-SNP guest image for one domain from a `git archive` of one
# commit (never the working tree) and print the hashes of what was built.
#
#   deploy/sev-snp/build.sh <domain> [options]
#     --ip <cfg>         network: `dhcp` (default) or the kernel's static form
#                        <ip>::<gateway>:<netmask>:<hostname>:<device>:off[:<dns0>[:<dns1>]]
#                        (Servury's panel shows this line for the machine)
#     --public-logs      service output on the serial console (the host reads it)
#     --selftest         boot-test image: prints a self-test and powers off
#     --acme-host <h>    ACME directory host (default acme-v02.api.letsencrypt.org;
#                        acme-staging-v02.api.letsencrypt.org while testing)
#     --ref <git-ref>    commit to build (default HEAD)
#     --out <dir>        output directory (default deploy/sev-snp/.generated/<domain>)
#     --check            build a second time without cache; every output must
#                        be byte-identical
#
# Output: vmlinuz, initrd.img, cmdline.txt, attested-vw.efi (the UKI),
# app-compose.json, build-info.json, initrd.files.txt. Runs on Linux and
# macOS (Docker with linux/amd64 emulation). Nothing here talks to Servury.
#
# The domain, the IP configuration and the two flags are all measured: a
# different value of any of them gives a different MEASUREMENT.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
domain="${1:?usage: build.sh <domain> [--ip <cfg>] [--public-logs] [--selftest] [--acme-host <h>] [--ref <ref>] [--out <dir>] [--check]}"
shift
ip="dhcp"; logs="false"; selftest="0"; acme="acme-v02.api.letsencrypt.org"; ref="HEAD"; out=""; check=""
while [ $# -gt 0 ]; do
  case "$1" in
    --ip) ip="$2"; shift 2;;
    --public-logs) logs="true"; shift;;
    --selftest) selftest="1"; shift;;
    --acme-host) acme="$2"; shift 2;;
    --ref) ref="$2"; shift 2;;
    --out) out="$2"; shift 2;;
    --check) check="1"; shift;;
    *) echo "unknown argument $1" >&2; exit 2;;
  esac
done
[[ "$domain" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] || { echo "bad domain" >&2; exit 1; }
[[ "$ip" =~ ^(dhcp|[0-9a-z.:-]+)$ ]] || { echo "bad --ip" >&2; exit 1; }
out="${out:-$here/.generated/$domain}"
mkdir -p "$out"

ctx="$(mktemp -d)"
trap 'rm -rf "$ctx"' EXIT
git -C "$root" archive "$ref" | tar -x -C "$ctx"
epoch="$(git -C "$root" log -1 --format=%ct "$ref")"
commit="$(git -C "$root" rev-parse "$ref")"

# Same pinned BuildKit builder as attest-sidecar/reproducible-build.sh.
BUILDKIT_IMAGE="docker.io/moby/buildkit:v0.29.0@sha256:0039c1d47e8748b5afea56f4e85f14febaf34452bd99d9552d2daa82262b5cc5"
BUILDER=avw-repro
if ! docker buildx inspect "$BUILDER" >/dev/null 2>&1; then
  docker buildx create --name "$BUILDER" --driver docker-container \
    --driver-opt "image=$BUILDKIT_IMAGE" >/dev/null
fi

build() { # <output dir> [extra buildx args]
  local dest="$1"; shift
  rm -rf "$dest"; mkdir -p "$dest"
  docker buildx build --builder "$BUILDER" "$@" \
    --platform linux/amd64 \
    --provenance=false --sbom=false \
    --build-arg "SOURCE_DATE_EPOCH=${epoch}" \
    --build-arg "SOURCE_COMMIT=${commit}" \
    --build-arg "DOMAIN=${domain}" \
    --build-arg "ACME_HOST=${acme}" \
    --build-arg "IP_CONFIG=${ip}" \
    --build-arg "PUBLIC_LOGS=${logs}" \
    --build-arg "SELFTEST=${selftest}" \
    --target out --output "type=local,dest=${dest}" \
    -f "$ctx/deploy/sev-snp/Dockerfile" "$ctx" >&2
}
sums() { (cd "$1" && shasum -a 256 vmlinuz initrd.img attested-vw.efi app-compose.json cmdline.txt initrd.files.txt build-info.json); }

build "$out"
if [ -n "$check" ]; then
  build "$out.check" --no-cache
  if [ "$(sums "$out")" != "$(sums "$out.check")" ]; then
    echo "NOT reproducible:" >&2
    diff <(sums "$out") <(sums "$out.check") >&2 || true
    exit 1
  fi
  rm -rf "$out.check"
  echo "reproducible: two builds (the second without cache) gave identical files" >&2
fi
echo "commit:   $commit"
echo "domain:   $domain"
echo "acme:     $acme"
echo "ip:       $ip"
echo "logs:     public_logs=$logs"
echo "selftest: $selftest"
echo "output:   $out"
echo "cmdline:  $(cat "$out/cmdline.txt")"
sums "$out"
