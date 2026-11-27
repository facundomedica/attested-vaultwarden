#!/usr/bin/env bash
# Build the single Confidential Space workload image for one domain, from a
# `git archive` of one commit (never the working tree), and print its digest.
#
#   deploy/gcp-cs/build.sh <domain> [git-ref] [--check]
#
# Environment:
#   ACME_HOST     ACME directory host (default acme-v02.api.letsencrypt.org;
#                 use acme-staging-v02.api.letsencrypt.org while testing)
#   LOG_REDIRECT  tee.launch_policy.log_redirect label: debugonly (default),
#                 always (development: logs may leave the VM) or never
#
# Output: an OCI archive deploy/gcp-cs/.generated/workload.oci.tar and its
# manifest digest. That digest is what `tee-image-reference=...@sha256:` must
# name and what the release policy pins; it does not change when the image
# is pushed to a registry. With --check the build is run twice without cache
# and the two digests must be equal.
#
# Nothing here talks to Google Cloud.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
domain="${1:?usage: build.sh <domain> [git-ref] [--check]}"
ref="${2:-HEAD}"
check="${3:-}"
acme="${ACME_HOST:-acme-v02.api.letsencrypt.org}"
logs="${LOG_REDIRECT:-debugonly}"
[[ "$domain" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] || { echo "bad domain" >&2; exit 1; }
case "$logs" in debugonly|always|never) ;; *) echo "LOG_REDIRECT must be debugonly, always or never" >&2; exit 1;; esac

out="$here/.generated"
mkdir -p "$out"
ctx="$(mktemp -d)"
trap 'rm -rf "$ctx"' EXIT
git -C "$root" archive "$ref" | tar -x -C "$ctx"
epoch="$(git -C "$root" log -1 --format=%ct "$ref")"
commit="$(git -C "$root" rev-parse "$ref")"

# Same pinned BuildKit builder as attest-sidecar/reproducible-build.sh: the
# BuildKit version affects the output layout, so it is part of the recipe.
BUILDKIT_IMAGE="docker.io/moby/buildkit:v0.29.0@sha256:0039c1d47e8748b5afea56f4e85f14febaf34452bd99d9552d2daa82262b5cc5"
BUILDER=avw-repro
if ! docker buildx inspect "$BUILDER" >/dev/null 2>&1; then
  docker buildx create --name "$BUILDER" --driver docker-container \
    --driver-opt "image=$BUILDKIT_IMAGE" >/dev/null
fi

build() { # <output tar> [extra buildx args]
  local dest="$1"; shift
  docker buildx build --builder "$BUILDER" "$@" \
    --platform linux/amd64 \
    --provenance=false --sbom=false \
    --build-arg "SOURCE_DATE_EPOCH=${epoch}" \
    --build-arg "DOMAIN=${domain}" \
    --build-arg "ACME_HOST=${acme}" \
    --build-arg "LOG_REDIRECT=${logs}" \
    --output "type=oci,dest=${dest},rewrite-timestamp=true" \
    -f "$ctx/deploy/gcp-cs/Dockerfile" "$ctx" >&2
  # Manifest digest from the OCI layout's index.
  tar -xOf "$dest" index.json | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["manifests"][0]["digest"])'
}

d1="$(build "$out/workload.oci.tar")"
if [ "$check" = "--check" ]; then
  d2="$(build "$out/workload.check.oci.tar" --no-cache)"
  rm -f "$out/workload.check.oci.tar"
  [ "$d1" = "$d2" ] || { echo "NOT reproducible: $d1 vs $d2" >&2; exit 1; }
  echo "reproducible: two builds gave the same digest" >&2
fi
echo "commit:       $commit"
echo "domain:       $domain"
echo "acme:         $acme"
echo "log_redirect: $logs"
echo "image:        $out/workload.oci.tar"
echo "digest:       $d1"
