#!/usr/bin/env bash
# Build the sidecar image reproducibly from a git commit and print its
# OCI manifest digest (PLATFORM, default linux/amd64). With --check, build twice from scratch and fail if the
# digests differ.
#
#   attest-sidecar/reproducible-build.sh [--check] [commit]   (default HEAD)
#
# Anyone can run this on a release tag and compare the printed digest with
# the `attest` image digest pinned in the release's compose / policy.
set -euo pipefail
check=0
if [ "${1:-}" = "--check" ]; then check=1; shift; fi
root="$(cd "$(dirname "$0")/.." && pwd)"
commit="$(git -C "$root" rev-parse "${1:-HEAD}")"
epoch="$(git -C "$root" log -1 --format=%ct "$commit")"
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT

# Dedicated BuildKit builder, pinned, so the BuildKit version (which affects
# the output layout) is part of the recipe. The default "docker" driver
# cannot export OCI archives.
BUILDKIT_IMAGE="docker.io/moby/buildkit:v0.29.0@sha256:0039c1d47e8748b5afea56f4e85f14febaf34452bd99d9552d2daa82262b5cc5"
BUILDER=avw-repro
if ! docker buildx inspect "$BUILDER" >/dev/null 2>&1; then
  docker buildx create --name "$BUILDER" --driver docker-container \
    --driver-opt "image=$BUILDKIT_IMAGE" >/dev/null
fi

build_once() { # $1 = output tar
  local ctx="$work/ctx"; rm -rf "$ctx"; mkdir -p "$ctx"
  git -C "$root" archive "$commit" | tar -x -C "$ctx"
  docker buildx build --builder "$BUILDER" --no-cache --quiet \
    --platform "${PLATFORM:-linux/amd64}" \
    --build-arg SOURCE_DATE_EPOCH="$epoch" \
    --provenance=false --sbom=false \
    --output "type=oci,dest=$1,rewrite-timestamp=true" \
    -f "$ctx/attest-sidecar/Dockerfile" "$ctx" >/dev/null
  # Digest of the image manifest referenced by the OCI index.
  local d
  d="$(tar -xOf "$1" index.json | jq -r '.manifests[0].digest')"
  [[ "$d" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "could not read image digest" >&2; return 1; }
  echo "$d"
}

d1="$(build_once "$work/a.tar")" || exit 1
echo "commit $commit (SOURCE_DATE_EPOCH=$epoch)"
echo "sidecar image digest: $d1"
if [ "$check" = 1 ]; then
  d2="$(build_once "$work/b.tar")" || exit 1
  echo "second build digest:  $d2"
  if [ "$d1" != "$d2" ]; then echo "NOT REPRODUCIBLE" >&2; exit 1; fi
  echo "reproducible: yes"
fi
