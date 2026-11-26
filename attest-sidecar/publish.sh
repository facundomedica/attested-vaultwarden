#!/usr/bin/env bash
# Build the sidecar reproducibly for linux/amd64 and push it, then print the
# digest to pin in the compose and the release policy.
#
#   docker login ghcr.io            # once, with a token that has write:packages
#   attest-sidecar/publish.sh ghcr.io/<owner>/attest-sidecar [commit]
#
# The pushed image is built exactly like reproducible-build.sh does, so anyone
# can rebuild the same commit and compare digests:
#   attest-sidecar/reproducible-build.sh <commit>
#
# GHCR packages are private by default: make the package public in GitHub
# (Package settings -> Change visibility) so Phala can pull it.
set -euo pipefail
repo="${1:?image repository, e.g. ghcr.io/<owner>/attest-sidecar}"
root="$(cd "$(dirname "$0")/.." && pwd)"
commit="$(git -C "$root" rev-parse "${2:-HEAD}")"
if [ -n "$(git -C "$root" status --porcelain)" ] && [ -z "${2:-}" ]; then
  echo "note: working tree is dirty; building committed $commit only" >&2
fi
epoch="$(git -C "$root" log -1 --format=%ct "$commit")"
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT

BUILDKIT_IMAGE="docker.io/moby/buildkit:v0.29.0@sha256:0039c1d47e8748b5afea56f4e85f14febaf34452bd99d9552d2daa82262b5cc5"
BUILDER=avw-repro
docker buildx inspect "$BUILDER" >/dev/null 2>&1 || \
  docker buildx create --name "$BUILDER" --driver docker-container --driver-opt "image=$BUILDKIT_IMAGE" >/dev/null

git -C "$root" archive "$commit" | tar -x -C "$work"
tag="${repo}:git-${commit:0:12}"
docker buildx build --builder "$BUILDER" --no-cache \
  --platform linux/amd64 \
  --build-arg SOURCE_DATE_EPOCH="$epoch" \
  --provenance=false --sbom=false \
  --metadata-file "$work/meta.json" \
  --output "type=image,name=${tag},push=true,rewrite-timestamp=true" \
  -f "$work/attest-sidecar/Dockerfile" "$work"
digest="$(jq -r '."containerimage.digest"' "$work/meta.json")"
[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "push did not report a digest" >&2; exit 1; }
echo
echo "pushed:  $tag"
echo "pin as:  ${repo}@${digest}"
echo "commit:  $commit (SOURCE_DATE_EPOCH=$epoch)"
