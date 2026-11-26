#!/usr/bin/env bash
# Tear down the local mock deployment, the relay and the local registry,
# including their volumes.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
docker compose -f "$here/relay.yml" down -v 2>/dev/null || true
[ -f "$here/.generated/docker-compose.yml" ] && docker compose -f "$here/.generated/docker-compose.yml" down -v || true
docker rm -f avw-registry >/dev/null 2>&1 || true
