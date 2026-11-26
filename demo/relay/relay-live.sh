#!/usr/bin/env bash
# Relay demo against a live deployment (runs only on this machine).
#   demo/relay/relay-live.sh vault.example.com policy/<release>.toml
set -euo pipefail
d="${1:?domain}"; pol="${2:?policy}"
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/../.." && pwd)"
export UPSTREAM="$d"
trap 'docker compose -f "$here/relay-live.yml" down -v >/dev/null 2>&1' EXIT
docker compose -f "$here/relay-live.yml" up -d --quiet-pull
for i in $(seq 1 30); do curl -skf "https://localhost:9443/alive" >/dev/null && break; sleep 1; done
docker compose -f "$here/relay-live.yml" cp relay:/data/caddy/pki/authorities/local/root.crt "$here/.relay-root.crt" >/dev/null
cargo build -q --release -p attested-vw-verify --manifest-path "$root/Cargo.toml"
set +e
"$root/target/release/attested-vw-verify" https://localhost:9443 --policy "$pol" --ca "$here/.relay-root.crt"; code=$?
set -e
rm -f "$here/.relay-root.crt"
echo "verifier exit $code (expected 1: TLS key binding must fail)"
[ "$code" = 1 ]
