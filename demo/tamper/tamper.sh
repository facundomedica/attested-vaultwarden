#!/usr/bin/env bash
# Tamper demo on a live Phala deployment: change ONE setting, redeploy, show
# the verifier failing against the published release policy, then restore.
#
#   demo/tamper/tamper.sh --yes <cvm-id> <domain> <attest-image@sha256:..> policy/<release>.toml
#
# The change: SIGNUPS_ALLOWED "false" -> "true" (an operator quietly opening
# registrations). It changes the app-compose, hence the measured compose
# hash. This UPDATES the live CVM twice (tamper, restore): two restarts.
set -euo pipefail
[ "${1:-}" = "--yes" ] || { echo "this updates a live CVM; pass --yes as the first argument" >&2; exit 2; }
shift
cvm="${1:?cvm-id}"; d="${2:?domain}"; img="${3:?attest image}"; pol="${4:?policy}"
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/../.." && pwd)"
gen="$here/.generated"; mkdir -p "$gen"
"$root/deploy/dstack/render.sh" "$d" "$img" phala "$gen/orig" >/dev/null
mkdir -p "$gen/tampered"
sed 's/SIGNUPS_ALLOWED: "false"/SIGNUPS_ALLOWED: "true"/' "$gen/orig/docker-compose.yml" > "$gen/tampered/docker-compose.yml"
diff "$gen/orig/docker-compose.yml" "$gen/tampered/docker-compose.yml" || true
flags=(--no-pre-launch-script --no-public-logs --no-public-sysinfo --wait)
cargo build -q --release -p attested-vw-verify --manifest-path "$root/Cargo.toml"
v() { "$root/target/release/attested-vw-verify" "https://$d" --policy "$pol"; }

echo "== deploying TAMPERED compose"
phala deploy --cvm-id "$cvm" -c "$gen/tampered/docker-compose.yml" "${flags[@]}"
sleep 20
set +e; v | tee "$gen/tampered.out"; code=$?; set -e
echo "verifier exit $code (expected 1, compose hash mismatch)"

echo "== restoring ORIGINAL compose"
phala deploy --cvm-id "$cvm" -c "$gen/orig/docker-compose.yml" "${flags[@]}"
sleep 20
set +e; v | tee "$gen/restored.out"; code2=$?; set -e
echo "verifier exit $code2 after restore (expected 0)"
[ "$code" = 1 ] && grep -q "✗ Compose hash" "$gen/tampered.out"
