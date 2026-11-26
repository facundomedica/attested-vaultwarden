#!/usr/bin/env bash
# Sidecar <-> dstack simulator integration test.
#
# Expected: the sidecar fetches app-compose via Info and a quote via
# GetQuote; the verifier fetches real Intel collateral for the recorded quote
# (network) and FAILS on the quote signature, because the simulator patches
# report_data into a quote it cannot re-sign. That failure is the point:
# the verifier must not accept simulator evidence.
#
# Needs: the simulator image (docker build -t avw-dstack-simulator:73b10c6
# deploy/dstack/simulator) and the local registry from deploy/local/up.sh.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../.." && pwd)"
gen="$here/.generated"; mkdir -p "$gen"

REGISTRY_IMAGE="docker.io/library/registry@sha256:82f6ff4a7f982960c8aa51617fea3aabc485df6e55cce80d22deb1de36f1bc3c"
docker inspect avw-registry >/dev/null 2>&1 || docker run -d --name avw-registry -p 127.0.0.1:5001:5000 "$REGISTRY_IMAGE" >/dev/null
docker build -q -f "$root/attest-sidecar/Dockerfile" -t localhost:5001/attest-sidecar:dev "$root" >/dev/null
docker push -q localhost:5001/attest-sidecar:dev >/dev/null
digest="$(docker buildx imagetools inspect localhost:5001/attest-sidecar:dev --format '{{json .Manifest}}' | jq -r .digest)"
image="localhost:5001/attest-sidecar@${digest}"

# The app-compose the simulator serves: the real dstack deployment, rendered.
"$root/deploy/dstack/render.sh" localhost "$image" none "$gen" | tee "$gen/render.txt"
compose_hash="$(sed -n 's/^compose_hash = //p' "$gen/render.txt")"
sed "s|__ATTEST_IMAGE__|${image}|" "$here/compose.yml" > "$gen/compose.yml"

cleanup() { [ "${KEEP:-0}" = 1 ] || docker compose -f "$gen/compose.yml" down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker compose -f "$gen/compose.yml" up -d --quiet-pull

zero="$(printf '0%.0s' $(seq 1 64))"
for i in $(seq 1 60); do
  curl -skf "https://localhost:8444/.well-known/tee-attestation?nonce=${zero}" -o "$gen/doc.json" && break
  [ "$i" = 60 ] && { docker compose -f "$gen/compose.yml" logs --tail 40; exit 1; }
  sleep 1
done
docker compose -f "$gen/compose.yml" cp proxy:/data/caddy/pki/authorities/local/root.crt "$gen/root.crt" >/dev/null

echo "----- sidecar document"
jq -r '"platform=\(.platform) quote_b64_len=\(.evidence.quote|length) event_log=\(.evidence.event_log != null) images=\(.image_digests|length)"' "$gen/doc.json"
served_hash="$(jq -j .app_compose "$gen/doc.json" | shasum -a 256 | cut -d' ' -f1)"
[ "$served_hash" = "$compose_hash" ] || { echo "!!!!! served app-compose differs from rendered one"; exit 1; }
echo "served app-compose = rendered app-compose ($compose_hash)"

# Placeholder TDX policy: measurements are unknown for the simulator's
# recorded quote, and irrelevant, because evidence must fail first.
z96="$(printf '0%.0s' $(seq 1 96))"
cat > "$gen/policy-sim.toml" <<TOML
schema = 1
release = "simulator-test"
date = "$(date -u +%Y-%m-%d)"
platform = "tdx"

[tdx]
mrtd = "$z96"
rtmr0 = "$z96"
rtmr1 = "$z96"
rtmr2 = "$z96"
compose_hash = "$compose_hash"
accepted_tcb_status = ["UpToDate", "SWHardeningNeeded"]
allow_smt = true
allow_dynamic_platform = true
allow_cached_keys = true

[[images]]
service = "attest"
image = "$image"
TOML

cargo build -q --release -p attested-vw-verify --manifest-path "$root/Cargo.toml"
set +e
out="$("$root/target/release/attested-vw-verify" https://localhost:8444 --policy "$gen/policy-sim.toml" --ca "$gen/root.crt" 2>&1)"; code=$?
set -e
echo "----- verifier (exit $code, want 1)"; echo "$out"
if [ "$code" = 1 ] && grep -q "✗ Hardware evidence" <<<"$out" && grep -q "✓ TLS key bound" <<<"$out"; then
  echo "SIMULATOR E2E: expectations met (protocol works; simulator evidence rejected)"
else
  echo "SIMULATOR E2E: UNEXPECTED"; exit 1
fi
