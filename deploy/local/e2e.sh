#!/usr/bin/env bash
# Local end-to-end test against the INSECURE MOCK deployment.
#
# Expectations:
#   A. honest stack, --allow-insecure-mock      -> exit 2, INSECURE MOCK banner
#   B. honest stack, no --allow-insecure-mock   -> exit 1, evidence refused
#   C. relay with a different TLS key           -> exit 1, TLS key binding fails
#   D. policy with a different compose hash     -> exit 1, compose hash fails
#
# KEEP=1 leaves the stack running afterwards.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
gen="$here/.generated"

cleanup() { [ "${KEEP:-0}" = 1 ] || "$here/down.sh"; }
trap cleanup EXIT

"$here/up.sh"
cargo build -q --release -p attested-vw-verify --manifest-path "$root/Cargo.toml"
verify="$root/target/release/attested-vw-verify"

fails=0
if curl -sf --cacert "$gen/root.crt" https://localhost:8443/alive >/dev/null; then
  echo "----- vaultwarden /alive reachable through the proxy"
else
  echo "!!!!! vaultwarden not reachable through the proxy"; exit 1
fi
expect() { # name expected_exit pattern -- cmd...
  local name="$1" want="$2" pat="$3"; shift 4
  set +e; out="$("$@" 2>&1)"; got=$?; set -e
  echo "----- $name (exit $got, want $want)"; echo "$out"
  if [ "$got" != "$want" ] || ! grep -qF -- "$pat" <<<"$out"; then
    echo "!!!!! $name: UNEXPECTED"; fails=$((fails + 1))
  fi
}

expect "A honest mock" 2 "INSECURE MOCK" -- \
  "$verify" https://localhost:8443 --policy "$gen/policy-mock.toml" --ca "$gen/root.crt" --allow-insecure-mock
expect "B mock refused" 1 "refused" -- \
  "$verify" https://localhost:8443 --policy "$gen/policy-mock.toml" --ca "$gen/root.crt"

docker compose -f "$here/relay.yml" up -d --quiet-pull
zero="$(printf '0%.0s' $(seq 1 64))"
for i in $(seq 1 60); do
  curl -skf "https://localhost:9443/.well-known/tee-attestation?nonce=${zero}" >/dev/null 2>&1 && break
  [ "$i" = 60 ] && { echo "relay did not come up" >&2; exit 1; }
  sleep 1
done
docker compose -f "$here/relay.yml" cp relay:/data/caddy/pki/authorities/local/root.crt "$gen/relay-root.crt" >/dev/null
expect "C relay" 1 "✗ TLS key bound to attestation" -- \
  "$verify" https://localhost:9443 --policy "$gen/policy-mock.toml" --ca "$gen/relay-root.crt" --allow-insecure-mock

sed -E 's/^compose_hash = ".*"/compose_hash = "'"$(printf '0%.0s' $(seq 1 64))"'"/' "$gen/policy-mock.toml" > "$gen/policy-wrong-hash.toml"
expect "D wrong compose hash" 1 "✗ Compose hash" -- \
  "$verify" https://localhost:8443 --policy "$gen/policy-wrong-hash.toml" --ca "$gen/root.crt" --allow-insecure-mock

if [ "$fails" -ne 0 ]; then echo "E2E: $fails unexpected result(s)"; exit 1; fi
echo "E2E: all expectations met"
