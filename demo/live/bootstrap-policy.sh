#!/usr/bin/env bash
# Draft a release policy from a LIVE deployment.
#
#   demo/live/bootstrap-policy.sh https://vault.example.com <release> [pccs_url]
#
# Runs the verifier with a permissive placeholder policy, and only if the
# hardware evidence itself verified (Intel signature chain, collateral,
# debug off), copies the observed values into policy/<release>.toml, plus
# the served app-compose into policy/<release>.app-compose.json for review.
#
# The result pins what is running NOW. MRTD/RTMR0-2 taken this way are not
# independently reproduced, and the policy says so in its header. Review the
# app-compose before committing the policy.
set -euo pipefail
url="${1:?https://domain}"; release="${2:?release name}"
root="$(cd "$(dirname "$0")/../.." && pwd)"
out="$root/policy/$release.toml"; ac="$root/policy/$release.app-compose.json"
[ -e "$out" ] && { echo "$out exists; refusing to overwrite" >&2; exit 1; }
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
z() { printf '0%.0s' $(seq 1 "$1"); }
cat > "$work/placeholder.toml" <<TOML
schema = 1
release = "bootstrap-placeholder"
date = "1970-01-01"
platform = "tdx"
[tdx]
mrtd = "$(z 96)"
rtmr0 = "$(z 96)"
rtmr1 = "$(z 96)"
rtmr2 = "$(z 96)"
compose_hash = "$(z 64)"
accepted_tcb_status = ["UpToDate", "SWHardeningNeeded", "ConfigurationNeeded", "ConfigurationAndSWHardeningNeeded", "OutOfDate", "OutOfDateConfigurationNeeded"]
allow_smt = true
allow_dynamic_platform = true
allow_cached_keys = true
[[images]]
service = "placeholder"
image = "placeholder@sha256:$(z 64)"
TOML
cargo build -q --release -p attested-vw-verify --manifest-path "$root/Cargo.toml"
set +e
"$root/target/release/attested-vw-verify" "$url" --policy "$work/placeholder.toml" --json ${3:+--pccs-url "$3"} > "$work/report.json"
set -e
r="$work/report.json"
for id in tls fetch spki_binding nonce evidence report_data event_log; do
  ok="$(jq -r --arg id "$id" '[.checks[] | select(.id == $id) | .passed] | first // false' "$r")"
  if [ "$ok" != true ]; then
    echo "check '$id' did not pass; not drafting a policy:" >&2
    jq -r --arg id "$id" '.checks[] | select(.id == $id) | .detail' "$r" >&2
    exit 1
  fi
done
o() { jq -r ".observed.$1" "$r"; }
[ "$(o compose_hash_measured)" = "$(o compose_hash_served)" ] || { echo "served app-compose differs from measured one" >&2; exit 1; }
flag() { jq -e --arg f "$1" '.observed.pck_flags_set | index($f)' "$r" >/dev/null && echo true || echo false; }

curl -sf "$url/.well-known/tee-attestation?nonce=$(z 64)" | jq -j .app_compose > "$ac"
[ "$(shasum -a 256 "$ac" | cut -d' ' -f1)" = "$(o compose_hash_measured)" ] || { echo "fetched app-compose does not hash to the measured value" >&2; exit 1; }

{
  echo "# Release policy drafted $(date -u +%Y-%m-%dT%H:%MZ) by demo/live/bootstrap-policy.sh from $url."
  echo "# MRTD/RTMR0-2 were OBSERVED from the live quote, NOT independently reproduced"
  echo "# with dstack-mr: this release does not support claim C2 (published OS image)."
  echo "# TCB status / advisories at drafting time: $(o tcb_status) $(jq -r '.observed.advisory_ids | join(" ")' "$r")"
  echo "# Reviewed app-compose: policy/$release.app-compose.json"
  echo "schema = 1"
  echo "release = \"$release\""
  echo "date = \"$(date -u +%Y-%m-%d)\""
  echo "platform = \"tdx\""
  # Config: the exact pre-launch script and encrypted env NAMES in use.
  if [ "$(o pre_launch_script_sha256)" != null ]; then
    echo "pre_launch_script_sha256 = \"$(o pre_launch_script_sha256)\""
  fi
  echo "allowed_envs = $(jq -c '.observed.allowed_envs' "$r")"
  echo
  echo "[tdx]"
  echo "mrtd = \"$(o mrtd)\""
  echo "rtmr0 = \"$(o rtmr0)\""
  echo "rtmr1 = \"$(o rtmr1)\""
  echo "rtmr2 = \"$(o rtmr2)\""
  echo "compose_hash = \"$(o compose_hash_measured)\""
  echo "accepted_tcb_status = [\"$(o tcb_status)\"]"
  echo "allow_smt = $(flag smt)"
  echo "allow_dynamic_platform = $(flag dynamic_platform)"
  echo "allow_cached_keys = $(flag cached_keys)"
  echo "key_provider = $(jq '.observed.key_provider' "$r")"
  jq -r '.observed.images[] | "\n[[images]]\nservice = \"\(.[0])\"\nimage = \"\(.[1])\""' "$r"
} > "$out"
echo "wrote $out and $ac"
echo "next: review both, then: attested-vw-verify $url --policy $out"
