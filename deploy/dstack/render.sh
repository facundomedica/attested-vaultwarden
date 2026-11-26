#!/usr/bin/env bash
# Render the dstack deployment for one domain and one sidecar image.
#
#   deploy/dstack/render.sh <domain> <attest-image@sha256:...> [key_provider] [out_dir]
#
# key_provider: "none" (default; disk key is random per boot, so data does
# NOT survive a CVM restart) or "local" (SGX sealing key from the host's
# local key provider; requires SGX on the host).
#
# Produces <out_dir>/docker-compose.yml and <out_dir>/app-compose.json in the
# layout dstack's vmm-cli `compose` command writes (manifest_version 2), and
# prints the compose hash that the release policy must pin.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
domain="${1:?domain}"; image="${2:?attest image pinned by digest}"
kp="${3:-none}"; out="${4:-$here/.generated}"
[[ "$image" =~ @sha256:[0-9a-f]{64}$ ]] || { echo "attest image must be pinned by @sha256" >&2; exit 1; }
[[ "$domain" =~ ^[a-z0-9.-]+$ ]] || { echo "bad domain" >&2; exit 1; }
case "$kp" in none|local) ;; *) echo "key_provider must be none or local" >&2; exit 1;; esac
mkdir -p "$out"
sed -e "s|__DOMAIN__|${domain}|g" -e "s|__ATTEST_IMAGE__|${image}|g" \
  "$here/docker-compose.template.yml" > "$out/docker-compose.yml"
python3 -I - "$out/docker-compose.yml" "$out/app-compose.json" "$kp" <<'PY'
import json, sys, hashlib
compose, outp, kp = sys.argv[1], sys.argv[2], sys.argv[3]
doc = {
    "manifest_version": 2,
    "name": "attested-vaultwarden",
    "runner": "docker-compose",
    "docker_compose_file": open(compose, "rb").read().decode("utf-8"),
    "kms_enabled": False,
    "gateway_enabled": False,
    "local_key_provider_enabled": kp == "local",
    "key_provider_id": "",
    "public_logs": False,
    "public_sysinfo": False,
    "allowed_envs": [],
    "no_instance_id": False,
    "secure_time": False,
    "key_provider": kp,
}
b = json.dumps(doc, indent=4, ensure_ascii=False).encode("utf-8")
open(outp, "wb").write(b)
print("compose_hash =", hashlib.sha256(b).hexdigest())
PY
echo "wrote $out/docker-compose.yml and $out/app-compose.json"
