#!/bin/bash
# PID 1 of the Confidential Space workload container: starts Vaultwarden,
# Caddy and the attestation sidecar, and exits as soon as ANY of them exits.
# The launcher (tee-restart-policy=Always) then reboots the whole VM about
# two minutes later (observed live; it does not restart the container in
# place), so the three never run as a partial set.
#
# Deliberately tiny and free of logic: it is part of what users trust.
# __DOMAIN__ and __ACME_HOST__ are filled in at image build time; nothing is
# read from operator-controlled environment (every variable is set here).
set -euo pipefail

# Start from an empty environment: only what is written below reaches the
# three processes, whatever the launcher or image defaults put in ours.
if [ -z "${AVW_CLEAN_ENV:-}" ]; then
  exec env -i AVW_CLEAN_ENV=1 PATH=/usr/local/bin:/usr/bin:/bin "$0"
fi

DOMAIN="__DOMAIN__"
ACME_HOST="__ACME_HOST__"

mkdir -p /data /caddy-data /caddy-config

# --- Vaultwarden: same settings as deploy/dstack/docker-compose.template.yml,
# plus I_REALLY_WANT_VOLATILE_STORAGE: Vaultwarden refuses to start without
# a persistent volume, and Confidential Space has none. THE VAULT IS LOST ON
# EVERY VM RESTART (docs/GCP_CONFIDENTIAL_SPACE.md, "Storage").
env -i PATH="$PATH" \
  DOMAIN="https://${DOMAIN}" \
  ROCKET_ADDRESS=127.0.0.1 ROCKET_PORT=8080 \
  DATA_FOLDER=/data I_REALLY_WANT_VOLATILE_STORAGE=true \
  SIGNUPS_ALLOWED=false INVITATIONS_ALLOWED=true \
  DISABLE_ICON_DOWNLOAD=true ICON_CACHE_TTL=0 ICON_SERVICE=internal \
  PUSH_ENABLED=false SSO_ENABLED=false \
  PASSWORD_HINTS_ALLOWED=false SHOW_PASSWORD_HINT=false \
  ORG_CREATION_USERS=none \
  IP_HEADER=X-Forwarded-For LOG_LEVEL=warn \
  /vaultwarden &

# --- Caddy: TLS terminates here; the key is generated in this VM's memory
# and the certificate is obtained with TLS-ALPN-01 on port 443.
env -i PATH="$PATH" HOME=/root \
  XDG_DATA_HOME=/caddy-data XDG_CONFIG_HOME=/caddy-config \
  caddy run --config /etc/caddy/Caddyfile --adapter caddyfile &

# --- Attestation sidecar: asks the launcher for a Google-signed token whose
# eat_nonce binds the verifier's nonce and the SPKI of Caddy's certificate.
# Rates kept under Google Cloud Attestation's 5 requests/second quota: 2 per
# client address, 4 for all clients together.
env -i PATH="$PATH" \
  ATTEST_PLATFORM=gcp-cs \
  ATTEST_LISTEN=127.0.0.1:8081 \
  ATTEST_RATE_PER_SEC=2 \
  ATTEST_GLOBAL_RATE_PER_SEC=4 \
  ATTEST_CERT_PATH="/caddy-data/caddy/certificates/${ACME_HOST}-directory/${DOMAIN}/${DOMAIN}.crt" \
  attest-sidecar &

# On TERM/INT: stop the children. The trap is cleared first, because
# `kill 0` also signals this shell.
trap 'trap - TERM INT; kill 0; exit 143' TERM INT
# First child to exit takes the container down with it.
status=0
wait -n || status=$?
echo "supervisor: a service exited (status ${status}); stopping the container" >&2
trap - TERM INT
kill 0 2>/dev/null || true
exit 1
