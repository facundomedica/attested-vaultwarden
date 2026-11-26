#!/usr/bin/env bash
# Certificate Transparency check: is every publicly logged certificate for
# the domain one whose key was seen inside the attested VM?
#
#   demo/live/ct-check.sh <domain> [verifier-output-file ...]
#
# Lists every certificate for <domain> from Cert Spotter's CT search API
# (https://sslmate.com/certspotter/api/, no account needed, rate limited)
# with its SubjectPublicKeyInfo SHA-256. The verifier binds exactly that
# value into the TDX quote, and prints it on its TLS line ("leaf SPKI
# SHA-256 <hex>"). Keys found in the given verifier outputs (default: the
# recorded PASS outputs in demo/) count as attested.
#
# A certificate whose key was never attested was issued for a key that
# nobody has seen inside the VM: issued outside the CVM (DNS/ACME control,
# THREAT_MODEL R2), or simply not verified yet. Exit 1 if there is one.
# Needs network, curl and jq. Not part of the unit tests.
set -euo pipefail
d="${1:?domain}"; shift
root="$(cd "$(dirname "$0")/../.." && pwd)"
if [ "$#" -eq 0 ]; then
  set -- "$root"/demo/live/*.expected.txt "$root"/demo/tamper/*.expected.txt
fi
attested="$(grep -h -o 'leaf SPKI SHA-256 [0-9a-f]\{64\}' "$@" 2>/dev/null | awk '{print $4}' | sort -u)"

json="$(curl -sf --max-time 60 \
  "https://api.certspotter.com/v1/issuances?domain=$d&expand=dns_names&expand=issuer")"
n="$(jq length <<<"$json")"
echo "CT: $n certificate(s) for $d (Cert Spotter); $(wc -w <<<"$attested" | tr -d ' ') attested key(s) known"
unseen=0
while IFS=$'\t' read -r nb issuer spki names; do
  if grep -qx "$spki" <<<"$attested"; then mark="✓ attested"; else mark="✗ key never attested"; unseen=$((unseen + 1)); fi
  printf '  %s  %s  %s  spki %s…  %s\n' "$mark" "$nb" "$issuer" "${spki:0:16}" "$names"
done < <(jq -r '.[] | [.not_before, .issuer.name, .pubkey_sha256, (.dns_names | join(","))] | @tsv' <<<"$json")
if [ "$unseen" -gt 0 ]; then
  echo "CT: $unseen certificate(s) for keys never seen in a verifier PASS: investigate (or verify the live server and pass its output)"
  exit 1
fi
echo "CT: every logged certificate's key was attested"
