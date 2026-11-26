#!/usr/bin/env bash
# Black-box smoke checks of a live deployment (no credentials needed).
#   demo/live/smoke.sh vault.example.com
set -uo pipefail
d="${1:?domain}"; fails=0
ok()  { echo "  ✓ $*"; }
bad() { echo "  ✗ $*"; fails=$((fails + 1)); }

issuer="$(echo | openssl s_client -connect "$d:443" -servername "$d" 2>/dev/null | openssl x509 -noout -issuer 2>/dev/null)"
case "$issuer" in *"Let's Encrypt"*) ok "certificate issued by Let's Encrypt ($issuer)";; *) bad "unexpected issuer: ${issuer:-none}";; esac
s="$(curl -s -o /dev/null -w '%{http_code}' "https://$d/alive")"; [ "$s" = 200 ] && ok "/alive 200" || bad "/alive $s"
s="$(curl -s -o /dev/null -w '%{http_code}' "https://$d/")"; [ "$s" = 200 ] && ok "web vault 200" || bad "web vault $s"
s="$(curl -s -o /dev/null -w '%{http_code}' "https://$d/admin")"; [ "$s" != 200 ] && ok "/admin not served ($s)" || bad "/admin is reachable"
s="$(curl -s -o /dev/null -w '%{http_code}' "https://$d/.well-known/tee-attestation?nonce=xyz")"; [ "$s" = 400 ] && ok "attestation rejects bad nonce (400)" || bad "bad nonce gave $s"
v="$(curl -s "https://$d/api/config" | jq -r '.version // empty' 2>/dev/null)"; [ -n "$v" ] && ok "server reports version $v" || bad "/api/config unreadable"
echo "smoke: $fails failure(s)"; exit "$fails"
