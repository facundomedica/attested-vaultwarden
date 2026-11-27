#!/usr/bin/env bash
# Certificate Transparency check: is every publicly logged, still valid
# certificate for the domain one whose key was seen inside the attested VM?
#
#   demo/live/ct-check.sh <domain> [verifier-output-file ...]
#
# Lists every unexpired certificate valid for <domain> (exact name or a
# covering *.parent wildcard) with its SubjectPublicKeyInfo SHA-256. The
# verifier binds exactly that value into the TDX quote, and prints it on its
# TLS line ("leaf SPKI SHA-256 <hex>"). Keys found in the given verifier
# outputs (default: the recorded PASS outputs in demo/) count as attested.
#
# A certificate whose key was never attested was issued for a key that
# nobody has seen inside the VM: issued outside the CVM (DNS/ACME control,
# THREAT_MODEL R2), or simply not verified yet.
#
# Sources
#   1. Cert Spotter (https://sslmate.com/certspotter/api/), primary. No
#      account needed, but rate limited per client IP: the API answers with
#      "x-ratelimit-limit: 100" (single-hostname queries per hour at the
#      time of writing; SSLMate may change it) and HTTP 429 + Retry-After
#      beyond that. One run costs 2 queries per name queried (results are
#      paginated; the last page is the empty one), so 4 for a subdomain.
#      If Cert Spotter cannot be read the check stops with exit 2: there is
#      nothing to conclude.
#   2. crt.sh (https://crt.sh/?q=<name>&output=json), second opinion. It
#      often answers 502 and lags the logs by hours to days. It is retried
#      (CT_CRTSH_TRIES, default 3); if it still fails, the check goes on
#      with Cert Spotter alone and says so in a WARNING line and in the last
#      line. Set CT_REQUIRE_CRTSH=1 to turn that into exit 3.
#
# Comparing the two. crt.sh's JSON has no key hash, and lists the
# precertificate and the final certificate as two entries. Entries are
# merged by (issuer, serial number), which a CA must keep unique; each
# merged entry is downloaded (https://crt.sh/?d=<id>) and its SPKI SHA-256
# computed locally with openssl. An issuance is then identified in both
# sources by (SPKI SHA-256, notBefore): both are fixed in the
# precertificate, so the pair is the same for a precertificate and its
# certificate, and it is the key hash, not a serial, that decides
# "attested". A crt.sh certificate missing from Cert Spotter is judged like
# any other (an unattested key there counts for exit 1). One that only Cert
# Spotter has is listed for information: expected while crt.sh lags.
#
# Expired certificates (not_after in the past) are dropped and counted: no
# client accepts them. Revoked ones are kept and marked, because clients
# check revocation unreliably.
#
# Exit: 0 every valid certificate's key was attested
#       1 some valid certificate's key was never attested
#       2 Cert Spotter unavailable (rate limit, network): no result
#       3 crt.sh unavailable and CT_REQUIRE_CRTSH=1
# Needs network, curl and jq; openssl for the crt.sh comparison. Not part of
# the unit tests.
set -euo pipefail
d="${1:?domain}"; shift
d="$(printf '%s' "${d%.}" | tr '[:upper:]' '[:lower:]')"
root="$(cd "$(dirname "$0")/../.." && pwd)"
if [ "$#" -eq 0 ]; then
  set -- "$root"/demo/live/*.expected.txt "$root"/demo/tamper/*.expected.txt
fi
attested="$(grep -h -o 'leaf SPKI SHA-256 [0-9a-f]\{64\}' "$@" 2>/dev/null | awk '{print $4}' | sort -u || true)"

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
now="$(date -u +%Y-%m-%dT%H:%M:%S)"   # compared as text with the first 19 chars of RFC 3339 UTC times
parent="${d#*.}"
wild=""
if [ "$parent" != "$d" ] && [[ "$parent" == *.* ]]; then wild="*.$parent"; fi

# ---- Cert Spotter -----------------------------------------------------------
api=https://api.certspotter.com/v1/issuances
# All pages of issuances for one name, as one JSON array on stdout.
cs_all() {
  local name="$1" after="" page code n=0
  : >"$tmp/cs.pages"
  while :; do
    n=$((n + 1))
    [ "$n" -le 50 ] || { echo "CT: Cert Spotter: more than 50 pages for $name, giving up" >&2; return 2; }
    code="$(curl -s --max-time 60 -D "$tmp/cs.hdr" -o "$tmp/cs.page" -w '%{http_code}' \
      "$api?domain=$name&expand=dns_names&expand=issuer${after:+&after=$after}" || true)"
    if [ "$code" = 429 ]; then
      echo "CT: Cert Spotter rate limit reached (HTTP 429, retry after $(awk 'tolower($1)=="retry-after:"{print $2}' "$tmp/cs.hdr" | tr -d '\r')s). No result." >&2
      return 2
    fi
    if [ "$code" != 200 ] || ! jq -e 'type == "array"' "$tmp/cs.page" >/dev/null 2>&1; then
      echo "CT: Cert Spotter query for $name failed (HTTP ${code:-none}). No result." >&2
      return 2
    fi
    [ "$(jq length "$tmp/cs.page")" -gt 0 ] || break
    cat "$tmp/cs.page" >>"$tmp/cs.pages"
    after="$(jq -r '.[-1].id' "$tmp/cs.page")"
  done
  jq -s 'add // []' "$tmp/cs.pages"
}
# Certificates naming <domain> itself, plus wildcard certificates for its
# parent (*.parent covers <domain>), which the exact-domain query omits.
cs_all "$d" >"$tmp/cs.exact" || exit 2
if [ -n "$wild" ]; then
  cs_all "$parent" >"$tmp/cs.parent" || exit 2
  jq --arg w "$wild" '[.[] | select(.dns_names | index($w))]' "$tmp/cs.parent" >"$tmp/cs.wild"
else
  echo '[]' >"$tmp/cs.wild"
fi
jq -s 'add | unique_by(.id) | sort_by(.not_before)' "$tmp/cs.exact" "$tmp/cs.wild" >"$tmp/cs.all"
jq --arg now "$now" '[.[] | select(.not_after[0:19] > $now)]' "$tmp/cs.all" >"$tmp/cs.valid"
n="$(jq length "$tmp/cs.valid")"
expired=$(( $(jq length "$tmp/cs.all") - n ))

echo "CT: $n certificate(s) for $d (Cert Spotter); $(wc -w <<<"$attested" | tr -d ' ') attested key(s) known; $expired expired dropped"
unseen=0
# One row; counts keys never attested. Args: not_before issuer spki names note
row() {
  local mark
  if grep -qx "$3" <<<"$attested"; then mark="✓ attested"; else mark="✗ key never attested"; unseen=$((unseen + 1)); fi
  printf '  %s  %s  %s  spki %s…  %s%s\n' "$mark" "$1" "$2" "${3:0:16}" "$4" "$5"
}
: >"$tmp/cs.keys"
while IFS=$'\t' read -r nb issuer spki names revoked; do
  note=""; [ "$revoked" = true ] && note="  (revoked)"
  row "$nb" "$issuer" "$spki" "$names" "$note"
  echo "$spki ${nb:0:19}" >>"$tmp/cs.keys"
done < <(jq -r '.[] | [.not_before, .issuer.name, .pubkey_sha256, (.dns_names | join(",")), (.revoked // false)] | @tsv' "$tmp/cs.valid")

# ---- crt.sh -----------------------------------------------------------------
tries="${CT_CRTSH_TRIES:-3}"
# GET with retries (crt.sh answers 502/503 under load). Body in $2.
crt_get() {
  local i=0 code
  while [ "$i" -lt "$tries" ]; do
    i=$((i + 1))
    code="$(curl -s --max-time 30 -o "$2" -w '%{http_code}' "$1" || true)"
    [ "$code" = 200 ] && return 0
    [ "$i" -lt "$tries" ] && sleep $((i * 4))
  done
  crt_err="HTTP ${code:-none} after $tries tries"
  return 1
}
crt_ok=1; crt_err=""
if ! command -v openssl >/dev/null 2>&1; then
  crt_ok=0; crt_err="openssl not found (needed to hash the certificates' keys)"
fi
: >"$tmp/crt.json.all"
if [ "$crt_ok" = 1 ]; then
  for name in "$d" ${wild:+"$wild"}; do
    q="${name/\*/%2A}"
    if crt_get "https://crt.sh/?q=$q&output=json&exclude=expired" "$tmp/crt.page" \
      && jq -e 'type == "array"' "$tmp/crt.page" >/dev/null 2>&1; then
      cat "$tmp/crt.page" >>"$tmp/crt.json.all"
    else
      crt_ok=0; crt_err="query for $name: ${crt_err:-not a JSON list}"; break
    fi
  done
fi
crt_only=0; cs_only=0; crt_n=0
if [ "$crt_ok" = 1 ]; then
  # Unexpired entries that really name <domain> or the wildcard, with the
  # precertificate and the certificate merged by (issuer, serial).
  jq -s --arg now "$now" --arg d "$d" --arg w "$wild" '
    add // []
    | map(select(.not_after[0:19] > $now))
    | map(select((.name_value | ascii_downcase | split("\n")) as $n | ($n | index($d)) or ($w != "" and ($n | index($w)))))
    | group_by([.issuer_name, .serial_number])
    | map({id: (map(.id) | min), issuer: .[0].issuer_name, not_before: .[0].not_before,
           names: (map(.name_value | split("\n")) | add | unique | join(","))})
    | sort_by(.not_before)' "$tmp/crt.json.all" >"$tmp/crt.merged"
  crt_n="$(jq length "$tmp/crt.merged")"
  : >"$tmp/crt.rows"; : >"$tmp/crt.keys"
  while IFS=$'\t' read -r id nb issuer names; do
    spki=""
    if crt_get "https://crt.sh/?d=$id" "$tmp/crt.pem"; then
      spki="$(openssl x509 -in "$tmp/crt.pem" -pubkey -noout 2>/dev/null \
        | openssl pkey -pubin -outform der 2>/dev/null | openssl dgst -sha256 2>/dev/null | awk '{print $NF}')" || spki=""
    fi
    if ! [[ "$spki" =~ ^[0-9a-f]{64}$ ]]; then
      crt_ok=0; crt_err="certificate $id could not be fetched or parsed (${crt_err:-bad certificate})"; break
    fi
    echo "$spki ${nb:0:19}" >>"$tmp/crt.keys"
    printf '%s\t%s\t%s\t%s\t%s\n' "${nb:0:19}Z" "$issuer" "$spki" "$names" "$id" >>"$tmp/crt.rows"
  done < <(jq -r '.[] | [.id, .not_before, .issuer, .names] | @tsv' "$tmp/crt.merged")
fi
if [ "$crt_ok" = 1 ]; then
  crt_only="$(grep -Fvxc -f "$tmp/cs.keys" "$tmp/crt.keys" || true)"
  [ -s "$tmp/cs.keys" ] || crt_only="$(wc -l <"$tmp/crt.keys" | tr -d ' ')"
  cs_only="$(grep -Fvxc -f "$tmp/crt.keys" "$tmp/cs.keys" || true)"
  [ -s "$tmp/crt.keys" ] || cs_only="$(wc -l <"$tmp/cs.keys" | tr -d ' ')"
  echo "CT: crt.sh has $crt_n certificate(s) (precertificates merged); $crt_only not in Cert Spotter, $cs_only in Cert Spotter only"
  while IFS=$'\t' read -r nb issuer spki names id; do
    grep -Fqx "$spki ${nb:0:19}" "$tmp/cs.keys" || row "$nb" "$issuer" "$spki" "$names" "  (crt.sh id $id only)"
  done <"$tmp/crt.rows"
  while read -r spki nb; do
    grep -Fqx "$spki $nb" "$tmp/crt.keys" || printf '  · Cert Spotter only (crt.sh lags or is incomplete)  %sZ  spki %s…\n' "$nb" "${spki:0:16}"
  done <"$tmp/cs.keys"
  sources="Cert Spotter and crt.sh"
else
  echo "CT: WARNING: crt.sh unavailable ($crt_err): no second source, result rests on Cert Spotter alone"
  sources="Cert Spotter only, crt.sh unavailable"
fi

if [ "$unseen" -gt 0 ]; then
  echo "CT: $unseen certificate(s) for keys never seen in a verifier PASS: investigate (or verify the live server and pass its output)"
  exit 1
fi
if [ "$crt_ok" != 1 ] && [ "${CT_REQUIRE_CRTSH:-0}" = 1 ]; then
  echo "CT: no unattested key in Cert Spotter, but crt.sh is required (CT_REQUIRE_CRTSH=1) and unavailable"
  exit 3
fi
if [ $((n + crt_only)) -eq 0 ]; then
  echo "CT: no unexpired certificate logged for $d: nothing to check ($sources)"
  exit 0
fi
echo "CT: every logged certificate's key was attested ($sources)"
