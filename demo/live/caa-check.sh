#!/usr/bin/env bash
# CAA check: can only the ACME account that lives inside the attested VM
# obtain a certificate for the name?
#
#   demo/live/caa-check.sh <name> <accounturi>
#   e.g. caa-check.sh vault.warden.facundo.dev \
#          https://acme-v02.api.letsencrypt.org/acme/acct/4048885521
#
# Before issuing, a CA looks up the "relevant CAA record set" (RFC 8659 §3):
# query CAA at the name; if the answer is empty, drop the leftmost label and
# try again, up to the root. The first non-empty set governs, and only that
# one: sets further up are ignored. For a wildcard *.X the search starts at
# X, and `issuewild` properties, if the set has any, replace `issue`.
# RFC 8657 adds the `accounturi` (one ACME account) and `validationmethods`
# parameters to an issuer's property; Let's Encrypt enforces both.
#
# Why the parent. The service name is a CNAME to the hosting gateway, and a
# name that owns a CNAME can own no other data (RFC 1034 §3.6.2, RFC 2181
# §10.1), so a CAA record cannot sit at the name itself. A CAA query there
# is answered by following the CNAME: what comes back is the *target's* CAA
# set, which the gateway operator controls (none today; if one appeared, it
# would govern, and this script would show it "via CNAME"). When that is
# empty the search climbs the parents of the original name, not of the
# target. So the record goes on the parent, and governs every name below
# the parent that has no set of its own: hence a dedicated parent label
# (vault.<label>.example) rather than the zone apex.
#
# A certificate valid for <name> is one naming <name> or the wildcard
# *.<parent> (one label only). Both are checked:
#   - <name>: the governing set must have `issue` properties, every one of
#     them "letsencrypt.org" with exactly accounturi=<accounturi>;
#     validationmethods is reported (absent = any method).
#   - *.<parent>: the set governing <parent> must forbid wildcards
#     (`issuewild ";"`) or restrict them to the same account (every
#     `issuewild`, or with no `issuewild` every `issue`, as above).
# Anything else fails: no CAA anywhere (any CA may issue), another CA, the
# same CA without accounturi or with another account. Records a DNS host
# adds on its own (Cloudflare does for its certificate CAs) are seen here
# like by a CA, and fail the check.
#
# What it does not show: CAA binds honest CAs at issuance time only. Whoever
# controls the zone can change the record, and certificates issued before it
# stay valid; ct-check.sh covers both. Answers come from public resolvers
# (CAA_RESOLVERS, default "1.1.1.1 8.8.8.8"), all of which must agree, and
# are not DNSSEC-validated here.
#
# Exit: 0 only the given account can obtain a certificate valid for <name>
#       1 CAA does not guarantee that
#       2 usage, lookup failure, or resolvers disagree (no conclusion)
# Needs dig. Not part of the unit tests.
set -euo pipefail
[ "$#" -eq 2 ] || { echo "usage: $0 <name> <accounturi>" >&2; exit 2; }
name="$(printf '%s' "${1%.}" | tr '[:upper:]' '[:lower:]')"
acct="$2"
ca=letsencrypt.org
resolvers="${CAA_RESOLVERS:-1.1.1.1 8.8.8.8}"
[[ "$name" == *.* ]] || { echo "CAA: $name has no parent to carry a record" >&2; exit 2; }
parent="${name#*.}"

caa_set=""; cname=""
# CAA set at exactly one name, as seen by every resolver, into $caa_set:
# lines "<flags> <tag> <value>" (tag lowercased, value unquoted), sorted.
# $cname is the CNAME target the answer came through, if any.
caa_at() {
  local r out status set c first="" have=0
  caa_set=""; cname=""
  for r in $resolvers; do
    out="$(dig +noall +comments +answer +time=5 +tries=2 "@$r" CAA "$1." 2>&1)" || {
      echo "CAA: lookup of $1 at $r failed" >&2; return 2; }
    status="$(sed -n 's/.*status: \([A-Z]*\).*/\1/p' <<<"$out" | head -1)"
    case "$status" in
      NOERROR|NXDOMAIN) ;;
      *) echo "CAA: lookup of $1 at $r failed (${status:-no answer}); a CA must refuse to issue on a failed lookup, and this check cannot conclude" >&2; return 2 ;;
    esac
    c="$(awk '$4 == "CNAME" { t = $5 } END { sub(/\.$/, "", t); print t }' <<<"$out")"
    [ -z "$c" ] || cname="$c"   # some resolvers leave the CNAME out of an empty answer
    set="$(awk '$4 == "CAA" { v = $7; for (i = 8; i <= NF; i++) v = v " " $i
                 gsub(/^"|"$/, "", v); gsub(/" "/, "", v); gsub(/\\/, "", v)
                 print $5, tolower($6), v }' <<<"$out" | sort)"
    if [ "$have" = 1 ] && [ "$set" != "$first" ]; then
      echo "CAA: resolvers disagree about $1 (propagating change?). Seen by $r:" >&2
      printf '%s\n' "${set:-(nothing)}" | sed 's/^/  /' >&2
      echo "Seen by the resolver(s) before it:" >&2
      printf '%s\n' "${first:-(nothing)}" | sed 's/^/  /' >&2
      return 2
    fi
    first="$set"; have=1
  done
  caa_set="$first"
}

found=""; found_set=""
# RFC 8659 §3 search from $1 upwards; prints the trail, sets found/found_set.
relevant() {
  local n="$1" s
  found=""; found_set=""
  while :; do
    caa_at "$n" || exit 2
    s="$caa_set"
    if [ -n "$s" ]; then
      found="$n"; found_set="$s"
      echo "  $n: $(grep -c . <<<"$s") CAA record(s)${cname:+, via CNAME to $cname}"
      sed 's/^\([0-9]*\) \([^ ]*\) \(.*\)$/    \1 \2 "\3"/' <<<"$s"
      return 0
    fi
    echo "  $n: no CAA${cname:+ (CNAME to $cname, none there either)}"
    [[ "$n" == *.* ]] || return 0
    n="${n#*.}"
  done
}

fails=0
ok()   { echo "  ✓ $*"; }
bad()  { echo "  ✗ $*"; fails=$((fails + 1)); }
# Values of one tag in a set, one per line.
values() { awk -v t="$2" '$2 == t { sub(/^[^ ]* [^ ]* ?/, ""); print }' <<<"$1"; }
# Judge one issue/issuewild value. Prints a description, returns 0 if it is
# "$ca with exactly our account", 3 if it is the empty issuer ";".
methods=""
judge() {
  local v="$1" issuer params uris
  issuer="$(printf '%s' "${v%%;*}" | tr -d ' \t' | tr '[:upper:]' '[:lower:]')"
  params=""; [[ "$v" == *";"* ]] && params="${v#*;}"
  if [ -z "$issuer" ]; then
    [ -z "$(tr -d ' \t;' <<<"$params")" ] && return 3
    why="malformed value \"$v\""; return 1
  fi
  [ "$issuer" = "$ca" ] || { why="allows another CA: $issuer"; return 1; }
  uris="$(tr ';' '\n' <<<"$params" | sed 's/^[ \t]*//; s/[ \t]*$//' | sed -n 's/^accounturi=//p')"
  [ -n "$uris" ] || { why="allows every $ca account (no accounturi)"; return 1; }
  [ "$uris" = "$acct" ] || { why="allows another account: $(tr '\n' ' ' <<<"$uris" | sed 's/ $//')"; return 1; }
  methods="$(tr ';' '\n' <<<"$params" | sed 's/^[ \t]*//; s/[ \t]*$//' | sed -n 's/^validationmethods=//p')"
  return 0
}
# All values of tag $2 in set $1 must be our account (";" values add
# nothing and are tolerated next to one). Args: set tag what
only_account() {
  local v rc good=0 m="" before="$fails"
  while IFS= read -r v; do
    [ -n "$v" ] || continue
    rc=0; judge "$v" || rc=$?
    case "$rc" in
      0) good=$((good + 1)); m="${methods:-any (no validationmethods parameter)}" ;;
      3) ;;
      *) bad "$3: $2 \"$v\" $why" ;;
    esac
  done < <(values "$1" "$2")
  [ "$fails" -eq "$before" ] || return 0
  if [ "$good" -gt 0 ]; then
    ok "$3: $2 allows only $ca, accounturi=$acct, validationmethods=$m"
  else
    bad "$3: $2 forbids every CA (\";\"): the VM cannot renew either"
  fi
}

echo "CAA for $name (RFC 8659 search; resolvers: $resolvers)"
relevant "$name"
name_at="$found"; name_set="$found_set"
if [ -z "$name_at" ]; then
  bad "$name: no CAA record at the name or any parent: every CA may issue, for any account"
elif [ -z "$(values "$name_set" issue)" ]; then
  bad "$name: the set at $name_at has no issue property: it does not restrict issuance"
else
  echo "  governed by the set at $name_at"
  only_account "$name_set" issue "$name"
fi

echo "CAA for *.$parent (wildcard that covers $name; search starts at $parent)"
if [ "$name_at" = "$name" ] || [ -z "$name_at" ]; then
  relevant "$parent"; wild_at="$found"; wild_set="$found_set"
else
  wild_at="$name_at"; wild_set="$name_set"   # the search from <name> already passed through <parent>
  echo "  same search, same set"
fi
if [ -z "$wild_at" ]; then
  bad "*.$parent: no CAA record at $parent or any parent: every CA may issue a wildcard"
else
  echo "  governed by the set at $wild_at"
  w="$(values "$wild_set" issuewild)"
  if [ -n "$w" ] && [ -z "$(grep -v '^[ ;]*$' <<<"$w")" ]; then
    ok "*.$parent: issuewild \";\" forbids wildcard certificates from every CA"
  elif [ -n "$w" ]; then
    only_account "$wild_set" issuewild "*.$parent"
  elif [ -n "$(values "$wild_set" issue)" ]; then
    echo "  no issuewild property: issue applies to wildcards too"
    only_account "$wild_set" issue "*.$parent"
  else
    bad "*.$parent: the set at $wild_at has neither issuewild nor issue: wildcards are unrestricted"
  fi
fi

if [ "$fails" -gt 0 ]; then
  echo "CAA: FAIL: $fails problem(s): certificates valid for $name can be issued outside account $acct"
  exit 1
fi
echo "CAA: PASS: only $acct can obtain a certificate valid for $name (at issuance time, from CAs that honour RFC 8657)"
