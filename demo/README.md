# Demos

| Demo | Where | What must happen |
|------|-------|------------------|
| `deploy/local/e2e.sh` | local, INSECURE mock | honest → exit 2 (mock never PASS); relay → ✗ TLS key binding; wrong compose hash → ✗ |
| `deploy/dstack/simulator/e2e.sh` | local, dstack simulator | sidecar ↔ guest agent works; verifier ✗ on the reused quote's signature |
| `demo/live/smoke.sh <domain>` | live | Let's Encrypt cert, Vaultwarden up, `/admin` off, bad nonce rejected |
| `demo/live/bootstrap-policy.sh <url> <release>` | live | drafts `policy/<release>.toml` from observed values (labelled as such) once evidence verifies |
| `demo/live/ct-check.sh <domain> [verifier outputs…]` | CT logs (network) | every logged certificate valid for the name (incl. `*.parent` wildcards) has a key seen in a verifier PASS; else exit 1 (the demo domain fails until the Cloudflare wildcards expire, D-048, D-052) |
| `demo/relay/relay-live.sh <domain> <policy>` | your machine → live | relay with its own TLS key → ✗ TLS key binding, exit 1 |
| `[ENV_FILE=…] demo/tamper/tamper.sh --yes <cvm> <domain> <image> <policy>` | live (2 restarts; flags must match the release, logs on by default) | `SIGNUPS_ALLOWED=true` → ✗ compose hash, exit 1; restore → PASS |

Recorded live outputs (2026-11-26, Phala Cloud): `live/smoke.expected.txt`,
`live/verify.expected.txt` (release 2026.11.0), `live/verify-2026.11.1.expected.txt`,
`live/verify-2026.11.2.expected.txt` (2026-11-27),
`live/verify-2026.11.4.expected.txt` and `live/verify-2026.11.4-after-restart.expected.txt`
(2026-11-27; same release before and after a CVM restart, different TLS key),
`live/ct-check.expected.txt` (2026-11-27, exit 1: Cloudflare wildcards until 2027-01-31),
`live/caa-check-vault.facundo.dev.expected.txt` (2026-11-27, exit 1: the name's own set passes,
the parent has no CAA for wildcards),
`relay/relay-live.expected.txt`, `tamper/tamper.expected.txt`.
They are verbatim; the relay transcript was recorded by an earlier verifier
build whose measurements line read "match the published OS image" before
that had been reproduced (the current verifier says "equal the values
pinned by release …"; reproduction is in `policy/*.reproduce.txt`).
