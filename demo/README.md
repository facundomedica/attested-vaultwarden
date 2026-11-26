# Demos

| Demo | Where | What must happen |
|------|-------|------------------|
| `deploy/local/e2e.sh` | local, INSECURE mock | honest → exit 2 (mock never PASS); relay → ✗ TLS key binding; wrong compose hash → ✗ |
| `deploy/dstack/simulator/e2e.sh` | local, dstack simulator | sidecar ↔ guest agent works; verifier ✗ on the reused quote's signature |
| `demo/live/smoke.sh <domain>` | live | Let's Encrypt cert, Vaultwarden up, `/admin` off, bad nonce rejected |
| `demo/live/bootstrap-policy.sh <url> <release>` | live | drafts `policy/<release>.toml` from observed values (labelled as such) once evidence verifies |
| `demo/relay/relay-live.sh <domain> <policy>` | your machine → live | relay with its own TLS key → ✗ TLS key binding, exit 1 |
| `[ENV_FILE=…] demo/tamper/tamper.sh --yes <cvm> <domain> <image> <policy>` | live (2 restarts; flags must match the release, logs on by default) | `SIGNUPS_ALLOWED=true` → ✗ compose hash, exit 1; restore → PASS |

Recorded live outputs (2026-11-26, Phala Cloud): `live/smoke.expected.txt`,
`live/verify.expected.txt` (release 2026.11.0), `live/verify-2026.11.1.expected.txt`,
`relay/relay-live.expected.txt`, `tamper/tamper.expected.txt`.
