# Local INSECURE MOCK deployment

Runs the full stack (Vaultwarden 1.37.5 + Caddy with a local CA + sidecar on
the INSECURE `Mock` provider) on your machine, so the verifier pipeline can be
exercised without TEE hardware. **Nothing here proves anything about any
server**: mock evidence is forgeable by design and the verifier never reports
PASS for it (exit code 2).

Requirements: Docker with Compose ≥ 2.23, `jq`, `curl`, `shasum`, Rust.

```bash
deploy/local/e2e.sh          # up, run the four expectations, tear down
KEEP=1 deploy/local/e2e.sh   # same, but leave the stack running
deploy/local/up.sh           # only bring it up
deploy/local/down.sh         # remove stack, relay, registry and volumes
```

Manual run after `up.sh`:

```bash
cargo run -p attested-vw-verify -- https://localhost:8443 \
  --policy deploy/local/.generated/policy-mock.toml \
  --ca deploy/local/.generated/root.crt --allow-insecure-mock
```

`e2e.sh` expectations: honest mock → exit 2 with banner; without
`--allow-insecure-mock` → exit 1; relay with a different TLS key
(`relay.yml`, port 9443) → exit 1 on the TLS key binding; policy with another
compose hash → exit 1.

Generated files live in `.generated/` (gitignored): rendered compose,
`app-compose.json`, mock policy, root CAs.
