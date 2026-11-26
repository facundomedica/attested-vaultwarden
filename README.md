# Attested Vaultwarden

> **Status: research prototype, milestone M0 (scaffold).** Nothing here is
> production-ready. Do not store real passwords in a deployment of this
> project. The threat model in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
> says exactly what is and is not protected.

Attested Vaultwarden runs **unmodified upstream
[Vaultwarden](https://github.com/dani-garcia/vaultwarden)** (a
Bitwarden-compatible password manager server) inside a confidential VM
(Intel TDX via [dstack](https://github.com/dstack-TEE/dstack); AMD SEV-SNP as
a stretch target) and lets anyone check, from their own machine, that:

1. the server runs on genuine TEE hardware (Intel/AMD-signed evidence, debug
   off, TCB up to date);
2. it runs exactly the published software: a pinned Vaultwarden image digest,
   a pinned compose file and a pinned OS image;
3. the TLS endpoint you are talking to terminates inside that same TEE, so a
   genuine TEE's attestation cannot be relayed in front of some other server.

## Why

Scarlata, Torrisi, Backendal and Paterson, *Zero Knowledge (About)
Encryption* (USENIX Security 2026, <https://eprint.iacr.org/2026/058>),
present 12 attacks against Bitwarden by a **malicious server**. Vaultwarden
speaks the same protocol to the same clients, so the same attacks apply to a
Vaultwarden operator who decides to deviate.

A TEE plus remote attestation changes the question from "what could this
server do?" to "what does the published code do?". It does **not** fix bugs
or protocol weaknesses in the published code, and it does **not** make the
official Bitwarden apps check anything. What it removes is the operator's
ability to run *different* code without that being detectable by anyone who
runs the verifier. See the attack mapping in the threat model.

## Components

| Path | What |
|------|------|
| `deploy/dstack/` | `docker-compose.yml` (Vaultwarden + Caddy + sidecar), Caddyfile, `.env.example` (placeholders only) |
| `attest-sidecar/` | Small Rust service serving `/.well-known/tee-attestation` |
| `verifier/` | `attested-vw-verify` CLI and the library it uses |
| `common/` | `report_data` construction, attestation JSON schema, policy format |
| `policy/` | One policy file per published release (expected measurements, compose hash, image allowlist) |
| `demo/` | Tamper and relay demos |
| `docs/` | Threat model, architecture, verification guide, related work, decision log |

## Verifying a deployment (target UX, not yet implemented)

```bash
attested-vw-verify https://vault.example.com --policy policy/<release>.toml
```

The verifier opens a normal WebPKI-validated TLS connection, sends a fresh
random nonce over that same connection, and checks the returned hardware
evidence, `report_data` binding, measurements, compose hash and image
allowlist. Any failure means FAIL and a non-zero exit code.

## Licence

Dual-licensed under either of [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE), at your option.
