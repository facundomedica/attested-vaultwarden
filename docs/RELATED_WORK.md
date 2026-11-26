# Related work

Links checked 2026-11-26. Descriptions are short summaries, not claims about
every detail of each system.

## Comparison

| System | TEE | What is attested | Who verifies, how | TLS bound to TEE? | Open |
|--------|-----|------------------|-------------------|-------------------|------|
| **This project** | Intel TDX via dstack (SEV-SNP verifier side) | Unmodified Vaultwarden + proxy + sidecar: compose hash, image digests, OS measurements, config pins | Anyone, with a standalone CLI, on demand | Yes: nonce + leaf SPKI in `report_data`, fetched on the same TLS connection | Yes |
| 1Password confidential computing | AWS Nitro Enclaves | 1Password's own enclave services; releases signed and logged in a transparency log | 1Password clients, automatically | Per their design (client ↔ enclave) | No |
| Signal SVR2 / SVR3 | SGX, Nitro, SEV-SNP (SVR3 across several) | PIN-protected secret recovery | Signal clients, automatically | Attested channel to the enclave | Yes |
| matter-labs/teepot | SGX (Gramine), TDX tooling | HashiCorp Vault and secret release | Clients/workloads requesting secrets | Attestation drives secret release | Yes (archived 2026-06) |
| Revelio | SEV-SNP | Web services in confidential VMs | Browser extension, per session | Yes (certificate bound to attestation) | Paper |
| Tinfoil | TDX, SEV-SNP | AI inference enclaves | Client SDKs / verifier, offline with embedded roots | Yes: SPKI fingerprint in report data | Yes |
| atlas-rs | TDX (dstack) | dstack apps | Rust client library | Yes: TLS exporter (EKM) | Yes |
| Phala domain attestation | TDX (dstack) | The gateway's TLS key and ACME account | Anyone, via `/.dstack/acme-info` | The *gateway* CVM holds the key | Yes |
| aDNS | Confidential computing + transparency | Name → attested service binding | DNS clients | Binding via attested DNS records | Paper |

## Notes

* **1Password** (<https://support.1password.com/confidential-computing-security/>,
  <https://1password.com/blog/confidential-computing>): the closest in spirit
  (a password manager moving server logic into enclaves, with a transparency
  ledger for releases), but closed source, Nitro-only, and verified by
  1Password's own clients. Our design is the inverse trade-off: open,
  verified by a separate tool anyone can build, but not checked by the
  everyday clients.
* **Signal SVR2/SVR3** (<https://github.com/signalapp/SecureValueRecovery2>,
  <https://www.usenix.org/conference/osdi24/presentation/connell>): mature
  client-verified enclaves for one narrow function; SVR3 spreads trust over
  several TEE vendors and clouds, an answer to the single-vendor risk that
  remains in our design (R4).
* **teepot** (<https://github.com/matter-labs/teepot>): attestation is checked
  *by the server side* before secrets are released; the direction is
  client→server for unsealing, not user→server for trust.
* **Revelio** (<https://arxiv.org/abs/2402.15277>): per-session verification
  by a browser extension before the page loads, which is exactly what our
  "Bitwarden apps don't check" limitation (R1) lacks; a natural follow-up
  for the web vault.
* **Tinfoil** (<https://github.com/tinfoilsh/tinfoil-go/tree/main/verify>):
  the same TLS binding idea (SPKI fingerprint in report data, checked against
  the live connection) applied to AI inference; plus Sigstore provenance for
  the code.
* **atlas-rs** (<https://github.com/concrete-security/atlas>): binds the TLS
  session itself via exported keying material (RFC 9266), stronger than our
  per-certificate binding but requiring the attestation endpoint to sit in
  the TLS stack. We use its verification order as a reference (D-007).
* **Phala gateway domain attestation**
  (<https://docs.phala.com/phala-cloud/networking/domain-attestation>) and
  **dstack-ingress**
  (<https://github.com/Dstack-TEE/dstack-examples/tree/main/custom-domain/dstack-ingress>):
  the platform's own answers to "who holds the TLS key". We use passthrough
  so the key lives in *our* CVM, and our own sidecar so the binding includes
  a verifier nonce.
* **aDNS** (<https://arxiv.org/abs/2503.14611>): addresses the residual risk
  that whoever controls DNS can point clients elsewhere (R1/R2).
* **IETF**: `draft-fossati-tls-attestation` was withdrawn (-10, 2026-07-23);
  attestation in TLS continues in the SEAT WG
  (<https://datatracker.ietf.org/wg/seat/documents/>). If it lands in TLS
  libraries, the sidecar endpoint could become part of the handshake.
* **SNPGuard** (<https://arxiv.org/abs/2406.01186>): attestation-gated disk
  key release for SEV-SNP, relevant to the SEV-SNP stretch target.

## Physical attacks (residual risk R4)

* **TEE.fail** (S&P '26, <https://tee.fail>): DDR5 interposer, extracts
  Intel's PCE key, so TDX/SGX quotes can be forged; SEV-SNP key extraction too.
* **DDRop** (2026, <https://ddropattack.eu/>): DDR5 write dropping, forged
  TDX reports.
* **WireTap** (CCS '25, <https://wiretap.fail>) and **Battering RAM**
  (S&P '26, <https://batteringram.eu>): DDR4 interposers against SGX and
  SEV-SNP attestation.

These break the hardware root of trust itself; vendors treat physical
attacks as out of scope, so "TCB up to date" does not cover them.

## What is new here

As far as we know, nobody has published an attested, user-verifiable
Vaultwarden (or any Bitwarden-protocol) deployment, nor mapped the ETH
Zurich / USI malicious-server attacks onto what remote attestation does and
does not constrain. The individual techniques (TDX quotes, RTMR3 replay,
TLS-key binding) are known; the contribution is putting them around an
unmodified, widely used password-manager server, with a public threat model,
fail-closed verification and recorded live results.
