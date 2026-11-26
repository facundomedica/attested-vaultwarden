# Related work

> Status: link collection (M0). Comparison prose is written in M5.

* **1Password confidential computing**: AWS Nitro Enclaves; clients verify the
  AWS attestation, a 1Password release signature and inclusion in a Rekor
  transparency log. Closed source.
  <https://support.1password.com/confidential-computing-security/>,
  <https://1password.com/blog/confidential-computing>
* **Signal SVR2 / SVR3**: enclave-backed PIN-protected secret recovery; SVR3
  spreads trust across clouds and enclave types (OSDI '24).
  <https://github.com/signalapp/SecureValueRecovery2>,
  <https://www.usenix.org/conference/osdi24/presentation/connell>
* **matter-labs/teepot**: HashiCorp Vault in SGX (Gramine) plus TDX tooling;
  attestation is client→server for secret release. Archived 2026-06-23.
  <https://github.com/matter-labs/teepot>
* **Revelio** (Galanou et al., 2024): SEV-SNP web services verified per
  session by a browser extension. <https://arxiv.org/abs/2402.15277>
* **aDNS** (Delignat-Lavaud et al., 2025): attested, transparency-logged DNS
  binding confidential services to names. <https://arxiv.org/abs/2503.14611>
* **IETF attestation in TLS**: `draft-fossati-tls-attestation` was withdrawn
  (-10, 2026-07-23); work continues in the SEAT WG (`draft-ietf-seat-use-cases`,
  `draft-fossati-seat-early-attestation`, `draft-fossati-seat-expat`).
  <https://datatracker.ietf.org/wg/seat/documents/>
* **Tinfoil**: TDX/SEV-SNP inference endpoints, nonce + SPKI fingerprint in
  report_data, offline verifier with embedded roots, Sigstore provenance.
  <https://github.com/tinfoilsh/tinfoil-go/tree/main/verify>
* **atlas-rs**: dstack TDX aTLS client with EKM binding, RTMR replay,
  compose-hash checks. <https://github.com/concrete-security/atlas>
* **Phala gateway domain attestation**: TEE-held TLS keys and ACME account for
  gateway domains. <https://docs.phala.com/phala-cloud/networking/domain-attestation>
* **dstack-ingress**: in-CVM HAProxy + certbot with CAA `accounturi` pinning.
  <https://github.com/Dstack-TEE/dstack-examples/tree/main/custom-domain/dstack-ingress>
* **SNPGuard** (IONOS): SEV-SNP attestation with LUKS key release.
  <https://arxiv.org/abs/2406.01186>

## Physical attacks relevant to R4

* **TEE.fail** (S&P '26): DDR5 interposer, extracts Intel PCE key → forged
  TDX/SGX quotes; SEV-SNP key extraction. <https://tee.fail>
* **WireTap** (CCS '25): DDR4 interposer, SGX quoting key. <https://wiretap.fail>
* **Battering RAM** (S&P '26): DDR4 aliasing interposer, breaks Scalable SGX
  and SEV-SNP attestation. <https://batteringram.eu>
* **DDRop** (2026): DDR5 write-dropping interposer, forged TDX reports.
  <https://ddropattack.eu/>

## What is new here

As far as we know, nobody has published an attested, user-verifiable
Vaultwarden (or Bitwarden-protocol) deployment, nor mapped the ETH Zurich /
USI malicious-server attacks onto what remote attestation does and does not
constrain.
