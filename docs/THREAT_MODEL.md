# Threat model

> Status: **revised after the first live run (2026-11-26)**. Research
> prototype. Platform facts and their sources: [DECISIONS.md](DECISIONS.md).

## 1. What this project claims

If `attested-vw-verify` reports PASS for `https://vault.example.com` against
`policy/<release>.toml`, then, **at the moment of verification and assuming
the hardware vendor's attestation root and the TEE itself are not broken**:

| # | Claim | Established by |
|---|-------|----------------|
| C1 | The responder is a genuine Intel TDX (or AMD SEV-SNP) guest, debug off, TCB acceptable to the policy. | Quote/report signature chain to the Intel/AMD root, collateral validity, TCB status and PCK platform flags (SMT, dynamic platform, cached keys) as the policy allows, debug attribute. SNP: VCEK bound to the report's TCB and chip; **no revocation (CRL) check yet**. |
| C2 | The guest booted the published firmware and OS image. | MRTD + RTMR0-2 (TDX) or launch measurement (SNP) equal the policy. |
| C3 | The guest runs the published compose document, and every container image in it is pinned by digest and allowlisted. | RTMR3 replay reproduces the quoted RTMR3 and its `compose-hash` event equals the policy; images parsed from that measured document. |
| C4 | The TLS private key behind the certificate the verifier just validated is held by that guest. | `report_data = SHA-512(tag ‖ nonce ‖ SHA-256(SPKI))` is signed by the TEE; the SPKI is taken from the verifier's own TLS handshake. |
| C5 | The evidence is fresh. | Verifier-chosen 32-byte random nonce in `report_data`. |

What PASS does **not** claim:

* that the published code is correct or free of malicious logic;
* that the next connection, or a connection from a Bitwarden app, reaches the
  same guest (see R1);
* anything about the disk state being the latest (see R6);
* anything when the platform is `mock`. Mock evidence proves nothing and the
  verifier never reports PASS for it.

C4 holds only if the TLS private key is generated inside the guest and never
leaves it. The dstack gateway terminates TLS outside the
app CVM by default, so the deployment uses gateway TLS *passthrough* to Caddy
inside the CVM ([ARCHITECTURE.md §2](ARCHITECTURE.md)). A deployment behind
the default terminating gateway URL would fail C4 by construction (the
gateway's certificate, not ours, is what the verifier sees).

## 2. Assets

| Asset | Where it lives | Why it matters |
|-------|----------------|----------------|
| Account metadata: emails, names, org/collection membership, item counts, timestamps, client IPs, event logs, device list | Vaultwarden DB (`/data/db.sqlite3`), process memory, logs | Plaintext to the server by protocol design (ETH BW04). Reveals who uses the service and how. |
| Stored master-password hashes (server-side hash of the client's KDF output) and KDF parameters | DB | Offline cracking: with the hash and the KDF parameters, weak master passwords fall. |
| Encrypted vaults (user keys wrapped under master key, item ciphertexts, attachments, Sends) | DB, `/data/attachments`, `/data/sends` | Ciphertexts for offline attacks; integrity (field swapping, BW05). |
| Server secrets: JWT signing key (`/data/rsa_key.pem`), 2FA (TOTP/WebAuthn/Duo) secrets, SMTP credentials, admin token, push installation key | `/data`, env | Forging sessions, bypassing 2FA, sending mail as the service. |
| Integrity of the web-vault JavaScript served to browsers | Bundled in the pinned Vaultwarden image | Malicious JS can exfiltrate the master password directly. |
| TLS private key | Proxy's storage inside the guest | Whoever holds it can impersonate the service. |

## 3. Adversaries

### In scope

| Adversary | Capabilities assumed | Mitigation | Residual |
|-----------|----------------------|------------|----------|
| **A1 Cloud / VPS operator, hypervisor** | Full control of host software, scheduling, device emulation, network, storage. | TDX/SNP memory confidentiality and integrity; dstack encrypted disk and network; attested boot chain. | Physical attacks (R4); rollback of disk (R6); denial of service. |
| **A2 Holder of disk, snapshots or backups** | Reads and replays any persistent storage. | Data disk LUKS-encrypted with a key the KMS releases only to the measured app; the verifier requires the RTMR3 `storage-encrypted` event to be `1` (dstack 0.6.5+). Backups taken *inside* the guest must be encrypted to a key the operator lacks; host-level snapshots are ciphertext. | Rollback (R6). Any backup tooling added later is in the TCB. |
| **A3 Network attacker** | Intercepts, modifies, replays traffic between users and the service and between components. | TLS terminated inside the guest; WebPKI validation in the verifier. | Mis-issued certificates (R2). |
| **A4 Service operator (us)** | Chooses what to deploy, holds the deployment credentials, injects secrets, controls DNS and the ACME account, can redeploy at will. | Measurements + compose hash + image allowlist against a public, signed release policy; TLS key generated in-guest; no operator access path in the published config (no SSH, no admin panel, see §5). | DNS and certificate control (R1, R2); unmeasured inputs (§5); publishing a malicious release openly (R3). |
| **A5 Relay attacker** | Owns a genuine TEE running the published software and forwards its attestation while serving users from a different, non-attested server. | The attested `report_data` commits to the SPKI of the certificate the verifier itself received in the same TLS connection; a relay serving a different key fails C4. | A relay that also holds the in-guest TLS key is impossible unless the key leaks (R4). |

### Out of scope / residual risks

* **R1 Official clients do not verify.** Bitwarden apps and browsers do not
  check attestation. Verification is periodic or manual. Between checks, an
  operator who controls DNS (or a network attacker with a valid certificate)
  can send some clients to a non-attested server and run any of the ETH
  attacks against them. Detection relies on (a) users running the verifier,
  (b) certificate-transparency monitoring of every certificate issued for the
  domain against attested SPKIs (stretch), (c) CAA `accounturi` pinning so
  only the in-guest ACME account can obtain certificates (stretch). Per-
  connection verification in clients is future work.
* **R2 DNS and WebPKI.** The operator controls the domain. WebPKI validation
  proves domain control, not attestation. Same mitigations as R1.
* **R3 Bugs or malicious logic in the published code.** Attestation proves
  *which* code runs, not that it is good. A release containing a backdoor
  passes verification. Mitigation is social: releases are public, pinned and
  diffable in `policy/`, and the images carry upstream build provenance.
* **R4 Side channels and physical attacks on the TEE.** Out of scope, but
  serious and recent: memory-bus interposers break the confidentiality and,
  worse, the attestation keys themselves. TEE.fail (DDR5, extracts Intel's
  PCE key, forges TDX quotes; also SEV-SNP key extraction),
  WireTap (DDR4, SGX quoting key), Battering RAM (DDR4, SGX and SEV-SNP
  attestation), DDRop (DDR5, write dropping, forged TDX reports). Vendors
  treat physical attacks as out of scope, so "TCB up to date" does not cover
  them. Anyone with physical access to the host (for example a datacentre
  insider) is therefore outside what this project defends against. See
  [RELATED_WORK.md](RELATED_WORK.md) for links.
* **R5 Denial of service.** The operator or host can always stop the service.
* **R6 Rollback of disk state.** A host can restore an older encrypted disk
  snapshot. The guest cannot tell, because TDX/SNP have no hardware
  monotonic counter exposed for this. Effects: deleted items or revoked
  devices reappear, a password change is undone, an old (weaker) KDF setting
  returns. Possible mitigations, none implemented: a freshness counter held by
  a separate attested service or KMS, a transparency log of DB state roots,
  client-side detection of revision dates going backwards.
* **R7 Client compromise and weak master passwords.** Malware on clients and
  guessable master passwords are not addressed.
* **R8 SSO identity provider.** If SSO is enabled, the IdP is outside the
  TEE. The attested release keeps `SSO_ENABLED=false`.
* **R9 Third parties the service talks to.** SMTP relay (sees recipient
  addresses and invite timing), Bitwarden push relay (off by default; sees
  device push tokens and timing), icon sources (off: `DISABLE_ICON_DOWNLOAD`).
* **R10 Platform components in the TCB.** Trusted: the dstack OS image
  (measured in MRTD/RTMR0-2), the dstack guest agent inside it, and the key
  provider/KMS that releases the disk key (recorded in RTMR3 `key-provider`
  and pinned by the policy). On Phala Cloud with the "Phala" KMS, Phala's
  operations decide which compose hashes receive keys; the on-chain KMS
  options move that decision to a contract. Self-hosted, the choice is none
  (no persistence), a local SGX key provider, or a self-run KMS (D-032). With TLS
  passthrough (ARCHITECTURE §2) the dstack gateway sees only ciphertext and is
  trusted for availability only. Container images are trusted as published
  upstream.

## 4. Mapping the ETH Zurich / USI attacks

Source: Scarlata, Torrisi, Backendal, Paterson, *Zero Knowledge (About)
Encryption*, USENIX Security 2026 (prepub PDF read in full; the ePrint full
version adds detail on BW03/BW04 that we have not read). Every Bitwarden
attack in the paper assumes a **malicious server**: the server sends forged or
substituted data that honest server code never sends. They are client and
protocol design flaws that let a deviating server go undetected.

That gives the key distinction: attestation can stop the operator from
*running a deviating server*, but only for connections that actually reach
the attested guest (R1), and only if the published code itself never sends
such data (R3).

| Attack | What the malicious server does | With attestation |
|--------|--------------------------------|------------------|
| BW01 Malicious auto-enrolment | Substitutes an attacker org public key and an auto-enrol account-recovery policy. | **Constrained**: honest Vaultwarden returns the org key and policy stored by the real org admin. Note: a *malicious org admin* can still legitimately enable auto-enrolment with honest server code. That is a feature, visible in the client, and not a server deviation. |
| BW02 Malicious key rotation | Substitutes org public key during rotation. | **Constrained**. |
| BW03 Malicious Key Connector conversion | Shows a fake Key Connector conversion and captures the master key. | **Constrained**: Key Connector is not configured; honest code never sends that state. (Details in the full version, not yet read.) |
| BW04 Unprotected item metadata | Reads/modifies unencrypted metadata. | **Modification constrained.** **Reading not addressed by the protocol**: honest code stores metadata in plaintext. The TEE keeps it from the host (A1, A2), but any path the published code offers to the operator (admin panel, logs) still exposes it. Hence §5. |
| BW05 Item field swapping | Swaps ciphertexts between fields/items. | **Constrained**. |
| BW06 Icon URL item decryption | Combines BW05 with icon fetching to leak decrypted fields. | **Swap constrained.** The icon-fetch side channel itself remains a client behaviour: clients ask the server for `/icons/<domain>/icon.png`, so even an honest server sees the domains in request paths. In-guest logs must not record them (§5). |
| BW07 Remove KDF iterations | Reports PBKDF2 with 1 iteration at login. | **Constrained**: honest code returns the user's stored KDF parameters. Rollback (R6) could restore an old, weaker parameter set. |
| BW08 Organisation injection | Adds the user to arbitrary orgs at sync. | **Constrained**: honest code only returns memberships created by the org's own invite/accept/confirm flow. |
| BW09 Organisation overwrite | Swaps in a server-controlled org key right after org creation. | **Constrained**. |
| BW10 Disable per-item keys | Downgrades the key hierarchy. | **Constrained**, as long as the pinned Vaultwarden release does not itself advertise the downgrade. Check per release. |
| BW11 User key overwriting | Sends null key material, then forges a CBC user-key ciphertext. | **Constrained**. |
| BW12 Downgrade to legacy | Forges a short, MAC-less user key to trigger CBC-only mode. | **Constrained**. |

"Constrained" means the operator cannot mount the attack *through the
attested guest* without changing the measured software, which the verifier
detects. It does **not** mean "fixed": the client weakness remains, and a
non-attested server reached via R1/R2 can still exploit it.

## 5. Unmeasured inputs: what the operator still controls

Anything that changes server behaviour without changing the measurements
undermines C3. Known channels, and how the release configuration closes
them:

| Channel | Risk | Release configuration |
|---------|------|-----------------------|
| Environment variables injected at deploy time (dstack encrypted env) | Values are **not measured**; only the `allowed_envs` names are, inside `app-compose.json` (dstack `docs/encrypted-env-spec.md`). Anyone with VMM access (operator or host) can substitute them. Any security-relevant setting injected this way is attacker-controlled. | All behaviour-affecting settings are written literally in the measured compose. Only true secrets (SMTP password, push key if enabled) come from encrypted env, by name, via an allowlist. |
| Registry read token (private sidecar image, Phala deployment) | Delivered as encrypted env `GHCR_READ_TOKEN`, unmeasured; read by a measured pre-launch script that runs `docker login`. | Policy pins the script hash and the env name; images are pinned by digest, so a substituted token can only break the pull. Compose interpolation is forbidden, so the env cannot reach configuration. |
| Vaultwarden admin panel (`/admin`) | If `ADMIN_TOKEN` comes from encrypted env, the host can replace it with a hash of its own token (row above). Holder of `ADMIN_TOKEN` can view user metadata (emails, item counts, orgs, last activity), delete/deauthorise users, invite users and **change configuration at runtime** (persisted to `config.json` in `/data`, overriding env). That is operator access to assets and to unmeasured behaviour. | `ADMIN_TOKEN` unset in attested releases (admin panel disabled); users are onboarded via org invitations. If a panel is ever needed, its Argon2 hash goes literally into the measured compose and every capability it grants is documented as operator power. DECISIONS.md D-008. |
| Logs | Platform log collection (e.g. container logs visible to the operator) can leak IPs, emails and icon domains. | `LOG_LEVEL=warn`. On dstack, `public_logs` (measured) decides whether container logs are served by the guest agent's external API; with it off, not even the owner can read them. Development deployments turn logs on deliberately, and their policies must say so; a release meant for real use turns them off. |
| Persistent `/data` | Files there (e.g. `config.json`) can change behaviour and survive redeploys. | Same as admin panel; verifier cannot see `/data`. |
| Upgrades | A new release is a new policy. | Every release is a public, signed policy file; users choose which releases they accept. |

## 6. Assumptions

* Intel's (or AMD's) attestation root of trust and collateral service are honest.
* The TEE hardware and firmware correctly implement isolation and
  measurement, modulo R4.
* The dstack OS image, guest agent and KMS behave as published (R10).
* The verifier binary and the policy file the user runs come from a source
  they trust (e.g. built from a signed tag).
* WebPKI is used only to reach the service; it is not part of the
  attestation argument, but a CA-issued certificate is what browsers and
  Bitwarden apps check.
