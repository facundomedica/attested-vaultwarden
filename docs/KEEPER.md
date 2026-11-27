# Design option: vault data in memory only, handed between attested VMs ("keeper")

> **Status (2026-11-27): a design option. NOT IMPLEMENTED, and not
> planned.** Nothing in this repository builds, deploys or verifies what
> this document describes. It is kept so that the option, its costs and
> the reasons for not taking it are on record ([DECISIONS D-054](DECISIONS.md)).
> A throwaway prototype of the protocol was written during the design and
> exercised on the INSECURE mock platform only; it was removed, and nothing
> here was ever run on a TEE. Where this text says "would", read it as a
> proposal, not as a description of software.

Contents: [1 the problem](#1-the-problem) ·
[2 the options side by side](#2-the-options-side-by-side) ·
[3 the design](#3-the-design) · [4 protocol](#4-handoff-protocol) ·
[5 how data survives restarts](#5-how-data-survives-restarts) ·
[6 recovery](#6-optional-recovery-when-every-replica-is-lost) ·
[7 optional and visible](#7-an-optional-mode-visible-to-whoever-verifies) ·
[8 platforms](#8-platforms) · [9 costs](#9-costs) ·
[10 residual risks](#10-residual-risks) ·
[11 why it was not built](#11-why-it-was-not-built)

## 1. The problem

On dstack, and therefore on Phala Cloud, every key the platform gives a VM,
the disk key included, is derived from the **app id**, not from the hash of
the measured compose. Whoever controls the app (the operator; with Phala's
own KMS also whoever decides which composes receive keys) can:

1. boot a compose nobody published under the same app id; it receives the
   same disk key;
2. read or change Vaultwarden's `/data` from inside that VM: the SQLite
   database (password hashes, encrypted vaults, metadata), the
   token-signing key `rsa_key.pem`, attachments;
3. boot the published compose again.

`attested-vw-verify` then reports PASS, correctly: every measurement is the
published one. It cannot see step 1. This is the *persistent-state
precondition* of [THREAT_MODEL §1](THREAT_MODEL.md): C3 and C4 hold only if
no compose other than a published one has ever run under the app id.

What the project does about it today (release 2026.11.4): TLS keys and
certificates live on a tmpfs and are re-issued at every boot;
Vaultwarden's `CONFIG_FILE` points at a tmpfs, so a planted `config.json`
is not read; a measured pre-launch script removes leftover containers. The
vault data, the ACME account key and the Docker image store remain on the
disk, and the precondition remains a stated assumption.

## 2. The options side by side

| Option | Idea | Closes the vault-data channel? | New trust or cost | Platforms | State here |
|---|---|---|---|---|---|
| **Documented precondition** (chosen) | Keep the disk; take what can be re-created off it (TLS keys, `config.json`); state the rest as an assumption | No. Operator can read and modify the vault via another compose | none | dstack | in release 2026.11.4 |
| **On-chain KMS with a compose allowlist** | The key service releases the disk key only to compose hashes listed in an app contract; the policy pins the contract and the KMS identity (RTMR3 `key-provider`) | Yes, for composes outside the list, as long as the list is honest | Whoever can change the list or upgrade the contract. On Phala: a contract on Base, with Phala's multisig in the trust path. The list must also constrain OS images: an allowlist that still admits an old OS image admits the published compose on an OS with known holes. *(Contract location, governance and the OS-image gap are as reported to this project; not checked against the contracts by this document.)* | dstack only | not used; the most direct fix for a Phala-only deployment |
| **SGX local key provider** | Self-hosted dstack: the disk key is sealed by an SGX enclave on the host; its measurement is in RTMR3 | Only if the enclave ties the key to the compose hash; **UNCONFIRMED** for dstack's provider. Otherwise the same app-id problem with a different key holder | Intel SGX on the host, the provider enclave, the host owner | self-hosted dstack | renderable (`render.sh … local`), not analysed for this question |
| **Ephemeral data disk** | No key provider: the disk key is random per boot (`render.sh … none`), or `/data` on a tmpfs | Yes: nothing survives a boot | **Every restart is an empty vault.** Usable for demos only | dstack `none`; Confidential Space by nature | renderable; what the Confidential Space run had |
| **Cross-platform key broker** | A small attested service, separate from the vault VM, releases a data key only to VMs whose attestation matches a published policy (the on-chain KMS idea without the chain and across TDX / SNP / Confidential Space) | Yes, if the broker is honest and its own state is safe | The broker becomes the thing to attack and to keep alive; it has the same bootstrap problem for *its* key, one level up; and encrypting `/data` under the released key needs dm-crypt or FUSE in a container, which the compose rules forbid | any | not designed further |
| **Keeper** (this document) | No key at all for vault data: `/data` in RAM, and the vault itself is handed to another VM after mutual attestation | Yes: there is nothing on the disk to read or plant | A second VM that must stay up; no data-preserving upgrades; a large new component inside the VM (§9–§11) | any platform the verifier supports | **not implemented** |

The keeper is the only option that removes the key instead of moving it,
and the only one that works the same on every platform. It is also by far
the most machinery.

## 3. The design

```
        VM A (primary)                                    VM B (standby)
┌───────────────────────────────┐                 ┌───────────────────────────────┐
│ vaultwarden ── /data (tmpfs)  │                 │ vaultwarden (not started)     │
│                  ▲            │                 │              /data (tmpfs)    │
│ keeper ──────────┘            │   TLS 1.3,      │ keeper                        │
│  data key K: RAM only         │◀───────────────▶│  K and newest snapshot: RAM   │
│  SQLite backup API            │  both sides     │  writes /data, then lets      │
│  own port, key made at start  │  attested       │  Vaultwarden start, at        │
│ proxy, attest: as today       │                 │  take-over                    │
└───────────────────────────────┘                 └───────────────────────────────┘
   persistent disk: Docker's own state and Caddy's ACME account. No vault data.
```

### 3.1 Pieces

* **`/data` on a tmpfs volume.** The compose rules already accept tmpfs
  volumes (the TLS certificates use one). They forbid `privileged`,
  `devices` and `cap_add`, which rules out dm-crypt and FUSE inside a
  container; that is why the design is "RAM plus snapshots" and not "an
  encrypted volume under a key from somewhere".
* **A keeper container** next to Vaultwarden, sharing that volume. It would
  verify peers with the verifier library (the same `check_document` the CLI
  calls) and obtain its own evidence through the sidecar's platform
  providers. A separate program rather than a mode of the sidecar: the
  sidecar is deliberately tiny, the keeper needs the whole verifier, a TLS
  stack and SQLite.
* **A 256-bit data key `K`**, generated at genesis, held only in keeper
  memory, handed on with the vault. With nothing encrypted at rest its jobs
  are: it names the **lineage** (a public hash of `K`), so that a standby
  can tell its primary from one that was reset; and it is the key for the
  optional recovery snapshots (§6).
* **A gate on Vaultwarden**: `depends_on: keeper: condition:
  service_healthy`, with the keeper healthy only once the vault is in
  `/data` or the node has decided it is a new vault. Otherwise Vaultwarden
  creates an empty database on the empty tmpfs and serves it.

### 3.2 Modes, pinned by the measured compose

| Mode | At boot | Afterwards |
|---|---|---|
| `genesis` | requires an empty `/data`; new `K`; ready at once; Vaultwarden creates a new vault | a source for peers that verify |
| `join` + peer address | fetches the vault from the peer; if no peer verifies in time, exits and Vaultwarden never starts | a source |
| `standby` + peer address | fetches a snapshot every N seconds and keeps the newest in memory; Vaultwarden does not run | takes over when no fetch has succeeded for a set time |

Mode and peer are literal values in the compose, hence measured. A node
would refuse to start on a `/data` that already holds a database: it has no
key for it and must not adopt data of unknown origin. A `genesis` node that
restarts starts an **empty** vault again; after the first failover every
node should therefore run `standby`.

### 3.3 Who may hold the vault: a trust bundle in the compose

A keeper must know which releases it may hand the vault to and accept it
from. That list has to be measured, or the operator edits it. So it is
written into the compose itself: a list of ordinary release policies, each
with a section such as

```toml
[keeper]
base_compose_hash = "…"
accept_from = true    # a joining node may take the vault FROM this release
handoff_to  = true    # a node may hand the vault TO this release
```

and the keeper reads it from its own measured app-compose (on dstack, the
document the guest agent reports, whose hash RTMR3 covers), not from a
mounted file that an earlier compose could have left behind.

**A circularity to solve.** A's compose lists B's release, B's lists A's.
If a release were named by its compose hash, each compose would contain
the other's hash. The way out: name a release by a **base hash**, the hash
of its app-compose *without* the bundle (everything else included:
services, images, environment with keeper mode and peer, volumes,
pre-launch script, platform flags). Deployment then takes two passes:
render with an empty bundle to obtain base hashes (and, on Phala, app
ids), write the bundle, render again.

**Acceptance rule.** A peer is accepted only if (1) its compose carries a
bundle byte-identical to ours, (2) its base hash is listed there with the
flag for the direction, and (3) its attestation passes the verifier
library against that entry, with the compose pin set to the document the
peer served. (1) and (2) are claims about text the peer sent; (3) proves
that this text is what the peer's hardware measured. By induction, every
VM that ever holds the vault runs a listed release and carries the same
list.

**A closed world.** The bundle is fixed when the first node is deployed. A
release that is not in it, which includes every future version, never
receives the vault. **There is no upgrade that keeps the data**: new
software means a new genesis and users re-importing their client exports
(or the recovery path of §6, with its holders acting as the upgrade
authority). A rule like "also trust releases signed by key X" would hand
the vault to the holder of X, which is the trust the design exists to
remove. This alone makes the design a poor fit for software that needs
security updates.

## 4. Handoff protocol

```
joiner B                                              source A
  │  TLS 1.3 to A's keeper port. A's certificate is self-signed, its key
  │  made in memory at start. B accepts any certificate, checks the
  │  handshake signature, records  spki_A = SHA-256(SPKI it received)
  │
  │  n_B ← 32 random bytes
  │  hello {n_B}                                     ───────▶
  │                                    evidence over report_data(n_B, spki_A)
  │                                    c ← fresh single-use challenge
  │                                     ◀─────── {attestation_A, c}
  │  verify A like the CLI does, with B's OWN n_B and spki_A, against the
  │  bundle (accept_from). Stop unless it passes.
  │
  │  (x_B, X_B) ← one-time X25519 key pair
  │  evidence over report_data(c, H(tag ‖ X_B ‖ spki_A))
  │  join {c, X_B, attestation_B}                    ───────▶   (same connection)
  │                                    c outstanding? consume it
  │                                    verify B with A's OWN c, spki_A and the
  │                                      received X_B, against the bundle (handoff_to)
  │                                    only now: consistent SQLite snapshot
  │                                      (online backup API), rsa_key.pem, attachments
  │                                     ◀─────── encrypted to X_B: K ‖ counter ‖ files
  │  decrypt; parse strictly; let SQLite check the database;
  │  same lineage and a newer counter than anything already held;
  │  write /data; let Vaultwarden start
```

`report_data(nonce, x)` is the construction the public endpoint uses, with
the keeper's TLS key hash (or the join binding) where the public endpoint
puts the web TLS key hash; that is what would let both checks reuse the
verifier unchanged.

| Element | Without it |
|---|---|
| B verifies A first, with the key hash from its own handshake | an operator VM, or a relay in front of the real A, could push a forged database into B (**mutual** verification is not optional) |
| A's evidence covers its TLS key; both requests on one connection | a relay with its own TLS key could sit in between |
| single-use, short-lived challenge | a recorded join request could be replayed |
| B's evidence covers `X_B` | someone forwards an honest joiner's attestation with their own key and receives the vault |
| B's evidence covers `spki_A` | a join request made for one source is presented to another |
| a domain tag in the join binding | an attestation from a VM's public endpoint passes as a join attestation |
| encryption to `X_B` on top of TLS | TLS here has no client authentication: the channel alone does not say that the reader is the attested B |
| identical bundles on both sides | B runs listed software but is configured to pass the vault on to anything |
| lineage and counter check | restarting the primary as a new genesis, or pointing a standby at a stale node, wipes or rolls back the standby |

**No WebPKI and no Let's Encrypt on this channel.** Attestation binds the
key, so no CA is involved: no issuance, no use of the 5-certificates-per-
week budget that the in-memory web certificates already strain, and it
works before DNS points at a node. It needs raw TCP to one more port (on
Phala, the gateway's TLS passthrough).

## 5. How data survives restarts

1. **A live peer.** A VM that boots in `join` or `standby` gets the vault
   from its peer. Restarting one VM at a time loses nothing.
2. **A standby that follows.** A standby would repeat the whole protocol
   every interval (fresh nonces and evidence each time, so a primary that
   stops verifying stops being followed) and keep the newest snapshot in
   memory. When the primary has been gone for the configured time it
   writes the snapshot to `/data` and starts serving. The take-over has to
   be automatic: any operator command that changes configuration is a new
   compose, hence a restart, hence the memory is gone. Loss at failover:
   the writes since the last snapshot.
3. **Replicas that do not fail together.** Two VMs at one provider share
   its outages, maintenance and account suspension. The sensible layout is
   one replica per provider, for example Phala (TDX), an SEV-SNP host and
   Google Cloud Confidential Space, which presupposes the platform work of
   §8.
4. **All replicas down at the same moment: the vault is gone**, unless the
   recovery path of §6 exists. In the disk variant the operator has to
   delete a disk to destroy the data; here, restarting everything at once
   is enough.

Failover is manual apart from the take-over: repoint DNS (and on Phala the
`_dstack-app-address` record) to the standby, which then obtains its own
certificate; a CAA `accounturi` pin must list both VMs' ACME accounts;
users verify the new server against *its* policy (another compose, another
app id), so both policies are published in advance; the old primary is
redeployed as a standby of the new one, which must already be a listed
release.

What goes wrong by design: **split brain** (a standby that merely cannot
reach the primary takes over while the primary still serves; nothing
merges the two); **rollback by partition** (the operator controls the
network: cut the standby off, let the primary collect writes, kill the
primary, repoint DNS; the window is unbounded and needs no key); **reset**
(a restarted `genesis` node serves an empty vault until DNS moves).

Bitwarden clients keep an encrypted copy and can export it. In every
variant that is the last line, and users should be told.

## 6. Optional recovery when every replica is lost

RAM-only data and "survives a power cut in two datacentres" contradict
each other unless something durable exists. The durable part can be made
useless to the operator:

* **Encrypted snapshots on untrusted storage.** The primary periodically
  writes the vault, AEAD-encrypted under a key derived from `K`, to the
  CVM's disk and/or an object-storage bucket. The authenticated header
  carries the lineage, a monotonic counter, and the identity of the release
  set and of the writing release. Without `K` the file is noise.
* **`K` escrowed as Shamir shares.** At genesis the keeper splits `K` into
  *n* shares, *t* of which rebuild it (for example 2-of-3), and encrypts
  each to a recovery public key (X25519 / `age` recipients) pinned
  literally in the measured compose. The holders are different people; one
  key can be a printed sheet. The operator alone holds at most one share.
  The escrow document is public and stored next to the snapshots.
* **Recovery.** A fresh VM boots a published release in a `recover` mode
  and serves its attestation, bound to a key it generated in memory. Each
  holder runs a small tool built like `attested-vw-verify`: it verifies the
  VM against a published policy **first**, and only on PASS decrypts their
  share locally and sends it over the TLS connection that attestation
  vouched for. With *t* shares the VM rebuilds `K`, checks the lineage,
  opens the newest snapshot that authenticates, and becomes a normal
  source. No holder releases a share to an unverified VM; no share passes
  through the operator in the clear; too few or wrong shares yield a key of
  another lineage, which is detected.

**Rollback at recovery.** Storage is untrusted, so an old snapshot can be
presented, and it authenticates, because it is genuine. The counter helps
only if someone knows the newest value: the primary would publish its
counter, holders would note the latest they saw and pass it to the
recovering VM, which refuses anything older. A holder who never looked
cannot help. Either that discipline is adopted, or the residual is
accepted and stated: recovery restores *a* genuine state, not provably the
last.

**Other properties.** *t* colluding holders can decrypt every snapshot
they can obtain, with no VM involved: the holders replace the operator as
the party to trust, with a threshold. Holders are not bound by the closed
world of §3.3 (they release to whatever they choose to verify), which
makes recovery the one route to newer software, and the holders the
upgrade authority. Losing more than *n − t* recovery keys makes recovery
impossible. Recovery is optional: without recipients in the compose there
is none, and "all replicas lost" is final.

**Single-user variant.** An operator who is also the only user does not
need protection from themselves, but may want the hosting provider and
anyone with their deployment credentials kept out. One recovery key held
offline by that person (1-of-1) and one standby on another provider would
do. For that case the default disk variant is the simpler answer; the
keeper's value grows with the number of people who have to trust the
operator.

## 7. An optional mode, visible to whoever verifies

If this were built, it would have to be a variant, not a replacement:

* the default compose (vault on the persistent disk) unchanged, the keeper
  selected by an explicit render flag; recovery optional within it;
* the mode is part of the measured compose (the keeper service's settings,
  `/data` declared as tmpfs, recovery threshold and recipients), so the
  verifier can **report it** on every run, for example

  ```
  storage mode: persistent disk (operator-tamperable, see THREAT_MODEL §1)
  storage mode: keeper, standby of https://…, recovery: none
  storage mode: keeper, recovery 2-of-3, recipient keys 1a2b…, 3c4d…, 5e6f…
  ```

* and a policy can pin it like any other setting (`storage_mode =
  "keeper"`), so that a deployment in the other mode fails.

The trade-off a user would read from that line:

| | Persistent disk | Keeper |
|---|---|---|
| VMs | 1 | 2 or more |
| A restart | data still there | needs a live peer (or recovery) |
| Operator reads or modifies the vault through the disk | possible, undetectable by the verifier | not possible: nothing is there |
| All VMs down at once | nothing lost | everything lost unless recovery shares exist |
| Upgrades | new policy, same data | no data-preserving upgrade |

Reporting the storage mode for the *existing* variants (persistent disk,
ephemeral) would be useful on its own and is independent of the keeper; it
is not implemented either.

## 8. Platforms

| Platform | How it would plug in | Notes |
|---|---|---|
| dstack / TDX (Phala, self-hosted) | evidence from the guest agent as the sidecar gets it; the bundle read from the measured app-compose; peers checked with the verifier's TDX path | each VM needs outbound access to Intel's collateral service to verify the other, and judges validity by a clock the host influences |
| SEV-SNP | the same scheme with `HOST_DATA` = SHA-256(app-compose) as the compose binding | there is still no SNP guest image ([SNP.md](SNP.md)) |
| Google Cloud Confidential Space | no measured compose document exists to carry a bundle (baked into the image, it would contain the image's own digest); it would have to travel in a launch-time value that the token attests, with the image digest as the release identity | Confidential Space has **no persistence at all**, so a keeper peer would be its only route to durability; it would inherit that platform's weaker statement (trust in Google's attestation service) |
| mock | forgeable evidence | a keeper on the mock platform hands the vault to anyone; for tests only |

Cross-platform handoff needs nothing extra in principle: a bundle can list
a TDX release and an SNP release, each side applying the other platform's
checks.

## 9. Costs

* **A second VM, always on.** On Phala a `tdx.small` is about $0.06/h
  (≈ $44 a month) plus its disk, so roughly twice the current bill; a
  third replica on another provider for real independence.
* **Operations.** A two-pass deployment (base hashes, then the bundle);
  one policy per node and role, all published before the first boot; DNS
  and CAA changes at failover; the rule never to restart the primary while
  the standby is not current; no in-place updates of both nodes; holders to
  recruit and keys to store if recovery is wanted.
* **No data-preserving upgrades** (§3.3).
* **Code inside the VM.** The throwaway prototype came to roughly 4,000
  lines of Rust with tests and added a TLS stack, certificate generation,
  X25519/HKDF/ChaCha20-Poly1305 and SQLite (C) to what runs next to the
  vault, all of it new, unaudited, and deciding who receives the entire
  vault.
* **Full snapshots.** Each sync sends the whole vault; fine for a few
  megabytes, not for large attachment stores. The vault sits in RAM two or
  three times during a handoff.

## 10. Residual risks

Even built as described, the design would leave:

* **The Docker image store on the persistent disk.** Images are pulled
  once and kept there; Docker does not re-check layer contents against the
  digest when starting a container (UNCONFIRMED for dstack 0.6.5, as in
  THREAT_MODEL §1). An operator who altered stored layers from another
  compose would run their code under the published measurements, and that
  code reads the vault from memory. The keeper takes the data off the
  disk; it does not make the disk trustworthy for code. This would become
  the main remaining route, and closing it needs images re-pulled by
  digest at every boot or a non-persistent image store.
* **The ACME account key**, still on the disk.
* **Denial of service and destruction**: stopping, partitioning, or
  restarting all replicas together.
* **Rollback** by partition (§5) and at recovery (§6).
* **Everything already out of scope**: clients do not verify; DNS belongs
  to the operator; physical attacks on the TEE. The last one gets worse:
  an attacker who can forge quotes can pose as a verified peer and is
  handed the vault directly.
* **Bugs in the keeper**, and a keeper process that dies takes the key
  with it (that node stops being a source; split brain until DNS moves).
* **Attachments** copied file by file beside a consistent database backup
  can be out of step with it.

## 11. Why it was not built

The design answers the question it was asked: with it, no key the operator
can obtain protects vault data, on any platform. The project still chose
not to build it (D-054):

* **Complexity against what it protects.** A new protocol, a second
  always-on VM, a two-pass deployment and a closed set of releases, for a
  research prototype whose only deployments so far are a demo VM that is
  stopped most of the time and one short Confidential Space run. The keeper would be the largest and most security-critical component
  in the repository.
* **It trades a confidentiality assumption for an availability hazard.**
  Today the operator must be trusted not to misuse the app id; with the
  keeper, a simultaneous restart destroys the vault unless the recovery
  machinery, with its own holders and its own rollback caveat, is built
  too.
* **No upgrades.** A password server that cannot take a security update
  without a new genesis is hard to recommend.
* **It does not finish the job.** The image store stays on the disk (§10),
  so the precondition would shrink, not disappear.

What the project does instead: the precondition is **documented** as an
assumption the verifier cannot check; TLS keys and certificates are
in-memory and re-issued at every boot; `CONFIG_FILE` is on a tmpfs; a
measured pre-launch script recreates all containers. For a deployment that
needs the vault-data channel closed on Phala, the on-chain KMS with a
compose allowlist (§2) is the smaller step and the one to evaluate first,
with its own trust in the contract's governance stated in the policy.

If the keeper is ever picked up again, the order that made sense in the
prototype was: the trust bundle and base hash; the handoff protocol with
its negative tests (wrong policy, relay, replayed challenge, forged peer,
wrong compose, damaged snapshot, counter rollback); a two-stack local
test; standby replication; and recovery last.
