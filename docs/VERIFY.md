# How to check an Attested Vaultwarden server yourself

This guide is for someone who uses (or is invited to) an Attested Vaultwarden
server and wants to check, from their own computer, that it is what it
claims to be. No TEE knowledge needed. Takes a few minutes.

> Research prototype. A PASS tells you specific, limited things (listed
> below). It does not make the server "safe for your passwords".

## What you need

* A computer with [Rust](https://rustup.rs) installed (macOS, Linux, or
  Windows with WSL).
* The server's address, e.g. `https://vault.example.com`.
* The **release policy** the operator published for the version they run:
  a file like `policy/2026.11.0-phala-dev.toml` in this repository.

## Step 1: get the verifier from a source you trust

Build it from this repository yourself, at a release tag:

```bash
git clone <this repository> attested-vaultwarden
cd attested-vaultwarden
git checkout <release tag>        # e.g. release/2026.11.1-phala-dev
git tag -v <release tag>          # signed by the maintainer
cargo build --release -p attested-vw-verify
```

Why build it yourself: the verifier is the one piece you must trust. A
verifier handed to you by the operator could simply print PASS.

## Step 2: read the policy you are about to trust

Open `policy/<release>.toml`. It pins:

* `compose_hash`: the exact deployment document. Its human-readable form is
  next to it, `policy/<release>.app-compose.json`: this is the whole
  configuration of the server (Vaultwarden settings, images, proxy config).
  Skim it: for example `SIGNUPS_ALLOWED: "false"`, no `ADMIN_TOKEN`.
* `[[images]]`: every container image, pinned by an `@sha256:` digest.
* `mrtd`, `rtmr0`…`rtmr2`: the firmware and operating system. The header
  comment says how they were obtained. Prefer releases whose values were
  *reproduced* from the published dstack image with `dstack-mr` (the header
  gives the command, so you can re-run it); values only *observed* from the
  running server prove less (see "What PASS means").
* `pre_launch_script_sha256`, `allowed_envs`: anything the platform may run
  or inject before the containers start.

## Step 3: run it

```bash
target/release/attested-vw-verify https://vault.example.com --policy policy/<release>.toml
```

It needs internet access to the server and to Intel's attestation service
(to fetch Intel's signed status data for the server's CPU).

You get a list of checks, each ✓ or ✗ with a reason, and a final
`Result: PASS` or `Result: FAIL`. The exit code is 0 only for PASS. Add
`--json` for machine-readable output; it carries the verdict as `result` (`PASS`, `FAIL`, `INSECURE_MOCK`) and `exit_code`, so do not derive it from the checks.

## Step 4: what each line means

| Line | Plain-language meaning |
|------|------------------------|
| TLS connection | Your computer reached the domain over normal HTTPS with a valid certificate. |
| Fetch attestation over same connection | The proof was fetched over **that same** encrypted connection, not a separate one. |
| TLS key bound to attestation | The proof is about the encryption key *your* connection uses. If this fails, you may be talking to a relay in front of the real server. |
| Freshness nonce | The proof was made just now, for your request (not replayed). |
| Hardware evidence | Intel's chip signed the proof; Intel's data says the chip's security patches are acceptable; debugging (which would let the host read memory) is off. |
| report_data matches | The signed proof contains your random challenge and your connection's key. |
| Firmware / OS measurements | The virtual machine booted the firmware and OS the release pins. |
| Runtime event log | The deployment details the OS recorded at boot are consistent with the signed proof, the disk is encrypted, and the key service is the expected one. |
| Compose hash | The server runs exactly the deployment document in the release (persistent data and unmeasured secret values are not part of it). |
| Measured config is self-contained | Nothing outside that document (scripts, injected settings) can change what runs, except what the release explicitly pins. |
| Images pinned and allowlisted | Every container image is pinned by digest and is one the release lists. (Whether that image was built from the published source is a separate check: rebuild it, see the policy header.) |

## What PASS means, and what it does not

PASS means, at the moment you ran it: your HTTPS connection to that domain
ends inside a genuine Intel TDX virtual machine whose firmware, OS,
deployment document and container image digests are the ones the release
pins. It says nothing about the data stored on that server.

PASS does **not** mean:

* that your Bitwarden app is talking to the same server right now. The apps
  don't check any of this. Run the verifier from time to time.
* that the published code has no bugs or backdoors. It proves *which* code
  runs, not that the code is good. Reviewing the release is a separate step.
* that the server's stored data is the latest (an old disk snapshot could be
  restored without the verifier noticing).
* anything against physical attacks on the server hardware.
* "runs the published OS image", if the policy header says the
  measurements were *observed*.

If you get `Result: PASS (INSECURE MOCK, proves nothing)`, you are looking at
a local test setup with no real hardware: ignore it.

## Verify from a browser

If you cannot install the command-line verifier, open the browser verifier
(`web/dist/index.html`, built with `web/build.sh`; get it from a source you
trust, never from the server you are checking), enter the domain and press
**Verify**. It prints the same ✓/✗ lines.

It is weaker than the command-line verifier in one way. A web page cannot
see the TLS certificate of its own connection, so it cannot check that
*your connection* ends inside the attested VM. Instead it checks that
*every* certificate currently valid for the domain in the public
Certificate Transparency logs belongs to a key that was attested inside the
VM. If so, a browser can only reach an attested VM under that name. The
result then reads `PASS (browser mode: CT-based binding)`.

What that leaves open: a certificate issued in the last few minutes may not
be visible yet (the check detects, it does not prevent); the certificate
list comes from one monitor, Cert Spotter, which is trusted to be complete;
keys attested in the past count for as long as their certificates are
valid; Intel collateral is fetched from Phala's mirror because Intel's
service does not answer web pages (it is Intel-signed and verified either
way). Servers older than release 2026.11.3 cannot be checked from a
browser. Details: `web/README.md`.

The page handles all three platforms and fetches the vendor material at
each run rather than carrying a copy:

* **TDX**: Intel collateral from Phala's mirror, as above.
* **Google Cloud Confidential Space**: Google's token signing keys, from
  the one Google URL fixed in the verifier. Nothing signs that key list;
  the page relies on the browser's TLS connection to Google, as the
  command-line verifier relies on its own. The server being checked cannot
  supply keys. As on the command line, no hardware quote is seen: the
  statement is Google's ([GCP_CONFIDENTIAL_SPACE.md](GCP_CONFIDENTIAL_SPACE.md), "Trust").
  Tested against a recorded token from a real Confidential Space VM, with
  the keys fetched live from a browser; not against a running deployment.
* **AMD SEV-SNP**: the VCEK certificate from the server's certificate
  table, or from AMD's key server if the server sent none. Either way it
  must be signed by the AMD roots built into the verifier and match the
  report. **No SNP deployment exists**; this path has only seen synthetic
  reports and one public AMD-signed sample ([SNP.md](SNP.md)).

If the material cannot be fetched (service down, rate limit, request
blocked), the "Hardware evidence" line fails and says why.

On the demo domain `vault.facundo.dev` the page currently ends in FAIL with
every line ✓ except the Certificate Transparency line: Cloudflare wildcard
certificates for `*.facundo.dev`, issued before 2026-11-27, remain valid
until 2027-01-31 (recorded run: `web/testdata/live-2026-11-27-vault.facundo.dev.json`).
That is the correct outcome, not a bug: someone outside the VM holds keys
that browsers accept for the name.

The image list under "Images pinned and allowlisted" shows each service
with its full digest. The command-line verifier also asks Docker Hub which
tags point at each digest right now (`= vaultwarden/server:1.37.5 (Docker
Hub, as of now; tags can move)`); that line is a convenience, never part of
the result, and `--no-registry-lookup` turns it off.

## If something fails

* **TLS key bound ✗ and report_data ✗, everything else ✓**: the server's
  hardware proof is real, but your connection is not to it. A relay, a
  misconfigured proxy (e.g. a CDN in "proxied" mode) or a certificate change
  in the last minutes. Run once more; if it persists, do not trust the
  endpoint.
* **Compose hash ✗**: the server runs a different configuration than the
  release you checked. Ask the operator which release it runs; if none
  matches a published policy, it is not running published software.
* **Hardware evidence ✗**: no valid Intel proof. Do not trust the server.
* **Measurements ✗**: different firmware/OS than the release pins.
* **Network / collateral errors**: Intel's service unreachable; try again.

Every ✗ is a FAIL. The verifier never "passes with warnings".
