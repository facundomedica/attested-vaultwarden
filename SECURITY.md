# Security

This is a **research prototype**. It is not production-ready, has had no
external audit, and must not hold real passwords. See the
[threat model](docs/THREAT_MODEL.md) for what it does and does not protect,
and its [Known issues](docs/THREAT_MODEL.md#7-known-issues) for findings
that are already known and open (one today: container images on the
persistent disk are not re-checked against their digests).

## Reporting a problem

Please report vulnerabilities privately through GitHub's
"Report a vulnerability" button on this repository (private security
advisory), not in a public issue.

Particularly welcome:

* any way to make `attested-vw-verify` print `PASS` for a server that does
  not run the release named in the policy, or whose TLS key is not held by
  the attested VM;
* parsing or policy-validation bugs that make the verifier fail open;
* claims in the docs that are stronger than what the checks show.

Problems in Vaultwarden, Bitwarden clients, dstack, Phala Cloud, Intel TDX
or AMD SEV-SNP themselves belong with those projects.
