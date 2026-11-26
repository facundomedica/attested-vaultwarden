# How to verify a deployment

> Status: placeholder (M2). TDX verification is implemented and tested
> against recorded real quotes; there is no live deployment to verify yet. This guide is written for non-experts in M5.

Planned outline:

1. Get the verifier from a source you trust (build from a signed tag).
2. Get the policy file for the release you are willing to trust from
   `policy/` at that tag.
3. Run `attested-vw-verify https://<domain> --policy policy/<release>.toml`.
4. Read the report: what each ✓ proves, and what PASS does not prove
   (see [THREAT_MODEL.md §1](THREAT_MODEL.md)).
5. Re-run periodically: the Bitwarden apps themselves do not check attestation.
