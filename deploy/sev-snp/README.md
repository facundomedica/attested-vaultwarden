# AMD SEV-SNP (stretch goal, not started)

Plan: a plain SEV-SNP confidential VM booting our own UKI with measured
direct boot; evidence from Linux configfs-tsm; expected launch measurement
computed with VirTEE `sev-snp-measure` for the published OVMF + UKI.
Optional: attestation-gated LUKS unlock (SNPGuard-style).

Nothing here is implemented yet. See docs/DECISIONS.md for open questions.
