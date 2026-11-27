# AMD SEV-SNP (no deployment kit yet)

Status: the verifier (`HOST_DATA` compose binding, launch-policy checks) and
the sidecar (configfs-tsm provider) are implemented and tested with
synthetic reports; **verified in code, never run on hardware**. There is no
guest image and nothing to deploy from this directory.

Design, the requirements on the guest image, and the steps for a first
deployment: [../../docs/SNP.md](../../docs/SNP.md) (DECISIONS D-050).
Measurement tooling: `policy/measure/measure-snp.sh` (untested).
