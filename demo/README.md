# Demos (M4)

* `tamper/`: change one environment variable or image digest in the compose,
  redeploy, and show the verifier failing on the compose hash / image
  allowlist.
* `relay/`: serve the attestation from the real CVM but terminate TLS on a
  different host; show the verifier failing on the SPKI binding.

Each demo will have a script and its recorded expected output.
