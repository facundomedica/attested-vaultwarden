# dstack deployment

* `docker-compose.template.yml`: Vaultwarden, Caddy and the `attest`
  sidecar, every image pinned by `@sha256:`, named volumes only, the
  Caddyfile embedded. Every behaviour-affecting setting is literal, because
  dstack measures this document (via `app-compose.json`) but does **not**
  measure encrypted environment variable values.
* `render.sh <domain> <attest-image@sha256> [none|local|phala|phala-private] [out]`:
  fills in the domain and sidecar digest; `phala-private` also writes the
  measured GHCR login script from `pre-launch-ghcr.sh.template`.
* `simulator/`: test of the sidecar against dstack's guest-agent simulator.

Output goes to `.generated/` (gitignored). Runbooks:
[../../docs/PHALA.md](../../docs/PHALA.md),
[../../docs/SELF_HOSTING.md](../../docs/SELF_HOSTING.md).

Note: the template's header comment says "allowed_envs = []". That is true
for the `phala` render; the `phala-private` render (both published
releases) has `allowed_envs = ["GHCR_READ_TOKEN"]`, read only by the
pre-launch script. The comment is part of the measured document, so it is
left unchanged for the published releases.
