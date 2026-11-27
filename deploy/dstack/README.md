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

Notes:

* The compose itself uses no encrypted env. The `phala-private` render (all
  published releases) has `allowed_envs = ["GHCR_READ_TOKEN"]`, read only
  by the pre-launch script. Up to 2026.11.2 the template's header comment
  said "allowed_envs = []"; the comment is part of the measured document,
  so those releases keep it (`policy/*.app-compose.json`).
* `render.sh` puts a revision (12 hex digits of SHA-256 over the filled-in
  template) into the name of the Caddyfile config. docker compose keeps a
  running container when only the inline content of a config changes, and
  the containers live on the persistent disk, so without the rename an
  update would measure the new Caddyfile while Caddy keeps the old one
  (seen live, DECISIONS D-049).
