# dstack deployment (M1 local / M3 dstack)

Not written yet. Planned files:

* `docker-compose.yml`: `vaultwarden` and `caddy` pinned by `@sha256:`,
  `attest` sidecar, named volumes only. Every behaviour-affecting setting is
  literal here, because dstack measures this document (via `app-compose.json`)
  but does **not** measure encrypted environment variable values.
* `Caddyfile`: embedded in the compose or mounted from a measured config.
* `.env.example`: placeholders only (e.g. `SMTP_PASSWORD=<set via dstack
  encrypted env>`). Never commit real values.

See docs/ARCHITECTURE.md for the TLS passthrough design.
