# Attested Vaultwarden workload image for Google Cloud Confidential Space.
#
# RESEARCH PROTOTYPE. Run once on a live Confidential Space VM (2026-11-27);
# see docs/GCP_CONFIDENTIAL_SPACE.md, "Live test".
#
# Confidential Space runs exactly ONE container, so the three roles that are
# three containers on dstack (unmodified Vaultwarden, Caddy terminating TLS,
# attestation sidecar) are three processes in one image here. The digest of
# THIS image is the `submods.container.image_digest` claim that Google's
# attestation token carries and that the release policy pins. Everything
# that decides behaviour is therefore baked in: the domain, the Caddyfile,
# Vaultwarden's settings, the launch policy labels. No operator-supplied
# environment or command is accepted (and the verifier rejects a token that
# shows one).
#
# Build context: a `git archive` of the repository at one commit (see
# build.sh), never a dirty working tree.
#
# Determinism: every upstream is pinned by digest, the sidecar is built
# exactly as attest-sidecar/Dockerfile does, and BuildKit clamps timestamps
# to SOURCE_DATE_EPOCH (`rewrite-timestamp=true`).

# --- attestation sidecar (same recipe as attest-sidecar/Dockerfile) --------
FROM docker.io/library/rust:1.97-slim-bookworm@sha256:2775a09d208ff0d7c1f50490c45b62db929e87ba1dcbc3f2132ac71a704bcdd3 AS build
ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \
    CARGO_INCREMENTAL=0 \
    RUSTFLAGS="--remap-path-prefix=/src=/build --remap-path-prefix=/usr/local/cargo=/cargo -C strip=symbols"
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p attest-sidecar

# --- Caddy: the upstream binary, unmodified (static Go binary) -------------
FROM docker.io/library/caddy@sha256:003a97808e781aa9f7e75cc2f43d34d461099031faf5e20faefb9f61126836f0 AS caddy
# 2.11.9-alpine, the same digest the dstack deployment pins.

# --- config rendered for one domain ----------------------------------------
FROM docker.io/vaultwarden/server@sha256:4fe17f415f90087377d37c755e0ea3cf189dcc6794e49cdd2a9adbb4937d9e1f AS config
ARG DOMAIN
# ACME directory host. Use acme-staging-v02.api.letsencrypt.org while
# testing: every VM boot requests a NEW certificate (see the doc).
ARG ACME_HOST=acme-v02.api.letsencrypt.org
COPY deploy/gcp-cs/Caddyfile.template deploy/gcp-cs/supervisor.sh /in/
RUN set -eu; \
    echo "${DOMAIN}" | grep -Eq '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$' || { echo "build with --build-arg DOMAIN=<fqdn>" >&2; exit 1; }; \
    echo "${ACME_HOST}" | grep -Eq '^[a-z0-9.-]+$'; \
    mkdir -p /out/etc/caddy /out/etc/attested-vw; \
    sed -e "s|__DOMAIN__|${DOMAIN}|g" -e "s|__ACME_HOST__|${ACME_HOST}|g" /in/Caddyfile.template > /out/etc/caddy/Caddyfile; \
    sed -e "s|__DOMAIN__|${DOMAIN}|g" -e "s|__ACME_HOST__|${ACME_HOST}|g" /in/supervisor.sh > /out/supervisor.sh; \
    chmod 0555 /out/supervisor.sh; chmod 0444 /out/etc/caddy/Caddyfile

# --- the workload image -----------------------------------------------------
# Vaultwarden's own image, unmodified (1.37.5, the digest the dstack
# deployment pins), plus two binaries, one script and one config file.
FROM docker.io/vaultwarden/server@sha256:4fe17f415f90087377d37c755e0ea3cf189dcc6794e49cdd2a9adbb4937d9e1f
ARG LOG_REDIRECT=debugonly
COPY --from=caddy /usr/bin/caddy /usr/local/bin/caddy
COPY --from=build /src/target/release/attest-sidecar /usr/local/bin/attest-sidecar
COPY --from=config /out/ /

# Launch policy: what the workload OPERATOR may change through VM metadata.
# These labels are part of the image config, hence of the attested digest.
#   - no command override, no environment override, no extra capabilities
#   - stdout/stderr leave the VM only on the debug image by default. Build
#     with LOG_REDIRECT=always for development deployments (logs then reach
#     Cloud Logging / the serial console when the operator asks for them;
#     Vaultwarden logs contain client IPs and account e-mail addresses).
LABEL "tee.launch_policy.allow_cmd_override"="false" \
      "tee.launch_policy.allow_env_override"="" \
      "tee.launch_policy.allow_capabilities"="false" \
      "tee.launch_policy.allow_cgroups"="false" \
      "tee.launch_policy.monitoring_memory_allow"="never" \
      "tee.launch_policy.log_redirect"="${LOG_REDIRECT}"

# The launcher opens exactly the EXPOSEd ports in the VM's own firewall; the
# container shares the VM's network namespace. Vaultwarden and the sidecar
# listen on loopback only.
EXPOSE 443/tcp

# Vaultwarden's HEALTHCHECK probes a port we moved; the launcher ignores it.
HEALTHCHECK NONE
ENTRYPOINT ["/supervisor.sh"]
CMD []
