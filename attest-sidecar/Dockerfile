# Reproducible build of the attestation sidecar. Build context: a
# `git archive` of the repository at one commit (see
# attest-sidecar/reproducible-build.sh), never a dirty working tree.
#
# Determinism: digest-pinned base images, `cargo --locked`, paths remapped
# out of the binary, SOURCE_DATE_EPOCH = commit time (BuildKit then clamps
# file and layer timestamps with `rewrite-timestamp=true`).
FROM docker.io/library/rust:1.97-slim-bookworm@sha256:2775a09d208ff0d7c1f50490c45b62db929e87ba1dcbc3f2132ac71a704bcdd3 AS build
ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \
    CARGO_INCREMENTAL=0 \
    RUSTFLAGS="--remap-path-prefix=/src=/build --remap-path-prefix=/usr/local/cargo=/cargo -C strip=symbols"
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p attest-sidecar

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=build /src/target/release/attest-sidecar /attest-sidecar
ENTRYPOINT ["/attest-sidecar"]
