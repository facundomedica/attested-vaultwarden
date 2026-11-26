# Build context: repository root.
#   docker build -f attest-sidecar/Dockerfile -t attest-sidecar .
# Base images pinned by digest (resolved 2026-11-26, see docs/DECISIONS.md D-021).
FROM docker.io/library/rust:1.97-slim-bookworm@sha256:2775a09d208ff0d7c1f50490c45b62db929e87ba1dcbc3f2132ac71a704bcdd3 AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p attest-sidecar

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=build /src/target/release/attest-sidecar /attest-sidecar
ENTRYPOINT ["/attest-sidecar"]
