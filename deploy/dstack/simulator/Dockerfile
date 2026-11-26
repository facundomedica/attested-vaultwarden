# dstack guest-agent SIMULATOR, built from a pinned upstream commit.
#
# It serves the guest-agent socket with a RECORDED real TDX quote whose
# report_data is patched to the caller's value (patch_report_data = true),
# so the quote signature does NOT verify. Use: wire-protocol and fail-closed
# tests of the sidecar's Dstack provider and the verifier. Never evidence.
FROM docker.io/library/rust:1.97-slim-bookworm@sha256:2775a09d208ff0d7c1f50490c45b62db929e87ba1dcbc3f2132ac71a704bcdd3 AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
      git ca-certificates pkg-config libssl-dev protobuf-compiler clang cmake make \
    && rm -rf /var/lib/apt/lists/*
ARG DSTACK_COMMIT=73b10c6774f5cde355f002326cbf96da93278995
WORKDIR /src
RUN git init -q dstack && cd dstack \
    && git remote add origin https://github.com/Dstack-TEE/dstack.git \
    && git fetch -q --depth 1 origin "$DSTACK_COMMIT" \
    && git checkout -q FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "$DSTACK_COMMIT" \
    && rm -f rust-toolchain.toml
WORKDIR /src/dstack
RUN cargo build --manifest-path dstack/Cargo.toml --release --locked -p dstack-guest-agent-simulator

FROM docker.io/library/debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/dstack/dstack/target/release/dstack-simulator /usr/local/bin/dstack-simulator
COPY --from=build /src/dstack/sdk/simulator/attestation.bin /sim/attestation.bin
COPY --from=build /src/dstack/sdk/simulator/appkeys.json /sim/appkeys.json
COPY --from=build /src/dstack/sdk/simulator/sys-config.json /sim/sys-config.json
COPY dstack.toml /sim/dstack.toml
WORKDIR /sim
ENTRYPOINT ["/usr/local/bin/dstack-simulator", "--config", "/sim/dstack.toml"]
