# dstack-mr, built from the dstack git revision that produced the OS image
# (mkosi-os-v0.6.5 release notes: git revision 350a0a73…). Used to compute
# expected MRTD / RTMR0-2 for a VM shape independently of any running CVM.
FROM docker.io/library/rust:1.97-slim-bookworm@sha256:2775a09d208ff0d7c1f50490c45b62db929e87ba1dcbc3f2132ac71a704bcdd3 AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
      git ca-certificates pkg-config libssl-dev protobuf-compiler clang cmake make \
    && rm -rf /var/lib/apt/lists/*
ARG DSTACK_COMMIT=350a0a73ffdb6041bda69118f13d81591870b565
WORKDIR /src
RUN git init -q dstack && cd dstack \
    && git remote add origin https://github.com/Dstack-TEE/dstack.git \
    && git fetch -q --depth 1 origin "$DSTACK_COMMIT" \
    && git checkout -q FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "$DSTACK_COMMIT" \
    && rm -f rust-toolchain.toml
WORKDIR /src/dstack
RUN cargo build --manifest-path dstack/Cargo.toml --release --locked -p dstack-mr-cli

FROM docker.io/library/debian:bookworm-slim
COPY --from=build /src/dstack/dstack/target/release/dstack-mr /usr/local/bin/dstack-mr
ENTRYPOINT ["/usr/local/bin/dstack-mr"]
