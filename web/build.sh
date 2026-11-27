#!/usr/bin/env bash
# Build the browser verifier: web/dist/index.html, one self-contained file
# (verifier wasm, glue, page script, every policy/*.toml and
# web/attested-spkis.txt inlined). Open it from disk or put it on any
# static host.
#
#   web/build.sh            build
#   web/build.sh --check    build twice from scratch outputs and compare
#
# Needs: the Rust toolchain of rust-toolchain / CI (stable) with the
# wasm32-unknown-unknown target, wasm-bindgen-cli 0.2.130 (the version in
# Cargo.lock), node >= 20.
#   rustup target add wasm32-unknown-unknown
#   cargo install wasm-bindgen-cli --version 0.2.130 --locked
#
# Determinism: `cargo --locked`, source and cargo paths remapped out of the
# binary, no timestamps, policies in name order. Same commit + same rustc +
# same wasm-bindgen => same file (checked on one machine with --check; not
# yet compared across machines).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
WASM_BINDGEN_VERSION=0.2.130

have="$(wasm-bindgen --version 2>/dev/null | awk '{print $2}' || true)"
if [ "$have" != "$WASM_BINDGEN_VERSION" ]; then
  echo "need wasm-bindgen-cli $WASM_BINDGEN_VERSION (found: ${have:-none}):" >&2
  echo "  cargo install wasm-bindgen-cli --version $WASM_BINDGEN_VERSION --locked" >&2
  exit 1
fi

commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
# The page embeds policy/, web/ and the verifier sources: say so if they
# differ from the commit.
if ! git diff --quiet HEAD -- policy web verifier common Cargo.toml Cargo.lock 2>/dev/null \
  || [ -n "$(git ls-files --others --exclude-standard -- policy web verifier common 2>/dev/null)" ]; then
  commit="$commit+uncommitted-changes"
fi

build() { # build <out.html> <cargo target dir>
  local out="$1" target="$2" tmp
  tmp="$(mktemp -d)"
  CARGO_TARGET_DIR="$target" \
  RUSTFLAGS="--remap-path-prefix=$root=/src --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=$(rustc --print sysroot)=/rust" \
    cargo build --locked -p attested-vw-web --profile wasm --target wasm32-unknown-unknown
  wasm-bindgen --target no-modules --no-typescript --out-dir "$tmp" \
    "$target/wasm32-unknown-unknown/wasm/attested_vw_web.wasm"
  mkdir -p "$(dirname "$out")"
  node web/assemble.mjs "$tmp/attested_vw_web.js" "$tmp/attested_vw_web_bg.wasm" "$commit" "$out"
  rm -rf "$tmp"
}

build web/dist/index.html "$root/target/web"
if [ "${1:-}" = "--check" ]; then
  second="$(mktemp -d)"
  build "$second/index.html" "$second/target"
  if cmp -s web/dist/index.html "$second/index.html"; then
    echo "reproducible: two independent builds are byte-identical"
    rm -rf "$second"
  else
    echo "NOT reproducible: web/dist/index.html differs from $second/index.html" >&2
    exit 1
  fi
fi
