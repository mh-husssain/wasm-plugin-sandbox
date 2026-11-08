#!/usr/bin/env bash
set -euo pipefail

VERIFY="false"
if [[ "${1:-}" == "--verify" ]]; then
  VERIFY="true"
fi

echo "[bootstrap] validating required tools"
command -v rustup >/dev/null 2>&1 || { echo "rustup is required. Install from https://rustup.rs/"; exit 1; }
command -v cargo >/dev/null 2>&1 || { echo "cargo is required. Ensure Rust is installed and on PATH."; exit 1; }

echo "[bootstrap] installing pinned toolchain and required components"
rustup show active-toolchain >/dev/null
rustup component add rustfmt clippy

echo "[bootstrap] prefetching dependencies with lockfile"
cargo fetch --locked

if [[ "$VERIFY" == "true" ]]; then
  echo "[bootstrap] running workspace verification gates"
  cargo check --workspace --locked
  cargo test --workspace --locked
fi

echo "[bootstrap] environment ready"
