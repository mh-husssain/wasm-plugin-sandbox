param(
    [switch]$Verify
)

$ErrorActionPreference = "Stop"

Write-Host "[bootstrap] validating required tools"
if (-not (Get-Command rustup -ErrorAction SilentlyContinue)) {
    throw "rustup is required. Install from https://rustup.rs/ and re-run."
}
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw "cargo is required. Ensure Rust is installed and on PATH."
}

Write-Host "[bootstrap] installing pinned toolchain and required components"
rustup show active-toolchain | Out-Null
rustup component add rustfmt clippy

Write-Host "[bootstrap] prefetching dependencies with lockfile"
cargo fetch --locked

if ($Verify) {
    Write-Host "[bootstrap] running workspace verification gates"
    cargo check --workspace --locked
    cargo test --workspace --locked
}

Write-Host "[bootstrap] environment ready"
