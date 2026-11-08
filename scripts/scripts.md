# scripts Directory Guide

## Purpose
Holds repository automation scripts for local development and onboarding.

## Files
- `bootstrap_env.sh`: one-command bootstrap for Linux/macOS.
- `bootstrap_env.ps1`: one-command bootstrap for Windows PowerShell.

## Bootstrap Usage
- Linux/macOS: `./scripts/bootstrap_env.sh`
- Linux/macOS (with verification): `./scripts/bootstrap_env.sh --verify`
- Windows PowerShell: `./scripts/bootstrap_env.ps1`
- Windows PowerShell (with verification): `./scripts/bootstrap_env.ps1 -Verify`

## Behavior
- Verifies required tooling (`rustup`, `cargo`).
- Ensures `rustfmt` and `clippy` components are installed.
- Prefetches dependencies with lockfile enforcement (`cargo fetch --locked`).
- Optionally runs workspace checks and tests.
