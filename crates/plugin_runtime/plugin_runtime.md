# plugin_runtime Crate Guide

## Purpose
Implements the PluginExecutor port using a WASM runtime backend.

## Module Map
- `loader`: resolves plugin package locations and manifest paths.
- `manifest`: runtime representation of package metadata.
- `compatibility`: host/plugin API compatibility checks.
- `sandbox_policy`: runtime safety limits and policy defaults.
- `executor`: orchestration point for runtime execution flow.
- `quarantine`: violation snapshot writer for failed validation/policy/runtime phases.
- `telemetry`: JSONL runtime event logger for success/failure audit trail.

## Responsibilities
- Resolve plugin artifacts and manifests.
- Enforce runtime isolation and execution policies.
- Translate runtime errors into core errors.

## Status
- Architecture skeleton complete for runtime boundaries.
- Manifest loading is wired to schema-driven validation against `contracts/plugin-manifest.schema.json`.
- Compatibility checks enforce semver policy for `api_version` and `manifest_version`.
- Runtime executes validated WASM modules via Wasmtime and prefers structured ABI exports:
	- required: `analyze_risk_v1(sample_size_bytes, static_signal_count, dynamic_signal_count) -> i32`
	- optional: `analyze_confidence_v1(...) -> i32`
	- optional: `analyze_verdict_v1(...) -> i32`
- Runtime keeps compatibility fallback for legacy `analyze_risk() -> i32` plugins.
- Runtime emits structured analysis envelope data in output (`analysis.request` and `analysis.response`).
- Runtime import policy is fail-closed: host imports are denied unless explicitly approved.
- Sandbox policy now enforces capability gates (`net.egress` allow/deny), execution timeout, and memory limits.
- Runtime enforces fail-closed plugin signature verification using Ed25519.
- Trusted verification key must be configured via `MALWARE_TRUSTED_ED25519_PUBKEY_HEX`.
- Preferred trusted signer source is `contracts/trusted-signers.json`.
- Optional override path can be set with `MALWARE_TRUSTED_SIGNERS_FILE`.
- Runtime falls back to `MALWARE_TRUSTED_ED25519_PUBKEY_HEX` only when no signer file is configured.
- Runtime exposes package validation API (`validate_plugin_package`) used by CLI pre-publish checks.
- Runtime quarantines failed plugin attempts under `quarantine/<plugin-name>/`.
- Runtime emits event telemetry to `artifacts/runtime-events.jsonl`.
- Telemetry path can be overridden via `MALWARE_RUNTIME_EVENT_LOG`.
- Telemetry event shape is contract-defined by `contracts/runtime-event.schema.json`.
- Telemetry events include `event_version` for forward-compatible ingestion.
- Package validation reports now emit per-check diagnostics and remediation hints.

## Operational Baseline
- Validation, compatibility, policy, and execution failures are fail-closed.
- Every failure emits telemetry and creates a quarantine record for auditability.
- Integration tests enforce baseline runtime budgets for cold start and execution latency.
