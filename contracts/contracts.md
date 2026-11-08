# contracts Directory Guide

## Purpose
Stores host-plugin contract definitions used by the WASM plugin model.

## Current Artifacts
- analysis.wit: initial contract skeleton for plugin lifecycle.
- versioning-policy.md: semantic version compatibility rules.
- plugin-manifest.schema.json: canonical plugin package schema.
- capability-matrix.md: host-approved capability catalogue.
- trusted-signers.example.json: bootstrap template for trusted Ed25519 signer keys.
- runtime-event.schema.json: machine-readable schema for runtime telemetry JSONL events.

## Notes
- Interface baseline now defines typed request/response records in `analysis.wit` (`analysis-request` and `analysis-response`).
- Contract changes must update WIT, schema, and capability docs together.
- Runtime manifest loading enforces this schema and compatibility policy before execution.
- Runtime also enforces entrypoint artifact integrity via manifest SHA-256 hash checks.
- Runtime signature verification can load trusted keys from `contracts/trusted-signers.json`.
- Override trust-store path with `MALWARE_TRUSTED_SIGNERS_FILE` if needed.
- Legacy single-key fallback remains supported through `MALWARE_TRUSTED_ED25519_PUBKEY_HEX`.
- Trusted signers support rotation windows via RFC3339 `not_before` and `not_after` fields.
- Runtime ABI execution currently prefers structured Wasm exports (`analyze_risk_v1`, optional `analyze_confidence_v1`, optional `analyze_verdict_v1`) and falls back to legacy `analyze_risk` for compatibility.
- Runtime package validation enforces export contract shape before publish via CLI (`malware-cli validate-package --plugin <name>`).
- Runtime telemetry events include explicit `event_version` for schema evolution (`1.0.0` baseline).

## Source-of-Truth Hierarchy
1. `analysis.wit` for callable host-plugin interface shape.
2. `plugin-manifest.schema.json` for package metadata validation.
3. `capability-matrix.md` for capability namespace and default policy.
