# Contract Versioning Policy

## Scope
Defines host-plugin contract compatibility rules for `contracts/analysis.wit` and related plugin manifest metadata.

## Version Channels
- `api_version`: semantic version for host-plugin callable interface.
- `manifest_version`: semantic version for plugin package metadata schema.

## Compatibility Rules
- Major version mismatch: incompatible, reject plugin.
- Minor version mismatch: allow when plugin minor is less than or equal to host-supported minor for the same major.
- Patch version mismatch: always allowed.

## Host Compatibility Mode
- Current host API baseline: `0.2.0`.
- Current host manifest baseline: `1.0.0`.
- Host must reject manifests with unsupported `manifest_version` major version.
- Host must reject plugins with unsupported `api_version` major version.

## Source of Truth
- Interface shape: `contracts/analysis.wit`.
- Package metadata contract: `contracts/plugin-manifest.schema.json`.
- Capability namespace: `contracts/capability-matrix.md`.

## Initial Baseline
- api_version: `0.2.0`
- manifest_version: `1.0.0`

## Governance
- Any contract change must update:
  - `contracts/analysis.wit`
  - `contracts/plugin-manifest.schema.json`
  - `contracts/capability-matrix.md`
  - relevant runtime and SDK docs
