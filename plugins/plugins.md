# plugins Directory Guide

## Purpose
Holds deployable plugin packages for runtime discovery. No plugins are shipped; the integration tests build and sign their own fixtures.

## Conventions
- Plugin binaries are stored as .wasm files.
- Each plugin includes a manifest with version and capability metadata.
- The plugin directory name must match the manifest `name`.
- Package integrity fields are always required.

## Canonical Package Layout
plugins/
  <plugin-name>/
    manifest.json
    plugin.wasm

## Required Manifest Fields
- `manifest_version`
- `name`
- `version`
- `api_version`
- `entrypoint`
- `capabilities`
- `integrity.sha256`
- `integrity.signature`

## Validation Expectations
- Manifest must satisfy `contracts/plugin-manifest.schema.json`.
- `api_version` must satisfy host compatibility policy.
- Capabilities must be declared in `contracts/capability-matrix.md`.
