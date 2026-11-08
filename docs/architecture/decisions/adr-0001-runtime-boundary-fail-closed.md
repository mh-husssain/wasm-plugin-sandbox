# ADR-0001: Runtime Boundary and Fail-Closed Plugin Enforcement

Status: Accepted
Date: 2026-04-01

## Context

The platform executes untrusted plugin packages that can influence malware analysis outcomes. Plugin packages include manifest metadata and WASM entrypoint binaries, both of which may be malformed or malicious.

## Decision

Establish crates/plugin_runtime as the exclusive plugin execution boundary and enforce fail-closed validation before any execution.

Mandatory runtime enforcement sequence:
1. Manifest schema validation.
2. Entry identity and path constraints.
3. Entrypoint integrity hashing.
4. Ed25519 signature verification against trusted signers.
5. Host-plugin compatibility checks.
6. Capability policy enforcement.
7. Module structure and import/export constraints.
8. Bounded execution with memory and timeout budgets.

Operational controls:
- Emit runtime telemetry for both success and failure phases.
- Record quarantine snapshots for policy and validation violations.

## Consequences

Positive:
- Strong trust boundary around plugin execution.
- Auditable denial path with operational diagnostics.
- Consistent cross-layer failure semantics.

Trade-offs:
- Additional startup and validation overhead.
- Requirement for managed trusted signer lifecycle.

## Alternatives Considered

1. Trust plugin packages by source location only.
- Rejected due to weak provenance guarantees.

2. Soft-fail validation with warning-only execution.
- Rejected because it allows unsafe execution paths.

3. Embed runtime policy decisions in adapters.
- Rejected because it breaks core/runtime boundary ownership.

## Follow-Up

- Add further ADRs as new adapters are introduced.
