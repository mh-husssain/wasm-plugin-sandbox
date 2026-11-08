# Integration Tests

This workspace package now executes architecture-level integration checks for:
- manifest contract validation (schema + semver channels)
- runtime boundary behavior (manifest loading, integrity checks, compatibility gates)
- runtime execution behavior and sandbox policy enforcement
	- capability gating (`net.egress`)
	- execution timeout
	- memory limit
	- host import policy denial for non-approved imports
	- package validation command/runtime path (`validate_plugin_package`)
	- malformed export signature rejection
	- quarantine and telemetry emission on validation/runtime failures
	- cold start and steady-state latency budget checks

Executable suite:
- `tests/runtime_contracts.rs`
- `tests/cli_core_parity.rs`

Planned next executable slices:
- `contract_compatibility/` scenario matrix expansion
- `runtime_boundaries/` additional WebAssembly structural edge cases as runtime parser policy evolves
- `cli_core_parity/` command-to-core behavior parity tests (executable baseline)
