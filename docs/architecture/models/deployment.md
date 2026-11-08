# Deployment Model

Status: Implemented for local Rust development and CI.

## Local Development Topology

```mermaid
graph LR
    Dev[Developer Workstation]
    Repo[Repository Working Copy]
    CLI[malware-cli process]
    Runtime[WasmPluginRuntime]
    Plugins[plugins/<name>/\nmanifest + wasm]
    Contracts[contracts/*]
    Telemetry[artifacts/runtime-events.jsonl]
    Quarantine[quarantine/]

    Dev --> Repo
    Dev --> CLI
    CLI --> Runtime
    Runtime --> Plugins
    Runtime --> Contracts
    Runtime --> Telemetry
    Runtime --> Quarantine
```

## CI Topology

```mermaid
graph TD
    Trigger[Push to main or Pull Request]

    subgraph Validation[Job: check]
        Fmt[cargo fmt --check]
        Lint[cargo clippy -D warnings]
        Test[cargo test --workspace --locked]
    end

    Audit[Job: RustSec advisory audit]

    Trigger --> Validation
    Trigger --> Audit
```

## Deployment Assertions

- The Rust toolchain is pinned in rust-toolchain.toml and dependencies resolve from the committed Cargo.lock.
- Runtime paths (contracts/, plugins/, quarantine/, artifacts/) are resolved relative to the working directory.
