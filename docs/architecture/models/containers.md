# Container Model

Status: Implemented.

```mermaid
graph LR
    User[User: Analyst]
    Author[User: Plugin Author]

    subgraph Repo[Repository Runtime Containers]
        C1[CLI Container\ncrates/cli\nRust\nImplemented]
        C4[Core Application Container\ncrates/core\nRust\nImplemented]
        C5[Runtime Execution Container\ncrates/plugin_runtime\nRust/Wasmtime\nImplemented]
        C6[Plugin SDK Container\ncrates/plugin_sdk\nRust\nImplemented]
    end

    D1[(Contracts Store\ncontracts/)]
    D2[(Plugin Package Store\nplugins/<name>/)]
    D3[(Quarantine Store\nquarantine/)]
    D4[(Telemetry Log\nartifacts/runtime-events.jsonl)]
    D5[(CI Workflow\n.github/workflows/ci.yml)]

    User --> C1
    C1 --> C4
    C4 -->|PluginExecutor trait| C5
    C5 --> D1
    C5 --> D2
    C5 --> D3
    C5 --> D4

    Author --> C6
    Author --> D2
    C6 --> D1

    D5 -.validates.-> C1
    D5 -.validates.-> C4
    D5 -.validates.-> C5
    D5 -.validates.-> C6
```

## Container Responsibilities

- CLI container: argument parsing, command dispatch, result rendering.
- Core container: request normalization and domain orchestration.
- Runtime container: validation, policy enforcement, Wasmtime execution, telemetry, and quarantine.
- SDK container: plugin-author contract validation and typed ABI models.
