# Dynamic Model: CLI Analysis Flow

Entry Point: crates/cli/src/main.rs run command
Status: Implemented

```mermaid
sequenceDiagram
    participant U as Analyst
    participant CLI as malware-cli
    participant Core as AnalysisService
    participant Runtime as WasmPluginRuntime
    participant Loader as PluginLoader
    participant Policy as SandboxPolicy
    participant Engine as Wasmtime
    participant Artifacts as Telemetry + Quarantine

    U->>CLI: run --plugin <name> --sample <path>
    CLI->>Core: execute_run(AnalysisRequest)
    Core->>Core: validate sample_path + normalize payload
    Core->>Runtime: PluginExecutor.execute(plugin, input)

    Runtime->>Policy: validate numeric limits
    alt policy invalid
        Runtime->>Artifacts: telemetry failure
        Runtime-->>Core: CoreError::RuntimeUnavailable
        Core-->>CLI: error
        CLI-->>U: exit 1
    end

    Runtime->>Loader: load_manifest(plugin)
    Loader->>Loader: schema + integrity + signature verification
    alt manifest/integrity/signature failure
        Runtime->>Artifacts: quarantine + telemetry
        Runtime-->>Core: CoreError::PluginFailure
        Core-->>CLI: error
        CLI-->>U: exit 1
    end

    Runtime->>Runtime: compatibility + capability checks
    alt compatibility/policy denied
        Runtime->>Artifacts: quarantine + telemetry
        Runtime-->>Core: CoreError
        Core-->>CLI: error
        CLI-->>U: exit 1
    end

    Runtime->>Engine: parse module + enforce import/export constraints
    Runtime->>Engine: instantiate with memory/fuel bounds
    Runtime->>Engine: call analyze_risk_v1(...) or analyze_risk()

    alt execution failure or timeout
        Runtime->>Artifacts: quarantine + telemetry
        Runtime-->>Core: CoreError
        Core-->>CLI: error
        CLI-->>U: exit 1
    else success
        Runtime->>Artifacts: telemetry success
        Runtime-->>Core: structured JSON output
        Core-->>CLI: AnalysisResult
        CLI-->>U: summary + risk_score
    end
```

## Notes

- validate-package follows the same validation stages but stops before analysis execution.
- Structured ABI is preferred; legacy scalar ABI is supported as compatibility fallback.
