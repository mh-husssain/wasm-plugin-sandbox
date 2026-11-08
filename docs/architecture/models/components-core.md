# Component Model: Core Container

Container: crates/core
Status: Implemented

```mermaid
graph TD
    A[AnalysisService\napplication.rs]
    B[AnalysisRequest / AnalysisResult\ndto.rs]
    C[AnalysisIntent\ndomain.rs]
    D[CoreError\nerrors.rs]
    E[PluginExecutor trait\nports.rs]

    CLI[CLI Adapter\ncrates/cli]
    Runtime[WasmPluginRuntime\ncrates/plugin_runtime]

    CLI --> A

    A --> B
    A --> C
    A --> D
    A --> E
    E -.implemented by.-> Runtime
```

## Behavioral Notes

- AnalysisService validates sample_path non-emptiness before runtime delegation.
- Input payload is normalized to ensure sample_path exists before executor call.
- Runtime output is normalized to stable AnalysisResult fields (summary, risk_score, raw_output).
- Core depends on abstraction (PluginExecutor), not runtime concrete types.
