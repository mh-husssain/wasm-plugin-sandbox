# Context Model

Status: Implemented (CLI, core, runtime and SDK).

## Scope

The system is a Rust-first malware analysis platform where execution of untrusted plugin packages is mediated by a runtime adapter with fail-closed validation and sandbox policy checks.

```mermaid
graph TD
    Analyst[Security Analyst]
    PluginAuthor[Plugin Author]
    Maintainer[Repository Maintainer]
    CI[GitHub Actions CI]

    subgraph System[Automated Malware Deobfuscation Platform]
        CLI[CLI Adapter\ncrates/cli\nImplemented]
        Core[Core Domain Service\ncrates/core\nImplemented]
        Runtime[WASM Plugin Runtime\ncrates/plugin_runtime\nImplemented]
        SDK[Plugin SDK\ncrates/plugin_sdk\nImplemented]
        Contracts[Contracts and Policy\ncontracts/\nImplemented]
    end

    PluginPkg[Plugin Package\nplugins/<name>/manifest.json + wasm]
    Quarantine[Quarantine Artifacts\nquarantine/]
    Telemetry[Runtime Events\nartifacts/runtime-events.jsonl]

    Analyst -->|run / validate-package| CLI
    CLI --> Core
    Core -->|PluginExecutor port| Runtime
    Runtime --> PluginPkg
    Runtime --> Quarantine
    Runtime --> Telemetry

    PluginAuthor -->|builds plugins against| SDK
    PluginAuthor -->|publishes package| PluginPkg
    Maintainer -->|updates| Contracts
    CI -->|format, lint, test\ndependency audit| System
```

## Key Context Assertions

- Plugin artifacts are untrusted by default and must pass manifest, compatibility, integrity, signature, and policy checks before execution.
- CI enforces formatting, lints, tests against the lockfile, and a dependency vulnerability audit.
