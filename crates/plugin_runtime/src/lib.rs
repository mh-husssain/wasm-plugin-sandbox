//! Wasmtime-backed runtime adapter implementing plugin loading, validation, and execution.
//!
//! The runtime is designed to be fail-closed and emits quarantine plus telemetry artifacts
//! for validation and execution failures.

#![warn(missing_docs)]

mod compatibility;
mod executor;
mod loader;
mod manifest;
mod quarantine;
mod sandbox_policy;
mod telemetry;

use crate::compatibility::CompatibilityChecker;
use crate::executor::RuntimeExecutor;
use crate::loader::PluginLoader;
use malware_core::{CoreError, PluginExecutor};
use serde_json::Value;

/// Structured output returned by `validate-package` success/failure paths.
pub use crate::executor::PackageValidationReport;
/// Per-check validation diagnostic entry with remediation guidance.
pub use crate::executor::ValidationCheck;
/// Decoded plugin package manifest.
pub use crate::manifest::PluginManifest;
/// Runtime sandbox limits and capability policy.
pub use crate::sandbox_policy::SandboxPolicy;

/// Runtime adapter implementing [`PluginExecutor`] using Wasmtime.
pub struct WasmPluginRuntime {
    executor: RuntimeExecutor,
}

impl WasmPluginRuntime {
    /// Creates a runtime using default sandbox policy values.
    ///
    /// # Returns
    /// A runtime instance ready to validate and execute plugins.
    pub fn new() -> Self {
        Self::with_policy(SandboxPolicy::default())
    }

    /// Creates a runtime with an explicit sandbox policy.
    ///
    /// # Arguments
    /// - `policy`: Resource and capability constraints to apply during execution.
    ///
    /// # Returns
    /// A runtime configured with the provided policy.
    pub fn with_policy(policy: SandboxPolicy) -> Self {
        let loader = PluginLoader::new();
        let compatibility = CompatibilityChecker::default();
        let executor = RuntimeExecutor::new(loader, policy, compatibility);
        Self { executor }
    }

    /// Validates a plugin package without executing plugin analysis code.
    ///
    /// # Arguments
    /// - `plugin_name`: Name of plugin package under `plugins/<name>/`.
    ///
    /// # Returns
    /// A [`PackageValidationReport`] containing status and check diagnostics.
    ///
    /// # Errors
    /// Returns [`CoreError`] when manifest, compatibility, policy, or module checks fail.
    pub fn validate_plugin_package(
        &self,
        plugin_name: &str,
    ) -> Result<PackageValidationReport, CoreError> {
        self.executor.validate_plugin_package(plugin_name)
    }
}

impl Default for WasmPluginRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginExecutor for WasmPluginRuntime {
    /// Executes plugin analysis with runtime validation and sandboxing.
    ///
    /// # Arguments
    /// - `plugin_name`: Plugin package to execute.
    /// - `input`: JSON input payload consumed by ABI extraction.
    ///
    /// # Returns
    /// JSON result containing summary, risk score, metadata, and analysis payload.
    ///
    /// # Errors
    /// Returns [`CoreError`] for validation failures, policy denials, or execution failures.
    fn execute(&self, plugin_name: &str, input: &Value) -> Result<Value, CoreError> {
        self.executor.execute(plugin_name, input)
    }
}
