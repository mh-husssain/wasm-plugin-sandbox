//! Shared CLI command execution helpers used by the binary entrypoint.

#![warn(missing_docs)]

use malware_core::{AnalysisRequest, AnalysisResult, AnalysisService, CoreError};
use malware_plugin_runtime::{PackageValidationReport, WasmPluginRuntime};
use serde_json::json;

/// Input for `run` command execution.
#[derive(Debug, Clone)]
pub struct RunCommand {
    /// Plugin package name.
    pub plugin: String,
    /// Sample path argument.
    pub sample: String,
}

/// Executes a run command through the core analysis service.
///
/// # Arguments
/// - `service`: Analysis service instance.
/// - `command`: Parsed run command arguments.
///
/// # Returns
/// Analysis result produced by the runtime.
///
/// # Errors
/// Returns [`CoreError`] if request validation or runtime execution fails.
pub fn execute_run(
    service: &AnalysisService,
    command: RunCommand,
) -> Result<AnalysisResult, CoreError> {
    let request = AnalysisRequest {
        sample_path: command.sample,
        plugin_name: command.plugin,
        input: json!({}),
    };

    service.analyze(request)
}

/// Formats run output for terminal rendering.
///
/// # Arguments
/// - `result`: Analysis result to display.
///
/// # Returns
/// Multi-line summary text.
pub fn format_run_output(result: &AnalysisResult) -> String {
    format!("summary: {}\nrisk_score: {}", result.summary, result.risk_score)
}

/// Executes package validation command through runtime validation flow.
///
/// # Arguments
/// - `runtime`: Plugin runtime adapter.
/// - `plugin_name`: Plugin package to validate.
///
/// # Returns
/// Validation report containing status and per-check diagnostics.
///
/// # Errors
/// Returns [`CoreError`] when package validation fails.
pub fn execute_validate_package(
    runtime: &WasmPluginRuntime,
    plugin_name: &str,
) -> Result<PackageValidationReport, CoreError> {
    runtime.validate_plugin_package(plugin_name)
}
