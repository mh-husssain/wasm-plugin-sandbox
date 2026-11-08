use crate::compatibility::CompatibilityChecker;
use crate::loader::PluginLoader;
use crate::manifest::PluginManifest;
use crate::quarantine::QuarantineManager;
use crate::sandbox_policy::SandboxPolicy;
use crate::telemetry::RuntimeTelemetry;
use malware_core::CoreError;
use serde::Serialize;
use serde_json::{json, Value};
use std::fs;
use wasmtime::{Config, Engine, Instance, Linker, Module, Store, StoreLimits, StoreLimitsBuilder};
use wasmtime::{ExternType, ValType};

const FUEL_UNITS_PER_MS: u64 = 100_000;

#[derive(Debug, Clone, Serialize)]
struct AnalysisRequestAbi {
    sample_size_bytes: u32,
    static_signal_count: u32,
    dynamic_signal_count: u32,
}

#[derive(Debug, Clone, Serialize)]
struct AnalysisResponseAbi {
    risk_score: f64,
    confidence: f64,
    verdict: &'static str,
    summary: String,
    abi_mode: &'static str,
}

/// Core runtime executor implementing validation and WASM invocation flow.
pub struct RuntimeExecutor {
    loader: PluginLoader,
    policy: SandboxPolicy,
    compatibility: CompatibilityChecker,
    quarantine: QuarantineManager,
    telemetry: RuntimeTelemetry,
}

/// Per-check validation diagnostic entry emitted by package validation.
#[derive(Debug, Clone, Serialize)]
pub struct ValidationCheck {
    /// Check identifier.
    pub check: &'static str,
    /// Check status (`pass` or `fail`).
    pub status: &'static str,
    /// Human-readable detail for the check result.
    pub detail: String,
    /// Recommended remediation action.
    pub remediation: &'static str,
}

/// Summary report returned by package validation operations.
#[derive(Debug, Clone, Serialize)]
pub struct PackageValidationReport {
    /// Plugin package name.
    pub plugin_name: String,
    /// Overall status (`valid` or `invalid`).
    pub status: &'static str,
    /// Plugin API channel version.
    pub api_version: String,
    /// Plugin manifest channel version.
    pub manifest_version: String,
    /// Ordered list of per-check diagnostics.
    pub checks: Vec<ValidationCheck>,
}

impl PackageValidationReport {
    fn passed(
        plugin_name: &str,
        api_version: String,
        manifest_version: String,
        checks: Vec<ValidationCheck>,
    ) -> Self {
        Self {
            plugin_name: plugin_name.to_string(),
            status: "valid",
            api_version,
            manifest_version,
            checks,
        }
    }

    /// Creates an invalid report from a runtime error with remediation hints.
    ///
    /// # Arguments
    /// - `plugin_name`: Plugin package name.
    /// - `error`: Runtime error to classify.
    ///
    /// # Returns
    /// An `invalid` validation report with a synthesized failing check entry.
    pub fn from_error(plugin_name: &str, error: &CoreError) -> Self {
        let error_text = error.to_string();
        let (check, remediation) = classify_validation_failure(&error_text);

        Self {
            plugin_name: plugin_name.to_string(),
            status: "invalid",
            api_version: "unknown".to_string(),
            manifest_version: "unknown".to_string(),
            checks: vec![ValidationCheck {
                check,
                status: "fail",
                detail: error_text,
                remediation,
            }],
        }
    }
}

impl RuntimeExecutor {
    /// Creates a runtime executor from pluggable policy and validation dependencies.
    ///
    /// # Arguments
    /// - `loader`: Plugin manifest and integrity loader.
    /// - `policy`: Sandbox policy constraints.
    /// - `compatibility`: Version compatibility checker.
    ///
    /// # Returns
    /// A runtime executor instance.
    pub fn new(
        loader: PluginLoader,
        policy: SandboxPolicy,
        compatibility: CompatibilityChecker,
    ) -> Self {
        let telemetry_path = std::env::var("MALWARE_RUNTIME_EVENT_LOG")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::PathBuf::from("artifacts/runtime-events.jsonl"));

        Self {
            loader,
            policy,
            compatibility,
            quarantine: QuarantineManager::new(std::path::PathBuf::from("quarantine")),
            telemetry: RuntimeTelemetry::new(telemetry_path),
        }
    }

    /// Validates and executes a plugin against an input payload.
    ///
    /// # Arguments
    /// - `plugin_name`: Plugin package name.
    /// - `input`: JSON payload to map into ABI request fields.
    ///
    /// # Returns
    /// Structured JSON output containing summary, score, and metadata.
    ///
    /// # Errors
    /// Returns [`CoreError`] when policy, manifest, compatibility, module, or runtime checks fail.
    pub fn execute(&self, plugin_name: &str, input: &Value) -> Result<Value, CoreError> {
        if !self.policy.is_valid() {
            let error = CoreError::RuntimeUnavailable(
                "sandbox policy is invalid: memory and timeout must both be greater than zero"
                    .to_string(),
            );
            self.telemetry.emit(plugin_name, "policy", "denied", &error.to_string());
            return Err(error);
        }

        let manifest = match self.loader.load_manifest(plugin_name) {
            Ok(manifest) => manifest,
            Err(error) => {
                self.handle_violation(plugin_name, "manifest-validation", &error);
                return Err(error);
            }
        };

        if let Err(error) = self.compatibility.validate(&manifest) {
            self.handle_violation(plugin_name, "compatibility", &error);
            return Err(error);
        }

        if let Err(error) = self.enforce_policy(&manifest) {
            self.handle_violation(plugin_name, "capability-policy", &error);
            return Err(error);
        }

        match self.execute_wasm_module(plugin_name, &manifest, input) {
            Ok(output) => {
                self.telemetry.emit(
                    plugin_name,
                    "execution",
                    "success",
                    "plugin execution completed",
                );
                Ok(output)
            }
            Err(error) => {
                self.handle_violation(plugin_name, "runtime-execution", &error);
                Err(error)
            }
        }
    }

    /// Validates plugin packaging and ABI contract checks without executing analysis logic.
    ///
    /// # Arguments
    /// - `plugin_name`: Plugin package name.
    ///
    /// # Returns
    /// Validation report with pass/fail check diagnostics.
    ///
    /// # Errors
    /// Returns [`CoreError`] when any validation step fails.
    pub fn validate_plugin_package(
        &self,
        plugin_name: &str,
    ) -> Result<PackageValidationReport, CoreError> {
        let mut checks = Vec::new();

        let manifest = match self.loader.load_manifest(plugin_name) {
            Ok(manifest) => manifest,
            Err(error) => {
                self.handle_violation(plugin_name, "manifest-validation", &error);
                return Err(error);
            }
        };
        checks.push(ValidationCheck {
            check: "manifest-validation",
            status: "pass",
            detail: "manifest loaded and signature/integrity checks passed".to_string(),
            remediation: "none",
        });

        if let Err(error) = self.compatibility.validate(&manifest) {
            self.handle_violation(plugin_name, "compatibility", &error);
            return Err(error);
        }
        checks.push(ValidationCheck {
            check: "compatibility",
            status: "pass",
            detail: "api_version and manifest_version are host-compatible".to_string(),
            remediation: "none",
        });

        if let Err(error) = self.enforce_policy(&manifest) {
            self.handle_violation(plugin_name, "capability-policy", &error);
            return Err(error);
        }
        checks.push(ValidationCheck {
            check: "capability-policy",
            status: "pass",
            detail: "requested capabilities are allowed by runtime policy".to_string(),
            remediation: "none",
        });

        self.validate_module_structure(plugin_name, &manifest)?;
        checks.push(ValidationCheck {
            check: "module-structure-and-signatures",
            status: "pass",
            detail: "wasm module imports/exports and required entrypoint signatures are valid"
                .to_string(),
            remediation: "none",
        });

        self.telemetry.emit(
            plugin_name,
            "package-validation",
            "success",
            "package validation completed",
        );

        Ok(PackageValidationReport::passed(
            plugin_name,
            manifest.api_version,
            manifest.manifest_version,
            checks,
        ))
    }

    fn enforce_policy(&self, manifest: &PluginManifest) -> Result<(), CoreError> {
        for capability in &manifest.capabilities {
            if !self.policy.allows_capability(capability) {
                return Err(CoreError::PluginFailure(format!(
                    "plugin '{}' requests capability '{}' that is blocked by sandbox policy",
                    manifest.id(),
                    capability
                )));
            }
        }

        Ok(())
    }

    fn execute_wasm_module(
        &self,
        plugin_name: &str,
        manifest: &PluginManifest,
        input: &Value,
    ) -> Result<Value, CoreError> {
        let entrypoint_path =
            std::path::Path::new("plugins").join(plugin_name).join(&manifest.entrypoint);

        let wasm_bytes = fs::read(&entrypoint_path).map_err(|error| {
            CoreError::PluginFailure(format!(
                "failed to read entrypoint '{}': {}",
                entrypoint_path.display(),
                error
            ))
        })?;

        let mut config = Config::new();
        config.consume_fuel(true);
        let engine = Engine::new(&config).map_err(|error| {
            CoreError::RuntimeUnavailable(format!("failed to initialize wasm engine: {}", error))
        })?;

        let memory_limit = usize::try_from(self.policy.max_memory_bytes).map_err(|_| {
            CoreError::RuntimeUnavailable(format!(
                "sandbox memory limit '{}' cannot fit platform usize",
                self.policy.max_memory_bytes
            ))
        })?;

        let module = Module::from_binary(&engine, &wasm_bytes).map_err(|error| {
            CoreError::PluginFailure(format!(
                "failed to parse wasm module '{}': {}",
                entrypoint_path.display(),
                error
            ))
        })?;

        self.validate_module_constraints(&module, manifest)?;

        self.enforce_import_policy(&module, manifest)?;

        let store_limits: StoreLimits = StoreLimitsBuilder::new().memory_size(memory_limit).build();
        let mut store = Store::new(&engine, store_limits);
        store.limiter(|limits| limits);

        let fuel_budget = self.policy.max_execution_ms.saturating_mul(FUEL_UNITS_PER_MS);
        store.set_fuel(fuel_budget).map_err(|error| {
            CoreError::RuntimeUnavailable(format!(
                "failed to configure execution fuel budget '{}': {}",
                fuel_budget, error
            ))
        })?;

        let linker = Linker::new(&engine);
        let instance = linker.instantiate(&mut store, &module).map_err(|error| {
            CoreError::RuntimeUnavailable(format!(
                "failed to instantiate plugin '{}': {}",
                manifest.id(),
                error
            ))
        })?;

        let request = extract_request_abi(input);
        let response = call_analyze_risk(
            &mut store,
            &instance,
            manifest,
            self.policy.max_execution_ms,
            &request,
        )?;

        let memory_limit = self.policy.max_memory_bytes;
        let time_limit = self.policy.max_execution_ms;
        let network_allowed = self.policy.allow_network;

        Ok(json!({
            "summary": response.summary,
            "risk_score": response.risk_score,
            "metadata": {
                "plugin_id": manifest.id(),
                "policy": {
                    "memory_limit_bytes": memory_limit,
                    "timeout_ms": time_limit,
                    "network_allowed": network_allowed
                }
            },
            "analysis": {
                "request": request,
                "response": {
                    "risk_score": response.risk_score,
                    "confidence": response.confidence,
                    "verdict": response.verdict,
                    "abi_mode": response.abi_mode
                }
            }
        }))
    }

    fn validate_module_structure(
        &self,
        plugin_name: &str,
        manifest: &PluginManifest,
    ) -> Result<(), CoreError> {
        let entrypoint_path =
            std::path::Path::new("plugins").join(plugin_name).join(&manifest.entrypoint);

        let wasm_bytes = fs::read(&entrypoint_path).map_err(|error| {
            CoreError::PluginFailure(format!(
                "failed to read entrypoint '{}': {}",
                entrypoint_path.display(),
                error
            ))
        })?;

        let engine = Engine::default();
        let module = Module::from_binary(&engine, &wasm_bytes).map_err(|error| {
            CoreError::PluginFailure(format!(
                "failed to parse wasm module '{}': {}",
                entrypoint_path.display(),
                error
            ))
        })?;

        self.validate_module_constraints(&module, manifest)?;
        self.enforce_import_policy(&module, manifest)?;
        self.validate_export_signatures(&module, manifest)
    }

    fn validate_module_constraints(
        &self,
        module: &Module,
        manifest: &PluginManifest,
    ) -> Result<(), CoreError> {
        let memory_count =
            module.imports().filter(|import| matches!(import.ty(), ExternType::Memory(_))).count()
                + module
                    .exports()
                    .filter(|export| matches!(export.ty(), ExternType::Memory(_)))
                    .count();

        if memory_count > 1 {
            return Err(CoreError::PluginFailure(format!(
                "plugin '{}' declares {} memories; at most one memory is allowed",
                manifest.id(),
                memory_count
            )));
        }

        Ok(())
    }

    fn validate_export_signatures(
        &self,
        module: &Module,
        manifest: &PluginManifest,
    ) -> Result<(), CoreError> {
        let has_structured = has_export_signature(
            module,
            "analyze_risk_v1",
            &[ValType::I32, ValType::I32, ValType::I32],
            &[ValType::I32],
        );
        let has_legacy = has_export_signature(module, "analyze_risk", &[], &[ValType::I32]);

        if !has_structured && !has_legacy {
            return Err(CoreError::PluginFailure(format!(
                "plugin '{}' must export either structured 'analyze_risk_v1(i32,i32,i32)->i32' or legacy 'analyze_risk()->i32'",
                manifest.id()
            )));
        }

        if has_export_named(module, "analyze_risk_v1") && !has_structured {
            return Err(CoreError::PluginFailure(format!(
                "plugin '{}' export 'analyze_risk_v1' has invalid signature; expected (i32, i32, i32) -> i32",
                manifest.id()
            )));
        }

        if has_export_named(module, "analyze_risk") && !has_legacy {
            return Err(CoreError::PluginFailure(format!(
                "plugin '{}' export 'analyze_risk' has invalid signature; expected () -> i32",
                manifest.id()
            )));
        }

        Ok(())
    }

    fn enforce_import_policy(
        &self,
        module: &Module,
        manifest: &PluginManifest,
    ) -> Result<(), CoreError> {
        let declared_imports = module
            .imports()
            .map(|import| format!("{}::{}", import.module(), import.name()))
            .collect::<Vec<_>>();

        if declared_imports.is_empty() {
            return Ok(());
        }

        Err(CoreError::PluginFailure(format!(
            "plugin '{}' declares non-approved host imports: {}",
            manifest.id(),
            declared_imports.join(", ")
        )))
    }

    fn handle_violation(&self, plugin_name: &str, phase: &str, error: &CoreError) {
        let message = error.to_string();
        let manifest_path = self.loader.locate_manifest(plugin_name).ok();

        self.telemetry.emit(plugin_name, phase, "failure", &message);
        self.telemetry.emit(plugin_name, "quarantine", "recorded", &message);
        self.quarantine.record_violation(plugin_name, phase, &message, manifest_path.as_deref());
    }
}

fn has_export_named(module: &Module, export_name: &str) -> bool {
    module.exports().any(|export| export.name() == export_name)
}

fn has_export_signature(
    module: &Module,
    export_name: &str,
    params: &[ValType],
    results: &[ValType],
) -> bool {
    module.exports().any(|export| {
        if export.name() != export_name {
            return false;
        }

        let ExternType::Func(function) = export.ty() else {
            return false;
        };

        let actual_params = function.params().collect::<Vec<_>>();
        let actual_results = function.results().collect::<Vec<_>>();

        actual_params.len() == params.len()
            && actual_results.len() == results.len()
            && actual_params
                .iter()
                .zip(params.iter())
                .all(|(actual, expected)| same_valtype(actual, expected))
            && actual_results
                .iter()
                .zip(results.iter())
                .all(|(actual, expected)| same_valtype(actual, expected))
    })
}

fn same_valtype(actual: &ValType, expected: &ValType) -> bool {
    std::mem::discriminant(actual) == std::mem::discriminant(expected)
}

fn extract_request_abi(input: &Value) -> AnalysisRequestAbi {
    AnalysisRequestAbi {
        sample_size_bytes: read_u32(
            input
                .get("sample_size_bytes")
                .or_else(|| input.get("sample").and_then(|sample| sample.get("size_bytes"))),
        ),
        static_signal_count: read_u32(
            input
                .get("signals")
                .and_then(|signals| signals.get("static_count"))
                .or_else(|| input.get("static_signal_count")),
        ),
        dynamic_signal_count: read_u32(
            input
                .get("signals")
                .and_then(|signals| signals.get("dynamic_count"))
                .or_else(|| input.get("dynamic_signal_count")),
        ),
    }
}

fn read_u32(value: Option<&Value>) -> u32 {
    value.and_then(Value::as_u64).and_then(|raw| u32::try_from(raw).ok()).unwrap_or(0)
}

fn call_analyze_risk(
    store: &mut Store<StoreLimits>,
    instance: &Instance,
    manifest: &PluginManifest,
    max_execution_ms: u64,
    request: &AnalysisRequestAbi,
) -> Result<AnalysisResponseAbi, CoreError> {
    let request_tuple = (
        as_i32(request.sample_size_bytes, manifest, "sample_size_bytes")?,
        as_i32(request.static_signal_count, manifest, "static_signal_count")?,
        as_i32(request.dynamic_signal_count, manifest, "dynamic_signal_count")?,
    );

    if let Ok(analyze_structured) =
        instance.get_typed_func::<(i32, i32, i32), i32>(&mut *store, "analyze_risk_v1")
    {
        let risk_basis_points = analyze_structured
            .call(&mut *store, request_tuple)
            .map_err(|error| map_call_error(error, manifest, max_execution_ms))?;
        let risk_score = normalize_basis_points(risk_basis_points, manifest, "risk")?;

        let confidence_basis_points = if let Ok(confidence) =
            instance.get_typed_func::<(i32, i32, i32), i32>(&mut *store, "analyze_confidence_v1")
        {
            confidence
                .call(&mut *store, request_tuple)
                .map_err(|error| map_call_error(error, manifest, max_execution_ms))?
        } else {
            5_000
        };
        let confidence = normalize_basis_points(confidence_basis_points, manifest, "confidence")?;

        let verdict_code = if let Ok(verdict) =
            instance.get_typed_func::<(i32, i32, i32), i32>(&mut *store, "analyze_verdict_v1")
        {
            verdict
                .call(&mut *store, request_tuple)
                .map_err(|error| map_call_error(error, manifest, max_execution_ms))?
        } else {
            verdict_code_from_score(risk_basis_points)
        };

        let verdict = verdict_from_code(verdict_code);
        let summary = format!("plugin '{}' executed (structured ABI)", manifest.id());

        return Ok(AnalysisResponseAbi {
            risk_score,
            confidence,
            verdict,
            summary,
            abi_mode: "structured-v1",
        });
    }

    let analyze_legacy =
        instance.get_typed_func::<(), i32>(&mut *store, "analyze_risk").map_err(|error| {
            CoreError::PluginFailure(format!(
                "plugin '{}' does not expose required function 'analyze_risk_v1(sample_size_bytes, static_signal_count, dynamic_signal_count)' or legacy 'analyze_risk': {}",
                manifest.id(),
                error
            ))
        })?;

    let basis_points = analyze_legacy
        .call(&mut *store, ())
        .map_err(|error| map_call_error(error, manifest, max_execution_ms))?;
    let risk_score = normalize_basis_points(basis_points, manifest, "risk")?;
    let verdict = verdict_from_code(verdict_code_from_score(basis_points));

    Ok(AnalysisResponseAbi {
        risk_score,
        confidence: 0.5,
        verdict,
        summary: format!("plugin '{}' executed (legacy ABI)", manifest.id()),
        abi_mode: "legacy-scalar",
    })
}

fn as_i32(value: u32, manifest: &PluginManifest, field_name: &str) -> Result<i32, CoreError> {
    i32::try_from(value).map_err(|_| {
        CoreError::PluginFailure(format!(
            "plugin '{}' input field '{}' exceeds i32 range",
            manifest.id(),
            field_name
        ))
    })
}

fn normalize_basis_points(
    basis_points: i32,
    manifest: &PluginManifest,
    field_name: &str,
) -> Result<f64, CoreError> {
    if !(0..=10_000).contains(&basis_points) {
        return Err(CoreError::PluginFailure(format!(
            "plugin '{}' returned out-of-range {} basis points {}",
            manifest.id(),
            field_name,
            basis_points
        )));
    }

    Ok(f64::from(basis_points) / 100.0)
}

fn map_call_error(
    error: wasmtime::Error,
    manifest: &PluginManifest,
    max_execution_ms: u64,
) -> CoreError {
    let details = error.to_string();
    if details.contains("all fuel consumed") || details.contains("out of fuel") {
        return CoreError::RuntimeUnavailable(format!(
            "plugin '{}' exceeded execution timeout ({} ms)",
            manifest.id(),
            max_execution_ms
        ));
    }

    CoreError::PluginFailure(format!("plugin '{}' execution failed: {}", manifest.id(), error))
}

fn verdict_code_from_score(score_basis_points: i32) -> i32 {
    match score_basis_points {
        0..=3_299 => 0,
        3_300..=6_699 => 1,
        _ => 2,
    }
}

fn verdict_from_code(code: i32) -> &'static str {
    match code {
        0 => "low",
        1 => "medium",
        _ => "high",
    }
}

fn classify_validation_failure(error_text: &str) -> (&'static str, &'static str) {
    if error_text.contains("schema") || error_text.contains("manifest") {
        return (
            "manifest-validation",
            "Ensure plugins/<name>/manifest.json satisfies contracts/plugin-manifest.schema.json and integrity fields are present.",
        );
    }

    if error_text.contains("signature") || error_text.contains("trusted sign") {
        return (
            "signature-verification",
            "Sign the plugin with an active trusted Ed25519 key and verify contracts/trusted-signers.json configuration.",
        );
    }

    if error_text.contains("major mismatch")
        || error_text.contains("minor")
        || error_text.contains("compat")
    {
        return (
            "compatibility",
            "Align plugin api_version and manifest_version with host baselines from contracts/versioning-policy.md.",
        );
    }

    if error_text.contains("capability") || error_text.contains("blocked by sandbox policy") {
        return (
            "capability-policy",
            "Remove blocked capabilities from the plugin manifest or update sandbox policy if explicitly approved.",
        );
    }

    if error_text.contains("non-approved host imports") {
        return (
            "import-policy",
            "Remove host imports from the module or migrate to approved contract-based plugin interfaces.",
        );
    }

    if error_text.contains("invalid signature") || error_text.contains("must export either") {
        return (
            "export-signatures",
            "Export analyze_risk_v1(i32,i32,i32)->i32 or analyze_risk()->i32 with exact signatures.",
        );
    }

    (
        "runtime-validation",
        "Review runtime validation logs and plugin package layout; rebuild plugin artifact and rerun validate-package.",
    )
}
