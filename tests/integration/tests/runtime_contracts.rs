//! Integration tests for runtime contract validation, execution safety, and policy behavior.

use ed25519_dalek::{Signer, SigningKey};
use malware_core::PluginExecutor;
use malware_plugin_runtime::{SandboxPolicy, WasmPluginRuntime};
use malware_plugin_sdk::{validate_manifest_contract, ManifestValidationError};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;
use std::time::{SystemTime, UNIX_EPOCH};

const HOST_API_VERSION: &str = "0.2.0";
const HOST_MANIFEST_VERSION: &str = "1.0.0";
static CWD_LOCK: Mutex<()> = Mutex::new(());

/// Restores process working directory after fixture-specific CWD switching.
struct CwdGuard {
    original: PathBuf,
}

impl CwdGuard {
    /// Switches process CWD and returns guard restoring original directory on drop.
    fn switch_to(new_dir: &Path) -> Self {
        let original = std::env::current_dir().expect("failed to read current dir");
        std::env::set_current_dir(new_dir).expect("failed to switch cwd");
        Self { original }
    }
}

impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.original);
    }
}

fn unique_temp_root(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock drift").as_nanos();
    let pid = std::process::id();
    std::env::temp_dir().join(format!("{prefix}-{pid}-{nanos}"))
}

/// Returns lowercase SHA-256 hex digest for fixture byte payload.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// Builds an in-memory manifest JSON value for fixture generation.
fn build_manifest(
    plugin_name: &str,
    api_version: &str,
    hash: &str,
    signature: &str,
    capabilities: &[&str],
) -> Value {
    json!({
        "manifest_version": HOST_MANIFEST_VERSION,
        "name": plugin_name,
        "version": "0.1.0",
        "api_version": api_version,
        "entrypoint": "plugin.wasm",
        "capabilities": capabilities,
        "integrity": {
            "sha256": hash,
            "signature": signature
        }
    })
}

/// Returns deterministic signing key used for integration tests.
fn test_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7_u8; 32])
}

/// Returns trusted fixture public key as lowercase hex.
fn trusted_public_key_hex() -> String {
    hex::encode(test_signing_key().verifying_key().to_bytes())
}

/// Signs canonical manifest material for test package construction.
fn sign_manifest_material(
    plugin_name: &str,
    version: &str,
    entrypoint: &str,
    hash: &str,
) -> String {
    let signing_key = test_signing_key();
    let message = format!("{}:{}:{}:{}", plugin_name, version, entrypoint, hash);
    let signature = signing_key.sign(message.as_bytes());
    hex::encode(signature.to_bytes())
}

/// Structured ABI module used for successful execution tests.
fn valid_test_wasm_module() -> Vec<u8> {
    wat::parse_str(
        r#"(module
            (func (export "analyze_risk_v1") (param i32 i32 i32) (result i32)
                i32.const 7342
            )
            (func (export "analyze_confidence_v1") (param i32 i32 i32) (result i32)
                i32.const 8800
            )
            (func (export "analyze_verdict_v1") (param i32 i32 i32) (result i32)
                i32.const 2
            )
        )"#,
    )
    .expect("failed to compile wat")
}

/// Module declaring two memories used for memory policy and validation checks.
fn memory_hungry_wasm_module() -> Vec<u8> {
    wat::parse_str(
        r#"(module
            (memory 2)
            (func (export "analyze_risk") (result i32)
                i32.const 5000
            )
        )"#,
    )
    .expect("failed to compile memory wat")
}

/// Module importing host functions used to validate import policy enforcement.
fn importing_wasm_module() -> Vec<u8> {
    wat::parse_str(
        r#"(module
            (import "env" "host_log" (func $host_log (param i32)))
            (func (export "analyze_risk_v1") (param i32 i32 i32) (result i32)
                i32.const 4200
            )
        )"#,
    )
    .expect("failed to compile importing wat")
}

/// Module with malformed export signature used for contract validation failure tests.
fn malformed_export_signature_wasm_module() -> Vec<u8> {
    wat::parse_str(
        r#"(module
            (func (export "analyze_risk_v1") (param i64 i32 i32) (result i32)
                i32.const 4200
            )
        )"#,
    )
    .expect("failed to compile malformed export wat")
}

/// Creates full runtime fixture with plugin package, schema, and trust configuration.
fn write_runtime_fixture(
    plugin_name: &str,
    api_version: &str,
    hash: &str,
    wasm_bytes: &[u8],
    capabilities: &[&str],
) -> PathBuf {
    let root = unique_temp_root("malware-runtime-it");
    let plugin_dir = root.join("plugins").join(plugin_name);
    let contracts_dir = root.join("contracts");

    fs::create_dir_all(&plugin_dir).expect("failed to create plugin dir");
    fs::create_dir_all(&contracts_dir).expect("failed to create contracts dir");

    fs::write(
        contracts_dir.join("plugin-manifest.schema.json"),
        include_str!("../../../contracts/plugin-manifest.schema.json"),
    )
    .expect("failed to write schema");

    let trusted_signers = json!({
        "version": "1.0.0",
        "signers": [
            {
                "key_id": "integration-test-signer",
                "algorithm": "ed25519",
                "public_key_hex": trusted_public_key_hex(),
                "status": "active"
            }
        ]
    });

    fs::write(
        contracts_dir.join("trusted-signers.json"),
        serde_json::to_vec_pretty(&trusted_signers).expect("failed to encode trusted signers"),
    )
    .expect("failed to write trusted signers file");

    fs::write(plugin_dir.join("plugin.wasm"), wasm_bytes).expect("failed to write wasm");

    let signature = sign_manifest_material(plugin_name, "0.1.0", "plugin.wasm", hash);
    let manifest = build_manifest(plugin_name, api_version, hash, &signature, capabilities);
    fs::write(
        plugin_dir.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).expect("failed to encode manifest"),
    )
    .expect("failed to write manifest");

    root
}

#[test]
fn sdk_accepts_schema_valid_host_compatible_manifest() {
    let manifest_text = serde_json::to_string(&build_manifest(
        "sdk-compatible-plugin",
        HOST_API_VERSION,
        &"0".repeat(64),
        "00",
        &["analysis.read_input"],
    ))
    .expect("manifest encode failed");

    let schema_text = include_str!("../../../contracts/plugin-manifest.schema.json");

    let result = validate_manifest_contract(
        &manifest_text,
        schema_text,
        HOST_API_VERSION,
        HOST_MANIFEST_VERSION,
    );

    assert!(result.is_ok(), "expected manifest to validate successfully");
}

#[test]
fn sdk_rejects_schema_invalid_manifest() {
    let bad_manifest = json!({
        "manifest_version": HOST_MANIFEST_VERSION,
        "name": "bad-plugin",
        "version": "0.1.0",
        "api_version": HOST_API_VERSION,
        "entrypoint": "plugin.wasm",
        "capabilities": []
    })
    .to_string();

    let schema_text = include_str!("../../../contracts/plugin-manifest.schema.json");
    let result = validate_manifest_contract(
        &bad_manifest,
        schema_text,
        HOST_API_VERSION,
        HOST_MANIFEST_VERSION,
    );

    assert!(matches!(result, Err(ManifestValidationError::SchemaMismatch(_))));
}

#[test]
fn runtime_rejects_entrypoint_hash_mismatch_before_execution() {
    let _lock = CWD_LOCK.lock().expect("cwd lock poisoned");
    let plugin_name = "hash-mismatch-plugin";
    let root = write_runtime_fixture(
        plugin_name,
        HOST_API_VERSION,
        &"0".repeat(64),
        b"fake-wasm-binary",
        &["analysis.read_input"],
    );

    let result = {
        let _cwd = CwdGuard::switch_to(&root);
        let runtime = WasmPluginRuntime::new();
        runtime.execute(plugin_name, &json!({"sample": "input"}))
    };

    assert!(result.is_err(), "expected runtime to fail for hash mismatch");
    let error_text = result.expect_err("error missing").to_string();
    assert!(
        error_text.contains("entrypoint hash mismatch"),
        "expected hash mismatch failure, got: {error_text}"
    );

    fs::remove_dir_all(&root).expect("failed to cleanup fixture");
}

#[test]
fn runtime_rejects_newer_api_minor_version() {
    let _lock = CWD_LOCK.lock().expect("cwd lock poisoned");
    let plugin_name = "api-too-new-plugin";
    let wasm_hash = sha256_hex(b"fake-wasm-binary");
    let root = write_runtime_fixture(
        plugin_name,
        "0.3.0",
        &wasm_hash,
        b"fake-wasm-binary",
        &["analysis.read_input"],
    );
    let result = {
        let _cwd = CwdGuard::switch_to(&root);
        let runtime = WasmPluginRuntime::new();
        runtime.execute(plugin_name, &json!({"sample": "input"}))
    };

    assert!(result.is_err(), "expected runtime to fail compatibility check");
    let error_text = result.expect_err("error missing").to_string();
    assert!(
        error_text.contains("minor") || error_text.contains("newer"),
        "expected semver minor compatibility failure, got: {error_text}"
    );

    fs::remove_dir_all(&root).expect("failed to cleanup fixture");
}

#[test]
fn runtime_rejects_invalid_wasm_when_validation_passes() {
    let _lock = CWD_LOCK.lock().expect("cwd lock poisoned");
    let plugin_name = "invalid-wasm-plugin";
    let wasm_hash = sha256_hex(b"fake-wasm-binary");
    let root = write_runtime_fixture(
        plugin_name,
        HOST_API_VERSION,
        &wasm_hash,
        b"fake-wasm-binary",
        &["analysis.read_input"],
    );
    let result = {
        let _cwd = CwdGuard::switch_to(&root);
        let runtime = WasmPluginRuntime::new();
        runtime.execute(plugin_name, &json!({"sample": "input"}))
    };

    assert!(result.is_err(), "expected wasm parse failure");
    let error_text = result.expect_err("error missing").to_string();
    assert!(
        error_text.contains("failed to parse wasm module"),
        "expected wasm parse error, got: {error_text}"
    );

    fs::remove_dir_all(&root).expect("failed to cleanup fixture");
}

#[test]
fn runtime_rejects_non_approved_host_imports() {
    let _lock = CWD_LOCK.lock().expect("cwd lock poisoned");
    let plugin_name = "host-import-plugin";
    let wasm_bytes = importing_wasm_module();
    let wasm_hash = sha256_hex(&wasm_bytes);
    let root = write_runtime_fixture(
        plugin_name,
        HOST_API_VERSION,
        &wasm_hash,
        &wasm_bytes,
        &["analysis.read_input"],
    );

    let result = {
        let _cwd = CwdGuard::switch_to(&root);
        let runtime = WasmPluginRuntime::new();
        runtime.execute(plugin_name, &json!({"sample": "input"}))
    };

    assert!(result.is_err(), "expected host import policy failure");
    let error_text = result.expect_err("error missing").to_string();
    assert!(
        error_text.contains("non-approved host imports") && error_text.contains("env::host_log"),
        "expected explicit host import policy failure, got: {error_text}"
    );

    fs::remove_dir_all(&root).expect("failed to cleanup fixture");
}

#[test]
fn runtime_validate_package_accepts_structured_plugin() {
    let _lock = CWD_LOCK.lock().expect("cwd lock poisoned");
    let plugin_name = "validate-structured-plugin";
    let wasm_bytes = valid_test_wasm_module();
    let wasm_hash = sha256_hex(&wasm_bytes);
    let root = write_runtime_fixture(
        plugin_name,
        HOST_API_VERSION,
        &wasm_hash,
        &wasm_bytes,
        &["analysis.read_input"],
    );

    let report = {
        let _cwd = CwdGuard::switch_to(&root);
        let runtime = WasmPluginRuntime::new();
        runtime.validate_plugin_package(plugin_name)
    }
    .expect("expected package validation success");

    assert_eq!(report.plugin_name, plugin_name);
    assert_eq!(report.status, "valid");
    assert_eq!(report.api_version, HOST_API_VERSION);

    fs::remove_dir_all(&root).expect("failed to cleanup fixture");
}

#[test]
fn runtime_validate_package_rejects_malformed_export_signature() {
    let _lock = CWD_LOCK.lock().expect("cwd lock poisoned");
    let plugin_name = "malformed-export-plugin";
    let wasm_bytes = malformed_export_signature_wasm_module();
    let wasm_hash = sha256_hex(&wasm_bytes);
    let root = write_runtime_fixture(
        plugin_name,
        HOST_API_VERSION,
        &wasm_hash,
        &wasm_bytes,
        &["analysis.read_input"],
    );

    let result = {
        let _cwd = CwdGuard::switch_to(&root);
        let runtime = WasmPluginRuntime::new();
        runtime.validate_plugin_package(plugin_name)
    };

    assert!(result.is_err(), "expected package validation failure");
    let error_text = result.expect_err("error missing").to_string();
    assert!(
        error_text.contains("invalid signature") || error_text.contains("must export either"),
        "expected export signature validation failure, got: {error_text}"
    );

    fs::remove_dir_all(&root).expect("failed to cleanup fixture");
}

#[test]
fn runtime_executes_valid_wasm_and_returns_risk_score() {
    let _lock = CWD_LOCK.lock().expect("cwd lock poisoned");
    let plugin_name = "valid-wasm-plugin";
    let wasm_bytes = valid_test_wasm_module();
    let wasm_hash = sha256_hex(&wasm_bytes);
    let root = write_runtime_fixture(
        plugin_name,
        HOST_API_VERSION,
        &wasm_hash,
        &wasm_bytes,
        &["analysis.read_input"],
    );
    let result = {
        let _cwd = CwdGuard::switch_to(&root);
        let runtime = WasmPluginRuntime::new();
        runtime.execute(
            plugin_name,
            &json!({
                "sample": {"size_bytes": 4096},
                "signals": {"static_count": 12, "dynamic_count": 3}
            }),
        )
    }
    .expect("expected valid wasm execution to succeed");

    let risk_score = result.get("risk_score").and_then(Value::as_f64).expect("missing risk_score");
    assert_eq!(risk_score, 73.42);

    let summary = result.get("summary").and_then(Value::as_str).expect("missing summary");
    assert!(summary.contains("executed"), "unexpected summary: {summary}");

    let analysis_response = result
        .get("analysis")
        .and_then(Value::as_object)
        .and_then(|analysis| analysis.get("response"))
        .and_then(Value::as_object)
        .expect("missing analysis.response");
    let confidence = analysis_response
        .get("confidence")
        .and_then(Value::as_f64)
        .expect("missing response confidence");
    let verdict =
        analysis_response.get("verdict").and_then(Value::as_str).expect("missing response verdict");
    let abi_mode = analysis_response
        .get("abi_mode")
        .and_then(Value::as_str)
        .expect("missing response abi_mode");

    assert_eq!(confidence, 88.0);
    assert_eq!(verdict, "high");
    assert_eq!(abi_mode, "structured-v1");

    fs::remove_dir_all(&root).expect("failed to cleanup fixture");
}

#[test]
fn runtime_cold_start_within_budget() {
    let _lock = CWD_LOCK.lock().expect("cwd lock poisoned");
    let plugin_name = "cold-start-budget-plugin";
    let wasm_bytes = valid_test_wasm_module();
    let wasm_hash = sha256_hex(&wasm_bytes);
    let root = write_runtime_fixture(
        plugin_name,
        HOST_API_VERSION,
        &wasm_hash,
        &wasm_bytes,
        &["analysis.read_input"],
    );

    let elapsed_ms = {
        let _cwd = CwdGuard::switch_to(&root);
        let runtime = WasmPluginRuntime::new();
        let start = Instant::now();
        let _ = runtime
            .execute(plugin_name, &json!({"sample": {"size_bytes": 1024}}))
            .expect("expected execution success");
        start.elapsed().as_millis()
    };

    assert!(elapsed_ms <= 5_000, "cold start exceeded budget: {elapsed_ms}ms");

    fs::remove_dir_all(&root).expect("failed to cleanup fixture");
}

#[test]
fn runtime_execution_latency_within_budget() {
    let _lock = CWD_LOCK.lock().expect("cwd lock poisoned");
    let plugin_name = "latency-budget-plugin";
    let wasm_bytes = valid_test_wasm_module();
    let wasm_hash = sha256_hex(&wasm_bytes);
    let root = write_runtime_fixture(
        plugin_name,
        HOST_API_VERSION,
        &wasm_hash,
        &wasm_bytes,
        &["analysis.read_input"],
    );

    let elapsed_ms = {
        let _cwd = CwdGuard::switch_to(&root);
        let runtime = WasmPluginRuntime::new();
        let _ = runtime
            .execute(plugin_name, &json!({"sample": {"size_bytes": 1024}}))
            .expect("warmup execution should succeed");

        let start = Instant::now();
        let _ = runtime
            .execute(plugin_name, &json!({"sample": {"size_bytes": 1024}}))
            .expect("second execution should succeed");
        start.elapsed().as_millis()
    };

    assert!(elapsed_ms <= 2_000, "execution latency exceeded budget: {elapsed_ms}ms");

    fs::remove_dir_all(&root).expect("failed to cleanup fixture");
}

#[test]
fn runtime_reports_memory_ceiling_in_metadata() {
    let _lock = CWD_LOCK.lock().expect("cwd lock poisoned");
    let plugin_name = "memory-ceiling-metadata-plugin";
    let wasm_bytes = valid_test_wasm_module();
    let wasm_hash = sha256_hex(&wasm_bytes);
    let root = write_runtime_fixture(
        plugin_name,
        HOST_API_VERSION,
        &wasm_hash,
        &wasm_bytes,
        &["analysis.read_input"],
    );

    let runtime = WasmPluginRuntime::with_policy(SandboxPolicy {
        max_memory_bytes: 16 * 1024 * 1024,
        max_execution_ms: 30_000,
        allow_network: false,
    });

    let result = {
        let _cwd = CwdGuard::switch_to(&root);
        runtime
            .execute(plugin_name, &json!({"sample": {"size_bytes": 512}}))
            .expect("expected execution success")
    };

    let memory_limit = result
        .get("metadata")
        .and_then(Value::as_object)
        .and_then(|m| m.get("policy"))
        .and_then(Value::as_object)
        .and_then(|m| m.get("memory_limit_bytes"))
        .and_then(Value::as_u64)
        .expect("missing metadata.policy.memory_limit_bytes");

    assert_eq!(memory_limit, 16 * 1024 * 1024);

    fs::remove_dir_all(&root).expect("failed to cleanup fixture");
}

#[test]
fn runtime_records_quarantine_and_telemetry_on_validation_failure() {
    let _lock = CWD_LOCK.lock().expect("cwd lock poisoned");
    let plugin_name = "quarantine-validation-plugin";
    let root = write_runtime_fixture(
        plugin_name,
        HOST_API_VERSION,
        &"0".repeat(64),
        b"fake-wasm-binary",
        &["analysis.read_input"],
    );

    let _ = {
        let _cwd = CwdGuard::switch_to(&root);
        let runtime = WasmPluginRuntime::new();
        runtime.execute(plugin_name, &json!({"sample": "input"}))
    };

    let quarantine_root = root.join("quarantine").join(plugin_name);
    assert!(quarantine_root.exists(), "expected quarantine folder to exist");
    let entries = fs::read_dir(&quarantine_root).expect("failed to read quarantine folder");
    assert!(entries.count() > 0, "expected quarantine entries");

    let telemetry_path = root.join("artifacts").join("runtime-events.jsonl");
    let telemetry =
        fs::read_to_string(&telemetry_path).expect("failed to read runtime telemetry log");
    assert!(
        telemetry.contains("manifest-validation") || telemetry.contains("runtime-execution"),
        "expected telemetry to include failure phase"
    );
    assert!(telemetry.contains("quarantine"), "expected telemetry to include quarantine event");

    fs::remove_dir_all(&root).expect("failed to cleanup fixture");
}

#[test]
fn runtime_telemetry_events_include_event_version() {
    let _lock = CWD_LOCK.lock().expect("cwd lock poisoned");
    let plugin_name = "telemetry-version-plugin";
    let wasm_bytes = valid_test_wasm_module();
    let wasm_hash = sha256_hex(&wasm_bytes);
    let root = write_runtime_fixture(
        plugin_name,
        HOST_API_VERSION,
        &wasm_hash,
        &wasm_bytes,
        &["analysis.read_input"],
    );

    let _result = {
        let _cwd = CwdGuard::switch_to(&root);
        let runtime = WasmPluginRuntime::new();
        runtime
            .execute(plugin_name, &json!({"sample": {"size_bytes": 256}}))
            .expect("expected execution success")
    };

    let telemetry_path = root.join("artifacts").join("runtime-events.jsonl");
    let telemetry =
        fs::read_to_string(&telemetry_path).expect("failed to read runtime telemetry log");

    let mut event_count = 0_u64;
    for line in telemetry.lines().filter(|line| !line.trim().is_empty()) {
        let event: Value =
            serde_json::from_str(line).expect("telemetry line should be valid JSON object");
        let version = event
            .get("event_version")
            .and_then(Value::as_str)
            .expect("telemetry event missing event_version");
        assert_eq!(version, "1.0.0", "unexpected telemetry event version");
        event_count += 1;
    }

    assert!(event_count > 0, "expected at least one telemetry event");

    fs::remove_dir_all(&root).expect("failed to cleanup fixture");
}

#[test]
fn runtime_blocks_network_capability_when_policy_disallows() {
    let _lock = CWD_LOCK.lock().expect("cwd lock poisoned");
    let plugin_name = "network-denied-plugin";
    let wasm_bytes = valid_test_wasm_module();
    let wasm_hash = sha256_hex(&wasm_bytes);
    let root = write_runtime_fixture(
        plugin_name,
        HOST_API_VERSION,
        &wasm_hash,
        &wasm_bytes,
        &["analysis.read_input", "net.egress"],
    );

    let runtime = WasmPluginRuntime::with_policy(SandboxPolicy {
        max_memory_bytes: 128 * 1024 * 1024,
        max_execution_ms: 30_000,
        allow_network: false,
    });

    let result = {
        let _cwd = CwdGuard::switch_to(&root);
        runtime.execute(plugin_name, &json!({"sample": "input"}))
    };

    assert!(result.is_err(), "expected policy block failure");
    let error_text = result.expect_err("error missing").to_string();
    assert!(
        error_text.contains("blocked by sandbox policy") && error_text.contains("net.egress"),
        "expected network capability block failure, got: {error_text}"
    );

    fs::remove_dir_all(&root).expect("failed to cleanup fixture");
}

#[test]
fn runtime_allows_network_capability_when_policy_allows() {
    let _lock = CWD_LOCK.lock().expect("cwd lock poisoned");
    let plugin_name = "network-allowed-plugin";
    let wasm_bytes = valid_test_wasm_module();
    let wasm_hash = sha256_hex(&wasm_bytes);
    let root = write_runtime_fixture(
        plugin_name,
        HOST_API_VERSION,
        &wasm_hash,
        &wasm_bytes,
        &["analysis.read_input", "net.egress"],
    );

    let runtime = WasmPluginRuntime::with_policy(SandboxPolicy {
        max_memory_bytes: 128 * 1024 * 1024,
        max_execution_ms: 30_000,
        allow_network: true,
    });

    let result = {
        let _cwd = CwdGuard::switch_to(&root);
        runtime.execute(plugin_name, &json!({"sample": "input"}))
    }
    .expect("expected execution success when network is allowed");

    let network_allowed = result
        .get("metadata")
        .and_then(Value::as_object)
        .and_then(|m| m.get("policy"))
        .and_then(Value::as_object)
        .and_then(|m| m.get("network_allowed"))
        .and_then(Value::as_bool)
        .expect("missing metadata.policy.network_allowed");
    assert!(network_allowed, "expected network policy metadata to be true");

    fs::remove_dir_all(&root).expect("failed to cleanup fixture");
}

#[test]
fn runtime_rejects_invalid_timeout_policy_before_execution() {
    let _lock = CWD_LOCK.lock().expect("cwd lock poisoned");
    let plugin_name = "timeout-policy-plugin";
    let wasm_bytes = valid_test_wasm_module();
    let wasm_hash = sha256_hex(&wasm_bytes);
    let root = write_runtime_fixture(
        plugin_name,
        HOST_API_VERSION,
        &wasm_hash,
        &wasm_bytes,
        &["analysis.read_input"],
    );

    let runtime = WasmPluginRuntime::with_policy(SandboxPolicy {
        max_memory_bytes: 128 * 1024 * 1024,
        max_execution_ms: 0,
        allow_network: false,
    });

    let result = {
        let _cwd = CwdGuard::switch_to(&root);
        runtime.execute(plugin_name, &json!({"sample": "input"}))
    };

    assert!(result.is_err(), "expected invalid timeout policy failure");
    let error_text = result.expect_err("error missing").to_string();
    assert!(
        error_text.contains("sandbox policy is invalid"),
        "expected invalid policy failure, got: {error_text}"
    );

    fs::remove_dir_all(&root).expect("failed to cleanup fixture");
}

#[test]
fn runtime_enforces_memory_limit_policy() {
    let _lock = CWD_LOCK.lock().expect("cwd lock poisoned");
    let plugin_name = "memory-policy-plugin";
    let wasm_bytes = memory_hungry_wasm_module();
    let wasm_hash = sha256_hex(&wasm_bytes);
    let root = write_runtime_fixture(
        plugin_name,
        HOST_API_VERSION,
        &wasm_hash,
        &wasm_bytes,
        &["analysis.read_input"],
    );

    let runtime = WasmPluginRuntime::with_policy(SandboxPolicy {
        max_memory_bytes: 64 * 1024,
        max_execution_ms: 30_000,
        allow_network: false,
    });

    let result = {
        let _cwd = CwdGuard::switch_to(&root);
        runtime.execute(plugin_name, &json!({"sample": "input"}))
    };

    assert!(result.is_err(), "expected memory-limit failure");
    let error_text = result.expect_err("error missing").to_string();
    assert!(
        error_text.contains("instantiate") && error_text.contains("memory"),
        "expected memory-limit failure, got: {error_text}"
    );

    fs::remove_dir_all(&root).expect("failed to cleanup fixture");
}
