//! Integration tests asserting CLI and core service behavioral parity.

use ed25519_dalek::{Signer, SigningKey};
use malware_cli::{execute_run, format_run_output, RunCommand};
use malware_core::{AnalysisRequest, AnalysisService};
use malware_plugin_runtime::WasmPluginRuntime;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

static CWD_LOCK: Mutex<()> = Mutex::new(());

/// Restores process working directory after temporary test fixture switching.
struct CwdGuard {
    original: PathBuf,
}

impl CwdGuard {
    /// Switches current working directory and returns a guard for restoration.
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

/// Returns lowercase SHA-256 hex digest of byte payload.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// Builds a minimal valid WASM module used for parity tests.
fn valid_test_wasm_module() -> Vec<u8> {
    wat::parse_str(
        r#"(module
            (func (export "analyze_risk") (result i32)
                i32.const 5150
            )
        )"#,
    )
    .expect("failed to compile wat")
}

/// Returns deterministic signing key used by integration fixtures.
fn test_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7_u8; 32])
}

/// Returns trusted test public key encoded as lowercase hex.
fn trusted_public_key_hex() -> String {
    hex::encode(test_signing_key().verifying_key().to_bytes())
}

/// Signs canonical manifest material for fixture generation.
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

/// Writes an isolated plugin fixture with manifest, schema, and trust store files.
fn write_runtime_fixture(plugin_name: &str) -> PathBuf {
    let root = unique_temp_root("malware-cli-it");
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

    let wasm_bytes = valid_test_wasm_module();
    fs::write(plugin_dir.join("plugin.wasm"), &wasm_bytes).expect("failed to write wasm");

    let hash = sha256_hex(&wasm_bytes);
    let signature = sign_manifest_material(plugin_name, "0.1.0", "plugin.wasm", &hash);

    let manifest = json!({
        "manifest_version": "1.0.0",
        "name": plugin_name,
        "version": "0.1.0",
        "api_version": "0.1.0",
        "entrypoint": "plugin.wasm",
        "capabilities": ["analysis.read_input"],
        "integrity": {
            "sha256": hash,
            "signature": signature
        }
    });

    fs::write(
        plugin_dir.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).expect("failed to encode manifest"),
    )
    .expect("failed to write manifest");

    root
}

#[test]
fn cli_run_matches_core_service_result() {
    let _lock = CWD_LOCK.lock().expect("cwd lock poisoned");
    let plugin_name = "parity-plugin";
    let sample_path = "samples/alpha.bin";
    let root = write_runtime_fixture(plugin_name);

    let runtime = Arc::new(WasmPluginRuntime::new());
    let service = AnalysisService::new(runtime);

    let cli_result = {
        let _cwd = CwdGuard::switch_to(&root);
        execute_run(
            &service,
            RunCommand { plugin: plugin_name.to_string(), sample: sample_path.to_string() },
        )
        .expect("cli run should succeed")
    };

    let core_result = {
        let _cwd = CwdGuard::switch_to(&root);
        service
            .analyze(AnalysisRequest {
                sample_path: sample_path.to_string(),
                plugin_name: plugin_name.to_string(),
                input: json!({}),
            })
            .expect("core analyze should succeed")
    };

    assert_eq!(cli_result.summary, core_result.summary);
    assert_eq!(cli_result.risk_score, core_result.risk_score);
    assert_eq!(cli_result.sample_path, core_result.sample_path);

    let output = format_run_output(&cli_result);
    assert!(output.contains("summary:"), "formatted output missing summary");
    assert!(output.contains("risk_score:"), "formatted output missing risk_score");

    fs::remove_dir_all(&root).expect("failed to cleanup fixture");
}

#[test]
fn cli_run_propagates_core_validation_error() {
    let runtime = Arc::new(WasmPluginRuntime::new());
    let service = AnalysisService::new(runtime);

    let err = execute_run(
        &service,
        RunCommand { plugin: "unused".to_string(), sample: "   ".to_string() },
    )
    .expect_err("expected invalid input error");

    assert!(err.to_string().contains("sample_path cannot be empty"), "unexpected error: {err}");
}
