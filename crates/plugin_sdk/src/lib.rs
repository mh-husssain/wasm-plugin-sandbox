//! Plugin authoring SDK helpers for manifest contract validation and typed ABI payloads.

#![warn(missing_docs)]

use jsonschema::JSONSchema;
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// Manifest model used by SDK validation utilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Manifest schema channel version.
    pub manifest_version: String,
    /// Plugin package name.
    pub name: String,
    /// Plugin package version.
    pub version: String,
    /// Runtime API channel version.
    pub api_version: String,
    /// Entrypoint WASM artifact name.
    pub entrypoint: String,
    /// Capability identifiers requested by the plugin.
    pub capabilities: Vec<String>,
    /// Integrity and signing metadata.
    pub integrity: Integrity,
}

/// Integrity metadata attached to plugin manifests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Integrity {
    /// SHA-256 hash of entrypoint bytes.
    pub sha256: String,
    /// Signature over canonical signing payload.
    pub signature: String,
}

/// Typed structured ABI input for plugin execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteInput {
    /// Sample size in bytes.
    pub sample_size_bytes: u32,
    /// Count of static analysis signals.
    pub static_signal_count: u32,
    /// Count of dynamic analysis signals.
    pub dynamic_signal_count: u32,
}

/// Typed structured ABI output for plugin execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteOutput {
    /// Plugin verdict label.
    pub verdict: String,
    /// Human-readable plugin summary.
    pub summary: String,
    /// Risk score as floating-point value.
    pub risk_score: f64,
    /// Confidence percentage or normalized score.
    pub confidence: f64,
    /// Optional plugin metadata payload.
    pub metadata: Value,
}

/// Validation errors produced by manifest contract checks.
#[derive(Debug, Error)]
pub enum ManifestValidationError {
    /// Manifest text is not valid JSON.
    #[error("manifest is not valid JSON: {0}")]
    InvalidManifestJson(String),
    /// Schema text is not valid JSON.
    #[error("schema is not valid JSON: {0}")]
    InvalidSchemaJson(String),
    /// Schema could not be compiled.
    #[error("schema failed to compile: {0}")]
    InvalidSchema(String),
    /// Manifest failed schema validation.
    #[error("manifest failed schema validation: {0}")]
    SchemaMismatch(String),
    /// Manifest decoded after schema validation still failed typed decoding.
    #[error("manifest is schema-valid but cannot be decoded: {0}")]
    DecodeFailure(String),
    /// Plugin or host semver channel is malformed.
    #[error("manifest has invalid {channel}: {value} ({reason})")]
    InvalidSemver {
        /// Semver channel being validated.
        channel: &'static str,
        /// Raw semver string value that failed parsing.
        value: String,
        /// Semver parser error detail.
        reason: String,
    },
    /// Semver major version is incompatible.
    #[error("manifest {channel} major mismatch: plugin={plugin}, host={host}")]
    MajorMismatch {
        /// Semver channel being validated.
        channel: &'static str,
        /// Plugin version value.
        plugin: String,
        /// Host baseline version value.
        host: String,
    },
    /// Plugin minor version is newer than host-supported baseline.
    #[error("manifest {channel} minor not supported: plugin={plugin}, host={host}")]
    MinorTooNew {
        /// Semver channel being validated.
        channel: &'static str,
        /// Plugin version value.
        plugin: String,
        /// Host baseline version value.
        host: String,
    },
}

/// Validates a manifest against JSON schema and host channel compatibility rules.
///
/// # Arguments
/// - `manifest_text`: Raw manifest JSON content.
/// - `schema_text`: Raw JSON schema content.
/// - `host_api_version`: Host API channel baseline.
/// - `host_manifest_version`: Host manifest channel baseline.
///
/// # Returns
/// Decoded and validated [`PluginManifest`].
///
/// # Errors
/// Returns [`ManifestValidationError`] for JSON parsing, schema, decode, or semver failures.
pub fn validate_manifest_contract(
    manifest_text: &str,
    schema_text: &str,
    host_api_version: &str,
    host_manifest_version: &str,
) -> Result<PluginManifest, ManifestValidationError> {
    let manifest_json: Value = serde_json::from_str(manifest_text)
        .map_err(|error| ManifestValidationError::InvalidManifestJson(error.to_string()))?;
    let schema_json: Value = serde_json::from_str(schema_text)
        .map_err(|error| ManifestValidationError::InvalidSchemaJson(error.to_string()))?;

    let schema = JSONSchema::compile(&schema_json)
        .map_err(|error| ManifestValidationError::InvalidSchema(error.to_string()))?;

    if let Err(errors) = schema.validate(&manifest_json) {
        let details = errors.map(|error| error.to_string()).collect::<Vec<_>>().join("; ");
        return Err(ManifestValidationError::SchemaMismatch(details));
    }

    let manifest: PluginManifest = serde_json::from_value(manifest_json)
        .map_err(|error| ManifestValidationError::DecodeFailure(error.to_string()))?;

    validate_semver_channel("api_version", &manifest.api_version, host_api_version)?;
    validate_semver_channel("manifest_version", &manifest.manifest_version, host_manifest_version)?;

    Ok(manifest)
}

fn validate_semver_channel(
    channel: &'static str,
    plugin_value: &str,
    host_value: &str,
) -> Result<(), ManifestValidationError> {
    let plugin =
        Version::parse(plugin_value).map_err(|error| ManifestValidationError::InvalidSemver {
            channel,
            value: plugin_value.to_string(),
            reason: error.to_string(),
        })?;
    let host =
        Version::parse(host_value).map_err(|error| ManifestValidationError::InvalidSemver {
            channel,
            value: host_value.to_string(),
            reason: error.to_string(),
        })?;

    if plugin.major != host.major {
        return Err(ManifestValidationError::MajorMismatch {
            channel,
            plugin: plugin.to_string(),
            host: host.to_string(),
        });
    }

    if plugin.minor > host.minor {
        return Err(ManifestValidationError::MinorTooNew {
            channel,
            plugin: plugin.to_string(),
            host: host.to_string(),
        });
    }

    Ok(())
}
