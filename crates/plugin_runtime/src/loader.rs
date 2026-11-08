use crate::manifest::PluginManifest;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hex::FromHex;
use jsonschema::JSONSchema;
use malware_core::CoreError;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const TRUSTED_PUBKEY_ENV: &str = "MALWARE_TRUSTED_ED25519_PUBKEY_HEX";
const TRUSTED_SIGNERS_FILE_ENV: &str = "MALWARE_TRUSTED_SIGNERS_FILE";
const DEFAULT_TRUSTED_SIGNERS_FILE: &str = "contracts/trusted-signers.json";

#[derive(Debug, Deserialize)]
struct TrustedSignersFile {
    signers: Vec<TrustedSignerRecord>,
}

#[derive(Debug, Deserialize)]
struct TrustedSignerRecord {
    algorithm: String,
    public_key_hex: String,
    status: Option<String>,
    not_before: Option<String>,
    not_after: Option<String>,
}

/// Resolves plugin manifests and enforces schema, integrity, and signature validation.
pub struct PluginLoader {
    plugin_root: PathBuf,
    manifest_schema_path: PathBuf,
}

impl PluginLoader {
    /// Creates a loader using default workspace paths.
    ///
    /// # Returns
    /// Loader configured to read plugins from `plugins/` and schema from `contracts/`.
    pub fn new() -> Self {
        Self {
            plugin_root: PathBuf::from("plugins"),
            manifest_schema_path: PathBuf::from("contracts").join("plugin-manifest.schema.json"),
        }
    }

    /// Resolves the manifest path for a plugin package name.
    ///
    /// # Arguments
    /// - `plugin_name`: Plugin package directory name.
    ///
    /// # Returns
    /// Full path to `manifest.json` under the plugin directory.
    ///
    /// # Errors
    /// Returns [`CoreError::InvalidInput`] if the plugin name is empty or contains unsupported characters.
    pub fn locate_manifest(&self, plugin_name: &str) -> Result<PathBuf, CoreError> {
        if plugin_name.trim().is_empty() {
            return Err(CoreError::InvalidInput("plugin name cannot be empty".to_string()));
        }

        if !plugin_name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) {
            return Err(CoreError::InvalidInput(
                "plugin name contains unsupported characters".to_string(),
            ));
        }

        Ok(self.plugin_root.join(plugin_name).join("manifest.json"))
    }

    /// Loads and validates a plugin manifest.
    ///
    /// # Arguments
    /// - `plugin_name`: Plugin package directory name.
    ///
    /// # Returns
    /// Decoded and validated [`PluginManifest`].
    ///
    /// # Errors
    /// Returns [`CoreError`] when manifest/schema parsing fails, schema checks fail,
    /// plugin identity is inconsistent, or integrity/signature verification fails.
    pub fn load_manifest(&self, plugin_name: &str) -> Result<PluginManifest, CoreError> {
        let manifest_path = self.locate_manifest(plugin_name)?;
        let manifest_text = fs::read_to_string(&manifest_path).map_err(|error| {
            CoreError::PluginFailure(format!(
                "failed to read manifest '{}': {}",
                manifest_path.display(),
                error
            ))
        })?;

        let manifest_json: Value = serde_json::from_str(&manifest_text).map_err(|error| {
            CoreError::PluginFailure(format!(
                "failed to parse manifest '{}': {}",
                manifest_path.display(),
                error
            ))
        })?;

        let schema_text = fs::read_to_string(&self.manifest_schema_path).map_err(|error| {
            CoreError::RuntimeUnavailable(format!(
                "failed to read schema '{}': {}",
                self.manifest_schema_path.display(),
                error
            ))
        })?;

        let schema_json: Value = serde_json::from_str(&schema_text).map_err(|error| {
            CoreError::RuntimeUnavailable(format!(
                "failed to parse schema '{}': {}",
                self.manifest_schema_path.display(),
                error
            ))
        })?;

        let schema = JSONSchema::compile(&schema_json).map_err(|error| {
            CoreError::RuntimeUnavailable(format!(
                "failed to compile schema '{}': {}",
                self.manifest_schema_path.display(),
                error
            ))
        })?;

        if let Err(errors) = schema.validate(&manifest_json) {
            let details = errors.map(|error| error.to_string()).collect::<Vec<_>>().join("; ");
            return Err(CoreError::PluginFailure(format!(
                "manifest '{}' failed schema validation: {}",
                manifest_path.display(),
                details
            )));
        }

        let manifest: PluginManifest = serde_json::from_value(manifest_json).map_err(|error| {
            CoreError::PluginFailure(format!(
                "manifest '{}' is schema-valid but could not be decoded: {}",
                manifest_path.display(),
                error
            ))
        })?;

        if manifest.name != plugin_name {
            return Err(CoreError::PluginFailure(format!(
                "manifest name '{}' does not match requested plugin '{}';",
                manifest.name, plugin_name
            )));
        }

        if manifest.entrypoint.contains(['/', '\\']) {
            return Err(CoreError::PluginFailure(
                "entrypoint must be a file name without path separators".to_string(),
            ));
        }

        self.validate_entrypoint_integrity(&manifest_path, &manifest)?;

        Ok(manifest)
    }

    fn validate_entrypoint_integrity(
        &self,
        manifest_path: &Path,
        manifest: &PluginManifest,
    ) -> Result<(), CoreError> {
        let plugin_dir = manifest_path.parent().ok_or_else(|| {
            CoreError::PluginFailure(format!(
                "manifest path '{}' has no parent directory",
                manifest_path.display()
            ))
        })?;

        let entrypoint_path = plugin_dir.join(&manifest.entrypoint);
        let entrypoint_bytes = fs::read(&entrypoint_path).map_err(|error| {
            CoreError::PluginFailure(format!(
                "failed to read entrypoint '{}': {}",
                entrypoint_path.display(),
                error
            ))
        })?;

        let mut hasher = Sha256::new();
        hasher.update(&entrypoint_bytes);
        let actual_hash = format!("{:x}", hasher.finalize());

        if !actual_hash.eq_ignore_ascii_case(&manifest.integrity.sha256) {
            return Err(CoreError::PluginFailure(format!(
                "entrypoint hash mismatch for '{}': expected='{}', actual='{}'",
                entrypoint_path.display(),
                manifest.integrity.sha256,
                actual_hash
            )));
        }

        self.validate_entrypoint_signature(manifest, &actual_hash)?;

        Ok(())
    }

    fn validate_entrypoint_signature(
        &self,
        manifest: &PluginManifest,
        entrypoint_hash: &str,
    ) -> Result<(), CoreError> {
        let trusted_keys = load_trusted_verifying_keys()?;

        let signature_bytes =
            <[u8; 64]>::from_hex(&manifest.integrity.signature).map_err(|error| {
                CoreError::PluginFailure(format!(
                    "plugin '{}' signature is not valid hex-encoded Ed25519 bytes: {}",
                    manifest.id(),
                    error
                ))
            })?;

        let signature = Signature::from_bytes(&signature_bytes);
        let signed_message = format!(
            "{}:{}:{}:{}",
            manifest.name, manifest.version, manifest.entrypoint, entrypoint_hash
        );

        if trusted_keys.iter().any(|key| key.verify(signed_message.as_bytes(), &signature).is_ok())
        {
            return Ok(());
        }

        Err(CoreError::PluginFailure(format!(
            "plugin '{}' signature verification failed against all trusted signers",
            manifest.id()
        )))
    }
}

fn load_trusted_verifying_keys() -> Result<Vec<VerifyingKey>, CoreError> {
    if let Some(path) = resolve_trusted_signers_file_path() {
        return load_trusted_signers_file(&path);
    }

    if let Ok(trusted_key_hex) = std::env::var(TRUSTED_PUBKEY_ENV) {
        return Ok(vec![parse_verifying_key_hex(&trusted_key_hex, TRUSTED_PUBKEY_ENV)?]);
    }

    Err(CoreError::RuntimeUnavailable(format!(
        "trusted signer configuration is missing; provide {} or {}",
        TRUSTED_SIGNERS_FILE_ENV, TRUSTED_PUBKEY_ENV
    )))
}

fn resolve_trusted_signers_file_path() -> Option<PathBuf> {
    if let Ok(path) = std::env::var(TRUSTED_SIGNERS_FILE_ENV) {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            return Some(PathBuf::from(trimmed));
        }
    }

    let default_path = PathBuf::from(DEFAULT_TRUSTED_SIGNERS_FILE);
    if default_path.exists() {
        return Some(default_path);
    }

    None
}

fn load_trusted_signers_file(path: &Path) -> Result<Vec<VerifyingKey>, CoreError> {
    let text = fs::read_to_string(path).map_err(|error| {
        CoreError::RuntimeUnavailable(format!(
            "failed to read trusted signers file '{}': {}",
            path.display(),
            error
        ))
    })?;

    let parsed: TrustedSignersFile = serde_json::from_str(&text).map_err(|error| {
        CoreError::RuntimeUnavailable(format!(
            "failed to parse trusted signers file '{}': {}",
            path.display(),
            error
        ))
    })?;

    let now = OffsetDateTime::now_utc();
    let mut trusted_keys = Vec::new();
    for signer in parsed.signers {
        if !signer.algorithm.eq_ignore_ascii_case("ed25519") {
            continue;
        }

        if let Some(status) = signer.status.as_deref() {
            if status.eq_ignore_ascii_case("revoked") || status.eq_ignore_ascii_case("disabled") {
                continue;
            }
        }

        if let Some(not_before) = signer.not_before.as_deref() {
            let not_before_time = OffsetDateTime::parse(not_before, &Rfc3339).map_err(|error| {
                CoreError::RuntimeUnavailable(format!(
                    "trusted signers file '{}' has invalid not_before value '{}': {}",
                    path.display(),
                    not_before,
                    error
                ))
            })?;

            if now < not_before_time {
                continue;
            }
        }

        if let Some(not_after) = signer.not_after.as_deref() {
            let not_after_time = OffsetDateTime::parse(not_after, &Rfc3339).map_err(|error| {
                CoreError::RuntimeUnavailable(format!(
                    "trusted signers file '{}' has invalid not_after value '{}': {}",
                    path.display(),
                    not_after,
                    error
                ))
            })?;

            if now > not_after_time {
                continue;
            }
        }

        let key = parse_verifying_key_hex(
            &signer.public_key_hex,
            &format!("{} signer key", path.display()),
        )?;
        trusted_keys.push(key);
    }

    if trusted_keys.is_empty() {
        return Err(CoreError::RuntimeUnavailable(format!(
            "trusted signers file '{}' does not provide any active Ed25519 keys",
            path.display()
        )));
    }

    Ok(trusted_keys)
}

fn parse_verifying_key_hex(key_hex: &str, source: &str) -> Result<VerifyingKey, CoreError> {
    let key_bytes = <[u8; 32]>::from_hex(key_hex.trim()).map_err(|error| {
        CoreError::RuntimeUnavailable(format!(
            "trusted signing key from {} is not valid 32-byte hex: {}",
            source, error
        ))
    })?;

    VerifyingKey::from_bytes(&key_bytes).map_err(|error| {
        CoreError::RuntimeUnavailable(format!(
            "trusted signing key from {} is invalid: {}",
            source, error
        ))
    })
}
