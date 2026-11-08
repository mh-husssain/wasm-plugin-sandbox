use serde::{Deserialize, Serialize};

/// Runtime-decoded plugin manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Manifest schema channel version.
    pub manifest_version: String,
    /// Plugin package name.
    pub name: String,
    /// Plugin package version.
    pub version: String,
    /// Runtime ABI/API channel version.
    pub api_version: String,
    /// Entrypoint WASM module file name.
    pub entrypoint: String,
    /// Declared plugin capabilities requested at runtime.
    pub capabilities: Vec<String>,
    /// Integrity metadata for entrypoint verification.
    pub integrity: Integrity,
}

/// Integrity metadata attached to plugin artifacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Integrity {
    /// SHA-256 hash of the entrypoint artifact.
    pub sha256: String,
    /// Ed25519 signature over canonical manifest signing material.
    pub signature: String,
}

impl PluginManifest {
    /// Returns a stable plugin identifier `<name>@<version>`.
    ///
    /// # Returns
    /// Human-readable plugin identity string.
    pub fn id(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }
}
