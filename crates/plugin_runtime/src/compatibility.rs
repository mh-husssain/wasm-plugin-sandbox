use crate::manifest::PluginManifest;
use malware_core::CoreError;
use semver::Version;

/// Validates plugin API and manifest channels against host-supported baselines.
pub struct CompatibilityChecker {
    expected_api_version: &'static str,
    expected_manifest_version: &'static str,
}

impl Default for CompatibilityChecker {
    fn default() -> Self {
        Self { expected_api_version: "0.2.0", expected_manifest_version: "1.0.0" }
    }
}

impl CompatibilityChecker {
    /// Validates manifest compatibility channels using semantic-version constraints.
    ///
    /// # Arguments
    /// - `manifest`: Manifest to validate against host channel baselines.
    ///
    /// # Returns
    /// `Ok(())` if the plugin is compatible with host channel constraints.
    ///
    /// # Errors
    /// Returns [`CoreError::PluginFailure`] for invalid plugin versions.
    /// Returns [`CoreError::RuntimeUnavailable`] when host baselines are invalid or incompatible.
    pub fn validate(&self, manifest: &PluginManifest) -> Result<(), CoreError> {
        Self::validate_semver_channel(
            "api_version",
            &manifest.api_version,
            self.expected_api_version,
            &manifest.name,
        )?;

        Self::validate_semver_channel(
            "manifest_version",
            &manifest.manifest_version,
            self.expected_manifest_version,
            &manifest.name,
        )?;

        Ok(())
    }

    fn validate_semver_channel(
        channel_name: &str,
        plugin_version_raw: &str,
        host_version_raw: &str,
        plugin_name: &str,
    ) -> Result<(), CoreError> {
        let plugin_version = Version::parse(plugin_version_raw).map_err(|error| {
            CoreError::PluginFailure(format!(
                "plugin '{}' has invalid {} '{}': {}",
                plugin_name, channel_name, plugin_version_raw, error
            ))
        })?;

        let host_version = Version::parse(host_version_raw).map_err(|error| {
            CoreError::RuntimeUnavailable(format!(
                "host has invalid baseline {} '{}': {}",
                channel_name, host_version_raw, error
            ))
        })?;

        if plugin_version.major != host_version.major {
            return Err(CoreError::RuntimeUnavailable(format!(
                "plugin '{}' {} major mismatch: plugin='{}', host='{}'",
                plugin_name, channel_name, plugin_version, host_version
            )));
        }

        if plugin_version.minor > host_version.minor {
            return Err(CoreError::RuntimeUnavailable(format!(
                "plugin '{}' {} minor '{}' is newer than host baseline '{}'",
                plugin_name, channel_name, plugin_version, host_version
            )));
        }

        Ok(())
    }
}
