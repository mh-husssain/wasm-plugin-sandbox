use serde::Serialize;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Persisted quarantine record written for policy and runtime violations.
#[derive(Debug, Clone, Serialize)]
pub struct QuarantineRecord {
    /// Plugin package name.
    pub plugin_name: String,
    /// Runtime phase where the violation occurred.
    pub phase: String,
    /// Violation reason.
    pub reason: String,
    /// RFC3339 timestamp for quarantine recording.
    pub quarantined_at: String,
}

/// Writes violation artifacts into quarantine snapshots on disk.
pub struct QuarantineManager {
    root: PathBuf,
}

impl QuarantineManager {
    /// Creates a manager rooted at the provided quarantine directory.
    ///
    /// # Arguments
    /// - `root`: Base directory used for per-plugin violation snapshots.
    ///
    /// # Returns
    /// A quarantine manager instance.
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// Records a violation snapshot and optional manifest copy.
    ///
    /// # Arguments
    /// - `plugin_name`: Plugin associated with the violation.
    /// - `phase`: Runtime phase where violation occurred.
    /// - `reason`: Human-readable violation details.
    /// - `manifest_path`: Optional manifest path to copy alongside violation record.
    ///
    /// # Errors
    /// This function is best-effort and does not return errors. Failures are reported to stderr.
    pub fn record_violation(
        &self,
        plugin_name: &str,
        phase: &str,
        reason: &str,
        manifest_path: Option<&Path>,
    ) {
        let now = OffsetDateTime::now_utc();
        let timestamp = now
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
            .replace(':', "-");

        let quarantine_dir = self.root.join(plugin_name).join(timestamp);
        if let Err(error) = fs::create_dir_all(&quarantine_dir) {
            eprintln!(
                "quarantine disabled for this violation: failed to create '{}': {}",
                quarantine_dir.display(),
                error
            );
            return;
        }

        let record = QuarantineRecord {
            plugin_name: plugin_name.to_string(),
            phase: phase.to_string(),
            reason: reason.to_string(),
            quarantined_at: now
                .format(&Rfc3339)
                .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string()),
        };

        if let Ok(serialized) = serde_json::to_vec_pretty(&record) {
            if let Err(error) = fs::write(quarantine_dir.join("violation.json"), serialized) {
                eprintln!("quarantine write failed for '{}': {}", quarantine_dir.display(), error);
            }
        }

        if let Some(path) = manifest_path {
            if path.exists() {
                if let Err(error) = fs::copy(path, quarantine_dir.join("manifest.snapshot.json")) {
                    eprintln!(
                        "quarantine manifest snapshot copy failed for '{}' from '{}': {}",
                        quarantine_dir.display(),
                        path.display(),
                        error
                    );
                }
            }
        }
    }
}
