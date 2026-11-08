use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const RUNTIME_EVENT_VERSION: &str = "1.0.0";

/// JSONL telemetry event emitted by runtime validation and execution phases.
#[derive(Debug, Clone, Serialize)]
pub struct RuntimeEvent {
    /// Event schema version used for downstream ingestion compatibility.
    pub event_version: &'static str,
    /// RFC3339 timestamp generated at emission time.
    pub timestamp: String,
    /// Plugin package name associated with this event.
    pub plugin_name: String,
    /// Logical runtime phase (validation, execution, quarantine, and similar).
    pub phase: String,
    /// Phase outcome (`success`, `failure`, `denied`, or `recorded`).
    pub outcome: String,
    /// Human-readable event description.
    pub message: String,
}

/// File-backed telemetry writer producing one JSON event per line.
pub struct RuntimeTelemetry {
    log_path: PathBuf,
}

impl RuntimeTelemetry {
    /// Creates a telemetry writer targeting a specific JSONL log path.
    ///
    /// # Arguments
    /// - `log_path`: Location of runtime event log file.
    ///
    /// # Returns
    /// A telemetry writer instance.
    pub fn new(log_path: PathBuf) -> Self {
        Self { log_path }
    }

    /// Emits a runtime event as a single JSON line.
    ///
    /// # Arguments
    /// - `plugin_name`: Plugin associated with the event.
    /// - `phase`: Runtime phase label.
    /// - `outcome`: Outcome classification for the phase.
    /// - `message`: Free-form event message.
    ///
    /// # Errors
    /// This function is best-effort and does not return errors. Failures are reported to stderr.
    pub fn emit(&self, plugin_name: &str, phase: &str, outcome: &str, message: &str) {
        if let Some(parent) = self.log_path.parent() {
            if let Err(error) = fs::create_dir_all(parent) {
                eprintln!(
                    "runtime telemetry disabled for this event: failed to create log directory '{}': {}",
                    parent.display(),
                    error
                );
                return;
            }
        }

        let event = RuntimeEvent {
            event_version: RUNTIME_EVENT_VERSION,
            timestamp: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string()),
            plugin_name: plugin_name.to_string(),
            phase: phase.to_string(),
            outcome: outcome.to_string(),
            message: message.to_string(),
        };

        let Ok(serialized) = serde_json::to_string(&event) else {
            eprintln!("runtime telemetry disabled for this event: failed to serialize event");
            return;
        };

        let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&self.log_path) else {
            eprintln!(
                "runtime telemetry disabled for this event: failed to open log file '{}'",
                self.log_path.display()
            );
            return;
        };

        if let Err(error) = writeln!(file, "{serialized}") {
            eprintln!(
                "runtime telemetry disabled for this event: failed to write event to '{}': {}",
                self.log_path.display(),
                error
            );
        }
    }
}
