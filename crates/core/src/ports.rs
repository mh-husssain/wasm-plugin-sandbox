use crate::errors::CoreError;
use serde_json::Value;

/// Port for executing a plugin with a JSON input payload.
pub trait PluginExecutor: Send + Sync {
    /// Executes the named plugin with the provided payload.
    ///
    /// # Arguments
    /// - `plugin_name`: Plugin package identifier.
    /// - `input`: Runtime payload passed to the plugin.
    ///
    /// # Returns
    /// JSON output produced by the runtime adapter.
    ///
    /// # Errors
    /// Returns [`CoreError`] when plugin loading, validation, or execution fails.
    fn execute(&self, plugin_name: &str, input: &Value) -> Result<Value, CoreError>;
}
