use crate::dto::{AnalysisRequest, AnalysisResult};
use crate::errors::CoreError;
use crate::ports::PluginExecutor;
use serde_json::{json, Value};
use std::sync::Arc;

/// Orchestrates malware analysis request processing against a plugin executor.
pub struct AnalysisService {
    executor: Arc<dyn PluginExecutor>,
}

impl AnalysisService {
    /// Creates a new service with the provided plugin execution backend.
    ///
    /// # Arguments
    /// - `executor`: Adapter implementing plugin execution semantics.
    ///
    /// # Returns
    /// A ready-to-use [`AnalysisService`].
    pub fn new(executor: Arc<dyn PluginExecutor>) -> Self {
        Self { executor }
    }

    /// Executes analysis and normalizes runtime output into a stable result DTO.
    ///
    /// # Arguments
    /// - `request`: Input containing plugin selection, sample path, and optional payload.
    ///
    /// # Returns
    /// Normalized [`AnalysisResult`] containing summary, risk score, and raw runtime output.
    ///
    /// # Errors
    /// Returns [`CoreError::InvalidInput`] when the sample path is empty.
    /// Returns runtime-originated [`CoreError`] values from the plugin executor.
    pub fn analyze(&self, request: AnalysisRequest) -> Result<AnalysisResult, CoreError> {
        if request.sample_path.trim().is_empty() {
            return Err(CoreError::InvalidInput("sample_path cannot be empty".to_string()));
        }

        let mut payload = request.input;
        if payload.get("sample_path").is_none() {
            payload["sample_path"] = json!(request.sample_path);
        }

        let output = self.executor.execute(&request.plugin_name, &payload)?;
        let summary = output
            .get("summary")
            .and_then(Value::as_str)
            .unwrap_or("No summary returned by plugin")
            .to_string();
        let risk_score = output.get("risk_score").and_then(Value::as_f64).unwrap_or(0.0);

        Ok(AnalysisResult {
            sample_path: payload
                .get("sample_path")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            plugin_name: request.plugin_name,
            summary,
            risk_score,
            raw_output: output,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal test executor returning deterministic values for service assertions.
    struct MockExecutor;

    impl PluginExecutor for MockExecutor {
        fn execute(&self, _plugin_name: &str, _input: &Value) -> Result<Value, CoreError> {
            Ok(json!({
                "summary": "Mock analysis complete",
                "risk_score": 0.42
            }))
        }
    }

    #[test]
    fn returns_result_from_executor() {
        let service = AnalysisService::new(Arc::new(MockExecutor));
        let request = AnalysisRequest {
            sample_path: "sample.bin".to_string(),
            plugin_name: "default".to_string(),
            input: json!({}),
        };

        let result = service.analyze(request).expect("analysis should succeed");
        assert_eq!(result.summary, "Mock analysis complete");
        assert_eq!(result.risk_score, 0.42);
    }
}
