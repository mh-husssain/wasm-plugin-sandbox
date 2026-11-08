use thiserror::Error;

/// Canonical error type shared by analysis orchestration and runtime adapters.
#[derive(Debug, Error)]
pub enum CoreError {
    /// User input failed validation.
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// Plugin contract, packaging, or runtime behavior caused execution failure.
    #[error("plugin failure: {0}")]
    PluginFailure(String),
    /// Host runtime could not satisfy requested operation.
    #[error("runtime unavailable: {0}")]
    RuntimeUnavailable(String),
}
