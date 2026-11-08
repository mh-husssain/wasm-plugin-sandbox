//! Core application contracts and orchestration for malware analysis.
//!
//! This crate defines:
//! - Domain primitives and DTOs.
//! - Error model shared across executors and frontends.
//! - Hexagonal ports used by runtime adapters.

#![warn(missing_docs)]

/// Application service layer.
pub mod application;
/// Domain-level intent types.
pub mod domain;
/// Serializable request/response DTOs.
pub mod dto;
/// Shared error taxonomy.
pub mod errors;
/// Adapter-facing port interfaces.
pub mod ports;

/// High-level analysis service coordinating request validation and plugin execution.
pub use application::AnalysisService;
/// User intent marker used by analysis orchestration.
pub use domain::AnalysisIntent;
/// Request and result payloads for analysis operations.
pub use dto::{AnalysisRequest, AnalysisResult};
/// Canonical error type used across crate boundaries.
pub use errors::CoreError;
/// Runtime execution port implemented by plugin runtimes.
pub use ports::PluginExecutor;
