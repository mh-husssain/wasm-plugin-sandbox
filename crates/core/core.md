# core Crate Guide

## Purpose
System-of-record crate for analysis domain logic and application orchestration.

## Module Map
- `domain`: core domain concepts and intent markers.
- `application`: use-case orchestration service layer.
- `ports`: adapter-facing interfaces (plugin executor and future ports).
- `errors`: core error taxonomy shared across layers.
- `dto`: request/response transfer models for adapters.

## Responsibilities
- Keep adapter-agnostic business boundaries in one crate.
- Expose stable interfaces consumed by CLI and future GUI shell.
- Prevent runtime-specific concerns from leaking into domain and application layers.
