# Model Review Checklist

Use this checklist for any architecture-significant pull request.

## 1. Scope and Coverage

- Context model reflects current system actors and trust boundaries.
- Container model reflects current runtime units and integration edges.
- Relevant component models are updated for changed internals.
- Relevant dynamic models are updated for changed flows.
- Deployment model is updated if CI or artifact flow changed.
- Threat model is updated for trust, integrity, or policy changes.

## 2. Status Marker Accuracy

- Every changed boundary is marked correctly: Implemented, Skeleton, or Planned.
- Planned edges are not represented as active flows.
- Skeleton paths include explicit gap notes and non-implementation statements.

## 3. Decision and Traceability

- ADR created or amended for boundary, policy, or dependency direction changes.
- ADR references concrete files and affected components.
- Pull request description links changed models and ADRs.

## 4. Security and Policy Integrity

- Threat model controls align with runtime validation behavior.
- Policy gates and trust assumptions match current runtime code.
- Residual risks are explicitly documented.

## 5. Quality and Readability

- Diagrams are syntactically valid Mermaid.
- File names and locations follow modelling conventions.
- Language is implementation-facing, precise, and testable.
- No contradictory statements across models and Architecture.md.
