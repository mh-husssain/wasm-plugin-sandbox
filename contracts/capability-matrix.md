# Capability Matrix

## Purpose
Define capability identifiers available to plugins and their host-side security posture.

## Baseline Capabilities
| Capability | Description | Default Policy |
| --- | --- | --- |
| `analysis.read_input` | Read structured analysis payload from host | allowed |
| `analysis.emit_result` | Return structured analysis output to host | allowed |
| `fs.read_sample` | Read submitted sample bytes via host mediation | denied |
| `fs.write_artifact` | Write artifact output via host mediation | denied |
| `net.egress` | Outbound network access | denied |

## Notes
- Capability values in plugin manifests must match this matrix.
- New capabilities require policy and schema updates before runtime enablement.
- This document and `contracts/plugin-manifest.schema.json` must remain in lockstep.
