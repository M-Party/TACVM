# Operation CVM components

Code that runs in (or is owned by) the **Operation CVM** control plane.

| Directory | Paper role | Responsibility |
|---|---|---|
| `policy_aggregation/` | Open Policy Parser (join) | Restrictive join + candidate digest |
| `policy_coordinator/` | Open Policy Parser (round FSM) | Collect proposals, distribute candidate, activate |
| `participant_registry/` | Enrollment | `TACVM-ACCEPT`, policy-key map `R`, all-registered barrier |
| `workload_launch/` | Workload auth control | `lambda_w` pending records + `B_w` lifecycle |
| `dispatcher/` | Workload Dispatcher | Authorize `TACVM-TRANS`, require LIVE `B_w`, call Trusted Service |
| `POLICY_SCHEMA.md` | Spec | Policy object schema |
| `POLICY_COMPONENTS.md` | Spec | Message sequence among policy units |
| `results_templates/` | Eval templates | Manifest/CSV column templates |

Quote generation/verification adapters used by the Operation CVM live under
`../shared/protocol` (`TeeBackend`), because the same encode/hash helpers are
shared with participants.
