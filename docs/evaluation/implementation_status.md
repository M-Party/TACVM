# TACVM Implementation Status

**Date:** 2026-09-19  
**Legend:** `IMPLEMENTED` | `EXISTING_AND_VERIFIED` | `PARTIAL` | `NOT_IMPLEMENTED` | `BLOCKED`

Paper Q1–Q3: [`EVALUATION_QUESTIONS.md`](EVALUATION_QUESTIONS.md).

## Evaluation questions

| Q | Artifact | Status here | Evidence |
|---|---|---|---|
| Q1 Fig.6(a) Trust vs \(N\) | stacked bars | PARTIAL (mock phases) | `evaluation/scripts/e1_*`; paper boot/RA from TDX host |
| Q1 Fig.6(b) Policy vs \(P\) | stacked bars | IMPLEMENTED (mock) | `e2_*`, `results/*e2*` (\(N=3\)) |
| Q2 Workload auth vs \(M\) | table | NOT_IMPLEMENTED locally | needs TDX fleet (`e3`/`e4`) |
| Q3 Control \(\Delta T\) | prose \(\Delta T\) | IMPLEMENTED (mock) | `e5_control_overhead.py`, `results/*e5*` |

## Layout

| Tree | Role |
|---|---|
| `operation_cvm/` | Operation CVM components |
| `workload_cvm/` | Workload CVM Trusted Service |
| `participants/` | Participant-side confirmer |
| `shared/protocol/` | Encode + TEE adapters |
| `evaluation/` | Harness |

## Protocol invariants (selected)

| Requirement | Status | Evidence |
|---|---|---|
| Restrictive join | PARTIAL | `operation_cvm/policy_aggregation` |
| Unanimous confirm + activate | PARTIAL | `operation_cvm/policy_coordinator` + `participants/policy_confirmer` |
| Unique policy-key registration | IMPLEMENTED | `operation_cvm/participant_registry` |
| Fresh `lambda_w` / replay reject / `B_w` invalidate | IMPLEMENTED (mock) | `operation_cvm/workload_launch` |
| Dispatcher + prior-state check | PARTIAL | `operation_cvm/dispatcher` + `workload_cvm/trusted_service` |
| Canonical encode | IMPLEMENTED | `shared/protocol` |
| Mock / TDX TEE backends | mock IMPLEMENTED; tdx stub | `shared/protocol/.../backends` |
| Coauthor client IDs + mutexes | EXISTING_AND_VERIFIED | external TDX host |

## Blockers on this host

- No Intel TDX / no `/dev/kvm` — cannot run formal Q1 boot/RA or Q2 fleet here.
- Coauthor `policy_server` sources are not in this tree by design.
