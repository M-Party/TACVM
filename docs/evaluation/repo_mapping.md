# TACVM Repository Mapping

**Date:** 2026-09-19  
**Strategy:** A — portable packages here; coauthor wires TDX host.  
**Paper questions:** [`EVALUATION_QUESTIONS.md`](EVALUATION_QUESTIONS.md)

## 1. Where code runs

| Tree | Runs at |
|---|---|
| `operation_cvm/` | Operation CVM |
| `workload_cvm/` | Workload CVM |
| `participants/` | Each participant |
| `shared/protocol/` | Shared libraries (imported by the above) |
| `evaluation/` | Host-side harness scripts |

## 2. Paper Q1–Q3 → harness

| Question | Artifact | Script | Runs at |
|---|---|---|---|
| Q1 Fig.6(a) | Trust establishment vs \(N\) | `e1_trust_establishment.sh` | TDX for boot/RA; mock dry-run here |
| Q1 Fig.6(b) | Policy processing vs \(P\) (\(N=3\)) | `e2_policy_scalability.sh` | Portable mock |
| Q2 Table | Workload auth / \(B_w\) vs \(M\) | `e3_workload_auth.sh` (+ fleet) | TDX host |
| Q3 \(\Delta T\) | Control-path admit overhead | `e5_admission.sh` | Mock here; remeasure on TDX |

## 3. Paper component → path

| Paper / spec component | Path | Status |
|---|---|---|
| Restrictive policy join | `operation_cvm/policy_aggregation/` | PARTIAL |
| Policy round FSM | `operation_cvm/policy_coordinator/` | PARTIAL |
| Participant confirmation | `participants/policy_confirmer/` | PARTIAL |
| Participant registry / ACCEPT | `operation_cvm/participant_registry/` | IMPLEMENTED (portable) |
| `lambda_w` / `B_w` FSM | `operation_cvm/workload_launch/` | IMPLEMENTED (mock) |
| Workload Dispatcher | `operation_cvm/dispatcher/` | PARTIAL |
| Trusted Service | `workload_cvm/trusted_service/` | PARTIAL (mock local state) |
| Canonical encode | `shared/protocol/tacvm_protocol/encode.py` | IMPLEMENTED |
| TEE adapters | `shared/protocol/tacvm_protocol/backends/` | mock IMPLEMENTED; tdx stub |
| Coauthor `policy_server` / fleet | on TDX host | EXISTING_AND_VERIFIED (external) |

## 4. Coauthor host (unchanged)

Native `/root/vm-verifier/policy_server`, `launch-client.sh`, `cvm-fleet-test.sh`,
global client IDs, `state_mutex_`, appraisal mutex — see
`docs/integration/tdx_adapter_guide.md`.
