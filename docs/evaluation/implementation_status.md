# TACVM Implementation Status

**Date:** 2026-09-18  
**Legend:** `IMPLEMENTED` | `EXISTING_AND_VERIFIED` | `PARTIAL` | `NOT_IMPLEMENTED` | `BLOCKED`

`EXISTING_AND_VERIFIED` below refers to the **coauthor TDX host**, not this checkout.

## Protocol and security invariants

| Requirement | Status | Evidence |
|---|---|---|
| No workload control before policy activation | NOT_IMPLEMENTED | No Operation CVM authority gate in this repo |
| All participants authenticate same Operation CVM | PARTIAL / BLOCKED locally | Coauthor has RA path; this repo has no boot accept flow |
| Unique policy-key registration | IMPLEMENTED (portable) | `protocol/tacvm_protocol/registry.py` |
| Proposal rounds scoped by pid/v/r | PARTIAL | Coordinator uses context fields; full pid derivation pending |
| Restrictive join cannot widen authority | PARTIAL | `policy-aggregation-core` implements intersection/DENY joins |
| Unanimous confirmation before activation | PARTIAL | Coordinator + confirmer prototypes |
| Atomic policy update | PARTIAL | Activate publishes snapshot in prototype; persistence TBD |
| Fresh `lambda_w` per Workload CVM | IMPLEMENTED (portable/mock) | `protocol/tacvm_protocol/workload.py` |
| Launch-context replay rejected | IMPLEMENTED (portable/mock) | `WorkloadLaunchFSM` |
| Evidence binds launch context + `pk_w` | PARTIAL | Mock attest hash via `TACVM-WORKLOAD-ATTEST` |
| `B_w` required before secrets/commands | IMPLEMENTED (portable/mock) | Dispatcher checks LIVE binding |
| Restart/channel loss invalidates `B_w` | IMPLEMENTED (portable/mock) | `on_channel_lost` |
| Trusted Service prior-state / artifact checks | PARTIAL | Mock local-state check in dispatcher |
| Replay protection for challenges/u/etc. | PARTIAL | Transition `u` replay rejected; challenge path on coauthor host |
| Global client IDs | EXISTING_AND_VERIFIED (coauthor) | Deployed to 16 CVMs |
| `state_mutex_` / appraisal mutex | EXISTING_AND_VERIFIED (coauthor) | Concurrent retest passed; server stayed alive |

## Repository assets

| Asset | Status | Path |
|---|---|---|
| Policy aggregation core | PARTIAL | `evaluation-assets/policy-aggregation-core/` |
| Policy coordinator | PARTIAL | `evaluation-assets/operation-cvm-policy-coordinator/` |
| Participant confirmer | PARTIAL | `evaluation-assets/participant-policy-confirmer/` |
| Homogeneous N fixtures | IMPLEMENTED | N=2/4/8/16/32 YAML + generator |
| Three-party fixture | IMPLEMENTED | `fixtures/three-party-proposals.yaml` |
| Canonical encode helper | IMPLEMENTED | `protocol/tacvm_protocol/encode.py` |
| Mock TEE backend | IMPLEMENTED | `protocol/tacvm_protocol/backends/mock.py` |
| TDX adapter backend | PARTIAL (explicit stub) | `protocol/tacvm_protocol/backends/tdx.py` |
| Adapter guide for coauthor | IMPLEMENTED (Phase A) | `docs/integration/tdx_adapter_guide.md` |
| Repo mapping | IMPLEMENTED (Phase A) | `docs/evaluation/repo_mapping.md` |

## Evaluation experiments

| Experiment | Status in this repo | Notes |
|---|---|---|
| E1 trust establishment | NOT_IMPLEMENTED | Needs coauthor RA + policy activation wiring |
| E2 policy scalability | PARTIAL inputs only | Fixtures/generator ready; timed harness TBD |
| E3 single Workload auth | NOT_IMPLEMENTED | Needs TDX provision/attest |
| E4 concurrent Workload auth | NOT_IMPLEMENTED | Extend coauthor fleet scripts |
| E5 admission | NOT_IMPLEMENTED | — |
| E6 Redis/ResNet | NOT_IMPLEMENTED | — |
| E7 security validation | NOT_IMPLEMENTED | — |

## Blockers on this host

- No Intel TDX / no real Quote generation.
- Coauthor `policy_server` sources are not in this tree by design.
- Formal E1/E3–E7 numbers require the TDX host after adapter wiring.
