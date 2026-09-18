# TACVM Implementation Status

**Date:** 2026-09-18  
**Legend:** `IMPLEMENTED` | `EXISTING_AND_VERIFIED` | `PARTIAL` | `NOT_IMPLEMENTED` | `BLOCKED`

`EXISTING_AND_VERIFIED` below refers to the **coauthor TDX host**, not this checkout.

## Protocol and security invariants

| Requirement | Status | Evidence |
|---|---|---|
| No workload control before policy activation | NOT_IMPLEMENTED | No Operation CVM authority gate in this repo |
| All participants authenticate same Operation CVM | PARTIAL / BLOCKED locally | Coauthor has RA path; this repo has no boot accept flow |
| Unique policy-key registration | NOT_IMPLEMENTED | — |
| Proposal rounds scoped by pid/v/r | PARTIAL | Coordinator uses context fields; full pid derivation pending |
| Restrictive join cannot widen authority | PARTIAL | `policy-aggregation-core` implements intersection/DENY joins |
| Unanimous confirmation before activation | PARTIAL | Coordinator + confirmer prototypes |
| Atomic policy update | PARTIAL | Activate publishes snapshot in prototype; persistence TBD |
| Fresh `lambda_w` per Workload CVM | NOT_IMPLEMENTED | — |
| Launch-context replay rejected | NOT_IMPLEMENTED | — |
| Evidence binds launch context + `pk_w` | NOT_IMPLEMENTED | — |
| `B_w` required before secrets/commands | NOT_IMPLEMENTED | — |
| Restart/channel loss invalidates `B_w` | NOT_IMPLEMENTED | — |
| Trusted Service prior-state / artifact checks | NOT_IMPLEMENTED | — |
| Replay protection for challenges/u/etc. | PARTIAL | Coauthor challenge path exists; full domain coverage TBD |
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
| Canonical encode helper | NOT_IMPLEMENTED | — |
| Mock TEE backend | NOT_IMPLEMENTED | — |
| E1–E7 harness | NOT_IMPLEMENTED | Specs only |
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
