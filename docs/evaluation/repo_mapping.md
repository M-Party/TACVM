# TACVM Repository Mapping

**Date:** 2026-09-18  
**Scope:** Map paper/spec components to (1) this repository and (2) the coauthor TDX prototype known from written feedback.  
**Strategy:** A — extend this repo; coauthor adapts existing verifier/fleet.

## 1. Paper component → this repository

| Paper / spec component | Current location in this repo | Status |
|---|---|---|
| Restrictive policy join / candidate | `evaluation-assets/policy-aggregation-core/` | PARTIAL (Python prototype) |
| Operation CVM policy round FSM | `evaluation-assets/operation-cvm-policy-coordinator/` | PARTIAL (uses `tacvm_protocol` wire encode) |
| Participant confirmation | `evaluation-assets/participant-policy-confirmer/` | PARTIAL (uses `tacvm_protocol` wire encode) |
| Policy schema / checklist | `evaluation-assets/POLICY_SCHEMA.md` | PARTIAL (provisional) |
| Component boundaries | `evaluation-assets/POLICY_COMPONENTS.md` | DOCUMENTED |
| Evaluation plan (older E1–E3 style) | `evaluation-assets/EVALUATION_PLAN.md` | DOCUMENTED |
| Result templates | `evaluation-assets/results/` | TEMPLATE ONLY |
| Design/impl contract | `TACVM_Cursor_Design_Implementation_Spec.md` | SPEC |
| Evaluation harness contract | `TACVM_Evaluation_Implementation_Spec.md` | SPEC |
| N-party scale fixtures | `evaluation-assets/policy-aggregation-core/fixtures/*-party-homogeneous.yaml` | IMPLEMENTED (mock inputs) |
| 3-party differential fixture | `.../fixtures/three-party-proposals.yaml` | IMPLEMENTED |
| Canonical encode library | `protocol/tacvm_protocol/` | IMPLEMENTED (encode + hash_domain) |
| BootManifest / d_M tooling | — | NOT_IMPLEMENTED |
| Participant acceptance (TACVM-ACCEPT) | — | NOT_IMPLEMENTED |
| Quote Verifier / DCAP QVL | — | NOT IN THIS REPO |
| Key Vault | — | NOT_IMPLEMENTED |
| Workload Dispatcher | — | NOT_IMPLEMENTED |
| Trusted Service | — | NOT_IMPLEMENTED |
| `lambda_w` / pending launch / `B_w` | — | NOT_IMPLEMENTED |
| `launch-client.sh` / fleet harness | — | NOT IN THIS REPO |
| E1–E7 formal harness | — | NOT_IMPLEMENTED |
| Mock TEE backend | `protocol/tacvm_protocol/backends/mock.py` | IMPLEMENTED |
| TDX adapter backend | `protocol/tacvm_protocol/backends/tdx.py` | PARTIAL (stub; coauthor wires) |

## 2. Paper component → coauthor TDX host (from feedback)

These paths are **on the coauthor machine**, not in this git checkout. Treat as integration targets.

| Paper / spec component | Known coauthor location / artifact | Notes |
|---|---|---|
| Operation CVM / verifier server | `/root/vm-verifier/policy_server` listening `0.0.0.0:50051` | Native gRPC multi-thread server |
| Quote appraisal / QVL | `QuoteAppraisal/quote_verifier.cc` | Process-wide appraisal mutex required |
| Challenge / session state | `server/policy_server.cc` (`pending_challenges_`, `sessions_`) | Protected by `state_mutex_` |
| Guest launcher | `launch-client.sh` | Builds `cvm_<id>_client_<n>` via `CVM_INSTANCE_ID` |
| Fleet orchestration | `cvm-fleet-test.sh` | Passes CVM number into guests; 16 CVMs deployed |
| Active vs container verifier | Native `policy_server` active; container `verifier-server1` stopped for concurrency retest | Do not accidentally point harness at stale container |

### Preserved concurrency / identity invariants

Must not regress when adapting:

1. Global client IDs: `cvm_01_client_01` … `cvm_16_client_02`
2. `state_mutex_` around challenge/session maps
3. Process-wide DCAP QVL/appraisal serialization
4. Post-run liveness check (requests passed ≠ server still alive)

## 3. Intended ownership after integration

| Concern | Owned in this repo | Wired by coauthor |
|---|---|---|
| Policy join semantics | Yes | Call from verifier/policy path |
| Round/activation FSM | Yes | Persist/publish active snapshot in server |
| Encode/domain separation | Yes | Use for REPORTDATA / accept / proposal / confirm / trans |
| Quote crypto & QVL | Interface only | Real TDX implementation |
| CVM provision / launch data | Interface only | Real platform + `lambda_w` injection |
| Fleet scheduling / SSH | Harness scripts (portable) | Existing 16-CVM inventory & scripts |
| Formal E1–E7 runners | Yes (skeleton → complete) | Provide env endpoints & credentials |

## 4. Mapping gaps to close next

1. Define adapter interfaces in code (`tee`, `provision`, `channel`) with `mock` + `tdx` stubs.
2. Align existing Python policy components with spec domain strings and error codes.
3. Add evaluation directory layout from the evaluation spec without requiring TDX locally.
4. Keep coauthor source out of this tree unless they later contribute it; integration remains doc-driven.
