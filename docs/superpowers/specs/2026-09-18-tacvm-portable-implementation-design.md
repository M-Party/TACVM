# TACVM Portable Implementation Design (Strategy A)

**Date:** 2026-09-18  
**Status:** Approved for Phase A start  
**Basis:** `TACVM_Cursor_Design_Implementation_Spec.md`, `TACVM_Evaluation_Implementation_Spec.md`, coauthor TDX prototype feedback

## 1. Goal

Implement TACVM protocol and evaluation assets in this repository so they can be packaged and adapted by the coauthor on a TDX-capable machine that already runs a native verifier and CVM fleet. This development host is SGX-only and must not claim real TDX end-to-end execution.

## 2. Constraints

- Target TEE for the paper is Intel TDX confidential VMs, not SGX.
- Coauthor already has: `policy_server` (gRPC `:50051`), DCAP/QVL appraisal, `launch-client.sh`, `cvm-fleet-test.sh`, 16 CVMs, global client IDs `cvm_XX_client_YY`, `state_mutex_`, process-wide appraisal mutex.
- This checkout currently contains policy agreement prototypes under `evaluation-assets/`, not the full C++ verifier stack.
- Do not create a parallel `policy_server_v2` or a second attestation stack.
- Do not disable security checks to improve benchmarks.
- Integration is documentation-driven: we define adapter points; the coauthor wires their existing code.

## 3. Architecture

```text
┌─────────────────────────────────────────────────────────┐
│ This repo (portable)                                    │
│  protocol core: encode, policy join, rounds, B_w FSM,   │
│  dispatcher checks, error codes, timestamps, E1–E7      │
│  harness skeleton + mock TEE backend                    │
└───────────────────────────┬─────────────────────────────┘
                            │ adapter interfaces
                            ▼
┌─────────────────────────────────────────────────────────┐
│ Coauthor TDX host (existing)                            │
│  policy_server, QuoteAppraisal/QVL, launch-client.sh,   │
│  cvm-fleet-test.sh, guest launchers, real Quotes/CVMs   │
└─────────────────────────────────────────────────────────┘
```

Two backends for hardware-dependent operations:

| Backend | Used where | Behavior |
|---|---|---|
| `mock` | This host / CI | Fake quotes, fake launches, deterministic digests |
| `tdx` | Coauthor host | Real TDX quote gen/verify, real CVM provision |

Production protocol path and evaluation path stay identical except for timestamps/logs.

## 4. Work already in this repo

- `evaluation-assets/policy-aggregation-core`: restrictive join + candidate digest
- `evaluation-assets/operation-cvm-policy-coordinator`: proposal→confirm→activate FSM
- `evaluation-assets/participant-policy-confirmer`: participant-side confirm
- Homogeneous fixtures for N=2/4/8/16/32 and a 3-party differential fixture
- Evaluation plan and CSV/manifest templates

## 5. Deliverables

1. `docs/evaluation/repo_mapping.md`
2. `docs/evaluation/implementation_status.md`
3. `docs/integration/tdx_adapter_guide.md` (for coauthor adaptation)
4. Protocol/design code for missing portable pieces (Phases B–F)
5. Evaluation harness skeletons E1–E7 (Phases G–H)
6. Unit/integration tests with mock backend
7. Packaging/runbook for handoff

## 6. Phased order

| Phase | Focus | Runnable here? |
|---|---|---|
| A | Mapping + adapter guide | Yes |
| B | Canonical encode, errors, logging, run IDs | Yes |
| C | Boot/participant acceptance interfaces + mock | Logic yes; real RA on TDX host |
| D | Policy schema/join/activation (extend existing) | Yes |
| E | Launch context, B_w FSM + mock provision | Logic yes |
| F | Artifact/Key Vault/Dispatcher/TS check interfaces | Logic yes |
| G | Timestamp/CSV/healthcheck plumbing | Yes |
| H | E1–E7 scripts; mock dry-run here, formal on TDX | Partial here |

## 7. Adapter points the coauthor must wire

Documented in detail in `docs/integration/tdx_adapter_guide.md`:

1. Quote generate / verify (keep appraisal mutex)
2. Challenge/session maps (keep `state_mutex_` + global client IDs)
3. Boot manifest / `d_M` / `pk_ch` binding
4. Policy proposal/confirm RPC or message hooks into Open Policy Parser APIs
5. Workload provision + opaque `lambda_w` launch data
6. Live binding channel establishment / invalidation
7. Fleet scripts calling evaluation harness entrypoints

## 8. Non-goals

- Porting TACVM onto SGX as the paper system
- Kubernetes K-Bench, CRUD workload generators
- Multi-cloud HA Operation CVM
- Rewriting the coauthor verifier from scratch

## 9. Acceptance for Phase A

Phase A is done when mapping, status, and adapter guide exist and describe how the coauthor connects without requiring their source tree in this environment.
