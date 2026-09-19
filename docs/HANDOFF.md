# Handoff notes for the TDX-host coauthor

This repository is developed on an SGX-only machine. Package it onto the TDX
host and adapt—do not expect real Quotes here.

Paper evaluation questions (Q1–Q3): [`evaluation/EVALUATION_QUESTIONS.md`](evaluation/EVALUATION_QUESTIONS.md).

```text
Q1 trust plane → Q2 Workload B_w → Q3 control-path ΔT
```

## Repository roles

| Tree | Meaning |
|---|---|
| `operation_cvm/` | Control-plane logic to embed/call from your `policy_server` |
| `workload_cvm/` | Trusted Service local enforcement |
| `participants/` | Participant-side confirmer |
| `shared/protocol/` | Canonical encode + TEE adapter interface |
| `evaluation/` | Harness scripts |

## What works locally (`TACVM_TEE_BACKEND=mock`)

```bash
python3 -m pytest -q
# Q1 Fig.6(b)
N=3 RULES="10 100 1000" bash evaluation/scripts/e2_policy_scalability.sh
# Q3 ΔT
ITERATIONS=30 WARMUPS=5 bash evaluation/scripts/e5_admission.sh
```

## What you must wire for paper numbers

| Question | On TDX host |
|---|---|
| Q1 Fig.6(a) | Real Op CVM boot + participant RA + policy activate |
| Q2 table | Workload auth / \(B_w\) for \(M=1..16\) |
| Q3 \(\Delta T\) | Same guest TS; Direct vs Op-CVM control path |

Follow [`integration/tdx_adapter_guide.md`](integration/tdx_adapter_guide.md).

Preserve on your host:

1. Global client IDs `cvm_XX_client_YY`
2. `state_mutex_` around challenge/session maps
3. Process-wide DCAP QVL/appraisal mutex
4. Post-run verifier liveness checks

Implement `shared/protocol` `TdxTeeBackend` methods against your Quote/QVL/launch
stack, and call Operation CVM packages from `policy_server` instead of forking a
second server.
