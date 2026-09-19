# TACVM

Portable TACVM protocol and policy components, organized by **where they run**.

## Layout (by role)

| Path | Runs at |
|---|---|
| [`operation_cvm/`](operation_cvm/README.md) | Operation CVM (policy parser, registry, launch/`B_w`, dispatcher) |
| [`workload_cvm/`](workload_cvm/README.md) | Workload CVM (Trusted Service local state) |
| [`participants/`](participants/README.md) | Each participant (policy confirmer) |
| [`shared/`](shared/README.md) | Shared encode + TEE adapters |
| [`evaluation/`](evaluation/README.md) | Q1–Q3 evaluation harness |
| [`docs/`](docs/README.md) | Design, **Q1–Q3 questions**, coauthor adapter guide |

```text
Participants                 Operation CVM                 Workload CVM
    │                            │                              │
    │ authenticate + policy      │                              │
    ├───────────────────────────►│                              │
    │                            │ create lambda_w, attest      │
    │                            ├─────────────────────────────►│
    │                            │◄──────────── B_w ────────────┤
    │                            │ authorize transition         │
    │                            ├─────────────────────────────►│ Trusted Service
```

## Quick start (no TDX)

```bash
python3 -m pytest -q
# Q1 Fig.6(b)
N=3 RULES="10 100 1000" bash evaluation/scripts/e2_policy_scalability.sh
# Q3 ΔT
ITERATIONS=30 WARMUPS=5 bash evaluation/scripts/e5_admission.sh
```

Paper evaluation questions: [`docs/evaluation/EVALUATION_QUESTIONS.md`](docs/evaluation/EVALUATION_QUESTIONS.md).

## Coauthor handoff

See [`docs/HANDOFF.md`](docs/HANDOFF.md) and
[`docs/integration/tdx_adapter_guide.md`](docs/integration/tdx_adapter_guide.md).
