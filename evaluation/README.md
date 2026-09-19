# TACVM evaluation harness

Paper-facing questions: [`docs/evaluation/EVALUATION_QUESTIONS.md`](../docs/evaluation/EVALUATION_QUESTIONS.md).

```text
Q1 trust plane → Q2 Workload B_w → Q3 control-path ΔT
```

## Local (no TDX)

```bash
export TACVM_TEE_BACKEND=mock

# Q1 Fig.6(b): policy processing vs P (fixed N=3)
N=3 RULES="10 100 1000" ITERATIONS=3 \
  bash evaluation/scripts/e2_policy_scalability.sh

# Q1 Fig.6(a) dry-run phases (boot/RA are mock stand-ins — not paper boot numbers)
bash evaluation/scripts/e1_trust_establishment.sh

# Q3: admit control-path ΔT (request → Trusted Service accept)
ITERATIONS=30 WARMUPS=5 bash evaluation/scripts/e5_admission.sh

# Optional full portable walkthrough
python3 evaluation/scripts/local_sim_op_already_up.py
```

## TDX host

| Question | Needs |
|---|---|
| Q1 Fig.6(a) | Real Operation CVM boot + participant RA |
| Q2 table | Workload CVM auth / live \(B_w\) fleet (\(M=1..16\)) |
| Q3 \(\Delta T\) | Same guest TS; Direct vs Op-CVM path over real control channel |

Wiring: [`docs/integration/tdx_adapter_guide.md`](../docs/integration/tdx_adapter_guide.md).

## Health checks

`evaluation/common/healthcheck.sh` skips live verifier probes when
`TACVM_TEE_BACKEND=mock` unless `TACVM_HEALTHCHECK_STRICT=1`.
