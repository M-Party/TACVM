# Handoff notes for the TDX-host coauthor

This repository is developed on an SGX-only machine. Package it (git clone or
tarball) onto the TDX host and adapt—do not expect real Quotes here.

## What works locally (`TACVM_TEE_BACKEND=mock`)

```bash
# Protocol unit tests
PYTHONPATH=protocol python3 -m pytest protocol/tests -q

# Policy components
PYTHONPATH="protocol:evaluation-assets/policy-aggregation-core:evaluation-assets/operation-cvm-policy-coordinator:evaluation-assets/participant-policy-confirmer" \
  python3 -m pytest evaluation-assets/policy-aggregation-core/tests \
  evaluation-assets/operation-cvm-policy-coordinator/tests \
  evaluation-assets/participant-policy-confirmer/tests -q

# E2 policy scalability dry-run
bash evaluation/scripts/e2_policy_scalability.sh
```

## What you must wire

Follow [`docs/integration/tdx_adapter_guide.md`](integration/tdx_adapter_guide.md).

Preserve on your host:

1. Global client IDs `cvm_XX_client_YY`
2. `state_mutex_` around challenge/session maps
3. Process-wide DCAP QVL/appraisal mutex
4. Post-run verifier liveness checks

Replace `TdxTeeBackend` stubs with calls into your `policy_server` /
`QuoteAppraisal` / `launch-client.sh` paths.

## Suggested first integration checks

1. Run mock tests on the TDX host (sanity).
2. Point `TACVM_VERIFIER_ENDPOINT` at native `policy_server:50051`.
3. Implement Quote generate/verify adapter using `hash_domain("TACVM-BOOT", ...)`.
4. Hook policy join/confirm into your RPC surface.
5. Only then enable E1/E3/E4 scripts beyond their current stubs.
