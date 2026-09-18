# TACVM evaluation harness

Layout follows `TACVM_Cursor_Design_Implementation_Spec.md` §22–§23.

## Local (no TDX)

```bash
# From repo root
export TACVM_TEE_BACKEND=mock
bash evaluation/scripts/e2_policy_scalability.sh
# or
bash evaluation/scripts/run_all.sh
```

E2 measures policy verify / join / candidate-construction time for fixed `N`
and rule counts `P` using homogeneous fixtures. It does **not** include Quote
RTT or CVM launch.

Results land in `results/<run_id>/raw` and `summary`.

## TDX host

Keep `docs/integration/tdx_adapter_guide.md` as the wiring contract. E1/E3–E7
scripts currently exit with status 2 until adapters and fleet hooks are ready.

## Health checks

`evaluation/common/healthcheck.sh` skips live verifier probes when
`TACVM_TEE_BACKEND=mock` unless `TACVM_HEALTHCHECK_STRICT=1`.
