#!/usr/bin/env bash
# E2 policy scalability dry-run (mock / no TDX).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=/dev/null
source "${ROOT}/evaluation/config/defaults.env"
# shellcheck source=/dev/null
source "${ROOT}/evaluation/common/run_context.sh"
# shellcheck source=/dev/null
source "${ROOT}/evaluation/common/healthcheck.sh"

N="${N:-8}"
RULES="${RULES:-10 100}"
ITERATIONS="${ITERATIONS:-3}"
RUN_ID="${TACVM_RUN_ID:-$(tacvm_make_run_id e2 0)}"
OUT_DIR="$(tacvm_init_run_dir "${RUN_ID}")"

export TACVM_TEE_BACKEND="${TACVM_TEE_BACKEND:-mock}"
tacvm_healthcheck_before
python3 "${ROOT}/evaluation/scripts/e2_policy_scalability.py" \
  --n "${N}" \
  --rules ${RULES} \
  --iterations "${ITERATIONS}" \
  --run-id "${RUN_ID}" \
  --out-dir "${OUT_DIR}"
tacvm_healthcheck_after
echo "E2 complete: ${OUT_DIR}"
