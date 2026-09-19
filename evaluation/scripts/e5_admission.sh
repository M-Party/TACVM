#!/usr/bin/env bash
# Q3 — workload management/control overhead (admit).
# Primary metric: ΔT = T_TACVM - T_Direct
# Boundary: request issued → Trusted Service accept (no container/startup).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=/dev/null
source "${ROOT}/evaluation/config/defaults.env"
# shellcheck source=/dev/null
source "${ROOT}/evaluation/common/run_context.sh"
# shellcheck source=/dev/null
source "${ROOT}/evaluation/common/healthcheck.sh"

ITERATIONS="${ITERATIONS:-30}"
WARMUPS="${WARMUPS:-5}"
RUN_ID="${TACVM_RUN_ID:-$(tacvm_make_run_id e5 0)}"
OUT_DIR="$(tacvm_init_run_dir "${RUN_ID}")"

export TACVM_TEE_BACKEND="${TACVM_TEE_BACKEND:-mock}"
tacvm_healthcheck_before
python3 "${ROOT}/evaluation/scripts/e5_control_overhead.py" \
  --iterations "${ITERATIONS}" \
  --warmups "${WARMUPS}" \
  --run-id "${RUN_ID}" \
  --out-dir "${OUT_DIR}"
tacvm_healthcheck_after
echo "E5/Q3 complete: ${OUT_DIR}"
