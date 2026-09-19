#!/usr/bin/env bash
# Q1 Fig.6(a) — multi-party trust establishment vs N (boot + auth + policy).
# Formal boot/RA numbers require TDX; mock dry-run is portable only.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=/dev/null
source "${ROOT}/evaluation/config/defaults.env"
# shellcheck source=/dev/null
source "${ROOT}/evaluation/common/run_context.sh"
# shellcheck source=/dev/null
source "${ROOT}/evaluation/common/healthcheck.sh"

N_LIST="${N_LIST:-2 4 8 16 32}"
RULES="${RULES:-100}"
P_LIST="${P_LIST:-10 100 1000}"
P_N="${P_N:-8}"
ITERATIONS="${ITERATIONS:-3}"
WARMUPS="${WARMUPS:-1}"
RUN_ID="${TACVM_RUN_ID:-$(tacvm_make_run_id e1 0)}"
OUT_DIR="$(tacvm_init_run_dir "${RUN_ID}")"

export TACVM_TEE_BACKEND="${TACVM_TEE_BACKEND:-mock}"
tacvm_healthcheck_before
# shellcheck disable=SC2086
python3 "${ROOT}/evaluation/scripts/e1_trust_establishment.py" \
  --n-list ${N_LIST} \
  --rules "${RULES}" \
  --p-list ${P_LIST} \
  --p-n "${P_N}" \
  --iterations "${ITERATIONS}" \
  --warmups "${WARMUPS}" \
  --run-id "${RUN_ID}" \
  --out-dir "${OUT_DIR}"
tacvm_healthcheck_after
echo "E1 complete: ${OUT_DIR}"
