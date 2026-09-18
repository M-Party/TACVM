#!/usr/bin/env bash
# Staged formal-run entrypoint. Currently only E2 dry-run is available locally.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
echo "Running available local experiments (E2 mock dry-run)..."
bash "${ROOT}/evaluation/scripts/e2_policy_scalability.sh"
echo "E1/E3-E7 remain blocked on TDX host adapter wiring."
