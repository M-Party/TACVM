#!/usr/bin/env bash
# shellcheck shell=bash
# Shared run-context helpers for TACVM evaluation scripts.

tacvm_repo_root() {
  local here
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  printf '%s\n' "${here}"
}

tacvm_make_run_id() {
  local experiment="${1:-run}"
  local iteration="${2:-0}"
  local stamp
  stamp="$(date -u +%Y%m%d-%H%M%S)"
  printf '%s-%s-%s\n' "${stamp}" "${experiment}" "${iteration}"
}

tacvm_init_run_dir() {
  local run_id="$1"
  local root="${TACVM_RESULTS_ROOT:-results}"
  local dir="${root}/${run_id}"
  mkdir -p "${dir}/logs" "${dir}/raw" "${dir}/summary"
  git -C "$(tacvm_repo_root)" rev-parse HEAD >"${dir}/git_commit.txt" 2>/dev/null || \
    echo "unknown" >"${dir}/git_commit.txt"
  printf '%s\n' "${dir}"
}

tacvm_write_json_file() {
  local path="$1"
  shift
  python3 - "$@" <<'PY' >"${path}"
import json, sys
print(json.dumps(json.loads(sys.argv[1]), indent=2, sort_keys=True))
PY
}
