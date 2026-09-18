#!/usr/bin/env bash
# shellcheck shell=bash

tacvm_monotonic_ns() {
  python3 - <<'PY'
import time
print(time.monotonic_ns())
PY
}

tacvm_elapsed_us() {
  local start_ns="$1"
  local end_ns="$2"
  python3 - "$start_ns" "$end_ns" <<'PY'
import sys
start=int(sys.argv[1]); end=int(sys.argv[2])
print((end-start)//1000)
PY
}
