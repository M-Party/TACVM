#!/usr/bin/env bash
# shellcheck shell=bash
# Health checks. On mock/dev hosts most checks are skipped unless STRICT=1.

tacvm_healthcheck_before() {
  local endpoint="${TACVM_VERIFIER_ENDPOINT:-127.0.0.1:50051}"
  local strict="${TACVM_HEALTHCHECK_STRICT:-0}"
  local backend="${TACVM_TEE_BACKEND:-mock}"

  if [[ "${backend}" == "mock" && "${strict}" != "1" ]]; then
    echo "healthcheck: mock backend — skipping live verifier/CVM probes"
    return 0
  fi

  local port="${endpoint##*:}"
  if ! ss -lntp 2>/dev/null | grep -q ":${port}"; then
    echo "healthcheck: verifier port ${port} is not listening" >&2
    return 1
  fi
  if pgrep -f 'verifier-server1' >/dev/null 2>&1; then
    echo "healthcheck: container-backed verifier-server1 appears running; prefer native policy_server" >&2
    return 1
  fi
  echo "healthcheck: basic port probe passed for ${endpoint}"
  return 0
}

tacvm_healthcheck_after() {
  local endpoint="${TACVM_VERIFIER_ENDPOINT:-127.0.0.1:50051}"
  local strict="${TACVM_HEALTHCHECK_STRICT:-0}"
  local backend="${TACVM_TEE_BACKEND:-mock}"
  if [[ "${backend}" == "mock" && "${strict}" != "1" ]]; then
    echo "healthcheck_after: mock backend — no server liveness probe"
    return 0
  fi
  local port="${endpoint##*:}"
  if ! ss -lntp 2>/dev/null | grep -q ":${port}"; then
    echo "healthcheck_after: verifier no longer listening on ${port}" >&2
    return 1
  fi
  echo "healthcheck_after: verifier still listening on ${port}"
  return 0
}
