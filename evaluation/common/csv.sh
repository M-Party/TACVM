#!/usr/bin/env bash
# shellcheck shell=bash

tacvm_csv_ensure_header() {
  local path="$1"
  local header="$2"
  if [[ ! -f "${path}" ]]; then
    printf '%s\n' "${header}" >"${path}"
  fi
}

tacvm_csv_append_row() {
  local path="$1"
  shift
  local IFS=,
  printf '%s\n' "$*" >>"${path}"
}
