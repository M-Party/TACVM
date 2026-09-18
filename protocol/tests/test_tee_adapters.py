from __future__ import annotations

import os

import pytest

from tacvm_protocol import hash_domain
from tacvm_protocol.tee import (
    AppraisalStatus,
    BindingStatus,
    TeeBackendError,
    get_tee_backend,
)


def test_mock_operation_quote_binds_boot_domain_reportdata():
    backend = get_tee_backend("mock")
    n_i = "ab" * 32
    pk_ch = "pk-channel"
    d_M = "sha384:manifest"
    evidence = backend.generate_operation_quote(n_i=n_i, pk_ch=pk_ch, d_M=d_M)
    expected = hash_domain(
        "TACVM-BOOT",
        {"n_i": n_i, "pk_ch": pk_ch, "d_M": d_M},
    )
    assert evidence.reportdata == expected
    result = backend.verify_quote(evidence, expected_reportdata=expected)
    assert result.status == AppraisalStatus.SUCCESS


def test_mock_quote_verify_fails_closed_on_reportdata_mismatch():
    backend = get_tee_backend("mock")
    evidence = backend.generate_operation_quote(
        n_i="cd" * 32, pk_ch="pk", d_M="sha384:m"
    )
    with pytest.raises(TeeBackendError) as captured:
        backend.verify_quote(evidence, expected_reportdata="sha384:deadbeef")
    assert captured.value.code == "ERR_CHANNEL_KEY_MISMATCH" or captured.value.code.startswith(
        "ERR_"
    )


def test_mock_provision_and_binding_lifecycle():
    backend = get_tee_backend("mock")
    lambda_w = backend.create_launch_context(w="w-1", pid="pid-1", pk_ch="pk")
    assert lambda_w.lambda_hash.startswith("sha384:")
    handle = backend.provision_workload_cvm(lambda_w)
    assert handle.platform_handle.startswith("mock-")

    binding = backend.verify_workload_evidence(
        w="w-1",
        lambda_hash=lambda_w.lambda_hash,
        pk_w="pk-w-1",
        challenge_n_w="ee" * 32,
    )
    assert binding.status == BindingStatus.LIVE
    assert binding.w == "w-1"

    backend.invalidate_binding("w-1")
    with pytest.raises(TeeBackendError) as captured:
        backend.require_live_binding("w-1")
    assert captured.value.code == "ERR_BINDING_NOT_LIVE"


def test_tdx_backend_is_explicit_stub():
    backend = get_tee_backend("tdx")
    with pytest.raises(TeeBackendError) as captured:
        backend.generate_operation_quote(n_i="aa" * 32, pk_ch="pk", d_M="m")
    assert captured.value.code == "ERR_TDX_ADAPTER_NOT_WIRED"


def test_backend_selected_by_env_defaults_to_mock(monkeypatch):
    monkeypatch.delenv("TACVM_TEE_BACKEND", raising=False)
    assert get_tee_backend().name == "mock"
    monkeypatch.setenv("TACVM_TEE_BACKEND", "tdx")
    assert get_tee_backend().name == "tdx"
    monkeypatch.setenv("TACVM_TEE_BACKEND", "nope")
    with pytest.raises(TeeBackendError) as captured:
        get_tee_backend()
    assert captured.value.code == "ERR_UNKNOWN_TEE_BACKEND"
