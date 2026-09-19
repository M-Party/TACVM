from __future__ import annotations

import pytest

from tacvm_protocol import get_tee_backend
from launch import (
    LaunchRecordStatus,
    WorkloadLaunchError,
    WorkloadLaunchFSM,
)


def test_fresh_lambda_establishes_live_binding_and_consumes_pending():
    fsm = WorkloadLaunchFSM(tee=get_tee_backend("mock"), pid="pid-1", pk_ch="pk-op")
    record = fsm.create_launch(w="w-1")
    assert record.status == LaunchRecordStatus.PENDING
    assert record.lambda_hash.startswith("sha384:")

    fsm.mark_provisioning("w-1")
    binding = fsm.authenticate_workload(
        w="w-1",
        pk_w="pk-w-1",
        challenge_n_w="ab" * 32,
    )
    assert binding.status.value == "LIVE"
    assert fsm.get_record("w-1").status == LaunchRecordStatus.CONSUMED
    assert fsm.require_live_binding("w-1").w == "w-1"


def test_rejects_launch_context_replay_after_success():
    fsm = WorkloadLaunchFSM(tee=get_tee_backend("mock"), pid="pid-1", pk_ch="pk-op")
    fsm.create_launch(w="w-2")
    fsm.authenticate_workload(w="w-2", pk_w="pk-w", challenge_n_w="cd" * 32)

    with pytest.raises(WorkloadLaunchError) as captured:
        fsm.authenticate_workload(w="w-2", pk_w="pk-w", challenge_n_w="cd" * 32)
    assert captured.value.code == "ERR_LAUNCH_REPLAY"


def test_channel_loss_invalidates_binding():
    fsm = WorkloadLaunchFSM(tee=get_tee_backend("mock"), pid="pid-1", pk_ch="pk-op")
    fsm.create_launch(w="w-3")
    fsm.authenticate_workload(w="w-3", pk_w="pk-w", challenge_n_w="ef" * 32)
    fsm.on_channel_lost("w-3")

    with pytest.raises(WorkloadLaunchError) as captured:
        fsm.require_live_binding("w-3")
    assert captured.value.code == "ERR_BINDING_NOT_LIVE"


def test_duplicate_w_is_rejected():
    fsm = WorkloadLaunchFSM(tee=get_tee_backend("mock"), pid="pid-1", pk_ch="pk-op")
    fsm.create_launch(w="w-dup")
    with pytest.raises(WorkloadLaunchError) as captured:
        fsm.create_launch(w="w-dup")
    assert captured.value.code == "ERR_LAUNCH_CONTEXT"
