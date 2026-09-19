from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tacvm_protocol import canonical_encode, get_tee_backend
from dispatcher import DispatcherError, TransitionDispatcher
from launch import WorkloadLaunchFSM
from trusted_service import WorkloadLocalState


def _sign_transition(private_key, fields):
    body = canonical_encode("TACVM-TRANS", fields)
    return {
        **fields,
        "signature": private_key.sign(body),
    }


def _ready_dispatcher():
    requester = Ed25519PrivateKey.generate()
    pk_hex = requester.public_key().public_bytes_raw().hex()
    tee = get_tee_backend("mock")
    fsm = WorkloadLaunchFSM(tee=tee, pid="pid-1", pk_ch="pk-op")
    fsm.create_launch("w-1")
    fsm.authenticate_workload("w-1", pk_w="pk-w", challenge_n_w="aa" * 32)
    dispatcher = TransitionDispatcher(
        pid="pid-1",
        policy_hash="sha384:pi",
        requester_keys={"id_O": pk_hex},
        launch_fsm=fsm,
        allowed_transitions={
            ("admit", "ABSENT", "RUNNING"),
            ("stop", "RUNNING", "STOPPED"),
        },
    )
    return requester, dispatcher, fsm


def test_admit_succeeds_with_live_binding_and_matching_state():
    requester, dispatcher, _ = _ready_dispatcher()
    fields = {
        "participant_id": "id_O",
        "pid": "pid-1",
        "policy_hash": "sha384:pi",
        "u": "op-1",
        "w": "w-1",
        "operation": "admit",
        "prior_state": "ABSENT",
        "next_state": "RUNNING",
        "artifact_digest": "sha256:model",
    }
    result = dispatcher.submit_transition(_sign_transition(requester, fields))
    assert result["status"] == "COMMITTED"
    assert result["local_state"] == "RUNNING"


def test_rejects_replay_policy_mismatch_and_dead_binding():
    requester, dispatcher, fsm = _ready_dispatcher()
    fields = {
        "participant_id": "id_O",
        "pid": "pid-1",
        "policy_hash": "sha384:pi",
        "u": "op-2",
        "w": "w-1",
        "operation": "admit",
        "prior_state": "ABSENT",
        "next_state": "RUNNING",
        "artifact_digest": "sha256:model",
    }
    dispatcher.submit_transition(_sign_transition(requester, fields))

    with pytest.raises(DispatcherError) as replay:
        dispatcher.submit_transition(_sign_transition(requester, fields))
    assert replay.value.code == "ERR_TRANS_REPLAY"

    bad_hash = dict(fields, u="op-3", policy_hash="sha384:other")
    with pytest.raises(DispatcherError) as policy:
        dispatcher.submit_transition(_sign_transition(requester, bad_hash))
    assert policy.value.code == "ERR_TRANS_POLICY_HASH"

    fsm.on_channel_lost("w-1")
    dead = dict(fields, u="op-4")
    with pytest.raises(DispatcherError) as binding:
        dispatcher.submit_transition(_sign_transition(requester, dead))
    assert binding.value.code == "ERR_BINDING_NOT_LIVE"


def test_trusted_service_rejects_wrong_prior_state():
    requester, dispatcher, _ = _ready_dispatcher()
    dispatcher._local_states["w-1"] = WorkloadLocalState(
        lifecycle_state="RUNNING",
        accepted_artifact_digest="sha256:model",
        last_successful_operation_id="seed",
    )
    fields = {
        "participant_id": "id_O",
        "pid": "pid-1",
        "policy_hash": "sha384:pi",
        "u": "op-5",
        "w": "w-1",
        "operation": "admit",
        "prior_state": "ABSENT",
        "next_state": "RUNNING",
        "artifact_digest": "sha256:model",
    }
    with pytest.raises(DispatcherError) as captured:
        dispatcher.submit_transition(_sign_transition(requester, fields))
    assert captured.value.code == "ERR_STATE_MISMATCH"
