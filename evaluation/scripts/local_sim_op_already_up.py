#!/usr/bin/env python3
"""Local simulation: Operation CVM already up (skip real TDX boot/Quote).

Assumes on the coauthor TDX host someone already:
  - launched Operation CVM
  - established TACVM-BOOT / pk_ch channel
  - published protocol id pid

This script then exercises the remaining portable path with TACVM_TEE_BACKEND=mock:

  1) participants ACCEPT → registry barrier
  2) proposals → candidate → CONFIRM → activate
  3) create lambda_w → mock-provision → authenticate → LIVE B_w
  4) signed TACVM-TRANS admit → dispatcher → Trusted Service COMMITTED
"""

from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [
    str(REPO / "shared" / "protocol"),
    str(REPO / "operation_cvm" / "policy_aggregation"),
    str(REPO / "operation_cvm" / "policy_coordinator"),
    str(REPO / "operation_cvm" / "participant_registry"),
    str(REPO / "operation_cvm" / "workload_launch"),
    str(REPO / "operation_cvm" / "dispatcher"),
    str(REPO / "workload_cvm" / "trusted_service"),
    str(REPO / "participants" / "policy_confirmer"),
]

os.environ.setdefault("TACVM_TEE_BACKEND", "mock")

from confirm_policy import confirm_policy_candidate  # noqa: E402
from coordinator import PolicyCoordinator, proposal_signing_message  # noqa: E402
from dispatcher import TransitionDispatcher  # noqa: E402
from launch import WorkloadLaunchFSM  # noqa: E402
from registry import BootManifestParticipant, ParticipantRegistry  # noqa: E402
from tacvm_policy_core import (  # noqa: E402
    load_policy_bundle,
    normalize_proposal,
    proposal_digest,
)
from tacvm_protocol import canonical_encode, get_tee_backend  # noqa: E402


def _step(name: str, detail: dict) -> None:
    print(f"[PASS] {name}")
    print(json.dumps(detail, indent=2, sort_keys=True))
    print()


def _sign_accept(registry: ParticipantRegistry, participant_id: str, boot_sk, policy_sk):
    pk_policy = policy_sk.public_key().public_bytes_raw().hex()
    fields = {
        "participant_id": participant_id,
        "d_M": registry.d_M,
        "pk_ch": registry.pk_ch,
        "pk_policy": pk_policy,
    }
    body = canonical_encode("TACVM-ACCEPT", fields)
    return {
        **fields,
        "boot_signature": boot_sk.sign(body),
        "policy_signature": policy_sk.sign(body),
    }


def _sign_proposal(proposal, private_key):
    proposal = normalize_proposal(proposal)
    digest_value = proposal_digest(proposal, already_normalized=True)
    participant_id = proposal["author"]["participant_id"]
    signature = private_key.sign(
        proposal_signing_message(participant_id, proposal["context"], digest_value)
    )
    return {
        "proposal": proposal,
        "proposal_digest": digest_value,
        "signature_algorithm": "Ed25519",
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def _sign_transition(private_key, fields):
    body = canonical_encode("TACVM-TRANS", fields)
    return {**fields, "signature": private_key.sign(body)}


def main() -> int:
    # --- Premise: Operation CVM already authenticated in TDX ---
    pid = "pid-local-sim-1"
    pk_ch = "pk-op-channel-mock"
    d_M = "sha384:boot-manifest-mock"
    tee = get_tee_backend("mock")
    _step(
        "0. assume Operation CVM already up (mock substitutes TDX Quote)",
        {"pid": pid, "pk_ch": pk_ch, "d_M": d_M, "tee": tee.name},
    )

    fixture = (
        REPO
        / "operation_cvm"
        / "policy_aggregation"
        / "fixtures"
        / "three-party-proposals.yaml"
    )
    context, proposals = load_policy_bundle(fixture)

    boot_keys = {
        p["author"]["participant_id"]: Ed25519PrivateKey.generate() for p in proposals
    }
    policy_keys = {
        p["author"]["participant_id"]: Ed25519PrivateKey.generate() for p in proposals
    }
    order = [p["author"]["participant_id"] for p in proposals]

    # 1) ACCEPT / registry
    registry = ParticipantRegistry(
        d_M=d_M,
        pk_ch=pk_ch,
        participants=[
            BootManifestParticipant(
                participant_id=pid_,
                boot_public_key=boot_keys[pid_].public_key(),
                expected_protocol_id=pid,
            )
            for pid_ in order
        ],
    )
    for pid_ in order:
        registry.submit_acceptance(
            _sign_accept(registry, pid_, boot_keys[pid_], policy_keys[pid_])
        )
    assert registry.all_registered()
    _step(
        "1. Operation CVM registry: all TACVM-ACCEPT registered",
        {"participants": order, "all_registered": True},
    )

    # 2) Policy round
    coordinator = PolicyCoordinator(
        context,
        {
            pid_: policy_keys[pid_].public_key()
            for pid_ in order
        },
    )
    by_participant = {}
    for proposal in proposals:
        proposal = dict(proposal)
        proposal["context"] = context
        participant_id = proposal["author"]["participant_id"]
        by_participant[participant_id] = proposal
        coordinator.submit_proposal(_sign_proposal(proposal, policy_keys[participant_id]))

    bundle = coordinator.build_candidate()
    inboxes = {}
    coordinator.distribute_candidate(
        lambda participant_id, message: inboxes.__setitem__(participant_id, message)
    )
    for participant_id in order:
        confirmation = confirm_policy_candidate(
            participant_id,
            by_participant[participant_id],
            context,
            inboxes[participant_id],
            policy_keys[participant_id],
        )
        coordinator.submit_confirmation(confirmation)
    active = coordinator.activate()
    policy_hash = bundle["candidate_digest"]
    _step(
        "2. Operation CVM policy: candidate confirmed and activated",
        {
            "state": coordinator.state,
            "candidate_digest": policy_hash,
            "confirmations": len(active["confirmations"]),
        },
    )

    # 3) Workload launch / B_w (mock = pretend TDX provisioned Workload CVM)
    launch_fsm = WorkloadLaunchFSM(tee=tee, pid=pid, pk_ch=pk_ch)
    w = "w-local-1"
    record = launch_fsm.create_launch(w)
    launch_fsm.mark_provisioning(w)
    binding = launch_fsm.authenticate_workload(
        w, pk_w="pk-workload-mock", challenge_n_w="bb" * 32
    )
    _step(
        "3. Operation CVM launch: LIVE B_w after mock provision+attest",
        {
            "w": w,
            "lambda_hash": record.lambda_hash,
            "binding_status": binding.status.value,
            "channel_id": binding.channel_id,
        },
    )

    # 4) Dispatcher → Trusted Service (Workload CVM local state)
    operator = Ed25519PrivateKey.generate()
    dispatcher = TransitionDispatcher(
        pid=pid,
        policy_hash=policy_hash,
        requester_keys={
            "id_O": operator.public_key().public_bytes_raw().hex(),
        },
        launch_fsm=launch_fsm,
        allowed_transitions={("admit", "ABSENT", "RUNNING")},
    )
    result = dispatcher.submit_transition(
        _sign_transition(
            operator,
            {
                "participant_id": "id_O",
                "pid": pid,
                "policy_hash": policy_hash,
                "u": "op-admit-1",
                "w": w,
                "operation": "admit",
                "prior_state": "ABSENT",
                "next_state": "RUNNING",
                "artifact_digest": "sha256:model-local-sim",
            },
        )
    )
    _step(
        "4. Operation CVM dispatcher → Workload CVM Trusted Service",
        result,
    )

    print("Local simulation OK (no real TDX Quotes / no fleet).")
    print("On TDX host: replace mock TeeBackend with real Quote/QVL/launch hooks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
