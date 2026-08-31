from __future__ import annotations

import base64
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from confirm_policy import confirm_policy_candidate
from coordinator import PolicyCoordinator, proposal_signing_message
from tacvm_policy_core import (
    PolicyError,
    load_policy_bundle,
    normalize_proposal,
    proposal_digest,
)


FIXTURE = (
    Path(__file__).parents[2]
    / "policy-aggregation-core"
    / "fixtures"
    / "three-party-proposals.yaml"
)


def sign_proposal(proposal, private_key):
    proposal = normalize_proposal(proposal)
    digest_value = proposal_digest(proposal)
    participant_id = proposal["author"]["participant_id"]
    return {
        "proposal": proposal,
        "proposal_digest": digest_value,
        "signature_algorithm": "Ed25519",
        "signature": base64.b64encode(
            private_key.sign(
                proposal_signing_message(
                    participant_id,
                    proposal["context"],
                    digest_value,
                )
            )
        ).decode("ascii"),
    }


def setup_round():
    context, proposals = load_policy_bundle(FIXTURE)
    private_keys = {
        proposal["author"]["participant_id"]: Ed25519PrivateKey.generate()
        for proposal in proposals
    }
    participant_keys = {
        participant_id: private_key.public_key()
        for participant_id, private_key in private_keys.items()
    }
    coordinator = PolicyCoordinator(context, participant_keys)
    for proposal in reversed(proposals):
        participant_id = proposal["author"]["participant_id"]
        coordinator.submit_proposal(
            sign_proposal(proposal, private_keys[participant_id])
        )
    return context, proposals, private_keys, coordinator


def test_distributes_one_candidate_and_activates_after_unanimous_confirmation():
    context, proposals, private_keys, coordinator = setup_round()
    bundle = coordinator.build_candidate()
    messages = {}
    coordinator.distribute_candidate(
        lambda participant_id, message: messages.__setitem__(participant_id, message)
    )
    assert len(messages) == 3
    assert {
        message["candidate_digest"] for message in messages.values()
    } == {bundle["candidate_digest"]}

    by_participant = {
        proposal["author"]["participant_id"]: proposal for proposal in proposals
    }
    for participant_id in private_keys:
        coordinator.submit_confirmation(
            confirm_policy_candidate(
                participant_id,
                by_participant[participant_id],
                context,
                messages[participant_id],
                private_keys[participant_id],
            )
        )

    active = coordinator.activate()
    assert coordinator.state == "ACTIVE"
    assert active["candidate_digest"] == bundle["candidate_digest"]

    notices = {}
    coordinator.distribute_activation(
        lambda participant_id, message: notices.__setitem__(participant_id, message)
    )
    assert set(notices) == set(private_keys)


def test_missing_confirmation_keeps_candidate_inactive():
    context, proposals, private_keys, coordinator = setup_round()
    coordinator.build_candidate()
    by_participant = {
        proposal["author"]["participant_id"]: proposal for proposal in proposals
    }
    for participant_id in ("id_M", "id_D"):
        message = coordinator.candidate_message(participant_id)
        coordinator.submit_confirmation(
            confirm_policy_candidate(
                participant_id,
                by_participant[participant_id],
                context,
                message,
                private_keys[participant_id],
            )
        )

    with pytest.raises(PolicyError) as captured:
        coordinator.activate()
    assert captured.value.code == "INCOMPLETE_CONFIRMATION_SET"
    assert coordinator.state == "AWAITING_CONFIRMATIONS"
