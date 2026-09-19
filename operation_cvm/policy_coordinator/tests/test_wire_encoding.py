from __future__ import annotations

import copy
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from confirm_policy import confirm_policy_candidate
from coordinator import (
    PolicyCoordinator,
    confirmation_signing_message,
    proposal_signing_message,
)
from tacvm_policy_core import PolicyError, load_policy_bundle, proposal_digest
from tacvm_protocol import canonical_encode


FIXTURE = (
    Path(__file__).resolve().parents[2] / "policy_aggregation" / "fixtures"
    / "three-party-proposals.yaml"
)


def test_proposal_and_confirm_messages_use_protocol_canonical_encode():
    context = {"policy_id": "pid", "version": 1, "round": 0}
    proposal_msg = proposal_signing_message("id_M", context, "sha384:abc")
    assert proposal_msg == canonical_encode(
        "TACVM-PROPOSAL",
        {
            "participant_id": "id_M",
            "policy_id": "pid",
            "version": 1,
            "round": 0,
            "proposal_digest": "sha384:abc",
        },
    )
    confirm_msg = confirmation_signing_message("id_M", context, "sha384:cand")
    assert confirm_msg == canonical_encode(
        "TACVM-CONFIRM",
        {
            "participant_id": "id_M",
            "policy_id": "pid",
            "version": 1,
            "round": 0,
            "candidate_digest": "sha384:cand",
        },
    )


def test_wrong_policy_round_fields_use_stable_error_codes():
    context, proposals = load_policy_bundle(FIXTURE)
    private_keys = {
        proposal["author"]["participant_id"]: Ed25519PrivateKey.generate()
        for proposal in proposals
    }
    participant_keys = {
        participant_id: key.public_key() for participant_id, key in private_keys.items()
    }
    coordinator = PolicyCoordinator(context, participant_keys)

    first = proposals[0]
    participant_id = first["author"]["participant_id"]
    wrong = copy.deepcopy(first)
    wrong["context"] = dict(context)
    wrong["context"]["round"] = context["round"] + 1
    from coordinator import proposal_signing_message as sign_msg
    from tacvm_policy_core import normalize_proposal
    import base64

    normalized = normalize_proposal(wrong)
    digest_value = proposal_digest(normalized, already_normalized=True)
    envelope = {
        "proposal": normalized,
        "proposal_digest": digest_value,
        "signature_algorithm": "Ed25519",
        "signature": base64.b64encode(
            private_keys[participant_id].sign(
                sign_msg(participant_id, wrong["context"], digest_value)
            )
        ).decode("ascii"),
    }
    with pytest.raises(PolicyError) as captured:
        coordinator.submit_proposal(envelope)
    assert captured.value.code == "ERR_POLICY_ROUND"
