from __future__ import annotations

import copy
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from confirm_policy import confirm_policy_candidate
from tacvm_policy_core import PolicyError, build_candidate, load_policy_bundle


FIXTURE = (
    Path(__file__).parents[2]
    / "policy-aggregation-core"
    / "fixtures"
    / "three-party-proposals.yaml"
)
PARTICIPANT_ORDER = ("id_M", "id_D", "id_O")


def test_confirms_only_the_locally_verified_candidate():
    context, proposals = load_policy_bundle(FIXTURE)
    by_participant = {
        proposal["author"]["participant_id"]: proposal for proposal in proposals
    }
    bundle = build_candidate(context, PARTICIPANT_ORDER, by_participant)
    proposal = by_participant["id_M"]
    private_key = Ed25519PrivateKey.generate()

    confirmation = confirm_policy_candidate(
        "id_M", proposal, context, bundle, private_key
    )
    assert confirmation["candidate_digest"] == bundle["candidate_digest"]
    assert confirmation["policy_id"] == context["policy_id"]

    forged = copy.deepcopy(bundle)
    forged["candidate_digest"] = "sha384:forged"
    with pytest.raises(PolicyError) as captured:
        confirm_policy_candidate("id_M", proposal, context, forged, private_key)
    assert captured.value.code == "CANDIDATE_DIGEST_MISMATCH"
