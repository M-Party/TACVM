from __future__ import annotations

import copy
from pathlib import Path

import pytest

from generate_homogeneous import build_homogeneous_bundle, participant_ids
from tacvm_policy_core import (
    PolicyError,
    build_candidate,
    load_policy_bundle,
    verify_candidate_against_proposal,
)


FIXTURE_DIR = Path(__file__).parents[1] / "fixtures"

HOMOGENEOUS_YAML = {
    4: FIXTURE_DIR / "four-party-homogeneous.yaml",
    8: FIXTURE_DIR / "eight-party-homogeneous.yaml",
    16: FIXTURE_DIR / "sixteen-party-homogeneous.yaml",
    32: FIXTURE_DIR / "thirty-two-party-homogeneous.yaml",
}


def assert_code(code, action):
    with pytest.raises(PolicyError) as captured:
        action()
    assert captured.value.code == code


@pytest.mark.parametrize("n", [4, 8, 16, 32])
def test_joins_homogeneous_proposals_from_yaml(n):
    context, proposals = load_policy_bundle(HOMOGENEOUS_YAML[n])
    order = participant_ids(n)
    by_participant = {
        proposal["author"]["participant_id"]: proposal for proposal in proposals
    }
    assert list(by_participant) == order

    result = build_candidate(context, order, by_participant)
    policy = result["candidate"]["policy"]
    assert [item["participant_id"] for item in result["candidate"]["inputs"]] == order
    assert policy["workload_cvms"]["entries"]["inference-cvm"]["measurements"]["mrtd"][
        "allowed"
    ] == ["MRTD_A"]
    assert policy["artifacts"]["entries"]["inference-service"][
        "allowed_content_digests"
    ] == ["ARTIFACT_H1"]
    assert len(policy["lifecycle"]["rules"]) == 4
    for proposal in proposals:
        assert verify_candidate_against_proposal(result["candidate"], proposal)


def test_generated_homogeneous_bundle_scales_and_rejects_gaps():
    bundle = build_homogeneous_bundle(n=32, rule_count=100)
    context = bundle["context"]
    proposals = bundle["proposals"]
    order = participant_ids(32)
    by_participant = {
        proposal["author"]["participant_id"]: proposal for proposal in proposals
    }

    result = build_candidate(context, order, by_participant)
    assert len(result["candidate"]["inputs"]) == 32
    assert len(result["candidate"]["policy"]["lifecycle"]["rules"]) == 100

    incomplete = copy.deepcopy(by_participant)
    incomplete.pop("id_16")
    assert_code(
        "INCOMPLETE_PROPOSAL_SET",
        lambda: build_candidate(context, order, incomplete),
    )
