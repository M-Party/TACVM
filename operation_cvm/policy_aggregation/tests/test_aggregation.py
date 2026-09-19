from __future__ import annotations

import copy
from pathlib import Path

import pytest

from tacvm_policy_core import (
    PolicyError,
    build_candidate,
    load_policy_bundle,
    verify_candidate_against_proposal,
)


FIXTURE = Path(__file__).parents[1] / "fixtures" / "three-party-proposals.yaml"
PARTICIPANT_ORDER = ("id_M", "id_D", "id_O")


def fixture():
    context, proposals = load_policy_bundle(FIXTURE)
    by_participant = {
        proposal["author"]["participant_id"]: proposal for proposal in proposals
    }
    return context, proposals, by_participant


def assert_code(code, action):
    with pytest.raises(PolicyError) as captured:
        action()
    assert captured.value.code == code


def test_joins_three_compatible_proposals_restrictively():
    context, _, by_participant = fixture()
    result = build_candidate(context, PARTICIPANT_ORDER, by_participant)
    policy = result["candidate"]["policy"]

    workload = policy["workload_cvms"]["entries"]["inference-cvm"]
    assert workload["measurements"]["mrtd"]["allowed"] == ["MRTD_A"]
    assert workload["measurements"]["rootfs"]["allowed_root_hashes"] == [
        "ROOTFS_R1"
    ]
    assert policy["artifacts"]["entries"]["inference-service"][
        "allowed_content_digests"
    ] == ["ARTIFACT_H1"]
    assert len(policy["lifecycle"]["rules"]) == 4


def test_candidate_is_deterministic_and_manifest_ordered():
    context, _, by_participant = fixture()
    reversed_map = dict(reversed(list(by_participant.items())))
    first = build_candidate(context, PARTICIPANT_ORDER, by_participant)
    second = build_candidate(context, PARTICIPANT_ORDER, reversed_map)

    assert first["candidate_digest"] == second["candidate_digest"]
    assert [
        item["participant_id"] for item in first["candidate"]["inputs"]
    ] == list(PARTICIPANT_ORDER)


def test_rejects_incomplete_or_wrong_round_inputs():
    context, _, by_participant = fixture()
    incomplete = dict(by_participant)
    incomplete.pop("id_D")
    assert_code(
        "INCOMPLETE_PROPOSAL_SET",
        lambda: build_candidate(context, PARTICIPANT_ORDER, incomplete),
    )

    wrong_round = copy.deepcopy(by_participant)
    wrong_round["id_M"]["context"]["round"] += 1
    assert_code(
        "REJECT_CONTEXT",
        lambda: build_candidate(context, PARTICIPANT_ORDER, wrong_round),
    )


def test_conflicts_abort_without_weakening_inputs():
    context, proposals, by_participant = fixture()
    role_conflict = copy.deepcopy(by_participant)
    role_conflict["id_D"]["roles"]["assignments"]["id_O"] = "auditor"
    assert_code(
        "BOTTOM_ROLE_CONFLICT",
        lambda: build_candidate(context, PARTICIPANT_ORDER, role_conflict),
    )

    result = build_candidate(context, PARTICIPANT_ORDER, by_participant)
    for proposal in proposals:
        assert verify_candidate_against_proposal(result["candidate"], proposal)


def test_participant_rejects_weakened_candidate():
    context, proposals, by_participant = fixture()
    candidate = build_candidate(context, PARTICIPANT_ORDER, by_participant)[
        "candidate"
    ]
    candidate["policy"]["artifacts"]["entries"]["inference-service"][
        "allowed_content_digests"
    ].append("ATTACKER_DIGEST")
    assert_code(
        "CANDIDATE_WEAKENS_PROPOSAL",
        lambda: verify_candidate_against_proposal(candidate, proposals[1]),
    )
