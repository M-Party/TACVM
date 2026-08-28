from __future__ import annotations

import copy
from pathlib import Path

import pytest

from tacvm_policy import (
    PolicyAggregator,
    PolicyError,
    generate_participant_key_pair,
    load_policy_bundle,
    sign_confirmation,
    sign_proposal,
    verify_candidate_against_proposal,
)


FIXTURE = Path(__file__).parents[1] / "fixtures" / "three-party-proposals.yaml"


def make_fixture():
    context, proposals = load_policy_bundle(FIXTURE)
    keys = {
        proposal["author"]["slot"]: generate_participant_key_pair()
        for proposal in proposals
    }
    roster = {slot: pair[1] for slot, pair in keys.items()}
    return context, proposals, keys, roster


def build(context, proposals, keys, roster, order=("s1", "s2", "s3")):
    aggregator = PolicyAggregator(context=context, roster=roster)
    by_slot = {proposal["author"]["slot"]: proposal for proposal in proposals}
    for slot in order:
        aggregator.submit_proposal(sign_proposal(by_slot[slot], keys[slot][0]))
    result = aggregator.build_candidate()
    return aggregator, result["candidate"], result["candidate_digest"]


def assert_code(code, action):
    with pytest.raises(PolicyError) as captured:
        action()
    assert captured.value.code == code


def test_joins_three_compatible_proposals_restrictively():
    context, proposals, keys, roster = make_fixture()
    _, candidate, _ = build(context, proposals, keys, roster)
    policy = candidate["policy"]

    workload = policy["workload_cvms"]["entries"]["inference-cvm"]
    assert workload["measurements"]["mrtd"]["allowed"] == ["MRTD_A"]
    assert workload["measurements"]["rootfs"]["allowed_root_hashes"] == [
        "ROOTFS_R1"
    ]
    assert workload["quote_verification"]["accepted_tcb_statuses"] == [
        "UP_TO_DATE"
    ]
    assert policy["artifacts"]["entries"]["inference-service"][
        "allowed_content_digests"
    ] == ["ARTIFACT_H1"]
    assert policy["communications"]["entries"]["client-api"]["peer_identity"][
        "spki_sha256"
    ] == ["CLIENT_SPKI"]
    assert len(policy["lifecycle"]["rules"]) == 4
    assert not any(
        rule["operation"] == "delete" and rule["from"] == "running"
        for rule in policy["lifecycle"]["rules"]
    )


def test_candidate_digest_is_independent_of_arrival_order():
    context, proposals, keys, roster = make_fixture()
    _, _, first = build(context, proposals, keys, roster, ("s1", "s2", "s3"))
    _, _, second = build(context, proposals, keys, roster, ("s3", "s1", "s2"))
    assert first == second


def test_all_participants_confirm_before_activation():
    context, proposals, keys, roster = make_fixture()
    aggregator, candidate, digest_value = build(context, proposals, keys, roster)
    for proposal in proposals:
        slot = proposal["author"]["slot"]
        assert verify_candidate_against_proposal(candidate, proposal)
        aggregator.submit_confirmation(
            sign_confirmation(slot, context, digest_value, keys[slot][0])
        )
    active = aggregator.activate()
    assert active["candidate_digest"] == digest_value
    assert len(active["confirmations"]) == 3


def test_missing_confirmation_keeps_policy_inactive():
    context, proposals, keys, roster = make_fixture()
    aggregator, _, digest_value = build(context, proposals, keys, roster)
    for slot in ("s1", "s2"):
        aggregator.submit_confirmation(
            sign_confirmation(slot, context, digest_value, keys[slot][0])
        )
    assert_code("INCOMPLETE_CONFIRMATION_SET", aggregator.activate)


def test_rejects_proposal_signed_by_another_slot():
    context, proposals, keys, roster = make_fixture()
    aggregator = PolicyAggregator(context=context, roster=roster)
    assert_code(
        "INVALID_PROPOSAL_SIGNATURE",
        lambda: aggregator.submit_proposal(sign_proposal(proposals[0], keys["s2"][0])),
    )


def test_role_conflict_returns_bottom():
    context, proposals, keys, roster = make_fixture()
    proposals[1]["roles"]["assignments"]["s3"] = "auditor"
    aggregator = PolicyAggregator(context=context, roster=roster)
    for proposal in proposals:
        slot = proposal["author"]["slot"]
        aggregator.submit_proposal(sign_proposal(proposal, keys[slot][0]))
    assert_code("BOTTOM_ROLE_CONFLICT", aggregator.build_candidate)


def test_disjoint_artifact_digests_return_bottom():
    context, proposals, keys, roster = make_fixture()
    proposals[1]["artifacts"]["entries"]["inference-service"][
        "allowed_content_digests"
    ] = ["ARTIFACT_H3"]
    aggregator = PolicyAggregator(context=context, roster=roster)
    for proposal in proposals:
        slot = proposal["author"]["slot"]
        aggregator.submit_proposal(sign_proposal(proposal, keys[slot][0]))
    assert_code("BOTTOM_EMPTY_ARTIFACT_SET", aggregator.build_candidate)


def test_participant_rejects_weakened_candidate():
    context, proposals, keys, roster = make_fixture()
    _, candidate, _ = build(context, proposals, keys, roster)
    candidate = copy.deepcopy(candidate)
    candidate["policy"]["artifacts"]["entries"]["inference-service"][
        "allowed_content_digests"
    ].append("ATTACKER_DIGEST")
    assert_code(
        "CANDIDATE_WEAKENS_PROPOSAL",
        lambda: verify_candidate_against_proposal(candidate, proposals[1]),
    )
