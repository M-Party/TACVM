from __future__ import annotations

import json
from pathlib import Path

from tacvm_policy import (
    PolicyAggregator,
    generate_participant_key_pair,
    load_policy_bundle,
    sign_confirmation,
    sign_proposal,
    verify_candidate_against_proposal,
)


def main() -> None:
    fixture = Path(__file__).parent / "fixtures" / "three-party-proposals.yaml"
    context, proposals = load_policy_bundle(fixture)

    key_pairs = {
        proposal["author"]["slot"]: generate_participant_key_pair()
        for proposal in proposals
    }
    roster = {slot: pair[1] for slot, pair in key_pairs.items()}
    aggregator = PolicyAggregator(context=context, roster=roster)

    # Arrival order does not affect the canonical candidate.
    by_slot = {proposal["author"]["slot"]: proposal for proposal in proposals}
    for slot in ("s3", "s1", "s2"):
        aggregator.submit_proposal(sign_proposal(by_slot[slot], key_pairs[slot][0]))

    result = aggregator.build_candidate()
    candidate = result["candidate"]
    digest_value = result["candidate_digest"]

    for proposal in proposals:
        slot = proposal["author"]["slot"]
        verify_candidate_against_proposal(candidate, proposal)
        aggregator.submit_confirmation(
            sign_confirmation(slot, context, digest_value, key_pairs[slot][0])
        )

    print(json.dumps(aggregator.activate(), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
