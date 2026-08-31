from __future__ import annotations

import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from confirm_policy import confirm_policy_candidate
from coordinator import PolicyCoordinator, proposal_signing_message
from tacvm_policy_core import load_policy_bundle, normalize_proposal, proposal_digest


def sign_proposal(proposal, private_key):
    proposal = normalize_proposal(proposal)
    digest_value = proposal_digest(proposal)
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


def main() -> None:
    fixture = (
        Path(__file__).parents[1]
        / "policy-aggregation-core"
        / "fixtures"
        / "three-party-proposals.yaml"
    )
    context, proposals = load_policy_bundle(fixture)
    private_keys = {
        proposal["author"]["participant_id"]: Ed25519PrivateKey.generate()
        for proposal in proposals
    }
    participant_keys = {
        participant_id: private_key.public_key()
        for participant_id, private_key in private_keys.items()
    }
    coordinator = PolicyCoordinator(context, participant_keys)

    for proposal in proposals:
        participant_id = proposal["author"]["participant_id"]
        coordinator.submit_proposal(
            sign_proposal(proposal, private_keys[participant_id])
        )

    bundle = coordinator.build_candidate()
    inboxes = {}
    coordinator.distribute_candidate(
        lambda participant_id, message: inboxes.__setitem__(participant_id, message)
    )

    by_participant = {
        proposal["author"]["participant_id"]: proposal for proposal in proposals
    }
    for participant_id in participant_keys:
        confirmation = confirm_policy_candidate(
            participant_id,
            by_participant[participant_id],
            context,
            inboxes[participant_id],
            private_keys[participant_id],
        )
        coordinator.submit_confirmation(confirmation)

    active = coordinator.activate()
    print(
        json.dumps(
            {
                "state": coordinator.state,
                "candidate_digest": bundle["candidate_digest"],
                "confirmation_count": len(active["confirmations"]),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
