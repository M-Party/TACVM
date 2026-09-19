from __future__ import annotations

import base64
import copy
from typing import Any, Callable, Dict, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from tacvm_policy_core import (
    PolicyError,
    build_candidate_from_accepted,
    normalize_proposal,
    proposal_digest,
    validate_proposal,
    validate_round_context,
)
from tacvm_protocol import canonical_encode


def proposal_signing_message(
    participant_id: str,
    context: Mapping[str, Any],
    digest_value: str,
) -> bytes:
    return canonical_encode(
        "TACVM-PROPOSAL",
        {
            "participant_id": participant_id,
            "policy_id": context["policy_id"],
            "version": context["version"],
            "round": context["round"],
            "proposal_digest": digest_value,
        },
    )


def confirmation_signing_message(
    participant_id: str,
    context: Mapping[str, Any],
    digest_value: str,
) -> bytes:
    return canonical_encode(
        "TACVM-CONFIRM",
        {
            "participant_id": participant_id,
            "policy_id": context["policy_id"],
            "version": context["version"],
            "round": context["round"],
            "candidate_digest": digest_value,
        },
    )


class PolicyCoordinator:
    """Operation CVM state machine for one policy negotiation round."""

    def __init__(
        self,
        context: Mapping[str, Any],
        participant_keys: Mapping[str, Ed25519PublicKey],
    ) -> None:
        self.context = copy.deepcopy(dict(context))
        validate_round_context(self.context)
        self.participant_keys = dict(participant_keys)
        self.participant_order = list(participant_keys)
        if not self.participant_order:
            raise PolicyError(
                "EMPTY_PARTICIPANT_SET",
                "At least one manifest participant is required",
            )
        if len(self.participant_order) != len(set(self.participant_order)):
            raise PolicyError(
                "DUPLICATE_PARTICIPANT",
                "Manifest participant identifiers must be unique",
            )

        self.state = "COLLECTING_PROPOSALS"
        self.proposals: Dict[str, Dict[str, Any]] = {}
        self.candidate_bundle: Optional[Dict[str, Any]] = None
        self.confirmations: Dict[str, Dict[str, Any]] = {}
        self.active: Optional[Dict[str, Any]] = None

    def proposal_request(self) -> Dict[str, Any]:
        return {
            "message_type": "TACVM-POLICY-REQUEST",
            "context": copy.deepcopy(self.context),
        }

    def proposal_request_message(self, participant_id: str) -> Dict[str, Any]:
        if self.state != "COLLECTING_PROPOSALS":
            raise PolicyError("ROUND_CLOSED", "Proposal collection is closed")
        if participant_id not in self.participant_keys:
            raise PolicyError(
                "UNKNOWN_PARTICIPANT",
                f"No manifest participant named {participant_id}",
            )
        return {
            **self.proposal_request(),
            "recipient_id": participant_id,
        }

    def distribute_proposal_request(
        self,
        send_message: Callable[[str, Mapping[str, Any]], None],
    ) -> None:
        for participant_id in self.participant_order:
            send_message(
                participant_id,
                self.proposal_request_message(participant_id),
            )

    def submit_proposal(self, envelope: Mapping[str, Any]) -> str:
        if self.state != "COLLECTING_PROPOSALS":
            raise PolicyError("ROUND_CLOSED", "Proposal collection is closed")

        proposal = envelope.get("proposal")
        if not isinstance(proposal, Mapping):
            raise PolicyError("INVALID_PROPOSAL", "Proposal body is missing")
        participant_id = proposal.get("author", {}).get("participant_id")
        public_key = self.participant_keys.get(participant_id)
        if public_key is None:
            raise PolicyError(
                "ERR_UNKNOWN_PARTICIPANT",
                f"No policy key is bound for {participant_id}",
            )
        if participant_id in self.proposals:
            raise PolicyError(
                "ERR_DUPLICATE_PROPOSAL",
                f"{participant_id} already submitted a proposal",
            )
        try:
            validate_proposal(proposal, self.context, set(self.participant_keys))
        except PolicyError as exc:
            if exc.code == "REJECT_CONTEXT":
                proposal_context = proposal.get("context", {})
                if proposal_context.get("policy_id") != self.context["policy_id"]:
                    raise PolicyError("ERR_POLICY_PID", str(exc)) from exc
                if proposal_context.get("version") != self.context["version"]:
                    raise PolicyError("ERR_POLICY_VERSION", str(exc)) from exc
                if proposal_context.get("round") != self.context["round"]:
                    raise PolicyError("ERR_POLICY_ROUND", str(exc)) from exc
            raise
        normalized = normalize_proposal(proposal)
        digest_value = proposal_digest(normalized, already_normalized=True)
        if digest_value != envelope.get("proposal_digest"):
            raise PolicyError(
                "PROPOSAL_DIGEST_MISMATCH",
                "Proposal digest does not match its body",
            )
        if envelope.get("signature_algorithm") != "Ed25519":
            raise PolicyError("UNSUPPORTED_SIGNATURE", "Only Ed25519 is supported")
        try:
            public_key.verify(
                base64.b64decode(envelope["signature"], validate=True),
                proposal_signing_message(
                    participant_id,
                    self.context,
                    digest_value,
                ),
            )
        except (InvalidSignature, KeyError, ValueError, TypeError):
            raise PolicyError(
                "ERR_POLICY_SIGNATURE",
                "Proposal signature verification failed",
            )

        self.proposals[participant_id] = {
            "proposal": normalized,
            "proposal_digest": digest_value,
            "signature_algorithm": "Ed25519",
            "signature": envelope["signature"],
        }
        return digest_value

    def build_candidate(self) -> Dict[str, Any]:
        if self.state != "COLLECTING_PROPOSALS":
            raise PolicyError("ROUND_CLOSED", "Candidate has already been built")
        missing = sorted(set(self.participant_keys) - set(self.proposals))
        if missing:
            raise PolicyError(
                "INCOMPLETE_PROPOSAL_SET",
                f"Missing proposals from {', '.join(missing)}",
            )

        proposals_by_participant = {
            participant_id: envelope
            for participant_id, envelope in self.proposals.items()
        }
        self.candidate_bundle = build_candidate_from_accepted(
            self.context,
            self.participant_order,
            proposals_by_participant,
        )
        self.state = "AWAITING_CONFIRMATIONS"
        return copy.deepcopy(self.candidate_bundle)

    def candidate_message(self, participant_id: str) -> Dict[str, Any]:
        if self.state != "AWAITING_CONFIRMATIONS" or self.candidate_bundle is None:
            raise PolicyError("NO_CANDIDATE", "No candidate is ready to send")
        if participant_id not in self.participant_keys:
            raise PolicyError(
                "UNKNOWN_PARTICIPANT",
                f"No manifest participant named {participant_id}",
            )
        return {
            "message_type": "TACVM-POLICY-CANDIDATE",
            "recipient_id": participant_id,
            **copy.deepcopy(self.candidate_bundle),
        }

    def distribute_candidate(
        self,
        send_message: Callable[[str, Mapping[str, Any]], None],
    ) -> None:
        """Send the same candidate over each participant's authenticated channel."""

        for participant_id in self.participant_order:
            send_message(
                participant_id,
                self.candidate_message(participant_id),
            )

    def submit_confirmation(self, confirmation: Mapping[str, Any]) -> None:
        if self.state != "AWAITING_CONFIRMATIONS" or self.candidate_bundle is None:
            raise PolicyError("NO_CANDIDATE", "No candidate is awaiting confirmation")

        participant_id = confirmation.get("participant_id")
        public_key = self.participant_keys.get(participant_id)
        if public_key is None:
            raise PolicyError(
                "UNKNOWN_PARTICIPANT",
                f"No policy key is bound for {participant_id}",
            )
        if participant_id in self.confirmations:
            raise PolicyError(
                "DUPLICATE_CONFIRMATION",
                f"{participant_id} already confirmed this candidate",
            )

        for field, code in (
            ("policy_id", "ERR_POLICY_PID"),
            ("version", "ERR_POLICY_VERSION"),
            ("round", "ERR_POLICY_ROUND"),
        ):
            if confirmation.get(field) != self.context[field]:
                raise PolicyError(
                    code,
                    f"Confirmation has an unexpected {field}",
                )
        digest_value = self.candidate_bundle["candidate_digest"]
        if confirmation.get("candidate_digest") != digest_value:
            raise PolicyError(
                "ERR_CONFIRM_HASH",
                "Confirmation targets another candidate",
            )
        if confirmation.get("signature_algorithm") != "Ed25519":
            raise PolicyError("UNSUPPORTED_SIGNATURE", "Only Ed25519 is supported")
        try:
            public_key.verify(
                base64.b64decode(confirmation["signature"], validate=True),
                confirmation_signing_message(
                    participant_id,
                    self.context,
                    digest_value,
                ),
            )
        except (InvalidSignature, KeyError, ValueError, TypeError):
            raise PolicyError(
                "INVALID_CONFIRMATION_SIGNATURE",
                "Confirmation signature verification failed",
            )

        self.confirmations[participant_id] = copy.deepcopy(dict(confirmation))

    def activate(self) -> Dict[str, Any]:
        if self.state != "AWAITING_CONFIRMATIONS" or self.candidate_bundle is None:
            raise PolicyError("NO_CANDIDATE", "No candidate can be activated")
        missing = sorted(set(self.participant_keys) - set(self.confirmations))
        if missing:
            raise PolicyError(
                "INCOMPLETE_CONFIRMATION_SET",
                f"Missing confirmations from {', '.join(missing)}",
            )

        self.active = {
            "context": copy.deepcopy(self.context),
            "candidate": copy.deepcopy(self.candidate_bundle["candidate"]),
            "candidate_digest": self.candidate_bundle["candidate_digest"],
            "confirmations": [
                copy.deepcopy(self.confirmations[participant_id])
                for participant_id in self.participant_order
            ],
        }
        self.state = "ACTIVE"
        return copy.deepcopy(self.active)

    def activation_message(self, participant_id: str) -> Dict[str, Any]:
        if self.state != "ACTIVE" or self.active is None:
            raise PolicyError("POLICY_INACTIVE", "No policy is active")
        if participant_id not in self.participant_keys:
            raise PolicyError(
                "UNKNOWN_PARTICIPANT",
                f"No manifest participant named {participant_id}",
            )
        return {
            "message_type": "TACVM-POLICY-ACTIVATED",
            "recipient_id": participant_id,
            "context": copy.deepcopy(self.context),
            "candidate_digest": self.active["candidate_digest"],
        }

    def distribute_activation(
        self,
        send_message: Callable[[str, Mapping[str, Any]], None],
    ) -> None:
        for participant_id in self.participant_order:
            send_message(
                participant_id,
                self.activation_message(participant_id),
            )
