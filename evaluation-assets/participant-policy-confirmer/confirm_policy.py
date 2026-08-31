from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
from typing import Any, Dict, Mapping

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tacvm_policy_core import (
    PolicyError,
    candidate_digest,
    canonical_json,
    verify_candidate_against_proposal,
)


def _confirmation_message(
    participant_id: str,
    context: Mapping[str, Any],
    digest_value: str,
) -> bytes:
    return canonical_json(
        {
            "domain": "TACVM-CONFIRM",
            "participant_id": participant_id,
            "policy_id": context["policy_id"],
            "version": context["version"],
            "round": context["round"],
            "candidate_digest": digest_value,
        }
    ).encode("utf-8")


def sign_confirmation(
    participant_id: str,
    context: Mapping[str, Any],
    digest_value: str,
    policy_private_key: Ed25519PrivateKey,
) -> Dict[str, Any]:
    signature = policy_private_key.sign(
        _confirmation_message(participant_id, context, digest_value)
    )
    return {
        "participant_id": participant_id,
        "policy_id": context["policy_id"],
        "version": context["version"],
        "round": context["round"],
        "candidate_digest": digest_value,
        "signature_algorithm": "Ed25519",
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def confirm_policy_candidate(
    participant_id: str,
    own_proposal: Mapping[str, Any],
    expected_context: Mapping[str, Any],
    candidate_bundle: Mapping[str, Any],
    policy_private_key: Ed25519PrivateKey,
) -> Dict[str, Any]:
    """Verify one candidate policy and return a TACVM-CONFIRM envelope."""

    if own_proposal.get("author", {}).get("participant_id") != participant_id:
        raise PolicyError(
            "PARTICIPANT_ID_MISMATCH",
            "The proposal author does not match the confirming participant",
        )

    candidate = candidate_bundle.get("candidate")
    supplied_digest = candidate_bundle.get("candidate_digest")
    if not isinstance(candidate, Mapping) or not isinstance(supplied_digest, str):
        raise PolicyError(
            "INVALID_CANDIDATE_BUNDLE",
            "The bundle must contain candidate and candidate_digest",
        )
    if candidate.get("schema") != "tacvm-policy-candidate/v0.2":
        raise PolicyError(
            "UNSUPPORTED_CANDIDATE_SCHEMA",
            f"Unsupported candidate schema {candidate.get('schema')}",
        )

    if canonical_json(candidate.get("context")) != canonical_json(expected_context):
        raise PolicyError(
            "CANDIDATE_CONTEXT_MISMATCH",
            "The candidate does not belong to the expected policy round",
        )

    local_digest = candidate_digest(candidate)
    if local_digest != supplied_digest:
        raise PolicyError(
            "CANDIDATE_DIGEST_MISMATCH",
            "The supplied digest does not match the received candidate",
        )

    verify_candidate_against_proposal(candidate, own_proposal)

    return sign_confirmation(
        participant_id,
        expected_context,
        local_digest,
        policy_private_key,
    )


def _load_document(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as source:
        document = yaml.safe_load(source)
    if not isinstance(document, dict):
        raise ValueError(f"{path} must contain one mapping")
    return document


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    with path.open("rb") as source:
        private_key = serialization.load_pem_private_key(
            source.read(),
            password=None,
        )
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("policy private key must be an Ed25519 private key")
    return private_key


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify and confirm one TACVM candidate policy",
    )
    parser.add_argument("--participant-id", required=True)
    parser.add_argument("--proposal", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--policy-private-key", type=Path, required=True)
    parser.add_argument("--policy-id", required=True)
    parser.add_argument("--version", type=int, required=True)
    parser.add_argument("--round", dest="round_number", type=int, required=True)
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    context = {
        "policy_id": args.policy_id,
        "version": args.version,
        "round": args.round_number,
    }
    confirmation = confirm_policy_candidate(
        participant_id=args.participant_id,
        own_proposal=_load_document(args.proposal),
        expected_context=context,
        candidate_bundle=_load_document(args.candidate),
        policy_private_key=_load_private_key(args.policy_private_key),
    )
    print(json.dumps(confirmation, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
