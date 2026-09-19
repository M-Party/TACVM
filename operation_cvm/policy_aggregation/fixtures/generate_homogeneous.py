#!/usr/bin/env python3
"""Generate a homogeneous N-party policy fixture for scale testing.

Every participant submits the same restrictive body (the successful intersection
shape of the three-party fixture). Only author.participant_id differs. Use this
to exercise N-way join / confirmation without introducing policy conflicts.
"""

from __future__ import annotations

import argparse
import copy
from pathlib import Path
from typing import Any, Dict, List, Sequence

import yaml


DEFAULT_CONTEXT = {
    "policy_id": "sha384:POLICY_SCALE_N",
    "version": 1,
    "round": 0,
}

BASE_LIFECYCLE_RULES = [
    {
        "id": "admit",
        "workload": "inference-service",
        "workload_cvm": "inference-cvm",
        "operation": "admit",
        "requester": "role:operator",
        "from": "absent",
        "to": "running",
        "artifact": "inference-service",
        "secrets": ["bundle-key"],
        "communication_profiles": ["client-api"],
    },
    {
        "id": "update",
        "workload": "inference-service",
        "workload_cvm": "inference-cvm",
        "operation": "update",
        "requester": "role:model_owner",
        "from": "running",
        "to": "running",
        "artifact": "inference-service",
        "secrets": ["bundle-key"],
        "communication_profiles": ["client-api"],
    },
    {
        "id": "stop",
        "workload": "inference-service",
        "workload_cvm": "inference-cvm",
        "operation": "stop",
        "requester": "role:operator",
        "from": "running",
        "to": "stopped",
        "artifact": None,
        "secrets": [],
        "communication_profiles": [],
    },
    {
        "id": "delete-stopped",
        "workload": "inference-service",
        "workload_cvm": "inference-cvm",
        "operation": "delete",
        "requester": "role:operator",
        "from": "stopped",
        "to": "absent",
        "artifact": None,
        "secrets": [],
        "communication_profiles": [],
    },
]


def participant_ids(n: int) -> List[str]:
    if n < 1:
        raise ValueError("n must be >= 1")
    width = max(2, len(str(n)))
    return [f"id_{i:0{width}d}" for i in range(1, n + 1)]


def role_assignments(ids: Sequence[str]) -> Dict[str, str]:
    assignments: Dict[str, str] = {}
    for index, participant_id in enumerate(ids):
        if index == 0:
            assignments[participant_id] = "model_owner"
        elif index == 1:
            assignments[participant_id] = "data_owner"
        elif index == 2:
            assignments[participant_id] = "operator"
        else:
            assignments[participant_id] = "observer"
    return assignments


def lifecycle_rules(rule_count: int) -> List[Dict[str, Any]]:
    if rule_count < len(BASE_LIFECYCLE_RULES):
        raise ValueError(
            f"rule_count must be >= {len(BASE_LIFECYCLE_RULES)} "
            "(base admit/update/stop/delete edges)"
        )
    rules = [copy.deepcopy(rule) for rule in BASE_LIFECYCLE_RULES]
    # Pad with identical synthetic edges so every party still intersects fully.
    for index in range(rule_count - len(BASE_LIFECYCLE_RULES)):
        rules.append(
            {
                "id": f"synthetic-{index:04d}",
                "workload": f"inference-service-pad-{index:04d}",
                "workload_cvm": "inference-cvm",
                "operation": "admit",
                "requester": "role:operator",
                "from": "absent",
                "to": "running",
                "artifact": "inference-service",
                "secrets": ["bundle-key"],
                "communication_profiles": ["client-api"],
            }
        )
    return rules


def shared_policy_body(ids: Sequence[str], rule_count: int) -> Dict[str, Any]:
    return {
        "defaults": {
            "roles": "DENY",
            "workload_cvms": "DENY",
            "artifacts": "DENY",
            "secret_release": "DENY",
            "communications": "DENY",
            "lifecycle": "DENY",
        },
        "roles": {"assignments": role_assignments(ids)},
        "workload_cvms": {
            "entries": {
                "inference-cvm": {
                    "tee_type": "tdx",
                    "measurements": {
                        "mrtd": {"allowed": ["MRTD_A"]},
                        "rtmr": {},
                        "rootfs": {
                            "scheme": "dm_verity",
                            "allowed_root_hashes": ["ROOTFS_R1"],
                        },
                    },
                    "quote_verification": {
                        "require_valid_chain": True,
                        "accepted_tcb_statuses": ["UP_TO_DATE"],
                    },
                    "launch_context": {
                        "required_fields": [
                            "workload_cvm_id",
                            "policy_id",
                            "operation_cvm_channel_key",
                        ]
                    },
                    "trusted_service_channel": {
                        "single_post_boot_quote_required": True,
                        "proof_of_key_possession_required": True,
                    },
                }
            }
        },
        "artifacts": {
            "entries": {
                "inference-service": {
                    "kind": "container",
                    "allowed_content_digests": ["ARTIFACT_H1"],
                    "encryption": "REQUIRED",
                    "registrars": ["role:model_owner"],
                }
            }
        },
        "secret_release": {
            "entries": {
                "bundle-key": {
                    "secret_type": "artifact_key",
                    "artifact": "inference-service",
                    "workload_cvms": ["inference-cvm"],
                    "operations": ["admit", "update"],
                    "requesters": ["role:model_owner", "role:operator"],
                    "require_authenticated_binding": True,
                    "require_artifact_digest_match": True,
                }
            }
        },
        "communications": {
            "entries": {
                "client-api": {
                    "direction": "egress",
                    "protocol": "tcp",
                    "endpoints": [
                        {"host": "api.collaboration.test", "ports": [443]},
                    ],
                    "peer_identity": {"spki_sha256": ["CLIENT_SPKI"]},
                }
            }
        },
        "lifecycle": {"rules": lifecycle_rules(rule_count)},
    }


def build_homogeneous_bundle(
    n: int = 32,
    rule_count: int = 4,
    context: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    ids = participant_ids(n)
    body = shared_policy_body(ids, rule_count)
    round_context = copy.deepcopy(context or DEFAULT_CONTEXT)
    round_context["policy_id"] = f"sha384:POLICY_SCALE_{n}"
    proposals = []
    for participant_id in ids:
        proposal = {
            "schema": "tacvm-policy-proposal/v0.2",
            "context": copy.deepcopy(round_context),
            "author": {"participant_id": participant_id},
            **copy.deepcopy(body),
        }
        proposals.append(proposal)
    return {"context": round_context, "proposals": proposals}


def write_bundle(path: Path, bundle: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    header = (
        "# Homogeneous N-party scale fixture. Generated by "
        "generate_homogeneous.py.\n"
        "# Every proposal body is identical; only author.participant_id differs.\n"
        "# Symbolic digests are for local join tests, not production TDX values.\n"
    )
    with path.open("w", encoding="utf-8") as handle:
        handle.write(header)
        yaml.safe_dump(
            bundle,
            handle,
            sort_keys=False,
            default_flow_style=False,
            allow_unicode=True,
        )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", type=int, default=32, help="participant count")
    parser.add_argument(
        "--rules",
        type=int,
        default=4,
        help="lifecycle rule count (minimum 4)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path(__file__).with_name("thirty-two-party-homogeneous.yaml"),
        help="output YAML path",
    )
    args = parser.parse_args(argv)
    bundle = build_homogeneous_bundle(n=args.n, rule_count=args.rules)
    write_bundle(args.output, bundle)
    print(
        f"Wrote {args.n} homogeneous proposals "
        f"({args.rules} lifecycle rules) to {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
