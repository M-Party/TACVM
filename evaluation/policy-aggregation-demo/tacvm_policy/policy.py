from __future__ import annotations

import base64
import copy
import hashlib
import json
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


REQUIRED_DEFAULTS = (
    "roles",
    "workload_cvms",
    "artifacts",
    "secret_release",
    "communications",
    "lifecycle",
)
SUPPORTED_OPERATIONS = {"admit", "update", "stop", "delete"}


class PolicyError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> None:
    raise PolicyError(code, message)


def _canonical_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int):
        if not -(2**53 - 1) <= value <= 2**53 - 1:
            _fail("NON_CANONICAL_NUMBER", "Integer exceeds the safe canonical range")
        return value
    if isinstance(value, float):
        _fail("NON_CANONICAL_NUMBER", "Floating-point values are not allowed")
    if isinstance(value, list):
        return [_canonical_value(item) for item in value]
    if isinstance(value, dict):
        result: Dict[str, Any] = {}
        for key in sorted(value):
            if not isinstance(key, str):
                _fail("NON_CANONICAL_KEY", "Policy object keys must be strings")
            result[key] = _canonical_value(value[key])
        return result
    _fail("NON_CANONICAL_VALUE", f"Unsupported policy value: {type(value).__name__}")


def canonical_json(value: Any) -> str:
    return json.dumps(
        _canonical_value(value),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _digest(algorithm: str, value: Any) -> str:
    encoded = canonical_json(value).encode("utf-8")
    return f"{algorithm}:{hashlib.new(algorithm, encoded).hexdigest()}"


def _sha384(value: Any) -> str:
    return _digest("sha384", value)


def _unique_sorted(values: Iterable[str]) -> List[str]:
    return sorted(set(values))


def _endpoint_key(endpoint: Mapping[str, Any]) -> str:
    normalized = {
        "host": endpoint["host"],
        "ports": sorted(set(endpoint["ports"])),
    }
    return canonical_json(normalized)


def _normalize_endpoint(endpoint: Mapping[str, Any]) -> Dict[str, Any]:
    return json.loads(_endpoint_key(endpoint))


def _normalize_rule(rule: Mapping[str, Any]) -> Dict[str, Any]:
    normalized = copy.deepcopy(dict(rule))
    normalized["secrets"] = _unique_sorted(normalized.get("secrets", []))
    normalized["communication_profiles"] = _unique_sorted(
        normalized.get("communication_profiles", [])
    )
    return normalized


def _rule_body(rule: Mapping[str, Any]) -> Dict[str, Any]:
    normalized = _normalize_rule(rule)
    normalized.pop("id", None)
    return normalized


def _rule_key(rule: Mapping[str, Any]) -> str:
    return canonical_json(_rule_body(rule))


def _normalize_workload(entry: Mapping[str, Any]) -> Dict[str, Any]:
    normalized = copy.deepcopy(dict(entry))
    measurements = normalized["measurements"]
    measurements["mrtd"]["allowed"] = _unique_sorted(
        measurements["mrtd"]["allowed"]
    )
    measurements["rootfs"]["allowed_root_hashes"] = _unique_sorted(
        measurements["rootfs"]["allowed_root_hashes"]
    )
    for rule in measurements.get("rtmr", {}).values():
        rule["allowed"] = _unique_sorted(rule["allowed"])
    quote = normalized["quote_verification"]
    quote["accepted_tcb_statuses"] = _unique_sorted(
        quote["accepted_tcb_statuses"]
    )
    launch = normalized["launch_context"]
    launch["required_fields"] = _unique_sorted(launch["required_fields"])
    return normalized


def _normalize_artifact(entry: Mapping[str, Any]) -> Dict[str, Any]:
    normalized = copy.deepcopy(dict(entry))
    normalized["allowed_content_digests"] = _unique_sorted(
        normalized["allowed_content_digests"]
    )
    normalized["registrars"] = _unique_sorted(normalized["registrars"])
    return normalized


def _normalize_secret(entry: Mapping[str, Any]) -> Dict[str, Any]:
    normalized = copy.deepcopy(dict(entry))
    for field in ("workload_cvms", "operations", "requesters"):
        normalized[field] = _unique_sorted(normalized[field])
    return normalized


def _normalize_communication(entry: Mapping[str, Any]) -> Dict[str, Any]:
    normalized = copy.deepcopy(dict(entry))
    endpoints = {
        _endpoint_key(endpoint): _normalize_endpoint(endpoint)
        for endpoint in normalized["endpoints"]
    }
    normalized["endpoints"] = [endpoints[key] for key in sorted(endpoints)]
    normalized["peer_identity"]["spki_sha256"] = _unique_sorted(
        normalized["peer_identity"]["spki_sha256"]
    )
    return normalized


def normalize_proposal(proposal: Mapping[str, Any]) -> Dict[str, Any]:
    result = copy.deepcopy(dict(proposal))
    result.setdefault("roles", {"assignments": {}})
    result.setdefault("workload_cvms", {"entries": {}})
    result.setdefault("artifacts", {"entries": {}})
    result.setdefault("secret_release", {"entries": {}})
    result.setdefault("communications", {"entries": {}})
    result.setdefault("lifecycle", {"rules": []})

    for name, entry in list(result["workload_cvms"]["entries"].items()):
        result["workload_cvms"]["entries"][name] = _normalize_workload(entry)
    for name, entry in list(result["artifacts"]["entries"].items()):
        result["artifacts"]["entries"][name] = _normalize_artifact(entry)
    for name, entry in list(result["secret_release"]["entries"].items()):
        result["secret_release"]["entries"][name] = _normalize_secret(entry)
    for name, entry in list(result["communications"]["entries"].items()):
        result["communications"]["entries"][name] = _normalize_communication(entry)
    result["lifecycle"]["rules"] = sorted(
        (_normalize_rule(rule) for rule in result["lifecycle"]["rules"]),
        key=_rule_key,
    )
    return result


def _contexts_equal(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    return canonical_json(left) == canonical_json(right)


def validate_proposal(
    proposal: Mapping[str, Any],
    expected_context: Mapping[str, Any],
    roster_slots: Set[str],
) -> None:
    if proposal.get("schema") != "tacvm-policy-proposal/v0.1":
        _fail("UNSUPPORTED_SCHEMA", f"Unsupported schema {proposal.get('schema')}")
    if not _contexts_equal(proposal.get("context", {}), expected_context):
        _fail("REJECT_CONTEXT", "Proposal context does not match the active round")
    slot = proposal.get("author", {}).get("slot")
    if slot not in roster_slots:
        _fail("UNKNOWN_SLOT", f"Unknown proposal author {slot}")
    defaults = proposal.get("defaults", {})
    for field in REQUIRED_DEFAULTS:
        if defaults.get(field) not in {"ANY", "DENY"}:
            _fail("INVALID_DEFAULT", f"{field} must declare ANY or DENY")
    for mapped_slot, role in proposal.get("roles", {}).get("assignments", {}).items():
        if mapped_slot not in roster_slots or not isinstance(role, str) or not role:
            _fail("INVALID_ROLE", f"Invalid role assignment for {mapped_slot}")
    for rule in proposal.get("lifecycle", {}).get("rules", []):
        if rule.get("operation") not in SUPPORTED_OPERATIONS:
            _fail("INVALID_OPERATION", f"Unsupported operation {rule.get('operation')}")
    try:
        normalize_proposal(proposal)
    except (KeyError, TypeError, ValueError) as exc:
        _fail("INVALID_PROPOSAL", f"Malformed policy field: {exc}")


def proposal_digest(proposal: Mapping[str, Any]) -> str:
    return _sha384(normalize_proposal(proposal))


def _proposal_signing_message(slot: str, digest_value: str) -> bytes:
    return canonical_json(
        {
            "domain": "TACVM-PROPOSAL",
            "slot": slot,
            "proposal_digest": digest_value,
        }
    ).encode("utf-8")


def generate_participant_key_pair() -> Tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def sign_proposal(
    proposal: Mapping[str, Any], private_key: Ed25519PrivateKey
) -> Dict[str, Any]:
    normalized = normalize_proposal(proposal)
    digest_value = proposal_digest(normalized)
    signature = private_key.sign(
        _proposal_signing_message(normalized["author"]["slot"], digest_value)
    )
    return {
        "proposal": normalized,
        "proposal_digest": digest_value,
        "signature_algorithm": "Ed25519",
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def _verify_signed_proposal(
    envelope: Mapping[str, Any], public_key: Ed25519PublicKey
) -> None:
    if envelope.get("signature_algorithm") != "Ed25519":
        _fail("UNSUPPORTED_SIGNATURE", "Only Ed25519 is supported")
    actual_digest = proposal_digest(envelope["proposal"])
    if actual_digest != envelope.get("proposal_digest"):
        _fail("PROPOSAL_DIGEST_MISMATCH", "Proposal digest does not match body")
    try:
        public_key.verify(
            base64.b64decode(envelope["signature"], validate=True),
            _proposal_signing_message(
                envelope["proposal"]["author"]["slot"], actual_digest
            ),
        )
    except (InvalidSignature, ValueError, TypeError):
        _fail("INVALID_PROPOSAL_SIGNATURE", "Proposal signature verification failed")


def _union_keys(
    proposals: Sequence[Mapping[str, Any]], section: str
) -> List[str]:
    keys: Set[str] = set()
    for proposal in proposals:
        keys.update(proposal[section]["entries"])
    return sorted(keys)


def _intersect_sets(arrays: Sequence[Sequence[str]]) -> List[str]:
    if not arrays:
        return []
    result = set(arrays[0])
    for values in arrays[1:]:
        result.intersection_update(values)
    return sorted(result)


def _union_sets(arrays: Sequence[Sequence[str]]) -> List[str]:
    result: Set[str] = set()
    for values in arrays:
        result.update(values)
    return sorted(result)


def _require_same(values: Iterable[str], code: str, field: str) -> str:
    distinct = sorted(set(values))
    if len(distinct) != 1:
        _fail(code, f"Conflicting {field}: {', '.join(distinct)}")
    return distinct[0]


def _entries_for(
    proposals: Sequence[Mapping[str, Any]],
    section: str,
    object_name: str,
    bottom_code: str,
) -> List[Mapping[str, Any]]:
    entries = []
    for proposal in proposals:
        entry = proposal[section]["entries"].get(object_name)
        if entry is not None:
            entries.append(entry)
        elif proposal["defaults"][section] == "DENY":
            _fail(
                bottom_code,
                f"{proposal['author']['slot']} denies unlisted {section}.{object_name}",
            )
    return entries


def _join_boolean_requirements(
    objects: Sequence[Mapping[str, Any]], excluded: Set[str] = frozenset()
) -> Dict[str, bool]:
    keys: Set[str] = set()
    for obj in objects:
        keys.update(key for key in obj if key not in excluded)
    result: Dict[str, bool] = {}
    for key in sorted(keys):
        values = [obj.get(key, False) for obj in objects]
        if not all(isinstance(value, bool) for value in values):
            _fail("INVALID_BOOLEAN_REQUIREMENT", f"{key} must be boolean")
        result[key] = any(values)
    return result


def _join_roles(proposals: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    assignments: Dict[str, str] = {}
    for proposal in proposals:
        for slot, role in proposal["roles"]["assignments"].items():
            if slot in assignments and assignments[slot] != role:
                _fail(
                    "BOTTOM_ROLE_CONFLICT",
                    f"Slot {slot} is assigned both {assignments[slot]} and {role}",
                )
            assignments[slot] = role
    return {"assignments": assignments}


def _join_rtmr(entries: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    indices: Set[str] = set()
    for entry in entries:
        indices.update(entry["measurements"].get("rtmr", {}))
    result = {}
    for index in sorted(indices):
        constrained = [
            entry["measurements"]["rtmr"][index]["allowed"]
            for entry in entries
            if index in entry["measurements"].get("rtmr", {})
        ]
        allowed = _intersect_sets(constrained)
        if not allowed:
            _fail(
                "BOTTOM_EMPTY_WORKLOAD_CVM_IDENTITY",
                f"Empty RTMR[{index}] intersection",
            )
        result[index] = {"allowed": allowed}
    return result


def _join_workloads(proposals: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    joined = {}
    for name in _union_keys(proposals, "workload_cvms"):
        entries = _entries_for(
            proposals,
            "workload_cvms",
            name,
            "BOTTOM_EMPTY_WORKLOAD_CVM_IDENTITY",
        )
        mrtd = _intersect_sets(
            [entry["measurements"]["mrtd"]["allowed"] for entry in entries]
        )
        roots = _intersect_sets(
            [
                entry["measurements"]["rootfs"]["allowed_root_hashes"]
                for entry in entries
            ]
        )
        statuses = _intersect_sets(
            [entry["quote_verification"]["accepted_tcb_statuses"] for entry in entries]
        )
        if not mrtd or not roots or not statuses:
            _fail(
                "BOTTOM_EMPTY_WORKLOAD_CVM_IDENTITY",
                f"Workload CVM {name} has no commonly accepted identity",
            )
        quote_requirements = _join_boolean_requirements(
            [entry["quote_verification"] for entry in entries],
            {"accepted_tcb_statuses"},
        )
        quote_requirements["accepted_tcb_statuses"] = statuses
        joined[name] = {
            "tee_type": _require_same(
                [entry["tee_type"] for entry in entries],
                "BOTTOM_WORKLOAD_CONFLICT",
                f"{name}.tee_type",
            ),
            "measurements": {
                "mrtd": {"allowed": mrtd},
                "rtmr": _join_rtmr(entries),
                "rootfs": {
                    "scheme": _require_same(
                        [entry["measurements"]["rootfs"]["scheme"] for entry in entries],
                        "BOTTOM_WORKLOAD_CONFLICT",
                        f"{name}.rootfs.scheme",
                    ),
                    "allowed_root_hashes": roots,
                },
            },
            "quote_verification": quote_requirements,
            "launch_context": {
                "required_fields": _union_sets(
                    [entry["launch_context"]["required_fields"] for entry in entries]
                )
            },
            "trusted_service_channel": _join_boolean_requirements(
                [entry["trusted_service_channel"] for entry in entries]
            ),
        }
    return {"entries": joined}


def _join_artifacts(proposals: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    joined = {}
    for name in _union_keys(proposals, "artifacts"):
        entries = _entries_for(
            proposals, "artifacts", name, "BOTTOM_EMPTY_ARTIFACT_SET"
        )
        digests = _intersect_sets(
            [entry["allowed_content_digests"] for entry in entries]
        )
        registrars = _intersect_sets([entry["registrars"] for entry in entries])
        if not digests or not registrars:
            _fail("BOTTOM_EMPTY_ARTIFACT_SET", f"Artifact {name} has empty intersection")
        joined[name] = {
            "kind": _require_same(
                [entry["kind"] for entry in entries],
                "BOTTOM_ARTIFACT_CONFLICT",
                f"{name}.kind",
            ),
            "allowed_content_digests": digests,
            "encryption": (
                "REQUIRED"
                if any(entry["encryption"] == "REQUIRED" for entry in entries)
                else "ANY"
            ),
            "registrars": registrars,
        }
    return {"entries": joined}


def _join_secrets(proposals: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    joined = {}
    for name in _union_keys(proposals, "secret_release"):
        entries = []
        denied = False
        for proposal in proposals:
            entry = proposal["secret_release"]["entries"].get(name)
            if entry is not None:
                entries.append(entry)
            elif proposal["defaults"]["secret_release"] == "DENY":
                denied = True
        if denied:
            continue
        workload_cvms = _intersect_sets([entry["workload_cvms"] for entry in entries])
        operations = _intersect_sets([entry["operations"] for entry in entries])
        requesters = _intersect_sets([entry["requesters"] for entry in entries])
        if not workload_cvms or not operations or not requesters:
            continue
        joined[name] = {
            "secret_type": _require_same(
                [entry["secret_type"] for entry in entries],
                "BOTTOM_SECRET_CONFLICT",
                f"{name}.secret_type",
            ),
            "artifact": _require_same(
                [entry["artifact"] for entry in entries],
                "BOTTOM_SECRET_CONFLICT",
                f"{name}.artifact",
            ),
            "workload_cvms": workload_cvms,
            "operations": operations,
            "requesters": requesters,
            "require_authenticated_binding": any(
                entry["require_authenticated_binding"] for entry in entries
            ),
            "require_artifact_digest_match": any(
                entry["require_artifact_digest_match"] for entry in entries
            ),
        }
    return {"entries": joined}


def _join_communications(proposals: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    joined = {}
    for name in _union_keys(proposals, "communications"):
        entries = []
        denied = False
        for proposal in proposals:
            entry = proposal["communications"]["entries"].get(name)
            if entry is not None:
                entries.append(entry)
            elif proposal["defaults"]["communications"] == "DENY":
                denied = True
        if denied:
            continue
        endpoint_keys = _intersect_sets(
            [[_endpoint_key(endpoint) for endpoint in entry["endpoints"]] for entry in entries]
        )
        identities = _intersect_sets(
            [entry["peer_identity"]["spki_sha256"] for entry in entries]
        )
        if not endpoint_keys or not identities:
            continue
        joined[name] = {
            "direction": _require_same(
                [entry["direction"] for entry in entries],
                "BOTTOM_COMMUNICATION_CONFLICT",
                f"{name}.direction",
            ),
            "protocol": _require_same(
                [entry["protocol"] for entry in entries],
                "BOTTOM_COMMUNICATION_CONFLICT",
                f"{name}.protocol",
            ),
            "endpoints": [json.loads(key) for key in endpoint_keys],
            "peer_identity": {"spki_sha256": identities},
        }
    return {"entries": joined}


def _join_lifecycle(proposals: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    restrictive = [
        proposal for proposal in proposals if proposal["defaults"]["lifecycle"] == "DENY"
    ]
    if not restrictive:
        _fail(
            "UNBOUNDED_LIFECYCLE",
            "At least one proposal must materialize lifecycle permissions",
        )
    rule_maps = [
        {_rule_key(rule): _rule_body(rule) for rule in proposal["lifecycle"]["rules"]}
        for proposal in restrictive
    ]
    common_keys = _intersect_sets([list(rule_map) for rule_map in rule_maps])
    rules = []
    for key in common_keys:
        rule_id = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
        rules.append({"id": f"joined-{rule_id}", **rule_maps[0][key]})
    return {"rules": sorted(rules, key=_rule_key)}


def join_policy_bodies(proposals: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    normalized = [normalize_proposal(proposal) for proposal in proposals]
    return {
        "roles": _join_roles(normalized),
        "workload_cvms": _join_workloads(normalized),
        "artifacts": _join_artifacts(normalized),
        "secret_release": _join_secrets(normalized),
        "communications": _join_communications(normalized),
        "lifecycle": _join_lifecycle(normalized),
    }


def candidate_digest(candidate: Mapping[str, Any]) -> str:
    return _sha384(candidate)


def _candidate_as_proposal(candidate: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "schema": "tacvm-policy-proposal/v0.1",
        "context": copy.deepcopy(candidate["context"]),
        "author": {"slot": "candidate"},
        "defaults": {field: "DENY" for field in REQUIRED_DEFAULTS},
        **copy.deepcopy(candidate["policy"]),
    }


def verify_candidate_against_proposal(
    candidate: Mapping[str, Any], proposal: Mapping[str, Any]
) -> bool:
    if not _contexts_equal(candidate["context"], proposal["context"]):
        _fail("CANDIDATE_CONTEXT_MISMATCH", "Candidate context differs from proposal")
    own_digest = proposal_digest(proposal)
    included = any(
        item["slot"] == proposal["author"]["slot"]
        and item["proposal_digest"] == own_digest
        for item in candidate["inputs"]
    )
    if not included:
        _fail(
            "PROPOSAL_NOT_INCLUDED",
            f"Candidate omits {proposal['author']['slot']}'s proposal",
        )
    try:
        restricted = join_policy_bodies([proposal, _candidate_as_proposal(candidate)])
    except PolicyError as exc:
        _fail(
            "CANDIDATE_WEAKENS_PROPOSAL",
            f"Candidate conflicts with {proposal['author']['slot']}: {exc}",
        )
    if canonical_json(restricted) != canonical_json(candidate["policy"]):
        _fail(
            "CANDIDATE_WEAKENS_PROPOSAL",
            f"Candidate admits behavior not allowed by {proposal['author']['slot']}",
        )
    return True


def _confirmation_message(context: Mapping[str, Any], digest_value: str) -> bytes:
    return canonical_json(
        {
            "domain": "TACVM-CONFIRM",
            "roster_digest": context["roster_digest"],
            "policy_id": context["policy_id"],
            "version": context["version"],
            "round": context["round"],
            "candidate_digest": digest_value,
        }
    ).encode("utf-8")


def sign_confirmation(
    slot: str,
    context: Mapping[str, Any],
    digest_value: str,
    private_key: Ed25519PrivateKey,
) -> Dict[str, Any]:
    signature = private_key.sign(_confirmation_message(context, digest_value))
    return {
        "slot": slot,
        "candidate_digest": digest_value,
        "signature_algorithm": "Ed25519",
        "signature": base64.b64encode(signature).decode("ascii"),
    }


class PolicyAggregator:
    def __init__(
        self,
        context: Mapping[str, Any],
        roster: Mapping[str, Ed25519PublicKey],
    ) -> None:
        self.context = copy.deepcopy(dict(context))
        self.roster = dict(roster)
        self.proposals: Dict[str, Dict[str, Any]] = {}
        self.confirmations: Dict[str, Dict[str, Any]] = {}
        self.candidate: Optional[Dict[str, Any]] = None
        self.candidate_digest_value: Optional[str] = None
        self.active: Optional[Dict[str, Any]] = None

    def submit_proposal(self, envelope: Mapping[str, Any]) -> str:
        if self.candidate is not None:
            _fail("ROUND_CLOSED", "Cannot add a proposal after candidate construction")
        slot = envelope.get("proposal", {}).get("author", {}).get("slot")
        public_key = self.roster.get(slot)
        if public_key is None:
            _fail("UNKNOWN_SLOT", f"No enrolled policy key for {slot}")
        if slot in self.proposals:
            _fail("DUPLICATE_PROPOSAL", f"Slot {slot} already submitted a proposal")
        validate_proposal(envelope["proposal"], self.context, set(self.roster))
        _verify_signed_proposal(envelope, public_key)
        self.proposals[slot] = copy.deepcopy(dict(envelope))
        return envelope["proposal_digest"]

    def build_candidate(self) -> Dict[str, Any]:
        missing = sorted(set(self.roster) - set(self.proposals))
        if missing:
            _fail("INCOMPLETE_PROPOSAL_SET", f"Missing proposals from {', '.join(missing)}")
        slots = sorted(self.roster)
        proposals = [self.proposals[slot]["proposal"] for slot in slots]
        self.candidate = {
            "schema": "tacvm-policy-candidate/v0.1",
            "context": copy.deepcopy(self.context),
            "inputs": [
                {
                    "slot": slot,
                    "proposal_digest": self.proposals[slot]["proposal_digest"],
                }
                for slot in slots
            ],
            "policy": join_policy_bodies(proposals),
        }
        self.candidate_digest_value = candidate_digest(self.candidate)
        return {
            "candidate": copy.deepcopy(self.candidate),
            "candidate_digest": self.candidate_digest_value,
        }

    def submit_confirmation(self, confirmation: Mapping[str, Any]) -> None:
        if self.candidate is None or self.candidate_digest_value is None:
            _fail("NO_CANDIDATE", "Build a candidate before collecting confirmations")
        slot = confirmation.get("slot")
        public_key = self.roster.get(slot)
        if public_key is None:
            _fail("UNKNOWN_SLOT", f"No enrolled policy key for {slot}")
        if slot in self.confirmations:
            _fail("DUPLICATE_CONFIRMATION", f"{slot} already confirmed")
        if confirmation.get("candidate_digest") != self.candidate_digest_value:
            _fail("CANDIDATE_DIGEST_MISMATCH", "Confirmation targets another candidate")
        try:
            public_key.verify(
                base64.b64decode(confirmation["signature"], validate=True),
                _confirmation_message(self.context, self.candidate_digest_value),
            )
        except (InvalidSignature, ValueError, TypeError):
            _fail("INVALID_CONFIRMATION_SIGNATURE", "Confirmation signature failed")
        self.confirmations[slot] = copy.deepcopy(dict(confirmation))

    def activate(self) -> Dict[str, Any]:
        if self.candidate is None or self.candidate_digest_value is None:
            _fail("NO_CANDIDATE", "No candidate exists")
        missing = sorted(set(self.roster) - set(self.confirmations))
        if missing:
            _fail(
                "INCOMPLETE_CONFIRMATION_SET",
                f"Missing confirmations from {', '.join(missing)}",
            )
        self.active = {
            "candidate": copy.deepcopy(self.candidate),
            "candidate_digest": self.candidate_digest_value,
            "confirmations": [self.confirmations[slot] for slot in sorted(self.roster)],
        }
        return copy.deepcopy(self.active)
