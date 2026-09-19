"""Operation CVM Workload Dispatcher — authorize then dispatch to Trusted Service."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Mapping, Optional, Set, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from tacvm_protocol import canonical_encode
from launch import WorkloadLaunchError, WorkloadLaunchFSM
from trusted_service import TrustedService, TrustedServiceError, WorkloadLocalState


class DispatcherError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass
class TransitionDispatcher:
    """Authorize signed transitions on the Operation CVM, then enforce on TS."""

    pid: str
    policy_hash: str
    requester_keys: Mapping[str, str]
    launch_fsm: WorkloadLaunchFSM
    allowed_transitions: Set[Tuple[str, str, str]] = field(default_factory=set)
    trusted_service: TrustedService = field(default_factory=TrustedService)
    _processed_u: Set[str] = field(default_factory=set)

    # Test helper compatibility with previous API.
    @property
    def _local_states(self) -> Dict[str, WorkloadLocalState]:
        return self.trusted_service._states

    def submit_transition(self, request: Mapping[str, object]) -> Dict[str, object]:
        participant_id = self._require_str(request, "participant_id")
        pid = self._require_str(request, "pid")
        policy_hash = self._require_str(request, "policy_hash")
        operation_id = self._require_str(request, "u")
        w = self._require_str(request, "w")
        operation = self._require_str(request, "operation")
        prior_state = self._require_str(request, "prior_state")
        next_state = self._require_str(request, "next_state")
        artifact_digest = request.get("artifact_digest")
        signature = request.get("signature")

        key_hex = self.requester_keys.get(participant_id)
        if key_hex is None:
            raise DispatcherError(
                "ERR_UNKNOWN_PARTICIPANT",
                f"Unknown requester {participant_id}",
            )
        if not isinstance(signature, (bytes, bytearray)):
            raise DispatcherError("ERR_TRANS_SIGNATURE", "Missing transition signature")
        fields = {
            "participant_id": participant_id,
            "pid": pid,
            "policy_hash": policy_hash,
            "u": operation_id,
            "w": w,
            "operation": operation,
            "prior_state": prior_state,
            "next_state": next_state,
            "artifact_digest": artifact_digest,
        }
        body = canonical_encode("TACVM-TRANS", fields)
        try:
            public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex))
            public_key.verify(bytes(signature), body)
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise DispatcherError(
                "ERR_TRANS_SIGNATURE",
                "Transition signature verification failed",
            ) from exc

        if pid != self.pid:
            raise DispatcherError("ERR_POLICY_PID", "Transition pid mismatch")
        if policy_hash != self.policy_hash:
            raise DispatcherError(
                "ERR_TRANS_POLICY_HASH",
                "Transition policy hash mismatch",
            )
        if operation_id in self._processed_u:
            raise DispatcherError(
                "ERR_TRANS_REPLAY",
                f"Operation id {operation_id} was already processed",
            )

        try:
            self.launch_fsm.require_live_binding(w)
        except WorkloadLaunchError as exc:
            raise DispatcherError(exc.code, str(exc)) from exc

        edge = (operation, prior_state, next_state)
        if self.allowed_transitions and edge not in self.allowed_transitions:
            raise DispatcherError(
                "ERR_TRANS_NOT_ALLOWED",
                f"Transition {edge} is not permitted by active policy",
            )

        try:
            local = self.trusted_service.enforce_and_commit(
                w,
                operation_id=operation_id,
                prior_state=prior_state,
                next_state=next_state,
                artifact_digest=artifact_digest,
            )
        except TrustedServiceError as exc:
            raise DispatcherError(exc.code, str(exc)) from exc

        self._processed_u.add(operation_id)
        return {
            "status": "COMMITTED",
            "u": operation_id,
            "w": w,
            "local_state": local.lifecycle_state,
            "artifact_digest": local.accepted_artifact_digest,
        }

    @staticmethod
    def _require_str(request: Mapping[str, object], key: str) -> str:
        value = request.get(key)
        if not isinstance(value, str) or not value:
            raise DispatcherError("ERR_POLICY_MALFORMED", f"Missing field {key}")
        return value
