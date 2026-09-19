"""Trusted Service local workload state (runs inside Workload CVM)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


class TrustedServiceError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass
class WorkloadLocalState:
    lifecycle_state: str = "ABSENT"
    accepted_artifact_digest: Optional[str] = None
    last_successful_operation_id: Optional[str] = None


class TrustedService:
    """Authoritative local state checks immediately before applying a transition."""

    def __init__(self) -> None:
        self._states: dict[str, WorkloadLocalState] = {}

    def get_state(self, w: str) -> WorkloadLocalState:
        return self._states.setdefault(w, WorkloadLocalState())

    def enforce_and_commit(
        self,
        w: str,
        *,
        operation_id: str,
        prior_state: str,
        next_state: str,
        artifact_digest: object = None,
    ) -> WorkloadLocalState:
        local = self.get_state(w)
        if local.lifecycle_state != prior_state:
            raise TrustedServiceError(
                "ERR_STATE_MISMATCH",
                f"Local state is {local.lifecycle_state}, request claims {prior_state}",
            )
        if artifact_digest is not None and not isinstance(artifact_digest, str):
            raise TrustedServiceError(
                "ERR_ARTIFACT_PLAINTEXT_DIGEST",
                "artifact_digest must be a string when provided",
            )
        local.lifecycle_state = next_state
        if isinstance(artifact_digest, str):
            local.accepted_artifact_digest = artifact_digest
        local.last_successful_operation_id = operation_id
        return local
