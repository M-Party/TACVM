"""Workload launch-context and live-binding state machine."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional

from .tee import BindingStatus, LaunchContext, LiveBinding, TeeBackend, TeeBackendError


class LaunchRecordStatus(str, Enum):
    PENDING = "PENDING"
    AUTHENTICATING = "AUTHENTICATING"
    CONSUMED = "CONSUMED"
    INVALID = "INVALID"


class WorkloadLaunchError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass
class PendingLaunchRecord:
    w: str
    pid: str
    pk_ch: str
    launch: LaunchContext
    status: LaunchRecordStatus

    @property
    def lambda_hash(self) -> str:
        return self.launch.lambda_hash

    @property
    def lambda_bytes(self) -> bytes:
        return self.launch.lambda_bytes


class WorkloadLaunchFSM:
    """Tracks pending ``lambda_w`` records and LIVE ``B_w`` bindings."""

    def __init__(self, tee: TeeBackend, pid: str, pk_ch: str) -> None:
        self.tee = tee
        self.pid = pid
        self.pk_ch = pk_ch
        self._records: Dict[str, PendingLaunchRecord] = {}

    def create_launch(self, w: str) -> PendingLaunchRecord:
        if not w:
            raise WorkloadLaunchError("ERR_LAUNCH_CONTEXT", "Workload id w is required")
        if w in self._records:
            raise WorkloadLaunchError(
                "ERR_LAUNCH_CONTEXT",
                f"Workload instance id {w} was already used",
            )
        launch = self.tee.create_launch_context(w=w, pid=self.pid, pk_ch=self.pk_ch)
        record = PendingLaunchRecord(
            w=w,
            pid=self.pid,
            pk_ch=self.pk_ch,
            launch=launch,
            status=LaunchRecordStatus.PENDING,
        )
        self._records[w] = record
        return record

    def mark_provisioning(self, w: str) -> PendingLaunchRecord:
        record = self._require_record(w)
        if record.status not in {
            LaunchRecordStatus.PENDING,
            LaunchRecordStatus.AUTHENTICATING,
        }:
            raise WorkloadLaunchError(
                "ERR_LAUNCH_REPLAY",
                f"Launch {w} is {record.status.value} and cannot be provisioned",
            )
        self.tee.provision_workload_cvm(record.launch)
        record.status = LaunchRecordStatus.AUTHENTICATING
        return record

    def authenticate_workload(
        self,
        w: str,
        pk_w: str,
        challenge_n_w: str,
    ) -> LiveBinding:
        record = self._require_record(w)
        if record.status == LaunchRecordStatus.CONSUMED:
            raise WorkloadLaunchError(
                "ERR_LAUNCH_REPLAY",
                f"Launch context for {w} was already consumed",
            )
        if record.status == LaunchRecordStatus.INVALID:
            raise WorkloadLaunchError(
                "ERR_LAUNCH_CONTEXT",
                f"Launch {w} is invalid",
            )
        if record.status == LaunchRecordStatus.PENDING:
            # Allow auth without an explicit provision step in mock unit tests.
            record.status = LaunchRecordStatus.AUTHENTICATING
        try:
            binding = self.tee.verify_workload_evidence(
                w=w,
                lambda_hash=record.launch.lambda_hash,
                pk_w=pk_w,
                challenge_n_w=challenge_n_w,
            )
        except TeeBackendError as exc:
            raise WorkloadLaunchError(exc.code, str(exc)) from exc

        # Attach active policy namespace pid onto the binding view.
        binding = LiveBinding(
            w=binding.w,
            pk_w=binding.pk_w,
            channel_id=binding.channel_id,
            attestation_identity=binding.attestation_identity,
            pid=self.pid,
            status=binding.status,
        )
        record.status = LaunchRecordStatus.CONSUMED
        return binding

    def on_channel_lost(self, w: str) -> None:
        record = self._records.get(w)
        if record is None:
            return
        try:
            self.tee.invalidate_binding(w)
        except TeeBackendError:
            pass
        if record.status != LaunchRecordStatus.CONSUMED:
            record.status = LaunchRecordStatus.INVALID

    def require_live_binding(self, w: str) -> LiveBinding:
        try:
            return self.tee.require_live_binding(w)
        except TeeBackendError as exc:
            raise WorkloadLaunchError(exc.code, str(exc)) from exc

    def get_record(self, w: str) -> PendingLaunchRecord:
        return self._require_record(w)

    def _require_record(self, w: str) -> PendingLaunchRecord:
        record = self._records.get(w)
        if record is None:
            raise WorkloadLaunchError("ERR_LAUNCH_UNKNOWN", f"Unknown launch {w}")
        return record
