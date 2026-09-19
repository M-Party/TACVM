"""Deterministic mock TEE backend for hosts without TDX."""

from __future__ import annotations

import hashlib
from typing import Dict

from ..encode import canonical_encode, hash_domain
from ..tee import (
    AppraisalResult,
    AppraisalStatus,
    BindingStatus,
    LaunchContext,
    LiveBinding,
    PlatformHandle,
    QuoteEvidence,
    TeeBackend,
    TeeBackendError,
)


class MockTeeBackend(TeeBackend):
    name = "mock"

    def __init__(self) -> None:
        self._bindings: Dict[str, LiveBinding] = {}
        self._pending_lambda: Dict[str, str] = {}

    def generate_operation_quote(self, n_i: str, pk_ch: str, d_M: str) -> QuoteEvidence:
        reportdata = hash_domain(
            "TACVM-BOOT",
            {"n_i": n_i, "pk_ch": pk_ch, "d_M": d_M},
        )
        body = canonical_encode(
            "TACVM-BOOT",
            {"n_i": n_i, "pk_ch": pk_ch, "d_M": d_M},
        )
        quote = b"MOCK-QUOTE:" + body
        event_log = b"MOCK-EVENT-LOG:" + hashlib.sha256(body).digest()
        return QuoteEvidence(
            reportdata=reportdata,
            quote=quote,
            event_log=event_log,
            backend=self.name,
        )

    def verify_quote(
        self, evidence: QuoteEvidence, expected_reportdata: str
    ) -> AppraisalResult:
        if not evidence.quote.startswith(b"MOCK-QUOTE:"):
            raise TeeBackendError("ERR_WORKLOAD_MEASUREMENT", "Not a mock quote")
        if evidence.reportdata != expected_reportdata:
            raise TeeBackendError(
                "ERR_CHANNEL_KEY_MISMATCH",
                "REPORTDATA does not match the expected boot binding",
            )
        return AppraisalResult(status=AppraisalStatus.SUCCESS, detail="mock-ok")

    def create_launch_context(self, w: str, pid: str, pk_ch: str) -> LaunchContext:
        lambda_bytes = canonical_encode(
            "TACVM-WORKLOAD",
            {"w": w, "pid": pid, "pk_ch": pk_ch},
        )
        lambda_hash = hash_domain(
            "TACVM-WORKLOAD",
            {"w": w, "pid": pid, "pk_ch": pk_ch},
        )
        self._pending_lambda[w] = lambda_hash
        return LaunchContext(
            w=w,
            pid=pid,
            pk_ch=pk_ch,
            lambda_bytes=lambda_bytes,
            lambda_hash=lambda_hash,
        )

    def provision_workload_cvm(self, launch: LaunchContext) -> PlatformHandle:
        if self._pending_lambda.get(launch.w) != launch.lambda_hash:
            raise TeeBackendError(
                "ERR_LAUNCH_CONTEXT",
                f"No pending launch context for {launch.w}",
            )
        return PlatformHandle(w=launch.w, platform_handle=f"mock-{launch.w}")

    def verify_workload_evidence(
        self,
        w: str,
        lambda_hash: str,
        pk_w: str,
        challenge_n_w: str,
    ) -> LiveBinding:
        expected = self._pending_lambda.get(w)
        if expected is None:
            raise TeeBackendError("ERR_LAUNCH_UNKNOWN", f"Unknown launch {w}")
        if expected != lambda_hash:
            raise TeeBackendError(
                "ERR_LAUNCH_CONTEXT",
                "Workload evidence does not match pending lambda_w",
            )
        # Consume pending launch on success (no replay).
        del self._pending_lambda[w]
        attest = hash_domain(
            "TACVM-WORKLOAD-ATTEST",
            {
                "n_w": challenge_n_w,
                "lambda_hash": lambda_hash,
                "pk_w": pk_w,
            },
        )
        binding = LiveBinding(
            w=w,
            pk_w=pk_w,
            channel_id=f"mock-channel-{w}",
            attestation_identity=attest,
            pid="",  # filled by higher-level FSM later
            status=BindingStatus.LIVE,
        )
        self._bindings[w] = binding
        return binding

    def invalidate_binding(self, w: str) -> None:
        current = self._bindings.get(w)
        if current is None:
            return
        self._bindings[w] = LiveBinding(
            w=current.w,
            pk_w=current.pk_w,
            channel_id=current.channel_id,
            attestation_identity=current.attestation_identity,
            pid=current.pid,
            status=BindingStatus.INVALID,
        )

    def require_live_binding(self, w: str) -> LiveBinding:
        binding = self._bindings.get(w)
        if binding is None or binding.status != BindingStatus.LIVE:
            raise TeeBackendError(
                "ERR_BINDING_NOT_LIVE",
                f"No LIVE binding for workload instance {w}",
            )
        return binding
