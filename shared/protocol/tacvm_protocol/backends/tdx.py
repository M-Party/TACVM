"""TDX backend stub — wire on the coauthor host, not on SGX-only machines."""

from __future__ import annotations

from ..tee import (
    AppraisalResult,
    LaunchContext,
    LiveBinding,
    PlatformHandle,
    QuoteEvidence,
    TeeBackend,
    TeeBackendError,
)

_NOT_WIRED = (
    "ERR_TDX_ADAPTER_NOT_WIRED",
    "TDX backend is not wired in this checkout. On the coauthor host, replace "
    "TdxTeeBackend methods with calls into policy_server / QuoteAppraisal / "
    "launch-client while keeping state_mutex_ and the appraisal mutex. See "
    "docs/integration/tdx_adapter_guide.md.",
)


class TdxTeeBackend(TeeBackend):
    name = "tdx"

    def generate_operation_quote(self, n_i: str, pk_ch: str, d_M: str) -> QuoteEvidence:
        raise TeeBackendError(*_NOT_WIRED)

    def verify_quote(
        self, evidence: QuoteEvidence, expected_reportdata: str
    ) -> AppraisalResult:
        raise TeeBackendError(*_NOT_WIRED)

    def create_launch_context(self, w: str, pid: str, pk_ch: str) -> LaunchContext:
        raise TeeBackendError(*_NOT_WIRED)

    def provision_workload_cvm(self, launch: LaunchContext) -> PlatformHandle:
        raise TeeBackendError(*_NOT_WIRED)

    def verify_workload_evidence(
        self,
        w: str,
        lambda_hash: str,
        pk_w: str,
        challenge_n_w: str,
    ) -> LiveBinding:
        raise TeeBackendError(*_NOT_WIRED)

    def invalidate_binding(self, w: str) -> None:
        raise TeeBackendError(*_NOT_WIRED)

    def require_live_binding(self, w: str) -> LiveBinding:
        raise TeeBackendError(*_NOT_WIRED)
