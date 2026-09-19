"""TEE / provision / binding adapter interfaces for TACVM.

Hardware-dependent operations go through ``TeeBackend``. Development hosts use
``mock``; coauthor TDX machines wire ``tdx`` (currently an explicit stub).
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class AppraisalStatus(str, Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"


class BindingStatus(str, Enum):
    LIVE = "LIVE"
    INVALID = "INVALID"


class TeeBackendError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class QuoteEvidence:
    reportdata: str
    quote: bytes
    event_log: bytes
    backend: str


@dataclass(frozen=True)
class AppraisalResult:
    status: AppraisalStatus
    detail: str = ""


@dataclass(frozen=True)
class LaunchContext:
    w: str
    pid: str
    pk_ch: str
    lambda_bytes: bytes
    lambda_hash: str


@dataclass(frozen=True)
class PlatformHandle:
    w: str
    platform_handle: str


@dataclass(frozen=True)
class LiveBinding:
    w: str
    pk_w: str
    channel_id: str
    attestation_identity: str
    pid: str
    status: BindingStatus


class TeeBackend(ABC):
    name: str

    @abstractmethod
    def generate_operation_quote(self, n_i: str, pk_ch: str, d_M: str) -> QuoteEvidence:
        raise NotImplementedError

    @abstractmethod
    def verify_quote(
        self, evidence: QuoteEvidence, expected_reportdata: str
    ) -> AppraisalResult:
        raise NotImplementedError

    @abstractmethod
    def create_launch_context(self, w: str, pid: str, pk_ch: str) -> LaunchContext:
        raise NotImplementedError

    @abstractmethod
    def provision_workload_cvm(self, launch: LaunchContext) -> PlatformHandle:
        raise NotImplementedError

    @abstractmethod
    def verify_workload_evidence(
        self,
        w: str,
        lambda_hash: str,
        pk_w: str,
        challenge_n_w: str,
    ) -> LiveBinding:
        raise NotImplementedError

    @abstractmethod
    def invalidate_binding(self, w: str) -> None:
        raise NotImplementedError

    @abstractmethod
    def require_live_binding(self, w: str) -> LiveBinding:
        raise NotImplementedError


def get_tee_backend(name: Optional[str] = None) -> TeeBackend:
    selected = (name or os.environ.get("TACVM_TEE_BACKEND") or "mock").strip().lower()
    if selected == "mock":
        from .backends.mock import MockTeeBackend

        return MockTeeBackend()
    if selected == "tdx":
        from .backends.tdx import TdxTeeBackend

        return TdxTeeBackend()
    raise TeeBackendError(
        "ERR_UNKNOWN_TEE_BACKEND",
        f"Unknown TACVM_TEE_BACKEND={selected!r}; use mock or tdx",
    )
