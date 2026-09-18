"""Canonical domain-separated encoding for TACVM protocol messages.

Uses deterministic canonical JSON (sorted keys, compact separators, UTF-8) so
the same logical fields always hash identically regardless of dict insertion
order. Every hash/signature domain must use one of the paper labels in
``DOMAINS``.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Mapping


DOMAINS = frozenset(
    {
        "TACVM-BOOT",
        "TACVM-ACCEPT",
        "TACVM-POLICY",
        "TACVM-PROPOSAL",
        "TACVM-CONFIRM",
        "TACVM-WORKLOAD",
        "TACVM-WORKLOAD-ATTEST",
        "TACVM-TRANS",
    }
)


class CanonicalEncodeError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> None:
    raise CanonicalEncodeError(code, message)


def _canonical_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        if not -(2**53 - 1) <= value <= 2**53 - 1:
            _fail("ERR_NON_CANONICAL_NUMBER", "Integer exceeds the safe canonical range")
        return value
    if isinstance(value, float):
        _fail("ERR_NON_CANONICAL_NUMBER", "Floating-point values are not allowed")
    if isinstance(value, list):
        return [_canonical_value(item) for item in value]
    if isinstance(value, dict):
        result: Dict[str, Any] = {}
        for key in sorted(value):
            if not isinstance(key, str):
                _fail("ERR_NON_CANONICAL_KEY", "Object keys must be strings")
            result[key] = _canonical_value(value[key])
        return result
    _fail("ERR_NON_CANONICAL_VALUE", f"Unsupported value type: {type(value).__name__}")


def _require_domain(domain: str) -> None:
    if domain not in DOMAINS:
        _fail("ERR_UNKNOWN_DOMAIN", f"Unsupported TACVM domain: {domain}")


def canonical_encode(domain: str, fields: Mapping[str, Any]) -> bytes:
    """Return deterministic UTF-8 bytes for ``domain`` + ``fields``."""

    _require_domain(domain)
    if not isinstance(fields, Mapping):
        _fail("ERR_NON_CANONICAL_VALUE", "Fields must be a mapping")
    payload = {
        "domain": domain,
        "fields": _canonical_value(dict(fields)),
    }
    text = json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return text.encode("utf-8")


def hash_domain(domain: str, fields: Mapping[str, Any], algorithm: str = "sha384") -> str:
    """Return ``algorithm:hex`` over ``canonical_encode(domain, fields)``."""

    if not isinstance(fields, Mapping):
        _fail("ERR_NON_CANONICAL_VALUE", "Fields must be a mapping")
    encoded = canonical_encode(domain, fields)
    try:
        digest = hashlib.new(algorithm, encoded).hexdigest()
    except ValueError as exc:
        raise CanonicalEncodeError(
            "ERR_UNKNOWN_HASH", f"Unsupported hash algorithm: {algorithm}"
        ) from exc
    return f"{algorithm}:{digest}"
