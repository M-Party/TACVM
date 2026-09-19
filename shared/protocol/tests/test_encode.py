from __future__ import annotations

import pytest

from tacvm_protocol import (
    DOMAINS,
    CanonicalEncodeError,
    canonical_encode,
    hash_domain,
)


def test_known_domains_include_paper_labels():
    for label in (
        "TACVM-BOOT",
        "TACVM-ACCEPT",
        "TACVM-POLICY",
        "TACVM-PROPOSAL",
        "TACVM-CONFIRM",
        "TACVM-WORKLOAD",
        "TACVM-WORKLOAD-ATTEST",
        "TACVM-TRANS",
    ):
        assert label in DOMAINS


def test_canonical_encode_is_deterministic_and_key_order_independent():
    left = canonical_encode(
        "TACVM-BOOT",
        {"n_i": "aa" * 32, "pk_ch": "pk-1", "d_M": "digest-m"},
    )
    right = canonical_encode(
        "TACVM-BOOT",
        {"d_M": "digest-m", "n_i": "aa" * 32, "pk_ch": "pk-1"},
    )
    assert left == right
    assert isinstance(left, bytes)
    assert left.startswith(b"{") or left.startswith(b"\x00") or len(left) > 0


def test_different_domains_do_not_collide_for_same_fields():
    fields = {"participant_id": "id_01", "pid": "p", "v": 1, "r": 0, "digest": "h"}
    proposal = hash_domain("TACVM-PROPOSAL", fields)
    confirm = hash_domain("TACVM-CONFIRM", fields)
    assert proposal != confirm
    assert proposal.startswith("sha384:")
    assert confirm.startswith("sha384:")


def test_hash_domain_matches_hash_of_canonical_bytes():
    import hashlib

    fields = {"w": "w-1", "pid": "pid-1", "pk_ch": "pk"}
    encoded = canonical_encode("TACVM-WORKLOAD", fields)
    expected = "sha384:" + hashlib.sha384(encoded).hexdigest()
    assert hash_domain("TACVM-WORKLOAD", fields) == expected


def test_rejects_unknown_domain_and_non_canonical_values():
    with pytest.raises(CanonicalEncodeError) as unknown:
        canonical_encode("TACVM-NOT-A-DOMAIN", {"a": 1})
    assert unknown.value.code == "ERR_UNKNOWN_DOMAIN"

    with pytest.raises(CanonicalEncodeError) as bad_float:
        canonical_encode("TACVM-POLICY", {"d_M": "x", "pk_ch": "y", "score": 1.5})
    assert bad_float.value.code == "ERR_NON_CANONICAL_NUMBER"

    with pytest.raises(CanonicalEncodeError) as bad_domain_type:
        hash_domain("TACVM-BOOT", ["not", "a", "mapping"])
    assert bad_domain_type.value.code == "ERR_NON_CANONICAL_VALUE"
