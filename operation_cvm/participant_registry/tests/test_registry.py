from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tacvm_protocol import canonical_encode
from registry import (
    BootManifestParticipant,
    ParticipantRegistry,
    RegistryError,
)


def _keys():
    boot = Ed25519PrivateKey.generate()
    policy = Ed25519PrivateKey.generate()
    return boot, policy


def _sign_acceptance(boot_key, policy_key, participant_id, d_M, pk_ch, pk_policy):
    body = canonical_encode(
        "TACVM-ACCEPT",
        {
            "participant_id": participant_id,
            "d_M": d_M,
            "pk_ch": pk_ch,
            "pk_policy": pk_policy,
        },
    )
    return {
        "participant_id": participant_id,
        "d_M": d_M,
        "pk_ch": pk_ch,
        "pk_policy": pk_policy,
        "boot_signature": boot_key.sign(body),
        "policy_signature": policy_key.sign(body),
    }


def test_registers_all_manifest_participants_then_opens_policy_barrier():
    boot_a, policy_a = _keys()
    boot_b, policy_b = _keys()
    d_M = "sha384:manifest"
    pk_ch = "pk-op"
    registry = ParticipantRegistry(
        d_M=d_M,
        pk_ch=pk_ch,
        participants=[
            BootManifestParticipant(
                "id_01", boot_a.public_key(), expected_protocol_id="p1"
            ),
            BootManifestParticipant(
                "id_02", boot_b.public_key(), expected_protocol_id="p2"
            ),
        ],
    )
    assert not registry.all_registered()

    pk_a = policy_a.public_key().public_bytes_raw().hex()
    pk_b = policy_b.public_key().public_bytes_raw().hex()
    registry.submit_acceptance(
        _sign_acceptance(boot_a, policy_a, "id_01", d_M, pk_ch, pk_a)
    )
    assert not registry.all_registered()
    registry.submit_acceptance(
        _sign_acceptance(boot_b, policy_b, "id_02", d_M, pk_ch, pk_b)
    )
    assert registry.all_registered()
    assert list(registry.policy_key_map()) == ["id_01", "id_02"]


def test_rejects_unknown_duplicate_and_policy_key_reuse():
    boot_a, policy_a = _keys()
    boot_b, policy_b = _keys()
    d_M = "sha384:manifest"
    pk_ch = "pk-op"
    registry = ParticipantRegistry(
        d_M=d_M,
        pk_ch=pk_ch,
        participants=[
            BootManifestParticipant("id_01", boot_a.public_key()),
            BootManifestParticipant("id_02", boot_b.public_key()),
        ],
    )
    pk_a = policy_a.public_key().public_bytes_raw().hex()

    with pytest.raises(RegistryError) as unknown:
        registry.submit_acceptance(
            _sign_acceptance(boot_a, policy_a, "id_99", d_M, pk_ch, pk_a)
        )
    assert unknown.value.code == "ERR_UNKNOWN_PARTICIPANT"

    env = _sign_acceptance(boot_a, policy_a, "id_01", d_M, pk_ch, pk_a)
    registry.submit_acceptance(env)
    with pytest.raises(RegistryError) as dup:
        registry.submit_acceptance(env)
    assert dup.value.code == "ERR_DUPLICATE_ACCEPTANCE"

    with pytest.raises(RegistryError) as reused:
        registry.submit_acceptance(
            _sign_acceptance(boot_b, policy_b, "id_02", d_M, pk_ch, pk_a)
        )
    assert reused.value.code == "ERR_POLICY_KEY_PROOF"
