"""Participant acceptance registry and all-registered barrier (Operation CVM)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from tacvm_protocol import canonical_encode


class RegistryError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class BootManifestParticipant:
    participant_id: str
    boot_public_key: Ed25519PublicKey
    expected_protocol_id: str = ""


@dataclass(frozen=True)
class RegisteredParticipant:
    participant_id: str
    policy_public_key_hex: str


class ParticipantRegistry:
    """Ordered registry R[id] -> policy key after TACVM-ACCEPT verification."""

    def __init__(
        self,
        d_M: str,
        pk_ch: str,
        participants: Iterable[BootManifestParticipant],
    ) -> None:
        ordered = list(participants)
        if not ordered:
            raise RegistryError("ERR_UNKNOWN_PARTICIPANT", "Manifest is empty")
        ids = [item.participant_id for item in ordered]
        if len(ids) != len(set(ids)):
            raise RegistryError(
                "ERR_UNKNOWN_PARTICIPANT",
                "Manifest participant identifiers must be unique",
            )
        self.d_M = d_M
        self.pk_ch = pk_ch
        self._manifest: Dict[str, BootManifestParticipant] = {
            item.participant_id: item for item in ordered
        }
        self._order: List[str] = ids
        self._accepted: Dict[str, RegisteredParticipant] = {}
        self._policy_keys: Dict[str, str] = {}

    def all_registered(self) -> bool:
        return len(self._accepted) == len(self._order)

    def policy_key_map(self) -> Dict[str, str]:
        return {
            participant_id: self._accepted[participant_id].policy_public_key_hex
            for participant_id in self._order
            if participant_id in self._accepted
        }

    def submit_acceptance(self, envelope: Mapping[str, object]) -> None:
        participant_id = envelope.get("participant_id")
        if not isinstance(participant_id, str) or participant_id not in self._manifest:
            raise RegistryError(
                "ERR_UNKNOWN_PARTICIPANT",
                f"Unknown participant {participant_id!r}",
            )
        if participant_id in self._accepted:
            raise RegistryError(
                "ERR_DUPLICATE_ACCEPTANCE",
                f"{participant_id} already registered a policy key",
            )

        d_M = envelope.get("d_M")
        pk_ch = envelope.get("pk_ch")
        pk_policy = envelope.get("pk_policy")
        boot_signature = envelope.get("boot_signature")
        policy_signature = envelope.get("policy_signature")
        if d_M != self.d_M:
            raise RegistryError("ERR_MANIFEST_MISMATCH", "Acceptance d_M mismatch")
        if pk_ch != self.pk_ch:
            raise RegistryError(
                "ERR_CHANNEL_KEY_MISMATCH",
                "Acceptance pk_ch mismatch",
            )
        if not isinstance(pk_policy, str) or not pk_policy:
            raise RegistryError("ERR_POLICY_KEY_PROOF", "pk_policy missing")
        if pk_policy in self._policy_keys:
            raise RegistryError(
                "ERR_POLICY_KEY_PROOF",
                "Policy key already bound to another participant",
            )
        if not isinstance(boot_signature, (bytes, bytearray)):
            raise RegistryError("ERR_BOOT_SIGNATURE", "boot_signature missing")
        if not isinstance(policy_signature, (bytes, bytearray)):
            raise RegistryError("ERR_POLICY_KEY_PROOF", "policy_signature missing")

        body = canonical_encode(
            "TACVM-ACCEPT",
            {
                "participant_id": participant_id,
                "d_M": d_M,
                "pk_ch": pk_ch,
                "pk_policy": pk_policy,
            },
        )
        manifest_entry = self._manifest[participant_id]
        try:
            manifest_entry.boot_public_key.verify(bytes(boot_signature), body)
        except InvalidSignature as exc:
            raise RegistryError(
                "ERR_BOOT_SIGNATURE",
                "Boot-key signature verification failed",
            ) from exc

        try:
            policy_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk_policy))
        except (ValueError, TypeError) as exc:
            raise RegistryError(
                "ERR_POLICY_KEY_PROOF",
                "pk_policy is not a valid Ed25519 public key",
            ) from exc
        try:
            policy_key.verify(bytes(policy_signature), body)
        except InvalidSignature as exc:
            raise RegistryError(
                "ERR_POLICY_KEY_PROOF",
                "Policy-key proof verification failed",
            ) from exc

        self._accepted[participant_id] = RegisteredParticipant(
            participant_id=participant_id,
            policy_public_key_hex=pk_policy,
        )
        self._policy_keys[pk_policy] = participant_id

    def require_complete(self) -> Dict[str, str]:
        if not self.all_registered():
            missing = [pid for pid in self._order if pid not in self._accepted]
            raise RegistryError(
                "ERR_UNKNOWN_PARTICIPANT",
                f"Missing acceptances from {', '.join(missing)}",
            )
        return self.policy_key_map()
