"""One pinned experimental PRIVATE_ZK profile for the V6 queue runtime.

The profile is a driver-owned software fence for the current synthetic native
fixture.  It is deliberately not a production manifest or a proof-backend
selection record.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from pathlib import Path
from typing import Any, Final


_DIGEST_BYTES: Final[int] = 64
_ZERO_SUITE: Final[bytes] = bytes(_DIGEST_BYTES)
PROFILE_EPOCH: Final[int] = 7
PROTOCOL_VERSION: Final[int] = 3
PROOF_ROLE: Final[bytes] = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/v3"
CIRCUIT_ID: Final[bytes] = bytes.fromhex(
    "0f9fefb8cf05cc4e7a6b9657878c05a37034736d193272e14981f97fdd5a4275"
)
NATIVE_DIMENSIONS: Final[tuple[int, int, int, int]] = (52_057, 40_721, 337, 24_455_436)
DIRECTIVES: Final[tuple[str, ...]] = (
    "CLEAR", "HOLD", "HUMAN_REVIEW", "BLOCK", "EXCEPTION_APPROVED",
)
_PROFILE_DOMAIN = b"BL/NATIVE-V3/PRIVATE-ZK/STATIC-PROFILE/v6\x00"


def _hash_text(domain: bytes, value: str) -> bytes:
    return hashlib.sha3_512(domain + b"\x00" + value.encode("ascii")).digest()


SOURCE_REGISTRY_SNAPSHOT: Final[bytes] = _hash_text(
    b"BL/NATIVE-V3/SOURCE-REGISTRY-SNAPSHOT/v2", "snapshot-1"
)
SOURCE_PROFILE: Final[bytes] = _hash_text(
    b"BL/NATIVE-V3/SOURCE-PROFILE/v2", "synthetic-authoritative"
)
GOVERNANCE_SNAPSHOT: Final[bytes] = _hash_text(
    b"BL/NATIVE-V3/GOVERNANCE-SNAPSHOT/v3", "governance-1"
)
AUTOMATIC_CONTROL_SET: Final[bytes] = _hash_text(
    b"BL/NATIVE-V3/CONTROL-SET/v3",
    ",".join(DIRECTIVES),
)
SETTLEMENT_DOMAIN: Final[bytes] = _hash_text(
    b"BL/NATIVE-V3/SETTLEMENT-DOMAIN/v3", "official-state-rail"
)
EVALUATOR_ID: Final[bytes] = _hash_text(
    b"BL/NATIVE-V3/EVALUATOR/v2", "minimal-clearance-evaluator"
)
SCHEMA_ID: Final[bytes] = _hash_text(
    b"BL/NATIVE-V3/SCHEMA/v2", "minimal-clearance-schema"
)
PROGRAM_ID: Final[bytes] = _hash_text(
    b"BL/NATIVE-V3/PROGRAM/v2", "minimal-clearance-program"
)
POLICY_ID: Final[bytes] = _hash_text(
    b"BL/NATIVE-V3/POLICY/v2", "minimal-five-directive-policy"
)
RULE_ID: Final[bytes] = _hash_text(
    b"BL/NATIVE-V3/RULE/v1", "synthetic-rule-v1"
)
INSTALLATION_ID: Final[bytes] = _hash_text(
    b"BL/NATIVE-V3/INSTALLATION-IDENTITY/v1", "synthetic-v3-installation"
)

_STATE_LAYOUT_LITERAL: Final[bytes] = (
    b"BLST-V2|magic:u8[4]@0|version:u8@4=2|policy_result:u8@5|"
    b"effective_directive:u8@6|complete:u8@7|membership:u8@8|absence:u8@9|"
    b"active:u8@10|exception_present:u8@11|exception_authorized:u8@12|"
    b"economic_mutation:u8@13|clearance_marker_before:u8@14|"
    b"clearance_marker_after:u8@15|epoch:u64be@16|sequence_before:u64be@24|"
    b"rule_effective_time:u64be@32|event_time:u64be@40|"
    b"observation_time:u64be@48|decision_time:u64be@56|read_time:u64be@64|"
    b"write_time:u64be@72|exception_valid_from:u64be@80|"
    b"exception_valid_until:u64be@88|sequence_after:u64be@96|"
    b"decision_index:u32be@104|decision_count:u32be@108|"
    b"read_access_index:u32be@112|write_access_index:u32be@116|"
    b"access_count:u32be@120|read_decision_index:u32be@124|"
    b"write_decision_index:u32be@128|read_mode:u8@132|write_mode:u8@133|"
    b"clearance_count_before:u64be@134|clearance_count_after:u64be@142|"
    b"digests:23*u8[64]@150|proposed_payment_commitment:u8[64]@1622|"
    b"length:1686|capacity:u32be=1|tail:final-64-bytes|no-padding"
)
_STATE_LAYOUT_ID: Final[bytes] = hashlib.sha3_512(
    b"BL/NATIVE-V3/STATE-LAYOUT/v2\x00" + _STATE_LAYOUT_LITERAL
).digest()
def _context_part(label: str, value: bytes) -> bytes:
    label_bytes = label.encode("ascii")
    return (
        len(label_bytes).to_bytes(4, "big")
        + label_bytes
        + len(value).to_bytes(8, "big")
        + value
    )


_NATIVE_DIMENSIONS_BYTES: Final[bytes] = b"".join(
    value.to_bytes(8, "big") for value in NATIVE_DIMENSIONS
)
_EXECUTION_CONTEXT_MATERIAL: Final[bytes] = (
    b"BL/NATIVE-V3/EXECUTION-CONTEXT/v4\x00"
    + _context_part("mode", b"PRIVATE_ZK")
    + _context_part("source_registry_snapshot", SOURCE_REGISTRY_SNAPSHOT)
    + _context_part("source_profile", SOURCE_PROFILE)
    + _context_part("governance_snapshot", GOVERNANCE_SNAPSHOT)
    + _context_part("automatic_control_set", AUTOMATIC_CONTROL_SET)
    + _context_part("settlement_domain", SETTLEMENT_DOMAIN)
    + _context_part("evaluator_id", EVALUATOR_ID)
    + _context_part("schema_id", SCHEMA_ID)
    + _context_part("program_id", PROGRAM_ID)
    + _context_part("policy_id", POLICY_ID)
    + _context_part("proof_role", PROOF_ROLE)
    + _context_part("semantic_profile", b"MINIMAL_CLEARANCE_SEMANTIC_V6")
    + _context_part("native_dimensions", _NATIVE_DIMENSIONS_BYTES)
    + _context_part("state_layout_id", _STATE_LAYOUT_ID)
    + _context_part("capacity", (1).to_bytes(4, "big"))
    + _context_part("profile_epoch", PROFILE_EPOCH.to_bytes(8, "big"))
)
EXECUTION_CONTEXT_ID: Final[bytes] = hashlib.sha3_512(
    _EXECUTION_CONTEXT_MATERIAL
).digest()


def _profile_identity_material() -> tuple[bytes, ...]:
    return (
        PROTOCOL_VERSION.to_bytes(4, "big"),
        PROOF_ROLE,
        _ZERO_SUITE,
        EXECUTION_CONTEXT_ID,
        SOURCE_REGISTRY_SNAPSHOT,
        SOURCE_PROFILE,
        GOVERNANCE_SNAPSHOT,
        AUTOMATIC_CONTROL_SET,
        EVALUATOR_ID,
        SCHEMA_ID,
        PROGRAM_ID,
        POLICY_ID,
        SETTLEMENT_DOMAIN,
        CIRCUIT_ID,
        b"".join(value.to_bytes(8, "big") for value in NATIVE_DIMENSIONS),
        PROFILE_EPOCH.to_bytes(8, "big"),
        b"proofSuiteId=null",
        b"production_usable=false",
        b"activation=false",
        RULE_ID,
    )


def derive_profile_digest(verifier_sha256: bytes) -> bytes:
    if type(verifier_sha256) is not bytes or len(verifier_sha256) != 32:
        raise ValueError("profile_verifier_sha256")
    digest = hashlib.sha3_512()
    digest.update(_PROFILE_DOMAIN)
    for part in _profile_identity_material() + (verifier_sha256,):
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return digest.digest()


def statement_matches_static(statement: Any) -> bool:
    """Check only the driver-owned fixed PRIVATE_ZK statement fields."""
    try:
        fixed = {
            "protocol_version": PROTOCOL_VERSION,
            "proof_role": PROOF_ROLE,
            "proof_suite": _ZERO_SUITE,
            "execution_context": _profile_identity_material()[3],
            "source_registry_snapshot": SOURCE_REGISTRY_SNAPSHOT,
            "source_profile": SOURCE_PROFILE,
            "governance_snapshot": GOVERNANCE_SNAPSHOT,
            "automatic_control_set": _profile_identity_material()[7],
            "evaluator_id": _profile_identity_material()[8],
            "schema_id": _profile_identity_material()[9],
            "program_id": _profile_identity_material()[10],
            "policy_id": _profile_identity_material()[11],
            "rule_id": RULE_ID,
            "settlement_domain": _profile_identity_material()[12],
            "epoch": PROFILE_EPOCH,
        }
        return all(statement.get(name) == value for name, value in fixed.items())
    except (AttributeError, KeyError, TypeError, ValueError):
        return False


@dataclass(frozen=True, slots=True)
class ExperimentalPrivateZkProfile:
    """Pinned profile plus the explicitly supplied experimental executable hash."""

    executable: Path = field(repr=False)
    verifier_sha256: bytes
    profile_digest: bytes
    profile_epoch: int = PROFILE_EPOCH
    proof_suite_id: None = None
    production_usable: bool = False
    activation: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.executable, Path) or not self.executable.is_absolute():
            raise ValueError("profile_executable")
        if type(self.verifier_sha256) is not bytes or len(self.verifier_sha256) != 32:
            raise ValueError("profile_verifier_sha256")
        if type(self.profile_digest) is not bytes or len(self.profile_digest) != 64:
            raise ValueError("profile_digest")
        if self.profile_digest != derive_profile_digest(self.verifier_sha256):
            raise ValueError("profile_digest")
        if self.profile_epoch != PROFILE_EPOCH or self.proof_suite_id is not None:
            raise ValueError("profile_epoch")
        if self.production_usable is not False or self.activation is not False:
            raise ValueError("profile_activation")

    @classmethod
    def supplied(cls, executable: Path, verifier_sha256: bytes) -> "ExperimentalPrivateZkProfile":
        return cls(executable, verifier_sha256, derive_profile_digest(verifier_sha256))

    def as_json(self) -> dict[str, Any]:
        material = _profile_identity_material()
        return {
            "profile_schema": "BL/NATIVE-V3/MINIMAL-CLEARANCE/PRIVATE-ZK-PROFILE/v6",
            "profile_digest": self.profile_digest.hex().upper(),
            "profile_epoch": self.profile_epoch,
            "verifier_sha256": self.verifier_sha256.hex().upper(),
            "circuit_id": CIRCUIT_ID.hex().upper(),
            "protocol_version": PROTOCOL_VERSION,
            "proof_role": PROOF_ROLE.decode("ascii"),
            "proof_suite_id": None,
            "production_usable": False,
            "activation": False,
            "directives": list(DIRECTIVES),
            "native_dimensions": list(NATIVE_DIMENSIONS),
            "execution_context": material[3].hex().upper(),
            "source_registry_snapshot": material[4].hex().upper(),
            "source_profile": material[5].hex().upper(),
            "governance_snapshot": material[6].hex().upper(),
            "automatic_control_set": material[7].hex().upper(),
            "evaluator_id": material[8].hex().upper(),
            "schema_id": material[9].hex().upper(),
            "program_id": material[10].hex().upper(),
            "policy_id": material[11].hex().upper(),
            "settlement_domain": material[12].hex().upper(),
        }

    def matches_statement(self, statement: Any) -> bool:
        return statement_matches_static(statement)


__all__ = (
    "CIRCUIT_ID", "DIRECTIVES", "ExperimentalPrivateZkProfile",
    "GOVERNANCE_SNAPSHOT", "NATIVE_DIMENSIONS", "PROFILE_EPOCH", "PROOF_ROLE",
    "PROTOCOL_VERSION", "INSTALLATION_ID", "RULE_ID", "derive_profile_digest",
    "SOURCE_PROFILE", "SOURCE_REGISTRY_SNAPSHOT", "statement_matches_static",
)
