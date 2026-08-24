"""One pinned experimental PRIVATE_ZK profile for the V4 queue runtime.

The profile is a driver-owned software fence for the current synthetic native
fixture.  It is deliberately not a production manifest or a proof-backend
selection record.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import re
from typing import Any, Final, Mapping


_DIGEST_BYTES: Final[int] = 64
_ZERO_SUITE: Final[bytes] = bytes(_DIGEST_BYTES)
PROFILE_EPOCH: Final[int] = 7
PROTOCOL_VERSION: Final[int] = 3
PROOF_ROLE: Final[bytes] = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/v1"
CIRCUIT_ID: Final[bytes] = bytes.fromhex(
    "1eaaf14f3b23db1ed02f3c378099627767f81142e0114f90448cac7c1cc66be0"
)
NATIVE_DIMENSIONS: Final[tuple[int, int, int, int]] = (36_969, 26_721, 217, 12_158_968)
DIRECTIVES: Final[tuple[str, ...]] = (
    "CLEAR", "HOLD", "HUMAN_REVIEW", "BLOCK", "EXCEPTION_APPROVED",
)
_PROFILE_DOMAIN = b"BL/NATIVE-V3/PRIVATE-ZK/STATIC-PROFILE/v4\x00"


def _hash_text(domain: bytes, value: str) -> bytes:
    return hashlib.sha3_512(domain + b"\x00" + value.encode("ascii")).digest()


def _profile_identity_material() -> tuple[bytes, ...]:
    return (
        PROTOCOL_VERSION.to_bytes(4, "big"),
        PROOF_ROLE,
        _ZERO_SUITE,
        _hash_text(b"BL/NATIVE-V3/EXECUTION-CONTEXT/v2", "minimal-clearance"),
        _hash_text(b"BL/NATIVE-V3/CONTROL-SET/v2", ",".join(DIRECTIVES)),
        _hash_text(b"BL/NATIVE-V3/EVALUATOR/v1", "minimal-clearance-evaluator"),
        _hash_text(b"BL/NATIVE-V3/SCHEMA/v1", "minimal-clearance-schema"),
        _hash_text(b"BL/NATIVE-V3/PROGRAM/v1", "minimal-clearance-program"),
        _hash_text(b"BL/NATIVE-V3/POLICY/v1", "minimal-five-directive-policy"),
        _hash_text(b"BL/NATIVE-V3/SETTLEMENT-DOMAIN/v2", "official-state-rail"),
        CIRCUIT_ID,
        b"".join(value.to_bytes(8, "big") for value in NATIVE_DIMENSIONS),
        PROFILE_EPOCH.to_bytes(8, "big"),
        b"proofSuiteId=null",
        b"production_usable=false",
        b"activation=false",
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


def derive_installation_id(root: Path) -> bytes:
    if not isinstance(root, Path) or not root.is_absolute():
        raise ValueError("profile_installation_root")
    return hashlib.sha3_512(
        b"BL/NATIVE-V3/INSTALLATION/v1\x00" + root.as_posix().encode("utf-8")
    ).digest()


def statement_matches_static(statement: Any) -> bool:
    """Check only the driver-owned fixed PRIVATE_ZK statement fields."""
    try:
        fixed = {
            "protocol_version": PROTOCOL_VERSION,
            "proof_role": PROOF_ROLE,
            "proof_suite": _ZERO_SUITE,
            "execution_context": _profile_identity_material()[3],
            "automatic_control_set": _profile_identity_material()[4],
            "evaluator_id": _profile_identity_material()[5],
            "schema_id": _profile_identity_material()[6],
            "program_id": _profile_identity_material()[7],
            "policy_id": _profile_identity_material()[8],
            "settlement_domain": _profile_identity_material()[9],
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
            "profile_schema": "BL/NATIVE-V3/MINIMAL-CLEARANCE/PRIVATE-ZK-PROFILE/v4",
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
            "automatic_control_set": material[4].hex().upper(),
            "evaluator_id": material[5].hex().upper(),
            "schema_id": material[6].hex().upper(),
            "program_id": material[7].hex().upper(),
            "policy_id": material[8].hex().upper(),
            "settlement_domain": material[9].hex().upper(),
        }

    def matches_statement(self, statement: Any) -> bool:
        return statement_matches_static(statement)


__all__ = (
    "CIRCUIT_ID", "DIRECTIVES", "ExperimentalPrivateZkProfile",
    "NATIVE_DIMENSIONS", "PROFILE_EPOCH", "PROOF_ROLE",
    "PROTOCOL_VERSION", "derive_installation_id", "derive_profile_digest",
    "statement_matches_static",
)
