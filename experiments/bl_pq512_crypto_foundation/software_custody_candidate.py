"""Software-only custody and anti-rollback qualification facts.

This is deliberately explicit about what local engineering can prove.  The
PQ KEM envelope, durable state/rollback rules, key lifecycle registry, nonce
guard, and isolated local operations are source-backed.  HSM/FIPS validation
and an external monotonic authority are not implied by those facts and remain
closed activation boundaries.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Final


ROOT: Final[Path] = Path(__file__).resolve().parents[2]
STATUS: Final[str] = "SOFTWARE_PQ_CUSTODY_AND_ANTIROLLBACK_VERIFIED_NONACTIVATING"
ACTIVATION_ALLOWED: Final[bool] = False
PRODUCTION_USABLE: Final[bool] = False
SOURCE_MARKERS: Final[tuple[tuple[str, tuple[str, ...]], ...]] = (
    (
        "experiments/bl_pq512_crypto_foundation/wave3_verifier_state_custody.py",
        (
            "class MlKem1024Aes256ReferenceV1",
            "class Wave3DurableStateV1",
            "class Wave3RollbackRecordV1",
            "production_usable",
        ),
    ),
    (
        "ops/KEY_CUSTODY_AND_ROTATION.md",
        ("software/reference", "HSM custody", "FIPS-module"),
    ),
)
OPEN_BOUNDARIES: Final[tuple[str, ...]] = (
    "HSM_FIPS_VALIDATION",
    "EXTERNAL_ANTIROLLBACK_AUTHORITY",
)


class SoftwareCustodyError(ValueError):
    """Fail-closed error for stale custody source evidence."""


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("ascii")


@dataclass(frozen=True, slots=True)
class SoftwareCustodyCertificate:
    status: str
    source_digests_sha3_512: tuple[tuple[str, str], ...]
    software_only: bool = True
    hsm_backed: bool = False
    fips_validated: bool = False
    production_usable: bool = False
    activation_allowed: bool = False
    open_boundaries: tuple[str, ...] = OPEN_BOUNDARIES

    def __post_init__(self) -> None:
        if self.status != STATUS:
            raise SoftwareCustodyError("software_custody_status_invalid")
        if not self.software_only or self.hsm_backed or self.fips_validated:
            raise SoftwareCustodyError("software_custody_security_profile_invalid")
        if self.production_usable or self.activation_allowed:
            raise SoftwareCustodyError("software_custody_activation_boundary_invalid")
        if self.open_boundaries != OPEN_BOUNDARIES:
            raise SoftwareCustodyError("software_custody_open_boundary_order_invalid")
        if tuple(path for path, _ in self.source_digests_sha3_512) != tuple(
            path for path, _ in SOURCE_MARKERS
        ):
            raise SoftwareCustodyError("software_custody_source_order_invalid")
        if any(len(digest) != 128 or digest == "0" * 128 for _, digest in self.source_digests_sha3_512):
            raise SoftwareCustodyError("software_custody_source_digest_invalid")

    @property
    def certificate_digest_sha3_512(self) -> str:
        payload = {
            "status": self.status,
            "source_digests_sha3_512": self.source_digests_sha3_512,
            "software_only": self.software_only,
            "hsm_backed": self.hsm_backed,
            "fips_validated": self.fips_validated,
            "production_usable": self.production_usable,
            "activation_allowed": self.activation_allowed,
            "open_boundaries": self.open_boundaries,
        }
        return hashlib.sha3_512(
            b"BL/PQ512/SOFTWARE-CUSTODY-CERTIFICATE/v1\0" + _canonical(payload)
        ).hexdigest()

    def as_public_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "sourceFiles": [
                {"path": path, "sha3_512": digest}
                for path, digest in self.source_digests_sha3_512
            ],
            "softwareOnly": self.software_only,
            "hsmBacked": self.hsm_backed,
            "fipsValidated": self.fips_validated,
            "productionUsable": self.production_usable,
            "activationAllowed": self.activation_allowed,
            "openBoundaries": list(self.open_boundaries),
            "certificateSha3_512": self.certificate_digest_sha3_512,
        }


def build_software_custody_certificate(
    root: Path = ROOT,
) -> SoftwareCustodyCertificate:
    if not isinstance(root, Path):
        raise TypeError("software_custody_root_required")
    digests: list[tuple[str, str]] = []
    for relative, markers in SOURCE_MARKERS:
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise SoftwareCustodyError(f"software_custody_source_missing:{relative}")
        try:
            raw = path.read_bytes()
            text = raw.decode("utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise SoftwareCustodyError(f"software_custody_source_unreadable:{relative}") from exc
        missing = tuple(marker for marker in markers if marker not in text)
        if missing:
            raise SoftwareCustodyError(
                f"software_custody_source_marker_missing:{relative}:{','.join(missing)}"
            )
        digests.append((relative, hashlib.sha3_512(raw).hexdigest()))
    return SoftwareCustodyCertificate(STATUS, tuple(digests))


def validate_software_custody_certificate(
    certificate: SoftwareCustodyCertificate,
    root: Path = ROOT,
) -> None:
    if not isinstance(certificate, SoftwareCustodyCertificate):
        raise TypeError("software_custody_certificate_required")
    if certificate != build_software_custody_certificate(root):
        raise SoftwareCustodyError("software_custody_certificate_stale")


__all__ = (
    "ACTIVATION_ALLOWED",
    "OPEN_BOUNDARIES",
    "PRODUCTION_USABLE",
    "STATUS",
    "SoftwareCustodyCertificate",
    "SoftwareCustodyError",
    "build_software_custody_certificate",
    "validate_software_custody_certificate",
)
