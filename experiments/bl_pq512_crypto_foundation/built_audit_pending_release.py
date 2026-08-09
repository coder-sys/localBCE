"""Nonactivating aggregate release identity and LB-010 qualification gate.

This module identifies exact candidate bytes. It does not select a global
``proofSuiteId`` and cannot make an artifact production-usable or active.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Final, Iterable


ROOT: Final[Path] = Path(__file__).resolve().parents[2]
RELEASE_SCHEMA: Final[Path] = ROOT / "schemas" / "bl_pq512_built_audit_pending_release_contract_v1.json"
PUBLIC_INPUT_SCHEMA: Final[Path] = ROOT / "ops" / "native_stark_public_inputs_v2.json"
RELEASE_IDENTITY_DOMAIN: Final[bytes] = b"BL/PQ512/BUILT-AUDIT-PENDING/RELEASE-IDENTITY/v1\x00"
SOURCE_SET_DOMAIN: Final[bytes] = b"BL/PQ512/BUILT-AUDIT-PENDING/SOURCE-SET/v1\x00"
UNQUALIFIED_STATUS: Final[str] = "AGGREGATE_UNQUALIFIED"
PUBLIC_FIELD_NAMES: Final[tuple[str, ...]] = (
    "protocolVersion",
    "settlementDomain",
    "batchNonce",
    "nullifierRootBefore",
    "nullifierRootAfter",
    "claimSourceRoot",
    "oracleFactsRoot",
    "policyRoot",
    "rulesetRoot",
    "opaqueBatchCommitment",
    "valueConservationCommitment",
    "settlementCommitment",
)
REQUIRED_ARTIFACT_ROLES: Final[tuple[str, ...]] = (
    "releaseContractSchema",
    "publicInputSchema",
    "proofParameters",
    "airProgram",
    "proverExecutable",
    "verifierExecutable",
    "transcriptContract",
    "toolchain",
)


class BuiltAuditPendingReleaseError(ValueError):
    """Fail-closed release identity or aggregate qualification error."""


def _wide(label: str, value: object) -> bytes:
    if type(value) is not bytes or len(value) != 64 or not any(value):
        raise BuiltAuditPendingReleaseError(f"release_{label}_invalid")
    return value


def _frame(domain: bytes, parts: Iterable[bytes]) -> bytes:
    output = bytearray(domain)
    for part in parts:
        if type(part) is not bytes or len(part) > 0xFFFF_FFFF:
            raise BuiltAuditPendingReleaseError("release_frame_part_invalid")
        output.extend(len(part).to_bytes(4, "big"))
        output.extend(part)
    return bytes(output)


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise BuiltAuditPendingReleaseError("release_json_duplicate_key")
        output[key] = value
    return output


def _strict_json(encoded: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(encoded.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BuiltAuditPendingReleaseError(f"release_{label}_json_invalid") from exc
    if type(value) is not dict:
        raise BuiltAuditPendingReleaseError(f"release_{label}_json_shape_invalid")
    return value


def _read_regular_file(path: Path, label: str, *, retain: bool) -> tuple[int, bytes, bytes]:
    if not isinstance(path, Path) or not path.is_absolute():
        raise BuiltAuditPendingReleaseError(f"release_{label}_path_invalid")
    try:
        with path.open("rb") as handle:
            before = os.fstat(handle.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
                raise BuiltAuditPendingReleaseError(f"release_{label}_file_invalid")
            digest = hashlib.sha3_512()
            content = bytearray()
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
                if retain:
                    content.extend(chunk)
            after = os.fstat(handle.fileno())
    except OSError as exc:
        raise BuiltAuditPendingReleaseError(f"release_{label}_read_failed") from exc
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ) or (retain and len(content) != before.st_size):
        raise BuiltAuditPendingReleaseError(f"release_{label}_changed_during_read")
    return before.st_size, digest.digest(), bytes(content)


@dataclass(frozen=True, slots=True)
class ReleaseArtifactPin:
    role: str
    byte_length: int
    sha3_512: bytes

    def __post_init__(self) -> None:
        if type(self.role) is not str or not self.role or "\x00" in self.role:
            raise BuiltAuditPendingReleaseError("release_artifact_role_invalid")
        if type(self.byte_length) is not int or self.byte_length <= 0:
            raise BuiltAuditPendingReleaseError("release_artifact_length_invalid")
        _wide("artifact_sha3_512", self.sha3_512)

    def commitment_bytes(self) -> bytes:
        return _frame(
            b"BL/PQ512/BUILT-AUDIT-PENDING/ARTIFACT-PIN/v1\x00",
            (self.role.encode("utf-8"), self.byte_length.to_bytes(8, "big"), self.sha3_512),
        )


def _pin(path: Path, role: str, *, retain: bool = False) -> tuple[ReleaseArtifactPin, bytes]:
    length, digest, content = _read_regular_file(path, role, retain=retain)
    return ReleaseArtifactPin(role, length, digest), content


def _validate_contract_schema(encoded: bytes) -> dict[str, object]:
    value = _strict_json(encoded, "contract_schema")
    envelope = value.get("envelope")
    sidecar = value.get("sidecar")
    profile = value.get("proofProfile")
    verifier = value.get("independentVerifier")
    qualification = value.get("qualification")
    release_identity = value.get("releaseIdentity")
    historical = value.get("historicalRejectedTransport")
    if (
        value.get("contractVersion") != "BL-PQ512-BUILT-AUDIT-PENDING-RELEASE-v1"
        or type(envelope) is not dict
        or envelope.get("magicAscii") != "BLPQENV1"
        or envelope.get("version") != 2
        or envelope.get("fixedPrefixBytes") != 1342
        or envelope.get("maximumEnvelopeBytes") != 536_870_912
        or envelope.get("proofPackageBytes") != 67_108_864
        or envelope.get("maximumTranscriptBytes") != 16_777_216
        or envelope.get("trailingBytesAllowed") is not False
        or type(sidecar) is not dict
        or sidecar.get("magicAscii") != "BLPQSC01"
        or sidecar.get("version") != 1
        or sidecar.get("flags") != 0
        or sidecar.get("encodedLength") != 744
        or type(profile) is not dict
        or profile.get("authoritativeCommitment") != "SHA3-512"
        or profile.get("baseField") != "M31"
        or profile.get("extensionField") != "Fp16"
        or profile.get("nativeWitnessHiding") != "Construction-8.2 candidate"
        or profile.get("launchTranscript") != "authenticated interactive public coin"
        or profile.get("authentication") != ["ML-DSA-87", "SLH-DSA-SHAKE-256f"]
        or type(verifier) is not dict
        or verifier.get("implementationDiversityClaimed") is not False
        or type(historical) is not dict
        or historical.get("magicAscii") != "BLPQEN01"
        or historical.get("version") != 1
        or type(release_identity) is not dict
        or release_identity.get("hash") != "SHA3-512"
        or release_identity.get("domainAsciiNul")
        != RELEASE_IDENTITY_DOMAIN.decode("ascii")
        or release_identity.get("requiredArtifactRoles")
        != [*REQUIRED_ARTIFACT_ROLES, "sourceSet"]
        or type(qualification) is not dict
        or qualification.get("aggregateStatus") != UNQUALIFIED_STATUS
        or qualification.get("callerPairedReceiptAndDigestAccepted") is not False
        or qualification.get("verifiedEvidenceImplementation") != "OPEN"
        or qualification.get("perProofBuiltAuditPendingReachable") is not False
        or qualification.get("globalProofSuiteId") is not None
        or qualification.get("productionUsable") is not False
        or qualification.get("activationAllowed") is not False
    ):
        raise BuiltAuditPendingReleaseError("release_contract_schema_semantics_invalid")
    return value


def _validate_public_input_schema(encoded: bytes, contract: dict[str, object]) -> None:
    value = _strict_json(encoded, "public_input_schema")
    fields = value.get("fields")
    contract_public = contract.get("publicInputSchema")
    if type(fields) is not list or len(fields) != 12 or type(contract_public) is not dict:
        raise BuiltAuditPendingReleaseError("release_public_input_schema_shape_invalid")
    observed = []
    for index, field in enumerate(fields):
        if (
            type(field) is not dict
            or field.get("index") != index
            or field.get("solidity_type") != "bytes32"
            or field.get("submission_field") != field.get("name")
        ):
            raise BuiltAuditPendingReleaseError("release_public_input_field_invalid")
        observed.append(field.get("name"))
    if tuple(observed) != PUBLIC_FIELD_NAMES:
        raise BuiltAuditPendingReleaseError("release_public_input_order_invalid")
    if (
        contract_public.get("bytes") != len(encoded)
        or contract_public.get("sha3_512") != hashlib.sha3_512(encoded).hexdigest()
        or contract_public.get("fieldCount") != 12
        or contract_public.get("fieldType") != "bytes32"
    ):
        raise BuiltAuditPendingReleaseError("release_public_input_schema_pin_mismatch")


@dataclass(frozen=True, slots=True)
class ReleaseCandidateIdentity:
    proof_suite_id: bytes
    artifacts: tuple[ReleaseArtifactPin, ...]
    sources: tuple[ReleaseArtifactPin, ...]
    status: str = UNQUALIFIED_STATUS
    global_proof_suite_id: None = None
    production_usable: bool = False
    activation_allowed: bool = False

    def __post_init__(self) -> None:
        _wide("proof_suite_id", self.proof_suite_id)
        if tuple(pin.role for pin in self.artifacts) != REQUIRED_ARTIFACT_ROLES:
            raise BuiltAuditPendingReleaseError("release_artifact_roles_invalid")
        if not self.sources or tuple(pin.role for pin in self.sources) != tuple(
            sorted(pin.role for pin in self.sources)
        ):
            raise BuiltAuditPendingReleaseError("release_source_set_invalid")
        if len({pin.role for pin in self.sources}) != len(self.sources):
            raise BuiltAuditPendingReleaseError("release_source_set_duplicate")
        if (
            self.status != UNQUALIFIED_STATUS
            or self.global_proof_suite_id is not None
            or self.production_usable
            or self.activation_allowed
        ):
            raise BuiltAuditPendingReleaseError("release_candidate_lifecycle_invalid")

    @property
    def source_set_sha3_512(self) -> bytes:
        return hashlib.sha3_512(
            _frame(SOURCE_SET_DOMAIN, (pin.commitment_bytes() for pin in self.sources))
        ).digest()

    @property
    def release_identity_sha3_512(self) -> bytes:
        parts = [self.proof_suite_id]
        parts.extend(pin.commitment_bytes() for pin in self.artifacts)
        parts.append(self.source_set_sha3_512)
        return hashlib.sha3_512(_frame(RELEASE_IDENTITY_DOMAIN, parts)).digest()

    def as_public_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "globalProofSuiteId": None,
            "candidateProofSuiteId": self.proof_suite_id.hex(),
            "releaseIdentitySha3_512": self.release_identity_sha3_512.hex(),
            "sourceSetSha3_512": self.source_set_sha3_512.hex(),
            "productionUsable": False,
            "activationAllowed": False,
        }


def build_release_candidate_identity(
    *,
    proof_suite_id: bytes,
    proof_parameters: Path,
    air_program: Path,
    prover_executable: Path,
    verifier_executable: Path,
    transcript_contract: Path,
    toolchain: Path,
    source_files: tuple[Path, ...],
    release_contract_schema: Path = RELEASE_SCHEMA,
    public_input_schema: Path = PUBLIC_INPUT_SCHEMA,
    root: Path = ROOT,
) -> ReleaseCandidateIdentity:
    _wide("proof_suite_id", proof_suite_id)
    if not isinstance(root, Path) or not root.is_absolute():
        raise BuiltAuditPendingReleaseError("release_root_invalid")
    schema_pin, schema_bytes = _pin(
        release_contract_schema, "releaseContractSchema", retain=True
    )
    public_pin, public_bytes = _pin(public_input_schema, "publicInputSchema", retain=True)
    contract = _validate_contract_schema(schema_bytes)
    _validate_public_input_schema(public_bytes, contract)
    paths = (
        ("proofParameters", proof_parameters),
        ("airProgram", air_program),
        ("proverExecutable", prover_executable),
        ("verifierExecutable", verifier_executable),
        ("transcriptContract", transcript_contract),
        ("toolchain", toolchain),
    )
    pins = [schema_pin, public_pin]
    for role, path in paths:
        pin, _ = _pin(path, role)
        pins.append(pin)
    source_records: list[tuple[str, Path]] = []
    for path in source_files:
        if not isinstance(path, Path) or not path.is_absolute():
            raise BuiltAuditPendingReleaseError("release_source_path_invalid")
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError as exc:
            raise BuiltAuditPendingReleaseError("release_source_outside_root") from exc
        source_records.append((f"source:{relative}", path))
    if tuple(role for role, _ in source_records) != tuple(sorted(role for role, _ in source_records)):
        raise BuiltAuditPendingReleaseError("release_source_order_invalid")
    source_pins = tuple(_pin(path, role)[0] for role, path in source_records)
    return ReleaseCandidateIdentity(proof_suite_id, tuple(pins), source_pins)


@dataclass(frozen=True, slots=True)
class AggregateReleaseQualification:
    proof_suite_id: bytes
    release_identity_sha3_512: bytes
    status: str = UNQUALIFIED_STATUS
    global_proof_suite_id: None = None
    production_usable: bool = False
    activation_allowed: bool = False

    def __post_init__(self) -> None:
        _wide("aggregate_proof_suite_id", self.proof_suite_id)
        _wide("aggregate_release_identity", self.release_identity_sha3_512)
        if (
            self.status != UNQUALIFIED_STATUS
            or self.global_proof_suite_id is not None
            or self.production_usable
            or self.activation_allowed
        ):
            raise BuiltAuditPendingReleaseError("release_aggregate_lifecycle_invalid")


def qualify_release_candidate(
    candidate: ReleaseCandidateIdentity,
    *,
    lb010_receipt: bytes | None = None,
    expected_receipt_sha3_512: bytes | None = None,
) -> AggregateReleaseQualification:
    if type(candidate) is not ReleaseCandidateIdentity:
        raise TypeError("release_candidate_identity_required")
    if lb010_receipt is None and expected_receipt_sha3_512 is None:
        return AggregateReleaseQualification(
            candidate.proof_suite_id,
            candidate.release_identity_sha3_512,
        )
    if lb010_receipt is None or expected_receipt_sha3_512 is None:
        raise BuiltAuditPendingReleaseError("release_lb010_receipt_pair_required")
    raise BuiltAuditPendingReleaseError(
        "release_lb010_self_attested_receipt_forbidden"
    )


__all__ = (
    "AggregateReleaseQualification",
    "BuiltAuditPendingReleaseError",
    "RELEASE_SCHEMA",
    "ReleaseArtifactPin",
    "ReleaseCandidateIdentity",
    "UNQUALIFIED_STATUS",
    "build_release_candidate_identity",
    "qualify_release_candidate",
)
