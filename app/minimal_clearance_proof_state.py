"""Verifier-to-state composition for the retained minimal-clearance proof.

This is a synthetic, nonactivating seam.  The native verifier owns proof
acceptance and verifier-selected public bytes.  This module independently
decodes those bytes, derives the typed semantic result, and owns a separate
SQLite clearance lane.  It never treats proof acceptance as a directive and
never writes settlement/payment state.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
from typing import Callable, Final, Protocol

from app.direct_state_owned_clearance_v1 import (
    DIRECT_DATABASE_CONTEXT_ID,
    DIRECT_DATABASE_DOMAIN,
    DIRECT_DATABASE_PROGRAM_ID,
    DIRECT_DATABASE_SCHEMA_ID,
    DIRECT_EPOCH,
    DIRECT_GOVERNANCE_AUTHORITY,
    DIRECT_INITIAL_CLEARANCE_ROOT,
    DIRECT_INITIAL_NULLIFIER_ROOT,
    DIRECT_INITIAL_PAYMENT_ROOT,
)
from app.production_boundary import ProductionBoundaryError
from app.transactional_database_boundary import SQLiteSettlementStoreV2


class MinimalClearanceProofStateError(ProductionBoundaryError):
    """Fail-closed errors at the proof-to-state boundary."""


class MinimalClearanceIndeterminateError(MinimalClearanceProofStateError):
    """The database committed but finalization returned an uncertain result."""


_DIGEST_BYTES: Final[int] = 64
_SHA256_BYTES: Final[int] = 32
_PUBLIC_BYTES: Final[int] = 3340
_PROOF_ROLE = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/v1"
_CIRCUIT_ID = bytes.fromhex(
    "1eaaf14f3b23db1ed02f3c378099627767f81142e0114f90448cac7c1cc66be0"
)
_ARTIFACT_MAGIC = b"BLMCV3P1"
_ARTIFACT_HEADER_BYTES: Final[int] = 68
_MAX_ARTIFACT_BYTES: Final[int] = 512 * 1024 * 1024 + _ARTIFACT_HEADER_BYTES + _PUBLIC_BYTES
_STATE_MAGIC = b"BLST"
_STATE_BYTES: Final[int] = 1622
_STATE_HEADER_BYTES: Final[int] = 150
_STATE_DIGEST_COUNT: Final[int] = 23
_ZERO_SUITE = bytes(_DIGEST_BYTES)
_PROOF_OPERATION_DOMAIN = b"BL/MINIMAL-CLEARANCE/PROOF-OPERATION/v1\x00"
_PROOF_REPLAY_DOMAIN = b"BL/MINIMAL-CLEARANCE/PROOF-REPLAY/v1\x00"
_PROOF_CLEARANCE_ROOT_DOMAIN = b"BL/MINIMAL-CLEARANCE/CLEARANCE-ROOT/v1\x00"
_PROOF_STATE_BINDING_DOMAIN = b"BL/MINIMAL-CLEARANCE/STATE-BINDING/v1\x00"
_PROOF_GENESIS_DOMAIN = b"BL/MINIMAL-CLEARANCE/GENESIS/v1\x00"
_PROOF_AUDIT_EVENT_DOMAIN = b"BL/MINIMAL-CLEARANCE/AUDIT-EVENT/v1\x00"
_PROOF_AUDIT_HEAD_DOMAIN = b"BL/MINIMAL-CLEARANCE/AUDIT-HEAD/v1\x00"
_PROOF_RECEIPT_DOMAIN = b"BL/MINIMAL-CLEARANCE/RECEIPT/v1\x00"
_ACCEPTANCE_MAGIC = b"BLPACV1\x00"
_ACCEPTANCE_VERSION: Final[int] = 1
_SCHEMA_VERSION: Final[int] = 1
_KIND = "DIRECT_CLEARANCE"

_STATEMENT_DIGEST_NAMES = (
    "proof_suite",
    "execution_context",
    "source_registry_snapshot",
    "source_profile",
    "governance_snapshot",
    "automatic_control_set",
    "settlement_domain",
    "evaluator_id",
    "schema_id",
    "program_id",
    "policy_id",
    "subject_id",
    "attempt_id",
    "request_id",
    "source_root_id",
    "completeness_id",
    "private_batch_commitment",
    "source_address",
    "source_key",
    "audit_address",
    "exception_id",
    "exception_scope_id",
    "rule_id",
    "decision_id",
    "state_before_id",
    "state_after_id",
)
_STATE_DIGEST_NAMES = (
    "source_root_id",
    "completeness_id",
    "subject_id",
    "attempt_id",
    "request_id",
    "exception_id",
    "exception_scope_id",
    "rule_id",
    "decision_id",
    "before_audit_head",
    "after_audit_head",
    "before_continuity_root",
    "after_continuity_root",
    "read_decision_id",
    "read_address",
    "read_key",
    "read_before",
    "read_after",
    "write_decision_id",
    "write_address",
    "write_key",
    "write_before",
    "write_after",
)


def _sha(domain: bytes, *parts: bytes) -> bytes:
    digest = hashlib.sha3_512()
    digest.update(domain)
    for part in parts:
        if type(part) is not bytes:
            raise MinimalClearanceProofStateError("proof_binding_part_invalid")
        digest.update(part)
    return digest.digest()


def _u64(value: int) -> bytes:
    if type(value) is not int or value < 0 or value >= 2**64:
        raise MinimalClearanceProofStateError("proof_u64_invalid")
    return value.to_bytes(8, "big")


def _u32(value: int) -> bytes:
    if type(value) is not int or value < 0 or value >= 2**32:
        raise MinimalClearanceProofStateError("proof_u32_invalid")
    return value.to_bytes(4, "big")


def _wide(value: bytes, label: str, *, allow_zero: bool = False) -> bytes:
    if type(value) is not bytes or len(value) != _DIGEST_BYTES:
        raise MinimalClearanceProofStateError(f"{label}_width")
    if not allow_zero and not any(value):
        raise MinimalClearanceProofStateError(f"{label}_zero")
    return value


def _take(data: bytes, offset: int, size: int, label: str) -> tuple[bytes, int]:
    end = offset + size
    if size < 0 or end < offset or end > len(data):
        raise MinimalClearanceProofStateError(f"{label}_truncated")
    return data[offset:end], end


def _read_u8(data: bytes, offset: int, label: str) -> tuple[int, int]:
    value, offset = _take(data, offset, 1, label)
    return value[0], offset


def _read_u32(data: bytes, offset: int, label: str) -> tuple[int, int]:
    value, offset = _take(data, offset, 4, label)
    return int.from_bytes(value, "big"), offset


def _read_u64(data: bytes, offset: int, label: str) -> tuple[int, int]:
    value, offset = _take(data, offset, 8, label)
    return int.from_bytes(value, "big"), offset


def _hex(value: bytes) -> str:
    return value.hex()


@dataclass(frozen=True, slots=True)
class MinimalProofStatementV1:
    """Verifier-selected public statement plus the proof-constrained state row."""

    statement_bytes: bytes
    values: tuple[tuple[str, object], ...]
    state_values: tuple[tuple[str, object], ...]
    join_id: bytes
    receipt_id: bytes
    settlement_id: bytes

    def get(self, name: str) -> object:
        for key, value in self.values:
            if key == name:
                return value
        for key, value in self.state_values:
            if key == name:
                return value
        raise KeyError(name)

    def state(self, name: str) -> object:
        for key, value in self.state_values:
            if key == name:
                return value
        raise KeyError(name)

    @property
    def epoch(self) -> int:
        return int(self.get("epoch"))

    @property
    def sequence_before(self) -> int:
        return int(self.get("sequence_before"))

    @property
    def state_before_id(self) -> bytes:
        return bytes(self.get("state_before_id"))

    @property
    def state_after_id(self) -> bytes:
        return bytes(self.get("state_after_id"))

    @property
    def request_id(self) -> bytes:
        return bytes(self.get("request_id"))

    @property
    def attempt_id(self) -> bytes:
        return bytes(self.get("attempt_id"))

    @property
    def decision_id(self) -> bytes:
        return bytes(self.get("decision_id"))

    @property
    def source_root_id(self) -> bytes:
        return bytes(self.get("source_root_id"))

    @property
    def directive(self) -> int:
        return int(self.state("effective_directive"))

    @property
    def policy_result(self) -> int:
        return int(self.state("policy_result"))


@dataclass(frozen=True, slots=True)
class MinimalProofAcceptanceV1:
    """Typed result produced only after independent proof acceptance."""

    statement: MinimalProofStatementV1
    artifact_sha256: bytes
    artifact_digest: bytes
    artifact_bytes: int
    circuit_id: bytes
    proof_accepted: bool = True

    def __post_init__(self) -> None:
        if type(self.statement) is not MinimalProofStatementV1:
            raise MinimalClearanceProofStateError("proof_acceptance_statement_invalid")
        if type(self.artifact_sha256) is not bytes or len(self.artifact_sha256) != _SHA256_BYTES:
            raise MinimalClearanceProofStateError("proof_acceptance_artifact_sha256_invalid")
        _wide(self.artifact_digest, "proof_acceptance_artifact_digest")
        if type(self.artifact_bytes) is not int or not 0 < self.artifact_bytes <= _MAX_ARTIFACT_BYTES:
            raise MinimalClearanceProofStateError("proof_acceptance_artifact_bytes_invalid")
        if self.circuit_id != _CIRCUIT_ID or type(self.proof_accepted) is not bool:
            raise MinimalClearanceProofStateError("proof_acceptance_circuit_or_flag_invalid")
        if not self.proof_accepted:
            raise MinimalClearanceProofStateError("proof_acceptance_required")

    def canonical_bytes(self) -> bytes:
        output = bytearray(_ACCEPTANCE_MAGIC)
        output.extend(_ACCEPTANCE_VERSION.to_bytes(4, "big"))
        output.extend(self.artifact_bytes.to_bytes(8, "big"))
        output.extend(self.artifact_sha256)
        output.extend(self.artifact_digest)
        output.extend(self.circuit_id)
        output.extend(len(self.statement.statement_bytes).to_bytes(4, "big"))
        output.extend(self.statement.statement_bytes)
        return bytes(output)

    @property
    def statement_digest(self) -> bytes:
        return _sha(b"BL/MINIMAL-CLEARANCE/STATEMENT/v1\x00", self.statement.statement_bytes)

    @property
    def bundle_id(self) -> bytes:
        return self.artifact_digest

    @property
    def policy_result(self) -> int:
        return self.statement.policy_result

    @property
    def effective_directive(self) -> int:
        return self.statement.directive


def _expected_state_id(
    execution_context: bytes,
    epoch: int,
    sequence: int,
    audit_head: bytes,
    continuity_root: bytes,
) -> bytes:
    return _sha(
        b"BL/NATIVE-V3/MINIMAL-BEFORE-STATE/v1\x00",
        execution_context,
        _u64(epoch),
        _u64(sequence),
        audit_head,
        continuity_root,
    )


def _parse_statement(statement_bytes: bytes) -> MinimalProofStatementV1:
    if type(statement_bytes) is not bytes or len(statement_bytes) != _PUBLIC_BYTES:
        raise MinimalClearanceProofStateError("proof_statement_length")
    offset = 0
    protocol, offset = _read_u8(statement_bytes, offset, "statement_protocol")
    role, offset = _take(statement_bytes, offset, len(_PROOF_ROLE), "statement_role")
    if protocol != 3 or role != _PROOF_ROLE:
        raise MinimalClearanceProofStateError("proof_statement_role")
    values: dict[str, object] = {"protocol_version": protocol, "proof_role": role}
    for name in _STATEMENT_DIGEST_NAMES:
        raw, offset = _take(statement_bytes, offset, _DIGEST_BYTES, f"statement_{name}")
        raw = bytes(raw)
        _wide(raw, f"statement_{name}", allow_zero=name == "proof_suite")
        values[name] = raw
    epoch, offset = _read_u64(statement_bytes, offset, "statement_epoch")
    sequence_before, offset = _read_u64(statement_bytes, offset, "statement_sequence")
    values["epoch"] = epoch
    values["sequence_before"] = sequence_before
    for name in ("active", "complete", "authoritative_membership", "authoritative_absence"):
        value, offset = _read_u8(statement_bytes, offset, f"statement_{name}")
        if value not in (0, 1):
            raise MinimalClearanceProofStateError(f"statement_{name}_boolean")
        values[name] = value
    state_bytes, offset = _take(statement_bytes, offset, _STATE_BYTES, "statement_state_commitment")
    if offset != len(statement_bytes):
        raise MinimalClearanceProofStateError("statement_trailing")
    state_bytes = bytes(state_bytes)
    values["state_commitment_bytes"] = state_bytes

    so = 0
    magic, so = _take(state_bytes, so, 4, "state_magic")
    version, so = _read_u8(state_bytes, so, "state_version")
    if magic != _STATE_MAGIC or version != 1:
        raise MinimalClearanceProofStateError("state_header")
    state: dict[str, object] = {}
    for name in (
        "policy_result", "effective_directive", "complete", "membership", "absence",
        "active", "exception_present", "exception_authorized", "economic_mutation",
        "clearance_marker_before", "clearance_marker_after",
    ):
        value, so = _read_u8(state_bytes, so, f"state_{name}")
        state[name] = value
    for name in (
        "epoch", "sequence_before", "rule_effective_time", "event_time", "observation_time",
        "decision_time", "read_time", "write_time", "exception_valid_from",
        "exception_valid_until", "sequence_after",
    ):
        value, so = _read_u64(state_bytes, so, f"state_{name}")
        state[name] = value
    for name in (
        "decision_index", "decision_count", "read_access_index", "write_access_index",
        "access_count", "read_decision_index", "write_decision_index",
    ):
        value, so = _read_u32(state_bytes, so, f"state_{name}")
        state[name] = value
    read_mode, so = _read_u8(state_bytes, so, "state_read_mode")
    write_mode, so = _read_u8(state_bytes, so, "state_write_mode")
    state["read_mode"] = read_mode
    state["write_mode"] = write_mode
    for name in ("clearance_count_before", "clearance_count_after"):
        value, so = _read_u64(state_bytes, so, f"state_{name}")
        state[name] = value
    for name in _STATE_DIGEST_NAMES:
        raw, so = _take(state_bytes, so, _DIGEST_BYTES, f"state_{name}")
        raw = bytes(raw)
        _wide(raw, f"state_{name}")
        state[name] = raw
    if so != len(state_bytes) or so != _STATE_BYTES:
        raise MinimalClearanceProofStateError("state_length")

    _validate_statement_and_state(values, state)
    join_id = _sha(
        b"BL/NATIVE-V3/MINIMAL-DECISION-ACCESS-JOIN/v1\x00",
        bytes(values["decision_id"]), bytes(state["read_decision_id"]),
        bytes(state["read_address"]), bytes(state["read_key"]),
        bytes(state["read_before"]), bytes(state["read_after"]),
        bytes(state["write_decision_id"]), bytes(state["write_address"]),
        bytes(state["write_key"]), bytes(state["write_before"]),
        bytes(state["write_after"]), bytes(values["state_before_id"]),
        bytes(values["state_after_id"]),
    )
    receipt_id = _sha(
        b"BL/NATIVE-V3/MINIMAL-RECEIPT-ID/v1\x00",
        bytes(values["automatic_control_set"]), bytes(values["decision_id"]), join_id,
        bytes(values["state_before_id"]), bytes(values["state_after_id"]), state_bytes,
    )
    settlement_id = _sha(
        b"BL/NATIVE-V3/MINIMAL-SETTLEMENT-REFERENCE/v1\x00",
        bytes(values["settlement_domain"]), bytes((int(state["effective_directive"]),)),
        bytes(values["decision_id"]), bytes(values["state_after_id"]),
    )
    return MinimalProofStatementV1(
        statement_bytes=statement_bytes,
        values=tuple(values.items()),
        state_values=tuple(state.items()),
        join_id=join_id,
        receipt_id=receipt_id,
        settlement_id=settlement_id,
    )


def _validate_statement_and_state(values: dict[str, object], state: dict[str, object]) -> None:
    policy = int(state["policy_result"])
    directive = int(state["effective_directive"])
    mapping = {1: 1, 2: 2, 3: 3, 4: 4, 5: 4}
    if directive not in mapping or policy != mapping[directive]:
        raise MinimalClearanceProofStateError("proof_policy_directive")
    for name in (
        "complete", "membership", "absence", "active", "exception_present",
        "exception_authorized", "economic_mutation", "clearance_marker_before",
        "clearance_marker_after",
    ):
        if int(state[name]) not in (0, 1):
            raise MinimalClearanceProofStateError(f"proof_{name}_boolean")
    if int(state["economic_mutation"]) != 0:
        raise MinimalClearanceProofStateError("proof_economic_mutation")
    expected = {
        1: (1, 1, 0, 1, 0, 0),
        2: (1, 0, 1, 0, 0, 0),
        3: (0, 0, 0, 0, 0, 0),
        4: (1, 1, 0, 0, 0, 0),
        5: (1, 1, 0, 0, 1, 1),
    }[directive]
    if tuple(int(state[name]) for name in ("complete", "membership", "absence", "active", "exception_present", "exception_authorized")) != expected:
        raise MinimalClearanceProofStateError("proof_directive_flags")
    if tuple(int(state[name]) for name in ("complete", "membership", "absence", "active")) != tuple(
        int(values[name])
        for name in ("complete", "authoritative_membership", "authoritative_absence", "active")
    ):
        raise MinimalClearanceProofStateError("proof_public_flag_binding")
    if int(state["epoch"]) != int(values["epoch"]) or int(state["sequence_before"]) != int(values["sequence_before"]):
        raise MinimalClearanceProofStateError("proof_state_epoch_sequence")
    if not (
        int(state["rule_effective_time"]) < int(state["event_time"]) < int(state["observation_time"]) < int(state["decision_time"])
    ):
        raise MinimalClearanceProofStateError("proof_chronology")
    if int(state["read_time"]) != int(state["observation_time"]) or int(state["write_time"]) != int(state["decision_time"]):
        raise MinimalClearanceProofStateError("proof_access_time")
    if tuple(int(state[name]) for name in ("decision_index", "decision_count", "read_access_index", "write_access_index", "access_count", "read_decision_index", "write_decision_index", "read_mode", "write_mode")) != (0, 1, 0, 1, 2, 0, 0, 1, 2):
        raise MinimalClearanceProofStateError("proof_access_shape")
    if int(state["sequence_after"]) != int(values["sequence_before"]) + 1:
        raise MinimalClearanceProofStateError("proof_sequence_after")
    clear_transition = directive in (1, 5)
    if int(state["clearance_marker_after"]) != int(bool(int(state["clearance_marker_before"]) or clear_transition)):
        raise MinimalClearanceProofStateError("proof_clearance_marker")
    expected_count = int(state["clearance_count_before"]) + int(clear_transition)
    if int(state["clearance_count_after"]) != expected_count:
        raise MinimalClearanceProofStateError("proof_clearance_count")
    if int(state["exception_present"]) != int(directive == 5) or int(state["exception_authorized"]) != int(directive == 5):
        raise MinimalClearanceProofStateError("proof_exception")
    exception_id = bytes(values["exception_id"])
    if directive != 5:
        if exception_id != b"\xe0" + bytes(63) or int(state["exception_valid_from"]) != 0 or int(state["exception_valid_until"]) != 0:
            raise MinimalClearanceProofStateError("proof_exception_sentinel")
    elif not (
        int(state["exception_valid_from"]) < int(state["exception_valid_until"])
        and int(state["exception_valid_from"]) <= int(state["decision_time"]) <= int(state["exception_valid_until"])
    ):
        raise MinimalClearanceProofStateError("proof_exception_interval")
    for name in _STATEMENT_DIGEST_NAMES[1:]:
        _wide(bytes(values[name]), f"proof_{name}")
    if bytes(values["proof_suite"]) != _ZERO_SUITE:
        raise MinimalClearanceProofStateError("proof_suite_not_null")
    if bytes(state["source_root_id"]) != bytes(values["source_root_id"]):
        raise MinimalClearanceProofStateError("proof_source_root_binding")
    if bytes(state["completeness_id"]) != bytes(values["completeness_id"]):
        raise MinimalClearanceProofStateError("proof_completeness_binding")
    if bytes(state["subject_id"]) != bytes(values["subject_id"]):
        raise MinimalClearanceProofStateError("proof_subject_binding")
    if bytes(state["attempt_id"]) != bytes(values["attempt_id"]):
        raise MinimalClearanceProofStateError("proof_attempt_binding")
    if bytes(state["request_id"]) != bytes(values["request_id"]):
        raise MinimalClearanceProofStateError("proof_request_binding")
    if bytes(state["exception_id"]) != exception_id or bytes(state["rule_id"]) != bytes(values["rule_id"]):
        raise MinimalClearanceProofStateError("proof_decision_context_binding")
    if bytes(state["decision_id"]) != bytes(values["decision_id"]):
        raise MinimalClearanceProofStateError("proof_decision_binding")
    if bytes(state["read_decision_id"]) != bytes(values["decision_id"]) or bytes(state["write_decision_id"]) != bytes(values["decision_id"]):
        raise MinimalClearanceProofStateError("proof_join_decision_binding")
    if bytes(state["read_before"]) != bytes(values["source_root_id"]) or bytes(state["read_after"]) != bytes(values["source_root_id"]):
        raise MinimalClearanceProofStateError("proof_read_value_binding")
    if bytes(state["write_before"]) != bytes(state["before_audit_head"]) or bytes(state["write_after"]) != bytes(state["after_audit_head"]):
        raise MinimalClearanceProofStateError("proof_write_value_binding")
    if bytes(state["write_address"]) != bytes(values["audit_address"]) or bytes(state["write_key"]) != bytes(values["decision_id"]):
        raise MinimalClearanceProofStateError("proof_write_address_binding")
    if bytes(state["read_address"]) != bytes(values["source_address"]) or bytes(state["read_key"]) != bytes(values["source_key"]):
        raise MinimalClearanceProofStateError("proof_read_address_binding")
    before_state = _expected_state_id(
        bytes(values["execution_context"]), int(values["epoch"]), int(values["sequence_before"]),
        bytes(state["before_audit_head"]), bytes(state["before_continuity_root"]),
    )
    if before_state != bytes(values["state_before_id"]):
        raise MinimalClearanceProofStateError("proof_before_state_id")
    expected_request = _sha(
        b"BL/NATIVE-V3/REQUEST-ID/v2\x00", bytes(values["subject_id"]), bytes(values["attempt_id"]),
        _u64(int(values["epoch"])), _u64(int(values["sequence_before"])), bytes(values["state_before_id"]),
    )
    if expected_request != bytes(values["request_id"]):
        raise MinimalClearanceProofStateError("proof_request_id")
    expected_decision = _sha(
        b"BL/NATIVE-V3/MINIMAL-DECISION/v1\x00", bytes(values["request_id"]), bytes(values["source_root_id"]),
        bytes(values["completeness_id"]), bytes((policy, directive)), bytes(values["exception_id"]),
    )
    if expected_decision != bytes(values["decision_id"]):
        raise MinimalClearanceProofStateError("proof_decision_id")
    expected_audit = _sha(
        b"BL/NATIVE-V3/MINIMAL-AUDIT-HEAD/v1\x00", bytes(state["before_audit_head"]),
        bytes(values["decision_id"]), bytes((directive,)),
    )
    expected_root = _sha(
        b"BL/NATIVE-V3/MINIMAL-CONTINUITY-ROOT/v1\x00", bytes(state["before_continuity_root"]),
        bytes(values["source_root_id"]), bytes(values["decision_id"]),
    )
    if expected_audit != bytes(state["after_audit_head"]) or expected_root != bytes(state["after_continuity_root"]):
        raise MinimalClearanceProofStateError("proof_after_continuity")
    expected_state = _sha(
        b"BL/NATIVE-V3/MINIMAL-STATE-ID/v1\x00", b"\x01", bytes(values["state_commitment_bytes"]),
    )
    if expected_state != bytes(values["state_after_id"]):
        raise MinimalClearanceProofStateError("proof_after_state_id")


def parse_acceptance_bytes(encoded: bytes) -> MinimalProofAcceptanceV1:
    if type(encoded) is not bytes or len(encoded) < 8 + 4 + 8 + 32 + 64 + 32 + 4:
        raise MinimalClearanceProofStateError("proof_acceptance_truncated")
    offset = 0
    magic, offset = _take(encoded, offset, len(_ACCEPTANCE_MAGIC), "acceptance_magic")
    if magic != _ACCEPTANCE_MAGIC:
        raise MinimalClearanceProofStateError("proof_acceptance_magic")
    version, offset = _read_u32(encoded, offset, "acceptance_version")
    if version != _ACCEPTANCE_VERSION:
        raise MinimalClearanceProofStateError("proof_acceptance_version")
    artifact_bytes, offset = _read_u64(encoded, offset, "acceptance_artifact_bytes")
    artifact_sha256, offset = _take(encoded, offset, _SHA256_BYTES, "acceptance_artifact_sha256")
    artifact_digest, offset = _take(encoded, offset, _DIGEST_BYTES, "acceptance_artifact_digest")
    circuit_id, offset = _take(encoded, offset, len(_CIRCUIT_ID), "acceptance_circuit_id")
    statement_size, offset = _read_u32(encoded, offset, "acceptance_statement_size")
    if statement_size != _PUBLIC_BYTES:
        raise MinimalClearanceProofStateError("proof_acceptance_statement_size")
    statement_bytes, offset = _take(encoded, offset, statement_size, "acceptance_statement")
    if offset != len(encoded):
        raise MinimalClearanceProofStateError("proof_acceptance_trailing")
    statement = _parse_statement(bytes(statement_bytes))
    return MinimalProofAcceptanceV1(
        statement=statement,
        artifact_sha256=bytes(artifact_sha256),
        artifact_digest=bytes(artifact_digest),
        artifact_bytes=artifact_bytes,
        circuit_id=bytes(circuit_id),
    )


class MinimalClearanceVerifierPort(Protocol):
    def expected_statement(self) -> bytes:
        """Return immutable verifier-owned public statement bytes."""

    def verify(self, artifact_path: Path) -> MinimalProofAcceptanceV1:
        """Independently verify one artifact and return typed accepted fields."""


def _regular_file(path: Path, label: str) -> None:
    if not isinstance(path, Path) or path.is_symlink() or not path.is_file():
        raise MinimalClearanceProofStateError(f"{label}_not_regular_file")
    size = path.stat().st_size
    if size <= 0 or size > _MAX_ARTIFACT_BYTES:
        raise MinimalClearanceProofStateError(f"{label}_size")


def _artifact_public_bytes(raw: bytes) -> tuple[bytes, bytes, bytes]:
    if len(raw) < _ARTIFACT_HEADER_BYTES or raw[:8] != _ARTIFACT_MAGIC:
        raise MinimalClearanceProofStateError("proof_artifact_header")
    if int.from_bytes(raw[8:12], "big") != 1:
        raise MinimalClearanceProofStateError("proof_artifact_version")
    circuit_id = raw[12:44]
    public_size = int.from_bytes(raw[56:60], "big")
    proof_size = int.from_bytes(raw[60:68], "big")
    expected = _ARTIFACT_HEADER_BYTES + public_size + proof_size
    if public_size != _PUBLIC_BYTES or expected != len(raw):
        raise MinimalClearanceProofStateError("proof_artifact_length")
    return circuit_id, raw[_ARTIFACT_HEADER_BYTES : _ARTIFACT_HEADER_BYTES + public_size], raw[_ARTIFACT_HEADER_BYTES + public_size :]


class NativeMinimalClearanceVerifier:
    """Runs the pinned independent verifier and uses its reconstruction output."""

    def __init__(self, executable: Path, *, timeout_seconds: float = 30.0 * 60.0) -> None:
        _regular_file(executable, "verifier_executable")
        if type(timeout_seconds) is not float or not 0 < timeout_seconds <= 30 * 60:
            raise MinimalClearanceProofStateError("verifier_timeout")
        self.executable = executable
        self.timeout_seconds = timeout_seconds

    def _run(self, *args: str) -> subprocess.CompletedProcess[bytes]:
        try:
            result = subprocess.run(
                [str(self.executable), *args],
                cwd=str(self.executable.parent),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
                env={"PATH": os.environ.get("PATH", ""), "BL_NETWORK_DISABLED": "1"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise MinimalClearanceProofStateError("verifier_process_unavailable") from exc
        if len(result.stdout) > 64 * 1024 or len(result.stderr) > 256 * 1024:
            raise MinimalClearanceProofStateError("verifier_output_cap")
        return result

    def expected_statement(self) -> bytes:
        with tempfile.TemporaryDirectory(prefix="blind-ledger-minimal-statement-") as directory:
            path = Path(directory) / "statement.bin"
            result = self._run("--public-statement-file", str(path))
            if result.returncode != 0 or not path.is_file():
                raise MinimalClearanceProofStateError("verifier_statement_reconstruction")
            return path.read_bytes()

    def verify(self, artifact_path: Path) -> MinimalProofAcceptanceV1:
        _regular_file(artifact_path, "proof_artifact")
        raw = artifact_path.read_bytes()
        circuit_id, public_bytes, _ = _artifact_public_bytes(raw)
        if circuit_id != _CIRCUIT_ID:
            raise MinimalClearanceProofStateError("proof_circuit_id")
        result = self._run(str(artifact_path))
        stdout = result.stdout.decode("ascii", "strict")
        if result.returncode != 0 or "MINIMAL_CLEARANCE_VERIFIER_ACCEPT " not in stdout:
            raise MinimalClearanceProofStateError("proof_verifier_rejected")
        expected = self.expected_statement()
        if expected != public_bytes:
            raise MinimalClearanceProofStateError("proof_public_statement_mismatch")
        statement = _parse_statement(expected)
        return MinimalProofAcceptanceV1(
            statement=statement,
            artifact_sha256=hashlib.sha256(raw).digest(),
            artifact_digest=hashlib.sha3_512(raw).digest(),
            artifact_bytes=len(raw),
            circuit_id=circuit_id,
        )


@dataclass(frozen=True, slots=True)
class MinimalClearanceStateSnapshotV1:
    schema_version: int
    epoch: int
    sequence: int
    state_id: bytes
    continuity_root: bytes
    clearance_root: bytes
    clearance_count: int
    replay_root: bytes
    payment_root: bytes
    settled_batch_count: int
    state_binding: bytes
    audit_head: bytes
    last_operation_digest: bytes | None


@dataclass(frozen=True, slots=True)
class MinimalClearanceReceiptV1:
    operation_digest: bytes
    artifact_sha256: bytes
    artifact_digest: bytes
    statement_digest: bytes
    circuit_id: bytes
    bundle_id: bytes
    receipt_id: bytes
    join_id: bytes
    settlement_id: bytes
    request_id: bytes
    attempt_id: bytes
    decision_id: bytes
    sequence_before: int
    sequence_after: int
    state_before_id: bytes
    state_after_id: bytes
    clearance_root_before: bytes
    clearance_root_after: bytes
    clearance_count_before: int
    clearance_count_after: int
    payment_root_before: bytes
    payment_root_after: bytes
    settled_batch_count_before: int
    settled_batch_count_after: int
    state_binding_after: bytes
    audit_head_after: bytes
    policy_result: int
    effective_directive: int
    proof_session_accepted: bool = True
    economic_mutation: bool = False
    proof_suite_id: None = None

    def canonical_bytes(self) -> bytes:
        payload = {
            item.name: (
                getattr(self, item.name).hex()
                if isinstance(getattr(self, item.name), bytes)
                else getattr(self, item.name)
            )
            for item in fields(self)
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")


def _receipt_from_row(row: tuple[object, ...]) -> MinimalClearanceReceiptV1:
    if len(row) != 32:
        raise MinimalClearanceProofStateError("proof_receipt_row_shape")
    values = [value if type(value) is int or type(value) is bool else bytes(value) for value in row]
    return MinimalClearanceReceiptV1(*values)  # type: ignore[arg-type]


def _receipt_values(receipt: MinimalClearanceReceiptV1) -> tuple[object, ...]:
    return (
        receipt.operation_digest, receipt.artifact_sha256, receipt.artifact_digest,
        receipt.statement_digest, receipt.circuit_id, receipt.bundle_id, receipt.receipt_id,
        receipt.join_id, receipt.settlement_id, receipt.request_id, receipt.attempt_id,
        receipt.decision_id, receipt.sequence_before, receipt.sequence_after,
        receipt.state_before_id, receipt.state_after_id, receipt.clearance_root_before,
        receipt.clearance_root_after, receipt.clearance_count_before, receipt.clearance_count_after,
        receipt.payment_root_before, receipt.payment_root_after,
        receipt.settled_batch_count_before, receipt.settled_batch_count_after,
        receipt.state_binding_after, receipt.audit_head_after, receipt.policy_result,
        receipt.effective_directive, int(receipt.proof_session_accepted), int(receipt.economic_mutation),
        1 if receipt.proof_suite_id is None else 0, receipt.canonical_bytes(),
    )


class MinimalClearanceStateStoreV1:
    """One proof-bound, SQLite-atomic, non-settlement clearance lane."""

    def __init__(
        self,
        *,
        path: Path,
        verifier: MinimalClearanceVerifierPort,
        before_fault: Callable[[str], None] | None = None,
        after_commit_fault: Callable[[str], None] | None = None,
    ) -> None:
        if not isinstance(path, Path) or path.exists() and path.is_symlink():
            raise MinimalClearanceProofStateError("proof_database_path")
        if not path.parent.is_dir():
            raise MinimalClearanceProofStateError("proof_database_parent")
        if not callable(getattr(verifier, "expected_statement", None)) or not callable(getattr(verifier, "verify", None)):
            raise MinimalClearanceProofStateError("proof_verifier_port")
        self.path = path
        self.verifier = verifier
        self._before_fault = before_fault
        self._after_commit_fault = after_commit_fault
        self._database = SQLiteSettlementStoreV2(
            path=path,
            settlement_domain=DIRECT_DATABASE_DOMAIN,
            governance_authority=DIRECT_GOVERNANCE_AUTHORITY,
            initial_strong_nullifier_root=DIRECT_INITIAL_NULLIFIER_ROOT,
            initial_strong_payment_state_root=DIRECT_INITIAL_PAYMENT_ROOT,
            initial_direct_clearance_root=DIRECT_INITIAL_CLEARANCE_ROOT,
            epoch=DIRECT_EPOCH,
            profile_id=DIRECT_DATABASE_CONTEXT_ID,
            suite_id=DIRECT_DATABASE_SCHEMA_ID,
            schema_id=DIRECT_DATABASE_SCHEMA_ID,
            verifier_artifact_identity=DIRECT_DATABASE_PROGRAM_ID,
        )
        self._initialize_proof_tables()

    def _connect(self):
        return self._database._connect()

    def _initialize_proof_tables(self) -> None:
        expected = self.verifier.expected_statement()
        expected_statement = _parse_statement(expected)
        with closing(self._connect()) as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS minimal_proof_clearance_state (
                    id INTEGER PRIMARY KEY CHECK (id=1), schema_version INTEGER NOT NULL CHECK(schema_version=1),
                    expected_statement BLOB NOT NULL, circuit_id BLOB NOT NULL CHECK(length(circuit_id)=32),
                    state_id BLOB NOT NULL CHECK(length(state_id)=64), epoch INTEGER NOT NULL CHECK(epoch>0),
                    sequence INTEGER NOT NULL CHECK(sequence>=0), continuity_root BLOB NOT NULL CHECK(length(continuity_root)=64),
                    clearance_root BLOB NOT NULL CHECK(length(clearance_root)=64), clearance_count INTEGER NOT NULL CHECK(clearance_count>=0),
                    replay_root BLOB NOT NULL CHECK(length(replay_root)=64), payment_root BLOB NOT NULL CHECK(length(payment_root)=64),
                    settled_batch_count INTEGER NOT NULL CHECK(settled_batch_count>=0), state_binding BLOB NOT NULL CHECK(length(state_binding)=64),
                    audit_head BLOB NOT NULL CHECK(length(audit_head)=64), last_operation_digest BLOB CHECK(last_operation_digest IS NULL OR length(last_operation_digest)=64)
                );
                CREATE TABLE IF NOT EXISTS minimal_proof_clearance_requests (
                    operation_digest BLOB PRIMARY KEY CHECK(length(operation_digest)=64), acceptance_bytes BLOB NOT NULL,
                    receipt_bytes BLOB NOT NULL, artifact_sha256 BLOB NOT NULL CHECK(length(artifact_sha256)=32),
                    artifact_digest BLOB NOT NULL UNIQUE CHECK(length(artifact_digest)=64), statement_digest BLOB NOT NULL CHECK(length(statement_digest)=64),
                    circuit_id BLOB NOT NULL CHECK(length(circuit_id)=32), receipt_id BLOB NOT NULL UNIQUE CHECK(length(receipt_id)=64),
                    join_id BLOB NOT NULL CHECK(length(join_id)=64), request_id BLOB NOT NULL CHECK(length(request_id)=64),
                    attempt_id BLOB NOT NULL CHECK(length(attempt_id)=64), decision_id BLOB NOT NULL CHECK(length(decision_id)=64),
                    sequence_before INTEGER NOT NULL, sequence_after INTEGER NOT NULL, state_before_id BLOB NOT NULL CHECK(length(state_before_id)=64),
                    state_after_id BLOB NOT NULL CHECK(length(state_after_id)=64), continuity_root_before BLOB NOT NULL CHECK(length(continuity_root_before)=64),
                    continuity_root_after BLOB NOT NULL CHECK(length(continuity_root_after)=64), replay_root_before BLOB NOT NULL CHECK(length(replay_root_before)=64),
                    replay_root_after BLOB NOT NULL CHECK(length(replay_root_after)=64), clearance_root_before BLOB NOT NULL CHECK(length(clearance_root_before)=64),
                    clearance_root_after BLOB NOT NULL CHECK(length(clearance_root_after)=64), clearance_count_before INTEGER NOT NULL,
                    clearance_count_after INTEGER NOT NULL, payment_root_before BLOB NOT NULL CHECK(length(payment_root_before)=64),
                    payment_root_after BLOB NOT NULL CHECK(length(payment_root_after)=64), settled_batch_count_before INTEGER NOT NULL,
                    settled_batch_count_after INTEGER NOT NULL, state_binding_before BLOB NOT NULL CHECK(length(state_binding_before)=64),
                    state_binding_after BLOB NOT NULL CHECK(length(state_binding_after)=64), audit_head_before BLOB NOT NULL CHECK(length(audit_head_before)=64),
                    audit_head_after BLOB NOT NULL CHECK(length(audit_head_after)=64), policy_result INTEGER NOT NULL, effective_directive INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS minimal_proof_clearance_audit (
                    sequence INTEGER PRIMARY KEY, previous_head BLOB NOT NULL CHECK(length(previous_head)=64),
                    event_commitment BLOB NOT NULL UNIQUE CHECK(length(event_commitment)=64), current_head BLOB NOT NULL CHECK(length(current_head)=64), payload BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS minimal_proof_clearance_transitions (
                    sequence_after INTEGER PRIMARY KEY, transition_kind TEXT NOT NULL CHECK(transition_kind='DIRECT_CLEARANCE'),
                    operation_digest BLOB NOT NULL UNIQUE CHECK(length(operation_digest)=64), state_binding_before BLOB NOT NULL CHECK(length(state_binding_before)=64),
                    state_binding_after BLOB NOT NULL CHECK(length(state_binding_after)=64), payment_root_before BLOB NOT NULL CHECK(length(payment_root_before)=64),
                    payment_root_after BLOB NOT NULL CHECK(length(payment_root_after)=64), settled_batch_count_before INTEGER NOT NULL, settled_batch_count_after INTEGER NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS minimal_proof_requests_no_update BEFORE UPDATE ON minimal_proof_clearance_requests BEGIN SELECT RAISE(ABORT,'minimal_proof_requests_append_only'); END;
                CREATE TRIGGER IF NOT EXISTS minimal_proof_requests_no_delete BEFORE DELETE ON minimal_proof_clearance_requests BEGIN SELECT RAISE(ABORT,'minimal_proof_requests_append_only'); END;
                CREATE TRIGGER IF NOT EXISTS minimal_proof_audit_no_update BEFORE UPDATE ON minimal_proof_clearance_audit BEGIN SELECT RAISE(ABORT,'minimal_proof_audit_append_only'); END;
                CREATE TRIGGER IF NOT EXISTS minimal_proof_audit_no_delete BEFORE DELETE ON minimal_proof_clearance_audit BEGIN SELECT RAISE(ABORT,'minimal_proof_audit_append_only'); END;
                CREATE TRIGGER IF NOT EXISTS minimal_proof_transition_no_update BEFORE UPDATE ON minimal_proof_clearance_transitions BEGIN SELECT RAISE(ABORT,'minimal_proof_transition_append_only'); END;
                CREATE TRIGGER IF NOT EXISTS minimal_proof_transition_no_delete BEFORE DELETE ON minimal_proof_clearance_transitions BEGIN SELECT RAISE(ABORT,'minimal_proof_transition_append_only'); END;
                """
            )
            row = connection.execute("SELECT * FROM minimal_proof_clearance_state WHERE id=1").fetchone()
            if row is None:
                clearance_root = _sha(_PROOF_GENESIS_DOMAIN, expected_statement.state_before_id, DIRECT_INITIAL_CLEARANCE_ROOT)
                replay_root = _sha(_PROOF_GENESIS_DOMAIN, expected_statement.attempt_id, expected_statement.request_id)
                binding = _sha(
                    _PROOF_STATE_BINDING_DOMAIN, expected, expected_statement.state_before_id,
                    _u64(expected_statement.epoch), _u64(expected_statement.sequence_before),
                    expected_statement.continuity_root if "continuity_root" in dict(expected_statement.state_values) else bytes(expected_statement.state("before_continuity_root")),
                    clearance_root, replay_root, DIRECT_INITIAL_PAYMENT_ROOT, _u64(0),
                )
                connection.execute(
                    "INSERT INTO minimal_proof_clearance_state VALUES (1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (1, expected, _CIRCUIT_ID, expected_statement.state_before_id, expected_statement.epoch,
                     expected_statement.sequence_before, bytes(expected_statement.state("before_continuity_root")),
                     clearance_root, int(expected_statement.state("clearance_count_before")), replay_root,
                     DIRECT_INITIAL_PAYMENT_ROOT, 0, binding, bytes(expected_statement.state("before_audit_head")), None),
                )
            else:
                if bytes(row[2]) != expected or bytes(row[3]) != _CIRCUIT_ID:
                    raise MinimalClearanceProofStateError("proof_verifier_context_changed")
        self.verify_integrity()

    def _state(self, connection) -> tuple[object, ...]:
        row = connection.execute("SELECT * FROM minimal_proof_clearance_state WHERE id=1").fetchone()
        if row is None or len(row) != 16:
            raise MinimalClearanceProofStateError("proof_state_missing")
        return tuple(value if type(value) is int or value is None else bytes(value) for value in row)

    def snapshot(self) -> MinimalClearanceStateSnapshotV1:
        with closing(self._connect()) as connection:
            row = self._state(connection)
        return MinimalClearanceStateSnapshotV1(
            schema_version=row[1], epoch=row[5], sequence=row[6], state_id=row[4], continuity_root=row[7],
            clearance_root=row[8], clearance_count=row[9], replay_root=row[10], payment_root=row[11],
            settled_batch_count=row[12], state_binding=row[13], audit_head=row[14], last_operation_digest=row[15],
        )  # type: ignore[arg-type]

    def _receipt_from_request(self, connection, operation_digest: bytes) -> MinimalClearanceReceiptV1:
        row = connection.execute(
            "SELECT operation_digest, acceptance_bytes, receipt_bytes, artifact_sha256, artifact_digest, statement_digest, circuit_id, "
            "receipt_id, join_id, request_id, attempt_id, decision_id, sequence_before, sequence_after, state_before_id, state_after_id, "
            "clearance_root_before, clearance_root_after, clearance_count_before, clearance_count_after, payment_root_before, payment_root_after, "
            "settled_batch_count_before, settled_batch_count_after, state_binding_after, audit_head_after, policy_result, effective_directive "
            "FROM minimal_proof_clearance_requests WHERE operation_digest=?",
            (operation_digest,),
        ).fetchone()
        if row is None:
            raise MinimalClearanceProofStateError("proof_receipt_missing")
        acceptance = parse_acceptance_bytes(bytes(row[1]))
        receipt = MinimalClearanceReceiptV1(
            operation_digest=bytes(row[0]), artifact_sha256=bytes(row[3]), artifact_digest=bytes(row[4]),
            statement_digest=bytes(row[5]), circuit_id=bytes(row[6]), bundle_id=bytes(row[4]),
            receipt_id=bytes(row[7]), join_id=bytes(row[8]), settlement_id=acceptance.statement.settlement_id,
            request_id=bytes(row[9]), attempt_id=bytes(row[10]), decision_id=bytes(row[11]),
            sequence_before=int(row[12]), sequence_after=int(row[13]), state_before_id=bytes(row[14]),
            state_after_id=bytes(row[15]), clearance_root_before=bytes(row[16]), clearance_root_after=bytes(row[17]),
            clearance_count_before=int(row[18]), clearance_count_after=int(row[19]), payment_root_before=bytes(row[20]),
            payment_root_after=bytes(row[21]), settled_batch_count_before=int(row[22]), settled_batch_count_after=int(row[23]),
            state_binding_after=bytes(row[24]), audit_head_after=bytes(row[25]), policy_result=int(row[26]),
            effective_directive=int(row[27]),
        )
        if bytes(row[2]) != receipt.canonical_bytes():
            raise MinimalClearanceProofStateError("proof_receipt_bytes_mismatch")
        return receipt

    def submit(self, artifact_path: Path) -> MinimalClearanceReceiptV1:
        acceptance = self.verifier.verify(artifact_path)
        if type(acceptance) is not MinimalProofAcceptanceV1:
            raise MinimalClearanceProofStateError("proof_verifier_result")
        return self.apply_acceptance(acceptance)

    def apply_acceptance(self, acceptance: MinimalProofAcceptanceV1) -> MinimalClearanceReceiptV1:
        encoded = acceptance.canonical_bytes()
        reparsed = parse_acceptance_bytes(encoded)
        if reparsed != acceptance:
            raise MinimalClearanceProofStateError("proof_acceptance_roundtrip")
        acceptance = reparsed
        if self._before_fault is not None:
            self._before_fault("before_transaction")
        with closing(self._connect()) as connection:
            began = False
            try:
                connection.execute("BEGIN IMMEDIATE")
                began = True
                state = self._state(connection)
                transaction_acceptance = parse_acceptance_bytes(encoded)
                if transaction_acceptance != acceptance:
                    raise MinimalClearanceProofStateError("proof_transaction_acceptance_roundtrip")
                acceptance = transaction_acceptance
                expected_statement = bytes(state[2])
                if acceptance.statement.statement_bytes != expected_statement:
                    raise MinimalClearanceProofStateError("proof_verifier_context_mismatch")
                if bytes(state[11]) != DIRECT_INITIAL_PAYMENT_ROOT or int(state[12]) != 0:
                    raise MinimalClearanceProofStateError("proof_payment_state_changed")
                operation_digest = _sha(
                    _PROOF_OPERATION_DOMAIN, encoded, bytes(state[13]), bytes(state[14]), bytes(state[11]),
                )
                existing = connection.execute(
                    "SELECT operation_digest, acceptance_bytes FROM minimal_proof_clearance_requests WHERE operation_digest=? OR artifact_digest=? OR request_id=? OR attempt_id=? OR receipt_id=?",
                    (sqlite3.Binary(operation_digest), sqlite3.Binary(acceptance.artifact_digest), sqlite3.Binary(acceptance.statement.request_id), sqlite3.Binary(acceptance.statement.attempt_id), sqlite3.Binary(acceptance.statement.receipt_id)),
                ).fetchall()
                if existing:
                    if len(existing) != 1 or bytes(existing[0][1]) != encoded:
                        raise MinimalClearanceProofStateError("proof_conflicting_retry")
                    receipt = self._receipt_from_request(connection, bytes(existing[0][0]))
                    connection.execute("COMMIT")
                    began = False
                    return receipt
                if (
                    bytes(state[7]) != bytes(acceptance.statement.state("before_continuity_root"))
                    or bytes(state[14]) != bytes(acceptance.statement.state("before_audit_head"))
                    or int(state[9]) != int(acceptance.statement.state("clearance_count_before"))
                ):
                    raise MinimalClearanceProofStateError("proof_state_binding_mismatch")
                if state[4] != acceptance.statement.state_before_id or state[5] != acceptance.statement.epoch or state[6] != acceptance.statement.sequence_before:
                    raise MinimalClearanceProofStateError("proof_stale_state")
                statement = acceptance.statement
                expected_join = _sha(
                    b"BL/NATIVE-V3/MINIMAL-DECISION-ACCESS-JOIN/v1\x00",
                    statement.decision_id, bytes(statement.state("read_decision_id")),
                    bytes(statement.state("read_address")), bytes(statement.state("read_key")),
                    bytes(statement.state("read_before")), bytes(statement.state("read_after")),
                    bytes(statement.state("write_decision_id")), bytes(statement.state("write_address")),
                    bytes(statement.state("write_key")), bytes(statement.state("write_before")),
                    bytes(statement.state("write_after")), statement.state_before_id,
                    statement.state_after_id,
                )
                expected_receipt = _sha(
                    b"BL/NATIVE-V3/MINIMAL-RECEIPT-ID/v1\x00",
                    bytes(statement.get("automatic_control_set")), statement.decision_id,
                    expected_join, statement.state_before_id, statement.state_after_id,
                    bytes(statement.get("state_commitment_bytes")),
                )
                expected_settlement = _sha(
                    b"BL/NATIVE-V3/MINIMAL-SETTLEMENT-REFERENCE/v1\x00",
                    bytes(statement.get("settlement_domain")),
                    bytes((statement.directive,)), statement.decision_id, statement.state_after_id,
                )
                if (
                    expected_join != statement.join_id
                    or expected_receipt != statement.receipt_id
                    or expected_settlement != statement.settlement_id
                ):
                    raise MinimalClearanceProofStateError("proof_statement_derivation")
                replay_after = _sha(_PROOF_REPLAY_DOMAIN, bytes(state[10]), acceptance.statement.attempt_id, acceptance.statement.request_id, acceptance.statement.receipt_id)
                advanced = acceptance.statement.directive in (1, 5)
                clearance_after = (
                    _sha(_PROOF_CLEARANCE_ROOT_DOMAIN, bytes(state[8]), acceptance.statement.state_after_id, acceptance.statement.decision_id, bytes((acceptance.statement.directive,)))
                    if advanced else bytes(state[8])
                )
                count_after = int(state[9]) + int(advanced)
                sequence_after = int(state[6]) + 1
                state_binding_after = _sha(
                    _PROOF_STATE_BINDING_DOMAIN, bytes(state[13]), operation_digest, acceptance.statement.state_after_id,
                    replay_after, clearance_after, _u64(count_after), bytes(state[11]), _u64(int(state[12])),
                    _u64(int(state[5])), _u64(sequence_after),
                )
                event_payload = json.dumps({
                    "event_kind": "MINIMAL_PROOF_DIRECT_CLEARANCE_V1", "version": 1,
                    "sequence_before": int(state[6]), "sequence_after": sequence_after,
                    "operation_digest": operation_digest.hex(), "artifact_digest": acceptance.artifact_digest.hex(),
                    "receipt_id": acceptance.statement.receipt_id.hex(), "request_id": acceptance.statement.request_id.hex(),
                    "attempt_id": acceptance.statement.attempt_id.hex(), "decision_id": acceptance.statement.decision_id.hex(),
                    "join_id": acceptance.statement.join_id.hex(), "policy_result": acceptance.policy_result,
                    "effective_directive": acceptance.statement.directive, "clearance_advanced": int(advanced),
                    "payment_root_before": bytes(state[11]).hex(), "payment_root_after": bytes(state[11]).hex(),
                    "settled_batch_count_before": int(state[12]), "settled_batch_count_after": int(state[12]),
                    "state_binding_before": bytes(state[13]).hex(), "state_binding_after": state_binding_after.hex(),
                }, sort_keys=True, separators=(",", ":")).encode("ascii")
                event_commitment = _sha(_PROOF_AUDIT_EVENT_DOMAIN, bytes(state[14]), event_payload)
                audit_after = _sha(_PROOF_AUDIT_HEAD_DOMAIN, bytes(state[14]), event_commitment)
                receipt = MinimalClearanceReceiptV1(
                    operation_digest=operation_digest, artifact_sha256=acceptance.artifact_sha256,
                    artifact_digest=acceptance.artifact_digest, statement_digest=acceptance.statement_digest,
                    circuit_id=acceptance.circuit_id, bundle_id=acceptance.bundle_id,
                    receipt_id=acceptance.statement.receipt_id, join_id=acceptance.statement.join_id,
                    settlement_id=acceptance.statement.settlement_id, request_id=acceptance.statement.request_id,
                    attempt_id=acceptance.statement.attempt_id, decision_id=acceptance.statement.decision_id,
                    sequence_before=int(state[6]), sequence_after=sequence_after,
                    state_before_id=acceptance.statement.state_before_id, state_after_id=acceptance.statement.state_after_id,
                    clearance_root_before=bytes(state[8]), clearance_root_after=clearance_after,
                    clearance_count_before=int(state[9]), clearance_count_after=count_after,
                    payment_root_before=bytes(state[11]), payment_root_after=bytes(state[11]),
                    settled_batch_count_before=int(state[12]), settled_batch_count_after=int(state[12]),
                    state_binding_after=state_binding_after, audit_head_after=audit_after,
                    policy_result=acceptance.policy_result, effective_directive=acceptance.statement.directive,
                )
                request_values = (
                    operation_digest, encoded, receipt.canonical_bytes(), acceptance.artifact_sha256,
                    acceptance.artifact_digest, acceptance.statement_digest, acceptance.circuit_id,
                    acceptance.statement.receipt_id, acceptance.statement.join_id,
                    acceptance.statement.request_id, acceptance.statement.attempt_id,
                    acceptance.statement.decision_id, int(state[6]), sequence_after,
                    acceptance.statement.state_before_id, acceptance.statement.state_after_id,
                    bytes(state[7]), bytes(acceptance.statement.state("after_continuity_root")),
                    bytes(state[10]), replay_after, bytes(state[8]), clearance_after,
                    int(state[9]), count_after, bytes(state[11]), bytes(state[11]),
                    int(state[12]), int(state[12]), bytes(state[13]), state_binding_after,
                    bytes(state[14]), audit_after, acceptance.policy_result,
                    acceptance.statement.directive,
                )
                connection.execute(
                    "INSERT INTO minimal_proof_clearance_requests VALUES ("
                    + ",".join("?" for _ in request_values) + ")",
                    request_values,
                )
                if self._before_fault is not None:
                    self._before_fault("after_replay_reservation")
                connection.execute(
                    "UPDATE minimal_proof_clearance_state SET sequence=?, state_id=?, continuity_root=?, clearance_root=?, clearance_count=?, replay_root=?, state_binding=?, audit_head=?, last_operation_digest=? WHERE id=1",
                    (sequence_after, acceptance.statement.state_after_id, bytes(acceptance.statement.state("after_continuity_root")), clearance_after, count_after, replay_after, state_binding_after, audit_after, operation_digest),
                )
                if self._before_fault is not None:
                    self._before_fault("after_state_write")
                connection.execute(
                    "INSERT INTO minimal_proof_clearance_audit VALUES (?,?,?,?,?)",
                    (sequence_after, bytes(state[14]), event_commitment, audit_after, event_payload),
                )
                if self._before_fault is not None:
                    self._before_fault("after_audit_write")
                transition_values = (
                    sequence_after, _KIND, operation_digest, bytes(state[13]),
                    state_binding_after, bytes(state[11]), bytes(state[11]),
                    int(state[12]), int(state[12]),
                )
                connection.execute(
                    "INSERT INTO minimal_proof_clearance_transitions VALUES ("
                    + ",".join("?" for _ in transition_values) + ")",
                    transition_values,
                )
                if self._before_fault is not None:
                    self._before_fault("before_receipt_commit")
                connection.execute("COMMIT")
                began = False
            except Exception:
                if began and connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        if self._after_commit_fault is not None:
            try:
                self._after_commit_fault("after_commit")
            except Exception as exc:
                raise MinimalClearanceIndeterminateError("proof_commit_indeterminate") from exc
        return receipt

    def verify_integrity(self) -> None:
        self._database.verify_integrity()
        with closing(self._connect()) as connection:
            state = self._state(connection)
            expected_bytes = self.verifier.expected_statement()
            expected_statement = _parse_statement(bytes(state[2]))
            if bytes(state[2]) != expected_bytes:
                raise MinimalClearanceProofStateError("proof_verifier_context_changed")
            if bytes(state[3]) != _CIRCUIT_ID or int(state[1]) != _SCHEMA_VERSION:
                raise MinimalClearanceProofStateError("proof_state_schema")
            if (
                int(state[5]) != expected_statement.epoch
                or bytes(state[11]) != DIRECT_INITIAL_PAYMENT_ROOT
                or int(state[12]) != 0
            ):
                raise MinimalClearanceProofStateError("proof_payment_or_epoch_integrity")
            rows = connection.execute("SELECT * FROM minimal_proof_clearance_requests ORDER BY sequence_after").fetchall()
            audits = connection.execute("SELECT * FROM minimal_proof_clearance_audit ORDER BY sequence").fetchall()
            transitions = connection.execute("SELECT * FROM minimal_proof_clearance_transitions ORDER BY sequence_after").fetchall()
            if len(rows) != len(audits) or len(rows) != len(transitions):
                raise MinimalClearanceProofStateError("proof_ledger_count")
            genesis_clearance = _sha(_PROOF_GENESIS_DOMAIN, expected_statement.state_before_id, DIRECT_INITIAL_CLEARANCE_ROOT)
            genesis_replay = _sha(_PROOF_GENESIS_DOMAIN, expected_statement.attempt_id, expected_statement.request_id)
            genesis_binding = _sha(
                _PROOF_STATE_BINDING_DOMAIN, expected_bytes, expected_statement.state_before_id,
                _u64(expected_statement.epoch), _u64(expected_statement.sequence_before),
                bytes(expected_statement.state("before_continuity_root")), genesis_clearance,
                genesis_replay, DIRECT_INITIAL_PAYMENT_ROOT, _u64(0),
            )
            if not rows:
                if (
                    bytes(state[4]) != expected_statement.state_before_id
                    or int(state[6]) != expected_statement.sequence_before
                    or bytes(state[7]) != bytes(expected_statement.state("before_continuity_root"))
                    or bytes(state[8]) != genesis_clearance
                    or int(state[9]) != int(expected_statement.state("clearance_count_before"))
                    or bytes(state[10]) != genesis_replay
                    or bytes(state[13]) != genesis_binding
                    or bytes(state[14]) != bytes(expected_statement.state("before_audit_head"))
                    or state[15] is not None
                ):
                    raise MinimalClearanceProofStateError("proof_genesis_state")
                return
            previous_state_id = expected_statement.state_before_id
            previous_root = bytes(expected_statement.state("before_continuity_root"))
            previous_clearance = genesis_clearance
            previous_count = int(expected_statement.state("clearance_count_before"))
            previous_replay = genesis_replay
            previous_binding = genesis_binding
            previous_head = bytes(expected_statement.state("before_audit_head"))
            expected_sequence = expected_statement.sequence_before + 1
            for row, audit, transition in zip(rows, audits, transitions):
                acceptance = parse_acceptance_bytes(bytes(row[1]))
                if acceptance.canonical_bytes() != bytes(row[1]):
                    raise MinimalClearanceProofStateError("proof_acceptance_bytes_mismatch")
                operation_digest = _sha(
                    _PROOF_OPERATION_DOMAIN, bytes(row[1]), previous_binding, previous_head, DIRECT_INITIAL_PAYMENT_ROOT,
                )
                if (
                    bytes(row[0]) != operation_digest
                    or bytes(row[3]) != acceptance.artifact_sha256
                    or acceptance.artifact_digest != bytes(row[4])
                    or acceptance.statement_digest != bytes(row[5])
                    or bytes(row[6]) != _CIRCUIT_ID
                    or acceptance.statement.receipt_id != bytes(row[7])
                    or acceptance.statement.join_id != bytes(row[8])
                    or acceptance.statement.request_id != bytes(row[9])
                    or acceptance.statement.attempt_id != bytes(row[10])
                    or acceptance.statement.decision_id != bytes(row[11])
                ):
                    raise MinimalClearanceProofStateError("proof_request_binding")
                if (
                    int(row[13]) != expected_sequence
                    or int(row[12]) != expected_sequence - 1
                    or bytes(row[14]) != previous_state_id
                    or bytes(row[15]) != acceptance.statement.state_after_id
                    or bytes(row[16]) != previous_root
                    or bytes(row[17]) != bytes(acceptance.statement.state("after_continuity_root"))
                    or bytes(row[18]) != previous_replay
                ):
                    raise MinimalClearanceProofStateError("proof_request_sequence")
                replay_after = _sha(
                    _PROOF_REPLAY_DOMAIN, previous_replay, acceptance.statement.attempt_id,
                    acceptance.statement.request_id, acceptance.statement.receipt_id,
                )
                advanced = acceptance.statement.directive in (1, 5)
                clearance_after = (
                    _sha(
                        _PROOF_CLEARANCE_ROOT_DOMAIN, previous_clearance,
                        acceptance.statement.state_after_id, acceptance.statement.decision_id,
                        bytes((acceptance.statement.directive,)),
                    )
                    if advanced else previous_clearance
                )
                count_after = previous_count + int(advanced)
                state_binding_after = _sha(
                    _PROOF_STATE_BINDING_DOMAIN, previous_binding, operation_digest,
                    acceptance.statement.state_after_id, replay_after, clearance_after,
                    _u64(count_after), DIRECT_INITIAL_PAYMENT_ROOT, _u64(0),
                    _u64(expected_statement.epoch), _u64(expected_sequence),
                )
                if (
                    bytes(row[19]) != replay_after
                    or bytes(row[20]) != previous_clearance
                    or bytes(row[21]) != clearance_after
                    or int(row[22]) != previous_count
                    or int(row[23]) != count_after
                    or bytes(row[24]) != DIRECT_INITIAL_PAYMENT_ROOT
                    or bytes(row[25]) != DIRECT_INITIAL_PAYMENT_ROOT
                    or int(row[26]) != 0
                    or int(row[27]) != 0
                    or bytes(row[28]) != previous_binding
                    or bytes(row[29]) != state_binding_after
                    or bytes(row[30]) != previous_head
                    or int(row[32]) != acceptance.policy_result
                    or int(row[33]) != acceptance.statement.directive
                ):
                    raise MinimalClearanceProofStateError("proof_state_chain")
                if (
                    bytes(audit[1]) != previous_head
                    or int(audit[0]) != expected_sequence
                    or bytes(audit[2]) != _sha(_PROOF_AUDIT_EVENT_DOMAIN, previous_head, bytes(audit[4]))
                    or bytes(audit[3]) != _sha(_PROOF_AUDIT_HEAD_DOMAIN, previous_head, bytes(audit[2]))
                    or bytes(audit[3]) != bytes(row[31])
                ):
                    raise MinimalClearanceProofStateError("proof_audit_chain")
                if (
                    transition[1] != _KIND
                    or int(transition[0]) != expected_sequence
                    or bytes(transition[2]) != operation_digest
                    or bytes(transition[3]) != previous_binding
                    or bytes(transition[4]) != state_binding_after
                    or bytes(transition[5]) != DIRECT_INITIAL_PAYMENT_ROOT
                    or bytes(transition[6]) != DIRECT_INITIAL_PAYMENT_ROOT
                    or int(transition[7]) != 0
                    or int(transition[8]) != 0
                ):
                    raise MinimalClearanceProofStateError("proof_transition_kind")
                expected_receipt = MinimalClearanceReceiptV1(
                    operation_digest=operation_digest, artifact_sha256=acceptance.artifact_sha256,
                    artifact_digest=acceptance.artifact_digest, statement_digest=acceptance.statement_digest,
                    circuit_id=_CIRCUIT_ID, bundle_id=acceptance.bundle_id,
                    receipt_id=acceptance.statement.receipt_id, join_id=acceptance.statement.join_id,
                    settlement_id=acceptance.statement.settlement_id, request_id=acceptance.statement.request_id,
                    attempt_id=acceptance.statement.attempt_id, decision_id=acceptance.statement.decision_id,
                    sequence_before=int(row[12]), sequence_after=int(row[13]),
                    state_before_id=bytes(row[14]), state_after_id=bytes(row[15]),
                    clearance_root_before=previous_clearance, clearance_root_after=clearance_after,
                    clearance_count_before=previous_count, clearance_count_after=count_after,
                    payment_root_before=DIRECT_INITIAL_PAYMENT_ROOT, payment_root_after=DIRECT_INITIAL_PAYMENT_ROOT,
                    settled_batch_count_before=0, settled_batch_count_after=0,
                    state_binding_after=state_binding_after, audit_head_after=bytes(row[31]),
                    policy_result=acceptance.policy_result, effective_directive=acceptance.statement.directive,
                )
                if bytes(row[2]) != expected_receipt.canonical_bytes():
                    raise MinimalClearanceProofStateError("proof_receipt_binding")
                previous_state_id = bytes(row[15])
                previous_root = bytes(row[17])
                previous_clearance = bytes(row[21])
                previous_count = int(row[23])
                previous_replay = bytes(row[19])
                previous_binding = bytes(row[29])
                previous_head = bytes(audit[3])
                expected_sequence += 1
            last = rows[-1]
            if (
                int(state[6]) != int(last[13])
                or bytes(state[4]) != bytes(last[15])
                or bytes(state[7]) != bytes(last[17])
                or bytes(state[8]) != bytes(last[21])
                or int(state[9]) != int(last[23])
                or bytes(state[10]) != bytes(last[19])
                or bytes(state[13]) != bytes(last[29])
                or bytes(state[14]) != bytes(last[31])
                or bytes(state[15]) != bytes(last[0])
            ):
                raise MinimalClearanceProofStateError("proof_current_state")

    def create_backup(self, destination: Path) -> None:
        self.verify_integrity()
        self._database.create_backup(destination)
        candidate = MinimalClearanceStateStoreV1(path=destination, verifier=self.verifier)
        candidate.close()

    def recover_from_backup(self, *, backup_path: Path, recovered_path: Path) -> "MinimalClearanceStateStoreV1":
        recovered = self._database.recover_from_backup(backup_path=backup_path, recovered_path=recovered_path)
        recovered.close()
        return MinimalClearanceStateStoreV1(path=recovered_path, verifier=self.verifier)

    def close(self) -> None:
        self._database.close()


class StaticMinimalClearanceVerifier:
    """Test-only verifier port for state semantics; never production authority."""

    def __init__(self, acceptance: MinimalProofAcceptanceV1) -> None:
        self.acceptance = acceptance

    def expected_statement(self) -> bytes:
        return self.acceptance.statement.statement_bytes

    def verify(self, artifact_path: Path) -> MinimalProofAcceptanceV1:
        return self.acceptance


__all__ = (
    "MinimalClearanceIndeterminateError",
    "MinimalClearanceProofStateError",
    "MinimalClearanceReceiptV1",
    "MinimalClearanceStateSnapshotV1",
    "MinimalClearanceStateStoreV1",
    "MinimalClearanceVerifierPort",
    "MinimalProofAcceptanceV1",
    "MinimalProofStatementV1",
    "NativeMinimalClearanceVerifier",
    "StaticMinimalClearanceVerifier",
    "parse_acceptance_bytes",
)
