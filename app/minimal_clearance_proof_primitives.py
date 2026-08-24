"""Retained synthetic minimal-clearance proof parsing and native-verifier primitives.

This is a synthetic, nonactivating seam.  The native verifier owns proof acceptance and verifier-selected public bytes.
This module independently decodes those bytes and derives the typed semantic
result. It never treats proof acceptance as a directive and never writes
settlement/payment state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Callable, Final

from app.minimal_clearance_verifier_process import (
    CAP_BYTES,
    ContainedVerifierResult,
    VerifierProcessError,
    run_contained_verifier,
)


class MinimalClearanceProofStateError(RuntimeError):
    """Fail-closed errors at the proof-to-state boundary."""


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
_MAX_EXECUTABLE_BYTES: Final[int] = _MAX_ARTIFACT_BYTES
_MAX_ACCEPTANCE: Final[int] = 65_536
_WORKSPACE_PREFIX: Final[str] = "BLV3-WORKSPACE-"
_WORKSPACE_MARKER_NAME: Final[str] = ".BLV3-WORKSPACE"
_WORKSPACE_MARKER: Final[bytes] = b"BL/NATIVE-V3/MINIMAL-CLEARANCE-WORKSPACE/v3\x00"
_STATE_MAGIC = b"BLST"
_STATE_BYTES: Final[int] = 1622
_STATE_HEADER_BYTES: Final[int] = 150
_STATE_DIGEST_COUNT: Final[int] = 23
_ZERO_SUITE = bytes(_DIGEST_BYTES)
_PRIVATE_ZK_ID_DOMAIN = b"BL/NATIVE-V3/PRIVATE-ZK/IDENTITY/v1\x00"


def _private_zk_wide(label: str) -> bytes:
    digest = hashlib.sha3_512(_PRIVATE_ZK_ID_DOMAIN)
    digest.update(label.encode("ascii"))
    return digest.digest()


PRIVATE_ZK_MODE_ID = _private_zk_wide("mode.PRIVATE_ZK.v1")
PRIVATE_ZK_DATABASE_CONTEXT_ID = _private_zk_wide("database-context.v1")
PRIVATE_ZK_DATABASE_SCHEMA_ID = _private_zk_wide("database-schema.v1")
PRIVATE_ZK_DATABASE_PROGRAM_ID = _private_zk_wide("database-program.v1")
PRIVATE_ZK_INITIAL_PAYMENT_ROOT = _private_zk_wide("payment-genesis.v1")
PRIVATE_ZK_INITIAL_CLEARANCE_ROOT = _private_zk_wide("clearance-genesis.v1")
PRIVATE_ZK_EPOCH = 7
_PRIVATE_ZK_PROFILE_DOMAIN = b"BL/NATIVE-V3/PRIVATE-ZK/PROFILE/v1\x00"

_GENERIC_READ: Final[int] = 0x80000000
_GENERIC_EXECUTE: Final[int] = 0x20000000
_FILE_SHARE_READ: Final[int] = 0x00000001
_FILE_SHARE_WRITE: Final[int] = 0x00000002
_OPEN_EXISTING: Final[int] = 3
_FILE_ATTRIBUTE_NORMAL: Final[int] = 0x00000080
_FILE_ATTRIBUTE_DIRECTORY: Final[int] = 0x00000010
_FILE_ATTRIBUTE_REPARSE_POINT: Final[int] = 0x00000400
_FILE_FLAG_OPEN_REPARSE_POINT: Final[int] = 0x00200000
_FILE_FLAG_BACKUP_SEMANTICS: Final[int] = 0x02000000


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(
        int(getattr(metadata, "st_file_attributes", 0))
        & _FILE_ATTRIBUTE_REPARSE_POINT
    )


def _private_zk_profile_digest(statement: MinimalProofStatementV1, verifier_sha256: bytes) -> bytes:
    parts = [
        PRIVATE_ZK_MODE_ID,
        PRIVATE_ZK_DATABASE_CONTEXT_ID,
        PRIVATE_ZK_DATABASE_SCHEMA_ID,
        PRIVATE_ZK_DATABASE_PROGRAM_ID,
        bytes(statement.get("execution_context")),
        bytes(statement.get("evaluator_id")),
        bytes(statement.get("schema_id")),
        bytes(statement.get("program_id")),
        bytes(statement.get("automatic_control_set")),
        _CIRCUIT_ID,
        verifier_sha256,
        _ZERO_SUITE,
        _u64(PRIVATE_ZK_EPOCH),
    ]
    return _sha(_PRIVATE_ZK_PROFILE_DOMAIN, *parts)
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
_SCHEMA_VERSION: Final[int] = 3
_KIND = "PRIVATE_ZK_CLEARANCE"
_NATIVE_INPUTS: Final[int] = 36_969
_NATIVE_PUBLIC_INPUTS: Final[int] = 26_721
_NATIVE_LAYERS: Final[int] = 217
_NATIVE_TERMS: Final[int] = 12_158_968
_NATIVE_RATE: Final[int] = 4
_NATIVE_QUERIES: Final[int] = 189
_NATIVE_TRANSCRIPT_VERSION: Final[int] = 6

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


@dataclass(frozen=True, slots=True)
class NativeVerificationCallResult:
    """Immutable result binding one acceptance to its own containment call."""

    acceptance: MinimalProofAcceptanceV1 = field(repr=False)
    containment: ContainedVerifierResult = field(repr=False)


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


def _positive_decimal(value: str, label: str) -> int:
    if re.fullmatch(r"[1-9][0-9]*", value) is None:
        raise MinimalClearanceProofStateError(f"{label}_integer")
    return int(value)


def _canonical_decimal(value: str, label: str) -> int:
    if re.fullmatch(r"(?:0|[1-9][0-9]*)", value) is None:
        raise MinimalClearanceProofStateError(f"{label}_integer")
    return int(value)


def _parse_build_trace(stderr: bytes, *, expected_lines: int) -> tuple[int, int, int, int]:
    try:
        text = stderr.decode("ascii", "strict")
    except UnicodeDecodeError:
        raise MinimalClearanceProofStateError("proof_verifier_stderr_encoding") from None
    text = text.replace("\r\n", "\n")
    if not text.endswith("\n") or "\r" in text:
        raise MinimalClearanceProofStateError("proof_verifier_stderr_grammar")

    lines = text.splitlines(keepends=True)
    if len(lines) != expected_lines:
        raise MinimalClearanceProofStateError("proof_verifier_stderr_line_count")
    prefixes = (
        "MINIMAL_CLEARANCE_BUILD phase=public\n",
        "MINIMAL_CLEARANCE_BUILD phase=private\n",
        "MINIMAL_CLEARANCE_BUILD phase=assertions\n",
        "MINIMAL_CLEARANCE_BUILD phase=mkcircuit\n",
    )
    if tuple(lines[:4]) != prefixes:
        raise MinimalClearanceProofStateError("proof_verifier_build_trace")
    match = re.fullmatch(
        r"MINIMAL_CLEARANCE_BUILD phase=complete inputs=([0-9]+) "
        r"public_inputs=([0-9]+) layers=([0-9]+) terms=([0-9]+)\n",
        lines[4],
    )
    if match is None:
        raise MinimalClearanceProofStateError("proof_verifier_build_complete")
    values = tuple(_positive_decimal(value, "proof_verifier_build") for value in match.groups())
    if values != (_NATIVE_INPUTS, _NATIVE_PUBLIC_INPUTS, _NATIVE_LAYERS, _NATIVE_TERMS):
        raise MinimalClearanceProofStateError("proof_verifier_build_profile")
    if expected_lines == 8:
        if tuple(lines[5:]) != (
            "MINIMAL_CLEARANCE_VERIFIER_STAGE proof.read=accept remaining=0\n",
            "MINIMAL_CLEARANCE_VERIFIER_STAGE commitment=received\n",
            "MINIMAL_CLEARANCE_VERIFIER_STAGE verify=accept\n",
        ):
            raise MinimalClearanceProofStateError("proof_verifier_stage_trace")
    return values  # type: ignore[return-value]


def _parse_acceptance_output(
    stdout: bytes, stderr: bytes, *, public_bytes: int, proof_bytes: int
) -> bytes:
    try:
        text = stdout.decode("ascii", "strict")
    except UnicodeDecodeError:
        raise MinimalClearanceProofStateError("proof_verifier_output_encoding") from None
    text = text.replace("\r\n", "\n")
    if "\r" in text or not text.endswith("\n") or text.count("\n") != 1:
        raise MinimalClearanceProofStateError("proof_verifier_output_grammar")
    match = re.fullmatch(
        r"MINIMAL_CLEARANCE_VERIFIER_ACCEPT inputs=([0-9]+) "
        r"public_inputs=([0-9]+) layers=([0-9]+) terms=([0-9]+) "
        r"public_bytes=([0-9]+) proof_bytes=([0-9]+) rate=([0-9]+) "
        r"queries=([0-9]+) transcript_version=([0-9]+) circuit_id=([0-9a-f]{64}) "
        r"statement_sha3_512=([0-9a-f]{128}) "
        r"state_mutations=0 clear_authorizations=0\n",
        text,
    )
    if match is None:
        raise MinimalClearanceProofStateError("proof_verifier_output_grammar")
    numbers = tuple(_positive_decimal(value, "proof_verifier_output") for value in match.groups()[:9])
    expected = (
        _NATIVE_INPUTS, _NATIVE_PUBLIC_INPUTS, _NATIVE_LAYERS, _NATIVE_TERMS,
        public_bytes, proof_bytes, _NATIVE_RATE, _NATIVE_QUERIES, _NATIVE_TRANSCRIPT_VERSION,
    )
    if numbers != expected or bytes.fromhex(match.group(10)) != _CIRCUIT_ID:
        raise MinimalClearanceProofStateError("proof_verifier_output_profile")
    _parse_build_trace(stderr, expected_lines=8)
    try:
        return bytes.fromhex(match.group(11))
    except ValueError:
        raise MinimalClearanceProofStateError("proof_verifier_statement_digest") from None


def _parse_preflight_output(stdout: bytes, stderr: bytes) -> None:
    try:
        text = stdout.decode("ascii", "strict")
    except UnicodeDecodeError:
        raise MinimalClearanceProofStateError("proof_preflight_encoding") from None
    text = text.replace("\r\n", "\n")
    if "\r" in text:
        raise MinimalClearanceProofStateError("proof_preflight_grammar")
    match = re.fullmatch(
        r"MINIMAL_CLEARANCE_PREFLIGHT_PASS proof_invocations=0 "
        r"circuit_id=([0-9a-f]{64}) inputs=([0-9]+) public_inputs=([0-9]+) "
        r"layers=([0-9]+) terms=([0-9]+) public_bytes=([0-9]+) "
        r"epoch=([0-9]+) sequence_before=([0-9]+) endian_kat_epoch=([0-9]+) "
        r"endian_kat_sequence=([0-9]+) verifier_owned_reconstruction=1 canonical_serialize=1\n",
        text,
    )
    if match is None:
        raise MinimalClearanceProofStateError("proof_preflight_grammar")
    values = tuple(_canonical_decimal(value, "proof_preflight") for value in match.groups()[1:])
    expected = (_NATIVE_INPUTS, _NATIVE_PUBLIC_INPUTS, _NATIVE_LAYERS, _NATIVE_TERMS, _PUBLIC_BYTES)
    if values[:5] != expected or bytes.fromhex(match.group(1)) != _CIRCUIT_ID:
        raise MinimalClearanceProofStateError("proof_preflight_profile")
    if values[5:7] != (7, 11):
        raise MinimalClearanceProofStateError("proof_preflight_statement")
    if values[7:] != (0x0102030405060708, 0x1112131415161718):
        raise MinimalClearanceProofStateError("proof_preflight_endian")
    _parse_build_trace(stderr, expected_lines=5)


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
    if (
        bytes(state["exception_id"]) != exception_id
        or bytes(state["exception_scope_id"]) != bytes(values["exception_scope_id"])
        or bytes(state["rule_id"]) != bytes(values["rule_id"])
    ):
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


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        int(metadata.st_dev), int(metadata.st_ino),
        int(metadata.st_size), int(metadata.st_mtime_ns),
    )


def _require_regular_metadata(
    metadata: os.stat_result, *, maximum: int, label: str
) -> None:
    if not stat.S_ISREG(metadata.st_mode) or int(metadata.st_ino) == 0:
        raise MinimalClearanceProofStateError(f"{label}_not_regular_file")
    if metadata.st_size <= 0 or metadata.st_size > maximum:
        raise MinimalClearanceProofStateError(f"{label}_size")


def _read_bounded_regular_file(
    path: Path, *, maximum: int, label: str
) -> bytes:
    """Read one stable regular file through one owned descriptor."""

    if not isinstance(path, Path) or type(maximum) is not int or maximum <= 0:
        raise MinimalClearanceProofStateError(f"{label}_input")
    path_error: MinimalClearanceProofStateError | None = None
    try:
        path_before = os.lstat(path)
    except (OSError, ValueError):
        path_error = MinimalClearanceProofStateError(f"{label}_not_regular_file")
    if path_error is not None:
        raise path_error
    _require_regular_metadata(path_before, maximum=maximum, label=label)

    descriptor: int | None = None
    result: bytes | None = None
    pending: BaseException | None = None
    try:
        try:
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
            opened = os.fstat(descriptor)
            _require_regular_metadata(opened, maximum=maximum, label=label)
            if _file_identity(opened) != _file_identity(path_before):
                raise MinimalClearanceProofStateError(f"{label}_identity")
            chunks: list[bytes] = []
            total = 0
            while total <= maximum:
                piece = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
                if not piece:
                    break
                chunks.append(piece)
                total += len(piece)
                if total > maximum:
                    raise MinimalClearanceProofStateError(f"{label}_size")
            descriptor_after = os.fstat(descriptor)
            path_after = os.lstat(path)
            _require_regular_metadata(path_after, maximum=maximum, label=label)
            if (
                _file_identity(descriptor_after) != _file_identity(opened)
                or _file_identity(path_after) != _file_identity(descriptor_after)
            ):
                raise MinimalClearanceProofStateError(f"{label}_identity")
            result = b"".join(chunks)
            if len(result) != descriptor_after.st_size:
                raise MinimalClearanceProofStateError(f"{label}_identity")
        except MinimalClearanceProofStateError as exc:
            pending = exc
        except (OSError, ValueError):
            pending = MinimalClearanceProofStateError(f"{label}_read")
        except Exception:
            pending = MinimalClearanceProofStateError(f"{label}_read")
    except BaseException as exc:
        pending = exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                if pending is None:
                    pending = MinimalClearanceProofStateError(f"{label}_read")
    if pending is not None:
        pending.__cause__ = None
        pending.__context__ = None
        raise pending
    if result is None:
        raise MinimalClearanceProofStateError(f"{label}_read")
    return result


def _write_private_snapshot(directory: Path, name: str, raw: bytes, label: str) -> Path:
    target = directory / name
    snapshot_error: MinimalClearanceProofStateError | None = None
    try:
        with target.open("xb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        target.chmod(stat.S_IREAD)
        reread = _read_bounded_regular_file(
            target, maximum=len(raw), label=f"{label}_snapshot"
        )
    except (OSError, ValueError):
        snapshot_error = MinimalClearanceProofStateError(f"{label}_snapshot")
    if snapshot_error is not None:
        raise snapshot_error
    if reread != raw:
        raise MinimalClearanceProofStateError(f"{label}_snapshot_mismatch")
    return target


def _snapshot_verified_file(
    source: Path,
    directory: Path,
    *,
    label: str,
    maximum: int,
    expected_sha256: bytes | None = None,
) -> tuple[Path, bytes]:
    raw = _read_bounded_regular_file(source, maximum=maximum, label=label)
    digest = hashlib.sha256(raw).digest()
    if expected_sha256 is not None and digest != expected_sha256:
        raise MinimalClearanceProofStateError(f"{label}_identity")
    target = _write_private_snapshot(directory, f"{label}.bin", raw, label)
    reread = _read_bounded_regular_file(
        target, maximum=len(raw), label=f"{label}_snapshot_read"
    )
    if hashlib.sha256(reread).digest() != digest or reread != raw:
        raise MinimalClearanceProofStateError(f"{label}_snapshot_identity")
    return target, reread


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


def _workspace_parent_ok(path: Path) -> bool:
    try:
        item = os.lstat(path)
        return stat.S_ISDIR(item.st_mode) and int(item.st_nlink) == 1 and not bool(int(getattr(item, "st_file_attributes", 0)) & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)))
    except (OSError, ValueError):
        return False


def _new_native_workspace(parent: Path) -> Path:
    if not isinstance(parent, Path) or not _workspace_parent_ok(parent):
        raise MinimalClearanceProofStateError("verifier_workspace")
    try:
        directory = Path(tempfile.mkdtemp(prefix=_WORKSPACE_PREFIX, dir=parent))
        marker = directory / _WORKSPACE_MARKER_NAME
        descriptor = os.open(str(marker), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            os.write(descriptor, _WORKSPACE_MARKER)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.chmod(marker, stat.S_IREAD)
        return directory
    except (OSError, ValueError):
        raise MinimalClearanceProofStateError("verifier_workspace") from None


def _remove_native_workspace(directory: Path, *, keep_artifact: Path | None = None) -> None:
    try:
        marker = directory / _WORKSPACE_MARKER_NAME
        marker_before = os.lstat(marker)
        if not stat.S_ISREG(marker_before.st_mode) or int(marker_before.st_nlink) != 1 or bool(int(getattr(marker_before, "st_file_attributes", 0)) & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))):
            raise OSError
        flags = int(os.O_RDONLY) | int(getattr(os, "O_BINARY", 0)) | int(getattr(os, "O_NOFOLLOW", 0))
        descriptor = os.open(str(marker), flags)
        try:
            marker_opened = os.fstat(descriptor)
            marker_bytes = os.read(descriptor, len(_WORKSPACE_MARKER) + 1)
        finally:
            os.close(descriptor)
        if (int(marker_opened.st_dev), int(marker_opened.st_ino), int(marker_opened.st_nlink)) != (int(marker_before.st_dev), int(marker_before.st_ino), int(marker_before.st_nlink)) or marker_bytes != _WORKSPACE_MARKER:
            raise OSError
        for item in list(directory.iterdir()):
            if item == marker or (keep_artifact is not None and item == keep_artifact):
                continue
            current = os.lstat(item)
            if not stat.S_ISREG(current.st_mode) or int(current.st_nlink) != 1:
                raise OSError
            item.chmod(stat.S_IRUSR | stat.S_IWUSR)
            item.unlink()
        if keep_artifact is None:
            marker.chmod(stat.S_IRUSR | stat.S_IWUSR)
            marker.unlink()
            directory.rmdir()
    except (OSError, ValueError):
        raise MinimalClearanceProofStateError("verifier_workspace_cleanup") from None


class _HeldWindowsFile:
    """One descriptor-owned Windows file held across the native call."""

    def __init__(
        self,
        path: Path,
        *,
        maximum: int,
        executable: bool = False,
    ) -> None:
        if os.name != "nt":
            raise MinimalClearanceProofStateError("verifier_windows_only")
        if not isinstance(path, Path) or not path.is_absolute() or type(maximum) is not int or maximum <= 0:
            raise MinimalClearanceProofStateError("verifier_file_input")
        self.path = path
        self.maximum = maximum
        self._descriptor: int | None = None
        self._chain: list[tuple[Path, tuple[int, int, int, int], int]] = []
        self._closed = False
        try:
            self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            self._configure_kernel()
        except BaseException:
            raise MinimalClearanceProofStateError("verifier_file_custody") from None
        try:
            before = os.lstat(path)
            _require_regular_metadata(before, maximum=maximum, label="verifier_file")
            if executable:
                self._chain = self._open_directory_chain(path.parent)
            access = _GENERIC_READ | (_GENERIC_EXECUTE if executable else 0)
            share = _FILE_SHARE_READ if executable else 0
            raw = self._kernel32.CreateFileW(
                str(path), access, share, None, _OPEN_EXISTING,
                _FILE_ATTRIBUTE_NORMAL | _FILE_FLAG_OPEN_REPARSE_POINT, None,
            )
            raw_value = self._handle_value(raw)
            if raw_value in (0, -1):
                raise OSError
            try:
                self._validate_handle(raw_value, expect_directory=False)
                import msvcrt

                descriptor = msvcrt.open_osfhandle(
                    raw_value, int(os.O_RDONLY) | int(getattr(os, "O_BINARY", 0))
                )
            except BaseException:
                self._kernel32.CloseHandle(ctypes.wintypes.HANDLE(raw_value))
                raise
            self._descriptor = descriptor
            opened = os.fstat(descriptor)
            _require_regular_metadata(opened, maximum=maximum, label="verifier_file")
            if _file_identity(opened) != _file_identity(before):
                raise OSError
            self._identity = _file_identity(opened)
            self._assert_path_and_chain()
        except MinimalClearanceProofStateError:
            self.close()
            raise
        except BaseException:
            self.close()
            raise MinimalClearanceProofStateError("verifier_file_custody") from None

    @staticmethod
    def _handle_value(raw: object) -> int:
        value = getattr(raw, "value", raw)
        if value is None:
            return 0
        return int(value)

    def _configure_kernel(self) -> None:
        self._kernel32.CreateFileW.argtypes = [
            ctypes.wintypes.LPCWSTR, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD,
            ctypes.wintypes.LPVOID, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD,
            ctypes.wintypes.HANDLE,
        ]
        self._kernel32.CreateFileW.restype = ctypes.wintypes.HANDLE
        self._kernel32.GetFileInformationByHandle.argtypes = [
            ctypes.wintypes.HANDLE, ctypes.wintypes.LPVOID,
        ]
        self._kernel32.GetFileInformationByHandle.restype = ctypes.wintypes.BOOL
        self._kernel32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
        self._kernel32.CloseHandle.restype = ctypes.wintypes.BOOL

    def _validate_handle(self, raw: int, *, expect_directory: bool) -> None:
        class _FileInformation(ctypes.Structure):
            _fields_ = [
                ("dwFileAttributes", ctypes.wintypes.DWORD),
                ("ftCreationTime", ctypes.c_ulonglong),
                ("ftLastAccessTime", ctypes.c_ulonglong),
                ("ftLastWriteTime", ctypes.c_ulonglong),
                ("dwVolumeSerialNumber", ctypes.wintypes.DWORD),
                ("nFileSizeHigh", ctypes.wintypes.DWORD),
                ("nFileSizeLow", ctypes.wintypes.DWORD),
                ("nNumberOfLinks", ctypes.wintypes.DWORD),
                ("nFileIndexHigh", ctypes.wintypes.DWORD),
                ("nFileIndexLow", ctypes.wintypes.DWORD),
            ]

        information = _FileInformation()
        if not self._kernel32.GetFileInformationByHandle(
            ctypes.wintypes.HANDLE(raw), ctypes.byref(information)
        ):
            raise OSError
        attributes = int(information.dwFileAttributes)
        if attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            raise OSError
        is_directory = bool(attributes & _FILE_ATTRIBUTE_DIRECTORY)
        if is_directory != expect_directory or int(information.nNumberOfLinks) != 1:
            raise OSError

    def _open_directory_chain(self, directory: Path) -> list[tuple[Path, tuple[int, int, int, int], int]]:
        chain: list[tuple[Path, tuple[int, int, int, int], int]] = []
        current = directory
        try:
            while True:
                metadata = os.lstat(current)
                if not stat.S_ISDIR(metadata.st_mode) or _is_reparse(metadata) or int(metadata.st_nlink) != 1:
                    raise OSError
                raw = self._kernel32.CreateFileW(
                    str(current), _GENERIC_READ,
                    _FILE_SHARE_READ | _FILE_SHARE_WRITE, None, _OPEN_EXISTING,
                    _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
                    None,
                )
                raw_value = self._handle_value(raw)
                if raw_value in (0, -1):
                    raise OSError
                try:
                    self._validate_handle(raw_value, expect_directory=True)
                except BaseException:
                    self._kernel32.CloseHandle(ctypes.wintypes.HANDLE(raw_value))
                    raise
                identity = _file_identity(metadata)
                chain.append((current, identity, raw_value))
                parent = current.parent
                if parent == current:
                    break
                current = parent
            return chain
        except BaseException:
            for _path, _identity, raw in reversed(chain):
                try:
                    self._kernel32.CloseHandle(ctypes.wintypes.HANDLE(raw))
                except BaseException:
                    pass
            raise

    def _assert_path_and_chain(self) -> None:
        descriptor = self._descriptor
        if self._closed or descriptor is None:
            raise MinimalClearanceProofStateError("verifier_file_custody")
        opened = os.fstat(descriptor)
        if _file_identity(opened) != self._identity:
            raise MinimalClearanceProofStateError("verifier_file_identity")
        current = os.lstat(self.path)
        _require_regular_metadata(current, maximum=self.maximum, label="verifier_file")
        if _file_identity(current) != self._identity:
            raise MinimalClearanceProofStateError("verifier_file_identity")
        for path, identity, raw in self._chain:
            current_dir = os.lstat(path)
            if _file_identity(current_dir) != identity or not stat.S_ISDIR(current_dir.st_mode) or _is_reparse(current_dir):
                raise MinimalClearanceProofStateError("verifier_executable_parent")
            self._validate_handle(raw, expect_directory=True)

    def _read_held(self) -> bytes:
        descriptor = self._descriptor
        if descriptor is None or self._closed:
            raise MinimalClearanceProofStateError("verifier_file_custody")
        try:
            self._assert_path_and_chain()
            os.lseek(descriptor, 0, os.SEEK_SET)
            chunks: list[bytes] = []
            total = 0
            while total <= self.maximum:
                chunk = os.read(descriptor, min(1 << 20, self.maximum + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > self.maximum:
                    raise MinimalClearanceProofStateError("verifier_file_size")
                chunks.append(chunk)
            if total <= 0:
                raise MinimalClearanceProofStateError("verifier_file_size")
            if total != int(os.fstat(descriptor).st_size):
                raise MinimalClearanceProofStateError("verifier_file_identity")
            self._assert_path_and_chain()
            return b"".join(chunks)
        except MinimalClearanceProofStateError:
            raise
        except BaseException:
            raise MinimalClearanceProofStateError("verifier_file_read") from None

    def digest(self, algorithm: str) -> tuple[int, bytes]:
        descriptor = self._descriptor
        if descriptor is None or self._closed:
            raise MinimalClearanceProofStateError("verifier_file_custody")
        try:
            self._assert_path_and_chain()
            os.lseek(descriptor, 0, os.SEEK_SET)
            hasher = hashlib.new(algorithm)
            total = 0
            while total <= self.maximum:
                chunk = os.read(descriptor, min(1 << 20, self.maximum + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > self.maximum:
                    raise MinimalClearanceProofStateError("verifier_file_size")
                hasher.update(chunk)
            if total != int(os.fstat(descriptor).st_size):
                raise MinimalClearanceProofStateError("verifier_file_identity")
            self._assert_path_and_chain()
            return total, hasher.digest()
        except MinimalClearanceProofStateError:
            raise
        except BaseException:
            raise MinimalClearanceProofStateError("verifier_file_read") from None

    @property
    def descriptor(self) -> int:
        if self._descriptor is None or self._closed:
            raise MinimalClearanceProofStateError("verifier_file_custody")
        return self._descriptor

    def reset(self) -> None:
        descriptor = self._descriptor
        if descriptor is None or self._closed:
            raise MinimalClearanceProofStateError("verifier_file_custody")
        try:
            self._assert_path_and_chain()
            os.lseek(descriptor, 0, os.SEEK_SET)
        except MinimalClearanceProofStateError:
            raise
        except BaseException:
            raise MinimalClearanceProofStateError("verifier_file_seek") from None

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        failed = False
        descriptor = self._descriptor
        self._descriptor = None
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                failed = True
        for _path, _identity, raw in reversed(self._chain):
            try:
                if not self._kernel32.CloseHandle(ctypes.wintypes.HANDLE(raw)):
                    failed = True
            except BaseException:
                failed = True
        self._chain.clear()
        if failed:
            raise MinimalClearanceProofStateError("verifier_file_close") from None

    def __enter__(self) -> "_HeldWindowsFile":
        return self

    def __exit__(self, _exc_type: object, _exc: object, _tb: object) -> None:
        self.close()


def _open_held_file(path: Path, *, maximum: int, executable: bool = False) -> _HeldWindowsFile:
    return _HeldWindowsFile(path, maximum=maximum, executable=executable)


class NativeMinimalClearanceVerifier:
    """Runs the pinned independent verifier and uses its reconstruction output."""

    def __init__(
        self,
        executable: Path,
        *,
        executable_sha256: str,
        workspace_parent: Path,
        timeout_seconds: float = 30.0 * 60.0,
    ) -> None:
        if type(executable_sha256) is not str or re.fullmatch(r"[0-9a-fA-F]{64}", executable_sha256) is None:
            raise MinimalClearanceProofStateError("verifier_executable_hash")
        if type(timeout_seconds) is not float or not 0 < timeout_seconds <= 30 * 60:
            raise MinimalClearanceProofStateError("verifier_timeout")
        self.executable = executable
        self._executable_sha256 = bytes.fromhex(executable_sha256)
        if not isinstance(workspace_parent, Path) or not _workspace_parent_ok(workspace_parent):
            raise MinimalClearanceProofStateError("verifier_workspace")
        self.workspace_parent = workspace_parent
        self.timeout_seconds = timeout_seconds
        self._preflight_checked = False
        self.identity_sha256()

    def identity_sha256(self) -> bytes:
        if os.name == "nt" and hasattr(self, "workspace_parent"):
            with _open_held_file(
                self.executable, maximum=_MAX_EXECUTABLE_BYTES, executable=True
            ) as held:
                _size, current = held.digest("sha256")
        else:
            current = hashlib.sha256(
                _read_bounded_regular_file(
                    self.executable, maximum=_MAX_EXECUTABLE_BYTES,
                    label="verifier_executable",
                )
            ).digest()
        if current != self._executable_sha256:
            raise MinimalClearanceProofStateError("verifier_executable_identity_changed")
        return current

    def _run(
        self,
        workspace: Path,
        *args: str,
        artifact: _HeldWindowsFile | None = None,
    ) -> ContainedVerifierResult:
        try:
            with _open_held_file(
                self.executable, maximum=_MAX_EXECUTABLE_BYTES, executable=True
            ) as executable:
                _size, before_digest = executable.digest("sha256")
                if before_digest != self._executable_sha256:
                    raise MinimalClearanceProofStateError("verifier_executable_identity_changed")
                process_failed = False
                try:
                    result = run_contained_verifier(
                        self.executable, tuple(args), workspace=workspace,
                        timeout_seconds=self.timeout_seconds,
                        _stdin_descriptor=(None if artifact is None else artifact.descriptor),
                    )
                except VerifierProcessError:
                    process_failed = True
                _size, after_digest = executable.digest("sha256")
                if after_digest != self._executable_sha256 or after_digest != before_digest:
                    raise MinimalClearanceProofStateError("verifier_executable_identity_changed")
                if process_failed:
                    raise MinimalClearanceProofStateError("verifier_process_unavailable")
        except MinimalClearanceProofStateError:
            raise
        if result.timed_out:
            raise MinimalClearanceProofStateError("verifier_timeout")
        if not result.cap_enforced or result.cap_bytes != CAP_BYTES or result.active_process_limit != 1:
            raise MinimalClearanceProofStateError("verifier_containment")
        if result.peak_job_commit_bytes > CAP_BYTES:
            raise MinimalClearanceProofStateError("verifier_memory_cap")
        return result

    def _ensure_preflight(self) -> None:
        if self._preflight_checked:
            return
        workspace = _new_native_workspace(self.workspace_parent)
        try:
            result = self._run(workspace, "--preflight")
            if result.exit_code != 0:
                raise MinimalClearanceProofStateError("verifier_preflight_rejected")
            _parse_preflight_output(result.stdout, result.stderr)
        finally:
            _remove_native_workspace(workspace)
        self._preflight_checked = True

    def preflight(self) -> None:
        """Run the pinned preflight once before the runtime admits work."""
        self.identity_sha256()
        self._ensure_preflight()

    def verify(
        self,
        artifact_path: Path,
        *,
        expected_artifact_bytes: int,
        expected_artifact_sha256: bytes,
        expected_artifact_sha3_512: bytes,
    ) -> NativeVerificationCallResult:
        self._ensure_preflight()
        if not isinstance(artifact_path, Path) or artifact_path.parent.parent != self.workspace_parent:
            raise MinimalClearanceProofStateError("verifier_workspace")
        workspace = artifact_path.parent
        if not _workspace_parent_ok(workspace):
            raise MinimalClearanceProofStateError("verifier_workspace")
        if (
            type(expected_artifact_bytes) is not int
            or not 0 < expected_artifact_bytes <= _MAX_ARTIFACT_BYTES
            or type(expected_artifact_sha256) is not bytes
            or len(expected_artifact_sha256) != _SHA256_BYTES
            or type(expected_artifact_sha3_512) is not bytes
            or len(expected_artifact_sha3_512) != _DIGEST_BYTES
        ):
            raise MinimalClearanceProofStateError("proof_artifact_metadata")
        try:
            with _open_held_file(
                artifact_path, maximum=_MAX_ARTIFACT_BYTES, executable=False
            ) as artifact:
                raw = artifact._read_held()
                if (
                    len(raw) != expected_artifact_bytes
                    or hashlib.sha256(raw).digest() != expected_artifact_sha256
                    or hashlib.sha3_512(raw).digest() != expected_artifact_sha3_512
                ):
                    raise MinimalClearanceProofStateError("proof_artifact_identity")
                circuit_id, public_bytes, proof_bytes = _artifact_public_bytes(raw)
                if circuit_id != _CIRCUIT_ID:
                    raise MinimalClearanceProofStateError("proof_circuit_id")
                artifact.reset()
                result = self._run(
                    workspace, "--verify-stdin", artifact=artifact
                )
                post_raw = artifact._read_held()
                if (
                    post_raw != raw
                    or len(post_raw) != expected_artifact_bytes
                    or hashlib.sha256(post_raw).digest() != expected_artifact_sha256
                    or hashlib.sha3_512(post_raw).digest() != expected_artifact_sha3_512
                ):
                    raise MinimalClearanceProofStateError("proof_artifact_identity")
                post_circuit_id, post_public_bytes, post_proof_bytes = _artifact_public_bytes(post_raw)
                if post_circuit_id != circuit_id or post_public_bytes != public_bytes or post_proof_bytes != proof_bytes:
                    raise MinimalClearanceProofStateError("proof_artifact_identity")
                if result.exit_code != 0:
                    raise MinimalClearanceProofStateError("proof_verifier_rejected")
                statement_digest = _parse_acceptance_output(
                    result.stdout, result.stderr,
                    public_bytes=len(post_public_bytes), proof_bytes=len(post_proof_bytes),
                )
                if statement_digest != hashlib.sha3_512(post_public_bytes).digest():
                    raise MinimalClearanceProofStateError("proof_verified_statement_digest")
                statement = _parse_statement(post_public_bytes)
                acceptance = MinimalProofAcceptanceV1(
                    statement=statement,
                    artifact_sha256=hashlib.sha256(post_raw).digest(),
                    artifact_digest=hashlib.sha3_512(post_raw).digest(),
                    artifact_bytes=len(post_raw),
                    circuit_id=post_circuit_id,
                )
                return NativeVerificationCallResult(acceptance, result)
        finally:
            _remove_native_workspace(workspace, keep_artifact=artifact_path)



__all__ = (
    "MinimalClearanceProofStateError",
    "MinimalProofStatementV1", "MinimalProofAcceptanceV1",
    "NativeMinimalClearanceVerifier", "NativeVerificationCallResult", "parse_acceptance_bytes",
)
