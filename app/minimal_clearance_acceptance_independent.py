"""Independent parser for the native minimal-clearance acceptance grammar.

This module owns a separate immutable view.  It intentionally does not import
the producer state module, its dataclasses, or its parsing helpers.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Final


class IndependentAcceptanceError(ValueError):
    """Bounded failure from the independent acceptance boundary."""


_DIGEST_BYTES: Final[int] = 64
_SHA256_BYTES: Final[int] = 32
_PUBLIC_BYTES: Final[int] = 5090
_HEADER_BYTES: Final[int] = 68
_MAX_PROOF_BYTES: Final[int] = 512 * 1024 * 1024
_MAX_ARTIFACT_BYTES: Final[int] = _MAX_PROOF_BYTES + _HEADER_BYTES + _PUBLIC_BYTES
_STATE_BYTES: Final[int] = 1686
_STATE_HEADER_BYTES: Final[int] = 150
_STATE_DIGEST_COUNT: Final[int] = 23
_STATE_PROPOSED_COMMITMENT_OFFSET: Final[int] = _STATE_HEADER_BYTES + _STATE_DIGEST_COUNT * _DIGEST_BYTES
_ACCEPTANCE_MAGIC = b"BLPACV3\x00"
_ACCEPTANCE_VERSION = 3
_CIRCUIT_ID = bytes.fromhex("0f9fefb8cf05cc4e7a6b9657878c05a37034736d193272e14981f97fdd5a4275")
_PROOF_ROLE = b"BL/NATIVE-V3/MINIMAL-CLEARANCE/v3"
_STATE_GENESIS_EPOCH: Final[int] = 7
_ZERO_SUITE = bytes(64)
_STATEMENT_DIGEST_NAMES = (
    "proof_suite", "execution_context", "source_registry_snapshot", "source_profile",
    "governance_snapshot", "automatic_control_set", "settlement_domain", "evaluator_id",
    "schema_id", "program_id", "policy_id", "subject_id", "attempt_id", "request_id",
    "source_root_id", "completeness_id", "private_batch_commitment", "source_address",
    "source_key", "audit_address", "exception_id", "exception_scope_id", "rule_id",
    "decision_id", "state_before_id", "state_after_id",
)
_STATE_DIGEST_NAMES = (
    "source_root_id", "completeness_id", "subject_id", "attempt_id", "request_id",
    "exception_id", "exception_scope_id", "rule_id", "decision_id", "before_audit_head",
    "after_audit_head", "before_continuity_root", "after_continuity_root", "read_decision_id",
    "read_address", "read_key", "read_before", "read_after", "write_decision_id",
    "write_address", "write_key", "write_before", "write_after",
)
_STATE_LAYOUT_LITERAL = (
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
_STATE_ID_DOMAIN = b"BL/NATIVE-V3/STATE-ID/v1\x00"


def _sha(domain: bytes, *parts: bytes) -> bytes:
    digest = hashlib.sha3_512(domain)
    for part in parts:
        if type(part) is not bytes:
            raise IndependentAcceptanceError("acceptance_hash_part")
        digest.update(part)
    return digest.digest()


_STATE_LAYOUT_ID = _sha(b"BL/NATIVE-V3/STATE-LAYOUT/v2\x00", _STATE_LAYOUT_LITERAL)
_NO_AUTHORIZED_AMOUNT = _sha(b"BL/NATIVE-V3/NO-AUTHORIZED-AMOUNT/v1\x00")


def _take(data: bytes, offset: int, size: int, label: str) -> tuple[bytes, int]:
    end = offset + size
    if size < 0 or end < offset or end > len(data):
        raise IndependentAcceptanceError(f"{label}_truncated")
    return data[offset:end], end


def _u8(data: bytes, offset: int, label: str) -> tuple[int, int]:
    value, offset = _take(data, offset, 1, label)
    return value[0], offset


def _u32(data: bytes, offset: int, label: str) -> tuple[int, int]:
    value, offset = _take(data, offset, 4, label)
    return int.from_bytes(value, "big"), offset


def _u64(data: bytes, offset: int, label: str) -> tuple[int, int]:
    value, offset = _take(data, offset, 8, label)
    return int.from_bytes(value, "big"), offset


def _wide(value: bytes, label: str, *, allow_zero: bool = False) -> bytes:
    if type(value) is not bytes or len(value) != _DIGEST_BYTES:
        raise IndependentAcceptanceError(f"{label}_width")
    if not allow_zero and not any(value):
        raise IndependentAcceptanceError(f"{label}_zero")
    return value


def _genesis_state_bytes() -> bytes:
    state = bytearray(_STATE_BYTES)
    state[:4] = b"BLST"
    state[4] = 2
    state[16:24] = _STATE_GENESIS_EPOCH.to_bytes(8, "big")
    state[470:534] = b"\xe0" + bytes(63)
    state[534:598] = b"\xe0" + bytes(63)
    state[_STATE_PROPOSED_COMMITMENT_OFFSET : _STATE_PROPOSED_COMMITMENT_OFFSET + _DIGEST_BYTES] = _NO_AUTHORIZED_AMOUNT
    return bytes(state)


def _decode_state_bytes(data: bytes, *, label: str) -> dict[str, object]:
    if type(data) is not bytes or len(data) != _STATE_BYTES:
        raise IndependentAcceptanceError(f"{label}_length")
    offset = 0
    magic, offset = _take(data, offset, 4, f"{label}_magic")
    version, offset = _u8(data, offset, f"{label}_version")
    if magic != b"BLST" or version != 2:
        raise IndependentAcceptanceError(f"{label}_header")
    state: dict[str, object] = {}
    for name in ("policy_result", "effective_directive", "complete", "membership", "absence", "active", "exception_present", "exception_authorized", "economic_mutation", "clearance_marker_before", "clearance_marker_after"):
        state[name], offset = _u8(data, offset, f"{label}_{name}")
    for name in ("epoch", "sequence_before", "rule_effective_time", "event_time", "observation_time", "decision_time", "read_time", "write_time", "exception_valid_from", "exception_valid_until", "sequence_after"):
        state[name], offset = _u64(data, offset, f"{label}_{name}")
    for name in ("decision_index", "decision_count", "read_access_index", "write_access_index", "access_count", "read_decision_index", "write_decision_index"):
        state[name], offset = _u32(data, offset, f"{label}_{name}")
    state["read_mode"], offset = _u8(data, offset, f"{label}_read_mode")
    state["write_mode"], offset = _u8(data, offset, f"{label}_write_mode")
    for name in ("clearance_count_before", "clearance_count_after"):
        state[name], offset = _u64(data, offset, f"{label}_{name}")
    is_genesis = data == _genesis_state_bytes()
    for name in _STATE_DIGEST_NAMES:
        value, offset = _take(data, offset, _DIGEST_BYTES, f"{label}_{name}")
        state[name] = _wide(bytes(value), f"{label}_{name}", allow_zero=is_genesis or (int(state["sequence_before"]) == 0 and name in {"before_audit_head", "before_continuity_root", "write_before"}))
    value, offset = _take(data, offset, _DIGEST_BYTES, f"{label}_proposed_payment_commitment")
    state["proposed_payment_commitment"] = _wide(bytes(value), f"{label}_proposed_payment_commitment")
    if offset != len(data):
        raise IndependentAcceptanceError(f"{label}_trailing")
    return state


@dataclass(frozen=True, slots=True)
class IndependentStatementV3:
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
class IndependentAcceptanceV3:
    statement: IndependentStatementV3
    artifact_sha256: bytes
    artifact_digest: bytes
    artifact_bytes: int
    circuit_id: bytes
    proof_accepted: bool = True

    def __post_init__(self) -> None:
        if type(self.statement) is not IndependentStatementV3:
            raise IndependentAcceptanceError("acceptance_statement")
        if type(self.artifact_sha256) is not bytes or len(self.artifact_sha256) != _SHA256_BYTES:
            raise IndependentAcceptanceError("acceptance_sha256")
        _wide(self.artifact_digest, "acceptance_sha3")
        if type(self.artifact_bytes) is not int or not 0 < self.artifact_bytes <= _MAX_ARTIFACT_BYTES:
            raise IndependentAcceptanceError("acceptance_bytes")
        if self.circuit_id != _CIRCUIT_ID or self.proof_accepted is not True:
            raise IndependentAcceptanceError("acceptance_identity")

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
        return _sha(b"BL/MINIMAL-CLEARANCE/STATEMENT/v3\x00", self.statement.statement_bytes)

    @property
    def bundle_id(self) -> bytes:
        return self.artifact_digest

    @property
    def policy_result(self) -> int:
        return self.statement.policy_result

    @property
    def effective_directive(self) -> int:
        return self.statement.directive


def _validate(
    values: dict[str, object],
    state: dict[str, object],
    predecessor: dict[str, object],
    *,
    expected_state_before_id: bytes | None = None,
) -> None:
    policy = int(state["policy_result"])
    directive = int(state["effective_directive"])
    mapping = {1: 1, 2: 2, 3: 3, 4: 4, 5: 4}
    if directive not in mapping or policy != mapping[directive]:
        raise IndependentAcceptanceError("acceptance_policy_directive")
    for name in ("complete", "membership", "absence", "active", "exception_present", "exception_authorized", "economic_mutation", "clearance_marker_before", "clearance_marker_after"):
        if int(state[name]) not in (0, 1):
            raise IndependentAcceptanceError("acceptance_boolean")
    if int(state["economic_mutation"]) != 0:
        raise IndependentAcceptanceError("acceptance_economic_mutation")
    proposed_payment_commitment = bytes(state["proposed_payment_commitment"])
    _wide(proposed_payment_commitment, "acceptance_proposed_payment_commitment")
    expected = {1: (1, 1, 0, 1, 0, 0), 2: (1, 0, 1, 0, 0, 0), 3: (0, 0, 0, 0, 0, 0), 4: (1, 1, 0, 0, 0, 0), 5: (1, 1, 0, 0, 1, 1)}[directive]
    flags = tuple(int(state[name]) for name in ("complete", "membership", "absence", "active", "exception_present", "exception_authorized"))
    if flags != expected or tuple(int(state[name]) for name in ("complete", "membership", "absence", "active")) != tuple(int(values[name]) for name in ("complete", "authoritative_membership", "authoritative_absence", "active")):
        raise IndependentAcceptanceError("acceptance_directive_flags")
    if int(state["epoch"]) != int(values["epoch"]) or int(state["sequence_before"]) != int(values["sequence_before"]):
        raise IndependentAcceptanceError("acceptance_epoch_sequence")
    if not int(state["rule_effective_time"]) < int(state["event_time"]) < int(state["observation_time"]) < int(state["decision_time"]):
        raise IndependentAcceptanceError("acceptance_chronology")
    if int(state["read_time"]) != int(state["observation_time"]) or int(state["write_time"]) != int(state["decision_time"]):
        raise IndependentAcceptanceError("acceptance_access_time")
    if tuple(int(state[name]) for name in ("decision_index", "decision_count", "read_access_index", "write_access_index", "access_count", "read_decision_index", "write_decision_index", "read_mode", "write_mode")) != (0, 1, 0, 1, 2, 0, 0, 1, 2):
        raise IndependentAcceptanceError("acceptance_access_shape")
    if int(values["sequence_before"]) >= 2**64 - 1 or int(state["sequence_after"]) != int(values["sequence_before"]) + 1:
        raise IndependentAcceptanceError("acceptance_sequence")
    clear_transition = directive in (1, 5)
    if int(state["clearance_marker_after"]) != int(bool(int(state["clearance_marker_before"]) or clear_transition)):
        raise IndependentAcceptanceError("acceptance_clearance_marker")
    if int(state["clearance_count_after"]) != int(state["clearance_count_before"]) + int(clear_transition):
        raise IndependentAcceptanceError("acceptance_clearance_count")
    exception_id = bytes(values["exception_id"])
    if directive != 5:
        if exception_id != b"\xe0" + bytes(63) or int(state["exception_valid_from"]) != 0 or int(state["exception_valid_until"]) != 0:
            raise IndependentAcceptanceError("acceptance_exception_sentinel")
    elif not int(state["exception_valid_from"]) < int(state["exception_valid_until"]) or not int(state["exception_valid_from"]) <= int(state["event_time"]) or not int(state["decision_time"]) <= int(state["exception_valid_until"]):
        raise IndependentAcceptanceError("acceptance_exception_interval")
    expected_exception_scope = (
        b"\xe0" + bytes(63)
        if directive != 5
        else _sha(
            b"BL/NATIVE-V3/EXCEPTION-SCOPE/v2\x00",
            exception_id,
            bytes(values["subject_id"]),
            bytes(values["rule_id"]),
            int(state["exception_valid_from"]).to_bytes(8, "big"),
            int(state["exception_valid_until"]).to_bytes(8, "big"),
            proposed_payment_commitment,
        )
    )
    if expected_exception_scope != bytes(values["exception_scope_id"]) or expected_exception_scope != bytes(state["exception_scope_id"]):
        raise IndependentAcceptanceError("acceptance_exception_scope")
    for name in _STATEMENT_DIGEST_NAMES[1:]:
        _wide(bytes(values[name]), "acceptance_" + name)
    if bytes(values["proof_suite"]) != _ZERO_SUITE:
        raise IndependentAcceptanceError("acceptance_proof_suite")
    for state_name, value_name in (("source_root_id", "source_root_id"), ("completeness_id", "completeness_id"), ("subject_id", "subject_id"), ("attempt_id", "attempt_id"), ("request_id", "request_id"), ("decision_id", "decision_id")):
        if bytes(state[state_name]) != bytes(values[value_name]):
            raise IndependentAcceptanceError("acceptance_state_binding")
    if (
        bytes(state["exception_id"]) != exception_id
        or bytes(state["exception_scope_id"]) != bytes(values["exception_scope_id"])
        or bytes(state["rule_id"]) != bytes(values["rule_id"])
    ):
        raise IndependentAcceptanceError("acceptance_decision_context")
    if bytes(state["read_decision_id"]) != bytes(values["decision_id"]) or bytes(state["write_decision_id"]) != bytes(values["decision_id"]):
        raise IndependentAcceptanceError("acceptance_join_decision")
    if bytes(state["read_before"]) != bytes(values["source_root_id"]) or bytes(state["read_after"]) != bytes(values["source_root_id"]):
        raise IndependentAcceptanceError("acceptance_read_value")
    if bytes(state["write_before"]) != bytes(state["before_audit_head"]) or bytes(state["write_after"]) != bytes(state["after_audit_head"]):
        raise IndependentAcceptanceError("acceptance_write_value")
    if bytes(state["write_address"]) != bytes(values["audit_address"]) or bytes(state["write_key"]) != bytes(values["decision_id"]):
        raise IndependentAcceptanceError("acceptance_write_address")
    if bytes(state["read_address"]) != bytes(values["source_address"]) or bytes(state["read_key"]) != bytes(values["source_key"]):
        raise IndependentAcceptanceError("acceptance_read_address")
    if type(expected_state_before_id) not in (bytes, type(None)):
        raise IndependentAcceptanceError("acceptance_expected_predecessor")
    if expected_state_before_id is not None and len(expected_state_before_id) != _DIGEST_BYTES:
        raise IndependentAcceptanceError("acceptance_expected_predecessor")
    predecessor_bytes = bytes(values["predecessor_state_bytes"])
    if int(predecessor["epoch"]) != int(values["epoch"]):
        raise IndependentAcceptanceError("acceptance_predecessor_epoch")
    if int(predecessor["sequence_after"]) != int(values["sequence_before"]):
        raise IndependentAcceptanceError("acceptance_predecessor_sequence")
    if bytes(predecessor["after_audit_head"]) != bytes(state["before_audit_head"]):
        raise IndependentAcceptanceError("acceptance_predecessor_audit")
    if bytes(predecessor["after_continuity_root"]) != bytes(state["before_continuity_root"]):
        raise IndependentAcceptanceError("acceptance_predecessor_continuity")
    if int(predecessor["clearance_marker_after"]) != int(state["clearance_marker_before"]):
        raise IndependentAcceptanceError("acceptance_predecessor_marker")
    if int(predecessor["clearance_count_after"]) != int(state["clearance_count_before"]):
        raise IndependentAcceptanceError("acceptance_predecessor_count")
    if int(values["sequence_before"]) == 0 and predecessor_bytes != _genesis_state_bytes():
        raise IndependentAcceptanceError("acceptance_genesis_state")
    expected_before_state = _sha(
        _STATE_ID_DOMAIN,
        bytes(values["execution_context"]),
        int(values["sequence_before"]).to_bytes(8, "big"), _STATE_LAYOUT_ID,
        (1).to_bytes(4, "big"), len(predecessor_bytes).to_bytes(8, "big"),
        predecessor_bytes,
    )
    if expected_before_state != bytes(values["state_before_id"]):
        raise IndependentAcceptanceError("acceptance_before_state_id")
    if expected_state_before_id is not None and expected_state_before_id != expected_before_state:
        raise IndependentAcceptanceError("acceptance_predecessor_mismatch")
    expected_request = _sha(b"BL/NATIVE-V3/REQUEST-ID/v2\x00", bytes(values["subject_id"]), bytes(values["attempt_id"]), int(values["epoch"]).to_bytes(8, "big"), int(values["sequence_before"]).to_bytes(8, "big"), bytes(values["state_before_id"]))
    if expected_request != bytes(values["request_id"]):
        raise IndependentAcceptanceError("acceptance_request")
    expected_decision = _sha(b"BL/NATIVE-V3/MINIMAL-DECISION/v2\x00", bytes(values["request_id"]), bytes(values["source_root_id"]), bytes(values["completeness_id"]), bytes((policy, directive)), bytes(values["exception_id"]), proposed_payment_commitment)
    if expected_decision != bytes(values["decision_id"]):
        raise IndependentAcceptanceError("acceptance_decision")
    expected_audit = _sha(b"BL/NATIVE-V3/MINIMAL-AUDIT-HEAD/v1\x00", bytes(state["before_audit_head"]), bytes(values["decision_id"]), bytes((directive,)))
    expected_root = _sha(b"BL/NATIVE-V3/MINIMAL-CONTINUITY-ROOT/v1\x00", bytes(state["before_continuity_root"]), bytes(values["source_root_id"]), bytes(values["decision_id"]))
    if expected_audit != bytes(state["after_audit_head"]) or expected_root != bytes(state["after_continuity_root"]):
        raise IndependentAcceptanceError("acceptance_after_continuity")
    expected_state = _sha(_STATE_ID_DOMAIN, bytes(values["execution_context"]), int(state["sequence_after"]).to_bytes(8, "big"), _STATE_LAYOUT_ID, (1).to_bytes(4, "big"), len(bytes(values["state_commitment_bytes"])).to_bytes(8, "big"), bytes(values["state_commitment_bytes"]))
    if expected_state != bytes(values["state_after_id"]):
        raise IndependentAcceptanceError("acceptance_after_state")


def _parse_statement(
    raw: bytes, *, expected_state_before_id: bytes | None = None
) -> IndependentStatementV3:
    if type(raw) is not bytes or len(raw) != _PUBLIC_BYTES:
        raise IndependentAcceptanceError("statement_length")
    offset = 0
    protocol, offset = _u8(raw, offset, "statement_protocol")
    role, offset = _take(raw, offset, len(_PROOF_ROLE), "statement_role")
    if protocol != 3 or role != _PROOF_ROLE:
        raise IndependentAcceptanceError("statement_role")
    values: dict[str, object] = {"protocol_version": protocol, "proof_role": role}
    for name in _STATEMENT_DIGEST_NAMES:
        value, offset = _take(raw, offset, _DIGEST_BYTES, "statement_" + name)
        values[name] = _wide(bytes(value), "statement_" + name, allow_zero=name == "proof_suite")
    values["epoch"], offset = _u64(raw, offset, "statement_epoch")
    values["sequence_before"], offset = _u64(raw, offset, "statement_sequence")
    for name in ("active", "complete", "authoritative_membership", "authoritative_absence"):
        values[name], offset = _u8(raw, offset, "statement_" + name)
        if values[name] not in (0, 1):
            raise IndependentAcceptanceError("statement_boolean")
    predecessor_bytes, offset = _take(raw, offset, _STATE_BYTES, "statement_predecessor_state")
    values["predecessor_state_bytes"] = bytes(predecessor_bytes)
    state_bytes, offset = _take(raw, offset, _STATE_BYTES, "statement_state")
    if offset != len(raw):
        raise IndependentAcceptanceError("statement_trailing")
    values["state_commitment_bytes"] = bytes(state_bytes)
    state = _decode_state_bytes(bytes(state_bytes), label="state")
    predecessor = _decode_state_bytes(bytes(predecessor_bytes), label="predecessor_state")
    _validate(values, state, predecessor, expected_state_before_id=expected_state_before_id)
    authorized = bytes(state["proposed_payment_commitment"]) if int(state["effective_directive"]) in (1, 5) else _NO_AUTHORIZED_AMOUNT
    state["authorized_payment_commitment"] = authorized
    join_id = _sha(b"BL/NATIVE-V3/MINIMAL-DECISION-ACCESS-JOIN/v2\x00", bytes(values["decision_id"]), bytes(state["read_decision_id"]), bytes(state["read_address"]), bytes(state["read_key"]), bytes(state["read_before"]), bytes(state["read_after"]), bytes(state["write_decision_id"]), bytes(state["write_address"]), bytes(state["write_key"]), bytes(state["write_before"]), bytes(state["write_after"]), bytes(values["state_before_id"]), bytes(values["state_after_id"]))
    receipt_id = _sha(b"BL/NATIVE-V3/MINIMAL-RECEIPT-ID/v2\x00", bytes(values["automatic_control_set"]), bytes(values["decision_id"]), join_id, bytes(values["state_before_id"]), bytes(values["state_after_id"]), bytes(state_bytes), authorized)
    settlement_id = _sha(b"BL/NATIVE-V3/MINIMAL-SETTLEMENT-REFERENCE/v2\x00", bytes(values["settlement_domain"]), bytes((int(state["effective_directive"]),)), bytes(values["decision_id"]), bytes(values["state_after_id"]), authorized)
    return IndependentStatementV3(bytes(raw), tuple(values.items()), tuple(state.items()), join_id, receipt_id, settlement_id)


def parse_acceptance_bytes(
    encoded: bytes, *, expected_state_before_id: bytes | None = None
) -> IndependentAcceptanceV3:
    if type(encoded) is not bytes or len(encoded) < 8 + 4 + 8 + 32 + 64 + 32 + 4:
        raise IndependentAcceptanceError("acceptance_truncated")
    offset = 0
    magic, offset = _take(encoded, offset, 8, "acceptance_magic")
    if magic != _ACCEPTANCE_MAGIC:
        raise IndependentAcceptanceError("acceptance_magic")
    version, offset = _u32(encoded, offset, "acceptance_version")
    if version != _ACCEPTANCE_VERSION:
        raise IndependentAcceptanceError("acceptance_version")
    artifact_bytes, offset = _u64(encoded, offset, "acceptance_artifact_bytes")
    artifact_sha256, offset = _take(encoded, offset, _SHA256_BYTES, "acceptance_sha256")
    artifact_digest, offset = _take(encoded, offset, _DIGEST_BYTES, "acceptance_sha3")
    circuit_id, offset = _take(encoded, offset, 32, "acceptance_circuit")
    statement_size, offset = _u32(encoded, offset, "acceptance_statement_size")
    if statement_size != _PUBLIC_BYTES:
        raise IndependentAcceptanceError("acceptance_statement_size")
    statement, offset = _take(encoded, offset, statement_size, "acceptance_statement")
    if offset != len(encoded):
        raise IndependentAcceptanceError("acceptance_trailing")
    result = IndependentAcceptanceV3(
        _parse_statement(
            bytes(statement), expected_state_before_id=expected_state_before_id
        ),
        bytes(artifact_sha256), bytes(artifact_digest), artifact_bytes, bytes(circuit_id)
    )
    if result.canonical_bytes() != encoded:
        raise IndependentAcceptanceError("acceptance_noncanonical")
    return result


__all__ = ("IndependentAcceptanceError", "IndependentAcceptanceV3", "IndependentStatementV3", "parse_acceptance_bytes")
