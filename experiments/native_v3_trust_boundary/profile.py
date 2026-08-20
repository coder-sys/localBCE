"""Canonical native-v3 trust-boundary profile and symbolic security ledger.

This module deliberately stops below the proof boundary.  It binds the frozen
Phase-0 fixture into a fixed public profile and records unresolved theorem
terms; it does not prove source membership, policy semantics, hiding, or state
transition correctness.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, localcontext
from fractions import Fraction
import hashlib
import json
from pathlib import Path
from typing import Any

from experiments.native_v3_phase0.native_v3_fixture import (
    ACCESS_READ,
    ACCESS_WRITE,
    DIRECTIVE_CLEAR,
    DIRECTIVE_NAMES,
    DIRECTIVE_POLICY_RESULT,
    EXPECTED_AMOUNT_SCOPE,
    EXPECTED_REASON_ID,
    EXPECTED_RULE_ID,
    NO_EXCEPTION_SENTINEL,
    OP_ROW_BYTES,
    AccessEvent,
    OrderedOperationRow,
    build_fixture,
)


class ProfileError(ValueError):
    """Raised for malformed or noncanonical trust-boundary data."""


PROFILE_VERSION = 1
PROFILE_NAME = "BL-NATIVE-V3-TRUST-BOUNDARY-PROFILE-v1"
PROFILE_ID_DOMAIN = b"BL/NATIVE-V3/TBP/PROFILE-ID/v1\0"
FRAME_DOMAIN = b"BL/NATIVE-V3/TBP/FRAME/v1\0"
STATEMENT_DOMAIN = b"BL/NATIVE-V3/TBP/STATEMENT/v1\0"
CONTROL_SET_DOMAIN = b"BL/NATIVE-V3/TBP/AUTOMATIC-CONTROL-SET/v1\0"
JOIN_DOMAIN = b"BL/NATIVE-V3/TBP/DECISION-ACCESS-JOIN/v1\0"
RECEIPT_DOMAIN = b"BL/NATIVE-V3/TBP/FROZEN-RECEIPT/v1\0"
COMPLETENESS_DOMAIN = b"BL/NATIVE-V3/TBP/COMPLETENESS/v1\0"
CHRONOLOGY_DOMAIN = b"BL/NATIVE-V3/TBP/CHRONOLOGY/v1\0"
REPLAY_DOMAIN = b"BL/NATIVE-V3/TBP/REPLAY/v1\0"
ATTEMPT_DOMAIN = b"BL/NATIVE-V3/TBP/ATTEMPT/v1\0"
PROFILE_BINDINGS_DOMAIN = b"BL/NATIVE-V3/TBP/BINDINGS/v1\0"
ACCESS_DOMAIN = b"BL/NATIVE-V3/TBP/ACCESS-ROW/v1\0"

PROFILE_ID = hashlib.sha3_512(PROFILE_ID_DOMAIN + PROFILE_NAME.encode()).digest()
FIXED_SALT_BYTES = 32
FIXED_SESSION_ID_BYTES = 32
FIXED_CHALLENGE_BYTES = 32
MAX_RETRIES = 4

EVENT_TIME = 7_000
OBSERVATION_TIME = 7_001
RULE_EFFECTIVE_TIME = 6_999
DECISION_TIME = 7_002

ACCESS_ROW_BYTES = 94
DECISION_ACCESS_JOIN_BYTES = 4 + OP_ROW_BYTES + 4 + (2 * ACCESS_ROW_BYTES)

PARAMETER_SET_DOMAIN = b"BL/NATIVE-V3/TBP/DP24-PARAMETER-SET/v1\0"
UPSTREAM_MANIFEST_RELATIVE_PATH = "experiments/longfellow_v09_native_v3/upstream_manifest.json"
UPSTREAM_MANIFEST_SHA256 = "A677B8A6BEA7DCA87E4370E8FA07FDFD17F345276B581629BE230022B8C0BB5D"
PARAMETER_SET_ID_EXPECTED = "3a8b4c62c78efded8b26d0a428b7bad17dc338b86ba945467ec8b815b8850080ad553452ac9dfc0d300df90cce3dc85b830ac9d24d543f8957fcef2e45b9e4ac"
IMPLEMENTATION_ATTESTATION_DOMAIN = (
    b"BL/NATIVE-V3/LONGFELLOW/IMPLEMENTATION-PARAMETER-ATTESTATION/v1\0"
)
IMPLEMENTATION_ATTESTATION_RELATIVE_PATH = (
    "experiments/longfellow_v09_native_v3/evidence/"
    "implementation_parameter_attestation.json"
)
IMPLEMENTATION_ATTESTATION_EVIDENCE_SHA256 = (
    "A64315F8C4ECD5F8C373E3751FA7D34BA4B5B917A5F04DE9EE6372E0D91BAFA0"
)

_DP24_CANDIDATE_VALUES = {
    "ell": 28,
    "rate_R": 1,
    "field_degree": 256,
    "theta": 4,
    "gamma": 324,
    "instances": 56,
}


CANONICAL_GRAMMAR: dict[str, Any] = {
    "integer_encoding": "unsigned big-endian",
    "hash": "SHA3-512",
    "domain_separation": {
        "profile_id": PROFILE_ID_DOMAIN.decode("ascii"),
        "statement_digest": STATEMENT_DOMAIN.decode("ascii"),
        "frame_tag": "BL/NATIVE-V3/TBP/FRAME-TAG/v1\\0",
        "commitment_digest": "BL/NATIVE-V3/TBP/COMMITMENT-DIGEST/v1\\0",
        "challenge_digest": "BL/NATIVE-V3/TBP/CHALLENGE-DIGEST/v1\\0",
        "challenge_authentication": "BL/NATIVE-V3/TBP/CHALLENGE-AUTH/v1\\0",
        "vector_leaf": "BL/NATIVE-V3/TBP/VECTOR-LEAF/v1\\0",
        "vector_node": "BL/NATIVE-V3/TBP/VECTOR-NODE/v1\\0",
        "leaf_tag": "BL/NATIVE-V3/TBP/LEAF-TAG/v1\\0",
        "node_tag": "BL/NATIVE-V3/TBP/NODE-TAG/v1\\0",
        "commitment_handle": "BL/NATIVE-V3/TBP/COMMITMENT-HANDLE/v1\\0",
        "transcript": "BL/NATIVE-V3/TBP/TRANSCRIPT/v1\\0",
    },
    "frame": {
        "fields": [
            ["magic", "bytes[8]", "BLTBFRM1"],
            ["version", "u16", 1],
            ["kind", "u8", "commitment=1,challenge=2,response=3"],
            ["role", "u8", "prover=1,verifier=2"],
            ["round", "u16", "commitment=0,challenge=1,response=2"],
            ["session_id", "bytes[32]", "nonzero; OS-CSPRNG session uniqueness"],
            ["domain_tag", "bytes[64]", "SHA3-512(frame-tag-domain,kind-domain,kind||role,round)"],
            ["payload_length", "u32", "exact remaining payload length"],
            ["payload", "bytes[payload_length]", "no trailing bytes"],
        ],
        "message_order": ["statement", "prover_commitment", "verifier_challenge", "prover_response"],
    },
    "statement": {
        "magic": "BLTBST01",
        "length_bytes": 992,
        "fields": [
            ["magic", "bytes[8]"],
            ["version", "u16=1"],
            ["flags", "u16=0"],
            ["proof_suite_marker", "u8=0"],
            ["reserved", "bytes[3]=0"],
            ["proof_suite_id", "bytes[64]=0/null"],
            ["session_id", "bytes[32]"],
            ["profile_id", "bytes[64]"],
            ["attempt_id", "bytes[64]"],
            ["phase0_statement_digest", "bytes[64]"],
            ["source_root", "bytes[64]"],
            ["control_set_id", "bytes[64]"],
            ["decision_access_join_id", "bytes[64]"],
            ["frozen_receipt_binding", "bytes[64]"],
            ["completeness_id", "bytes[64]"],
            ["chronology_id", "bytes[64]"],
            ["replay_id", "bytes[64]"],
            ["exception_id_or_sentinel", "bytes[64]"],
            ["state_before_id", "bytes[64]"],
            ["state_after_id", "bytes[64]"],
            ["statement_sequence_before", "u64"],
            ["statement_sequence_after", "u64"],
            ["event_time", "u64"],
            ["observation_time", "u64"],
            ["rule_effective_time", "u64"],
            ["decision_time", "u64"],
        ],
    },
    "commitment_payload": {
        "fields": [
            ["statement_digest", "bytes[64]"],
            ["vector_root", "bytes[64]"],
            ["commitment_handle", "bytes[64]"],
            ["leaf_count", "u32=2"],
            ["salt_bytes", "u16=32"],
            ["reserved", "u16=0"],
        ],
        "handle": "SHA3-512(handle-domain,session_id,statement_digest,vector_root)",
    },
    "challenge_payload": {
        "fields": [
            ["commitment_digest", "bytes[64]"],
            ["challenge_nonce", "bytes[32]", "verifier OS-CSPRNG"],
            ["challenge_scalar", "bytes[32]", "verifier OS-CSPRNG"],
            ["selected_index", "u32", "big-endian first four scalar bytes modulo 2"],
            ["auth_tag", "bytes[64]", "fixture-only HMAC-SHA3-512 under verifier-held 32-byte key"],
        ],
        "prover_supplied_challenge": False,
        "fresh_after_commitment": True,
    },
    "response_payload": {
        "fields": [
            ["commitment_digest", "bytes[64]"],
            ["challenge_digest", "bytes[64]"],
            ["commitment_handle", "bytes[64]"],
            ["response_nonce", "bytes[32]", "prover OS-CSPRNG"],
            ["opening_length", "u32"],
            ["opening", "bytes[opening_length]"],
        ],
    },
    "vector_leaf": {
        "magic": "BLTBLF01",
        "fields": [
            ["magic", "bytes[8]"],
            ["version", "u16=1"],
            ["reserved", "u16=0"],
            ["leaf_tag", "bytes[64]"],
            ["index", "u32", "ordered indices exactly 0 then 1"],
            ["value_length", "u32"],
            ["value", "bytes[value_length]", "fixture-only private registered fact or fixed padding"],
            ["salt_length", "u16=32"],
            ["salt", "bytes[32]", "hidden in statement; no production hiding claim"],
        ],
    },
    "vector_node": {
        "magic": "BLTBND01",
        "fields": [
            ["magic", "bytes[8]"],
            ["version", "u16=1"],
            ["reserved", "u16=0"],
            ["node_tag", "bytes[64]"],
            ["height", "u16=0"],
            ["left_index", "u32=0"],
            ["left_hash", "bytes[64]"],
            ["right_hash", "bytes[64]"],
        ],
        "root": "SHA3-512(vector-node-domain,canonical-node-bytes)",
    },
    "opening": {
        "magic": "BLTBOP01",
        "fields": [
            ["magic", "bytes[8]"],
            ["version", "u16=1"],
            ["reserved", "u16=0"],
            ["index", "u32"],
            ["value_length", "u32"],
            ["value", "bytes[value_length]"],
            ["salt_length", "u16=32"],
            ["salt", "bytes[32]"],
            ["path_count", "u16=1"],
            ["sibling_is_left", "u8 in {0,1}"],
            ["path_reserved", "u8=0"],
            ["sibling_hash", "bytes[64]"],
        ],
        "order": "exactly one sibling; index must equal verifier-selected index",
    },
    "transcript": {
        "magic": "BLTBTX01",
        "fields": [
            ["magic", "bytes[8]"],
            ["version", "u16=1"],
            ["flags", "u16=0"],
            ["session_id", "bytes[32]"],
            ["statement_length", "u32"],
            ["statement", "bytes[statement_length]"],
            ["frame_count", "u16=3"],
            ["ordered_frames", "3 x (u32 length, bytes)"],
            ["transcript_digest", "bytes[64]", "SHA3-512(transcript-domain,session,statement,commitment,challenge,response)"],
        ],
    },
    "private_or_fixture_only": ["vector values", "leaf salts", "prover response nonce", "verifier authentication key"],
}


def _sha(domain: bytes, *parts: bytes) -> bytes:
    h = hashlib.sha3_512()
    h.update(domain)
    for part in parts:
        h.update(part)
    return h.digest()


def u16(value: int) -> bytes:
    if not 0 <= value <= 0xFFFF:
        raise ProfileError("u16-range")
    return value.to_bytes(2, "big")


def u32(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFFFF:
        raise ProfileError("u32-range")
    return value.to_bytes(4, "big")


def u64(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        raise ProfileError("u64-range")
    return value.to_bytes(8, "big")


def nonzero64(value: bytes, label: str) -> bytes:
    if len(value) != 64 or not any(value):
        raise ProfileError(f"{label}:width-or-zero")
    return value


def fixed_field(value: bytes, label: str) -> bytes:
    return nonzero64(value, label)


def read_exact(data: bytes, offset: int, length: int, label: str) -> tuple[bytes, int]:
    end = offset + length
    if end > len(data):
        raise ProfileError(f"{label}:truncated")
    return data[offset:end], end


def _ascii_field(value: bytes, label: str) -> bytes:
    if len(value) > 0xFFFF:
        raise ProfileError(f"{label}:too-long")
    return u16(len(value)) + value


def access_row_bytes(index: int, count: int, operation_index: int, mode: int, value: bytes) -> bytes:
    if (
        type(index) is not int
        or type(count) is not int
        or type(operation_index) is not int
        or type(mode) is not int
    ):
        raise ProfileError("access-row:integer-fields")
    if count != 2 or index not in (0, 1) or operation_index != 0:
        raise ProfileError("access-row:geometry")
    expected_mode = ACCESS_READ if index == 0 else ACCESS_WRITE
    if mode != expected_mode:
        raise ProfileError("access-row:role-order")
    if not isinstance(value, bytes) or len(value) != 64:
        raise ProfileError("access-row:fields")
    return b"BLTBAC01" + u16(1) + u16(0) + u32(index) + u32(count) + u32(operation_index) + bytes((mode, 0)) + u32(len(value)) + value


def _parse_access_row(data: bytes) -> AccessEvent:
    if len(data) != ACCESS_ROW_BYTES:
        raise ProfileError("access-row:length")
    if data[:8] != b"BLTBAC01" or data[8:10] != u16(1) or data[10:12] != b"\0\0":
        raise ProfileError("access-row:header")
    index = int.from_bytes(data[12:16], "big")
    count = int.from_bytes(data[16:20], "big")
    operation_index = int.from_bytes(data[20:24], "big")
    mode = data[24]
    if data[25:26] != b"\0":
        raise ProfileError("access-row:reserved")
    value_length = int.from_bytes(data[26:30], "big")
    if value_length != 64:
        raise ProfileError("access-row:value")
    access = AccessEvent(operation_index, mode, data[30:94])
    if access_row_bytes(index, count, operation_index, mode, access.value) != data:
        raise ProfileError("access-row:noncanonical")
    return access


@dataclass(frozen=True, slots=True)
class DecisionAccessJoin:
    """The producer-owned, exact one-decision/two-access join boundary."""

    operation: OrderedOperationRow
    accesses: tuple[AccessEvent, ...]
    decision_count: int = 1
    access_count: int = 2

    def canonical_bytes(self) -> bytes:
        if type(self.decision_count) is not int or self.decision_count != 1:
            raise ProfileError("join:decision-count")
        if type(self.access_count) is not int or self.access_count != 2:
            raise ProfileError("join:access-count")
        if not isinstance(self.operation, OrderedOperationRow):
            raise ProfileError("join:operation-type")
        if self.operation.operation_index != 0 or self.operation.operation_count != 1:
            raise ProfileError("join:operation-geometry")
        operation_bytes = self.operation.canonical_bytes()
        accesses = tuple(self.accesses)
        if len(accesses) != self.access_count:
            raise ProfileError("join:access-count")
        expected = (
            (ACCESS_READ, self.operation.value_before),
            (ACCESS_WRITE, self.operation.value_after),
        )
        rows: list[bytes] = []
        for index, (access, (expected_mode, expected_value)) in enumerate(zip(accesses, expected, strict=True)):
            if type(access) is not AccessEvent:
                raise ProfileError("join:access-type")
            if access.operation_index != self.operation.operation_index:
                raise ProfileError("join:access-operation")
            if access.mode != expected_mode:
                raise ProfileError("join:access-role-order")
            if access.value != expected_value:
                raise ProfileError("join:access-value")
            rows.append(access_row_bytes(index, self.access_count, access.operation_index, access.mode, access.value))
        result = b"".join((u32(self.decision_count), operation_bytes, u32(self.access_count), *rows))
        if len(result) != DECISION_ACCESS_JOIN_BYTES:
            raise AssertionError("decision/access join length")
        return result

    @property
    def join_id(self) -> bytes:
        return _sha(JOIN_DOMAIN, self.canonical_bytes())


def parse_decision_access_join(data: bytes) -> DecisionAccessJoin:
    if len(data) != DECISION_ACCESS_JOIN_BYTES:
        raise ProfileError("join:length")
    decision_count = int.from_bytes(data[:4], "big")
    operation_start = 4
    operation_end = operation_start + OP_ROW_BYTES
    try:
        operation = OrderedOperationRow.parse(data[operation_start:operation_end])
    except ValueError as exc:
        raise ProfileError("join:operation") from exc
    access_count_start = operation_end
    access_count = int.from_bytes(data[access_count_start:access_count_start + 4], "big")
    rows_start = access_count_start + 4
    accesses = tuple(
        _parse_access_row(data[rows_start + index * ACCESS_ROW_BYTES:rows_start + (index + 1) * ACCESS_ROW_BYTES])
        for index in range(2)
    )
    join = DecisionAccessJoin(operation, accesses, decision_count=decision_count, access_count=access_count)
    if join.canonical_bytes() != data:
        raise ProfileError("join:noncanonical")
    return join


def control_set_bytes() -> bytes:
    scope = _sha(b"BL/NATIVE-V3/TBP/SCOPE/v1\0", b"synthetic-subject-payment-scope-v1")
    conflict_policy = b"priority-then-human-review"
    directive_mapping = bytes((1, 1, 2, 2, 3, 3, 4, 4, 5, 5))
    return b"BLTBCT01" + u16(1) + u16(0) + u32(1) + EXPECTED_RULE_ID + u16(1) + _ascii_field(conflict_policy, "control-set:conflict") + scope + u64(0) + u64(16) + u16(len(directive_mapping)) + directive_mapping


@dataclass(frozen=True)
class ProfileBindings:
    profile_id: bytes
    attempt_id: bytes
    phase0_statement_digest: bytes
    source_root: bytes
    control_set_id: bytes
    decision_access_join_id: bytes
    frozen_receipt_binding: bytes
    completeness_id: bytes
    chronology_id: bytes
    replay_id: bytes
    exception_id_or_sentinel: bytes
    state_before_id: bytes
    state_after_id: bytes
    statement_sequence_before: int
    statement_sequence_after: int
    event_time: int
    observation_time: int
    rule_effective_time: int
    decision_time: int

    def __post_init__(self) -> None:
        for label, value in (
            ("profile-id", self.profile_id),
            ("attempt-id", self.attempt_id),
            ("phase0-statement", self.phase0_statement_digest),
            ("source-root", self.source_root),
            ("control-set", self.control_set_id),
            ("decision-access-join", self.decision_access_join_id),
            ("receipt", self.frozen_receipt_binding),
            ("completeness", self.completeness_id),
            ("chronology", self.chronology_id),
            ("replay", self.replay_id),
            ("exception", self.exception_id_or_sentinel),
            ("state-before", self.state_before_id),
            ("state-after", self.state_after_id),
        ):
            fixed_field(value, label)
        if self.statement_sequence_after != self.statement_sequence_before + 1:
            raise ProfileError("bindings:sequence")
        if len({self.event_time, self.observation_time, self.rule_effective_time, self.decision_time}) != 4:
            raise ProfileError("bindings:times-not-distinct")
        if not (self.rule_effective_time < self.event_time < self.observation_time < self.decision_time):
            raise ProfileError("bindings:chronology")

    def canonical_bytes(self) -> bytes:
        return b"".join(
            (
                b"BLTBBN01",
                u16(PROFILE_VERSION),
                u16(0),
                self.profile_id,
                self.attempt_id,
                self.phase0_statement_digest,
                self.source_root,
                self.control_set_id,
                self.decision_access_join_id,
                self.frozen_receipt_binding,
                self.completeness_id,
                self.chronology_id,
                self.replay_id,
                self.exception_id_or_sentinel,
                self.state_before_id,
                self.state_after_id,
                u64(self.statement_sequence_before),
                u64(self.statement_sequence_after),
                u64(self.event_time),
                u64(self.observation_time),
                u64(self.rule_effective_time),
                u64(self.decision_time),
            )
        )


def build_profile_bindings() -> ProfileBindings:
    fixture = build_fixture()
    phase0_statement = fixture.statement.canonical_bytes()
    operation = fixture.operation.canonical_bytes()
    decision_access_join = DecisionAccessJoin(fixture.operation, fixture.accesses)
    if decision_access_join.operation.canonical_bytes() != operation:
        raise ProfileError("join:operation-binding")
    decision_access_join_id = decision_access_join.join_id
    auth_bytes = (
        NO_EXCEPTION_SENTINEL
        if fixture.exception_authorization is None
        else fixture.exception_authorization.canonical_bytes()
    )
    receipt_bytes = b"".join(
        (
            phase0_statement,
            operation,
            auth_bytes,
            fixture.before_state.canonical_bytes(),
            fixture.after_state.canonical_bytes(),
        )
    )
    frozen_receipt_binding = _sha(RECEIPT_DOMAIN, receipt_bytes)
    source_root = fixture.before_state.source_registry_root
    completeness_bytes = b"".join(
        (
            b"BLTBFC01",
            u16(1),
            u16(0),
            source_root,
            fixture.source_leaf.leaf_id,
            fixture.operation.address,
            u64(OBSERVATION_TIME),
            b"\1",
            u32(1),
        )
    )
    completeness_id = _sha(COMPLETENESS_DOMAIN, completeness_bytes)
    chronology_bytes = b"".join(
        (
            b"BLTBCH01",
            u16(1),
            u16(0),
            u64(EVENT_TIME),
            u64(OBSERVATION_TIME),
            u64(RULE_EFFECTIVE_TIME),
            u64(DECISION_TIME),
            u64(fixture.statement.epoch),
        )
    )
    chronology_id = _sha(CHRONOLOGY_DOMAIN, chronology_bytes)
    attempt_id = _sha(ATTEMPT_DOMAIN, fixture.source_leaf.leaf_id, fixture.operation.row_id, b"synthetic-attempt-v1")
    replay_id = _sha(
        REPLAY_DOMAIN,
        attempt_id,
        u64(fixture.statement.epoch),
        u64(fixture.statement.sequence_before),
        fixture.before_state.state_id,
        fixture.after_state.state_id,
    )
    control_set_id = _sha(CONTROL_SET_DOMAIN, control_set_bytes())
    return ProfileBindings(
        profile_id=PROFILE_ID,
        attempt_id=attempt_id,
        phase0_statement_digest=_sha(STATEMENT_DOMAIN, phase0_statement),
        source_root=source_root,
        control_set_id=control_set_id,
        decision_access_join_id=decision_access_join_id,
        frozen_receipt_binding=frozen_receipt_binding,
        completeness_id=completeness_id,
        chronology_id=chronology_id,
        replay_id=replay_id,
        exception_id_or_sentinel=fixture.operation.exception_authorization_id,
        state_before_id=fixture.before_state.state_id,
        state_after_id=fixture.after_state.state_id,
        statement_sequence_before=fixture.statement.sequence_before,
        statement_sequence_after=fixture.statement.sequence_after,
        event_time=EVENT_TIME,
        observation_time=OBSERVATION_TIME,
        rule_effective_time=RULE_EFFECTIVE_TIME,
        decision_time=DECISION_TIME,
    )


def _decimal_fraction(value: Fraction, digits: int = 80) -> str:
    with localcontext() as ctx:
        ctx.prec = digits
        return format(Decimal(value.numerator) / Decimal(value.denominator), "f")


def _decimal_log2(value: Fraction, digits: int = 50) -> str:
    if value <= 0:
        raise ProfileError("ledger:log2-nonpositive")
    with localcontext() as ctx:
        ctx.prec = digits + 12
        result = (Decimal(value.numerator).ln() - Decimal(value.denominator).ln()) / Decimal(2).ln()
        return format(+result, "f")


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _verified_upstream_manifest_sha256() -> str:
    repository_root = Path(__file__).resolve().parents[2]
    manifest_path = repository_root / UPSTREAM_MANIFEST_RELATIVE_PATH
    try:
        digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest().upper()
    except OSError as exc:
        raise ProfileError("ledger:provenance-source-unavailable") from exc
    if digest != UPSTREAM_MANIFEST_SHA256:
        raise ProfileError("ledger:provenance-source-mismatch")
    return digest


def _read_attestation_u32(record: bytes, offset: int) -> tuple[int, int]:
    end = offset + 4
    if end > len(record):
        raise ProfileError("ledger:implementation-attestation-truncated-u32")
    return int.from_bytes(record[offset:end], "big"), end


def _read_attestation_u64(record: bytes, offset: int) -> tuple[int, int]:
    end = offset + 8
    if end > len(record):
        raise ProfileError("ledger:implementation-attestation-truncated-u64")
    return int.from_bytes(record[offset:end], "big"), end


def _parse_implementation_attestation_record(record: bytes) -> dict[str, Any]:
    magic = b"BLPAV301"
    identity_bytes = 64
    if len(record) < len(magic) + 8 + identity_bytes:
        raise ProfileError("ledger:implementation-attestation-record-size")
    if record[: len(magic)] != magic:
        raise ProfileError("ledger:implementation-attestation-record-magic")
    version, offset = _read_attestation_u32(record, len(magic))
    field_count, offset = _read_attestation_u32(record, offset)
    if version != 1 or field_count != 24:
        raise ProfileError("ledger:implementation-attestation-record-header")
    body_end = len(record) - identity_bytes
    fields: dict[int, tuple[int, bytes]] = {}
    for expected_id in range(1, field_count + 1):
        if offset + 7 > body_end:
            raise ProfileError("ledger:implementation-attestation-field-header")
        field_id = int.from_bytes(record[offset : offset + 2], "big")
        field_type = record[offset + 2]
        length = int.from_bytes(record[offset + 3 : offset + 7], "big")
        offset += 7
        if field_id != expected_id or offset + length > body_end:
            raise ProfileError("ledger:implementation-attestation-field-order")
        fields[field_id] = (field_type, record[offset : offset + length])
        offset += length
    if offset != body_end:
        raise ProfileError("ledger:implementation-attestation-record-trailing")
    if hashlib.sha3_512(
        IMPLEMENTATION_ATTESTATION_DOMAIN + record[:body_end]
    ).digest() != record[body_end:]:
        raise ProfileError("ledger:implementation-attestation-record-identity")

    bytes_fields = {1, 6, 8, 12, 13, 14, 19, 20, 21, 22, 23, 24}
    u32_fields = {2, 3, 4, 5, 7, 9}
    u64_fields = {10, 11, 15, 16, 17, 18}
    if set(fields) != bytes_fields | u32_fields | u64_fields:
        raise ProfileError("ledger:implementation-attestation-field-set")
    for field_id, (field_type, payload) in fields.items():
        expected_type = 1 if field_id in bytes_fields else 2 if field_id in u32_fields else 3
        expected_length = None if field_id in bytes_fields else 4 if field_id in u32_fields else 8
        if field_type != expected_type or (
            expected_length is not None and len(payload) != expected_length
        ):
            raise ProfileError("ledger:implementation-attestation-field-type")
    def text(field_id: int) -> str:
        try:
            return fields[field_id][1].decode("ascii")
        except UnicodeDecodeError as exc:
            raise ProfileError("ledger:implementation-attestation-field-ascii") from exc

    def u32_field(field_id: int) -> int:
        return int.from_bytes(fields[field_id][1], "big")

    def u64_field(field_id: int) -> int:
        return int.from_bytes(fields[field_id][1], "big")

    return {
        "artifact_header_bytes": u64_field(10),
        "artifact_magic_hex": fields[8][1].hex(),
        "artifact_public_statement_bytes": u64_field(11),
        "artifact_version": u32_field(9),
        "circuit_id": fields[14][1].hex(),
        "circuit_inputs": u64_field(15),
        "circuit_layers": u64_field(17),
        "circuit_public_inputs": u64_field(16),
        "circuit_terms": u64_field(18),
        "field_degree": u32_field(2),
        "field_family": text(1),
        "field_serialized_bytes": u32_field(3),
        "proof_queries": u32_field(5),
        "proof_rate": u32_field(4),
        "proof_role": text(12),
        "public_statement_grammar": text(13),
        "quad_patch_sha256": text(23),
        "sha3_patch_sha256": text(22),
        "transcript_label": text(6),
        "transcript_version": u32_field(7),
        "upstream_commit": text(20),
        "upstream_remote": text(19),
        "upstream_tree": text(21),
    }


def _verified_implementation_attestation() -> dict[str, Any]:
    repository_root = Path(__file__).resolve().parents[2]
    evidence_path = repository_root / IMPLEMENTATION_ATTESTATION_RELATIVE_PATH
    try:
        evidence_bytes = evidence_path.read_bytes()
        evidence = json.loads(evidence_bytes)
    except (OSError, json.JSONDecodeError) as exc:
        raise ProfileError("ledger:implementation-attestation-evidence-unavailable") from exc
    if hashlib.sha256(evidence_bytes).hexdigest().upper() != IMPLEMENTATION_ATTESTATION_EVIDENCE_SHA256:
        raise ProfileError("ledger:implementation-attestation-evidence-mismatch")
    if evidence.get("schema") != "BL/NATIVE-V3/LONGFELLOW/IMPLEMENTATION-PARAMETER-ATTESTATION-EVIDENCE/v1":
        raise ProfileError("ledger:implementation-attestation-schema")
    if evidence.get("implementation_status") != "IMPLEMENTATION_ATTESTED":
        raise ProfileError("ledger:implementation-attestation-status")
    if evidence.get("proof_suite_id") is not None or evidence.get("production_usable") is not False or evidence.get("activation") is not False:
        raise ProfileError("ledger:implementation-attestation-flags")
    try:
        record_hex = evidence["record_hex"]
        record = bytes.fromhex(record_hex)
    except (KeyError, TypeError, ValueError) as exc:
        raise ProfileError("ledger:implementation-attestation-record-encoding") from exc
    if record_hex != record.hex() or evidence.get("record_bytes") != len(record):
        raise ProfileError("ledger:implementation-attestation-record-canonical")
    if evidence.get("record_sha256") != hashlib.sha256(record).hexdigest().upper():
        raise ProfileError("ledger:implementation-attestation-record-sha256")
    identity = record[-64:].hex()
    if evidence.get("record_identity_sha3_512") != identity:
        raise ProfileError("ledger:implementation-attestation-record-sha3")
    if evidence.get("identity_domain") != (IMPLEMENTATION_ATTESTATION_DOMAIN[:-1].decode("ascii") + r"\0"):
        raise ProfileError("ledger:implementation-attestation-domain")
    parsed_facts = _parse_implementation_attestation_record(record)
    if evidence.get("facts") != parsed_facts:
        raise ProfileError("ledger:implementation-attestation-facts")
    parity = evidence.get("producer_verifier_parity")
    if parity != {
        "record_bytes_equal": True,
        "record_identity_equal": True,
        "independent_verifier": True,
    }:
        raise ProfileError("ledger:implementation-attestation-parity")
    matrix = evidence.get("adversarial_matrix")
    if matrix != {"cases": 17, "rejected": 17, "proof_invocations": 0, "state_mutations": 0}:
        raise ProfileError("ledger:implementation-attestation-matrix")
    dp24_mapping = evidence.get("dp24_mapping")
    if not isinstance(dp24_mapping, dict) or any(
        dp24_mapping.get(name) != "UNKNOWN"
        for name in ("ell", "rate_R", "field_degree", "theta", "gamma", "instances")
    ):
        raise ProfileError("ledger:implementation-attestation-dp24-mapping")
    return {
        "activation": False,
        "adversarial_matrix": matrix,
        "evidence_sha256": IMPLEMENTATION_ATTESTATION_EVIDENCE_SHA256,
        "facts": parsed_facts,
        "identity_algorithm": evidence["identity_algorithm"],
        "identity_domain": evidence["identity_domain"],
        "implementation_status": evidence["implementation_status"],
        "production_usable": False,
        "proof_suite_id": None,
        "record_bytes": len(record),
        "record_identity_sha3_512": identity,
        "record_sha256": hashlib.sha256(record).hexdigest().upper(),
        "producer_verifier_parity": parity,
        "dp24_mapping": dp24_mapping,
        "schema": evidence["schema"],
    }


def _parameter_set_descriptor() -> dict[str, Any]:
    manifest_sha256 = _verified_upstream_manifest_sha256()
    return {
        "schema": "BL/NATIVE-V3/TBP/DP24-PARAMETER-SET/v1",
        "status": "UNKNOWN_NOT_AUTHORITY_BOUND",
        "identity_algorithm": "SHA3-512(BL/NATIVE-V3/TBP/DP24-PARAMETER-SET/v1\\0 || canonical-json(descriptor))",
        "provenance": {
            "source": "No authoritative repository byte derives the DP24 tuple; the pinned Longfellow manifest records only upstream pin/build/SHA3 facts.",
            "authoritative_repository_bytes": [
                {
                    "path": UPSTREAM_MANIFEST_RELATIVE_PATH,
                    "sha256": manifest_sha256,
                    "role": "pinned upstream identity only; no DP24 tuple derivation",
                }
            ],
            "pinned_upstream_commit": "fe83ec6c4efa5f98bc2439c8b06e5eccd153aca0",
            "pinned_upstream_tree": "829f5dd115f3b5bdd77dc57c72293a5ccc3ca244",
        },
        "fields": {
            name: {
                "value": None,
                "status": "UNKNOWN",
                "candidate_value": value,
                "candidate_value_status": "HYPOTHETICAL_CANDIDATE_INPUT",
                "source": "historical symbolic-ledger literal; not derivable from the authoritative pinned bytes",
            }
            for name, value in _DP24_CANDIDATE_VALUES.items()
        },
    }


def _parameter_set() -> dict[str, Any]:
    descriptor = _parameter_set_descriptor()
    parameter_set_id = hashlib.sha3_512(PARAMETER_SET_DOMAIN + _canonical_json_bytes(descriptor)).hexdigest()
    if parameter_set_id != PARAMETER_SET_ID_EXPECTED:
        raise ProfileError("ledger:parameter-provenance-identity")
    return {"id": parameter_set_id, **descriptor}


def build_security_ledger() -> dict[str, Any]:
    parameter_set = _parameter_set()
    implementation_attestation = _verified_implementation_attestation()
    unresolved = [
        {
            "id": "vc_collapse_binding",
            "symbol": "epsilon_VCCollapse(lambda,t_VCCollapse)",
            "coefficient": "sum_i L_i*q_i",
            "status": "UNRESOLVED",
            "source": "2025/947 interactive IOP-to-argument bound",
            "bound": None,
        },
        {
            "id": "salted_leaf_hiding",
            "symbol": "epsilon_SaltedLeafHiding(lambda,salt_bytes)",
            "coefficient": "1",
            "status": "UNRESOLVED",
            "source": "Diamond 2025/1015 honest-verifier ideal-vector-oracle discussion",
            "bound": None,
        },
        {
            "id": "malicious_verifier_zk_composition",
            "symbol": "epsilon_MaliciousVerifierZK(lambda)",
            "coefficient": "1",
            "status": "UNRESOLVED",
            "source": "2026/307 abstract IOP composition",
            "bound": None,
        },
        {
            "id": "semantic_state_composition",
            "symbol": "epsilon_SemanticStateComposition(lambda)",
            "coefficient": "1",
            "status": "UNRESOLVED",
            "source": "No primary theorem for this native-v3 composition",
            "bound": None,
        },
        {
            "id": "abort_retry_union",
            "symbol": "epsilon_AbortRetryUnion(lambda,retry_cap)",
            "coefficient": "retry_cap * session_count",
            "status": "UNRESOLVED",
            "source": "No pinned abort/retry/grinding composition theorem",
            "bound": None,
        },
        {
            "id": "verifier_challenge_authentication",
            "symbol": "epsilon_VerifierChallengeAuthentication(lambda)",
            "coefficient": "1",
            "status": "UNRESOLVED",
            "source": "Fixture HMAC tag only; no production PQ authority selected",
            "bound": None,
        },
    ]
    ledger: dict[str, Any] = {
        "schema": "BL/NATIVE-V3/TRUST-BOUNDARY-SECURITY-LEDGER/v1",
        "profile_id": PROFILE_ID.hex(),
        "proof_backend_selected": False,
        "proof_suite_id": None,
        "complete_bound_available": False,
        "production_usable": False,
        "activation": False,
        "parameter_set": parameter_set,
        "dp24": {
            "theorem": "ePrint_2024_504_Theorem_4_17",
            "construction": "4.12",
            "model": "ideal-vector-oracle-only",
            "parameter_set_id": parameter_set["id"],
            "status": "UNKNOWN",
            "formulas": {
                "epsilon_extraction_plus_sumcheck": "((2^(ell+rate_R))+(2*ell))/2^field_degree",
                "epsilon_query": "(1/2+1/(2*2^rate_R))^gamma",
                "epsilon_union": "instances*(epsilon_extraction_plus_sumcheck+epsilon_query)",
            },
            "exact_rational_arithmetic": {
                "status": "DEFERRED_UNTIL_PARAMETER_PROVENANCE",
                "used": False,
                "reason": "at least one DP24 parameter is UNKNOWN; numeric epsilon and security bits are suppressed",
            },
            "epsilon_extraction_plus_sumcheck_fraction": None,
            "epsilon_query_fraction": None,
            "epsilon_single_fraction": None,
            "epsilon_union_fraction": None,
            "epsilon_single_decimal": None,
            "epsilon_union_decimal": None,
            "bits_single_decimal": None,
            "bits_union_decimal": None,
        },
        "implementation_attestation": implementation_attestation,
        "unresolved_terms": unresolved,
        "zero_placeholders_allowed": False,
        "nonclaims": [
            "no proof backend",
            "no ZK",
            "no concrete vector-commitment binding reduction",
            "no salted-leaf hiding theorem",
            "no semantic/state proof composition",
            "no production challenge authentication",
            "no production usability or activation",
        ],
    }
    validate_security_ledger(ledger)
    return ledger


def validate_security_ledger(ledger: dict[str, Any]) -> None:
    if ledger.get("complete_bound_available") is not False:
        raise ProfileError("ledger:complete-bound-must-be-false")
    if ledger.get("production_usable") is not False or ledger.get("activation") is not False:
        raise ProfileError("ledger:production-flags")
    if ledger.get("proof_backend_selected") is not False or ledger.get("proof_suite_id") is not None:
        raise ProfileError("ledger:backend-selected")
    expected_parameter_set = _parameter_set()
    if ledger.get("parameter_set") != expected_parameter_set:
        raise ProfileError("ledger:parameter-provenance")
    if ledger.get("implementation_attestation") != _verified_implementation_attestation():
        raise ProfileError("ledger:implementation-attestation")
    dp24 = ledger.get("dp24")
    if not isinstance(dp24, dict) or dp24.get("status") != "UNKNOWN" or dp24.get("parameter_set_id") != expected_parameter_set["id"]:
        raise ProfileError("ledger:dp24-unknown-status")
    if any(dp24.get(name) is not None for name in ("epsilon_single_fraction", "epsilon_union_fraction", "bits_single_decimal", "bits_union_decimal")):
        raise ProfileError("ledger:numeric-claim-with-unknown-parameters")
    terms = ledger.get("unresolved_terms")
    if not isinstance(terms, list) or not terms:
        raise ProfileError("ledger:terms-missing")
    for term in terms:
        if term.get("status") != "UNRESOLVED":
            raise ProfileError(f"ledger:term-not-unresolved:{term.get('id')}")
        if term.get("bound") is not None:
            raise ProfileError(f"ledger:caller-bound-forbidden:{term.get('id')}")
        if not term.get("symbol") or not term.get("coefficient") or not term.get("source"):
            raise ProfileError(f"ledger:term-incomplete:{term.get('id')}")
    if ledger.get("zero_placeholders_allowed") is not False:
        raise ProfileError("ledger:zero-placeholders")


def profile_manifest() -> dict[str, Any]:
    bindings = build_profile_bindings()
    security_ledger = build_security_ledger()
    return {
        "schema": "BL/NATIVE-V3/TRUST-BOUNDARY-PROFILE/v1",
        "profile_name": PROFILE_NAME,
        "profile_id": PROFILE_ID.hex(),
        "status": "TRUST_BOUNDARY_ONLY",
        "proof_backend_selected": False,
        "proof_suite_id": None,
        "complete_bound_available": False,
        "production_usable": False,
        "activation": False,
        "fixture_only": True,
        "implementation_attestation": security_ledger["implementation_attestation"],
        "phase0_binding_ids": {
            "attempt_id": bindings.attempt_id.hex(),
            "phase0_statement_digest": bindings.phase0_statement_digest.hex(),
            "source_root": bindings.source_root.hex(),
            "control_set_id": bindings.control_set_id.hex(),
            "decision_access_join_id": bindings.decision_access_join_id.hex(),
            "frozen_receipt_binding": bindings.frozen_receipt_binding.hex(),
            "completeness_id": bindings.completeness_id.hex(),
            "chronology_id": bindings.chronology_id.hex(),
            "replay_id": bindings.replay_id.hex(),
            "exception_id_or_sentinel": bindings.exception_id_or_sentinel.hex(),
            "state_before_id": bindings.state_before_id.hex(),
            "state_after_id": bindings.state_after_id.hex(),
        },
        "grammar": CANONICAL_GRAMMAR,
        "verifier_owned_public_bindings": {
            "profile_id": PROFILE_ID.hex(),
            "phase0_statement_digest": bindings.phase0_statement_digest.hex(),
            "source_root": bindings.source_root.hex(),
            "phase0_typed_receipt": {
                "policy_result_code": DIRECTIVE_POLICY_RESULT[DIRECTIVE_CLEAR],
                "policy_result": "PASS",
                "effective_directive_code": DIRECTIVE_CLEAR,
                "effective_directive": DIRECTIVE_NAMES[DIRECTIVE_CLEAR],
                "receipt_binding": bindings.frozen_receipt_binding.hex(),
                "exception_id_or_sentinel": bindings.exception_id_or_sentinel.hex(),
                "economic_clearance": "profile fixture only; verifier acceptance is never CLEAR",
            },
            "automatic_control_set": {
                "control_set_id": bindings.control_set_id.hex(),
                "owner": "verifier",
                "rule_order": [EXPECTED_RULE_ID.hex()],
                "conflict_policy": "priority-then-human-review",
                "scope": "SHA3-512(BL/NATIVE-V3/TBP/SCOPE/v1\\0,synthetic-subject-payment-scope-v1)",
                "effective_interval": [0, 16],
                "directive_mapping": [1, 1, 2, 2, 3, 3, 4, 4, 5, 5],
            },
            "decision_access_join": {
                "join_id": bindings.decision_access_join_id.hex(),
                "decision_row_count": 1,
                "state_access_row_count": 2,
                "access_order": ["read", "write"],
                "access_indices": [0, 1],
                "access_value_binding": [
                    "access[0].value == operation.value_before",
                    "access[1].value == operation.value_after",
                ],
                "operation_index": 0,
                "canonical_join": "u32(decision_count)||operation_row||u32(access_count)||ordered_state_access_rows",
            },
            "frozen_receipt": bindings.frozen_receipt_binding.hex(),
            "completeness_or_nonmembership": {
                "completeness_id": bindings.completeness_id.hex(),
                "source_root": bindings.source_root.hex(),
                "subject_leaf": "registered source leaf bound by Phase-0 fixture",
                "observation_time": bindings.observation_time,
                "complete": True,
                "absence_authorized": False,
            },
            "chronology": {
                "chronology_id": bindings.chronology_id.hex(),
                "event_time": bindings.event_time,
                "observation_time": bindings.observation_time,
                "rule_effective_time": bindings.rule_effective_time,
                "decision_time": bindings.decision_time,
                "sequence_before": bindings.statement_sequence_before,
                "sequence_after": bindings.statement_sequence_after,
            },
            "replay": {
                "replay_id": bindings.replay_id.hex(),
                "attempt_id": bindings.attempt_id.hex(),
                "retry_cap": MAX_RETRIES,
                "exception_id_or_sentinel": bindings.exception_id_or_sentinel.hex(),
            },
            "state_transition": {
                "before_state_root": bindings.state_before_id.hex(),
                "after_state_root": bindings.state_after_id.hex(),
                "exact_transition": "one chronological read/write transition; profile evidence only",
            },
        },
        "retry_cap": MAX_RETRIES,
        "security_ledger": "security_ledger.json",
        "security_ledger_status": security_ledger["dp24"]["status"],
        "security_parameter_set_id": security_ledger["parameter_set"]["id"],
        "nonclaims": [
            "protocol-boundary evidence only",
            "no ZK or native hiding claim",
            "no VC collapse/binding claim",
            "no source membership or policy proof",
            "no state transition authorization",
        ],
    }


def json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, indent=2).encode("utf-8") + b"\n"


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("manifest", "ledger"))
    args = parser.parse_args()
    payload = profile_manifest() if args.command == "manifest" else build_security_ledger()
    print(json.dumps(payload, sort_keys=True, indent=2))
