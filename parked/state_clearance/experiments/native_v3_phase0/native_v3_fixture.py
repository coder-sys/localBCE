"""Small native-v3 Phase-0 canonicalization and witness KAT.

This module owns no proof backend.  It freezes the byte boundary that a future
native verifier must receive and provides a deterministic plaintext reference
check for one synthetic record/operation transition.  The plaintext check is
not a proof and has no production authority.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
import sys
from typing import Sequence


class CanonicalError(ValueError):
    """Raised for any noncanonical or context-incompatible byte sequence."""


def _digest(domain: bytes, *parts: bytes) -> bytes:
    hasher = hashlib.sha3_512()
    hasher.update(domain)
    for part in parts:
        hasher.update(part)
    return hasher.digest()


def _u16(value: int) -> bytes:
    return value.to_bytes(2, "big", signed=False)


def _u32(value: int) -> bytes:
    return value.to_bytes(4, "big", signed=False)


def _u64(value: int) -> bytes:
    return value.to_bytes(8, "big", signed=False)


def _read(data: bytes, offset: int, length: int, label: str) -> tuple[bytes, int]:
    end = offset + length
    if end > len(data):
        raise CanonicalError(f"{label}:truncated")
    return data[offset:end], end


def _nonzero(value: bytes, label: str) -> bytes:
    if len(value) != 64 or not any(value):
        raise CanonicalError(f"{label}:zero-or-wrong-width")
    return value


def _expect(value: bytes, expected: bytes, label: str) -> None:
    if value != expected:
        raise CanonicalError(f"{label}:mismatch")


STATEMENT_MAGIC = b"BLNV3ST1"
STATEMENT_PROTOCOL_VERSION = 3
STATEMENT_FLAGS = 0
STATEMENT_BYTES = 556
NULL_PROOF_SUITE = b"\0" * 64

CONTEXT_MAGIC = b"BLNV3CX1"
CONTEXT_VERSION = 1
CONTEXT_BYTES = 8 + 2 + 2 + 64 * 6
CONTEXT_DOMAIN = b"BL/NATIVE-V3/EXECUTION-CONTEXT/v1\0"

SOURCE_LEAF_MAGIC = b"BLNV3SL1"
SOURCE_LEAF_VERSION = 1
SOURCE_LEAF_BYTES = 212
SOURCE_LEAF_DOMAIN = b"BL/NATIVE-V3/SOURCE-REGISTRY-LEAF/v1\0"
SOURCE_PAYLOAD_DOMAIN = b"BL/NATIVE-V3/SOURCE-PAYLOAD/v1\0"

OP_ROW_MAGIC = b"BLNV3OR1"
OP_ROW_VERSION = 1
OP_ROW_BYTES = 480
OP_ROW_DOMAIN = b"BL/NATIVE-V3/ORDERED-OPERATION-ROW/v1\0"
OPERATION_KIND_DECISION = 1
ACCESS_READ = 0
ACCESS_WRITE = 1

# The operation row carries the underlying deterministic result separately
# from the effective clearance directive.  A directive is never inferred from
# proof acceptance, and an exception is never represented by a caller boolean.
POLICY_RESULT_PASS = 1
POLICY_RESULT_MISSING_EVIDENCE = 2
POLICY_RESULT_AMBIGUOUS = 3
POLICY_RESULT_FAIL = 4
DIRECTIVE_CLEAR = 1
DIRECTIVE_HOLD = 2
DIRECTIVE_HUMAN_REVIEW = 3
DIRECTIVE_BLOCK = 4
DIRECTIVE_EXCEPTION_APPROVED = 5
DIRECTIVE_NAMES = {
    DIRECTIVE_CLEAR: "CLEAR",
    DIRECTIVE_HOLD: "HOLD",
    DIRECTIVE_HUMAN_REVIEW: "HUMAN_REVIEW",
    DIRECTIVE_BLOCK: "BLOCK",
    DIRECTIVE_EXCEPTION_APPROVED: "EXCEPTION_APPROVED",
}
DIRECTIVE_POLICY_RESULT = {
    DIRECTIVE_CLEAR: POLICY_RESULT_PASS,
    DIRECTIVE_HOLD: POLICY_RESULT_MISSING_EVIDENCE,
    DIRECTIVE_HUMAN_REVIEW: POLICY_RESULT_AMBIGUOUS,
    DIRECTIVE_BLOCK: POLICY_RESULT_FAIL,
    # An exception preserves the underlying failed policy result.
    DIRECTIVE_EXCEPTION_APPROVED: POLICY_RESULT_FAIL,
}
NO_EXCEPTION_SENTINEL = b"\xe0" + b"\0" * 63
CLEARANCE_AUDIT_ONLY = 0
CLEARANCE_ADVANCED = 1

AUTH_MAGIC = b"BLNV3EA1"
AUTH_VERSION = 1
AUTH_BYTES = 484
AUTH_ID_DOMAIN = b"BL/NATIVE-V3/EXCEPTION-AUTHORIZATION-ID/v1\0"
AUTH_SIGNATURE_DOMAIN = b"BL/NATIVE-V3/SYNTHETIC-AUTHORIZATION-SEAL/v1\0"
AUTH_CURRENT_TIME = 8

STATE_MAGIC = b"BLNV3SC1"
STATE_VERSION = 1
STATE_BYTES = 832
STATE_LAYOUT_ID = _digest(b"BL/NATIVE-V3/STATE-LAYOUT/v1\0", b"one-row-transition")
STATE_ID_DOMAIN = b"BL/NATIVE-V3/STATE-ID/v1\0"
STATE_REGISTRY_DOMAIN = b"BL/NATIVE-V3/SOURCE-REGISTRY-ROOT/v1\0"
STATE_OPERATION_DOMAIN = b"BL/NATIVE-V3/OPERATION-ROOT/v1\0"
STATE_SEMANTIC_DOMAIN = b"BL/NATIVE-V3/SEMANTIC-DECISION/v1\0"
PRIVATE_BATCH_DOMAIN = b"BL/NATIVE-V3/PRIVATE-BATCH/v1\0"
SETTLEMENT_DOMAIN = b"BL/NATIVE-V3/SETTLEMENT/v1\0"
TRUSTED_AUTHORIZER_ID = _digest(
    b"BL/NATIVE-V3/AUTHORIZER/v1\0", b"synthetic-state-authorizer-v1"
)
EXPECTED_RULE_ID = _digest(b"BL/NATIVE-V3/RULE/v1\0", b"synthetic-clearance-rule-v1")
EXPECTED_REASON_ID = _digest(
    b"BL/NATIVE-V3/EXCEPTION-REASON/v1\0", b"synthetic-governed-reason-v1"
)
EXPECTED_AMOUNT_SCOPE = _digest(
    b"BL/NATIVE-V3/AMOUNT-SCOPE/v1\0", b"synthetic-amount-scope-v1"
)


@dataclass(frozen=True)
class ContextRegistry:
    profile_id: bytes
    schema_id: bytes
    program_id: bytes
    verifier_id: bytes
    backend_candidate_id: bytes
    statement_grammar_id: bytes

    def __post_init__(self) -> None:
        for label, value in self._fields():
            _nonzero(value, label)

    def _fields(self) -> tuple[tuple[str, bytes], ...]:
        return (
            ("profile_id", self.profile_id),
            ("schema_id", self.schema_id),
            ("program_id", self.program_id),
            ("verifier_id", self.verifier_id),
            ("backend_candidate_id", self.backend_candidate_id),
            ("statement_grammar_id", self.statement_grammar_id),
        )

    def canonical_bytes(self) -> bytes:
        return b"".join(
            (
                CONTEXT_MAGIC,
                _u16(CONTEXT_VERSION),
                _u16(0),
                *(value for _, value in self._fields()),
            )
        )

    @property
    def execution_context_id(self) -> bytes:
        return _digest(CONTEXT_DOMAIN, self.canonical_bytes())

    @classmethod
    def parse(cls, data: bytes) -> "ContextRegistry":
        if len(data) != CONTEXT_BYTES:
            raise CanonicalError("context:length")
        _expect(data[:8], CONTEXT_MAGIC, "context:magic")
        _expect(data[8:10], _u16(CONTEXT_VERSION), "context:version")
        _expect(data[10:12], _u16(0), "context:flags")
        values: list[bytes] = []
        offset = 12
        for index in range(6):
            value, offset = _read(data, offset, 64, f"context:field-{index}")
            values.append(_nonzero(value, f"context:field-{index}"))
        if offset != len(data):
            raise CanonicalError("context:trailing")
        return cls(*values)


@dataclass(frozen=True)
class StatementV3:
    execution_context_id: bytes
    settlement_domain_id: bytes
    epoch: int
    sequence_before: int
    sequence_after: int
    state_before_id: bytes
    state_after_id: bytes
    governance_snapshot_id: bytes
    private_batch_commitment: bytes
    settlement_commitment: bytes
    proof_suite_id: bytes | None = None

    def __post_init__(self) -> None:
        _nonzero(self.execution_context_id, "statement:execution-context")
        _nonzero(self.settlement_domain_id, "statement:settlement-domain")
        if self.sequence_after != self.sequence_before + 1:
            raise CanonicalError("statement:sequence-not-one-transition")
        for label, value in (
            ("state-before", self.state_before_id),
            ("state-after", self.state_after_id),
            ("governance", self.governance_snapshot_id),
            ("private-batch", self.private_batch_commitment),
            ("settlement", self.settlement_commitment),
        ):
            _nonzero(value, f"statement:{label}")
        if self.proof_suite_id is not None:
            _nonzero(self.proof_suite_id, "statement:proof-suite")

    def canonical_bytes(self) -> bytes:
        suite_marker = b"\0" if self.proof_suite_id is None else b"\1"
        suite_value = NULL_PROOF_SUITE if self.proof_suite_id is None else self.proof_suite_id
        result = b"".join(
            (
                STATEMENT_MAGIC,
                _u16(STATEMENT_PROTOCOL_VERSION),
                _u16(STATEMENT_FLAGS),
                suite_marker,
                b"\0\0\0",
                _u32(STATEMENT_BYTES),
                suite_value,
                self.execution_context_id,
                self.settlement_domain_id,
                _u64(self.epoch),
                _u64(self.sequence_before),
                _u64(self.sequence_after),
                self.state_before_id,
                self.state_after_id,
                self.governance_snapshot_id,
                self.private_batch_commitment,
                self.settlement_commitment,
            )
        )
        if len(result) != STATEMENT_BYTES:
            raise AssertionError(f"statement internal length {len(result)}")
        return result

    @classmethod
    def parse(cls, data: bytes, context: ContextRegistry | None = None) -> "StatementV3":
        if len(data) != STATEMENT_BYTES:
            raise CanonicalError("statement:length")
        _expect(data[:8], STATEMENT_MAGIC, "statement:magic")
        _expect(data[8:10], _u16(STATEMENT_PROTOCOL_VERSION), "statement:version")
        _expect(data[10:12], _u16(STATEMENT_FLAGS), "statement:flags")
        marker = data[12]
        if marker not in (0, 1) or data[13:16] != b"\0\0\0":
            raise CanonicalError("statement:suite-marker-or-reserved")
        _expect(data[16:20], _u32(STATEMENT_BYTES), "statement:declared-length")
        suite_raw = data[20:84]
        if marker == 0:
            _expect(suite_raw, NULL_PROOF_SUITE, "statement:null-suite-bytes")
            suite = None
        else:
            suite = _nonzero(suite_raw, "statement:proof-suite")
        execution_context_id = _nonzero(data[84:148], "statement:execution-context")
        if context is not None and execution_context_id != context.execution_context_id:
            raise CanonicalError("statement:unknown-execution-context")
        statement = cls(
            execution_context_id=execution_context_id,
            settlement_domain_id=_nonzero(data[148:212], "statement:settlement-domain"),
            epoch=int.from_bytes(data[212:220], "big"),
            sequence_before=int.from_bytes(data[220:228], "big"),
            sequence_after=int.from_bytes(data[228:236], "big"),
            state_before_id=_nonzero(data[236:300], "statement:state-before"),
            state_after_id=_nonzero(data[300:364], "statement:state-after"),
            governance_snapshot_id=_nonzero(data[364:428], "statement:governance"),
            private_batch_commitment=_nonzero(data[428:492], "statement:private-batch"),
            settlement_commitment=_nonzero(data[492:556], "statement:settlement"),
            proof_suite_id=suite,
        )
        # The field offsets above intentionally include the fixed header and
        # all five 64-byte identities.  Keep this explicit check so an edit to
        # the grammar cannot silently change the wire width.
        if len(statement.canonical_bytes()) != len(data):
            raise CanonicalError("statement:noncanonical-reencoding")
        return statement


@dataclass(frozen=True)
class SourceRegistryLeaf:
    record_id: bytes
    payload_commitment: bytes
    governance_snapshot_id: bytes
    source_kind: int = 1

    def canonical_bytes(self) -> bytes:
        if self.source_kind != 1:
            raise CanonicalError("source-leaf:kind")
        result = b"".join(
            (
                SOURCE_LEAF_MAGIC,
                _u16(SOURCE_LEAF_VERSION),
                _u16(0),
                bytes((self.source_kind,)),
                b"\0\0\0",
                _u32(64),
                _nonzero(self.record_id, "source-leaf:record-id"),
                _nonzero(self.payload_commitment, "source-leaf:payload"),
                _nonzero(self.governance_snapshot_id, "source-leaf:governance"),
            )
        )
        if len(result) != SOURCE_LEAF_BYTES:
            raise AssertionError("source leaf length")
        return result

    @property
    def leaf_id(self) -> bytes:
        return _digest(SOURCE_LEAF_DOMAIN, self.canonical_bytes())

    @classmethod
    def parse(cls, data: bytes) -> "SourceRegistryLeaf":
        if len(data) != SOURCE_LEAF_BYTES:
            raise CanonicalError("source-leaf:length")
        _expect(data[:8], SOURCE_LEAF_MAGIC, "source-leaf:magic")
        _expect(data[8:10], _u16(SOURCE_LEAF_VERSION), "source-leaf:version")
        _expect(data[10:12], _u16(0), "source-leaf:flags")
        if data[12] != 1 or data[13:16] != b"\0\0\0":
            raise CanonicalError("source-leaf:kind-or-reserved")
        _expect(data[16:20], _u32(64), "source-leaf:payload-length")
        leaf = cls(
            record_id=_nonzero(data[20:84], "source-leaf:record-id"),
            payload_commitment=_nonzero(data[84:148], "source-leaf:payload"),
            governance_snapshot_id=_nonzero(data[148:212], "source-leaf:governance"),
        )
        if leaf.canonical_bytes() != data:
            raise CanonicalError("source-leaf:noncanonical-reencoding")
        return leaf


@dataclass(frozen=True)
class ExceptionAuthorization:
    """Fixed authorization record used by the synthetic boundary KAT.

    The record carries every field the native-v3 boundary must cover.  The
    deterministic SHA3 seal is deliberately a KAT-only placeholder for the
    future verifier-owned PQ signature; it is not a production signature or
    a proof of authorization.
    """

    authorization_id: bytes
    signer_id: bytes
    subject_id: bytes
    rule_id: bytes
    reason_id: bytes
    amount_scope: bytes
    effective_at: int
    expires_at: int
    policy_result: int
    signature: bytes

    @classmethod
    def from_fields(
        cls,
        signer_id: bytes,
        subject_id: bytes,
        rule_id: bytes,
        reason_id: bytes,
        amount_scope: bytes,
        effective_at: int,
        expires_at: int,
        policy_result: int,
    ) -> "ExceptionAuthorization":
        provisional = cls(
            authorization_id=b"\0" * 64,
            signer_id=signer_id,
            subject_id=subject_id,
            rule_id=rule_id,
            reason_id=reason_id,
            amount_scope=amount_scope,
            effective_at=effective_at,
            expires_at=expires_at,
            policy_result=policy_result,
            signature=b"\0" * 64,
        )
        body = provisional.body_bytes()
        authorization_id = _digest(AUTH_ID_DOMAIN, body)
        signature = _digest(AUTH_SIGNATURE_DOMAIN, signer_id, body)
        return cls(
            authorization_id=authorization_id,
            signer_id=signer_id,
            subject_id=subject_id,
            rule_id=rule_id,
            reason_id=reason_id,
            amount_scope=amount_scope,
            effective_at=effective_at,
            expires_at=expires_at,
            policy_result=policy_result,
            signature=signature,
        )

    def body_bytes(self) -> bytes:
        if self.effective_at >= self.expires_at:
            raise CanonicalError("exception:interval")
        if self.policy_result not in {
            POLICY_RESULT_PASS,
            POLICY_RESULT_MISSING_EVIDENCE,
            POLICY_RESULT_AMBIGUOUS,
            POLICY_RESULT_FAIL,
        }:
            raise CanonicalError("exception:policy-result")
        return b"".join(
            (
                AUTH_MAGIC,
                _u16(AUTH_VERSION),
                _u16(0),
                _nonzero(self.signer_id, "exception:signer"),
                _nonzero(self.subject_id, "exception:subject"),
                _nonzero(self.rule_id, "exception:rule"),
                _nonzero(self.reason_id, "exception:reason"),
                _nonzero(self.amount_scope, "exception:amount-scope"),
                _u64(self.effective_at),
                _u64(self.expires_at),
                bytes((self.policy_result,)),
                b"\0" * 7,
            )
        )

    def canonical_bytes(self) -> bytes:
        body = self.body_bytes()
        _nonzero(self.authorization_id, "exception:authorization-id")
        _nonzero(self.signature, "exception:signature")
        if self.authorization_id != _digest(AUTH_ID_DOMAIN, body):
            raise CanonicalError("exception:authorization-id-seal")
        if self.signature != _digest(AUTH_SIGNATURE_DOMAIN, self.signer_id, body):
            raise CanonicalError("exception:signature-seal")
        result = b"".join(
            (
                AUTH_MAGIC,
                _u16(AUTH_VERSION),
                _u16(0),
                self.authorization_id,
                self.signer_id,
                self.subject_id,
                self.rule_id,
                self.reason_id,
                self.amount_scope,
                _u64(self.effective_at),
                _u64(self.expires_at),
                bytes((self.policy_result,)),
                b"\0" * 7,
                self.signature,
            )
        )
        if len(result) != AUTH_BYTES:
            raise AssertionError("exception authorization length")
        return result

    @classmethod
    def parse(cls, data: bytes) -> "ExceptionAuthorization":
        if len(data) != AUTH_BYTES:
            raise CanonicalError("exception:length")
        _expect(data[:8], AUTH_MAGIC, "exception:magic")
        _expect(data[8:10], _u16(AUTH_VERSION), "exception:version")
        _expect(data[10:12], _u16(0), "exception:flags")
        if data[413:420] != b"\0" * 7:
            raise CanonicalError("exception:reserved")
        authorization = cls(
            authorization_id=_nonzero(data[12:76], "exception:authorization-id"),
            signer_id=_nonzero(data[76:140], "exception:signer"),
            subject_id=_nonzero(data[140:204], "exception:subject"),
            rule_id=_nonzero(data[204:268], "exception:rule"),
            reason_id=_nonzero(data[268:332], "exception:reason"),
            amount_scope=_nonzero(data[332:396], "exception:amount-scope"),
            effective_at=int.from_bytes(data[396:404], "big"),
            expires_at=int.from_bytes(data[404:412], "big"),
            policy_result=data[412],
            signature=_nonzero(data[420:484], "exception:signature"),
        )
        if authorization.canonical_bytes() != data:
            raise CanonicalError("exception:noncanonical-reencoding")
        return authorization


@dataclass(frozen=True)
class OrderedOperationRow:
    operation_index: int
    operation_count: int
    settlement_domain_id: bytes
    source_record_id: bytes
    address: bytes
    key: bytes
    value_before: bytes
    value_after: bytes
    policy_result: int
    effective_directive: int
    exception_authorization_id: bytes = NO_EXCEPTION_SENTINEL
    operation_kind: int = OPERATION_KIND_DECISION
    access_mode: int = ACCESS_WRITE

    def canonical_bytes(self) -> bytes:
        if self.operation_index >= self.operation_count:
            raise CanonicalError("operation-row:index")
        if self.operation_count != 1:
            raise CanonicalError("operation-row:fixture-count")
        if self.operation_kind != OPERATION_KIND_DECISION:
            raise CanonicalError("operation-row:kind")
        if self.access_mode != ACCESS_WRITE:
            raise CanonicalError("operation-row:mode")
        if self.policy_result not in {
            POLICY_RESULT_PASS,
            POLICY_RESULT_MISSING_EVIDENCE,
            POLICY_RESULT_AMBIGUOUS,
            POLICY_RESULT_FAIL,
        }:
            raise CanonicalError("operation-row:policy-result")
        if self.effective_directive not in DIRECTIVE_NAMES:
            raise CanonicalError("operation-row:directive")
        if self.policy_result != DIRECTIVE_POLICY_RESULT[self.effective_directive]:
            raise CanonicalError("operation-row:directive-policy-mismatch")
        if self.effective_directive == DIRECTIVE_EXCEPTION_APPROVED:
            if self.exception_authorization_id == NO_EXCEPTION_SENTINEL:
                raise CanonicalError("operation-row:exception-required")
            _nonzero(self.exception_authorization_id, "operation-row:exception-id")
        elif self.exception_authorization_id != NO_EXCEPTION_SENTINEL:
            raise CanonicalError("operation-row:exception-sentinel")
        result = b"".join(
            (
                OP_ROW_MAGIC,
                _u16(OP_ROW_VERSION),
                _u16(0),
                _u32(self.operation_index),
                _u32(self.operation_count),
                bytes((self.operation_kind, self.access_mode)),
                b"\0\0",
                _nonzero(self.settlement_domain_id, "operation-row:domain"),
                _nonzero(self.source_record_id, "operation-row:record-id"),
                _nonzero(self.address, "operation-row:address"),
                _nonzero(self.key, "operation-row:key"),
                _nonzero(self.value_before, "operation-row:before"),
                _nonzero(self.value_after, "operation-row:after"),
                bytes((self.policy_result, self.effective_directive)),
                _nonzero(self.exception_authorization_id, "operation-row:exception-id"),
                b"\0" * 6,
            )
        )
        if len(result) != OP_ROW_BYTES:
            raise AssertionError("operation row length")
        return result

    @property
    def row_id(self) -> bytes:
        return _digest(OP_ROW_DOMAIN, self.canonical_bytes())

    @classmethod
    def parse(cls, data: bytes) -> "OrderedOperationRow":
        if len(data) != OP_ROW_BYTES:
            raise CanonicalError("operation-row:length")
        _expect(data[:8], OP_ROW_MAGIC, "operation-row:magic")
        _expect(data[8:10], _u16(OP_ROW_VERSION), "operation-row:version")
        _expect(data[10:12], _u16(0), "operation-row:flags")
        if data[20:22] != bytes((OPERATION_KIND_DECISION, ACCESS_WRITE)) or data[22:24] != b"\0\0":
            raise CanonicalError("operation-row:kind-or-mode")
        if data[474:480] != b"\0" * 6:
            raise CanonicalError("operation-row:trailing-reserved")
        row = cls(
            operation_index=int.from_bytes(data[12:16], "big"),
            operation_count=int.from_bytes(data[16:20], "big"),
            settlement_domain_id=_nonzero(data[24:88], "operation-row:domain"),
            source_record_id=_nonzero(data[88:152], "operation-row:record-id"),
            address=_nonzero(data[152:216], "operation-row:address"),
            key=_nonzero(data[216:280], "operation-row:key"),
            value_before=_nonzero(data[280:344], "operation-row:before"),
            value_after=_nonzero(data[344:408], "operation-row:after"),
            policy_result=data[408],
            effective_directive=data[409],
            exception_authorization_id=_nonzero(data[410:474], "operation-row:exception-id"),
        )
        if row.canonical_bytes() != data:
            raise CanonicalError("operation-row:noncanonical-reencoding")
        return row


@dataclass(frozen=True)
class AccessEvent:
    operation_index: int
    mode: int
    value: bytes


@dataclass(frozen=True)
class StateCommitment:
    context_id: bytes
    sequence: int
    source_registry_root: bytes
    operation_root: bytes
    semantic_root: bytes
    clearance_state: int
    row_count: int
    row_slot: bytes

    def canonical_bytes(self) -> bytes:
        if self.row_count not in (0, 1) or len(self.row_slot) != OP_ROW_BYTES:
            raise CanonicalError("state:geometry")
        if self.clearance_state not in (CLEARANCE_AUDIT_ONLY, CLEARANCE_ADVANCED):
            raise CanonicalError("state:clearance-state")
        if self.row_count == 0 and self.clearance_state != CLEARANCE_AUDIT_ONLY:
            raise CanonicalError("state:empty-clearance-state")
        result = b"".join(
            (
                STATE_MAGIC,
                _u16(STATE_VERSION),
                _u16(0),
                STATE_LAYOUT_ID,
                _nonzero(self.context_id, "state:context"),
                _u64(self.sequence),
                _u32(1),
                _u32(self.row_count),
                _nonzero(self.source_registry_root, "state:source-root"),
                _nonzero(self.operation_root, "state:operation-root"),
                _nonzero(self.semantic_root, "state:semantic-root"),
                bytes((self.clearance_state,)),
                b"\0" * 3,
                self.row_slot,
            )
        )
        if len(result) != STATE_BYTES:
            raise AssertionError("state commitment length")
        return result

    @property
    def state_id(self) -> bytes:
        encoded = self.canonical_bytes()
        return _digest(
            STATE_ID_DOMAIN,
            self.context_id,
            _u64(self.sequence),
            STATE_LAYOUT_ID,
            _u32(1),
            _u64(len(encoded)),
            encoded,
        )


@dataclass(frozen=True)
class Fixture:
    context: ContextRegistry
    statement: StatementV3
    source_payload: bytes
    source_leaf: SourceRegistryLeaf
    operation: OrderedOperationRow
    exception_authorization: ExceptionAuthorization | None
    before_state: StateCommitment
    after_state: StateCommitment
    accesses: tuple[AccessEvent, AccessEvent]


def _fixture_context() -> ContextRegistry:
    def item(label: bytes) -> bytes:
        return _digest(b"BL/NATIVE-V3/CONTEXT-ITEM/v1\0", label)

    return ContextRegistry(
        profile_id=item(b"native-v3-phase0-cpu-one-transition"),
        schema_id=item(b"native-v3-statement-schema-v1"),
        program_id=item(b"native-v3-one-record-five-directive-v2"),
        verifier_id=item(b"native-v3-unselected-verifier-placeholder-v1"),
        backend_candidate_id=item(b"native-v3-backend-unselected-v1"),
        statement_grammar_id=item(b"native-v3-fixed-statement-556-v2-directive"),
    )


def build_fixture(effective_directive: int = DIRECTIVE_CLEAR) -> Fixture:
    context = _fixture_context()
    settlement_domain_id = _digest(b"BL/NATIVE-V3/SETTLEMENT-DOMAIN/v1\0", b"synthetic-domain")
    governance_snapshot_id = _digest(b"BL/NATIVE-V3/GOVERNANCE/v1\0", b"synthetic-governance-epoch-7")
    source_payload = b"synthetic-registered-record-native-v3-phase0".ljust(64, b"\0")
    payload_commitment = _digest(SOURCE_PAYLOAD_DOMAIN, source_payload)
    record_id = _digest(b"BL/NATIVE-V3/RECORD-ID/v1\0", payload_commitment)
    source_leaf = SourceRegistryLeaf(record_id, payload_commitment, governance_snapshot_id)
    address = _digest(b"BL/NATIVE-V3/ADDRESS/v1\0", b"synthetic-address-1")
    key = _digest(b"BL/NATIVE-V3/KEY/v1\0", b"synthetic-key-1")
    value_before = _digest(b"BL/NATIVE-V3/VALUE/v1\0", b"before")
    value_after = _digest(b"BL/NATIVE-V3/VALUE/v1\0", b"after")
    policy_result = DIRECTIVE_POLICY_RESULT[effective_directive]
    exception_authorization = None
    if effective_directive == DIRECTIVE_EXCEPTION_APPROVED:
        exception_authorization = ExceptionAuthorization.from_fields(
            signer_id=TRUSTED_AUTHORIZER_ID,
            subject_id=address,
            rule_id=EXPECTED_RULE_ID,
            reason_id=EXPECTED_REASON_ID,
            amount_scope=EXPECTED_AMOUNT_SCOPE,
            effective_at=7,
            expires_at=9,
            policy_result=policy_result,
        )
    operation = OrderedOperationRow(
        operation_index=0,
        operation_count=1,
        settlement_domain_id=settlement_domain_id,
        source_record_id=record_id,
        address=address,
        key=key,
        value_before=value_before,
        value_after=value_after,
        policy_result=policy_result,
        effective_directive=effective_directive,
        exception_authorization_id=(
            NO_EXCEPTION_SENTINEL
            if exception_authorization is None
            else exception_authorization.authorization_id
        ),
    )
    source_root = _digest(STATE_REGISTRY_DOMAIN, source_leaf.leaf_id)
    empty_operation_root = _digest(STATE_OPERATION_DOMAIN, b"empty")
    empty_semantic_root = _digest(STATE_SEMANTIC_DOMAIN, b"empty")
    before_state = StateCommitment(
        context_id=context.execution_context_id,
        sequence=7,
        source_registry_root=source_root,
        operation_root=empty_operation_root,
        semantic_root=empty_semantic_root,
        clearance_state=CLEARANCE_AUDIT_ONLY,
        row_count=0,
        row_slot=b"\0" * OP_ROW_BYTES,
    )
    operation_root = _digest(STATE_OPERATION_DOMAIN, operation.row_id)
    semantic_root = _digest(
        STATE_SEMANTIC_DOMAIN,
        bytes((operation.policy_result, operation.effective_directive)),
        operation.exception_authorization_id,
        operation.source_record_id,
        operation.value_before,
        operation.value_after,
    )
    clearance_state = (
        CLEARANCE_ADVANCED
        if effective_directive in {DIRECTIVE_CLEAR, DIRECTIVE_EXCEPTION_APPROVED}
        else CLEARANCE_AUDIT_ONLY
    )
    after_state = StateCommitment(
        context_id=context.execution_context_id,
        sequence=8,
        source_registry_root=source_root,
        operation_root=operation_root,
        semantic_root=semantic_root,
        clearance_state=clearance_state,
        row_count=1,
        row_slot=operation.canonical_bytes(),
    )
    private_batch_commitment = _digest(
        PRIVATE_BATCH_DOMAIN,
        source_leaf.leaf_id,
        operation.row_id,
        bytes((operation.policy_result, operation.effective_directive)),
        operation.exception_authorization_id,
        source_payload,
    )
    settlement_commitment = _digest(
        SETTLEMENT_DOMAIN,
        settlement_domain_id,
        operation.row_id,
        bytes((operation.effective_directive,)),
        after_state.state_id,
    )
    statement = StatementV3(
        execution_context_id=context.execution_context_id,
        settlement_domain_id=settlement_domain_id,
        epoch=7,
        sequence_before=7,
        sequence_after=8,
        state_before_id=before_state.state_id,
        state_after_id=after_state.state_id,
        governance_snapshot_id=governance_snapshot_id,
        private_batch_commitment=private_batch_commitment,
        settlement_commitment=settlement_commitment,
    )
    accesses = (
        AccessEvent(0, ACCESS_READ, value_before),
        AccessEvent(0, ACCESS_WRITE, value_after),
    )
    return Fixture(
        context,
        statement,
        source_payload,
        source_leaf,
        operation,
        exception_authorization,
        before_state,
        after_state,
        accesses,
    )


def _check_exception_authorization(
    operation: OrderedOperationRow, authorization: ExceptionAuthorization | None
) -> None:
    if operation.effective_directive != DIRECTIVE_EXCEPTION_APPROVED:
        if authorization is not None:
            raise CanonicalError("exception:unexpected-for-nonexception")
        if operation.exception_authorization_id != NO_EXCEPTION_SENTINEL:
            raise CanonicalError("exception:missing-sentinel")
        return
    if authorization is None:
        raise CanonicalError("exception:authorization-missing")
    ExceptionAuthorization.parse(authorization.canonical_bytes())
    if authorization.authorization_id != operation.exception_authorization_id:
        raise CanonicalError("exception:identity-not-row-bound")
    if authorization.signer_id != TRUSTED_AUTHORIZER_ID:
        raise CanonicalError("exception:unauthorized-signer")
    if authorization.policy_result != operation.policy_result:
        raise CanonicalError("exception:underlying-result")
    if authorization.subject_id != operation.address:
        raise CanonicalError("exception:subject-scope")
    if authorization.rule_id != EXPECTED_RULE_ID:
        raise CanonicalError("exception:rule-scope")
    if authorization.reason_id != EXPECTED_REASON_ID:
        raise CanonicalError("exception:reason-scope")
    if authorization.amount_scope != EXPECTED_AMOUNT_SCOPE:
        raise CanonicalError("exception:amount-scope")
    if not authorization.effective_at <= AUTH_CURRENT_TIME < authorization.expires_at:
        raise CanonicalError("exception:expired-or-not-effective")


def _check_operation_semantics(
    operation: OrderedOperationRow, authorization: ExceptionAuthorization | None
) -> None:
    # canonical_bytes performs the fixed enum/sentinel/policy-result checks;
    # this additional check covers the signed authorization boundary.
    OrderedOperationRow.parse(operation.canonical_bytes())
    _check_exception_authorization(operation, authorization)


def check_private_fixture(
    fixture: Fixture,
    statement_bytes: bytes,
    source_payload: bytes,
    source_leaf: SourceRegistryLeaf,
    operations: Sequence[OrderedOperationRow],
    accesses: Sequence[AccessEvent],
    before_state: StateCommitment,
    after_state: StateCommitment,
    exception_authorization: ExceptionAuthorization | None = None,
) -> None:
    statement = StatementV3.parse(statement_bytes, fixture.context)
    if source_payload != fixture.source_payload:
        raise CanonicalError("witness:source-payload")
    if source_leaf != fixture.source_leaf:
        raise CanonicalError("witness:source-leaf")
    if operations:
        _check_operation_semantics(operations[0], exception_authorization)
    if tuple(operations) != (fixture.operation,):
        raise CanonicalError("witness:operation-table")
    if tuple(accesses) != fixture.accesses:
        raise CanonicalError("witness:chronology")
    expected_clearance_state = (
        CLEARANCE_ADVANCED
        if fixture.operation.effective_directive
        in {DIRECTIVE_CLEAR, DIRECTIVE_EXCEPTION_APPROVED}
        else CLEARANCE_AUDIT_ONLY
    )
    if after_state.clearance_state != expected_clearance_state:
        raise CanonicalError("state:forbidden-economic-mutation")
    if before_state != fixture.before_state or after_state != fixture.after_state:
        raise CanonicalError("witness:state-commitment")
    if statement != fixture.statement:
        raise CanonicalError("statement:values-do-not-match-witness")


def _directive_kat(effective_directive: int) -> dict[str, object]:
    fixture = build_fixture(effective_directive)
    statement = fixture.statement.canonical_bytes()
    context_bytes = fixture.context.canonical_bytes()
    source_leaf = fixture.source_leaf.canonical_bytes()
    operation = fixture.operation.canonical_bytes()
    before_state = fixture.before_state.canonical_bytes()
    after_state = fixture.after_state.canonical_bytes()
    if ContextRegistry.parse(context_bytes) != fixture.context:
        raise AssertionError("context roundtrip")
    if SourceRegistryLeaf.parse(source_leaf) != fixture.source_leaf:
        raise AssertionError("source leaf roundtrip")
    if OrderedOperationRow.parse(operation) != fixture.operation:
        raise AssertionError("operation row roundtrip")
    if fixture.exception_authorization is not None:
        if ExceptionAuthorization.parse(fixture.exception_authorization.canonical_bytes()) != fixture.exception_authorization:
            raise AssertionError("exception authorization roundtrip")
    check_private_fixture(
        fixture,
        statement,
        fixture.source_payload,
        fixture.source_leaf,
        [fixture.operation],
        fixture.accesses,
        fixture.before_state,
        fixture.after_state,
        fixture.exception_authorization,
    )
    return {
        "directive": DIRECTIVE_NAMES[effective_directive],
        "policy_result": fixture.operation.policy_result,
        "effective_directive": fixture.operation.effective_directive,
        "exception_authorization_id": fixture.operation.exception_authorization_id.hex(),
        "exception_authorization_bytes": 0
        if fixture.exception_authorization is None
        else len(fixture.exception_authorization.canonical_bytes()),
        "clearance_state": fixture.after_state.clearance_state,
        "operation_row_bytes": len(operation),
        "operation_row_id": fixture.operation.row_id.hex(),
        "statement_bytes": len(statement),
        "statement_sha3_512": hashlib.sha3_512(statement).hexdigest(),
        "state_commitment_bytes": len(after_state),
        "state_before_id": fixture.before_state.state_id.hex(),
        "state_after_id": fixture.after_state.state_id.hex(),
        "state_after_commitment_sha3_512": hashlib.sha3_512(after_state).hexdigest(),
    }


def kat() -> dict[str, object]:
    directives = [
        DIRECTIVE_CLEAR,
        DIRECTIVE_HOLD,
        DIRECTIVE_HUMAN_REVIEW,
        DIRECTIVE_BLOCK,
        DIRECTIVE_EXCEPTION_APPROVED,
    ]
    vectors = {DIRECTIVE_NAMES[value]: _directive_kat(value) for value in directives}
    fixture = build_fixture(DIRECTIVE_CLEAR)
    return {
        "status": "NATIVE_V3_PHASE0_FIVE_DIRECTIVE_KAT_PASS",
        "directive_kats": vectors,
        "context_registry_bytes": len(fixture.context.canonical_bytes()),
        "execution_context_id": fixture.context.execution_context_id.hex(),
        "source_registry_leaf_bytes": SOURCE_LEAF_BYTES,
        "source_registry_leaf_id": fixture.source_leaf.leaf_id.hex(),
        "ordered_operation_row_bytes": OP_ROW_BYTES,
        "state_commitment_bytes": STATE_BYTES,
        "source_payload_private": True,
        "payment_authority": "OFFICIAL_EXTERNAL_PAYMENT_SYSTEM_ONLY",
        "blind_ledger_moves_money": False,
        "proof_suite_id": None,
        "production_usable": False,
        "activation": False,
        "proof_backend": "NOT_IMPLEMENTED",
        "plaintext_reference_check": True,
        "synthetic_signature_kat_only": True,
    }


def negative_report() -> dict[str, str]:
    fixture = build_fixture()
    statement = fixture.statement.canonical_bytes()
    results: dict[str, str] = {}

    def expect_reject(label: str, operation) -> None:  # type: ignore[no-untyped-def]
        try:
            operation()
        except (CanonicalError, ValueError, AssertionError) as error:
            results[label] = f"REJECT:{error}"
        else:
            results[label] = "UNEXPECTED_ACCEPT"

    def check_variant(
        variant: Fixture,
        operation: OrderedOperationRow,
        authorization: ExceptionAuthorization | None,
        after_state: StateCommitment | None = None,
    ) -> None:
        check_private_fixture(
            variant,
            variant.statement.canonical_bytes(),
            variant.source_payload,
            variant.source_leaf,
            [operation],
            variant.accesses,
            variant.before_state,
            variant.after_state if after_state is None else after_state,
            authorization,
        )

    expect_reject("wrong-statement-magic", lambda: StatementV3.parse(b"X" + statement[1:], fixture.context))
    expect_reject(
        "wrong-statement-context",
        lambda: StatementV3.parse(statement[:84] + bytes([statement[84] ^ 1]) + statement[85:], fixture.context),
    )
    expect_reject(
        "wrong-directive",
        lambda: OrderedOperationRow.parse(
            fixture.operation.canonical_bytes()[:409]
            + bytes((DIRECTIVE_HOLD,))
            + fixture.operation.canonical_bytes()[410:]
        ),
    )
    expect_reject(
        "wrong-before-state",
        lambda: check_private_fixture(
            fixture,
            statement[:236] + bytes([statement[236] ^ 1]) + statement[237:],
            fixture.source_payload,
            fixture.source_leaf,
            [fixture.operation],
            fixture.accesses,
            fixture.before_state,
            fixture.after_state,
        ),
    )
    expect_reject(
        "wrong-source-root",
        lambda: check_private_fixture(
            fixture,
            statement,
            fixture.source_payload,
            SourceRegistryLeaf(
                fixture.source_leaf.record_id,
                bytes([fixture.source_leaf.payload_commitment[0] ^ 1])
                + fixture.source_leaf.payload_commitment[1:],
                fixture.source_leaf.governance_snapshot_id,
            ),
            [fixture.operation],
            fixture.accesses,
            fixture.before_state,
            fixture.after_state,
        ),
    )
    expect_reject(
        "corruption",
        lambda: SourceRegistryLeaf.parse(
            bytes([fixture.source_leaf.canonical_bytes()[0] ^ 1])
            + fixture.source_leaf.canonical_bytes()[1:]
        ),
    )
    expect_reject(
        "reorder",
        lambda: check_private_fixture(
            fixture,
            statement,
            fixture.source_payload,
            fixture.source_leaf,
            [fixture.operation],
            [fixture.accesses[1], fixture.accesses[0]],
            fixture.before_state,
            fixture.after_state,
        ),
    )
    expect_reject(
        "omission",
        lambda: check_private_fixture(
            fixture,
            statement,
            fixture.source_payload,
            fixture.source_leaf,
            [],
            [],
            fixture.before_state,
            fixture.after_state,
        ),
    )
    expect_reject(
        "duplicate-replay",
        lambda: check_private_fixture(
            fixture,
            statement,
            fixture.source_payload,
            fixture.source_leaf,
            [fixture.operation, fixture.operation],
            [*fixture.accesses, fixture.accesses[1]],
            fixture.before_state,
            fixture.after_state,
        ),
    )
    exception_fixture = build_fixture(DIRECTIVE_EXCEPTION_APPROVED)
    valid_auth = exception_fixture.exception_authorization
    assert valid_auth is not None
    wrong_signer = _digest(b"BL/NATIVE-V3/AUTHORIZER/v1\0", b"wrong-signer")
    unauthorized = ExceptionAuthorization.from_fields(
        signer_id=wrong_signer,
        subject_id=valid_auth.subject_id,
        rule_id=valid_auth.rule_id,
        reason_id=valid_auth.reason_id,
        amount_scope=valid_auth.amount_scope,
        effective_at=valid_auth.effective_at,
        expires_at=valid_auth.expires_at,
        policy_result=valid_auth.policy_result,
    )
    expect_reject(
        "unauthorized-exception",
        lambda: check_variant(
            exception_fixture,
            replace(exception_fixture.operation, exception_authorization_id=unauthorized.authorization_id),
            unauthorized,
        ),
    )
    expired = ExceptionAuthorization.from_fields(
        signer_id=TRUSTED_AUTHORIZER_ID,
        subject_id=valid_auth.subject_id,
        rule_id=valid_auth.rule_id,
        reason_id=valid_auth.reason_id,
        amount_scope=valid_auth.amount_scope,
        effective_at=7,
        expires_at=AUTH_CURRENT_TIME,
        policy_result=valid_auth.policy_result,
    )
    expect_reject(
        "expired-exception",
        lambda: check_variant(
            exception_fixture,
            replace(exception_fixture.operation, exception_authorization_id=expired.authorization_id),
            expired,
        ),
    )
    wrong_scope = ExceptionAuthorization.from_fields(
        signer_id=TRUSTED_AUTHORIZER_ID,
        subject_id=valid_auth.subject_id,
        rule_id=valid_auth.rule_id,
        reason_id=valid_auth.reason_id,
        amount_scope=_digest(b"BL/NATIVE-V3/AMOUNT-SCOPE/v1\0", b"wrong-scope"),
        effective_at=valid_auth.effective_at,
        expires_at=valid_auth.expires_at,
        policy_result=valid_auth.policy_result,
    )
    expect_reject(
        "wrong-scope-exception",
        lambda: check_variant(
            exception_fixture,
            replace(exception_fixture.operation, exception_authorization_id=wrong_scope.authorization_id),
            wrong_scope,
        ),
    )
    blocked = build_fixture(DIRECTIVE_BLOCK)
    expect_reject(
        "forbidden-economic-mutation",
        lambda: check_variant(
            blocked,
            blocked.operation,
            None,
            replace(blocked.after_state, clearance_state=CLEARANCE_ADVANCED),
        ),
    )
    expect_reject(
        "after-state-mutation",
        lambda: check_private_fixture(
            fixture,
            statement,
            fixture.source_payload,
            fixture.source_leaf,
            [fixture.operation],
            fixture.accesses,
            fixture.before_state,
            StateCommitment(
                fixture.after_state.context_id,
                fixture.after_state.sequence,
                fixture.after_state.source_registry_root,
                fixture.after_state.operation_root,
                fixture.after_state.semantic_root,
                fixture.after_state.clearance_state,
                fixture.after_state.row_count,
                bytes([fixture.after_state.row_slot[0] ^ 1]) + fixture.after_state.row_slot[1:],
            ),
        ),
    )
    return results


def main(argv: Sequence[str]) -> int:
    if len(argv) != 2 or argv[1] not in {"kat", "negatives"}:
        print("usage: native_v3_fixture.py kat|negatives", file=sys.stderr)
        return 2
    if argv[1] == "kat":
        print(json.dumps(kat(), sort_keys=True))
        return 0
    report = negative_report()
    print(json.dumps(report, sort_keys=True))
    return 0 if report and all(value.startswith("REJECT:") for value in report.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
