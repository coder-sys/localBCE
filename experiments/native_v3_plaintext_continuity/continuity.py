"""Small, deterministic plaintext provider-continuity boundary.

This module is intentionally an application seam, not a proof backend.  The
state-owned evaluator receives only synthetic canonical records, a fixed
verifier-owned automatic control set, and authoritative completeness evidence.
It produces one read-only audit transition and a typed five-directive result.
The existing native-v3 trust-boundary profile is visible only through
``TrustBoundaryAdapter``; no private assertion is proved here.
"""

from __future__ import annotations

from dataclasses import dataclass
import ctypes
import hashlib
import json
import os
import struct
import sys
import time
import tracemalloc
from typing import Any, Mapping, Sequence

from experiments.native_v3_phase0.native_v3_fixture import (
    DIRECTIVE_BLOCK,
    DIRECTIVE_CLEAR,
    DIRECTIVE_EXCEPTION_APPROVED,
    DIRECTIVE_HOLD,
    DIRECTIVE_HUMAN_REVIEW,
    DIRECTIVE_NAMES,
    DIRECTIVE_POLICY_RESULT,
    ExceptionAuthorization,
    EXPECTED_AMOUNT_SCOPE,
    EXPECTED_REASON_ID,
    EXPECTED_RULE_ID,
    NO_EXCEPTION_SENTINEL,
    POLICY_RESULT_AMBIGUOUS,
    POLICY_RESULT_FAIL,
    POLICY_RESULT_MISSING_EVIDENCE,
    POLICY_RESULT_PASS,
    TRUSTED_AUTHORIZER_ID,
)
from experiments.native_v3_trust_boundary.profile import build_profile_bindings


class ContinuityError(ValueError):
    """Raised for any malformed, stale, conflicting, or caller-rebound input."""


VERSION = 2
MAX_FACTS = 8
MAX_BUNDLE_BYTES = 1_000_000
NULL_PROOF_SUITE = b"\0" * 64

FACT_MAGIC = b"BLCFAC02"
FACT_SET_MAGIC = b"BLCFST02"
COMPLETENESS_MAGIC = b"BLCCMP02"
REQUEST_MAGIC = b"BLCRQT02"
CONTROL_SET_MAGIC = b"BLCSET02"
STATE_MAGIC = b"BLCSTA02"
DECISION_MAGIC = b"BLCDCS02"
ACCESS_MAGIC = b"BLCACS02"
JOIN_MAGIC = b"BLCJON02"
RECEIPT_MAGIC = b"BLCREC02"
BUNDLE_MAGIC = b"BLCBND02"

FACT_ID_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/FACT-ID/v2\0"
SOURCE_ROOT_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/SOURCE-ROOT/v2\0"
SUBJECT_KEY_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/SUBJECT-KEY/v2\0"
COMPLETENESS_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/COMPLETENESS/v2\0"
REQUEST_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/REQUEST/v2\0"
REQUEST_ID_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/REQUEST-ID/v2\0"
CHRONOLOGY_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/CHRONOLOGY/v2\0"
MODE_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/EVIDENCE-MODE/v2\0"
EVALUATOR_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/EVALUATOR/v2\0"
CONTROL_SET_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/CONTROL-SET/v2\0"
STATE_CONTEXT_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/STATE-CONTEXT/v2\0"
STATE_ID_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/STATE-ID/v2\0"
AUDIT_HEAD_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/AUDIT-HEAD/v2\0"
CONTINUITY_ROOT_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/ROOT/v2\0"
DECISION_ID_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/DECISION-ID/v2\0"
DECISION_ROW_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/DECISION-ROW/v2\0"
ACCESS_ROW_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/ACCESS-ROW/v2\0"
JOIN_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/DECISION-ACCESS-JOIN/v2\0"
REPLAY_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/REPLAY/v2\0"
PATH_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/DECISION-PATH/v2\0"
RECEIPT_ID_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/RECEIPT-ID/v2\0"
BUNDLE_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/BUNDLE/v2\0"
ADAPTER_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/PLAINTEXT-ADAPTER/v2\0"
REASON_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/REASON/v2\0"
ADDRESS_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/STATE-ADDRESS/v2\0"

FACT_ACTIVE = 1
FACT_EXPIRED = 2
FACT_TERMINATED = 3
ACCESS_READ = 1
ACCESS_WRITE = 2
MODE_MARKER_DIRECT_STATE_OWNED = 1
PROOF_ACCEPTANCE_FALSE = 0
ECONOMIC_MUTATION_FALSE = 0

EVENT_TIME = 7_000
OBSERVATION_TIME = 7_001
RULE_EFFECTIVE_TIME = 6_999
CONTROL_EFFECTIVE_START = 6_000
CONTROL_EFFECTIVE_END = 9_000
DECISION_TIME = 7_002

CONTROL_SCOPE = b"provider-credential-enrollment-continuity-v1"
CONFLICT_POLICY = b"priority-then-human-review"
DIRECTIVE_MAPPING = bytes(
    (
        DIRECTIVE_CLEAR,
        DIRECTIVE_HOLD,
        DIRECTIVE_HUMAN_REVIEW,
        DIRECTIVE_BLOCK,
        DIRECTIVE_EXCEPTION_APPROVED,
    )
)


def _sha(domain: bytes, *parts: bytes) -> bytes:
    hasher = hashlib.sha3_512()
    hasher.update(domain)
    for part in parts:
        hasher.update(part)
    return hasher.digest()


def _u16(value: int) -> bytes:
    if not 0 <= value <= 0xFFFF:
        raise ContinuityError("u16:range")
    return struct.pack(">H", value)


def _u32(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFFFF:
        raise ContinuityError("u32:range")
    return struct.pack(">I", value)


def _u64(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        raise ContinuityError("u64:range")
    return struct.pack(">Q", value)


def _nonzero(value: bytes, label: str) -> bytes:
    if len(value) != 64 or not any(value):
        raise ContinuityError(f"{label}:width-or-zero")
    return value


def _read(data: bytes, offset: int, length: int, label: str) -> tuple[bytes, int]:
    if length < 0:
        raise ContinuityError(f"{label}:negative-length")
    end = offset + length
    if end < offset or end > len(data):
        raise ContinuityError(f"{label}:truncated")
    return data[offset:end], end


def _read_u32(data: bytes, offset: int, label: str) -> tuple[int, int]:
    raw, offset = _read(data, offset, 4, label)
    return int.from_bytes(raw, "big"), offset


def _read_u64(data: bytes, offset: int, label: str) -> tuple[int, int]:
    raw, offset = _read(data, offset, 8, label)
    return int.from_bytes(raw, "big"), offset


def _fixed_header(data: bytes, magic: bytes, label: str) -> int:
    if len(data) < 12:
        raise ContinuityError(f"{label}:truncated-header")
    if data[:8] != magic:
        raise ContinuityError(f"{label}:magic")
    if data[8:10] != _u16(VERSION) or data[10:12] != b"\0\0":
        raise ContinuityError(f"{label}:header")
    return 12


def _finish(offset: int, data: bytes, label: str) -> None:
    if offset != len(data):
        raise ContinuityError(f"{label}:trailing")


def _length_prefixed(value: bytes, label: str) -> bytes:
    if len(value) > 0xFFFFFFFF:
        raise ContinuityError(f"{label}:too-large")
    return _u32(len(value)) + value


SYNTHETIC_PROVIDER_ID = _sha(
    b"BL/NATIVE-V3/CONTINUITY/SYNTHETIC-PROVIDER/v2\0", b"synthetic-provider-credential-continuity-1"
)
SYNTHETIC_CREDENTIAL_ID = _sha(
    b"BL/NATIVE-V3/CONTINUITY/SYNTHETIC-CREDENTIAL/v2\0", b"synthetic-credential-1"
)
SYNTHETIC_ENROLLMENT_ID = _sha(
    b"BL/NATIVE-V3/CONTINUITY/SYNTHETIC-ENROLLMENT/v2\0", b"synthetic-enrollment-1"
)
SYNTHETIC_FEED_ID = _sha(
    b"BL/NATIVE-V3/CONTINUITY/SYNTHETIC-FEED/v2\0", b"synthetic-authoritative-feed-1"
)
RULE_ID = EXPECTED_RULE_ID
DIRECT_STATE_OWNED_MODE_ID = _sha(MODE_DOMAIN, b"DIRECT_STATE_OWNED")
EVALUATOR_ID = _sha(EVALUATOR_DOMAIN, b"verifier-owned-plaintext-continuity-v1")
REASON_VALID = _sha(REASON_DOMAIN, b"valid-continuity")
REASON_EXPIRED_OR_TERMINATED = _sha(REASON_DOMAIN, b"expired-or-terminated")
REASON_MISSING_AUTHORITATIVE = _sha(REASON_DOMAIN, b"authoritative-absence")
REASON_INCOMPLETE_OR_AMBIGUOUS = _sha(REASON_DOMAIN, b"incomplete-or-ambiguous")
REASON_STALE_RULE = _sha(REASON_DOMAIN, b"stale-rule-interval")
REASON_CONTROL_INTERVAL = _sha(REASON_DOMAIN, b"control-set-decision-time")


def source_state_address(provider_id: bytes) -> bytes:
    return _sha(ADDRESS_DOMAIN, b"credential-enrollment-source", provider_id)


def audit_state_address(provider_id: bytes) -> bytes:
    return _sha(ADDRESS_DOMAIN, b"continuity-audit-head", provider_id)


@dataclass(frozen=True)
class TrustBoundaryAdapter:
    """Only the narrow existing profile seam exposed to this plaintext path."""

    profile_id: bytes
    phase0_statement_digest: bytes
    frozen_phase0_receipt_binding: bytes
    proof_suite_id: None = None

    @classmethod
    def create(cls) -> "TrustBoundaryAdapter":
        bindings = build_profile_bindings()
        return cls(
            profile_id=bindings.profile_id,
            phase0_statement_digest=bindings.phase0_statement_digest,
            frozen_phase0_receipt_binding=bindings.frozen_receipt_binding,
        )

    def bind_private_assertion(self, source_root: bytes) -> bytes:
        """Return a future assertion seam; this method proves nothing."""

        return _sha(
            ADAPTER_DOMAIN,
            _nonzero(self.profile_id, "adapter:profile"),
            _nonzero(self.frozen_phase0_receipt_binding, "adapter:receipt"),
            _nonzero(source_root, "adapter:source-root"),
        )


def _validate_synthetic_fact(fact: "CredentialEnrollmentFact", observation_time: int | None = None) -> None:
    if fact.provider_id != SYNTHETIC_PROVIDER_ID:
        raise ContinuityError("fact:synthetic-provider")
    if fact.credential_id != SYNTHETIC_CREDENTIAL_ID:
        raise ContinuityError("fact:synthetic-credential")
    if fact.enrollment_id != SYNTHETIC_ENROLLMENT_ID:
        raise ContinuityError("fact:synthetic-enrollment")
    if fact.feed_id != SYNTHETIC_FEED_ID:
        raise ContinuityError("fact:synthetic-feed")
    if fact.observed_at == 0:
        raise ContinuityError("fact:observation")
    if observation_time is not None and fact.observed_at != observation_time:
        raise ContinuityError("fact:observation-time")
    if fact.issued_at >= fact.expires_at:
        raise ContinuityError("fact:interval")
    if fact.status == FACT_ACTIVE:
        if fact.terminated_at != 0 or not fact.issued_at <= fact.observed_at < fact.expires_at:
            raise ContinuityError("fact:active-temporal")
    elif fact.status == FACT_EXPIRED:
        if fact.terminated_at != 0 or fact.observed_at < fact.expires_at:
            raise ContinuityError("fact:expired-temporal")
    elif fact.status == FACT_TERMINATED:
        if not fact.issued_at <= fact.terminated_at <= fact.observed_at:
            raise ContinuityError("fact:terminated-temporal")
    else:
        raise ContinuityError("fact:status")


def control_set_bytes() -> bytes:
    return b"".join(
        (
            CONTROL_SET_MAGIC,
            _u16(VERSION),
            _u16(0),
            bytes((MODE_MARKER_DIRECT_STATE_OWNED,)),
            b"\0" * 3,
            DIRECT_STATE_OWNED_MODE_ID,
            EVALUATOR_ID,
            RULE_ID,
            _u32(100),
            _u16(len(CONTROL_SCOPE)),
            CONTROL_SCOPE,
            _u64(CONTROL_EFFECTIVE_START),
            _u64(CONTROL_EFFECTIVE_END),
            _u16(len(CONFLICT_POLICY)),
            CONFLICT_POLICY,
            bytes((len(DIRECTIVE_MAPPING),)),
            DIRECTIVE_MAPPING,
            b"\0" * 3,
        )
    )


def automatic_control_set_id() -> bytes:
    return _sha(CONTROL_SET_DOMAIN, control_set_bytes())


@dataclass(frozen=True)
class CredentialEnrollmentFact:
    provider_id: bytes
    credential_id: bytes
    enrollment_id: bytes
    feed_id: bytes
    status: int
    issued_at: int
    expires_at: int
    terminated_at: int
    observed_at: int
    record_id: bytes

    @classmethod
    def synthetic(
        cls,
        status: int,
        *,
        issued_at: int = 6_000,
        expires_at: int = 8_000,
        terminated_at: int = 0,
        observed_at: int = OBSERVATION_TIME,
    ) -> "CredentialEnrollmentFact":
        provisional = cls(
            SYNTHETIC_PROVIDER_ID,
            SYNTHETIC_CREDENTIAL_ID,
            SYNTHETIC_ENROLLMENT_ID,
            SYNTHETIC_FEED_ID,
            status,
            issued_at,
            expires_at,
            terminated_at,
            observed_at,
            b"\0" * 64,
        )
        return cls(
            provisional.provider_id,
            provisional.credential_id,
            provisional.enrollment_id,
            provisional.feed_id,
            provisional.status,
            provisional.issued_at,
            provisional.expires_at,
            provisional.terminated_at,
            provisional.observed_at,
            _sha(FACT_ID_DOMAIN, provisional.body_bytes()),
        )

    def body_bytes(self) -> bytes:
        _validate_synthetic_fact(self)
        return b"".join(
            (
                FACT_MAGIC,
                _u16(VERSION),
                _u16(0),
                self.provider_id,
                self.credential_id,
                self.enrollment_id,
                self.feed_id,
                bytes((self.status,)),
                b"\0" * 7,
                _u64(self.issued_at),
                _u64(self.expires_at),
                _u64(self.terminated_at),
                _u64(self.observed_at),
            )
        )

    def canonical_bytes(self) -> bytes:
        body = self.body_bytes()
        if self.record_id != _sha(FACT_ID_DOMAIN, body):
            raise ContinuityError("fact:record-id")
        return body + _nonzero(self.record_id, "fact:record-id")

    @classmethod
    def parse(cls, data: bytes) -> "CredentialEnrollmentFact":
        expected = 12 + 64 * 4 + 8 + 32 + 64
        if len(data) != expected:
            raise ContinuityError("fact:length")
        offset = _fixed_header(data, FACT_MAGIC, "fact")
        provider, offset = _read(data, offset, 64, "fact:provider")
        credential, offset = _read(data, offset, 64, "fact:credential")
        enrollment, offset = _read(data, offset, 64, "fact:enrollment")
        feed, offset = _read(data, offset, 64, "fact:feed")
        status_raw, offset = _read(data, offset, 1, "fact:status")
        reserved, offset = _read(data, offset, 7, "fact:reserved")
        if reserved != b"\0" * 7:
            raise ContinuityError("fact:reserved")
        issued, offset = _read_u64(data, offset, "fact:issued")
        expires, offset = _read_u64(data, offset, "fact:expires")
        terminated, offset = _read_u64(data, offset, "fact:terminated")
        observed, offset = _read_u64(data, offset, "fact:observed")
        record_id, offset = _read(data, offset, 64, "fact:record-id")
        _finish(offset, data, "fact")
        fact = cls(provider, credential, enrollment, feed, status_raw[0], issued, expires, terminated, observed, record_id)
        if fact.canonical_bytes() != data:
            raise ContinuityError("fact:noncanonical")
        return fact

    @property
    def subject_key(self) -> bytes:
        return _sha(SUBJECT_KEY_DOMAIN, self.provider_id, self.credential_id, self.enrollment_id)


@dataclass(frozen=True)
class CredentialFactSet:
    feed_id: bytes
    facts: tuple[CredentialEnrollmentFact, ...]

    def canonical_bytes(self) -> bytes:
        if self.feed_id != SYNTHETIC_FEED_ID:
            raise ContinuityError("fact-set:synthetic-feed")
        if len(self.facts) > MAX_FACTS:
            raise ContinuityError("fact-set:count")
        if tuple(sorted(self.facts, key=lambda fact: fact.record_id)) != self.facts:
            raise ContinuityError("fact-set:order")
        ids = [fact.record_id for fact in self.facts]
        if len(set(ids)) != len(ids):
            raise ContinuityError("fact-set:duplicate")
        encoded = [FACT_SET_MAGIC, _u16(VERSION), _u16(0), self.feed_id, _u32(len(self.facts))]
        for fact in self.facts:
            if fact.feed_id != self.feed_id:
                raise ContinuityError("fact-set:feed-mismatch")
            encoded.append(_length_prefixed(fact.canonical_bytes(), "fact-set:fact"))
        return b"".join(encoded)

    @classmethod
    def parse(cls, data: bytes) -> "CredentialFactSet":
        offset = _fixed_header(data, FACT_SET_MAGIC, "fact-set")
        feed, offset = _read(data, offset, 64, "fact-set:feed")
        count, offset = _read_u32(data, offset, "fact-set:count")
        if count > MAX_FACTS:
            raise ContinuityError("fact-set:count")
        facts: list[CredentialEnrollmentFact] = []
        for index in range(count):
            length, offset = _read_u32(data, offset, f"fact-set:length-{index}")
            if length > 1_024:
                raise ContinuityError("fact-set:fact-too-large")
            raw, offset = _read(data, offset, length, f"fact-set:fact-{index}")
            facts.append(CredentialEnrollmentFact.parse(raw))
        _finish(offset, data, "fact-set")
        result = cls(feed, tuple(facts))
        if result.canonical_bytes() != data:
            raise ContinuityError("fact-set:noncanonical")
        return result

    @property
    def source_root(self) -> bytes:
        return _sha(SOURCE_ROOT_DOMAIN, self.canonical_bytes())

    def matching(self, request: "ContinuityRequest") -> tuple[CredentialEnrollmentFact, ...]:
        return tuple(fact for fact in self.facts if fact.subject_key == request.subject_key)


@dataclass(frozen=True)
class FeedCompleteness:
    feed_id: bytes
    provider_id: bytes
    scope_id: bytes
    observation_time: int
    complete: bool
    nonmembership_keys: tuple[bytes, ...]

    def canonical_bytes(self) -> bytes:
        if self.feed_id != SYNTHETIC_FEED_ID:
            raise ContinuityError("completeness:synthetic-feed")
        if self.provider_id != SYNTHETIC_PROVIDER_ID:
            raise ContinuityError("completeness:synthetic-provider")
        _nonzero(self.scope_id, "completeness:scope")
        if not self.complete and self.nonmembership_keys:
            raise ContinuityError("completeness:incomplete-has-absence")
        if tuple(sorted(self.nonmembership_keys)) != self.nonmembership_keys:
            raise ContinuityError("completeness:absence-order")
        if len(set(self.nonmembership_keys)) != len(self.nonmembership_keys):
            raise ContinuityError("completeness:absence-duplicate")
        for key in self.nonmembership_keys:
            _nonzero(key, "completeness:absence-key")
        return b"".join(
            (
                COMPLETENESS_MAGIC,
                _u16(VERSION),
                _u16(0),
                self.feed_id,
                self.provider_id,
                self.scope_id,
                _u64(self.observation_time),
                bytes((1 if self.complete else 0,)),
                b"\0" * 7,
                _u32(len(self.nonmembership_keys)),
                *self.nonmembership_keys,
            )
        )

    @classmethod
    def parse(cls, data: bytes) -> "FeedCompleteness":
        offset = _fixed_header(data, COMPLETENESS_MAGIC, "completeness")
        feed, offset = _read(data, offset, 64, "completeness:feed")
        provider, offset = _read(data, offset, 64, "completeness:provider")
        scope, offset = _read(data, offset, 64, "completeness:scope")
        observation, offset = _read_u64(data, offset, "completeness:observation")
        complete_raw, offset = _read(data, offset, 1, "completeness:complete")
        reserved, offset = _read(data, offset, 7, "completeness:reserved")
        if complete_raw[0] not in (0, 1) or reserved != b"\0" * 7:
            raise ContinuityError("completeness:flags")
        count, offset = _read_u32(data, offset, "completeness:count")
        if count > MAX_FACTS:
            raise ContinuityError("completeness:count")
        keys: list[bytes] = []
        for index in range(count):
            key, offset = _read(data, offset, 64, f"completeness:key-{index}")
            keys.append(key)
        _finish(offset, data, "completeness")
        result = cls(feed, provider, scope, observation, bool(complete_raw[0]), tuple(keys))
        if result.canonical_bytes() != data:
            raise ContinuityError("completeness:noncanonical")
        return result

    @property
    def evidence_id(self) -> bytes:
        return _sha(COMPLETENESS_DOMAIN, self.canonical_bytes())

    def authoritative_absence_for(self, request: "ContinuityRequest", feed_id: bytes) -> bool:
        return (
            self.complete
            and self.feed_id == feed_id
            and self.provider_id == request.provider_id
            and self.scope_id == request.subject_key
            and self.observation_time == request.observation_time
            and request.subject_key in self.nonmembership_keys
        )


@dataclass(frozen=True)
class ContinuityRequest:
    provider_id: bytes
    credential_id: bytes
    enrollment_id: bytes
    attempt_id: bytes
    epoch: int
    sequence_before: int
    event_time: int
    observation_time: int
    rule_effective_time: int
    decision_time: int
    expected_before_state_id: bytes | None = None

    def canonical_bytes(self) -> bytes:
        if self.provider_id != SYNTHETIC_PROVIDER_ID:
            raise ContinuityError("request:synthetic-provider")
        if self.credential_id != SYNTHETIC_CREDENTIAL_ID:
            raise ContinuityError("request:synthetic-credential")
        if self.enrollment_id != SYNTHETIC_ENROLLMENT_ID:
            raise ContinuityError("request:synthetic-enrollment")
        _nonzero(self.attempt_id, "request:attempt")
        if self.epoch != 7 or self.sequence_before != 0:
            raise ContinuityError("request:fixture-state")
        if self.expected_before_state_id is None:
            raise ContinuityError("request:before-state-required")
        _nonzero(self.expected_before_state_id, "request:before-state")
        if not (self.rule_effective_time < self.event_time < self.observation_time < self.decision_time):
            raise ContinuityError("request:chronology")
        return b"".join(
            (
                REQUEST_MAGIC,
                _u16(VERSION),
                _u16(0),
                self.provider_id,
                self.credential_id,
                self.enrollment_id,
                self.attempt_id,
                _u64(self.epoch),
                _u64(self.sequence_before),
                _u64(self.event_time),
                _u64(self.observation_time),
                _u64(self.rule_effective_time),
                _u64(self.decision_time),
                self.expected_before_state_id,
            )
        )

    @property
    def request_id(self) -> bytes:
        return _sha(REQUEST_ID_DOMAIN, self.canonical_bytes())

    @property
    def subject_key(self) -> bytes:
        return _sha(SUBJECT_KEY_DOMAIN, self.provider_id, self.credential_id, self.enrollment_id)

    @classmethod
    def synthetic(cls, label: bytes = b"attempt-1", *, rule_effective_time: int = RULE_EFFECTIVE_TIME) -> "ContinuityRequest":
        initial = ContinuityState.initial(TrustBoundaryAdapter.create()).state_id
        return cls(
            SYNTHETIC_PROVIDER_ID,
            SYNTHETIC_CREDENTIAL_ID,
            SYNTHETIC_ENROLLMENT_ID,
            _sha(b"BL/NATIVE-V3/CONTINUITY/ATTEMPT/v2\0", label),
            7,
            0,
            EVENT_TIME,
            OBSERVATION_TIME,
            rule_effective_time,
            DECISION_TIME,
            initial,
        )


def _scope_for(request: ContinuityRequest) -> bytes:
    return request.subject_key


def _chronology_id(request: ContinuityRequest) -> bytes:
    return _sha(
        CHRONOLOGY_DOMAIN,
        request.canonical_bytes(),
    )


def _control_set_valid() -> None:
    raw = control_set_bytes()
    offset = _fixed_header(raw, CONTROL_SET_MAGIC, "control-set")
    if raw[offset] != MODE_MARKER_DIRECT_STATE_OWNED or raw[offset + 1 : offset + 4] != b"\0" * 3:
        raise ContinuityError("control-set:mode")
    if len(raw) < 200 or automatic_control_set_id() == b"\0" * 64:
        raise ContinuityError("control-set:invalid")


@dataclass(frozen=True)
class ContinuityEvaluation:
    policy_result: int
    effective_directive: int
    reason_id: bytes
    exception_id: bytes
    source_root: bytes
    completeness_id: bytes
    decision_path_id: bytes


class VerifierOwnedContinuityEvaluator:
    """Only evaluator available at this boundary; mode and rules are constants."""

    def __init__(self, adapter: TrustBoundaryAdapter | None = None) -> None:
        self.adapter = adapter or TrustBoundaryAdapter.create()
        expected = build_profile_bindings()
        if (
            self.adapter.profile_id != expected.profile_id
            or self.adapter.phase0_statement_digest != expected.phase0_statement_digest
            or self.adapter.frozen_phase0_receipt_binding != expected.frozen_receipt_binding
            or self.adapter.proof_suite_id is not None
        ):
            raise ContinuityError("adapter:verifier-owned-profile-mismatch")
        _control_set_valid()

    @staticmethod
    def reject_caller_overrides(fields: Mapping[str, object] | None) -> None:
        if not fields:
            return
        raise ContinuityError("caller-fields:forbidden")

    def evaluate(
        self,
        request: ContinuityRequest,
        facts: CredentialFactSet,
        completeness: FeedCompleteness,
        exception: ExceptionAuthorization | None = None,
        *,
        caller_fields: Mapping[str, object] | None = None,
    ) -> ContinuityEvaluation:
        self.reject_caller_overrides(caller_fields)
        request.canonical_bytes()
        expected_before = ContinuityState.initial(self.adapter).state_id
        if request.expected_before_state_id != expected_before:
            raise ContinuityError("request:before-state")
        fact_bytes = facts.canonical_bytes()
        completeness_bytes = completeness.canonical_bytes()
        for fact in facts.facts:
            _validate_synthetic_fact(fact, request.observation_time)
        if facts.feed_id != completeness.feed_id:
            raise ContinuityError("source:feed-mismatch")
        if completeness.provider_id != request.provider_id:
            raise ContinuityError("completeness:provider-mismatch")
        if completeness.scope_id != _scope_for(request):
            raise ContinuityError("completeness:scope-mismatch")
        if completeness.observation_time != request.observation_time:
            raise ContinuityError("completeness:time-mismatch")
        if {fact.subject_key for fact in facts.facts}.intersection(completeness.nonmembership_keys):
            raise ContinuityError("completeness:fact-nonmembership-conflict")
        source_root = _sha(SOURCE_ROOT_DOMAIN, fact_bytes)
        completeness_id = _sha(COMPLETENESS_DOMAIN, completeness_bytes)

        if not CONTROL_EFFECTIVE_START <= request.rule_effective_time < CONTROL_EFFECTIVE_END:
            policy_result = POLICY_RESULT_AMBIGUOUS
            directive = DIRECTIVE_HUMAN_REVIEW
            reason = REASON_STALE_RULE
        elif not CONTROL_EFFECTIVE_START <= request.decision_time < CONTROL_EFFECTIVE_END:
            policy_result = POLICY_RESULT_AMBIGUOUS
            directive = DIRECTIVE_HUMAN_REVIEW
            reason = REASON_CONTROL_INTERVAL
        else:
            matching = facts.matching(request)
            if len(matching) > 1:
                policy_result = POLICY_RESULT_AMBIGUOUS
                directive = DIRECTIVE_HUMAN_REVIEW
                reason = REASON_INCOMPLETE_OR_AMBIGUOUS
            elif not matching:
                if completeness.authoritative_absence_for(request, facts.feed_id):
                    policy_result = POLICY_RESULT_MISSING_EVIDENCE
                    directive = DIRECTIVE_HOLD
                    reason = REASON_MISSING_AUTHORITATIVE
                else:
                    policy_result = POLICY_RESULT_AMBIGUOUS
                    directive = DIRECTIVE_HUMAN_REVIEW
                    reason = REASON_INCOMPLETE_OR_AMBIGUOUS
            else:
                fact = matching[0]
                if fact.status == FACT_ACTIVE:
                    policy_result = POLICY_RESULT_PASS
                    directive = DIRECTIVE_CLEAR
                    reason = REASON_VALID
                elif fact.status in {FACT_EXPIRED, FACT_TERMINATED}:
                    policy_result = POLICY_RESULT_FAIL
                    directive = DIRECTIVE_BLOCK
                    reason = REASON_EXPIRED_OR_TERMINATED
                else:
                    raise ContinuityError("fact:status")

        exception_id = NO_EXCEPTION_SENTINEL
        if exception is not None:
            if policy_result != POLICY_RESULT_FAIL:
                raise ContinuityError("exception:underlying-result")
            try:
                exception_bytes = exception.canonical_bytes()
                ExceptionAuthorization.parse(exception_bytes)
            except (ValueError, AssertionError) as error:
                raise ContinuityError("exception:canonical") from error
            if (
                exception.signer_id != TRUSTED_AUTHORIZER_ID
                or exception.subject_id != request.credential_id
                or exception.rule_id != RULE_ID
                or exception.reason_id != EXPECTED_REASON_ID
                or exception.amount_scope != EXPECTED_AMOUNT_SCOPE
                or exception.policy_result != policy_result
                or exception.effective_at > request.rule_effective_time
                or request.decision_time >= exception.expires_at
            ):
                raise ContinuityError("exception:scope-or-interval")
            exception_id = exception.authorization_id
            directive = DIRECTIVE_EXCEPTION_APPROVED

        if policy_result != DIRECTIVE_POLICY_RESULT[directive]:
            raise ContinuityError("directive:policy-result-mismatch")
        path = _sha(
            PATH_DOMAIN,
            automatic_control_set_id(),
            RULE_ID,
            source_root,
            completeness_id,
            reason,
            bytes((policy_result, directive)),
            exception_id,
        )
        return ContinuityEvaluation(policy_result, directive, reason, exception_id, source_root, completeness_id, path)


STATE_BYTES = 220
REQUEST_BYTES = 380
DECISION_BYTES = 1_276
ACCESS_BYTES = 360
EXCEPTION_NONE_SENTINEL = NO_EXCEPTION_SENTINEL


@dataclass(frozen=True)
class ContinuityState:
    context_id: bytes
    sequence: int
    row_count: int
    audit_head: bytes
    continuity_root: bytes

    @classmethod
    def initial(cls, adapter: TrustBoundaryAdapter) -> "ContinuityState":
        return cls(
            _sha(STATE_CONTEXT_DOMAIN, adapter.profile_id, DIRECT_STATE_OWNED_MODE_ID),
            0,
            0,
            _sha(AUDIT_HEAD_DOMAIN, b"empty"),
            _sha(CONTINUITY_ROOT_DOMAIN, b"empty"),
        )

    def canonical_bytes(self) -> bytes:
        _nonzero(self.context_id, "state:context")
        if (self.sequence, self.row_count) not in {(0, 0), (1, 1)}:
            raise ContinuityError("state:row-count")
        if self.row_count == 0 and (
            self.audit_head != _sha(AUDIT_HEAD_DOMAIN, b"empty")
            or self.continuity_root != _sha(CONTINUITY_ROOT_DOMAIN, b"empty")
        ):
            raise ContinuityError("state:initial-values")
        return b"".join(
            (
                STATE_MAGIC,
                _u16(VERSION),
                _u16(0),
                self.context_id,
                _u64(self.sequence),
                _u32(self.row_count),
                b"\0" * 4,
                _nonzero(self.audit_head, "state:audit-head"),
                _nonzero(self.continuity_root, "state:root"),
            )
        )

    @property
    def state_id(self) -> bytes:
        return _sha(STATE_ID_DOMAIN, self.canonical_bytes())

    def advance(self, decision_id: bytes, source_root: bytes, directive: int) -> "ContinuityState":
        if self.row_count != 0:
            raise ContinuityError("state:one-transition-cap")
        _nonzero(decision_id, "state:decision")
        _nonzero(source_root, "state:source")
        return ContinuityState(
            self.context_id,
            self.sequence + 1,
            1,
            _sha(AUDIT_HEAD_DOMAIN, self.audit_head, decision_id, bytes((directive,))),
            _sha(CONTINUITY_ROOT_DOMAIN, self.continuity_root, source_root, decision_id),
        )

    @classmethod
    def parse(cls, data: bytes) -> "ContinuityState":
        if len(data) != STATE_BYTES:
            raise ContinuityError("state:length")
        offset = _fixed_header(data, STATE_MAGIC, "state")
        context, offset = _read(data, offset, 64, "state:context")
        sequence, offset = _read_u64(data, offset, "state:sequence")
        row_count, offset = _read_u32(data, offset, "state:row-count")
        reserved, offset = _read(data, offset, 4, "state:reserved")
        audit, offset = _read(data, offset, 64, "state:audit")
        root, offset = _read(data, offset, 64, "state:root")
        _finish(offset, data, "state")
        result = cls(context, sequence, row_count, audit, root)
        if result.canonical_bytes() != data:
            raise ContinuityError("state:noncanonical")
        if reserved != b"\0" * 4:
            raise ContinuityError("state:reserved")
        return result


@dataclass(frozen=True)
class ClearanceDecisionRow:
    decision_index: int
    decision_count: int
    decision_id: bytes
    attempt_id: bytes
    provider_id: bytes
    credential_id: bytes
    enrollment_id: bytes
    mode_id: bytes
    control_set_id: bytes
    rule_id: bytes
    source_root: bytes
    phase0_receipt_binding: bytes
    completeness_id: bytes
    chronology_id: bytes
    replay_id: bytes
    exception_id: bytes
    state_before_id: bytes
    state_after_id: bytes
    decision_path_id: bytes
    reason_id: bytes
    request_id: bytes
    policy_result: int
    effective_directive: int
    economic_mutation: int
    proof_session_accepted: int
    event_time: int
    observation_time: int
    rule_effective_time: int
    decision_time: int

    def _identities(self) -> tuple[bytes, ...]:
        return (
            self.decision_id,
            self.attempt_id,
            self.provider_id,
            self.credential_id,
            self.enrollment_id,
            self.mode_id,
            self.control_set_id,
            self.rule_id,
            self.source_root,
            self.phase0_receipt_binding,
            self.completeness_id,
            self.chronology_id,
            self.replay_id,
            self.exception_id,
            self.state_before_id,
            self.state_after_id,
            self.decision_path_id,
            self.reason_id,
            self.request_id,
        )

    def canonical_bytes(self) -> bytes:
        if (self.decision_index, self.decision_count) != (0, 1):
            raise ContinuityError("decision:index-count")
        for index, value in enumerate(self._identities()):
            _nonzero(value, f"decision:identity-{index}")
        if self.policy_result not in {POLICY_RESULT_PASS, POLICY_RESULT_MISSING_EVIDENCE, POLICY_RESULT_AMBIGUOUS, POLICY_RESULT_FAIL}:
            raise ContinuityError("decision:policy-result")
        if self.effective_directive not in DIRECTIVE_NAMES:
            raise ContinuityError("decision:directive")
        if self.policy_result != DIRECTIVE_POLICY_RESULT[self.effective_directive]:
            raise ContinuityError("decision:directive-policy")
        if self.economic_mutation != ECONOMIC_MUTATION_FALSE or self.proof_session_accepted != PROOF_ACCEPTANCE_FALSE:
            raise ContinuityError("decision:forbidden-mutation-or-proof")
        if not (self.rule_effective_time < self.event_time < self.observation_time < self.decision_time):
            raise ContinuityError("decision:chronology")
        return b"".join(
            (
                DECISION_MAGIC,
                _u16(VERSION),
                _u16(0),
                _u32(self.decision_index),
                _u32(self.decision_count),
                *self._identities(),
                bytes((self.policy_result, self.effective_directive, self.economic_mutation, self.proof_session_accepted)),
                b"\0" * 4,
                _u64(self.event_time),
                _u64(self.observation_time),
                _u64(self.rule_effective_time),
                _u64(self.decision_time),
            )
        )

    @property
    def row_id(self) -> bytes:
        return _sha(DECISION_ROW_DOMAIN, self.canonical_bytes())

    @classmethod
    def parse(cls, data: bytes) -> "ClearanceDecisionRow":
        if len(data) != DECISION_BYTES:
            raise ContinuityError("decision:length")
        offset = _fixed_header(data, DECISION_MAGIC, "decision")
        index, offset = _read_u32(data, offset, "decision:index")
        count, offset = _read_u32(data, offset, "decision:count")
        identities: list[bytes] = []
        for item in range(19):
            value, offset = _read(data, offset, 64, f"decision:identity-{item}")
            identities.append(value)
        flags, offset = _read(data, offset, 4, "decision:flags")
        reserved, offset = _read(data, offset, 4, "decision:reserved")
        event, offset = _read_u64(data, offset, "decision:event")
        observation, offset = _read_u64(data, offset, "decision:observation")
        rule_effective, offset = _read_u64(data, offset, "decision:rule-effective")
        decision, offset = _read_u64(data, offset, "decision:decision-time")
        _finish(offset, data, "decision")
        if reserved != b"\0" * 4:
            raise ContinuityError("decision:reserved")
        result = cls(index, count, *identities, *flags, event, observation, rule_effective, decision)
        if result.canonical_bytes() != data:
            raise ContinuityError("decision:noncanonical")
        return result


@dataclass(frozen=True)
class StateAccessRow:
    decision_id: bytes
    decision_index: int
    access_index: int
    access_count: int
    access_time: int
    address: bytes
    key: bytes
    value_before: bytes
    value_after: bytes
    mode: int

    def canonical_bytes(self) -> bytes:
        _nonzero(self.decision_id, "access:decision")
        if (self.decision_index, self.access_count) != (0, 2) or self.access_index not in {0, 1}:
            raise ContinuityError("access:index-count")
        for index, value in enumerate((self.address, self.key, self.value_before, self.value_after)):
            _nonzero(value, f"access:identity-{index}")
        if self.mode not in {ACCESS_READ, ACCESS_WRITE}:
            raise ContinuityError("access:mode")
        if self.mode == ACCESS_READ and self.value_before != self.value_after:
            raise ContinuityError("access:read-mutates")
        if self.mode == ACCESS_WRITE and self.value_before == self.value_after:
            raise ContinuityError("access:write-no-change")
        return b"".join(
            (
                ACCESS_MAGIC,
                _u16(VERSION),
                _u16(0),
                self.decision_id,
                _u32(self.decision_index),
                _u32(self.access_index),
                _u32(self.access_count),
                _u64(self.access_time),
                self.address,
                self.key,
                self.value_before,
                self.value_after,
                bytes((self.mode,)),
                b"\0" * 7,
            )
        )

    @property
    def row_id(self) -> bytes:
        return _sha(ACCESS_ROW_DOMAIN, self.canonical_bytes())

    @classmethod
    def parse(cls, data: bytes) -> "StateAccessRow":
        if len(data) != ACCESS_BYTES:
            raise ContinuityError("access:length")
        offset = _fixed_header(data, ACCESS_MAGIC, "access")
        decision_id, offset = _read(data, offset, 64, "access:decision")
        decision_index, offset = _read_u32(data, offset, "access:decision-index")
        access_index, offset = _read_u32(data, offset, "access:index")
        access_count, offset = _read_u32(data, offset, "access:count")
        access_time, offset = _read_u64(data, offset, "access:time")
        address, offset = _read(data, offset, 64, "access:address")
        key, offset = _read(data, offset, 64, "access:key")
        before, offset = _read(data, offset, 64, "access:before")
        after, offset = _read(data, offset, 64, "access:after")
        mode_raw, offset = _read(data, offset, 1, "access:mode")
        reserved, offset = _read(data, offset, 7, "access:reserved")
        _finish(offset, data, "access")
        if reserved != b"\0" * 7:
            raise ContinuityError("access:reserved")
        result = cls(decision_id, decision_index, access_index, access_count, access_time, address, key, before, after, mode_raw[0])
        if result.canonical_bytes() != data:
            raise ContinuityError("access:noncanonical")
        return result


@dataclass(frozen=True)
class DecisionAccessJoin:
    decision: ClearanceDecisionRow
    accesses: tuple[StateAccessRow, StateAccessRow]
    before_state: ContinuityState
    after_state: ContinuityState

    def canonical_bytes(self) -> bytes:
        decision = self.decision.canonical_bytes()
        try:
            before_state_id = self.before_state.state_id
            after_state_id = self.after_state.state_id
        except ContinuityError as error:
            raise ContinuityError("join:state-binding") from error
        if (
            self.decision.state_before_id != before_state_id
            or self.decision.state_after_id != after_state_id
        ):
            raise ContinuityError("join:state-binding")
        try:
            expected_after = self.before_state.advance(
                self.decision.decision_id,
                self.decision.source_root,
                self.decision.effective_directive,
            )
        except ContinuityError as error:
            raise ContinuityError("join:state-transition") from error
        if self.after_state != expected_after:
            raise ContinuityError("join:state-transition")
        if len(self.accesses) != 2 or [row.access_index for row in self.accesses] != [0, 1]:
            raise ContinuityError("join:access-order")
        if any(row.decision_id != self.decision.decision_id for row in self.accesses):
            raise ContinuityError("join:decision-binding")
        for row in self.accesses:
            row.canonical_bytes()
        read, write = self.accesses
        if (
            read.mode != ACCESS_READ
            or read.access_time != self.decision.observation_time
            or read.address != source_state_address(self.decision.provider_id)
            or read.key != _sha(
                SUBJECT_KEY_DOMAIN,
                self.decision.provider_id,
                self.decision.credential_id,
                self.decision.enrollment_id,
            )
            or read.value_before != self.decision.source_root
            or read.value_after != self.decision.source_root
        ):
            raise ContinuityError("join:read")
        if (
            write.mode != ACCESS_WRITE
            or write.access_time != self.decision.decision_time
            or write.address != audit_state_address(self.decision.provider_id)
            or write.key != self.decision.decision_id
        ):
            raise ContinuityError("join:write")
        if (
            write.value_before != self.before_state.audit_head
            or write.value_after != self.after_state.audit_head
        ):
            raise ContinuityError("join:write-state")
        return b"".join(
            (
                JOIN_MAGIC,
                _u16(VERSION),
                _u16(0),
                _u32(1),
                _u32(2),
                _length_prefixed(decision, "join:decision"),
                *(_length_prefixed(row.canonical_bytes(), "join:access") for row in self.accesses),
            )
        )

    @property
    def join_id(self) -> bytes:
        return _sha(JOIN_DOMAIN, self.canonical_bytes())


@dataclass(frozen=True)
class ContinuityReceipt:
    adapter_binding: bytes
    control_set_id: bytes
    phase0_receipt_binding: bytes
    decision: ClearanceDecisionRow
    accesses: tuple[StateAccessRow, StateAccessRow]
    before_state: ContinuityState
    after_state: ContinuityState
    join_id: bytes
    request: ContinuityRequest | None = None
    exception_authorization: ExceptionAuthorization | None = None
    proof_suite_id: None = None
    proof_session_accepted: bool = False
    economic_mutation: bool = False

    def body_bytes(self) -> bytes:
        if self.proof_suite_id is not None or self.proof_session_accepted or self.economic_mutation:
            raise ContinuityError("receipt:proof-or-economic-authority")
        _nonzero(self.adapter_binding, "receipt:adapter")
        _nonzero(self.control_set_id, "receipt:control-set")
        _nonzero(self.phase0_receipt_binding, "receipt:phase0")
        join = DecisionAccessJoin(self.decision, self.accesses, self.before_state, self.after_state)
        if self.join_id != join.join_id:
            raise ContinuityError("receipt:join")
        try:
            expected_after = self.before_state.advance(
                self.decision.decision_id,
                self.decision.source_root,
                self.decision.effective_directive,
            )
        except ContinuityError as error:
            raise ContinuityError("receipt:state-transition") from error
        if self.after_state != expected_after:
            raise ContinuityError("receipt:state-transition")
        write = self.accesses[1]
        if write.value_before != self.before_state.audit_head or write.value_after != self.after_state.audit_head:
            raise ContinuityError("receipt:write-state")
        if self.decision.control_set_id != self.control_set_id or self.decision.phase0_receipt_binding != self.phase0_receipt_binding:
            raise ContinuityError("receipt:decision-binding")
        if self.decision.state_before_id != self.before_state.state_id or self.decision.state_after_id != self.after_state.state_id:
            raise ContinuityError("receipt:state-binding")
        if self.request is None:
            raise ContinuityError("receipt:request-required")
        request_raw = self.request.canonical_bytes()
        if (
            self.decision.request_id != _sha(REQUEST_ID_DOMAIN, request_raw)
            or self.decision.attempt_id != self.request.attempt_id
            or self.decision.provider_id != self.request.provider_id
            or self.decision.credential_id != self.request.credential_id
            or self.decision.enrollment_id != self.request.enrollment_id
            or (self.decision.event_time, self.decision.observation_time, self.decision.rule_effective_time, self.decision.decision_time)
            != (self.request.event_time, self.request.observation_time, self.request.rule_effective_time, self.request.decision_time)
        ):
            raise ContinuityError("receipt:request-binding")
        expected_exception = EXCEPTION_NONE_SENTINEL
        if self.exception_authorization is not None:
            try:
                expected_exception = self.exception_authorization.authorization_id
                self.exception_authorization.canonical_bytes()
            except (ValueError, AssertionError) as error:
                raise ContinuityError("receipt:exception") from error
        if self.decision.exception_id != expected_exception:
            raise ContinuityError("receipt:exception-binding")
        decision = self.decision.canonical_bytes()
        return b"".join(
            (
                RECEIPT_MAGIC,
                _u16(VERSION),
                _u16(0),
                bytes((0, PROOF_ACCEPTANCE_FALSE, ECONOMIC_MUTATION_FALSE, MODE_MARKER_DIRECT_STATE_OWNED)),
                b"\0" * 4,
                NULL_PROOF_SUITE,
                self.adapter_binding,
                self.control_set_id,
                self.decision.decision_id,
                self.join_id,
                self.before_state.state_id,
                self.after_state.state_id,
                self.phase0_receipt_binding,
                _length_prefixed(decision, "receipt:decision"),
                _u32(len(self.accesses)),
                *(_length_prefixed(row.canonical_bytes(), "receipt:access") for row in self.accesses),
            )
        )

    @property
    def receipt_id(self) -> bytes:
        return _sha(RECEIPT_ID_DOMAIN, self.body_bytes())

    def canonical_bytes(self) -> bytes:
        return self.body_bytes() + self.receipt_id

    @property
    def bundle_bytes(self) -> bytes:
        raise ContinuityError("receipt:bundle-requires-source")

    @classmethod
    def parse(
        cls,
        data: bytes,
        *,
        before_state: ContinuityState | None = None,
        after_state: ContinuityState | None = None,
        request: ContinuityRequest | None = None,
        exception_authorization: ExceptionAuthorization | None = None,
    ) -> "ContinuityReceipt":
        if len(data) < 64:
            raise ContinuityError("receipt:length")
        body, receipt_id = data[:-64], data[-64:]
        offset = _fixed_header(body, RECEIPT_MAGIC, "receipt")
        markers, offset = _read(body, offset, 4, "receipt:markers")
        reserved, offset = _read(body, offset, 4, "receipt:reserved")
        suite, offset = _read(body, offset, 64, "receipt:suite")
        adapter, offset = _read(body, offset, 64, "receipt:adapter")
        control, offset = _read(body, offset, 64, "receipt:control")
        decision_id, offset = _read(body, offset, 64, "receipt:decision-id")
        join_id, offset = _read(body, offset, 64, "receipt:join-id")
        before_id, offset = _read(body, offset, 64, "receipt:before-id")
        after_id, offset = _read(body, offset, 64, "receipt:after-id")
        phase0, offset = _read(body, offset, 64, "receipt:phase0")
        decision_length, offset = _read_u32(body, offset, "receipt:decision-length")
        if decision_length != DECISION_BYTES:
            raise ContinuityError("receipt:decision-length")
        decision_raw, offset = _read(body, offset, decision_length, "receipt:decision")
        decision = ClearanceDecisionRow.parse(decision_raw)
        access_count, offset = _read_u32(body, offset, "receipt:access-count")
        if access_count != 2:
            raise ContinuityError("receipt:access-count")
        accesses: list[StateAccessRow] = []
        for index in range(access_count):
            length, offset = _read_u32(body, offset, f"receipt:access-length-{index}")
            if length != ACCESS_BYTES:
                raise ContinuityError("receipt:access-length")
            raw, offset = _read(body, offset, length, f"receipt:access-{index}")
            accesses.append(StateAccessRow.parse(raw))
        _finish(offset, body, "receipt")
        if markers != bytes((0, PROOF_ACCEPTANCE_FALSE, ECONOMIC_MUTATION_FALSE, MODE_MARKER_DIRECT_STATE_OWNED)) or reserved != b"\0" * 4 or suite != NULL_PROOF_SUITE:
            raise ContinuityError("receipt:markers-or-suite")
        if decision.decision_id != decision_id or decision.control_set_id != control or decision.phase0_receipt_binding != phase0:
            raise ContinuityError("receipt:decision-binding")
        if _sha(RECEIPT_ID_DOMAIN, body) != receipt_id:
            raise ContinuityError("receipt:id")
        if before_state is None or after_state is None:
            raise ContinuityError("receipt:state-bytes-required")
        result = cls(
            adapter,
            control,
            phase0,
            decision,
            (accesses[0], accesses[1]),
            before_state,
            after_state,
            join_id,
            request,
            exception_authorization,
        )
        if result.canonical_bytes() != data:
            raise ContinuityError("receipt:noncanonical")
        return result


def bundle_bytes(
    receipt: ContinuityReceipt,
    facts: CredentialFactSet,
    completeness: FeedCompleteness,
    request: ContinuityRequest | None = None,
    exception_authorization: ExceptionAuthorization | None = None,
) -> bytes:
    request = request or receipt.request
    if request is None:
        raise ContinuityError("bundle:request-required")
    if exception_authorization is None:
        exception_authorization = receipt.exception_authorization
    receipt_raw = receipt.canonical_bytes()
    request_raw = request.canonical_bytes()
    fact_raw = facts.canonical_bytes()
    completeness_raw = completeness.canonical_bytes()
    exception_raw = (
        exception_authorization.canonical_bytes()
        if exception_authorization is not None
        else EXCEPTION_NONE_SENTINEL
    )
    before_raw = receipt.before_state.canonical_bytes()
    after_raw = receipt.after_state.canonical_bytes()
    result = b"".join(
        (
            BUNDLE_MAGIC,
            _u16(VERSION),
            _u16(0),
            _length_prefixed(receipt_raw, "bundle:receipt"),
            _length_prefixed(request_raw, "bundle:request"),
            _length_prefixed(fact_raw, "bundle:facts"),
            _length_prefixed(completeness_raw, "bundle:completeness"),
            _length_prefixed(exception_raw, "bundle:exception"),
            _length_prefixed(before_raw, "bundle:before"),
            _length_prefixed(after_raw, "bundle:after"),
        )
    )
    if len(result) > MAX_BUNDLE_BYTES:
        raise ContinuityError("bundle:size")
    return result


def bundle_id(data: bytes) -> bytes:
    return _sha(BUNDLE_DOMAIN, data)


class ContinuityStore:
    """One local, synthetic, audit-only state transition with replay guards."""

    def __init__(self, adapter: TrustBoundaryAdapter | None = None) -> None:
        self.adapter = adapter or TrustBoundaryAdapter.create()
        self.evaluator = VerifierOwnedContinuityEvaluator(self.adapter)
        self._state = ContinuityState.initial(self.adapter)
        self._consumed_attempts: set[bytes] = set()

    @property
    def state(self) -> ContinuityState:
        return self._state

    def apply(
        self,
        request: ContinuityRequest,
        facts: CredentialFactSet,
        completeness: FeedCompleteness,
        exception: ExceptionAuthorization | None = None,
        *,
        caller_fields: Mapping[str, object] | None = None,
    ) -> ContinuityReceipt:
        self.evaluator.reject_caller_overrides(caller_fields)
        request.canonical_bytes()
        if request.attempt_id in self._consumed_attempts:
            raise ContinuityError("replay:attempt")
        if request.sequence_before != self._state.sequence:
            raise ContinuityError("state:sequence")
        if self._state != ContinuityState.initial(self.adapter):
            raise ContinuityError("state:initial-precondition")
        if request.expected_before_state_id is not None and request.expected_before_state_id != self._state.state_id:
            raise ContinuityError("state:before-root")
        evaluation = self.evaluator.evaluate(request, facts, completeness, exception)
        before = self._state
        replay_id = _sha(REPLAY_DOMAIN, request.canonical_bytes(), before.state_id, evaluation.source_root, automatic_control_set_id())
        decision_id = _sha(
            DECISION_ID_DOMAIN,
            request.canonical_bytes(),
            before.state_id,
            evaluation.source_root,
            evaluation.completeness_id,
            bytes((evaluation.policy_result, evaluation.effective_directive)),
            evaluation.exception_id,
        )
        after = before.advance(decision_id, evaluation.source_root, evaluation.effective_directive)
        decision = ClearanceDecisionRow(
            0,
            1,
            decision_id,
            request.attempt_id,
            request.provider_id,
            request.credential_id,
            request.enrollment_id,
            DIRECT_STATE_OWNED_MODE_ID,
            automatic_control_set_id(),
            RULE_ID,
            evaluation.source_root,
            self.adapter.frozen_phase0_receipt_binding,
            evaluation.completeness_id,
            _chronology_id(request),
            replay_id,
            evaluation.exception_id,
            before.state_id,
            after.state_id,
            evaluation.decision_path_id,
            evaluation.reason_id,
            request.request_id,
            evaluation.policy_result,
            evaluation.effective_directive,
            ECONOMIC_MUTATION_FALSE,
            PROOF_ACCEPTANCE_FALSE,
            request.event_time,
            request.observation_time,
            request.rule_effective_time,
            request.decision_time,
        )
        decision.canonical_bytes()
        accesses = (
            StateAccessRow(
                decision_id,
                0,
                0,
                2,
                request.observation_time,
                source_state_address(request.provider_id),
                request.subject_key,
                evaluation.source_root,
                evaluation.source_root,
                ACCESS_READ,
            ),
            StateAccessRow(
                decision_id,
                0,
                1,
                2,
                request.decision_time,
                audit_state_address(request.provider_id),
                decision_id,
                before.audit_head,
                after.audit_head,
                ACCESS_WRITE,
            ),
        )
        join = DecisionAccessJoin(decision, accesses, before, after)
        receipt = ContinuityReceipt(
            self.adapter.bind_private_assertion(evaluation.source_root),
            automatic_control_set_id(),
            self.adapter.frozen_phase0_receipt_binding,
            decision,
            accesses,
            before,
            after,
            join.join_id,
            request,
            exception,
        )
        receipt.canonical_bytes()
        self._state = after
        self._consumed_attempts.add(request.attempt_id)
        return receipt


def make_completeness(request: ContinuityRequest, facts: CredentialFactSet, *, complete: bool, absent: bool = False) -> FeedCompleteness:
    return FeedCompleteness(
        facts.feed_id,
        request.provider_id,
        request.subject_key,
        request.observation_time,
        complete,
        (request.subject_key,) if absent else (),
    )


def make_governed_exception(request: ContinuityRequest) -> ExceptionAuthorization:
    return ExceptionAuthorization.from_fields(
        signer_id=TRUSTED_AUTHORIZER_ID,
        subject_id=request.credential_id,
        rule_id=RULE_ID,
        reason_id=EXPECTED_REASON_ID,
        amount_scope=EXPECTED_AMOUNT_SCOPE,
        effective_at=request.rule_effective_time,
        expires_at=request.decision_time + 1,
        policy_result=POLICY_RESULT_FAIL,
    )


def build_demo_case(name: str) -> tuple[ContinuityRequest, CredentialFactSet, FeedCompleteness, ExceptionAuthorization | None]:
    request = ContinuityRequest.synthetic(name.encode("ascii"))
    exception: ExceptionAuthorization | None = None
    if name == "valid-continuity":
        facts = CredentialFactSet(SYNTHETIC_FEED_ID, (CredentialEnrollmentFact.synthetic(FACT_ACTIVE),))
        complete = make_completeness(request, facts, complete=True)
    elif name == "expired-credential":
        facts = CredentialFactSet(SYNTHETIC_FEED_ID, (CredentialEnrollmentFact.synthetic(FACT_EXPIRED, expires_at=6_900),))
        complete = make_completeness(request, facts, complete=True)
    elif name == "terminated-credential":
        facts = CredentialFactSet(SYNTHETIC_FEED_ID, (CredentialEnrollmentFact.synthetic(FACT_TERMINATED, terminated_at=7_000),))
        complete = make_completeness(request, facts, complete=True)
    elif name == "missing-incomplete-feed":
        facts = CredentialFactSet(SYNTHETIC_FEED_ID, ())
        complete = make_completeness(request, facts, complete=False)
    elif name == "authoritative-absence":
        facts = CredentialFactSet(SYNTHETIC_FEED_ID, ())
        complete = make_completeness(request, facts, complete=True, absent=True)
    elif name == "conflicting-facts":
        active = CredentialEnrollmentFact.synthetic(FACT_ACTIVE)
        terminated = CredentialEnrollmentFact.synthetic(FACT_TERMINATED, terminated_at=7_000)
        facts = CredentialFactSet(SYNTHETIC_FEED_ID, tuple(sorted((active, terminated), key=lambda fact: fact.record_id)))
        complete = make_completeness(request, facts, complete=True)
    elif name == "stale-rule-interval":
        request = ContinuityRequest.synthetic(name.encode("ascii"), rule_effective_time=CONTROL_EFFECTIVE_START - 1)
        facts = CredentialFactSet(SYNTHETIC_FEED_ID, (CredentialEnrollmentFact.synthetic(FACT_ACTIVE),))
        complete = make_completeness(request, facts, complete=True)
    elif name == "governed-exception":
        facts = CredentialFactSet(SYNTHETIC_FEED_ID, (CredentialEnrollmentFact.synthetic(FACT_TERMINATED, terminated_at=7_000),))
        complete = make_completeness(request, facts, complete=True)
        exception = make_governed_exception(request)
    else:
        raise ContinuityError("demo:unknown-case")
    return request, facts, complete, exception


DEMO_CASES = (
    "valid-continuity",
    "expired-credential",
    "terminated-credential",
    "missing-incomplete-feed",
    "authoritative-absence",
    "conflicting-facts",
    "stale-rule-interval",
    "governed-exception",
)


def build_known_answer_vectors() -> dict[str, Any]:
    vectors: dict[str, Any] = {}
    for name in DEMO_CASES:
        request, facts, completeness, exception = build_demo_case(name)
        store = ContinuityStore()
        receipt = store.apply(request, facts, completeness, exception)
        raw_bundle = bundle_bytes(receipt, facts, completeness)
        vectors[name] = {
            "policy_result": receipt.decision.policy_result,
            "effective_directive": DIRECTIVE_NAMES[receipt.decision.effective_directive],
            "proof_session_accepted": receipt.proof_session_accepted,
            "proof_suite_id": receipt.proof_suite_id,
            "economic_mutation": receipt.economic_mutation,
            "automatic_control_set_id": receipt.control_set_id.hex(),
            "decision_id": receipt.decision.decision_id.hex(),
            "request_id": receipt.decision.request_id.hex(),
            "reason_id": receipt.decision.reason_id.hex(),
            "join_id": receipt.join_id.hex(),
            "state_before_id": receipt.before_state.state_id.hex(),
            "state_after_id": receipt.after_state.state_id.hex(),
            "receipt_id": receipt.receipt_id.hex(),
            "bundle_sha3_512": bundle_id(raw_bundle).hex(),
            "bundle_bytes": len(raw_bundle),
            "source_root": receipt.decision.source_root.hex(),
            "exception_id": receipt.decision.exception_id.hex(),
        }
    return vectors


def _process_memory() -> dict[str, int | None]:
    if os.name != "nt":
        return {"working_set_bytes": None, "pagefile_bytes": None, "peak_working_set_bytes": None}
    class Counters(ctypes.Structure):
        _fields_ = [
            ("cb", ctypes.c_ulong),
            ("PageFaultCount", ctypes.c_ulong),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]
    counters = Counters()
    counters.cb = ctypes.sizeof(Counters)
    try:
        get_memory = ctypes.windll.psapi.GetProcessMemoryInfo
        get_memory.argtypes = [ctypes.c_void_p, ctypes.POINTER(Counters), ctypes.c_ulong]
        get_memory.restype = ctypes.c_int
        ok = get_memory(
            ctypes.windll.kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb
        )
    except (AttributeError, OSError):
        return {"working_set_bytes": None, "pagefile_bytes": None, "peak_working_set_bytes": None}
    if not ok:
        return {"working_set_bytes": None, "pagefile_bytes": None, "peak_working_set_bytes": None}
    return {
        "working_set_bytes": int(counters.WorkingSetSize),
        "pagefile_bytes": int(counters.PagefileUsage),
        "peak_working_set_bytes": int(counters.PeakWorkingSetSize),
    }


def measure_direct_slice() -> dict[str, Any]:
    tracemalloc.start()
    before = _process_memory()
    started = time.perf_counter()
    vectors = build_known_answer_vectors()
    elapsed = time.perf_counter() - started
    current, peak = tracemalloc.get_traced_memory()
    after = _process_memory()
    tracemalloc.stop()
    return {
        "cases": len(vectors),
        "elapsed_seconds": elapsed,
        "python_heap_current_bytes": current,
        "python_heap_peak_bytes": peak,
        "process_before": before,
        "process_after": after,
        "pagefile_growth_bytes": None
        if before["pagefile_bytes"] is None or after["pagefile_bytes"] is None
        else after["pagefile_bytes"] - before["pagefile_bytes"],
        "complete_proof_resource_gate_measured": False,
        "proof_backend_selected": False,
    }


def build_manifest() -> dict[str, Any]:
    return {
        "schema": "BL/NATIVE-V3/PLAINTEXT-CONTINUITY-PROFILE/v2",
        "wire_version": VERSION,
        "bundle_parts": ["receipt", "request", "facts", "completeness", "exception-or-sentinel", "before-state", "after-state"],
        "mode": "DIRECT_STATE_OWNED",
        "mode_id": DIRECT_STATE_OWNED_MODE_ID.hex(),
        "automatic_control_set_id": automatic_control_set_id().hex(),
        "control_set_bytes": len(control_set_bytes()),
        "rule_id": RULE_ID.hex(),
        "rule_order": [RULE_ID.hex()],
        "priority": 100,
        "conflict_policy": CONFLICT_POLICY.decode("ascii"),
        "scope": CONTROL_SCOPE.decode("ascii"),
        "effective_interval": [CONTROL_EFFECTIVE_START, CONTROL_EFFECTIVE_END],
        "directive_order": list(DIRECTIVE_NAMES.values()),
        "proof_suite_id": None,
        "proof_session_accepted": False,
        "production_usable": False,
        "activation": False,
        "state_transition": {
            "kind": "one-read-one-write-audit-only",
            "before_root": "SHA3-512(BLCSTA02 canonical before state)",
            "after_root": "SHA3-512(BLCSTA02 canonical after state)",
            "economic_mutation": False,
            "join": "one ClearanceDecisionRow + exactly two ordered StateAccessRow values",
        },
        "absence": {
            "authoritative": "complete=true and exact subject_key nonmembership",
            "incomplete_feed": "HUMAN_REVIEW; no absence inference",
        },
        "synthetic_inputs_only": True,
        "nonclaims": [
            "no ZK",
            "no private assertion hiding",
            "no PQ proof security",
            "no production proof readiness",
            "no complete <=2^-128 composition bound",
            "no payment movement or economic clearance authority",
            "Phase-0 exception seal remains synthetic-KAT-only",
        ],
    }


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv if argv is None else argv)
    if len(args) != 2 or args[1] not in {"kat", "manifest", "telemetry"}:
        print("usage: continuity.py kat|manifest|telemetry", file=sys.stderr)
        return 2
    payload: Any
    if args[1] == "kat":
        payload = {
            "status": "NATIVE_V3_PLAINTEXT_CONTINUITY_KAT_PASS",
            "vectors": build_known_answer_vectors(),
            "automatic_control_set_id": automatic_control_set_id().hex(),
            "proof_suite_id": None,
            "proof_session_accepted": False,
            "production_usable": False,
            "activation": False,
            "payment_authority": "OFFICIAL_EXTERNAL_PAYMENT_SYSTEM_ONLY",
        }
    elif args[1] == "manifest":
        payload = build_manifest()
    else:
        payload = measure_direct_slice()
    print(json.dumps(payload, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
