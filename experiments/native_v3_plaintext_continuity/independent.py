"""Independent V2 semantic parser for the plaintext continuity bundle.

This module deliberately does not import producer record or evaluator classes.
It parses the bounded V2 byte grammar, reconstructs the request, facts,
completeness, exception, decision, access, join, and state values, and then
re-evaluates the fixed synthetic rule before returning a typed summary.
"""

from __future__ import annotations

import hashlib
import json
import sys
from typing import Any

from experiments.native_v3_trust_boundary.profile import build_profile_bindings


class IndependentParseError(ValueError):
    """Raised when the independently parsed bundle is not exact."""


VERSION = 2
MAX_FACTS = 8
MAX_BUNDLE_BYTES = 1_000_000
FACT_BYTES = 372
REQUEST_BYTES = 380
STATE_BYTES = 220
DECISION_BYTES = 1_276
ACCESS_BYTES = 360
AUTH_BYTES = 484
NULL_SUITE = b"\0" * 64
SENTINEL = b"\xe0" + b"\0" * 63

FACT_ACTIVE = 1
FACT_EXPIRED = 2
FACT_TERMINATED = 3
ACCESS_READ = 1
ACCESS_WRITE = 2
POLICY_PASS = 1
POLICY_MISSING = 2
POLICY_AMBIGUOUS = 3
POLICY_FAIL = 4
DIRECTIVE_CLEAR = 1
DIRECTIVE_HOLD = 2
DIRECTIVE_REVIEW = 3
DIRECTIVE_BLOCK = 4
DIRECTIVE_EXCEPTION = 5

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
JOIN_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/DECISION-ACCESS-JOIN/v2\0"
REPLAY_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/REPLAY/v2\0"
PATH_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/DECISION-PATH/v2\0"
RECEIPT_ID_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/RECEIPT-ID/v2\0"
BUNDLE_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/BUNDLE/v2\0"
ADAPTER_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/PLAINTEXT-ADAPTER/v2\0"
REASON_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/REASON/v2\0"
ADDRESS_DOMAIN = b"BL/NATIVE-V3/CONTINUITY/STATE-ADDRESS/v2\0"

AUTH_MAGIC = b"BLNV3EA1"
AUTH_VERSION = 1
AUTH_ID_DOMAIN = b"BL/NATIVE-V3/EXCEPTION-AUTHORIZATION-ID/v1\0"
AUTH_SIGNATURE_DOMAIN = b"BL/NATIVE-V3/SYNTHETIC-AUTHORIZATION-SEAL/v1\0"

CONTROL_SCOPE = b"provider-credential-enrollment-continuity-v1"
CONFLICT_POLICY = b"priority-then-human-review"
DIRECTIVE_MAPPING = bytes((1, 2, 3, 4, 5))
CONTROL_EFFECTIVE_START = 6_000
CONTROL_EFFECTIVE_END = 9_000


def _sha(domain: bytes, *parts: bytes) -> bytes:
    hasher = hashlib.sha3_512()
    hasher.update(domain)
    for part in parts:
        hasher.update(part)
    return hasher.digest()


RULE_ID = _sha(b"BL/NATIVE-V3/RULE/v1\0", b"synthetic-clearance-rule-v1")
MODE_ID = _sha(MODE_DOMAIN, b"DIRECT_STATE_OWNED")
EVALUATOR_ID = _sha(EVALUATOR_DOMAIN, b"verifier-owned-plaintext-continuity-v1")
SYNTHETIC_PROVIDER_ID = _sha(
    b"BL/NATIVE-V3/CONTINUITY/SYNTHETIC-PROVIDER/v2\0",
    b"synthetic-provider-credential-continuity-1",
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
TRUSTED_AUTHORIZER_ID = _sha(
    b"BL/NATIVE-V3/AUTHORIZER/v1\0", b"synthetic-state-authorizer-v1"
)
EXPECTED_REASON_ID = _sha(
    b"BL/NATIVE-V3/EXCEPTION-REASON/v1\0", b"synthetic-governed-reason-v1"
)
EXPECTED_AMOUNT_SCOPE = _sha(
    b"BL/NATIVE-V3/AMOUNT-SCOPE/v1\0", b"synthetic-amount-scope-v1"
)
REASON_VALID = _sha(REASON_DOMAIN, b"valid-continuity")
REASON_EXPIRED_OR_TERMINATED = _sha(REASON_DOMAIN, b"expired-or-terminated")
REASON_MISSING_AUTHORITATIVE = _sha(REASON_DOMAIN, b"authoritative-absence")
REASON_INCOMPLETE_OR_AMBIGUOUS = _sha(REASON_DOMAIN, b"incomplete-or-ambiguous")
REASON_STALE_RULE = _sha(REASON_DOMAIN, b"stale-rule-interval")
REASON_CONTROL_INTERVAL = _sha(REASON_DOMAIN, b"control-set-decision-time")


def _u16(value: int) -> bytes:
    return value.to_bytes(2, "big")


def _u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def _u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def _take(data: bytes, offset: int, length: int, label: str) -> tuple[bytes, int]:
    if length < 0:
        raise IndependentParseError(f"{label}:negative-length")
    end = offset + length
    if end < offset or end > len(data):
        raise IndependentParseError(f"{label}:truncated")
    return data[offset:end], end


def _u32_at(data: bytes, offset: int, label: str) -> tuple[int, int]:
    raw, offset = _take(data, offset, 4, label)
    return int.from_bytes(raw, "big"), offset


def _u64_at(data: bytes, offset: int, label: str) -> tuple[int, int]:
    raw, offset = _take(data, offset, 8, label)
    return int.from_bytes(raw, "big"), offset


def _header(data: bytes, magic: bytes, label: str) -> int:
    if len(data) < 12 or data[:8] != magic or data[8:10] != _u16(VERSION) or data[10:12] != b"\0\0":
        raise IndependentParseError(f"{label}:v2-header")
    return 12


def _nonzero(value: bytes, label: str) -> None:
    if len(value) != 64 or not any(value):
        raise IndependentParseError(f"{label}:zero-or-width")


def _finish(offset: int, data: bytes, label: str) -> None:
    if offset != len(data):
        raise IndependentParseError(f"{label}:trailing")


def _source_address(provider_id: bytes) -> bytes:
    return _sha(ADDRESS_DOMAIN, b"credential-enrollment-source", provider_id)


def _audit_address(provider_id: bytes) -> bytes:
    return _sha(ADDRESS_DOMAIN, b"continuity-audit-head", provider_id)


def _control_set_bytes() -> bytes:
    return b"".join(
        (
            CONTROL_SET_MAGIC,
            _u16(VERSION),
            _u16(0),
            bytes((1,)),
            b"\0" * 3,
            MODE_ID,
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


def _initial_state_id(profile_id: bytes) -> bytes:
    context = _sha(STATE_CONTEXT_DOMAIN, profile_id, MODE_ID)
    raw = b"".join(
        (
            STATE_MAGIC,
            _u16(VERSION),
            _u16(0),
            context,
            _u64(0),
            _u32(0),
            b"\0" * 4,
            _sha(AUDIT_HEAD_DOMAIN, b"empty"),
            _sha(CONTINUITY_ROOT_DOMAIN, b"empty"),
        )
    )
    return _sha(STATE_ID_DOMAIN, raw)


def _parse_request(data: bytes) -> dict[str, Any]:
    if len(data) != REQUEST_BYTES:
        raise IndependentParseError("request:length")
    offset = _header(data, REQUEST_MAGIC, "request")
    provider, offset = _take(data, offset, 64, "request:provider")
    credential, offset = _take(data, offset, 64, "request:credential")
    enrollment, offset = _take(data, offset, 64, "request:enrollment")
    attempt, offset = _take(data, offset, 64, "request:attempt")
    epoch, offset = _u64_at(data, offset, "request:epoch")
    sequence, offset = _u64_at(data, offset, "request:sequence")
    event, offset = _u64_at(data, offset, "request:event")
    observation, offset = _u64_at(data, offset, "request:observation")
    rule_effective, offset = _u64_at(data, offset, "request:rule-effective")
    decision_time, offset = _u64_at(data, offset, "request:decision")
    expected_before, offset = _take(data, offset, 64, "request:before-state")
    _finish(offset, data, "request")
    if provider != SYNTHETIC_PROVIDER_ID or credential != SYNTHETIC_CREDENTIAL_ID or enrollment != SYNTHETIC_ENROLLMENT_ID:
        raise IndependentParseError("request:synthetic-identity")
    _nonzero(attempt, "request:attempt")
    if (epoch, sequence) != (7, 0):
        raise IndependentParseError("request:fixture-state")
    _nonzero(expected_before, "request:before-state")
    if not (rule_effective < event < observation < decision_time):
        raise IndependentParseError("request:chronology")
    subject = _sha(SUBJECT_KEY_DOMAIN, provider, credential, enrollment)
    return {
        "raw": data,
        "id": _sha(REQUEST_ID_DOMAIN, data),
        "provider_id": provider,
        "credential_id": credential,
        "enrollment_id": enrollment,
        "attempt_id": attempt,
        "epoch": epoch,
        "sequence_before": sequence,
        "event_time": event,
        "observation_time": observation,
        "rule_effective_time": rule_effective,
        "decision_time": decision_time,
        "expected_before_state_id": expected_before,
        "subject_key": subject,
    }


def _parse_fact_set(data: bytes, request: dict[str, Any]) -> dict[str, Any]:
    offset = _header(data, FACT_SET_MAGIC, "fact-set")
    feed, offset = _take(data, offset, 64, "fact-set:feed")
    if feed != SYNTHETIC_FEED_ID:
        raise IndependentParseError("fact-set:synthetic-feed")
    count, offset = _u32_at(data, offset, "fact-set:count")
    if count > MAX_FACTS:
        raise IndependentParseError("fact-set:count")
    records: list[dict[str, Any]] = []
    for index in range(count):
        length, offset = _u32_at(data, offset, f"fact-set:length-{index}")
        if length != FACT_BYTES:
            raise IndependentParseError("fact-set:fact-length")
        raw, offset = _take(data, offset, length, f"fact-set:fact-{index}")
        fact_offset = _header(raw, FACT_MAGIC, "fact")
        provider, fact_offset = _take(raw, fact_offset, 64, "fact:provider")
        credential, fact_offset = _take(raw, fact_offset, 64, "fact:credential")
        enrollment, fact_offset = _take(raw, fact_offset, 64, "fact:enrollment")
        fact_feed, fact_offset = _take(raw, fact_offset, 64, "fact:feed")
        status_raw, fact_offset = _take(raw, fact_offset, 1, "fact:status")
        reserved, fact_offset = _take(raw, fact_offset, 7, "fact:reserved")
        issued, fact_offset = _u64_at(raw, fact_offset, "fact:issued")
        expires, fact_offset = _u64_at(raw, fact_offset, "fact:expires")
        terminated, fact_offset = _u64_at(raw, fact_offset, "fact:terminated")
        observed, fact_offset = _u64_at(raw, fact_offset, "fact:observed")
        record_id, fact_offset = _take(raw, fact_offset, 64, "fact:id")
        _finish(fact_offset, raw, "fact")
        status = status_raw[0]
        if (
            provider != SYNTHETIC_PROVIDER_ID
            or credential != SYNTHETIC_CREDENTIAL_ID
            or enrollment != SYNTHETIC_ENROLLMENT_ID
            or fact_feed != feed
            or reserved != b"\0" * 7
            or status not in (FACT_ACTIVE, FACT_EXPIRED, FACT_TERMINATED)
            or issued >= expires
            or observed != request["observation_time"]
        ):
            raise IndependentParseError("fact:identity-or-snapshot")
        if status == FACT_ACTIVE and (terminated != 0 or not issued <= observed < expires):
            raise IndependentParseError("fact:active-temporal")
        if status == FACT_EXPIRED and (terminated != 0 or observed < expires):
            raise IndependentParseError("fact:expired-temporal")
        if status == FACT_TERMINATED and not issued <= terminated <= observed:
            raise IndependentParseError("fact:terminated-temporal")
        _nonzero(record_id, "fact:id")
        if _sha(FACT_ID_DOMAIN, raw[:-64]) != record_id:
            raise IndependentParseError("fact:id")
        records.append(
            {
                "raw": raw,
                "provider_id": provider,
                "credential_id": credential,
                "enrollment_id": enrollment,
                "feed_id": fact_feed,
                "status": status,
                "issued_at": issued,
                "expires_at": expires,
                "terminated_at": terminated,
                "observed_at": observed,
                "record_id": record_id,
                "subject_key": _sha(SUBJECT_KEY_DOMAIN, provider, credential, enrollment),
            }
        )
    _finish(offset, data, "fact-set")
    record_ids = [fact["record_id"] for fact in records]
    if record_ids != sorted(record_ids) or len(set(record_ids)) != len(record_ids):
        raise IndependentParseError("fact-set:order-or-duplicate")
    return {
        "raw": data,
        "feed_id": feed,
        "count": count,
        "facts": records,
        "source_root": _sha(SOURCE_ROOT_DOMAIN, data),
    }


def _parse_completeness(data: bytes, request: dict[str, Any]) -> dict[str, Any]:
    offset = _header(data, COMPLETENESS_MAGIC, "completeness")
    feed, offset = _take(data, offset, 64, "completeness:feed")
    provider, offset = _take(data, offset, 64, "completeness:provider")
    scope, offset = _take(data, offset, 64, "completeness:scope")
    observation, offset = _u64_at(data, offset, "completeness:observation")
    complete_raw, offset = _take(data, offset, 1, "completeness:complete")
    reserved, offset = _take(data, offset, 7, "completeness:reserved")
    count, offset = _u32_at(data, offset, "completeness:count")
    if (
        feed != SYNTHETIC_FEED_ID
        or provider != SYNTHETIC_PROVIDER_ID
        or scope != request["subject_key"]
        or observation != request["observation_time"]
        or complete_raw[0] not in (0, 1)
        or reserved != b"\0" * 7
        or count > MAX_FACTS
    ):
        raise IndependentParseError("completeness:identity-or-flags")
    keys: list[bytes] = []
    for index in range(count):
        key, offset = _take(data, offset, 64, f"completeness:key-{index}")
        _nonzero(key, "completeness:key")
        keys.append(key)
    _finish(offset, data, "completeness")
    if not complete_raw[0] and keys:
        raise IndependentParseError("completeness:incomplete-absence")
    if keys != sorted(keys) or len(set(keys)) != len(keys):
        raise IndependentParseError("completeness:absence-order-or-duplicate")
    return {
        "raw": data,
        "feed_id": feed,
        "provider_id": provider,
        "scope_id": scope,
        "observation_time": observation,
        "complete": bool(complete_raw[0]),
        "keys": keys,
        "id": _sha(COMPLETENESS_DOMAIN, data),
    }


def _parse_exception(data: bytes) -> dict[str, Any] | None:
    if data == SENTINEL:
        return None
    if len(data) != AUTH_BYTES:
        raise IndependentParseError("exception:length-or-sentinel")
    if data[:8] != AUTH_MAGIC or data[8:10] != _u16(AUTH_VERSION) or data[10:12] != b"\0\0":
        raise IndependentParseError("exception:header")
    authorization_id = data[12:76]
    signer_id = data[76:140]
    subject_id = data[140:204]
    rule_id = data[204:268]
    reason_id = data[268:332]
    amount_scope = data[332:396]
    effective_at = int.from_bytes(data[396:404], "big")
    expires_at = int.from_bytes(data[404:412], "big")
    policy_result = data[412]
    reserved = data[413:420]
    signature = data[420:484]
    for label, value in (
        ("exception:authorization", authorization_id),
        ("exception:signer", signer_id),
        ("exception:subject", subject_id),
        ("exception:rule", rule_id),
        ("exception:reason", reason_id),
        ("exception:amount", amount_scope),
        ("exception:signature", signature),
    ):
        _nonzero(value, label)
    if reserved != b"\0" * 7 or not effective_at < expires_at or policy_result not in (1, 2, 3, 4):
        raise IndependentParseError("exception:semantic")
    body = data[:12] + data[76:420]
    if _sha(AUTH_ID_DOMAIN, body) != authorization_id:
        raise IndependentParseError("exception:authorization-id")
    if _sha(AUTH_SIGNATURE_DOMAIN, signer_id, body) != signature:
        raise IndependentParseError("exception:signature")
    return {
        "raw": data,
        "authorization_id": authorization_id,
        "signer_id": signer_id,
        "subject_id": subject_id,
        "rule_id": rule_id,
        "reason_id": reason_id,
        "amount_scope": amount_scope,
        "effective_at": effective_at,
        "expires_at": expires_at,
        "policy_result": policy_result,
        "signature": signature,
    }


def _parse_state(data: bytes) -> dict[str, Any]:
    if len(data) != STATE_BYTES:
        raise IndependentParseError("state:length")
    offset = _header(data, STATE_MAGIC, "state")
    context, offset = _take(data, offset, 64, "state:context")
    sequence, offset = _u64_at(data, offset, "state:sequence")
    row_count, offset = _u32_at(data, offset, "state:row-count")
    reserved, offset = _take(data, offset, 4, "state:reserved")
    audit, offset = _take(data, offset, 64, "state:audit")
    root, offset = _take(data, offset, 64, "state:root")
    _finish(offset, data, "state")
    if (sequence, row_count) not in ((0, 0), (1, 1)) or reserved != b"\0" * 4:
        raise IndependentParseError("state:shape")
    _nonzero(context, "state:context")
    _nonzero(audit, "state:audit")
    _nonzero(root, "state:root")
    return {
        "raw": data,
        "context": context,
        "sequence": sequence,
        "row_count": row_count,
        "audit": audit,
        "root": root,
        "id": _sha(STATE_ID_DOMAIN, data),
    }


def _parse_decision(data: bytes) -> dict[str, Any]:
    if len(data) != DECISION_BYTES:
        raise IndependentParseError("decision:length")
    offset = _header(data, DECISION_MAGIC, "decision")
    decision_index, offset = _u32_at(data, offset, "decision:index")
    decision_count, offset = _u32_at(data, offset, "decision:count")
    identities: list[bytes] = []
    for index in range(19):
        value, offset = _take(data, offset, 64, f"decision:identity-{index}")
        _nonzero(value, "decision:identity")
        identities.append(value)
    flags, offset = _take(data, offset, 4, "decision:flags")
    reserved, offset = _take(data, offset, 4, "decision:reserved")
    event, offset = _u64_at(data, offset, "decision:event")
    observation, offset = _u64_at(data, offset, "decision:observation")
    rule_effective, offset = _u64_at(data, offset, "decision:rule-effective")
    decision_time, offset = _u64_at(data, offset, "decision:decision-time")
    _finish(offset, data, "decision")
    if (decision_index, decision_count) != (0, 1) or reserved != b"\0" * 4 or flags[2:] != b"\0\0":
        raise IndependentParseError("decision:shape-or-flags")
    policy, directive = flags[:2]
    if directive not in (1, 2, 3, 4, 5) or policy != {1: 1, 2: 2, 3: 3, 4: 4, 5: 4}[directive]:
        raise IndependentParseError("decision:policy-directive")
    if not (rule_effective < event < observation < decision_time):
        raise IndependentParseError("decision:chronology")
    if directive == DIRECTIVE_EXCEPTION:
        _nonzero(identities[13], "decision:exception")
    elif identities[13] != SENTINEL:
        raise IndependentParseError("decision:exception-sentinel")
    names = (
        "decision_id", "attempt_id", "provider_id", "credential_id", "enrollment_id",
        "mode_id", "control_set_id", "rule_id", "source_root", "phase0_receipt_binding",
        "completeness_id", "chronology_id", "replay_id", "exception_id", "state_before_id",
        "state_after_id", "decision_path_id", "reason_id", "request_id",
    )
    result = dict(zip(names, identities))
    result.update(
        {
            "policy_result": policy,
            "effective_directive": directive,
            "event_time": event,
            "observation_time": observation,
            "rule_effective_time": rule_effective,
            "decision_time": decision_time,
            "raw": data,
        }
    )
    return result


def _parse_access(data: bytes) -> dict[str, Any]:
    if len(data) != ACCESS_BYTES:
        raise IndependentParseError("access:length")
    offset = _header(data, ACCESS_MAGIC, "access")
    decision_id, offset = _take(data, offset, 64, "access:decision")
    decision_index, offset = _u32_at(data, offset, "access:decision-index")
    access_index, offset = _u32_at(data, offset, "access:index")
    access_count, offset = _u32_at(data, offset, "access:count")
    access_time, offset = _u64_at(data, offset, "access:time")
    address, offset = _take(data, offset, 64, "access:address")
    key, offset = _take(data, offset, 64, "access:key")
    before, offset = _take(data, offset, 64, "access:before")
    after, offset = _take(data, offset, 64, "access:after")
    mode_raw, offset = _take(data, offset, 1, "access:mode")
    reserved, offset = _take(data, offset, 7, "access:reserved")
    _finish(offset, data, "access")
    if (decision_index, access_count, access_index) not in ((0, 2, 0), (0, 2, 1)) or reserved != b"\0" * 7:
        raise IndependentParseError("access:shape")
    if mode_raw[0] == ACCESS_READ and before != after:
        raise IndependentParseError("access:read-mutates")
    if mode_raw[0] == ACCESS_WRITE and before == after:
        raise IndependentParseError("access:write-no-change")
    if mode_raw[0] not in (ACCESS_READ, ACCESS_WRITE):
        raise IndependentParseError("access:mode")
    _nonzero(decision_id, "access:decision")
    return {
        "decision_id": decision_id,
        "access_index": access_index,
        "access_time": access_time,
        "address": address,
        "key": key,
        "before": before,
        "after": after,
        "mode": mode_raw[0],
        "raw": data,
    }


def _evaluate_semantics(
    request: dict[str, Any],
    facts: dict[str, Any],
    completeness: dict[str, Any],
    exception: dict[str, Any] | None,
) -> tuple[int, int, bytes, bytes]:
    if not CONTROL_EFFECTIVE_START <= request["rule_effective_time"] < CONTROL_EFFECTIVE_END:
        policy, directive, reason = POLICY_AMBIGUOUS, DIRECTIVE_REVIEW, REASON_STALE_RULE
    elif not CONTROL_EFFECTIVE_START <= request["decision_time"] < CONTROL_EFFECTIVE_END:
        policy, directive, reason = POLICY_AMBIGUOUS, DIRECTIVE_REVIEW, REASON_CONTROL_INTERVAL
    else:
        matching = [fact for fact in facts["facts"] if fact["subject_key"] == request["subject_key"]]
        if len(matching) > 1:
            policy, directive, reason = POLICY_AMBIGUOUS, DIRECTIVE_REVIEW, REASON_INCOMPLETE_OR_AMBIGUOUS
        elif not matching:
            authoritative_absence = (
                completeness["complete"]
                and completeness["feed_id"] == facts["feed_id"]
                and completeness["provider_id"] == request["provider_id"]
                and completeness["scope_id"] == request["subject_key"]
                and completeness["observation_time"] == request["observation_time"]
                and request["subject_key"] in completeness["keys"]
            )
            if authoritative_absence:
                policy, directive, reason = POLICY_MISSING, DIRECTIVE_HOLD, REASON_MISSING_AUTHORITATIVE
            else:
                policy, directive, reason = POLICY_AMBIGUOUS, DIRECTIVE_REVIEW, REASON_INCOMPLETE_OR_AMBIGUOUS
        elif matching[0]["status"] == FACT_ACTIVE:
            policy, directive, reason = POLICY_PASS, DIRECTIVE_CLEAR, REASON_VALID
        elif matching[0]["status"] in (FACT_EXPIRED, FACT_TERMINATED):
            policy, directive, reason = POLICY_FAIL, DIRECTIVE_BLOCK, REASON_EXPIRED_OR_TERMINATED
        else:
            raise IndependentParseError("semantic:unknown-status")

    exception_id = SENTINEL
    if exception is not None:
        if policy != POLICY_FAIL:
            raise IndependentParseError("exception:underlying-result")
        if (
            exception["signer_id"] != TRUSTED_AUTHORIZER_ID
            or exception["subject_id"] != request["credential_id"]
            or exception["rule_id"] != RULE_ID
            or exception["reason_id"] != EXPECTED_REASON_ID
            or exception["amount_scope"] != EXPECTED_AMOUNT_SCOPE
            or exception["policy_result"] != policy
            or exception["effective_at"] > request["rule_effective_time"]
            or request["decision_time"] >= exception["expires_at"]
        ):
            raise IndependentParseError("exception:scope-or-interval")
        exception_id = exception["authorization_id"]
        directive = DIRECTIVE_EXCEPTION
    if policy != {1: 1, 2: 2, 3: 3, 4: 4, 5: 4}[directive]:
        raise IndependentParseError("semantic:policy-directive")
    return policy, directive, reason, exception_id


def parse_bundle(data: bytes) -> dict[str, Any]:
    if len(data) > MAX_BUNDLE_BYTES:
        raise IndependentParseError("bundle:size")
    offset = _header(data, BUNDLE_MAGIC, "bundle")
    caps = (8_192, REQUEST_BYTES, 4_096, 4_096, AUTH_BYTES, STATE_BYTES, STATE_BYTES)
    parts: list[bytes] = []
    for index, cap in enumerate(caps):
        length, offset = _u32_at(data, offset, f"bundle:length-{index}")
        if length > cap:
            raise IndependentParseError(f"bundle:part-{index}-cap")
        part, offset = _take(data, offset, length, f"bundle:part-{index}")
        parts.append(part)
    _finish(offset, data, "bundle")
    receipt_raw, request_raw, facts_raw, completeness_raw, exception_raw, before_raw, after_raw = parts
    request = _parse_request(request_raw)
    profile = build_profile_bindings()
    expected_initial = _initial_state_id(profile.profile_id)
    if request["expected_before_state_id"] != expected_initial:
        raise IndependentParseError("request:initial-before-state")
    facts = _parse_fact_set(facts_raw, request)
    completeness = _parse_completeness(completeness_raw, request)
    if any(fact["subject_key"] in completeness["keys"] for fact in facts["facts"]):
        raise IndependentParseError("completeness:fact-nonmembership-conflict")
    exception = _parse_exception(exception_raw)
    before = _parse_state(before_raw)
    after = _parse_state(after_raw)

    if len(receipt_raw) < 64:
        raise IndependentParseError("receipt:length")
    body = receipt_raw[:-64]
    receipt_id = receipt_raw[-64:]
    offset = _header(body, RECEIPT_MAGIC, "receipt")
    markers, offset = _take(body, offset, 4, "receipt:markers")
    reserved, offset = _take(body, offset, 4, "receipt:reserved")
    suite, offset = _take(body, offset, 64, "receipt:suite")
    adapter_binding, offset = _take(body, offset, 64, "receipt:adapter")
    control_id, offset = _take(body, offset, 64, "receipt:control")
    receipt_decision_id, offset = _take(body, offset, 64, "receipt:decision-id")
    receipt_join_id, offset = _take(body, offset, 64, "receipt:join-id")
    receipt_before_id, offset = _take(body, offset, 64, "receipt:before-id")
    receipt_after_id, offset = _take(body, offset, 64, "receipt:after-id")
    receipt_phase0, offset = _take(body, offset, 64, "receipt:phase0")
    decision_length, offset = _u32_at(body, offset, "receipt:decision-length")
    if decision_length != DECISION_BYTES:
        raise IndependentParseError("receipt:decision-length")
    decision_raw, offset = _take(body, offset, decision_length, "receipt:decision")
    decision = _parse_decision(decision_raw)
    access_count, offset = _u32_at(body, offset, "receipt:access-count")
    if access_count != 2:
        raise IndependentParseError("receipt:access-count")
    accesses: list[dict[str, Any]] = []
    access_raws: list[bytes] = []
    for index in range(2):
        length, offset = _u32_at(body, offset, f"receipt:access-length-{index}")
        if length != ACCESS_BYTES:
            raise IndependentParseError("receipt:access-length")
        raw, offset = _take(body, offset, length, f"receipt:access-{index}")
        access_raws.append(raw)
        accesses.append(_parse_access(raw))
    _finish(offset, body, "receipt")

    if markers != bytes((0, 0, 0, 1)) or reserved != b"\0" * 4 or suite != NULL_SUITE:
        raise IndependentParseError("receipt:profile-or-mutation")
    if _sha(RECEIPT_ID_DOMAIN, body) != receipt_id:
        raise IndependentParseError("receipt:id")
    if receipt_decision_id != decision["decision_id"] or control_id != decision["control_set_id"] or receipt_phase0 != decision["phase0_receipt_binding"]:
        raise IndependentParseError("receipt:decision-binding")
    if receipt_before_id != before["id"] or receipt_after_id != after["id"]:
        raise IndependentParseError("receipt:state-id")
    if decision["state_before_id"] != before["id"] or decision["state_after_id"] != after["id"]:
        raise IndependentParseError("decision:state-id")
    if decision["request_id"] != request["id"]:
        raise IndependentParseError("request:id")
    if (
        decision["attempt_id"] != request["attempt_id"]
        or decision["provider_id"] != request["provider_id"]
        or decision["credential_id"] != request["credential_id"]
        or decision["enrollment_id"] != request["enrollment_id"]
        or (decision["event_time"], decision["observation_time"], decision["rule_effective_time"], decision["decision_time"])
        != (request["event_time"], request["observation_time"], request["rule_effective_time"], request["decision_time"])
    ):
        raise IndependentParseError("request:decision-binding")
    if decision["source_root"] != facts["source_root"] or completeness["feed_id"] != facts["feed_id"]:
        raise IndependentParseError("source:root-or-feed")
    if decision["completeness_id"] != completeness["id"] or completeness["observation_time"] != decision["observation_time"]:
        raise IndependentParseError("completeness:binding")
    expected_control = _sha(CONTROL_SET_DOMAIN, _control_set_bytes())
    if control_id != expected_control or decision["mode_id"] != MODE_ID or decision["rule_id"] != RULE_ID:
        raise IndependentParseError("control-set:binding")
    if receipt_phase0 != profile.frozen_receipt_binding:
        raise IndependentParseError("phase0:receipt-binding")
    expected_adapter = _sha(ADAPTER_DOMAIN, profile.profile_id, profile.frozen_receipt_binding, facts["source_root"])
    if adapter_binding != expected_adapter:
        raise IndependentParseError("adapter:binding")
    expected_context = _sha(STATE_CONTEXT_DOMAIN, profile.profile_id, MODE_ID)
    if before["context"] != expected_context or after["context"] != expected_context:
        raise IndependentParseError("state:context")
    if before["id"] != expected_initial or (before["sequence"], before["row_count"]) != (0, 0):
        raise IndependentParseError("state:initial")
    if before["audit"] != _sha(AUDIT_HEAD_DOMAIN, b"empty") or before["root"] != _sha(CONTINUITY_ROOT_DOMAIN, b"empty"):
        raise IndependentParseError("state:initial-values")
    if request["expected_before_state_id"] != before["id"]:
        raise IndependentParseError("state:request-before")
    if (after["sequence"], after["row_count"]) != (1, 1):
        raise IndependentParseError("state:chronology")

    policy, directive, reason, expected_exception = _evaluate_semantics(request, facts, completeness, exception)
    if decision["policy_result"] != policy or decision["effective_directive"] != directive or decision["reason_id"] != reason:
        raise IndependentParseError("semantic:decision-binding")
    if decision["exception_id"] != expected_exception:
        raise IndependentParseError("exception:decision-binding")
    if exception is None and directive == DIRECTIVE_EXCEPTION:
        raise IndependentParseError("exception:missing")
    if exception is not None and exception["authorization_id"] != decision["exception_id"]:
        raise IndependentParseError("exception:id")
    expected_chronology = _sha(CHRONOLOGY_DOMAIN, request_raw)
    expected_replay = _sha(REPLAY_DOMAIN, request_raw, before["id"], facts["source_root"], control_id)
    expected_decision = _sha(
        DECISION_ID_DOMAIN,
        request_raw,
        before["id"],
        facts["source_root"],
        completeness["id"],
        bytes((policy, directive)),
        expected_exception,
    )
    expected_path = _sha(
        PATH_DOMAIN,
        control_id,
        RULE_ID,
        facts["source_root"],
        completeness["id"],
        reason,
        bytes((policy, directive)),
        expected_exception,
    )
    if (
        decision["decision_id"] != expected_decision
        or decision["chronology_id"] != expected_chronology
        or decision["replay_id"] != expected_replay
        or decision["decision_path_id"] != expected_path
    ):
        raise IndependentParseError("decision:identity-recompute")
    expected_audit = _sha(AUDIT_HEAD_DOMAIN, before["audit"], decision["decision_id"], bytes((directive,)))
    expected_root = _sha(CONTINUITY_ROOT_DOMAIN, before["root"], facts["source_root"], decision["decision_id"])
    if after["audit"] != expected_audit or after["root"] != expected_root:
        raise IndependentParseError("state:transition")

    if [row["access_index"] for row in accesses] != [0, 1] or any(row["decision_id"] != decision["decision_id"] for row in accesses):
        raise IndependentParseError("join:order-or-decision")
    if (
        accesses[0]["mode"] != ACCESS_READ
        or accesses[0]["access_time"] != request["observation_time"]
        or accesses[0]["address"] != _source_address(request["provider_id"])
        or accesses[0]["key"] != request["subject_key"]
        or accesses[0]["before"] != facts["source_root"]
        or accesses[0]["after"] != facts["source_root"]
    ):
        raise IndependentParseError("access:read")
    if (
        accesses[1]["mode"] != ACCESS_WRITE
        or accesses[1]["access_time"] != request["decision_time"]
        or accesses[1]["address"] != _audit_address(request["provider_id"])
        or accesses[1]["key"] != decision["decision_id"]
        or accesses[1]["before"] != before["audit"]
        or accesses[1]["after"] != after["audit"]
    ):
        raise IndependentParseError("access:write")
    join_raw = b"".join(
        (
            JOIN_MAGIC,
            _u16(VERSION),
            _u16(0),
            _u32(1),
            _u32(2),
            _u32(len(decision_raw)),
            decision_raw,
            *(_u32(len(raw)) + raw for raw in access_raws),
        )
    )
    if receipt_join_id != _sha(JOIN_DOMAIN, join_raw):
        raise IndependentParseError("join:id")

    return {
        "status": "NATIVE_V3_PLAINTEXT_CONTINUITY_INDEPENDENT_PARSE_PASS",
        "receipt_id": receipt_id.hex(),
        "bundle_sha3_512": _sha(BUNDLE_DOMAIN, data).hex(),
        "request_id": request["id"].hex(),
        "reason_id": reason.hex(),
        "policy_result": policy,
        "effective_directive": directive,
        "state_before_id": before["id"].hex(),
        "state_after_id": after["id"].hex(),
        "access_count": len(accesses),
        "proof_suite_id": None,
        "proof_session_accepted": False,
        "economic_mutation": False,
    }


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv if argv is None else argv)
    if len(args) != 2 or args[1] != "verify":
        print("usage: independent.py verify", file=sys.stderr)
        return 2
    data = sys.stdin.buffer.read(MAX_BUNDLE_BYTES + 1)
    if len(data) > MAX_BUNDLE_BYTES:
        print(json.dumps({"status": "NATIVE_V3_PLAINTEXT_CONTINUITY_INDEPENDENT_PARSE_REJECT", "error": "bundle:size"}, sort_keys=True))
        return 1
    try:
        payload = parse_bundle(data)
    except IndependentParseError as error:
        print(
            json.dumps(
                {
                    "status": "NATIVE_V3_PLAINTEXT_CONTINUITY_INDEPENDENT_PARSE_REJECT",
                    "error": str(error),
                },
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(payload, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
