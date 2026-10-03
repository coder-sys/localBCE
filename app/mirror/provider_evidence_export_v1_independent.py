"""Independent verifier for the bounded Provider Evidence Export V1.

This module owns no producer code, graph code, schema constants, persistence,
replay state, or transport.  It reparses only the response grammar and returns
an opaque typed projection.  Replay consumption belongs to the receiving Blind
governance owner.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
import traceback
from typing import NoReturn


class IndependentProviderEvidenceExportError(ValueError):
    """Raised for a malformed, rebound, stale, or noncanonical export."""


RESPONSE_DOMAIN = "BL/MIRROR/PROVIDER_EVIDENCE_EXPORT/RESPONSE"
CONSUMER_DOMAIN = "BLIND/PROVIDER_GOVERNANCE_EVIDENCE"
EVIDENCE_PROFILE = "provider-continuity-aggregate"
EVIDENCE_PROFILE_VERSION = 1
QUALIFICATION_STATUS = "SYNTHETIC_ONLY"
OUTCOME_KINDS = tuple(
    "CONTINUITY_CONFIRMED CREDENTIAL_EXPIRED ENROLLMENT_TERMINATED EVIDENCE_INCOMPLETE "
    "AUTHORITATIVE_RECORD_ABSENT SOURCE_CONFLICT COVERAGE_STALE".split()
)
RESPONSE_KEYS = set(
    "domain version operation_ref consumer_domain evidence_profile evidence_profile_version issued_at "
    "expires_at outcome source_count complete_source_count record_count finding_count discrepancy_count "
    "qualification_status synthetic_only production_usable activation clearance_authority "
    "payment_authority economic_mutation proofSuiteId".split()
)
MAX_BYTES = 4_096
MAX_TIME = 10**12
MAX_WINDOW_SECONDS = 300
MAX_SOURCE_COUNT = 2
MAX_RECORD_COUNT = 16
MAX_FINDING_COUNT = 8
MAX_DISCREPANCY_COUNT = 8
_OPERATION_REF = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class VerifiedProviderEvidenceExportV1:
    """Opaque allowlisted response projection for the receiving owner."""

    operation_ref: str
    consumer_domain: str
    evidence_profile: str
    evidence_profile_version: int
    issued_at: int
    expires_at: int
    outcome: str
    source_count: int
    complete_source_count: int
    record_count: int
    finding_count: int
    discrepancy_count: int
    qualification_status: str
    synthetic_only: bool
    production_usable: bool
    activation: bool
    clearance_authority: bool
    payment_authority: bool
    economic_mutation: bool
    proof_suite_id: None


def _fail(code: str) -> NoReturn:
    error = IndependentProviderEvidenceExportError(code)
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    raise error


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (RecursionError, TypeError, ValueError, UnicodeEncodeError):
        _fail("export:noncanonical")


def _duplicate_reject(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail("export:duplicate-key")
        result[key] = value
    return result


def _parse(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_BYTES:
        _fail("export:byte-cap")
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_duplicate_reject,
            parse_constant=lambda _value: _fail("export:constant"),
        )
    except IndependentProviderEvidenceExportError:
        raise
    except (RecursionError, UnicodeDecodeError, TypeError, ValueError, json.JSONDecodeError):
        _fail("export:parse")
    if not isinstance(value, dict) or _canonical(value) != raw:
        _fail("export:noncanonical")
    return value


def _expect_keys(value: object, expected: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        _fail("export:response-keys")
    return value


def _integer(value: object, code: str, *, minimum: int = 0, maximum: int = MAX_TIME) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _fail(code)
    return value


def _operation_ref(value: object, code: str = "export:operation-ref") -> str:
    if type(value) is not str or _OPERATION_REF.fullmatch(value) is None or set(value) == {"0"}:
        _fail(code)
    return value


def _flag(value: object, code: str, expected: bool) -> bool:
    if type(value) is not bool or value is not expected:
        _fail(code)
    return value


def _validate_aggregate_consistency(
    outcome: str,
    source_count: int,
    complete_source_count: int,
    record_count: int,
    finding_count: int,
    discrepancy_count: int,
) -> None:
    if outcome == "AUTHORITATIVE_RECORD_ABSENT":
        _fail("export:outcome-unreachable")
    if finding_count != 1:
        _fail("export:finding-count")
    if discrepancy_count > 1:
        _fail("export:discrepancy-count")
    if outcome == "SOURCE_CONFLICT":
        if discrepancy_count != 1 or complete_source_count != MAX_SOURCE_COUNT or record_count < 3:
            _fail("export:aggregate-consistency")
    elif outcome == "EVIDENCE_INCOMPLETE":
        if discrepancy_count != 0 or complete_source_count >= MAX_SOURCE_COUNT:
            _fail("export:aggregate-consistency")
    elif outcome == "COVERAGE_STALE":
        if discrepancy_count != 0:
            _fail("export:aggregate-consistency")
    elif discrepancy_count != 0 or complete_source_count != MAX_SOURCE_COUNT or record_count != 2:
        _fail("export:aggregate-consistency")


def _verify_export_inner(
    raw: bytes,
    *,
    expected_operation_ref: str,
    now: int,
) -> VerifiedProviderEvidenceExportV1:
    """Reparse and independently verify one response for one receiver operation."""

    expected_ref = _operation_ref(expected_operation_ref, "export:expected-operation-ref")
    current_time = _integer(now, "export:clock")
    value = _expect_keys(_parse(raw), RESPONSE_KEYS)
    if value["domain"] != RESPONSE_DOMAIN or type(value["version"]) is not int or value["version"] != 1:
        _fail("export:domain-version")
    if value["operation_ref"] != expected_ref:
        _fail("export:operation-binding")
    if value["consumer_domain"] != CONSUMER_DOMAIN:
        _fail("export:consumer-domain")
    if (
        value["evidence_profile"] != EVIDENCE_PROFILE
        or type(value["evidence_profile_version"]) is not int
        or value["evidence_profile_version"] != EVIDENCE_PROFILE_VERSION
    ):
        _fail("export:evidence-profile")
    issued_at = _integer(value["issued_at"], "export:issued-at")
    expires_at = _integer(value["expires_at"], "export:expires-at")
    if expires_at <= issued_at or expires_at - issued_at > MAX_WINDOW_SECONDS:
        _fail("export:window")
    if issued_at > current_time or expires_at <= current_time:
        _fail("export:time-window")
    if type(value["outcome"]) is not str or value["outcome"] not in OUTCOME_KINDS:
        _fail("export:outcome")
    source_count = _integer(value["source_count"], "export:source-count", minimum=MAX_SOURCE_COUNT, maximum=MAX_SOURCE_COUNT)
    complete_source_count = _integer(
        value["complete_source_count"],
        "export:complete-source-count",
        minimum=0,
        maximum=MAX_SOURCE_COUNT,
    )
    if complete_source_count > source_count:
        _fail("export:complete-source-count")
    record_count = _integer(value["record_count"], "export:record-count", minimum=0, maximum=MAX_RECORD_COUNT)
    finding_count = _integer(value["finding_count"], "export:finding-count", minimum=1, maximum=MAX_FINDING_COUNT)
    discrepancy_count = _integer(
        value["discrepancy_count"],
        "export:discrepancy-count",
        minimum=0,
        maximum=MAX_DISCREPANCY_COUNT,
    )
    _validate_aggregate_consistency(
        value["outcome"],
        source_count,
        complete_source_count,
        record_count,
        finding_count,
        discrepancy_count,
    )
    if value["qualification_status"] != QUALIFICATION_STATUS:
        _fail("export:qualification")
    _flag(value["synthetic_only"], "export:synthetic", True)
    _flag(value["production_usable"], "export:production", False)
    _flag(value["activation"], "export:activation", False)
    _flag(value["clearance_authority"], "export:clearance", False)
    _flag(value["payment_authority"], "export:payment", False)
    _flag(value["economic_mutation"], "export:economic", False)
    if value["proofSuiteId"] is not None:
        _fail("export:proof-suite")
    if _canonical(value) != raw:
        _fail("export:noncanonical")
    return VerifiedProviderEvidenceExportV1(
        operation_ref=expected_ref,
        consumer_domain=CONSUMER_DOMAIN,
        evidence_profile=EVIDENCE_PROFILE,
        evidence_profile_version=EVIDENCE_PROFILE_VERSION,
        issued_at=issued_at,
        expires_at=expires_at,
        outcome=value["outcome"],
        source_count=source_count,
        complete_source_count=complete_source_count,
        record_count=record_count,
        finding_count=finding_count,
        discrepancy_count=discrepancy_count,
        qualification_status=QUALIFICATION_STATUS,
        synthetic_only=True,
        production_usable=False,
        activation=False,
        clearance_authority=False,
        payment_authority=False,
        economic_mutation=False,
        proof_suite_id=None,
    )


def verify_export(
    raw: bytes,
    *,
    expected_operation_ref: str,
    now: int,
) -> VerifiedProviderEvidenceExportV1:
    """Reparse and independently verify one response for one receiver operation."""

    try:
        return _verify_export_inner(raw, expected_operation_ref=expected_operation_ref, now=now)
    except IndependentProviderEvidenceExportError as error:
        raw = b""
        expected_operation_ref = ""
        try:
            traceback.clear_frames(error.__traceback__)
        except Exception:
            pass
        raise
