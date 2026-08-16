"""Independent bounded verifier for the external Provider Trust Graph V1.

This file intentionally duplicates the small wire grammar and semantic
checks instead of importing the producer's records or evaluator.  Acceptance
means only that a synthetic read-only graph artifact is internally coherent;
it is not a clearance, payment, proof, or deployment decision.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
import re
import sys
from typing import Mapping, Sequence


class IndependentProviderTrustGraphError(ValueError):
    """Raised when the canonical graph artifact cannot be independently verified."""


SCHEMA = "mirror-provider-trust-graph-v1"
SCHEMA_V2 = "mirror-provider-trust-graph-v2"
SCOPE = "provider-credential-enrollment-continuity-v1"
PROVIDER_GRAPH_SUBJECT = "SYNTH_PROVIDER_001"
SUBJECT_KEY = "SYNTH_PROVIDER_001|SYNTH_CREDENTIAL_001|SYNTH_ENROLLMENT_001"
CREDENTIAL_ID = "SYNTH_CREDENTIAL_001"
ENROLLMENT_ID = "SYNTH_ENROLLMENT_001"
SOURCE_CREDENTIAL_ID = "SYNTH_SOURCE_CREDENTIAL_001"
SOURCE_ENROLLMENT_ID = "SYNTH_SOURCE_ENROLLMENT_001"
SOURCE_CREDENTIAL_KIND = "CREDENTIAL_REGISTRY"
SOURCE_ENROLLMENT_KIND = "ENROLLMENT_REGISTRY"
SOURCE_IDS = (SOURCE_CREDENTIAL_ID, SOURCE_ENROLLMENT_ID)
AUTH_CREDENTIAL_ID = "SYNTH_AUTHORITY_CREDENTIAL_001"
AUTH_ENROLLMENT_ID = "SYNTH_AUTHORITY_ENROLLMENT_001"
PROVENANCE_CREDENTIAL_ID = "SYNTH_PROVENANCE_CREDENTIAL_001"
PROVENANCE_ENROLLMENT_ID = "SYNTH_PROVENANCE_ENROLLMENT_001"
STATUS_ACTIVE = "ACTIVE"
STATUS_EXPIRED = "EXPIRED"
STATUS_TERMINATED = "TERMINATED"
STATUSES = (STATUS_ACTIVE, STATUS_EXPIRED, STATUS_TERMINATED)
FINDING_CONTINUITY = "CONTINUITY_CONFIRMED"
FINDING_EXPIRED = "CREDENTIAL_EXPIRED"
FINDING_TERMINATED = "ENROLLMENT_TERMINATED"
FINDING_INCOMPLETE = "EVIDENCE_INCOMPLETE"
FINDING_ABSENT = "AUTHORITATIVE_RECORD_ABSENT"
FINDING_CONFLICT = "SOURCE_CONFLICT"
FINDING_STALE = "COVERAGE_STALE"
FINDING_KINDS = (
    FINDING_CONTINUITY,
    FINDING_EXPIRED,
    FINDING_TERMINATED,
    FINDING_INCOMPLETE,
    FINDING_ABSENT,
    FINDING_CONFLICT,
    FINDING_STALE,
)
LIFECYCLE_OPEN = "OPEN"
LIFECYCLE_REMEDIATED = "REMEDIATED"
LIFECYCLE_RETEST_FAILED = "RETEST_FAILED"
LIFECYCLES = (LIFECYCLE_OPEN, LIFECYCLE_REMEDIATED, LIFECYCLE_RETEST_FAILED)
MAX_ARTIFACT_BYTES = 524_288
MAX_SOURCES = 2
MAX_RECORDS_PER_SOURCE = 8
MAX_FINDINGS = 8
MAX_DISCREPANCIES = 8
MAX_PARITY_CASES = 8
MAX_STRING_BYTES = 128
MAX_NODES = 4_096
MAX_DEPTH = 16
MAX_HISTORY_DEPTH = 1
MAX_TIMESTAMP = 2_147_483_647
SOURCE_INPUT_KEYS = {
    "source_id",
    "source_kind",
    "coverage_scope",
    "coverage_observation_time",
    "coverage_effective_start",
    "coverage_effective_end",
    "coverage_complete",
    "coverage_authority_id",
    "nonmembership_keys",
    "records",
    "provenance",
}
SOURCE_OUTPUT_KEYS = SOURCE_INPUT_KEYS | {"source_root"}
PROVENANCE_KEYS = {"provenance_id", "integrity_digest"}
RECORD_KEYS = {
    "record_id",
    "record_kind",
    "provider_id",
    "credential_id",
    "enrollment_id",
    "subject_key",
    "observed_at",
    "issued_at",
    "valid_from",
    "valid_until",
    "terminated_at",
    "status",
}
FINDING_KEYS = {
    "finding_id",
    "kind",
    "lifecycle",
    "subject_key",
    "observation_snapshot_id",
    "evidence_refs",
}
DISCREPANCY_KEYS = {
    "discrepancy_id",
    "kind",
    "responsibility_boundary",
    "evidence_refs",
    "parity_case_id",
}
REMEDIATION_OUTPUT_KEYS = {
    "action_artifact_id",
    "submitted_at",
    "retest_result",
    "prior_finding_ids",
    "prior_artifact",
}
PARITY_OUTPUT_KEYS = {
    "case_id",
    "expected_kind",
    "expected_present",
    "observed_kinds",
    "passed",
    "evidence_refs",
    "discrepancy_id",
}
IDENTITY_KEYS = {
    "provider_graph_subject",
    "scope",
    "observation_time",
    "snapshot_id",
    "snapshot_root",
    "source_coverage_root",
    "findings_root",
    "discrepancies_root",
    "remediation_root",
    "parity_root",
    "lifecycle",
    "prior_report_id",
    "prior_snapshot_id",
    "prior_snapshot_root",
}
TRANSITION_KEYS = {
    "transition_id",
    "transition_kind",
    "prior_report_id",
    "prior_snapshot_id",
    "prior_snapshot_root",
    "current_report_id",
    "current_snapshot_id",
    "current_snapshot_root",
}
REPORT_KEYS = {"report_id", "identity_material", "lifecycle"}
AUTHORITY_KEYS = {
    "clearance_authority",
    "payment_authority",
    "economic_mutation",
    "production_usable",
    "synthetic_only",
}
OUTPUT_KEYS = {
    "schema",
    "subject",
    "observation_snapshot",
    "source_coverage",
    "findings",
    "discrepancies",
    "remediation",
    "parity_cases",
    "transition",
    "report",
    "authority",
}
PROFILE_KEYS = {"profile_id", "version", "profile_digest"}
V2_OUTPUT_KEYS = OUTPUT_KEYS | {"profile"}
V2_IDENTITY_KEYS = IDENTITY_KEYS | PROFILE_KEYS
_RE_HEX = re.compile(r"^[0-9a-f]{128}$")
_RE_RECORD = re.compile(r"^SYNTH_(CREDENTIAL|ENROLLMENT)_RECORD_00[1-8]$")
_RE_ACTION = re.compile(r"^SYNTH_ACTION_00[1-8]$")


@dataclass(frozen=True)
class _GraphProfile:
    v2: bool
    schema: str
    profile_id: str | None
    version: int | None
    profile_digest: str | None
    subject: str
    scope: str
    credential_id: str
    enrollment_id: str
    subject_key: str
    source_roles: tuple[str, ...]
    source_kinds: tuple[str, ...]
    record_kinds: tuple[str, ...]
    authority_ids: tuple[str, ...]
    provenance_ids: tuple[str, ...]
    observation_start: int | None
    observation_end: int | None
    effective_start: int
    effective_end: int
    allow_nonmembership: bool

    def role_index(self, source_id: str) -> int:
        try:
            return self.source_roles.index(source_id)
        except ValueError as exc:
            raise IndependentProviderTrustGraphError("profile:source-role") from exc


def _profile_material(profile: object) -> dict[str, object]:
    details = getattr(profile, "source_role_details")
    return {
        "profile_id": getattr(profile, "profile_id"),
        "version": getattr(profile, "version"),
        "subject": getattr(profile, "subject"),
        "scope": getattr(profile, "scope"),
        "observation_window": {"start": getattr(profile, "observation_start"), "end": getattr(profile, "observation_end")},
        "effective_start": getattr(profile, "effective_start"),
        "effective_end": getattr(profile, "effective_end"),
        "source_roles": [
            {
                "source_id": getattr(role, "source_id"),
                "source_kind": getattr(role, "source_kind"),
                "record_kind": getattr(role, "record_kind"),
                "authority_id": getattr(role, "authority_id"),
                "provenance_id": getattr(role, "provenance_id"),
            }
            for role in details
        ],
        "require_complete": getattr(profile, "require_complete"),
        "credential_id": getattr(profile, "credential_id"),
        "enrollment_id": getattr(profile, "enrollment_id"),
        "verifier_id": getattr(profile, "verifier_id"),
        "verifier_epoch": getattr(profile, "verifier_epoch"),
        "evidence_mode": getattr(getattr(profile, "evidence_mode"), "value"),
        "allow_nonmembership": getattr(profile, "allow_nonmembership"),
        "canonical_order": getattr(profile, "canonical_order"),
        "root_rule": getattr(profile, "root_rule"),
    }


def _profile_digest(profile: object) -> str:
    h = hashlib.sha3_512()
    h.update(b"BL/MIRROR/SOURCE-ADMISSION/profile/v1\0")
    h.update(json.dumps(_profile_material(profile), ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii"))
    return h.hexdigest()


def _profile_view(profile: object | None) -> _GraphProfile:
    if isinstance(profile, _GraphProfile):
        return profile
    if profile is None:
        return _GraphProfile(
            False,
            SCHEMA,
            None,
            None,
            None,
            PROVIDER_GRAPH_SUBJECT,
            SCOPE,
            CREDENTIAL_ID,
            ENROLLMENT_ID,
            SUBJECT_KEY,
            SOURCE_IDS,
            (SOURCE_CREDENTIAL_KIND, SOURCE_ENROLLMENT_KIND),
            ("CREDENTIAL", "ENROLLMENT"),
            (AUTH_CREDENTIAL_ID, AUTH_ENROLLMENT_ID),
            (PROVENANCE_CREDENTIAL_ID, PROVENANCE_ENROLLMENT_ID),
            None,
            None,
            6_000,
            9_000,
            True,
        )
    try:
        details = getattr(profile, "source_role_details")
        roles = tuple(
            (
                getattr(role, "source_id"),
                getattr(role, "source_kind"),
                getattr(role, "record_kind"),
                getattr(role, "authority_id"),
                getattr(role, "provenance_id"),
            )
            for role in details
        )
        profile_digest = _profile_digest(profile)
        supplied_digest = getattr(profile, "profile_digest")
    except Exception as exc:
        raise IndependentProviderTrustGraphError("profile:configuration") from exc
    role_ids = tuple(role[0] for role in roles)
    if (
        len(roles) != 2
        or role_ids != tuple(sorted(role_ids))
        or len(set(role_ids)) != len(role_ids)
        or len(set(role[1] for role in roles)) != len(roles)
        or {role[2] for role in roles} != {"CREDENTIAL", "ENROLLMENT"}
        or profile_digest != supplied_digest
        or getattr(profile, "version") != 2
        or getattr(profile, "canonical_order") != "lexicographic-v1"
        or getattr(profile, "root_rule") != "source-root-v1"
        or type(getattr(profile, "allow_nonmembership")) is not bool
    ):
        raise IndependentProviderTrustGraphError("profile:configuration")
    subject = getattr(profile, "subject")
    credential_id = getattr(profile, "credential_id")
    enrollment_id = getattr(profile, "enrollment_id")
    return _GraphProfile(
        True,
        SCHEMA_V2,
        getattr(profile, "profile_id"),
        getattr(profile, "version"),
        profile_digest,
        subject,
        getattr(profile, "scope"),
        credential_id,
        enrollment_id,
        subject + "|" + credential_id + "|" + enrollment_id,
        role_ids,
        tuple(role[1] for role in roles),
        tuple(role[2] for role in roles),
        tuple(role[3] for role in roles),
        tuple(role[4] for role in roles),
        getattr(profile, "observation_start"),
        getattr(profile, "observation_end"),
        getattr(profile, "effective_start"),
        getattr(profile, "effective_end"),
        getattr(profile, "allow_nonmembership"),
    )


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise IndependentProviderTrustGraphError("json:noncanonical-value") from exc


def _duplicate_reject(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise IndependentProviderTrustGraphError("json:duplicate-key")
        result[key] = value
    return result


def _walk(value: object, depth: int = 0, count: list[int] | None = None) -> None:
    count = [0] if count is None else count
    count[0] += 1
    if count[0] > MAX_NODES:
        raise IndependentProviderTrustGraphError("json:node-cap")
    if depth > MAX_DEPTH:
        raise IndependentProviderTrustGraphError("json:depth-cap")
    if isinstance(value, float):
        raise IndependentProviderTrustGraphError("json:float-forbidden")
    if isinstance(value, str):
        try:
            size = len(value.encode("ascii"))
        except UnicodeEncodeError as exc:
            raise IndependentProviderTrustGraphError("json:non-ascii") from exc
        if size > MAX_STRING_BYTES:
            raise IndependentProviderTrustGraphError("json:string-cap")
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise IndependentProviderTrustGraphError("json:key-type")
            _walk(key, depth + 1, count)
            _walk(item, depth + 1, count)
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth + 1, count)


def _parse(raw: bytes) -> dict[str, object]:
    if not isinstance(raw, bytes) or not raw:
        raise IndependentProviderTrustGraphError("json:empty-or-type")
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise IndependentProviderTrustGraphError("json:byte-cap")
    try:
        text = raw.decode("utf-8", errors="strict")
        if text.startswith("\ufeff"):
            raise IndependentProviderTrustGraphError("json:bom")
        value = json.loads(
            text,
            object_pairs_hook=_duplicate_reject,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                IndependentProviderTrustGraphError("json:constant-forbidden")
            ),
        )
    except IndependentProviderTrustGraphError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IndependentProviderTrustGraphError("json:parse") from exc
    if not isinstance(value, dict):
        raise IndependentProviderTrustGraphError("json:top-level")
    _walk(value)
    if _canonical(value) != raw:
        raise IndependentProviderTrustGraphError("json:not-canonical")
    return value


def _digest(label: str, value: object, *, profile: _GraphProfile | None = None) -> str:
    h = hashlib.sha3_512()
    version = "v2" if profile is not None and profile.v2 else "v1"
    h.update(("BL/MIRROR/PROVIDER-TRUST-GRAPH/" + label + "/" + version + "\0").encode("ascii"))
    h.update(_canonical(value))
    return h.hexdigest()


def _expect_keys(value: object, expected: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise IndependentProviderTrustGraphError(f"{label}:schema")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise IndependentProviderTrustGraphError(f"{label}:text")
    try:
        size = len(value.encode("ascii"))
    except UnicodeEncodeError as exc:
        raise IndependentProviderTrustGraphError(f"{label}:ascii") from exc
    if size > MAX_STRING_BYTES:
        raise IndependentProviderTrustGraphError(f"{label}:length")
    return value


def _int(value: object, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise IndependentProviderTrustGraphError(f"{label}:integer")
    if not minimum <= value <= MAX_TIMESTAMP:
        raise IndependentProviderTrustGraphError(f"{label}:range")
    return value


def _bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise IndependentProviderTrustGraphError(f"{label}:boolean")
    return value


def _hex(value: object, label: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str) or _RE_HEX.fullmatch(value) is None:
        raise IndependentProviderTrustGraphError(f"{label}:hex")
    return value


def _sorted_unique(values: object, label: str, *, maximum: int) -> list[str]:
    if not isinstance(values, list) or len(values) > maximum:
        raise IndependentProviderTrustGraphError(f"{label}:list-cap")
    result = [_text(item, label) for item in values]
    if result != sorted(result) or len(set(result)) != len(result):
        raise IndependentProviderTrustGraphError(f"{label}:order-or-duplicate")
    return result


def _expected_status(record: Mapping[str, object], observation_time: int) -> str:
    issued = record["issued_at"]
    valid_until = record["valid_until"]
    terminated = record["terminated_at"]
    assert isinstance(issued, int) and isinstance(valid_until, int) and isinstance(terminated, int)
    if record["record_kind"] == "CREDENTIAL":
        if terminated != 0:
            raise IndependentProviderTrustGraphError("record:credential-termination")
        return STATUS_ACTIVE if observation_time < valid_until else STATUS_EXPIRED
    if terminated:
        if not issued <= terminated <= observation_time:
            raise IndependentProviderTrustGraphError("record:termination-time")
        return STATUS_TERMINATED
    return STATUS_ACTIVE if observation_time < valid_until else STATUS_EXPIRED


def _validate_record(
    value: object,
    source_kind: str,
    observation_time: int,
    *,
    profile: _GraphProfile | None = None,
) -> dict[str, object]:
    view = _profile_view(profile)
    record = _expect_keys(value, RECORD_KEYS, "record")
    record_id = _text(record["record_id"], "record:id")
    if _RE_RECORD.fullmatch(record_id) is None:
        raise IndependentProviderTrustGraphError("record:id:not-synthetic")
    try:
        role_index = view.source_kinds.index(source_kind)
    except ValueError as exc:
        raise IndependentProviderTrustGraphError("record:source-mismatch") from exc
    expected_kind = view.record_kinds[role_index]
    expected_prefix = "SYNTH_" + expected_kind
    if not record_id.startswith(expected_prefix):
        raise IndependentProviderTrustGraphError("record:id:source-mismatch")
    if record["record_kind"] != expected_kind:
        raise IndependentProviderTrustGraphError("record:kind:source-mismatch")
    for field, expected in (
        ("provider_id", view.subject),
        ("credential_id", view.credential_id),
        ("enrollment_id", view.enrollment_id),
        ("subject_key", view.subject_key),
    ):
        if _text(record[field], "record:" + field) != expected:
            raise IndependentProviderTrustGraphError("record:identity-mismatch")
    if _int(record["observed_at"], "record:observed-at") != observation_time:
        raise IndependentProviderTrustGraphError("record:observation-mismatch")
    issued = _int(record["issued_at"], "record:issued-at")
    valid_from = _int(record["valid_from"], "record:valid-from")
    valid_until = _int(record["valid_until"], "record:valid-until")
    _int(record["terminated_at"], "record:terminated-at")
    if issued != valid_from or valid_until <= issued:
        raise IndependentProviderTrustGraphError("record:interval-contradiction")
    status = _text(record["status"], "record:status")
    if status not in STATUSES:
        raise IndependentProviderTrustGraphError("record:status:enum")
    if status != _expected_status(record, observation_time):
        raise IndependentProviderTrustGraphError("record:status-time-mismatch")
    if expected_kind == "CREDENTIAL" and status == STATUS_TERMINATED:
        raise IndependentProviderTrustGraphError("record:credential-status")
    if expected_kind == "ENROLLMENT" and status == STATUS_EXPIRED:
        raise IndependentProviderTrustGraphError("record:enrollment-status")
    return record


def _integrity_material(source: Mapping[str, object]) -> dict[str, object]:
    material = dict(source)
    provenance = dict(material["provenance"])  # type: ignore[arg-type]
    provenance.pop("integrity_digest", None)
    material["provenance"] = provenance
    material.pop("source_root", None)
    return material


def _integrity_digest(source: Mapping[str, object], *, profile: _GraphProfile | None = None) -> str:
    return _digest("source-integrity", _integrity_material(source), profile=profile)


def _source_root(source: Mapping[str, object], *, profile: _GraphProfile | None = None) -> str:
    return _digest("source-root", {"source": dict(source)}, profile=profile)


def _validate_source(
    value: object,
    observation_time: int,
    *,
    profile: _GraphProfile | None = None,
) -> dict[str, object]:
    view = _profile_view(profile)
    source = _expect_keys(value, SOURCE_OUTPUT_KEYS, "source")
    source_id = _text(source["source_id"], "source:id")
    source_kind = _text(source["source_kind"], "source:kind")
    if source_id not in view.source_roles or source_kind not in view.source_kinds:
        raise IndependentProviderTrustGraphError("source:identity")
    role_index = view.role_index(source_id)
    expected = (view.source_kinds[role_index], view.authority_ids[role_index], view.provenance_ids[role_index])
    provenance = _expect_keys(source["provenance"], PROVENANCE_KEYS, "source:provenance")
    if (source_kind, source["coverage_authority_id"], provenance["provenance_id"]) != expected:
        raise IndependentProviderTrustGraphError("source:authority-or-provenance")
    if source_kind != view.source_kinds[role_index]:
        raise IndependentProviderTrustGraphError("source:kind-id-mismatch")
    if _text(source["coverage_scope"], "source:scope") != view.scope:
        raise IndependentProviderTrustGraphError("source:scope")
    if _int(source["coverage_observation_time"], "source:coverage-observation") != observation_time:
        raise IndependentProviderTrustGraphError("source:coverage-observation-mismatch")
    start = _int(source["coverage_effective_start"], "source:coverage-start")
    end = _int(source["coverage_effective_end"], "source:coverage-end")
    if start >= end:
        raise IndependentProviderTrustGraphError("source:coverage-interval")
    _bool(source["coverage_complete"], "source:complete")
    _text(source["coverage_authority_id"], "source:authority")
    nonmembership = _sorted_unique(source["nonmembership_keys"], "source:nonmembership", maximum=2)
    if nonmembership and not view.allow_nonmembership:
        raise IndependentProviderTrustGraphError("source:nonmembership-policy")
    if any(value != view.subject_key for value in nonmembership):
        raise IndependentProviderTrustGraphError("source:nonmembership-identity")
    records = source["records"]
    if not isinstance(records, list) or len(records) > MAX_RECORDS_PER_SOURCE:
        raise IndependentProviderTrustGraphError("source:record-cap")
    record_items = [_validate_record(record, source_kind, observation_time, profile=view) for record in records]
    ids = [record["record_id"] for record in record_items]
    if ids != sorted(ids) or len(set(ids)) != len(ids):
        raise IndependentProviderTrustGraphError("source:record-order-or-duplicate")
    _text(provenance["provenance_id"], "source:provenance-id")
    _hex(provenance["integrity_digest"], "source:integrity")
    _hex(source["source_root"], "source:root")
    return source


def _fact_nonmembership_conflict(sources: Sequence[Mapping[str, object]]) -> None:
    for source in sources:
        facts = {record["subject_key"] for record in source["records"]}  # type: ignore[union-attr]
        nonmembership = set(source["nonmembership_keys"])  # type: ignore[arg-type]
        if facts & nonmembership:
            raise IndependentProviderTrustGraphError("completeness:fact-nonmembership-conflict")


def _validate_sources(
    sources: object,
    observation_time: int,
    *,
    profile: _GraphProfile | None = None,
) -> list[dict[str, object]]:
    view = _profile_view(profile)
    if not isinstance(sources, list) or len(sources) != len(view.source_roles):
        raise IndependentProviderTrustGraphError("sources:exact-count")
    items = [_validate_source(source, observation_time, profile=view) for source in sources]
    ids = [source["source_id"] for source in items]
    if ids != list(view.source_roles) or ids != sorted(ids):
        raise IndependentProviderTrustGraphError("sources:identity-or-order")
    # This contradiction is checked before the digest/root checks so a mutated
    # completeness record is rejected as contradictory evidence, not merely as
    # a downstream hash failure.
    _fact_nonmembership_conflict(items)
    for source in items:
        if source["provenance"]["integrity_digest"] != _integrity_digest(source, profile=view):  # type: ignore[index]
            raise IndependentProviderTrustGraphError("source:integrity-mismatch")
        without_root = {key: value for key, value in source.items() if key != "source_root"}
        if source["source_root"] != _source_root(without_root, profile=view):
            raise IndependentProviderTrustGraphError("source:root-mismatch")
    return items


def _finding(value: object, snapshot_id: str, *, profile: _GraphProfile | None = None) -> dict[str, object]:
    view = _profile_view(profile)
    item = _expect_keys(value, FINDING_KEYS, "finding")
    finding_id = _hex(item["finding_id"], "finding:id")
    kind = _text(item["kind"], "finding:kind")
    if kind not in FINDING_KINDS:
        raise IndependentProviderTrustGraphError("finding:kind")
    lifecycle = _text(item["lifecycle"], "finding:lifecycle")
    if lifecycle not in LIFECYCLES:
        raise IndependentProviderTrustGraphError("finding:lifecycle")
    if _text(item["subject_key"], "finding:subject") != view.subject_key:
        raise IndependentProviderTrustGraphError("finding:subject")
    if _text(item["observation_snapshot_id"], "finding:snapshot") != snapshot_id:
        raise IndependentProviderTrustGraphError("finding:snapshot-mismatch")
    refs = _sorted_unique(item["evidence_refs"], "finding:evidence", maximum=MAX_RECORDS_PER_SOURCE * MAX_SOURCES)
    expected_id = _digest(
        "finding-id",
        {
            "kind": kind,
            "subject_key": view.subject_key,
            "observation_snapshot_id": snapshot_id,
            "evidence_refs": refs,
        },
        profile=view,
    )
    if finding_id != expected_id:
        raise IndependentProviderTrustGraphError("finding:id-mismatch")
    return item


def _findings_root(findings: Sequence[Mapping[str, object]], *, profile: _GraphProfile | None = None) -> str:
    return _digest("findings-root", {"findings": list(findings)}, profile=profile)


def _validate_identity(identity: object, *, profile: _GraphProfile | None = None) -> dict[str, object]:
    view = _profile_view(profile)
    item = _expect_keys(identity, V2_IDENTITY_KEYS if view.v2 else IDENTITY_KEYS, "identity")
    if _text(item["provider_graph_subject"], "identity:subject") != view.subject or _text(item["scope"], "identity:scope") != view.scope:
        raise IndependentProviderTrustGraphError("identity:subject-or-scope")
    if view.v2 and (
        item["profile_id"] != view.profile_id
        or item["version"] != view.version
        or item["profile_digest"] != view.profile_digest
    ):
        raise IndependentProviderTrustGraphError("identity:profile")
    _int(item["observation_time"], "identity:observation-time", minimum=1)
    _text(item["snapshot_id"], "identity:snapshot")
    _hex(item["snapshot_root"], "identity:snapshot-root")
    for field in ("source_coverage_root", "findings_root", "discrepancies_root", "parity_root"):
        _hex(item[field], "identity:" + field)
    _hex(item["remediation_root"], "identity:remediation-root", nullable=True)
    if _text(item["lifecycle"], "identity:lifecycle") not in LIFECYCLES:
        raise IndependentProviderTrustGraphError("identity:lifecycle")
    _hex(item["prior_report_id"], "identity:prior-report", nullable=True)
    if item["prior_snapshot_id"] is not None:
        _text(item["prior_snapshot_id"], "identity:prior-snapshot")
    _hex(item["prior_snapshot_root"], "identity:prior-snapshot-root", nullable=True)
    prior_link = (
        item["prior_report_id"],
        item["prior_snapshot_id"],
        item["prior_snapshot_root"],
    )
    if not (all(value is None for value in prior_link) or all(value is not None for value in prior_link)):
        raise IndependentProviderTrustGraphError("identity:prior-link")
    return item


def _validate_prior_artifact(value: object, *, profile: _GraphProfile | None = None) -> dict[str, object]:
    """Independently verify the complete initial artifact used for retest."""

    item = _verify_artifact(value, allow_retest=False, history_depth=0, profile=profile)
    report = _expect_keys(item["report"], REPORT_KEYS, "prior-artifact:report")
    identity = _validate_identity(report["identity_material"], profile=profile)
    if report["lifecycle"] != LIFECYCLE_OPEN or item["remediation"] is not None:
        raise IndependentProviderTrustGraphError("prior-artifact:must-be-initial-open")
    if identity["lifecycle"] != LIFECYCLE_OPEN or any(
        value is not None
        for value in (
            identity["prior_report_id"],
            identity["prior_snapshot_id"],
            identity["prior_snapshot_root"],
        )
    ):
        raise IndependentProviderTrustGraphError("prior-artifact:must-be-initial-open")
    transition = _expect_keys(item["transition"], TRANSITION_KEYS, "prior-artifact:transition")
    if transition["transition_kind"] != "INITIAL" or any(
        transition[field] is not None
        for field in ("prior_report_id", "prior_snapshot_id", "prior_snapshot_root")
    ):
        raise IndependentProviderTrustGraphError("prior-artifact:must-be-initial-open")
    return item


def _make_finding(kind: str, snapshot_id: str, refs: Sequence[str], *, profile: _GraphProfile | None = None) -> dict[str, object]:
    view = _profile_view(profile)
    refs = sorted(refs)
    body = {
        "kind": kind,
        "lifecycle": LIFECYCLE_OPEN,
        "subject_key": view.subject_key,
        "observation_snapshot_id": snapshot_id,
        "evidence_refs": refs,
    }
    return {"finding_id": _digest("finding-id", {key: body[key] for key in ("kind", "subject_key", "observation_snapshot_id", "evidence_refs")}, profile=view), **body}


def _make_discrepancy(kind: str, responsibility: str, refs: Sequence[str], parity_case_id: str | None, *, profile: _GraphProfile | None = None) -> dict[str, object]:
    body = {
        "kind": kind,
        "responsibility_boundary": responsibility,
        "evidence_refs": sorted(refs),
        "parity_case_id": parity_case_id,
    }
    return {"discrepancy_id": _digest("discrepancy-id", body, profile=profile), **body}


def _evaluate(
    sources: Sequence[Mapping[str, object]],
    observation_time: int,
    snapshot_id: str,
    *,
    profile: _GraphProfile | None = None,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    view = _profile_view(profile)
    stale = [source["source_id"] for source in sources if not source["coverage_effective_start"] <= observation_time < source["coverage_effective_end"]]  # type: ignore[operator]
    if stale:
        return [_make_finding(FINDING_STALE, snapshot_id, stale, profile=view)], []
    incomplete = [source["source_id"] for source in sources if not source["coverage_complete"]]
    if incomplete:
        return [_make_finding(FINDING_INCOMPLETE, snapshot_id, incomplete, profile=view)], []
    matches = [record for source in sources for record in source["records"]]  # type: ignore[union-attr]
    missing = [source for source in sources if not source["records"]]
    if missing:
        if view.allow_nonmembership and not matches and all(source["nonmembership_keys"] == [view.subject_key] for source in sources):  # type: ignore[comparison-overlap]
            return [_make_finding(FINDING_ABSENT, snapshot_id, list(view.source_roles), profile=view)], []
        raise IndependentProviderTrustGraphError("evidence:partial-absence")
    if any(len(source["records"]) > 1 for source in sources):  # type: ignore[arg-type]
        refs = [record["record_id"] for record in matches]
        return [_make_finding(FINDING_CONFLICT, snapshot_id, refs, profile=view)], [_make_discrepancy("SOURCE_CONFLICT_EVIDENCE", "SOURCE_RECONCILIATION_REQUIRED", refs, None, profile=view)]
    credential = next(record for record in matches if record["record_kind"] == "CREDENTIAL")
    enrollment = next(record for record in matches if record["record_kind"] == "ENROLLMENT")
    refs = [credential["record_id"], enrollment["record_id"]]
    if credential["status"] == STATUS_EXPIRED:
        return [_make_finding(FINDING_EXPIRED, snapshot_id, refs, profile=view)], []
    if enrollment["status"] == STATUS_TERMINATED:
        return [_make_finding(FINDING_TERMINATED, snapshot_id, refs, profile=view)], []
    return [_make_finding(FINDING_CONTINUITY, snapshot_id, refs, profile=view)], []


def _validate_parity(value: object, findings: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) > MAX_PARITY_CASES:
        raise IndependentProviderTrustGraphError("parity:count-cap")
    observed = sorted({finding["kind"] for finding in findings})
    result: list[dict[str, object]] = []
    for raw in value:
        item = _expect_keys(raw, PARITY_OUTPUT_KEYS, "parity")
        case_id = _text(item["case_id"], "parity:id")
        expected_kind = _text(item["expected_kind"], "parity:expected-kind")
        if expected_kind not in FINDING_KINDS:
            raise IndependentProviderTrustGraphError("parity:expected-kind")
        expected_present = _bool(item["expected_present"], "parity:expected-present")
        observed_kinds = _sorted_unique(item["observed_kinds"], "parity:observed", maximum=MAX_FINDINGS)
        if observed_kinds != observed:
            raise IndependentProviderTrustGraphError("parity:observed-mismatch")
        passed = _bool(item["passed"], "parity:passed")
        if passed != ((expected_kind in observed) == expected_present):
            raise IndependentProviderTrustGraphError("parity:result-mismatch")
        refs = _sorted_unique(item["evidence_refs"], "parity:evidence", maximum=MAX_FINDINGS)
        expected_refs = sorted(finding["finding_id"] for finding in findings if finding["kind"] == expected_kind)
        if refs != expected_refs:
            raise IndependentProviderTrustGraphError("parity:evidence-mismatch")
        discrepancy_id = _hex(item["discrepancy_id"], "parity:discrepancy", nullable=True)
        if passed != (discrepancy_id is None):
            raise IndependentProviderTrustGraphError("parity:discrepancy-binding")
        result.append(item)
    ids = [case["case_id"] for case in result]
    if ids != sorted(ids) or len(set(ids)) != len(ids):
        raise IndependentProviderTrustGraphError("parity:order-or-duplicate")
    return result


def _validate_discrepancies(value: object, findings: Sequence[Mapping[str, object]], parity: Sequence[Mapping[str, object]], *, profile: _GraphProfile | None = None) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) > MAX_DISCREPANCIES:
        raise IndependentProviderTrustGraphError("discrepancy:count-cap")
    parity_ids = {case["case_id"] for case in parity}
    result: list[dict[str, object]] = []
    for raw in value:
        item = _expect_keys(raw, DISCREPANCY_KEYS, "discrepancy")
        discrepancy_id = _hex(item["discrepancy_id"], "discrepancy:id")
        kind = _text(item["kind"], "discrepancy:kind")
        responsibility = _text(item["responsibility_boundary"], "discrepancy:responsibility")
        if (kind, responsibility) not in (
            ("SOURCE_CONFLICT_EVIDENCE", "SOURCE_RECONCILIATION_REQUIRED"),
            ("PARITY_MISMATCH", "EVIDENCE_AND_EXPECTATION_REVIEW"),
        ):
            raise IndependentProviderTrustGraphError("discrepancy:kind-or-responsibility")
        refs = _sorted_unique(item["evidence_refs"], "discrepancy:evidence", maximum=MAX_RECORDS_PER_SOURCE * MAX_SOURCES)
        parity_case_id = item["parity_case_id"]
        if kind == "PARITY_MISMATCH":
            if parity_case_id is None or parity_case_id not in parity_ids:
                raise IndependentProviderTrustGraphError("discrepancy:parity-reference")
        elif parity_case_id is not None:
            raise IndependentProviderTrustGraphError("discrepancy:source-reference")
        expected = _digest("discrepancy-id", {key: item[key] for key in DISCREPANCY_KEYS if key != "discrepancy_id"}, profile=profile)
        if discrepancy_id != expected:
            raise IndependentProviderTrustGraphError("discrepancy:id-mismatch")
        result.append(item)
    ids = [item["discrepancy_id"] for item in result]
    if ids != sorted(ids) or len(set(ids)) != len(ids):
        raise IndependentProviderTrustGraphError("discrepancy:order-or-duplicate")
    return result


def _verify_artifact(
    artifact: object,
    *,
    allow_retest: bool,
    history_depth: int,
    profile: _GraphProfile | None = None,
) -> dict[str, object]:
    view = _profile_view(profile)
    item = _expect_keys(artifact, V2_OUTPUT_KEYS if view.v2 else OUTPUT_KEYS, "artifact")
    if _text(item["schema"], "artifact:schema") != view.schema:
        raise IndependentProviderTrustGraphError("artifact:schema")
    if view.v2:
        artifact_profile = _expect_keys(item["profile"], PROFILE_KEYS, "artifact:profile")
        if artifact_profile != {"profile_id": view.profile_id, "version": view.version, "profile_digest": view.profile_digest}:
            raise IndependentProviderTrustGraphError("artifact:profile")
    subject = _expect_keys(item["subject"], {"provider_graph_subject", "scope"}, "subject")
    if _text(subject["provider_graph_subject"], "subject") != view.subject or _text(subject["scope"], "scope") != view.scope:
        raise IndependentProviderTrustGraphError("subject:identity")
    snapshot = _expect_keys(item["observation_snapshot"], {"snapshot_id", "snapshot_root", "observation_time"}, "snapshot")
    snapshot_id = _text(snapshot["snapshot_id"], "snapshot:id")
    snapshot_root = _hex(snapshot["snapshot_root"], "snapshot:root")
    observation_time = _int(snapshot["observation_time"], "snapshot:time", minimum=1)
    if view.v2 and not view.observation_start <= observation_time < view.observation_end:  # type: ignore[operator]
        raise IndependentProviderTrustGraphError("snapshot:observation-window")
    sources = _validate_sources(item["source_coverage"], observation_time, profile=view)
    expected_snapshot_root = _digest(
        "snapshot-root",
        {
            "provider_graph_subject": view.subject,
            "scope": view.scope,
            "observation_time": observation_time,
            "source_roots": [source["source_root"] for source in sources],
        },
        profile=view,
    )
    if snapshot_root != expected_snapshot_root:
        raise IndependentProviderTrustGraphError("snapshot:root-mismatch")
    if snapshot_id != _digest("snapshot-id", {"snapshot_root": snapshot_root, "observation_time": observation_time}, profile=view):
        raise IndependentProviderTrustGraphError("snapshot:id-mismatch")
    finding_values = item["findings"]
    if not isinstance(finding_values, list) or len(finding_values) > MAX_FINDINGS:
        raise IndependentProviderTrustGraphError("finding:count-cap")
    findings = [_finding(value, snapshot_id, profile=view) for value in finding_values]
    finding_ids = [finding["finding_id"] for finding in findings]
    if finding_ids != sorted(finding_ids) or len(set(finding_ids)) != len(finding_ids):
        raise IndependentProviderTrustGraphError("finding:order-or-duplicate")
    expected_findings, expected_discrepancies = _evaluate(sources, observation_time, snapshot_id, profile=view)
    if findings != expected_findings:
        raise IndependentProviderTrustGraphError("finding:semantic-mismatch")
    parity = _validate_parity(item["parity_cases"], findings)
    discrepancies = _validate_discrepancies(item["discrepancies"], findings, parity, profile=view)
    all_expected_discrepancies = list(expected_discrepancies)
    for case in parity:
        if not case["passed"]:
            all_expected_discrepancies.append(_make_discrepancy("PARITY_MISMATCH", "EVIDENCE_AND_EXPECTATION_REVIEW", case["evidence_refs"], case["case_id"], profile=view))
    all_expected_discrepancies.sort(key=lambda entry: entry["discrepancy_id"])
    if discrepancies != all_expected_discrepancies:
        raise IndependentProviderTrustGraphError("discrepancy:semantic-mismatch")
    remediation = item["remediation"]
    prior_report_id: str | None = None
    prior_snapshot_id: str | None = None
    prior_snapshot_root: str | None = None
    if remediation is None:
        lifecycle = LIFECYCLE_OPEN
    else:
        if not allow_retest or history_depth <= 0:
            raise IndependentProviderTrustGraphError("prior-artifact:nested-retest-forbidden")
        remediation_item = _expect_keys(remediation, REMEDIATION_OUTPUT_KEYS, "remediation")
        action = _text(remediation_item["action_artifact_id"], "remediation:action")
        if _RE_ACTION.fullmatch(action) is None:
            raise IndependentProviderTrustGraphError("remediation:action")
        submitted = _int(remediation_item["submitted_at"], "remediation:submitted-at")
        result = _text(remediation_item["retest_result"], "remediation:result")
        if result not in ("PASSED", "FAILED"):
            raise IndependentProviderTrustGraphError("remediation:result")
        prior_ids = _sorted_unique(remediation_item["prior_finding_ids"], "remediation:prior-findings", maximum=MAX_FINDINGS)
        if not prior_ids:
            raise IndependentProviderTrustGraphError("remediation:prior-findings-empty")
        prior_artifact = _validate_prior_artifact(remediation_item["prior_artifact"], profile=view)
        prior_report = _expect_keys(prior_artifact["report"], REPORT_KEYS, "prior-artifact:report")
        prior_snapshot = _expect_keys(prior_artifact["observation_snapshot"], {"snapshot_id", "snapshot_root", "observation_time"}, "prior-artifact:snapshot")
        prior_report_id = _hex(prior_report["report_id"], "prior-artifact:report-id")
        prior_snapshot_id = _text(prior_snapshot["snapshot_id"], "prior-artifact:snapshot-id")
        prior_snapshot_root = _hex(prior_snapshot["snapshot_root"], "prior-artifact:snapshot-root")
        prior_known = {finding["finding_id"] for finding in prior_artifact["findings"]}
        if not set(prior_ids).issubset(prior_known) or submitted <= prior_snapshot["observation_time"] or submitted > observation_time:
            raise IndependentProviderTrustGraphError("remediation:prior-binding")
        if result == "PASSED" and findings[0]["kind"] != FINDING_CONTINUITY:
            raise IndependentProviderTrustGraphError("remediation:passed-result-mismatch")
        if result == "FAILED" and findings[0]["kind"] == FINDING_CONTINUITY:
            raise IndependentProviderTrustGraphError("remediation:failed-result-mismatch")
        lifecycle = LIFECYCLE_REMEDIATED if result == "PASSED" else LIFECYCLE_RETEST_FAILED
    report = _expect_keys(item["report"], REPORT_KEYS, "report")
    report_id = _hex(report["report_id"], "report:id")
    identity = _validate_identity(report["identity_material"], profile=view)
    if report["lifecycle"] != lifecycle or identity["lifecycle"] != lifecycle:
        raise IndependentProviderTrustGraphError("report:lifecycle")
    if identity["snapshot_id"] != snapshot_id or identity["snapshot_root"] != snapshot_root or identity["observation_time"] != observation_time:
        raise IndependentProviderTrustGraphError("report:snapshot-binding")
    expected_prior = prior_report_id
    expected_prior_snapshot = prior_snapshot_id
    expected_prior_root = prior_snapshot_root
    expected_identity = dict(identity)
    expected_identity.update(
        {
            "source_coverage_root": _digest("source-coverage-root", {"source_roots": [source["source_root"] for source in sources]}, profile=view),
            "findings_root": _findings_root(findings, profile=view),
            "discrepancies_root": _digest("discrepancies-root", {"discrepancies": discrepancies}, profile=view),
            "remediation_root": _digest("remediation-root", {"remediation": remediation}, profile=view) if remediation is not None else None,
            "parity_root": _digest("parity-root", {"parity_cases": parity}, profile=view),
            "prior_report_id": expected_prior,
            "prior_snapshot_id": expected_prior_snapshot,
            "prior_snapshot_root": expected_prior_root,
        }
    )
    if identity != expected_identity:
        raise IndependentProviderTrustGraphError("report:identity-material-mismatch")
    if report_id != _digest("report-id", identity, profile=view):
        raise IndependentProviderTrustGraphError("report:id-mismatch")
    transition = _expect_keys(item["transition"], TRANSITION_KEYS, "transition")
    expected_kind = "RETEST" if remediation is not None else "INITIAL"
    if not allow_retest and (
        lifecycle != LIFECYCLE_OPEN
        or any(value is not None for value in (expected_prior, expected_prior_snapshot, expected_prior_root))
    ):
        raise IndependentProviderTrustGraphError("prior-artifact:must-be-initial-open")
    if transition["transition_kind"] != expected_kind:
        raise IndependentProviderTrustGraphError("transition:kind")
    if (transition["prior_report_id"], transition["prior_snapshot_id"], transition["prior_snapshot_root"]) != (expected_prior, expected_prior_snapshot, expected_prior_root):
        raise IndependentProviderTrustGraphError("transition:prior-binding")
    if (transition["current_report_id"], transition["current_snapshot_id"], transition["current_snapshot_root"]) != (report_id, snapshot_id, snapshot_root):
        raise IndependentProviderTrustGraphError("transition:current-binding")
    transition_core = {key: transition[key] for key in TRANSITION_KEYS if key != "transition_id"}
    if transition["transition_id"] != _digest("transition-id", transition_core, profile=view):
        raise IndependentProviderTrustGraphError("transition:id-mismatch")
    authority = _expect_keys(item["authority"], AUTHORITY_KEYS, "authority")
    if authority != {
        "clearance_authority": False,
        "payment_authority": False,
        "economic_mutation": False,
        "production_usable": False,
        "synthetic_only": True,
    }:
        raise IndependentProviderTrustGraphError("authority:flags")
    return item


def verify_bytes(raw: bytes) -> dict[str, object]:
    artifact = _parse(raw)
    item = _verify_artifact(artifact, allow_retest=True, history_depth=MAX_HISTORY_DEPTH)
    report = _expect_keys(item["report"], REPORT_KEYS, "report")
    snapshot = _expect_keys(item["observation_snapshot"], {"snapshot_id", "snapshot_root", "observation_time"}, "snapshot")
    findings = item["findings"]
    return {
        "report_id": report["report_id"],
        "finding_kinds": [finding["kind"] for finding in findings],
        "lifecycle": report["lifecycle"],
        "transition_id": item["transition"]["transition_id"],
        "artifact_bytes": len(raw),
        "accepted": True,
    }


def verify_bytes_v2(raw: bytes, profile_registry: Mapping[str, object]) -> dict[str, object]:
    """Verify V2 only against an external state-configured profile registry."""

    if not isinstance(profile_registry, Mapping) or not profile_registry:
        raise IndependentProviderTrustGraphError("profile:registry-required")
    artifact = _parse(raw)
    profile_value = _expect_keys(artifact.get("profile"), PROFILE_KEYS, "artifact:profile")
    profile_id = _text(profile_value["profile_id"], "artifact:profile-id")
    configured = profile_registry.get(profile_id)
    if configured is None:
        raise IndependentProviderTrustGraphError("profile:registry-miss")
    view = _profile_view(configured)
    if not view.v2 or view.profile_id != profile_id:
        raise IndependentProviderTrustGraphError("profile:registry-mismatch")
    if profile_value != {"profile_id": view.profile_id, "version": view.version, "profile_digest": view.profile_digest}:
        raise IndependentProviderTrustGraphError("profile:artifact-not-authority")
    item = _verify_artifact(artifact, allow_retest=True, history_depth=MAX_HISTORY_DEPTH, profile=view)
    report = _expect_keys(item["report"], REPORT_KEYS, "report")
    return {
        "report_id": report["report_id"],
        "finding_kinds": [finding["kind"] for finding in item["findings"]],
        "lifecycle": report["lifecycle"],
        "transition_id": item["transition"]["transition_id"],
        "artifact_bytes": len(raw),
        "profile_id": view.profile_id,
        "profile_version": view.version,
        "profile_digest": view.profile_digest,
        "accepted": True,
    }


def verify_file(path: str | Path) -> dict[str, object]:
    file_path = Path(path)
    try:
        if file_path.stat().st_size > MAX_ARTIFACT_BYTES:
            raise IndependentProviderTrustGraphError("file:byte-cap")
        with file_path.open("rb") as handle:
            raw = handle.read(MAX_ARTIFACT_BYTES + 1)
    except OSError:
        raise
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise IndependentProviderTrustGraphError("file:byte-cap")
    return verify_bytes(raw)


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: python -m app.mirror.provider_trust_graph_independent ARTIFACT.json", file=sys.stderr)
        return 2
    try:
        print(json.dumps(verify_file(args[0]), sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, IndependentProviderTrustGraphError) as exc:
        print(f"REJECT {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
