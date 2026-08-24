"""Bounded synthetic Provider Trust Graph V1 producer.

This is the external, read-only Mirror product seam.  It is deliberately
independent from the native-v3 clearance conformance harness: no clearance
rows, directives, proof receipts, payment data, or economic state are
constructed here.  The wire artifact is strict canonical JSON so a separate
verifier can recompute every product identity and finding from the evidence
carried in the artifact.
"""

from __future__ import annotations

from copy import deepcopy
import ctypes
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import stat
import time
from typing import Any, Mapping, Sequence

from app.mirror.error_boundary import raise_redacted

try:
    import resource
except ImportError:  # pragma: no cover - Windows does not ship resource.
    resource = None  # type: ignore[assignment]


class ProviderTrustGraphError(ValueError):
    """Raised for any malformed, contradictory, stale, or rebound evidence."""


SCHEMA = "mirror-provider-trust-graph-v1"
INPUT_SCHEMA = "mirror-provider-trust-graph-input-v1"
SCHEMA_V2 = "mirror-provider-trust-graph-v2"
INPUT_SCHEMA_V2 = "mirror-provider-trust-graph-input-v2"
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
SOURCE_KINDS = (SOURCE_CREDENTIAL_KIND, SOURCE_ENROLLMENT_KIND)
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
RETEST_PASSED = "PASSED"
RETEST_FAILED = "FAILED"

MAX_INPUT_BYTES = 262_144
MAX_ARTIFACT_BYTES = 262_144
MAX_SOURCES = 2
MAX_RECORDS_PER_SOURCE = 8
MAX_FINDINGS = 8
MAX_DISCREPANCIES = 8
MAX_PARITY_CASES = 8
MAX_STRING_BYTES = 512
MAX_NODES = 4_096
MAX_DEPTH = 16
MAX_HISTORY_DEPTH = 1
MAX_TIMESTAMP = 2_147_483_647

INPUT_KEYS = {
    "schema",
    "provider_graph_subject",
    "scope",
    "observation_time",
    "sources",
    "prior_artifact",
    "remediation",
    "parity_cases",
}
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
PARITY_INPUT_KEYS = {"case_id", "expected_kind", "expected_present"}
REMEDIATION_INPUT_KEYS = {
    "action_artifact_id",
    "submitted_at",
    "retest_result",
    "prior_finding_ids",
}
SUBJECT_KEYS = {"provider_graph_subject", "scope"}
SNAPSHOT_KEYS = {"snapshot_id", "snapshot_root", "observation_time"}
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
V2_INPUT_KEYS = INPUT_KEYS | {"profile_id", "profile_version", "profile_digest"}
V2_OUTPUT_KEYS = OUTPUT_KEYS | {"profile"}
V2_IDENTITY_KEYS = IDENTITY_KEYS | PROFILE_KEYS

_RE_HEX = re.compile(r"^[0-9a-f]{128}$")
_RE_RECORD = re.compile(r"^SYNTH_(CREDENTIAL|ENROLLMENT)_RECORD_00[1-8]$")
_RE_ACTION = re.compile(r"^SYNTH_ACTION_00[1-8]$")


@dataclass(frozen=True)
class _GraphProfile:
    """Internal profile projection shared by the producer's V1/V2 grammar."""

    v2: bool
    schema: str
    input_schema: str
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
    require_complete: bool
    allow_nonmembership: bool

    def role_index(self, source_id: str) -> int:
        try:
            return self.source_roles.index(source_id)
        except ValueError as exc:
            raise_redacted(ProviderTrustGraphError, "profile:source-role")


def _profile_view(profile: object | None) -> _GraphProfile:
    if isinstance(profile, _GraphProfile):
        return profile
    if profile is None:
        return _GraphProfile(
            False,
            SCHEMA,
            INPUT_SCHEMA,
            None,
            None,
            None,
            PROVIDER_GRAPH_SUBJECT,
            SCOPE,
            CREDENTIAL_ID,
            ENROLLMENT_ID,
            SUBJECT_KEY,
            SOURCE_IDS,
            SOURCE_KINDS,
            ("CREDENTIAL", "ENROLLMENT"),
            (AUTH_CREDENTIAL_ID, AUTH_ENROLLMENT_ID),
            (PROVENANCE_CREDENTIAL_ID, PROVENANCE_ENROLLMENT_ID),
            None,
            None,
            6_000,
            9_000,
            True,
            True,
        )
    try:
        profile_id = getattr(profile, "profile_id")
        version = getattr(profile, "version")
        subject = getattr(profile, "subject")
        scope = getattr(profile, "scope")
        credential_id = getattr(profile, "credential_id")
        enrollment_id = getattr(profile, "enrollment_id")
        details = getattr(profile, "source_role_details")
        observation_start = getattr(profile, "observation_start")
        observation_end = getattr(profile, "observation_end")
        effective_start = getattr(profile, "effective_start")
        effective_end = getattr(profile, "effective_end")
        require_complete = getattr(profile, "require_complete")
        allow_nonmembership = getattr(profile, "allow_nonmembership")
        canonical_order = getattr(profile, "canonical_order")
        root_rule = getattr(profile, "root_rule")
        profile_digest = getattr(profile, "profile_digest")
    except Exception:
        raise_redacted(ProviderTrustGraphError, "profile:configuration")
    if (
        type(profile_id) is not str
        or type(version) is not int
        or version not in (2, 3)
        or type(subject) is not str
        or type(scope) is not str
        or type(credential_id) is not str
        or type(enrollment_id) is not str
        or not isinstance(details, tuple)
        or len(details) != 2
        or type(observation_start) is not int
        or type(observation_end) is not int
        or type(profile_digest) is not str
        or type(require_complete) is not bool
        or type(allow_nonmembership) is not bool
        or canonical_order != "lexicographic-v1"
        or root_rule != "source-root-v1"
    ):
        raise ProviderTrustGraphError("profile:configuration")
    roles = []
    for detail in details:
        try:
            roles.append(
                (
                    getattr(detail, "source_id"),
                    getattr(detail, "source_kind"),
                    getattr(detail, "record_kind"),
                    getattr(detail, "authority_id"),
                    getattr(detail, "provenance_id"),
                )
            )
        except Exception as exc:
            raise_redacted(ProviderTrustGraphError, "profile:source-role")
    role_ids = tuple(role[0] for role in roles)
    if (
        role_ids != tuple(sorted(role_ids))
        or len(set(role_ids)) != len(role_ids)
        or len(set(role[1] for role in roles)) != len(roles)
        or {role[2] for role in roles} != {"CREDENTIAL", "ENROLLMENT"}
    ):
        raise ProviderTrustGraphError("profile:source-role-order")
    return _GraphProfile(
        True,
        SCHEMA_V2,
        INPUT_SCHEMA_V2,
        profile_id,
        version,
        profile_digest,
        subject,
        scope,
        credential_id,
        enrollment_id,
        subject + "|" + credential_id + "|" + enrollment_id,
        tuple(role[0] for role in roles),
        tuple(role[1] for role in roles),
        tuple(role[2] for role in roles),
        tuple(role[3] for role in roles),
        tuple(role[4] for role in roles),
        observation_start,
        observation_end,
        int(effective_start),
        int(effective_end),
        require_complete,
        allow_nonmembership,
    )


def _canonical(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError):
        raise_redacted(ProviderTrustGraphError, "json:noncanonical-value")
    try:
        return rendered.encode("utf-8")
    except UnicodeEncodeError:
        raise_redacted(ProviderTrustGraphError, "json:noncanonical-value")


def _duplicate_reject(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ProviderTrustGraphError("json:duplicate-key")
        result[key] = value
    return result


def _walk(value: object, depth: int = 0, count: list[int] | None = None) -> None:
    if count is None:
        count = [0]
    count[0] += 1
    if count[0] > MAX_NODES:
        raise ProviderTrustGraphError("json:node-cap")
    if depth > MAX_DEPTH:
        raise ProviderTrustGraphError("json:depth-cap")
    if isinstance(value, float):
        raise ProviderTrustGraphError("json:float-forbidden")
    if isinstance(value, str):
        try:
            raw = value.encode("ascii")
        except UnicodeEncodeError:
            raise_redacted(ProviderTrustGraphError, "json:non-ascii")
        if len(raw) > MAX_STRING_BYTES:
            raise ProviderTrustGraphError("json:string-cap")
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ProviderTrustGraphError("json:key-type")
            _walk(key, depth + 1, count)
            _walk(item, depth + 1, count)
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth + 1, count)


def parse_canonical(raw: bytes, *, artifact: bool = False) -> dict[str, object]:
    cap = MAX_ARTIFACT_BYTES if artifact else MAX_INPUT_BYTES
    if not isinstance(raw, bytes) or not raw:
        raise ProviderTrustGraphError("json:empty-or-type")
    if len(raw) > cap:
        raise ProviderTrustGraphError("json:byte-cap")
    try:
        text = raw.decode("utf-8", errors="strict")
        if text.startswith("\ufeff"):
            raise ProviderTrustGraphError("json:bom")
        value = json.loads(
            text,
            object_pairs_hook=_duplicate_reject,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ProviderTrustGraphError("json:constant-forbidden")
            ),
        )
    except ProviderTrustGraphError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise_redacted(ProviderTrustGraphError, "json:parse")
    if not isinstance(value, dict):
        raise ProviderTrustGraphError("json:top-level")
    _walk(value)
    if _canonical(value) != raw:
        raise ProviderTrustGraphError("json:not-canonical")
    return value


def canonical_input(value: Mapping[str, object]) -> bytes:
    """Encode a caller-built input object; validation occurs during build."""

    raw = _canonical(value)
    if len(raw) > MAX_INPUT_BYTES:
        raise ProviderTrustGraphError("json:byte-cap")
    return raw


def _digest(label: str, value: object, *, profile: _GraphProfile | None = None) -> str:
    h = hashlib.sha3_512()
    version = "v2" if profile is not None and profile.v2 else "v1"
    h.update(("BL/MIRROR/PROVIDER-TRUST-GRAPH/" + label + "/" + version + "\0").encode("ascii"))
    h.update(_canonical(value))
    return h.hexdigest()


def _expect_keys(value: object, expected: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ProviderTrustGraphError(f"{label}:schema")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ProviderTrustGraphError(f"{label}:text")
    try:
        raw = value.encode("ascii")
    except UnicodeEncodeError:
        raise_redacted(ProviderTrustGraphError, f"{label}:ascii")
    if len(raw) > MAX_STRING_BYTES:
        raise ProviderTrustGraphError(f"{label}:length")
    return value


def _int(value: object, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProviderTrustGraphError(f"{label}:integer")
    if not minimum <= value <= MAX_TIMESTAMP:
        raise ProviderTrustGraphError(f"{label}:range")
    return value


def _bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise ProviderTrustGraphError(f"{label}:boolean")
    return value


def _hex(value: object, label: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str) or _RE_HEX.fullmatch(value) is None:
        raise ProviderTrustGraphError(f"{label}:hex")
    return value


def _sorted_unique(values: object, label: str, *, maximum: int) -> list[str]:
    if not isinstance(values, list) or len(values) > maximum:
        raise ProviderTrustGraphError(f"{label}:list-cap")
    result = [_text(item, label) for item in values]
    if result != sorted(result) or len(set(result)) != len(result):
        raise ProviderTrustGraphError(f"{label}:order-or-duplicate")
    return result


def _record_expected_status(record: dict[str, object], observation_time: int) -> str:
    issued = record["issued_at"]
    valid_until = record["valid_until"]
    terminated = record["terminated_at"]
    assert isinstance(issued, int) and isinstance(valid_until, int) and isinstance(terminated, int)
    if record["record_kind"] == "CREDENTIAL":
        if terminated != 0:
            raise ProviderTrustGraphError("record:credential-termination")
        return STATUS_ACTIVE if observation_time < valid_until else STATUS_EXPIRED
    if terminated:
        if not issued <= terminated <= observation_time:
            raise ProviderTrustGraphError("record:termination-time")
        return STATUS_TERMINATED
    return STATUS_ACTIVE if observation_time < valid_until else STATUS_EXPIRED


def _validate_record(
    record: object,
    source_kind: str,
    observation_time: int,
    *,
    profile: _GraphProfile | None = None,
) -> dict[str, object]:
    view = _profile_view(profile)
    item = _expect_keys(record, RECORD_KEYS, "record")
    record_id = _text(item["record_id"], "record:id")
    if view.version == 3:
        if _RE_HEX.fullmatch(record_id) is None:
            raise ProviderTrustGraphError("record:id:opaque")
    elif _RE_RECORD.fullmatch(record_id) is None:
        raise ProviderTrustGraphError("record:id:not-synthetic")
    try:
        role_index = view.source_kinds.index(source_kind)
    except ValueError:
        raise_redacted(ProviderTrustGraphError, "record:source-mismatch")
    expected_kind = view.record_kinds[role_index]
    expected_prefix = "SYNTH_" + expected_kind
    if view.version != 3 and not record_id.startswith(expected_prefix):
        raise ProviderTrustGraphError("record:id:source-mismatch")
    if item["record_kind"] not in ("CREDENTIAL", "ENROLLMENT"):
        raise ProviderTrustGraphError("record:kind")
    if item["record_kind"] != expected_kind:
        raise ProviderTrustGraphError("record:kind:source-mismatch")
    for field, expected in (
        ("provider_id", view.subject),
        ("credential_id", view.credential_id),
        ("enrollment_id", view.enrollment_id),
        ("subject_key", view.subject_key),
    ):
        if _text(item[field], "record:" + field) != expected:
            raise ProviderTrustGraphError("record:identity-mismatch")
    observed = _int(item["observed_at"], "record:observed_at")
    if observed != observation_time:
        raise ProviderTrustGraphError("record:observation-mismatch")
    issued = _int(item["issued_at"], "record:issued_at")
    valid_from = _int(item["valid_from"], "record:valid_from")
    valid_until = _int(item["valid_until"], "record:valid_until")
    terminated = _int(item["terminated_at"], "record:terminated_at")
    if issued != valid_from or valid_until <= issued:
        raise ProviderTrustGraphError("record:interval-contradiction")
    status = _text(item["status"], "record:status")
    if status not in STATUSES:
        raise ProviderTrustGraphError("record:status:enum")
    expected_status = _record_expected_status(item, observation_time)
    if status != expected_status:
        raise ProviderTrustGraphError("record:status-time-mismatch")
    if item["record_kind"] == "CREDENTIAL" and status == STATUS_TERMINATED:
        raise ProviderTrustGraphError("record:credential-status")
    if item["record_kind"] == "ENROLLMENT" and status == STATUS_EXPIRED:
        raise ProviderTrustGraphError("record:enrollment-status")
    return item


def _source_integrity_material(source: Mapping[str, object]) -> dict[str, object]:
    material = dict(source)
    provenance = dict(material["provenance"])  # type: ignore[arg-type]
    provenance.pop("integrity_digest", None)
    material["provenance"] = provenance
    material.pop("source_root", None)
    return material


def source_integrity_digest(source: Mapping[str, object], profile: object | None = None) -> str:
    """Return the exact V1 provenance digest for a source without rebinding it."""

    view = profile if isinstance(profile, _GraphProfile) else _profile_view(profile)
    return _digest("source-integrity", _source_integrity_material(source), profile=view)


def _source_root(source: Mapping[str, object], *, profile: _GraphProfile | None = None) -> str:
    return _digest("source-root", {"source": dict(source)}, profile=profile)


def _validate_source(
    source: object,
    observation_time: int,
    *,
    output: bool,
    profile: _GraphProfile | None = None,
) -> dict[str, object]:
    view = _profile_view(profile)
    item = _expect_keys(source, SOURCE_OUTPUT_KEYS if output else SOURCE_INPUT_KEYS, "source")
    source_id = _text(item["source_id"], "source:id")
    source_kind = _text(item["source_kind"], "source:kind")
    if source_id not in view.source_roles or source_kind not in view.source_kinds:
        raise ProviderTrustGraphError("source:identity")
    role_index = view.role_index(source_id)
    provenance = _expect_keys(item["provenance"], PROVENANCE_KEYS, "source:provenance")
    expected = (view.source_kinds[role_index], view.authority_ids[role_index], view.provenance_ids[role_index])
    if (source_kind, item["coverage_authority_id"], provenance["provenance_id"]) != expected:
        raise ProviderTrustGraphError("source:authority-or-provenance")
    if source_kind != view.source_kinds[role_index]:
        raise ProviderTrustGraphError("source:kind-id-mismatch")
    if _text(item["coverage_scope"], "source:scope") != view.scope:
        raise ProviderTrustGraphError("source:scope")
    coverage_observation = _int(item["coverage_observation_time"], "source:coverage-observation")
    if coverage_observation != observation_time:
        raise ProviderTrustGraphError("source:coverage-observation-mismatch")
    start = _int(item["coverage_effective_start"], "source:coverage-start")
    end = _int(item["coverage_effective_end"], "source:coverage-end")
    if start >= end:
        raise ProviderTrustGraphError("source:coverage-interval")
    coverage_complete = _bool(item["coverage_complete"], "source:complete")
    if view.v2 and view.require_complete and coverage_complete is not True:
        raise ProviderTrustGraphError("source:completeness-policy")
    _text(item["coverage_authority_id"], "source:authority")
    nonmembership = _sorted_unique(item["nonmembership_keys"], "source:nonmembership", maximum=2)
    if nonmembership and not view.allow_nonmembership:
        raise ProviderTrustGraphError("source:nonmembership-policy")
    if any(key != view.subject_key for key in nonmembership):
        raise ProviderTrustGraphError("source:nonmembership-identity")
    records = item["records"]
    if not isinstance(records, list) or len(records) > MAX_RECORDS_PER_SOURCE:
        raise ProviderTrustGraphError("source:record-cap")
    record_items = [_validate_record(record, source_kind, observation_time, profile=view) for record in records]
    if [record["record_id"] for record in record_items] != sorted(record["record_id"] for record in record_items):
        raise ProviderTrustGraphError("source:record-order")
    if len({record["record_id"] for record in record_items}) != len(record_items):
        raise ProviderTrustGraphError("source:record-duplicate")
    _text(provenance["provenance_id"], "source:provenance-id")
    _hex(provenance["integrity_digest"], "source:integrity")
    if output:
        _hex(item["source_root"], "source:root")
    return item


def _validate_fact_nonmembership(sources: Sequence[Mapping[str, object]]) -> None:
    for source in sources:
        facts = {
            record["subject_key"]
            for record in source["records"]  # type: ignore[union-attr]
        }
        nonmembership = set(source["nonmembership_keys"])  # type: ignore[arg-type]
        if facts & nonmembership:
            raise ProviderTrustGraphError("completeness:fact-nonmembership-conflict")


def _validate_sources(
    sources: object,
    observation_time: int,
    *,
    output: bool,
    profile: _GraphProfile | None = None,
) -> list[dict[str, object]]:
    view = _profile_view(profile)
    if not isinstance(sources, list) or len(sources) != len(view.source_roles):
        raise ProviderTrustGraphError("sources:exact-count")
    items = [_validate_source(source, observation_time, output=output, profile=view) for source in sources]
    ids = [item["source_id"] for item in items]
    if ids != list(view.source_roles) or ids != sorted(ids):
        raise ProviderTrustGraphError("sources:identity-or-order")
    _validate_fact_nonmembership(items)
    for source in items:
        expected_digest = source_integrity_digest(source, view)
        actual_digest = source["provenance"]["integrity_digest"]  # type: ignore[index]
        if expected_digest != actual_digest:
            raise ProviderTrustGraphError("source:integrity-mismatch")
        if output and _source_root({key: value for key, value in source.items() if key != "source_root"}, profile=view) != source["source_root"]:
            raise ProviderTrustGraphError("source:root-mismatch")
    return items


def _validate_finding(
    finding: object,
    *,
    snapshot_id: str | None = None,
    profile: _GraphProfile | None = None,
) -> dict[str, object]:
    view = _profile_view(profile)
    item = _expect_keys(finding, FINDING_KEYS, "finding")
    finding_id = _hex(item["finding_id"], "finding:id")
    kind = _text(item["kind"], "finding:kind")
    if kind not in FINDING_KINDS:
        raise ProviderTrustGraphError("finding:kind")
    lifecycle = _text(item["lifecycle"], "finding:lifecycle")
    if lifecycle not in LIFECYCLES:
        raise ProviderTrustGraphError("finding:lifecycle")
    if _text(item["subject_key"], "finding:subject") != view.subject_key:
        raise ProviderTrustGraphError("finding:subject")
    current_snapshot = _text(item["observation_snapshot_id"], "finding:snapshot")
    if snapshot_id is not None and current_snapshot != snapshot_id:
        raise ProviderTrustGraphError("finding:snapshot-mismatch")
    refs = _sorted_unique(item["evidence_refs"], "finding:evidence", maximum=MAX_RECORDS_PER_SOURCE * MAX_SOURCES)
    expected_id = _digest(
        "finding-id",
        {
            "kind": kind,
            "subject_key": view.subject_key,
            "observation_snapshot_id": current_snapshot,
            "evidence_refs": refs,
        },
        profile=view,
    )
    if finding_id != expected_id:
        raise ProviderTrustGraphError("finding:id-mismatch")
    return item


def _findings_root(findings: Sequence[Mapping[str, object]], *, profile: _GraphProfile | None = None) -> str:
    return _digest("findings-root", {"findings": list(findings)}, profile=profile)


def _validate_identity_material(
    identity: object,
    *,
    profile: _GraphProfile | None = None,
) -> dict[str, object]:
    view = _profile_view(profile)
    item = _expect_keys(identity, V2_IDENTITY_KEYS if view.v2 else IDENTITY_KEYS, "report:identity-material")
    if _text(item["provider_graph_subject"], "identity:subject") != view.subject:
        raise ProviderTrustGraphError("identity:subject")
    if _text(item["scope"], "identity:scope") != view.scope:
        raise ProviderTrustGraphError("identity:scope")
    if view.v2:
        if (
            item["profile_id"] != view.profile_id
            or item["version"] != view.version
            or item["profile_digest"] != view.profile_digest
        ):
            raise ProviderTrustGraphError("identity:profile")
    observation_time = _int(item["observation_time"], "identity:observation-time")
    _text(item["snapshot_id"], "identity:snapshot")
    _hex(item["snapshot_root"], "identity:snapshot-root")
    for field in (
        "source_coverage_root",
        "findings_root",
        "discrepancies_root",
        "parity_root",
    ):
        _hex(item[field], "identity:" + field)
    _hex(item["remediation_root"], "identity:remediation-root", nullable=True)
    lifecycle = _text(item["lifecycle"], "identity:lifecycle")
    if lifecycle not in LIFECYCLES:
        raise ProviderTrustGraphError("identity:lifecycle")
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
        raise ProviderTrustGraphError("identity:prior-link")
    if observation_time <= 0:
        raise ProviderTrustGraphError("identity:observation-time")
    return item


def _validate_prior_artifact(
    prior: object,
    *,
    profile: _GraphProfile | None = None,
) -> dict[str, object]:
    """Validate a complete, non-retest artifact before it can be retest input."""

    item = _validate_output(prior, allow_retest=False, history_depth=0, profile=profile)
    report = _expect_keys(item["report"], REPORT_KEYS, "prior-artifact:report")
    identity = _validate_identity_material(report["identity_material"], profile=profile)
    if report["lifecycle"] != LIFECYCLE_OPEN or item["remediation"] is not None:
        raise ProviderTrustGraphError("prior-artifact:must-be-initial-open")
    if identity["lifecycle"] != LIFECYCLE_OPEN or any(
        value is not None
        for value in (
            identity["prior_report_id"],
            identity["prior_snapshot_id"],
            identity["prior_snapshot_root"],
        )
    ):
        raise ProviderTrustGraphError("prior-artifact:must-be-initial-open")
    transition = _expect_keys(item["transition"], TRANSITION_KEYS, "prior-artifact:transition")
    if transition["transition_kind"] != "INITIAL" or any(
        transition[field] is not None
        for field in ("prior_report_id", "prior_snapshot_id", "prior_snapshot_root")
    ):
        raise ProviderTrustGraphError("prior-artifact:must-be-initial-open")
    return item


def _validate_input_parity(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) > MAX_PARITY_CASES:
        raise ProviderTrustGraphError("parity:count-cap")
    result: list[dict[str, object]] = []
    for case in value:
        item = _expect_keys(case, PARITY_INPUT_KEYS, "parity-case")
        _text(item["case_id"], "parity:id")
        kind = _text(item["expected_kind"], "parity:expected-kind")
        if kind not in FINDING_KINDS:
            raise ProviderTrustGraphError("parity:expected-kind")
        _bool(item["expected_present"], "parity:expected-present")
        result.append(item)
    ids = [item["case_id"] for item in result]
    if ids != sorted(ids) or len(set(ids)) != len(ids):
        raise ProviderTrustGraphError("parity:order-or-duplicate")
    return result


def _validate_input_remediation(value: object) -> dict[str, object] | None:
    if value is None:
        return None
    item = _expect_keys(value, REMEDIATION_INPUT_KEYS, "remediation")
    action = _text(item["action_artifact_id"], "remediation:action")
    if _RE_ACTION.fullmatch(action) is None:
        raise ProviderTrustGraphError("remediation:action")
    _int(item["submitted_at"], "remediation:submitted-at")
    result = _text(item["retest_result"], "remediation:result")
    if result not in (RETEST_PASSED, RETEST_FAILED):
        raise ProviderTrustGraphError("remediation:result")
    ids = _sorted_unique(item["prior_finding_ids"], "remediation:prior-findings", maximum=MAX_FINDINGS)
    if not ids:
        raise ProviderTrustGraphError("remediation:prior-findings-empty")
    return item


def _validate_input(value: object, *, profile: _GraphProfile | None = None) -> dict[str, object]:
    view = _profile_view(profile)
    item = _expect_keys(value, V2_INPUT_KEYS if view.v2 else INPUT_KEYS, "input")
    if _text(item["schema"], "input:schema") != view.input_schema:
        raise ProviderTrustGraphError("input:schema")
    if _text(item["provider_graph_subject"], "input:subject") != view.subject:
        raise ProviderTrustGraphError("input:subject")
    if _text(item["scope"], "input:scope") != view.scope:
        raise ProviderTrustGraphError("input:scope")
    if view.v2 and (
        item["profile_id"] != view.profile_id
        or item["profile_version"] != view.version
        or item["profile_digest"] != view.profile_digest
    ):
        raise ProviderTrustGraphError("input:profile")
    observation_time = _int(item["observation_time"], "input:observation-time", minimum=1)
    if view.v2 and not view.observation_start <= observation_time < view.observation_end:  # type: ignore[operator]
        raise ProviderTrustGraphError("input:observation-window")
    _validate_sources(item["sources"], observation_time, output=False, profile=view)
    if item["prior_artifact"] is not None:
        _validate_prior_artifact(item["prior_artifact"], profile=view)
    _validate_input_remediation(item["remediation"])
    _validate_input_parity(item["parity_cases"])
    if item["remediation"] is None and item["prior_artifact"] is not None:
        raise ProviderTrustGraphError("input:prior-artifact-without-remediation")
    if item["remediation"] is not None and item["prior_artifact"] is None:
        raise ProviderTrustGraphError("input:remediation-without-prior-artifact")
    if item["prior_artifact"] is not None:
        prior = item["prior_artifact"]
        remediation = item["remediation"]
        assert isinstance(prior, dict) and isinstance(remediation, dict)
        prior_snapshot = _expect_keys(prior["observation_snapshot"], SNAPSHOT_KEYS, "prior-artifact:snapshot")
        prior_observation_time = prior_snapshot["observation_time"]
        prior_findings = prior["findings"]
        if remediation["submitted_at"] <= prior_observation_time or remediation["submitted_at"] > observation_time:
            raise ProviderTrustGraphError("remediation:chronology")
        prior_ids = {finding["finding_id"] for finding in prior_findings}
        if not set(remediation["prior_finding_ids"]).issubset(prior_ids):
            raise ProviderTrustGraphError("remediation:unknown-prior-finding")
    return item


def _finding(
    kind: str,
    snapshot_id: str,
    refs: Sequence[str],
    *,
    lifecycle: str = LIFECYCLE_OPEN,
    profile: _GraphProfile | None = None,
) -> dict[str, object]:
    view = _profile_view(profile)
    ordered_refs = sorted(refs)
    body: dict[str, object] = {
        "kind": kind,
        "lifecycle": lifecycle,
        "subject_key": view.subject_key,
        "observation_snapshot_id": snapshot_id,
        "evidence_refs": ordered_refs,
    }
    return {"finding_id": _digest("finding-id", {key: body[key] for key in ("kind", "subject_key", "observation_snapshot_id", "evidence_refs")}, profile=view), **body}


def _discrepancy(
    kind: str,
    responsibility: str,
    refs: Sequence[str],
    parity_case_id: str | None,
    *,
    profile: _GraphProfile | None = None,
) -> dict[str, object]:
    body: dict[str, object] = {
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
    stale_sources = [
        source["source_id"]
        for source in sources
        if not source["coverage_effective_start"] <= observation_time < source["coverage_effective_end"]  # type: ignore[operator]
    ]
    if stale_sources:
        return [_finding(FINDING_STALE, snapshot_id, stale_sources, profile=view)], []
    incomplete_sources = [source["source_id"] for source in sources if not source["coverage_complete"]]
    if incomplete_sources:
        return [_finding(FINDING_INCOMPLETE, snapshot_id, incomplete_sources, profile=view)], []
    matches = [record for source in sources for record in source["records"]]  # type: ignore[union-attr]
    missing_sources = [source for source in sources if not source["records"]]
    if missing_sources:
        if view.allow_nonmembership and not matches and all(source["nonmembership_keys"] == [view.subject_key] for source in sources):  # type: ignore[comparison-overlap]
            return [_finding(FINDING_ABSENT, snapshot_id, list(view.source_roles), profile=view)], []
        raise ProviderTrustGraphError("evidence:partial-absence")
    if any(len(source["records"]) > 1 for source in sources):  # type: ignore[arg-type]
        refs = [record["record_id"] for record in matches]
        return [
            _finding(FINDING_CONFLICT, snapshot_id, refs, profile=view)
        ], [
            _discrepancy("SOURCE_CONFLICT_EVIDENCE", "SOURCE_RECONCILIATION_REQUIRED", refs, None, profile=view)
        ]
    credential = next(record for record in matches if record["record_kind"] == "CREDENTIAL")
    enrollment = next(record for record in matches if record["record_kind"] == "ENROLLMENT")
    refs = [credential["record_id"], enrollment["record_id"]]
    if credential["status"] == STATUS_EXPIRED:
        return [_finding(FINDING_EXPIRED, snapshot_id, refs, profile=view)], []
    if enrollment["status"] == STATUS_TERMINATED:
        return [_finding(FINDING_TERMINATED, snapshot_id, refs, profile=view)], []
    return [_finding(FINDING_CONTINUITY, snapshot_id, refs, profile=view)], []


def _validate_output_parity(value: object, findings: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) > MAX_PARITY_CASES:
        raise ProviderTrustGraphError("parity:count-cap")
    observed = {finding["kind"] for finding in findings}
    result: list[dict[str, object]] = []
    for raw_case in value:
        item = _expect_keys(raw_case, PARITY_OUTPUT_KEYS, "parity-output")
        case_id = _text(item["case_id"], "parity:id")
        expected_kind = _text(item["expected_kind"], "parity:expected-kind")
        if expected_kind not in FINDING_KINDS:
            raise ProviderTrustGraphError("parity:expected-kind")
        expected_present = _bool(item["expected_present"], "parity:expected-present")
        observed_kinds = _sorted_unique(item["observed_kinds"], "parity:observed", maximum=MAX_FINDINGS)
        if observed_kinds != sorted(observed) or any(kind not in FINDING_KINDS for kind in observed_kinds):
            raise ProviderTrustGraphError("parity:observed-mismatch")
        passed = _bool(item["passed"], "parity:passed")
        expected_passed = (expected_kind in observed) == expected_present
        if passed != expected_passed:
            raise ProviderTrustGraphError("parity:result-mismatch")
        refs = _sorted_unique(item["evidence_refs"], "parity:evidence", maximum=MAX_FINDINGS)
        expected_refs = sorted(finding["finding_id"] for finding in findings if finding["kind"] == expected_kind)
        if refs != expected_refs:
            raise ProviderTrustGraphError("parity:evidence-mismatch")
        discrepancy_id = _hex(item["discrepancy_id"], "parity:discrepancy", nullable=True)
        if passed and discrepancy_id is not None:
            raise ProviderTrustGraphError("parity:unexpected-discrepancy")
        if not passed and discrepancy_id is None:
            raise ProviderTrustGraphError("parity:missing-discrepancy")
        result.append(item)
    ids = [item["case_id"] for item in result]
    if ids != sorted(ids) or len(set(ids)) != len(ids):
        raise ProviderTrustGraphError("parity:order-or-duplicate")
    return result


def _validate_discrepancies(
    value: object,
    findings: Sequence[Mapping[str, object]],
    parity: Sequence[Mapping[str, object]],
    *,
    profile: _GraphProfile | None = None,
) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) > MAX_DISCREPANCIES:
        raise ProviderTrustGraphError("discrepancy:count-cap")
    finding_ids = {finding["finding_id"] for finding in findings}
    parity_ids = {case["case_id"] for case in parity}
    result: list[dict[str, object]] = []
    for raw in value:
        item = _expect_keys(raw, DISCREPANCY_KEYS, "discrepancy")
        discrepancy_id = _hex(item["discrepancy_id"], "discrepancy:id")
        kind = _text(item["kind"], "discrepancy:kind")
        if kind not in ("SOURCE_CONFLICT_EVIDENCE", "PARITY_MISMATCH"):
            raise ProviderTrustGraphError("discrepancy:kind")
        responsibility = _text(item["responsibility_boundary"], "discrepancy:responsibility")
        if responsibility not in ("SOURCE_RECONCILIATION_REQUIRED", "EVIDENCE_AND_EXPECTATION_REVIEW"):
            raise ProviderTrustGraphError("discrepancy:responsibility")
        refs = _sorted_unique(item["evidence_refs"], "discrepancy:evidence", maximum=MAX_RECORDS_PER_SOURCE * MAX_SOURCES)
        parity_case_id = item["parity_case_id"]
        if parity_case_id is not None and parity_case_id not in parity_ids:
            raise ProviderTrustGraphError("discrepancy:parity-reference")
        if kind == "PARITY_MISMATCH" and parity_case_id is None:
            raise ProviderTrustGraphError("discrepancy:parity-reference")
        if kind == "SOURCE_CONFLICT_EVIDENCE" and parity_case_id is not None:
            raise ProviderTrustGraphError("discrepancy:source-reference")
        expected = _digest("discrepancy-id", {key: item[key] for key in DISCREPANCY_KEYS if key != "discrepancy_id"}, profile=profile)
        if discrepancy_id != expected:
            raise ProviderTrustGraphError("discrepancy:id-mismatch")
        if any(ref in finding_ids for ref in refs) and kind == "SOURCE_CONFLICT_EVIDENCE":
            raise ProviderTrustGraphError("discrepancy:evidence-kind")
        result.append(item)
    ids = [item["discrepancy_id"] for item in result]
    if ids != sorted(ids) or len(set(ids)) != len(ids):
        raise ProviderTrustGraphError("discrepancy:order-or-duplicate")
    return result


def _validate_output(
    value: object,
    *,
    allow_retest: bool = True,
    history_depth: int = MAX_HISTORY_DEPTH,
    profile: _GraphProfile | None = None,
) -> dict[str, object]:
    view = _profile_view(profile)
    item = _expect_keys(value, V2_OUTPUT_KEYS if view.v2 else OUTPUT_KEYS, "artifact")
    if _text(item["schema"], "artifact:schema") != view.schema:
        raise ProviderTrustGraphError("artifact:schema")
    if view.v2:
        profile_value = _expect_keys(item["profile"], PROFILE_KEYS, "artifact:profile")
        if profile_value != {"profile_id": view.profile_id, "version": view.version, "profile_digest": view.profile_digest}:
            raise ProviderTrustGraphError("artifact:profile")
    subject = _expect_keys(item["subject"], SUBJECT_KEYS, "artifact:subject")
    if _text(subject["provider_graph_subject"], "artifact:subject") != view.subject or _text(subject["scope"], "artifact:scope") != view.scope:
        raise ProviderTrustGraphError("artifact:subject")
    snapshot = _expect_keys(item["observation_snapshot"], SNAPSHOT_KEYS, "artifact:snapshot")
    snapshot_id = _text(snapshot["snapshot_id"], "snapshot:id")
    snapshot_root = _hex(snapshot["snapshot_root"], "snapshot:root")
    observation_time = _int(snapshot["observation_time"], "snapshot:time", minimum=1)
    if view.v2 and not view.observation_start <= observation_time < view.observation_end:  # type: ignore[operator]
        raise ProviderTrustGraphError("snapshot:observation-window")
    _validate_sources(item["source_coverage"], observation_time, output=True, profile=view)
    source_items = item["source_coverage"]
    assert isinstance(source_items, list)
    expected_snapshot_root = _digest(
        "snapshot-root",
        {
            "provider_graph_subject": view.subject,
            "scope": view.scope,
            "observation_time": observation_time,
            "source_roots": [source["source_root"] for source in source_items],
        },
        profile=view,
    )
    if snapshot_root != expected_snapshot_root:
        raise ProviderTrustGraphError("snapshot:root-mismatch")
    expected_snapshot_id = _digest("snapshot-id", {"snapshot_root": snapshot_root, "observation_time": observation_time}, profile=view)
    if snapshot_id != expected_snapshot_id:
        raise ProviderTrustGraphError("snapshot:id-mismatch")
    findings_value = item["findings"]
    if not isinstance(findings_value, list) or len(findings_value) > MAX_FINDINGS:
        raise ProviderTrustGraphError("finding:count-cap")
    findings = [_validate_finding(value, snapshot_id=snapshot_id, profile=view) for value in findings_value]
    finding_ids = [finding["finding_id"] for finding in findings]
    if finding_ids != sorted(finding_ids) or len(set(finding_ids)) != len(finding_ids):
        raise ProviderTrustGraphError("finding:order-or-duplicate")
    _validate_fact_nonmembership(source_items)
    source_inputs = [{key: value for key, value in source.items() if key != "source_root"} for source in source_items]
    expected_sources = _validate_sources(source_inputs, observation_time, output=False, profile=view)
    expected_source_roots = [_source_root(source, profile=view) for source in expected_sources]
    if expected_source_roots != [source["source_root"] for source in source_items]:
        raise ProviderTrustGraphError("source:root-mismatch")
    expected_findings, expected_discrepancies = _evaluate(expected_sources, observation_time, snapshot_id, profile=view)
    if expected_findings != findings:
        raise ProviderTrustGraphError("finding:semantic-mismatch")
    parity = _validate_output_parity(item["parity_cases"], findings)
    discrepancies = _validate_discrepancies(item["discrepancies"], findings, parity, profile=view)
    expected_discrepancy_cores = expected_discrepancies[:]
    for case in parity:
        if not case["passed"]:
            refs = list(case["evidence_refs"])
            expected_discrepancy_cores.append(
                _discrepancy("PARITY_MISMATCH", "EVIDENCE_AND_EXPECTATION_REVIEW", refs, case["case_id"], profile=view)
            )
    expected_discrepancy_cores.sort(key=lambda entry: entry["discrepancy_id"])
    if expected_discrepancy_cores != discrepancies:
        raise ProviderTrustGraphError("discrepancy:semantic-mismatch")
    remediation = item["remediation"]
    prior_report_id: str | None = None
    prior_snapshot_id: str | None = None
    prior_snapshot_root: str | None = None
    if remediation is not None:
        if not allow_retest or history_depth <= 0:
            raise ProviderTrustGraphError("prior-artifact:nested-retest-forbidden")
        remediation_item = _expect_keys(remediation, REMEDIATION_OUTPUT_KEYS, "remediation-output")
        action = _text(remediation_item["action_artifact_id"], "remediation:action")
        if _RE_ACTION.fullmatch(action) is None:
            raise ProviderTrustGraphError("remediation:action")
        submitted = _int(remediation_item["submitted_at"], "remediation:submitted-at")
        result = _text(remediation_item["retest_result"], "remediation:result")
        if result not in (RETEST_PASSED, RETEST_FAILED):
            raise ProviderTrustGraphError("remediation:result")
        prior_ids = _sorted_unique(remediation_item["prior_finding_ids"], "remediation:prior-findings", maximum=MAX_FINDINGS)
        if not prior_ids:
            raise ProviderTrustGraphError("remediation:prior-findings-empty")
        prior = _validate_prior_artifact(remediation_item["prior_artifact"], profile=view)
        prior_report = _expect_keys(prior["report"], REPORT_KEYS, "prior-artifact:report")
        prior_snapshot = _expect_keys(prior["observation_snapshot"], SNAPSHOT_KEYS, "prior-artifact:snapshot")
        prior_report_id = _hex(prior_report["report_id"], "prior-artifact:report-id")
        prior_snapshot_id = _text(prior_snapshot["snapshot_id"], "prior-artifact:snapshot-id")
        prior_snapshot_root = _hex(prior_snapshot["snapshot_root"], "prior-artifact:snapshot-root")
        prior_findings = prior["findings"]
        if prior_ids != sorted(prior_ids) or not set(prior_ids).issubset({finding["finding_id"] for finding in prior_findings}):
            raise ProviderTrustGraphError("remediation:prior-findings")
        if submitted <= prior_snapshot["observation_time"] or submitted > observation_time:
            raise ProviderTrustGraphError("remediation:chronology")
        if result == RETEST_PASSED and findings[0]["kind"] != FINDING_CONTINUITY:
            raise ProviderTrustGraphError("remediation:passed-result-mismatch")
        if result == RETEST_FAILED and findings[0]["kind"] == FINDING_CONTINUITY:
            raise ProviderTrustGraphError("remediation:failed-result-mismatch")
        lifecycle = LIFECYCLE_REMEDIATED if result == RETEST_PASSED else LIFECYCLE_RETEST_FAILED
    else:
        lifecycle = LIFECYCLE_OPEN
    report = _expect_keys(item["report"], REPORT_KEYS, "report")
    identity = _validate_identity_material(report["identity_material"], profile=view)
    report_id = _hex(report["report_id"], "report:id")
    if report["lifecycle"] != lifecycle or identity["lifecycle"] != lifecycle:
        raise ProviderTrustGraphError("report:lifecycle")
    if identity["snapshot_id"] != snapshot_id or identity["snapshot_root"] != snapshot_root or identity["observation_time"] != observation_time:
        raise ProviderTrustGraphError("report:snapshot-binding")
    expected_identity = dict(identity)
    expected_identity["source_coverage_root"] = _digest("source-coverage-root", {"source_roots": [source["source_root"] for source in source_items]}, profile=view)
    expected_identity["findings_root"] = _findings_root(findings, profile=view)
    expected_identity["discrepancies_root"] = _digest("discrepancies-root", {"discrepancies": discrepancies}, profile=view)
    expected_identity["parity_root"] = _digest("parity-root", {"parity_cases": parity}, profile=view)
    expected_identity["remediation_root"] = _digest("remediation-root", {"remediation": remediation}, profile=view) if remediation is not None else None
    expected_identity["prior_report_id"] = prior_report_id
    expected_identity["prior_snapshot_id"] = prior_snapshot_id
    expected_identity["prior_snapshot_root"] = prior_snapshot_root
    if identity != expected_identity:
        raise ProviderTrustGraphError("report:identity-material-mismatch")
    if report_id != _digest("report-id", identity, profile=view):
        raise ProviderTrustGraphError("report:id-mismatch")
    transition = _expect_keys(item["transition"], TRANSITION_KEYS, "transition")
    transition_kind = _text(transition["transition_kind"], "transition:kind")
    expected_prior = prior_report_id
    expected_prior_snapshot = prior_snapshot_id
    expected_prior_root = prior_snapshot_root
    if not allow_retest and any(value is not None for value in (expected_prior, expected_prior_snapshot, expected_prior_root)):
        raise ProviderTrustGraphError("prior-artifact:must-be-initial-open")
    if transition_kind != ("RETEST" if remediation is not None else "INITIAL"):
        raise ProviderTrustGraphError("transition:kind")
    if (transition["prior_report_id"], transition["prior_snapshot_id"], transition["prior_snapshot_root"]) != (expected_prior, expected_prior_snapshot, expected_prior_root):
        raise ProviderTrustGraphError("transition:prior-binding")
    if (transition["current_report_id"], transition["current_snapshot_id"], transition["current_snapshot_root"]) != (report_id, snapshot_id, snapshot_root):
        raise ProviderTrustGraphError("transition:current-binding")
    transition_core = {key: transition[key] for key in TRANSITION_KEYS if key != "transition_id"}
    if transition["transition_id"] != _digest("transition-id", transition_core, profile=view):
        raise ProviderTrustGraphError("transition:id-mismatch")
    authority = _expect_keys(item["authority"], AUTHORITY_KEYS, "authority")
    if authority != {
        "clearance_authority": False,
        "payment_authority": False,
        "economic_mutation": False,
        "production_usable": False,
        "synthetic_only": True,
    }:
        raise ProviderTrustGraphError("authority:flags")
    return item


def _source_for_demo(source_id: str, source_kind: str, *, observation_time: int, records: list[dict[str, object]], complete: bool = True, nonmembership: list[str] | None = None, end: int = 9_000) -> dict[str, object]:
    is_credential = source_kind == SOURCE_CREDENTIAL_KIND
    source: dict[str, object] = {
        "source_id": source_id,
        "source_kind": source_kind,
        "coverage_scope": SCOPE,
        "coverage_observation_time": observation_time,
        "coverage_effective_start": 6_000,
        "coverage_effective_end": end,
        "coverage_complete": complete,
        "coverage_authority_id": AUTH_CREDENTIAL_ID if is_credential else AUTH_ENROLLMENT_ID,
        "nonmembership_keys": [] if nonmembership is None else nonmembership,
        "records": records,
        "provenance": {
            "provenance_id": PROVENANCE_CREDENTIAL_ID if is_credential else PROVENANCE_ENROLLMENT_ID,
            "integrity_digest": "0" * 128,
        },
    }
    source["provenance"]["integrity_digest"] = source_integrity_digest(source)  # type: ignore[index]
    return source


def _demo_record(kind: str, *, record_number: int = 1, observation_time: int = 7_000, valid_until: int = 9_000, status: str = STATUS_ACTIVE, terminated_at: int = 0) -> dict[str, object]:
    prefix = "CREDENTIAL" if kind == "CREDENTIAL" else "ENROLLMENT"
    return {
        "record_id": f"SYNTH_{prefix}_RECORD_{record_number:03d}",
        "record_kind": kind,
        "provider_id": PROVIDER_GRAPH_SUBJECT,
        "credential_id": CREDENTIAL_ID,
        "enrollment_id": ENROLLMENT_ID,
        "subject_key": SUBJECT_KEY,
        "observed_at": observation_time,
        "issued_at": 6_000,
        "valid_from": 6_000,
        "valid_until": valid_until,
        "terminated_at": terminated_at,
        "status": status,
    }


def demo_input(case: str = "confirmed") -> dict[str, object]:
    """Build one canonical synthetic input vector for tests and operators."""

    observation_time = 7_000
    credential_record = _demo_record("CREDENTIAL", observation_time=observation_time)
    enrollment_record = _demo_record("ENROLLMENT", observation_time=observation_time)
    credential_records = [credential_record]
    enrollment_records = [enrollment_record]
    credential_complete = True
    enrollment_complete = True
    credential_nonmembership: list[str] = []
    enrollment_nonmembership: list[str] = []
    credential_end = 9_000
    enrollment_end = 9_000
    if case == "expired":
        credential_record["valid_until"] = 6_500
        credential_record["status"] = STATUS_EXPIRED
    elif case == "terminated":
        enrollment_record["terminated_at"] = 6_500
        enrollment_record["status"] = STATUS_TERMINATED
    elif case == "incomplete":
        enrollment_complete = False
    elif case == "absent":
        credential_records = []
        enrollment_records = []
        credential_nonmembership = [SUBJECT_KEY]
        enrollment_nonmembership = [SUBJECT_KEY]
    elif case == "conflict":
        credential_records = [credential_record, _demo_record("CREDENTIAL", record_number=2, observation_time=observation_time)]
    elif case == "stale":
        credential_end = 6_999
    elif case != "confirmed":
        raise ProviderTrustGraphError("demo:unknown-case")
    return {
        "schema": INPUT_SCHEMA,
        "provider_graph_subject": PROVIDER_GRAPH_SUBJECT,
        "scope": SCOPE,
        "observation_time": observation_time,
        "sources": [
            _source_for_demo(SOURCE_CREDENTIAL_ID, SOURCE_CREDENTIAL_KIND, observation_time=observation_time, records=credential_records, complete=credential_complete, nonmembership=credential_nonmembership, end=credential_end),
            _source_for_demo(SOURCE_ENROLLMENT_ID, SOURCE_ENROLLMENT_KIND, observation_time=observation_time, records=enrollment_records, complete=enrollment_complete, nonmembership=enrollment_nonmembership, end=enrollment_end),
        ],
        "prior_artifact": None,
        "remediation": None,
        "parity_cases": [],
    }


def refresh_input_digests(value: Mapping[str, object], profile: object | None = None) -> dict[str, object]:
    """Return a test-only copy with source provenance digests recomputed."""

    result = deepcopy(value)
    sources = result.get("sources")
    if isinstance(sources, list):
        for source in sources:
            if isinstance(source, dict) and isinstance(source.get("provenance"), dict):
                source["provenance"]["integrity_digest"] = source_integrity_digest(source, profile)
    return result


def _snapshot(
    sources: Sequence[Mapping[str, object]],
    observation_time: int,
    *,
    profile: _GraphProfile | None = None,
) -> tuple[str, str]:
    view = _profile_view(profile)
    root = _digest(
        "snapshot-root",
        {
            "provider_graph_subject": view.subject,
            "scope": view.scope,
            "observation_time": observation_time,
            "source_roots": [_source_root({key: value for key, value in source.items() if key != "source_root"}, profile=view) for source in sources],
        },
        profile=view,
    )
    return _digest("snapshot-id", {"snapshot_root": root, "observation_time": observation_time}, profile=view), root


def _process_peak_bytes() -> int | None:
    if os.name == "nt":
        try:
            class Counters(ctypes.Structure):
                _fields_ = [
                    ("cb", ctypes.c_ulong),
                    ("page_fault_count", ctypes.c_ulong),
                    ("peak_working_set_size", ctypes.c_size_t),
                    ("working_set_size", ctypes.c_size_t),
                    ("quota_peak_paged_pool_usage", ctypes.c_size_t),
                    ("quota_paged_pool_usage", ctypes.c_size_t),
                    ("quota_peak_non_paged_pool_usage", ctypes.c_size_t),
                    ("quota_non_paged_pool_usage", ctypes.c_size_t),
                    ("pagefile_usage", ctypes.c_size_t),
                    ("peak_pagefile_usage", ctypes.c_size_t),
                ]
            counters = Counters()
            counters.cb = ctypes.sizeof(Counters)
            process = ctypes.windll.kernel32.GetCurrentProcess()
            get_memory = ctypes.windll.psapi.GetProcessMemoryInfo
            get_memory.argtypes = [ctypes.c_void_p, ctypes.POINTER(Counters), ctypes.c_ulong]
            get_memory.restype = ctypes.c_int
            if not get_memory(process, ctypes.byref(counters), counters.cb):
                return None
            return int(counters.peak_working_set_size)
        except (AttributeError, OSError):
            return None
    try:
        if resource is None:
            return None
        usage = resource.getrusage(resource.RUSAGE_SELF)
        return int(usage.ru_maxrss * (1 if sys.platform == "darwin" else 1024))
    except (AttributeError, OSError):
        return None


def build_report(raw_input: bytes, *, profile: object | None = None) -> tuple[bytes, dict[str, object]]:
    """Evaluate one bounded input and return canonical artifact plus telemetry."""

    start = time.perf_counter_ns()
    before = _process_peak_bytes()
    view = profile if isinstance(profile, _GraphProfile) else _profile_view(profile)
    input_value = parse_canonical(raw_input, artifact=False)
    validated = _validate_input(input_value, profile=view)
    observation_time = validated["observation_time"]
    assert isinstance(observation_time, int)
    input_sources = validated["sources"]
    assert isinstance(input_sources, list)
    sources = _validate_sources(input_sources, observation_time, output=False, profile=view)
    _validate_fact_nonmembership(sources)
    source_outputs: list[dict[str, object]] = []
    for source in sources:
        output_source = deepcopy(source)
        output_source["source_root"] = _source_root(source, profile=view)
        source_outputs.append(output_source)
    snapshot_id, snapshot_root = _snapshot(sources, observation_time, profile=view)
    findings, discrepancies = _evaluate(sources, observation_time, snapshot_id, profile=view)
    input_parity = _validate_input_parity(validated["parity_cases"])
    parity_outputs: list[dict[str, object]] = []
    for case in input_parity:
        expected_kind = case["expected_kind"]
        observed_kinds = sorted({finding["kind"] for finding in findings})
        expected_refs = sorted(finding["finding_id"] for finding in findings if finding["kind"] == expected_kind)
        passed = (expected_kind in observed_kinds) == case["expected_present"]
        parity_outputs.append(
            {
                "case_id": case["case_id"],
                "expected_kind": expected_kind,
                "expected_present": case["expected_present"],
                "observed_kinds": observed_kinds,
                "passed": passed,
                "evidence_refs": expected_refs,
                "discrepancy_id": None,
            }
        )
    for case in parity_outputs:
        if not case["passed"]:
            mismatch = _discrepancy(
                "PARITY_MISMATCH",
                "EVIDENCE_AND_EXPECTATION_REVIEW",
                case["evidence_refs"],
                case["case_id"],
                profile=view,
            )
            discrepancies.append(mismatch)
            case["discrepancy_id"] = mismatch["discrepancy_id"]
    discrepancies.sort(key=lambda entry: entry["discrepancy_id"])
    prior_artifact = validated["prior_artifact"]
    remediation_input = validated["remediation"]
    remediation_output: dict[str, object] | None = None
    prior_report_id: str | None = None
    prior_snapshot_id: str | None = None
    prior_snapshot_root: str | None = None
    if remediation_input is not None:
        assert isinstance(remediation_input, dict) and isinstance(prior_artifact, dict)
        prior = _validate_prior_artifact(prior_artifact, profile=view)
        prior_report = _expect_keys(prior["report"], REPORT_KEYS, "prior-artifact:report")
        prior_snapshot = _expect_keys(prior["observation_snapshot"], SNAPSHOT_KEYS, "prior-artifact:snapshot")
        prior_report_id = _hex(prior_report["report_id"], "prior-artifact:report-id")
        prior_snapshot_id = _text(prior_snapshot["snapshot_id"], "prior-artifact:snapshot-id")
        prior_snapshot_root = _hex(prior_snapshot["snapshot_root"], "prior-artifact:snapshot-root")
        current_kind = findings[0]["kind"]
        if remediation_input["retest_result"] == RETEST_PASSED and current_kind != FINDING_CONTINUITY:
            raise ProviderTrustGraphError("remediation:passed-result-mismatch")
        if remediation_input["retest_result"] == RETEST_FAILED and current_kind == FINDING_CONTINUITY:
            raise ProviderTrustGraphError("remediation:failed-result-mismatch")
        remediation_output = {
            "action_artifact_id": remediation_input["action_artifact_id"],
            "submitted_at": remediation_input["submitted_at"],
            "retest_result": remediation_input["retest_result"],
            "prior_finding_ids": remediation_input["prior_finding_ids"],
            "prior_artifact": deepcopy(prior),
        }
        lifecycle = LIFECYCLE_REMEDIATED if remediation_input["retest_result"] == RETEST_PASSED else LIFECYCLE_RETEST_FAILED
    else:
        lifecycle = LIFECYCLE_OPEN
    identity: dict[str, object] = {
        "provider_graph_subject": view.subject,
        "scope": view.scope,
        "observation_time": observation_time,
        "snapshot_id": snapshot_id,
        "snapshot_root": snapshot_root,
        "source_coverage_root": _digest("source-coverage-root", {"source_roots": [source["source_root"] for source in source_outputs]}, profile=view),
        "findings_root": _findings_root(findings, profile=view),
        "discrepancies_root": _digest("discrepancies-root", {"discrepancies": discrepancies}, profile=view),
        "remediation_root": _digest("remediation-root", {"remediation": remediation_output}, profile=view) if remediation_output is not None else None,
        "parity_root": _digest("parity-root", {"parity_cases": parity_outputs}, profile=view),
        "lifecycle": lifecycle,
        "prior_report_id": prior_report_id,
        "prior_snapshot_id": prior_snapshot_id,
        "prior_snapshot_root": prior_snapshot_root,
    }
    if view.v2:
        identity = {
            "profile_id": view.profile_id,
            "version": view.version,
            "profile_digest": view.profile_digest,
            **identity,
        }
    report_id = _digest("report-id", identity, profile=view)
    transition_core: dict[str, object] = {
        "transition_kind": "RETEST" if remediation_output is not None else "INITIAL",
        "prior_report_id": prior_report_id,
        "prior_snapshot_id": prior_snapshot_id,
        "prior_snapshot_root": prior_snapshot_root,
        "current_report_id": report_id,
        "current_snapshot_id": snapshot_id,
        "current_snapshot_root": snapshot_root,
    }
    transition = {"transition_id": _digest("transition-id", transition_core, profile=view), **transition_core}
    artifact: dict[str, object] = {
        "schema": view.schema,
        "subject": {"provider_graph_subject": view.subject, "scope": view.scope},
        "observation_snapshot": {"snapshot_id": snapshot_id, "snapshot_root": snapshot_root, "observation_time": observation_time},
        "source_coverage": source_outputs,
        "findings": findings,
        "discrepancies": discrepancies,
        "remediation": remediation_output,
        "parity_cases": parity_outputs,
        "transition": transition,
        "report": {"report_id": report_id, "identity_material": identity, "lifecycle": lifecycle},
        "authority": {
            "clearance_authority": False,
            "payment_authority": False,
            "economic_mutation": False,
            "production_usable": False,
            "synthetic_only": True,
        },
    }
    if view.v2:
        artifact["profile"] = {
            "profile_id": view.profile_id,
            "version": view.version,
            "profile_digest": view.profile_digest,
        }
    _validate_output(artifact, profile=view)
    raw = _canonical(artifact)
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise ProviderTrustGraphError("artifact:byte-cap")
    after = _process_peak_bytes()
    peak = max(value for value in (before, after) if value is not None) if any(value is not None for value in (before, after)) else None
    telemetry: dict[str, object] = {
        "artifact_bytes": len(raw),
        "wall_time_ns": time.perf_counter_ns() - start,
        "process_tree_peak_bytes": peak,
        "process_tree_scope": "single-process; no child processes",
        "proof_performance_claim": False,
    }
    return raw, telemetry


def build_demo_report(case: str = "confirmed") -> tuple[bytes, dict[str, object]]:
    return build_report(canonical_input(demo_input(case)))


def prior_artifact_from_artifact(raw: bytes, profile: object | None = None) -> dict[str, object]:
    """Extract the complete initial artifact needed by an append-only retest."""

    artifact = parse_canonical(raw, artifact=True)
    view = profile if isinstance(profile, _GraphProfile) else _profile_view(profile)
    _validate_prior_artifact(artifact, profile=view)
    return deepcopy(artifact)


def prior_link_from_artifact(raw: bytes, profile: object | None = None) -> dict[str, object]:
    """Compatibility helper returning the full artifact, never a partial link."""

    return prior_artifact_from_artifact(raw, profile)


def _read_bounded(path: str | Path, maximum: int) -> bytes:
    try:
        file_path = Path(path)
    except Exception:
        raise_redacted(ProviderTrustGraphError, "file:read")
    descriptor = -1
    try:
        before_stat = os.lstat(os.fspath(file_path))
        if stat.S_ISLNK(before_stat.st_mode) or not stat.S_ISREG(before_stat.st_mode):
            raise_redacted(ProviderTrustGraphError, "file:read")
        if before_stat.st_size > maximum:
            raise_redacted(ProviderTrustGraphError, "file:byte-cap")
        before = (int(before_stat.st_dev), int(before_stat.st_ino), int(before_stat.st_nlink), int(before_stat.st_size), int(before_stat.st_mtime_ns))
        descriptor = os.open(os.fspath(file_path), os.O_RDONLY | getattr(os, "O_BINARY", 0))
        opened_stat = os.fstat(descriptor)
        opened = (int(opened_stat.st_dev), int(opened_stat.st_ino), int(opened_stat.st_nlink), int(opened_stat.st_size), int(opened_stat.st_mtime_ns))
        if stat.S_ISLNK(opened_stat.st_mode) or not stat.S_ISREG(opened_stat.st_mode) or opened != before:
            raise_redacted(ProviderTrustGraphError, "file:changed")
        raw = os.read(descriptor, maximum + 1)
        closed_stat = os.fstat(descriptor)
        closed = (int(closed_stat.st_dev), int(closed_stat.st_ino), int(closed_stat.st_nlink), int(closed_stat.st_size), int(closed_stat.st_mtime_ns))
        if closed != opened:
            raise_redacted(ProviderTrustGraphError, "file:changed")
    except ProviderTrustGraphError:
        raise
    except Exception:
        raise_redacted(ProviderTrustGraphError, "file:read")
    finally:
        if descriptor != -1:
            try:
                os.close(descriptor)
            except Exception:
                raise_redacted(ProviderTrustGraphError, "file:read")
    try:
        final_stat = os.lstat(os.fspath(file_path))
    except Exception:
        raise_redacted(ProviderTrustGraphError, "file:read")
    final = (int(final_stat.st_dev), int(final_stat.st_ino), int(final_stat.st_nlink), int(final_stat.st_size), int(final_stat.st_mtime_ns))
    if stat.S_ISLNK(final_stat.st_mode) or not stat.S_ISREG(final_stat.st_mode) or final != before:
        raise_redacted(ProviderTrustGraphError, "file:changed")
    if len(raw) > maximum:
        raise_redacted(ProviderTrustGraphError, "file:byte-cap")
    return raw


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: python -m app.mirror.provider_trust_graph INPUT.json", file=sys.stderr)
        return 2
    try:
        raw, telemetry = build_report(_read_bounded(args[0], MAX_INPUT_BYTES))
        print(json.dumps({"accepted": True, "artifact_bytes": len(raw), "process_tree_peak_bytes": telemetry["process_tree_peak_bytes"]}, sort_keys=True))
        return 0
    except (OSError, ProviderTrustGraphError):
        print("REJECT input", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
