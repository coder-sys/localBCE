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
import os
from pathlib import Path
import re
import sys
import stat
from typing import Mapping, Sequence

from app.mirror.error_boundary import raise_redacted


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
MAX_INPUT_BYTES = 262_144
MAX_ARTIFACT_BYTES = 262_144
MAX_SOURCES = 2
MAX_RECORDS_PER_SOURCE = 8
MAX_FINDINGS = 8
MAX_DISCREPANCIES = 8
MAX_STRING_BYTES = 512
MAX_NODES = 4_096
MAX_DEPTH = 16
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
    "finding_id", "kind", "subject_key", "observation_snapshot_id", "evidence_refs",
}
DISCREPANCY_KEYS = {
    "discrepancy_id", "kind", "responsibility_boundary", "evidence_refs",
}
IDENTITY_KEYS = {
    "provider_graph_subject", "scope", "observation_time", "snapshot_id",
    "snapshot_root", "source_coverage_root", "findings_root", "discrepancies_root",
}
REPORT_KEYS = {"report_id", "identity_material"}
AUTHORITY_KEYS = {
    "clearance_authority", "payment_authority", "economic_mutation",
    "production_usable", "synthetic_only",
}
OUTPUT_KEYS = {
    "schema", "subject", "observation_snapshot", "source_coverage",
    "findings", "discrepancies", "report", "authority",
}
PROFILE_KEYS = {"profile_id", "version", "profile_digest"}
V2_OUTPUT_KEYS = OUTPUT_KEYS | {"profile"}
V2_IDENTITY_KEYS = IDENTITY_KEYS | PROFILE_KEYS
INPUT_SCHEMA_V2 = "mirror-provider-trust-graph-input-v2"
_RE_HEX = re.compile(r"^[0-9a-f]{128}$")
_RE_RECORD = re.compile(r"^SYNTH_(CREDENTIAL|ENROLLMENT)_RECORD_00[1-8]$")


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
    require_complete: bool
    allow_nonmembership: bool

    def role_index(self, source_id: str) -> int:
        try:
            return self.source_roles.index(source_id)
        except ValueError as exc:
            raise_redacted(IndependentProviderTrustGraphError, "profile:source-role")


@dataclass(frozen=True)
class _VerifiedGraphArtifactV2:
    """One independently verified V2 artifact retained only in bounded memory."""

    value: dict[str, object]
    profile: _GraphProfile
    summary: dict[str, object]
    raw_digest: str
    raw_length: int


def _profile_material(profile: object) -> dict[str, object]:
    details = getattr(profile, "source_role_details")
    material = {
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
    source_contract_digest = getattr(profile, "source_contract_digest", None)
    if source_contract_digest is not None:
        material["source_contract_digest"] = source_contract_digest
    return material


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
        require_complete = getattr(profile, "require_complete")
        allow_nonmembership = getattr(profile, "allow_nonmembership")
    except Exception:
        raise_redacted(IndependentProviderTrustGraphError, "profile:configuration")
    role_ids = tuple(role[0] for role in roles)
    if (
        len(roles) != 2
        or role_ids != tuple(sorted(role_ids))
        or len(set(role_ids)) != len(role_ids)
        or len(set(role[1] for role in roles)) != len(roles)
        or {role[2] for role in roles} != {"CREDENTIAL", "ENROLLMENT"}
        or profile_digest != supplied_digest
        or getattr(profile, "version") not in (2, 3)
        or getattr(profile, "canonical_order") != "lexicographic-v1"
        or getattr(profile, "root_rule") != "source-root-v1"
        or type(require_complete) is not bool
        or type(allow_nonmembership) is not bool
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
        require_complete,
        allow_nonmembership,
    )


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise_redacted(IndependentProviderTrustGraphError, "json:noncanonical-value")


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
        except UnicodeEncodeError:
            raise_redacted(IndependentProviderTrustGraphError, "json:non-ascii")
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
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise_redacted(IndependentProviderTrustGraphError, "json:parse")
    if not isinstance(value, dict):
        raise IndependentProviderTrustGraphError("json:top-level")
    _walk(value)
    if _canonical(value) != raw:
        raise IndependentProviderTrustGraphError("json:not-canonical")
    return value


def _parse_input(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > 262_144:
        raise IndependentProviderTrustGraphError("input:byte-cap")
    return _parse(raw)


def _digest(label: str, value: object, *, profile: _GraphProfile | None = None) -> str:
    h = hashlib.sha3_512()
    version = "v2" if profile is not None and profile.v2 else "v1"
    h.update(("BL/MIRROR/PROVIDER-TRUST-GRAPH/" + label + "/" + version + "\0").encode("ascii"))
    h.update(_canonical(value))
    return h.hexdigest()


def _raw_digest(raw: bytes) -> str:
    return hashlib.sha3_512(raw).hexdigest()


def _expect_keys(value: object, expected: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise IndependentProviderTrustGraphError(f"{label}:schema")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise IndependentProviderTrustGraphError(f"{label}:text")
    try:
        size = len(value.encode("ascii"))
    except UnicodeEncodeError:
        raise_redacted(IndependentProviderTrustGraphError, f"{label}:ascii")
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
    if view.version == 3:
        if _RE_HEX.fullmatch(record_id) is None:
            raise IndependentProviderTrustGraphError("record:id:opaque")
    elif _RE_RECORD.fullmatch(record_id) is None:
        raise IndependentProviderTrustGraphError("record:id:not-synthetic")
    try:
        role_index = view.source_kinds.index(source_kind)
    except ValueError:
        raise_redacted(IndependentProviderTrustGraphError, "record:source-mismatch")
    expected_kind = view.record_kinds[role_index]
    expected_prefix = "SYNTH_" + expected_kind
    if view.version != 3 and not record_id.startswith(expected_prefix):
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
    output: bool = True,
) -> dict[str, object]:
    view = _profile_view(profile)
    source = _expect_keys(value, SOURCE_OUTPUT_KEYS if output else SOURCE_INPUT_KEYS, "source")
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
    coverage_complete = _bool(source["coverage_complete"], "source:complete")
    if view.v2 and view.require_complete and coverage_complete is not True:
        raise IndependentProviderTrustGraphError("source:completeness-policy")
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
    if output:
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
    output: bool = True,
) -> list[dict[str, object]]:
    view = _profile_view(profile)
    if not isinstance(sources, list) or len(sources) != len(view.source_roles):
        raise IndependentProviderTrustGraphError("sources:exact-count")
    items = [_validate_source(source, observation_time, profile=view, output=output) for source in sources]
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
        if output:
            without_root = {key: value for key, value in source.items() if key != "source_root"}
            if source["source_root"] != _source_root(without_root, profile=view):
                raise IndependentProviderTrustGraphError("source:root-mismatch")
    return items


def _findings_root(findings: Sequence[Mapping[str, object]], *, profile: _GraphProfile | None = None) -> str:
    return _digest("findings-root", {"findings": list(findings)}, profile=profile)


def verify_file(path: str | Path) -> dict[str, object]:
    try:
        file_path = Path(path)
    except Exception:
        raise_redacted(IndependentProviderTrustGraphError, "file:read")
    descriptor = -1
    try:
        before_stat = os.lstat(os.fspath(file_path))
        if stat.S_ISLNK(before_stat.st_mode) or not stat.S_ISREG(before_stat.st_mode):
            raise_redacted(IndependentProviderTrustGraphError, "file:read")
        if before_stat.st_size > MAX_ARTIFACT_BYTES:
            raise_redacted(IndependentProviderTrustGraphError, "file:byte-cap")
        before = (int(before_stat.st_dev), int(before_stat.st_ino), int(before_stat.st_nlink), int(before_stat.st_size), int(before_stat.st_mtime_ns))
        descriptor = os.open(os.fspath(file_path), os.O_RDONLY | getattr(os, "O_BINARY", 0))
        opened_stat = os.fstat(descriptor)
        opened = (int(opened_stat.st_dev), int(opened_stat.st_ino), int(opened_stat.st_nlink), int(opened_stat.st_size), int(opened_stat.st_mtime_ns))
        if stat.S_ISLNK(opened_stat.st_mode) or not stat.S_ISREG(opened_stat.st_mode) or opened != before:
            raise_redacted(IndependentProviderTrustGraphError, "file:changed")
        raw = os.read(descriptor, MAX_ARTIFACT_BYTES + 1)
        closed_stat = os.fstat(descriptor)
        closed = (int(closed_stat.st_dev), int(closed_stat.st_ino), int(closed_stat.st_nlink), int(closed_stat.st_size), int(closed_stat.st_mtime_ns))
        if closed != opened:
            raise_redacted(IndependentProviderTrustGraphError, "file:changed")
    except IndependentProviderTrustGraphError:
        raise
    except Exception:
        raise_redacted(IndependentProviderTrustGraphError, "file:read")
    finally:
        if descriptor != -1:
            try:
                os.close(descriptor)
            except Exception:
                raise_redacted(IndependentProviderTrustGraphError, "file:read")
    try:
        final_stat = os.lstat(os.fspath(file_path))
    except Exception:
        raise_redacted(IndependentProviderTrustGraphError, "file:read")
    final = (int(final_stat.st_dev), int(final_stat.st_ino), int(final_stat.st_nlink), int(final_stat.st_size), int(final_stat.st_mtime_ns))
    if stat.S_ISLNK(final_stat.st_mode) or not stat.S_ISREG(final_stat.st_mode) or final != before:
        raise_redacted(IndependentProviderTrustGraphError, "file:changed")
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise_redacted(IndependentProviderTrustGraphError, "file:byte-cap")
    return verify_bytes(raw)


_NEW_INPUT_KEYS_V1 = {"schema", "provider_graph_subject", "scope", "observation_time", "sources"}
_NEW_INPUT_KEYS_V2 = {"schema", "profile_id", "profile_version", "profile_digest", "provider_graph_subject", "scope", "observation_time", "sources"}
_NEW_OUTPUT_KEYS_V1 = {"schema", "subject", "observation_snapshot", "source_coverage", "findings", "discrepancies", "report", "authority"}
_NEW_OUTPUT_KEYS_V2 = _NEW_OUTPUT_KEYS_V1 | {"profile"}
_NEW_IDENTITY_KEYS_V1 = {"provider_graph_subject", "scope", "observation_time", "snapshot_id", "snapshot_root", "source_coverage_root", "findings_root", "discrepancies_root"}
_NEW_IDENTITY_KEYS_V2 = _NEW_IDENTITY_KEYS_V1 | {"profile_id", "version", "profile_digest"}
_NEW_FINDING_KEYS = {"finding_id", "kind", "subject_key", "observation_snapshot_id", "evidence_refs"}
_NEW_DISCREPANCY_KEYS = {"discrepancy_id", "kind", "responsibility_boundary", "evidence_refs"}
_NEW_REPORT_KEYS = {"report_id", "identity_material"}


def _new_finding(kind: str, snapshot_id: str, refs: Sequence[str], *, profile: _GraphProfile) -> dict[str, object]:
    body = {"kind": kind, "subject_key": profile.subject_key, "observation_snapshot_id": snapshot_id, "evidence_refs": sorted(refs)}
    return {"finding_id": _digest("finding-id", body, profile=profile), **body}


def _new_discrepancy(kind: str, refs: Sequence[str], *, profile: _GraphProfile) -> dict[str, object]:
    body = {"kind": kind, "responsibility_boundary": "UNKNOWN", "evidence_refs": sorted(refs)}
    return {"discrepancy_id": _digest("discrepancy-id", body, profile=profile), **body}


def _new_evaluate(sources: Sequence[Mapping[str, object]], observation_time: int, snapshot_id: str, *, profile: _GraphProfile) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    stale = [source["source_id"] for source in sources if not source["coverage_effective_start"] <= observation_time < source["coverage_effective_end"]]
    if stale:
        return [_new_finding(FINDING_STALE, snapshot_id, stale, profile=profile)], []
    incomplete = [source["source_id"] for source in sources if not source["coverage_complete"]]
    if incomplete:
        return [_new_finding(FINDING_INCOMPLETE, snapshot_id, incomplete, profile=profile)], []
    matches = [record for source in sources for record in source["records"]]
    missing = [source for source in sources if not source["records"]]
    if missing:
        if profile.allow_nonmembership and not matches and all(source["nonmembership_keys"] == [profile.subject_key] for source in sources):
            return [_new_finding(FINDING_ABSENT, snapshot_id, list(profile.source_roles), profile=profile)], []
        raise IndependentProviderTrustGraphError("evidence:partial-absence")
    if any(len(source["records"]) > 1 for source in sources):
        refs = [record["record_id"] for record in matches]
        return [_new_finding(FINDING_CONFLICT, snapshot_id, refs, profile=profile)], [_new_discrepancy("SOURCE_CONFLICT_EVIDENCE", refs, profile=profile)]
    credential = next(record for record in matches if record["record_kind"] == "CREDENTIAL")
    enrollment = next(record for record in matches if record["record_kind"] == "ENROLLMENT")
    refs = [credential["record_id"], enrollment["record_id"]]
    if credential["status"] == STATUS_EXPIRED:
        return [_new_finding(FINDING_EXPIRED, snapshot_id, refs, profile=profile)], []
    if enrollment["status"] == STATUS_TERMINATED:
        return [_new_finding(FINDING_TERMINATED, snapshot_id, refs, profile=profile)], []
    return [_new_finding(FINDING_CONTINUITY, snapshot_id, refs, profile=profile)], []


def _new_validate_input(value: object, *, profile: _GraphProfile) -> dict[str, object]:
    expected = _NEW_INPUT_KEYS_V2 if profile.v2 else _NEW_INPUT_KEYS_V1
    item = _expect_keys(value, expected, "input")
    if item["schema"] != INPUT_SCHEMA_V2:
        raise IndependentProviderTrustGraphError("input:schema")
    if item["provider_graph_subject"] != profile.subject:
        raise IndependentProviderTrustGraphError("input:subject")
    if item["scope"] != profile.scope:
        raise IndependentProviderTrustGraphError("input:scope")
    if profile.v2 and (item["profile_id"], item["profile_version"], item["profile_digest"]) != (profile.profile_id, profile.version, profile.profile_digest):
        raise IndependentProviderTrustGraphError("input:profile")
    observation = _int(item["observation_time"], "input:observation-time", minimum=1)
    if profile.v2 and not profile.observation_start <= observation < profile.observation_end:  # type: ignore[operator]
        raise IndependentProviderTrustGraphError("input:observation-window")
    _validate_sources(item["sources"], observation, profile=profile, output=False)
    return item


def _new_validate_artifact(value: object, *, profile: _GraphProfile) -> dict[str, object]:
    expected = _NEW_OUTPUT_KEYS_V2 if profile.v2 else _NEW_OUTPUT_KEYS_V1
    item = _expect_keys(value, expected, "artifact")
    if item["schema"] != profile.schema:
        raise IndependentProviderTrustGraphError("artifact:schema")
    if profile.v2 and item["profile"] != {"profile_id": profile.profile_id, "version": profile.version, "profile_digest": profile.profile_digest}:
        raise IndependentProviderTrustGraphError("artifact:profile")
    subject = _expect_keys(item["subject"], {"provider_graph_subject", "scope"}, "artifact:subject")
    if subject != {"provider_graph_subject": profile.subject, "scope": profile.scope}:
        raise IndependentProviderTrustGraphError("artifact:subject")
    snapshot = _expect_keys(item["observation_snapshot"], {"snapshot_id", "snapshot_root", "observation_time"}, "artifact:snapshot")
    snapshot_id = _text(snapshot["snapshot_id"], "snapshot:id")
    snapshot_root = _hex(snapshot["snapshot_root"], "snapshot:root")
    observation = _int(snapshot["observation_time"], "snapshot:time", minimum=1)
    if profile.v2 and not profile.observation_start <= observation < profile.observation_end:  # type: ignore[operator]
        raise IndependentProviderTrustGraphError("snapshot:observation-window")
    sources = _validate_sources(item["source_coverage"], observation, profile=profile, output=True)
    expected_snapshot_root = _digest("snapshot-root", {"provider_graph_subject": profile.subject, "scope": profile.scope, "observation_time": observation, "source_roots": [source["source_root"] for source in sources]}, profile=profile)
    if snapshot_root != expected_snapshot_root or snapshot_id != _digest("snapshot-id", {"snapshot_root": snapshot_root, "observation_time": observation}, profile=profile):
        raise IndependentProviderTrustGraphError("snapshot:binding")
    finding_values = item["findings"]
    if not isinstance(finding_values, list) or len(finding_values) > MAX_FINDINGS:
        raise IndependentProviderTrustGraphError("finding:count-cap")
    findings: list[dict[str, object]] = []
    for value in finding_values:
        finding = _expect_keys(value, _NEW_FINDING_KEYS, "finding")
        kind = _text(finding["kind"], "finding:kind")
        if kind not in FINDING_KINDS or finding["subject_key"] != profile.subject_key or finding["observation_snapshot_id"] != snapshot_id:
            raise IndependentProviderTrustGraphError("finding:binding")
        refs = _sorted_unique(finding["evidence_refs"], "finding:evidence", maximum=MAX_RECORDS_PER_SOURCE * MAX_SOURCES)
        if finding["finding_id"] != _digest("finding-id", {"kind": kind, "subject_key": profile.subject_key, "observation_snapshot_id": snapshot_id, "evidence_refs": refs}, profile=profile):
            raise IndependentProviderTrustGraphError("finding:id")
        findings.append(finding)
    if [finding["finding_id"] for finding in findings] != sorted(finding["finding_id"] for finding in findings) or len({finding["finding_id"] for finding in findings}) != len(findings):
        raise IndependentProviderTrustGraphError("finding:order-or-duplicate")
    expected_findings, expected_discrepancies = _new_evaluate(sources, observation, snapshot_id, profile=profile)
    if findings != expected_findings:
        raise IndependentProviderTrustGraphError("finding:semantic-mismatch")
    discrepancy_values = item["discrepancies"]
    if not isinstance(discrepancy_values, list) or len(discrepancy_values) > MAX_DISCREPANCIES:
        raise IndependentProviderTrustGraphError("discrepancy:count-cap")
    discrepancies: list[dict[str, object]] = []
    for value in discrepancy_values:
        discrepancy = _expect_keys(value, _NEW_DISCREPANCY_KEYS, "discrepancy")
        if discrepancy["kind"] != "SOURCE_CONFLICT_EVIDENCE" or discrepancy["responsibility_boundary"] != "UNKNOWN":
            raise IndependentProviderTrustGraphError("discrepancy:authority")
        refs = _sorted_unique(discrepancy["evidence_refs"], "discrepancy:evidence", maximum=MAX_RECORDS_PER_SOURCE * MAX_SOURCES)
        expected_id = _digest("discrepancy-id", {"kind": discrepancy["kind"], "responsibility_boundary": "UNKNOWN", "evidence_refs": refs}, profile=profile)
        if discrepancy["discrepancy_id"] != expected_id:
            raise IndependentProviderTrustGraphError("discrepancy:id")
        discrepancies.append(discrepancy)
    if discrepancies != expected_discrepancies:
        raise IndependentProviderTrustGraphError("discrepancy:semantic-mismatch")
    report = _expect_keys(item["report"], _NEW_REPORT_KEYS, "report")
    identity = _expect_keys(report["identity_material"], _NEW_IDENTITY_KEYS_V2 if profile.v2 else _NEW_IDENTITY_KEYS_V1, "report:identity")
    if identity["provider_graph_subject"] != profile.subject or identity["scope"] != profile.scope or identity["snapshot_id"] != snapshot_id or identity["snapshot_root"] != snapshot_root or identity["observation_time"] != observation:
        raise IndependentProviderTrustGraphError("report:binding")
    if profile.v2 and (identity["profile_id"], identity["version"], identity["profile_digest"]) != (profile.profile_id, profile.version, profile.profile_digest):
        raise IndependentProviderTrustGraphError("report:profile")
    for field in ("snapshot_root", "source_coverage_root", "findings_root", "discrepancies_root"):
        _hex(identity[field], "report:" + field)
    expected_identity = dict(identity)
    expected_identity["source_coverage_root"] = _digest("source-coverage-root", {"source_roots": [source["source_root"] for source in sources]}, profile=profile)
    expected_identity["findings_root"] = _digest("findings-root", {"findings": findings}, profile=profile)
    expected_identity["discrepancies_root"] = _digest("discrepancies-root", {"discrepancies": discrepancies}, profile=profile)
    if identity != expected_identity or report["report_id"] != _digest("report-id", identity, profile=profile):
        raise IndependentProviderTrustGraphError("report:identity")
    authority = _expect_keys(item["authority"], AUTHORITY_KEYS, "authority")
    if authority != {"clearance_authority": False, "payment_authority": False, "economic_mutation": False, "production_usable": False, "synthetic_only": True}:
        raise IndependentProviderTrustGraphError("authority:flags")
    return item


def _new_graph_checked(raw: bytes, registry: Mapping[str, object]) -> _VerifiedGraphArtifactV2:
    if not isinstance(registry, Mapping) or not registry:
        raise IndependentProviderTrustGraphError("profile:registry-required")
    artifact = _parse(raw)
    profile_value = _expect_keys(artifact.get("profile"), PROFILE_KEYS, "artifact:profile")
    profile_id = _text(profile_value["profile_id"], "artifact:profile-id")
    configured = registry.get(profile_id)
    if configured is None:
        raise IndependentProviderTrustGraphError("profile:registry-miss")
    view = _profile_view(configured)
    if not view.v2 or profile_value != {"profile_id": view.profile_id, "version": view.version, "profile_digest": view.profile_digest}:
        raise IndependentProviderTrustGraphError("profile:artifact-not-authority")
    item = _new_validate_artifact(artifact, profile=view)
    summary = {"report_id": item["report"]["report_id"], "finding_kinds": [finding["kind"] for finding in item["findings"]], "artifact_bytes": len(raw), "profile_id": view.profile_id, "profile_version": view.version, "profile_digest": view.profile_digest, "accepted": True}
    return _VerifiedGraphArtifactV2(value=item, profile=view, summary=summary, raw_digest=_raw_digest(raw), raw_length=len(raw))


def _new_input_value(raw: bytes, profile: _GraphProfile) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_INPUT_BYTES:
        raise IndependentProviderTrustGraphError("input:byte-cap")
    return _new_validate_input(_parse(raw), profile=profile)


def _new_bind_input(graph_input_raw: bytes, artifact_raw: bytes, *, verified: _VerifiedGraphArtifactV2) -> dict[str, object]:
    if type(artifact_raw) is not bytes or not artifact_raw or len(artifact_raw) > MAX_ARTIFACT_BYTES or verified.raw_length != len(artifact_raw) or verified.raw_digest != _raw_digest(artifact_raw):
        raise IndependentProviderTrustGraphError("artifact:verification-binding")
    input_value = _new_input_value(graph_input_raw, verified.profile)
    artifact = verified.value
    subject = artifact["subject"]
    if subject != {"provider_graph_subject": input_value["provider_graph_subject"], "scope": input_value["scope"]}:
        raise IndependentProviderTrustGraphError("input:artifact-subject")
    snapshot = artifact["observation_snapshot"]
    if snapshot["observation_time"] != input_value["observation_time"]:
        raise IndependentProviderTrustGraphError("input:artifact-time")
    projected = [{key: value for key, value in source.items() if key != "source_root"} for source in artifact["source_coverage"]]
    if projected != input_value["sources"]:
        raise IndependentProviderTrustGraphError("input:artifact-sources")
    return dict(verified.summary)


def verify_bytes(raw: bytes) -> dict[str, object]:
    artifact = _parse(raw)
    view = _profile_view(None)
    item = _new_validate_artifact(artifact, profile=view)
    return {"report_id": item["report"]["report_id"], "finding_kinds": [finding["kind"] for finding in item["findings"]], "artifact_bytes": len(raw), "accepted": True}


def verify_artifact_v2(raw: bytes, profile_registry: Mapping[str, object]) -> _VerifiedGraphArtifactV2:
    return _new_graph_checked(raw, profile_registry)


def verify_bytes_v2(raw: bytes, profile_registry: Mapping[str, object]) -> dict[str, object]:
    return dict(_new_graph_checked(raw, profile_registry).summary)


def _bind_input_to_verified_v2(graph_input_raw: bytes, artifact_raw: bytes, *, verified: _VerifiedGraphArtifactV2) -> dict[str, object]:
    return _new_bind_input(graph_input_raw, artifact_raw, verified=verified)


def verify_input_binding_v2(graph_input_raw: bytes, artifact_raw: bytes, profile_registry: Mapping[str, object]) -> dict[str, object]:
    return _new_bind_input(graph_input_raw, artifact_raw, verified=_new_graph_checked(artifact_raw, profile_registry))


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: python -m app.mirror.provider_trust_graph_independent ARTIFACT.json", file=sys.stderr)
        return 2
    try:
        print(json.dumps(verify_file(args[0]), sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, IndependentProviderTrustGraphError):
        print("REJECT input", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
