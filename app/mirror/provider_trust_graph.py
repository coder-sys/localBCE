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
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Mapping, Sequence

from app.mirror.error_boundary import raise_redacted


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

INPUT_KEYS = set("schema provider_graph_subject scope observation_time sources".split())
SOURCE_INPUT_KEYS = set(
    "source_id source_kind coverage_scope coverage_observation_time coverage_effective_start "
    "coverage_effective_end coverage_complete coverage_authority_id nonmembership_keys records provenance".split()
)
SOURCE_OUTPUT_KEYS = SOURCE_INPUT_KEYS | {"source_root"}
PROVENANCE_KEYS = {"provenance_id", "integrity_digest"}
RECORD_KEYS = set(
    "record_id record_kind provider_id credential_id enrollment_id subject_key observed_at issued_at "
    "valid_from valid_until terminated_at status".split()
)
SUBJECT_KEYS = {"provider_graph_subject", "scope"}
SNAPSHOT_KEYS = {"snapshot_id", "snapshot_root", "observation_time"}
FINDING_KEYS = set("finding_id kind subject_key observation_snapshot_id evidence_refs".split())
DISCREPANCY_KEYS = set("discrepancy_id kind responsibility_boundary evidence_refs".split())
IDENTITY_KEYS = set(
    "provider_graph_subject scope observation_time snapshot_id snapshot_root source_coverage_root "
    "findings_root discrepancies_root".split()
)
REPORT_KEYS = {"report_id", "identity_material"}
AUTHORITY_KEYS = set("clearance_authority payment_authority economic_mutation production_usable synthetic_only".split())
OUTPUT_KEYS = set("schema subject observation_snapshot source_coverage findings discrepancies report authority".split())
PROFILE_KEYS = {"profile_id", "version", "profile_digest"}
V2_INPUT_KEYS = INPUT_KEYS | {"profile_id", "profile_version", "profile_digest"}
V2_OUTPUT_KEYS = OUTPUT_KEYS | {"profile"}
V2_IDENTITY_KEYS = IDENTITY_KEYS | PROFILE_KEYS

_RE_HEX = re.compile(r"^[0-9a-f]{128}$")
_RE_RECORD = re.compile(r"^SYNTH_(CREDENTIAL|ENROLLMENT)_RECORD_00[1-8]$")
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
            False, SCHEMA, INPUT_SCHEMA, None, None, None, PROVIDER_GRAPH_SUBJECT, SCOPE, CREDENTIAL_ID, ENROLLMENT_ID,
            SUBJECT_KEY, SOURCE_IDS, SOURCE_KINDS, ("CREDENTIAL", "ENROLLMENT"),
            (AUTH_CREDENTIAL_ID, AUTH_ENROLLMENT_ID), (PROVENANCE_CREDENTIAL_ID, PROVENANCE_ENROLLMENT_ID),
            None, None, 6_000, 9_000, True, True,
        )
    try:
        (profile_id, version, subject, scope, credential_id, enrollment_id, details, observation_start, observation_end,
         effective_start, effective_end, require_complete, allow_nonmembership, canonical_order, root_rule,
         profile_digest) = (getattr(profile, name) for name in (
            "profile_id version subject scope credential_id enrollment_id source_role_details observation_start "
            "observation_end effective_start effective_end require_complete allow_nonmembership canonical_order "
            "root_rule profile_digest").split())
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
    try:
        roles = [tuple(getattr(detail, name) for name in ("source_id", "source_kind", "record_kind", "authority_id", "provenance_id"))
                 for detail in details]
    except Exception:
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
        *zip(*roles),
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


def _validate_finding(finding: object, *, snapshot_id: str | None = None, profile: _GraphProfile | None = None) -> dict[str, object]:
    view = _profile_view(profile)
    item = _expect_keys(finding, FINDING_KEYS, "finding")
    kind = _text(item["kind"], "finding:kind")
    if kind not in FINDING_KINDS:
        raise ProviderTrustGraphError("finding:kind")
    if _text(item["subject_key"], "finding:subject") != view.subject_key:
        raise ProviderTrustGraphError("finding:subject")
    current_snapshot = _text(item["observation_snapshot_id"], "finding:snapshot")
    if snapshot_id is not None and current_snapshot != snapshot_id:
        raise ProviderTrustGraphError("finding:snapshot-mismatch")
    refs = _sorted_unique(item["evidence_refs"], "finding:evidence", maximum=MAX_RECORDS_PER_SOURCE * MAX_SOURCES)
    expected_id = _digest("finding-id", {"kind": kind, "subject_key": view.subject_key, "observation_snapshot_id": current_snapshot, "evidence_refs": refs}, profile=view)
    if item["finding_id"] != expected_id:
        raise ProviderTrustGraphError("finding:id-mismatch")
    return item


def _findings_root(findings: Sequence[Mapping[str, object]], *, profile: _GraphProfile | None = None) -> str:
    return _digest("findings-root", {"findings": list(findings)}, profile=profile)


def _validate_identity_material(identity: object, *, profile: _GraphProfile | None = None) -> dict[str, object]:
    view = _profile_view(profile)
    item = _expect_keys(identity, V2_IDENTITY_KEYS if view.v2 else IDENTITY_KEYS, "report:identity-material")
    if item["provider_graph_subject"] != view.subject or item["scope"] != view.scope:
        raise ProviderTrustGraphError("identity:subject-or-scope")
    if view.v2 and (item["profile_id"], item["version"], item["profile_digest"]) != (view.profile_id, view.version, view.profile_digest):
        raise ProviderTrustGraphError("identity:profile")
    _int(item["observation_time"], "identity:observation-time", minimum=1)
    _text(item["snapshot_id"], "identity:snapshot")
    for field in ("snapshot_root", "source_coverage_root", "findings_root", "discrepancies_root"):
        _hex(item[field], "identity:" + field)
    return item


def _validate_input(value: object, *, profile: _GraphProfile | None = None) -> dict[str, object]:
    view = _profile_view(profile)
    item = _expect_keys(value, V2_INPUT_KEYS if view.v2 else INPUT_KEYS, "input")
    if item["schema"] != view.input_schema:
        raise ProviderTrustGraphError("input:schema")
    if item["provider_graph_subject"] != view.subject:
        raise ProviderTrustGraphError("input:subject")
    if item["scope"] != view.scope:
        raise ProviderTrustGraphError("input:scope")
    if view.v2 and (item["profile_id"], item["profile_version"], item["profile_digest"]) != (view.profile_id, view.version, view.profile_digest):
        raise ProviderTrustGraphError("input:profile")
    observation_time = _int(item["observation_time"], "input:observation-time", minimum=1)
    if view.v2 and not view.observation_start <= observation_time < view.observation_end:  # type: ignore[operator]
        raise ProviderTrustGraphError("input:observation-window")
    _validate_sources(item["sources"], observation_time, output=False, profile=view)
    return item


def _finding(kind: str, snapshot_id: str, refs: Sequence[str], *, profile: _GraphProfile | None = None) -> dict[str, object]:
    view = _profile_view(profile)
    body = {"kind": kind, "subject_key": view.subject_key, "observation_snapshot_id": snapshot_id, "evidence_refs": sorted(refs)}
    return {"finding_id": _digest("finding-id", body, profile=view), **body}


def _discrepancy(kind: str, refs: Sequence[str], *, profile: _GraphProfile | None = None) -> dict[str, object]:
    body = {"kind": kind, "responsibility_boundary": "UNKNOWN", "evidence_refs": sorted(refs)}
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
            _discrepancy("SOURCE_CONFLICT_EVIDENCE", refs, profile=view)
        ]
    credential = next(record for record in matches if record["record_kind"] == "CREDENTIAL")
    enrollment = next(record for record in matches if record["record_kind"] == "ENROLLMENT")
    refs = [credential["record_id"], enrollment["record_id"]]
    if credential["status"] == STATUS_EXPIRED:
        return [_finding(FINDING_EXPIRED, snapshot_id, refs, profile=view)], []
    if enrollment["status"] == STATUS_TERMINATED:
        return [_finding(FINDING_TERMINATED, snapshot_id, refs, profile=view)], []
    return [_finding(FINDING_CONTINUITY, snapshot_id, refs, profile=view)], []


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


def _validate_output(value: object, *, profile: _GraphProfile | None = None) -> dict[str, object]:
    """Validate the retained observation/findings grammar only.

    Corrective action and retest state are Core-owned.  They are deliberately
    absent from this artifact, so an old lifecycle-shaped artifact fails the
    exact-key check rather than being reinterpreted.
    """
    view = _profile_view(profile)
    item = _expect_keys(value, V2_OUTPUT_KEYS if view.v2 else OUTPUT_KEYS, "artifact")
    if item["schema"] != view.schema:
        raise ProviderTrustGraphError("artifact:schema")
    if view.v2 and item["profile"] != {"profile_id": view.profile_id, "version": view.version, "profile_digest": view.profile_digest}:
        raise ProviderTrustGraphError("artifact:profile")
    subject = _expect_keys(item["subject"], SUBJECT_KEYS, "artifact:subject")
    if subject != {"provider_graph_subject": view.subject, "scope": view.scope}:
        raise ProviderTrustGraphError("artifact:subject")
    snapshot = _expect_keys(item["observation_snapshot"], SNAPSHOT_KEYS, "artifact:snapshot")
    snapshot_id = _text(snapshot["snapshot_id"], "snapshot:id")
    snapshot_root = _hex(snapshot["snapshot_root"], "snapshot:root")
    observation_time = _int(snapshot["observation_time"], "snapshot:time", minimum=1)
    if view.v2 and not view.observation_start <= observation_time < view.observation_end:  # type: ignore[operator]
        raise ProviderTrustGraphError("snapshot:observation-window")
    source_items = _validate_sources(item["source_coverage"], observation_time, output=True, profile=view)
    expected_snapshot_root = _digest("snapshot-root", {"provider_graph_subject": view.subject, "scope": view.scope, "observation_time": observation_time, "source_roots": [source["source_root"] for source in source_items]}, profile=view)
    if snapshot_root != expected_snapshot_root or snapshot_id != _digest("snapshot-id", {"snapshot_root": snapshot_root, "observation_time": observation_time}, profile=view):
        raise ProviderTrustGraphError("snapshot:binding")
    findings_value = item["findings"]
    if not isinstance(findings_value, list) or len(findings_value) > MAX_FINDINGS:
        raise ProviderTrustGraphError("finding:count-cap")
    findings = [_validate_finding(raw, snapshot_id=snapshot_id, profile=view) for raw in findings_value]
    finding_ids = [finding["finding_id"] for finding in findings]
    if finding_ids != sorted(finding_ids) or len(set(finding_ids)) != len(finding_ids):
        raise ProviderTrustGraphError("finding:order-or-duplicate")
    expected_findings, expected_discrepancies = _evaluate(source_items, observation_time, snapshot_id, profile=view)
    if findings != expected_findings:
        raise ProviderTrustGraphError("finding:semantic-mismatch")
    discrepancies_value = item["discrepancies"]
    if not isinstance(discrepancies_value, list) or len(discrepancies_value) > MAX_DISCREPANCIES:
        raise ProviderTrustGraphError("discrepancy:count-cap")
    discrepancies: list[dict[str, object]] = []
    finding_set = {finding["finding_id"] for finding in findings}
    for raw in discrepancies_value:
        discrepancy = _expect_keys(raw, DISCREPANCY_KEYS, "discrepancy")
        kind = _text(discrepancy["kind"], "discrepancy:kind")
        if kind != "SOURCE_CONFLICT_EVIDENCE" or discrepancy["responsibility_boundary"] != "UNKNOWN":
            raise ProviderTrustGraphError("discrepancy:authority")
        refs = _sorted_unique(discrepancy["evidence_refs"], "discrepancy:evidence", maximum=MAX_RECORDS_PER_SOURCE * MAX_SOURCES)
        if not set(refs).isdisjoint(finding_set):
            raise ProviderTrustGraphError("discrepancy:evidence")
        if discrepancy["discrepancy_id"] != _digest("discrepancy-id", {"kind": kind, "responsibility_boundary": "UNKNOWN", "evidence_refs": refs}, profile=view):
            raise ProviderTrustGraphError("discrepancy:id")
        discrepancies.append(discrepancy)
    if [entry["discrepancy_id"] for entry in discrepancies] != sorted(entry["discrepancy_id"] for entry in discrepancies) or len({entry["discrepancy_id"] for entry in discrepancies}) != len(discrepancies):
        raise ProviderTrustGraphError("discrepancy:order-or-duplicate")
    if discrepancies != expected_discrepancies:
        raise ProviderTrustGraphError("discrepancy:semantic-mismatch")
    report = _expect_keys(item["report"], REPORT_KEYS, "report")
    identity = _validate_identity_material(report["identity_material"], profile=view)
    if identity["snapshot_id"] != snapshot_id or identity["snapshot_root"] != snapshot_root or identity["observation_time"] != observation_time:
        raise ProviderTrustGraphError("report:snapshot-binding")
    expected_identity = dict(identity)
    expected_identity["source_coverage_root"] = _digest("source-coverage-root", {"source_roots": [source["source_root"] for source in source_items]}, profile=view)
    expected_identity["findings_root"] = _findings_root(findings, profile=view)
    expected_identity["discrepancies_root"] = _digest("discrepancies-root", {"discrepancies": discrepancies}, profile=view)
    if identity != expected_identity or report["report_id"] != _digest("report-id", identity, profile=view):
        raise ProviderTrustGraphError("report:identity-material-mismatch")
    authority = _expect_keys(item["authority"], AUTHORITY_KEYS, "authority")
    if authority != {"clearance_authority": False, "payment_authority": False, "economic_mutation": False, "production_usable": False, "synthetic_only": True}:
        raise ProviderTrustGraphError("authority:flags")
    return item


def build_report(raw_input: bytes, *, profile: object | None = None) -> bytes:
    """Build only derived observation/findings evidence; no caller lifecycle."""
    view = profile if isinstance(profile, _GraphProfile) else _profile_view(profile)
    validated = _validate_input(parse_canonical(raw_input, artifact=False), profile=view)
    observation_time = validated["observation_time"]
    assert isinstance(observation_time, int)
    sources = _validate_sources(validated["sources"], observation_time, output=False, profile=view)
    source_outputs: list[dict[str, object]] = []
    for source in sources:
        output = deepcopy(source)
        output["source_root"] = _source_root(source, profile=view)
        source_outputs.append(output)
    snapshot_id, snapshot_root = _snapshot(sources, observation_time, profile=view)
    findings, discrepancies = _evaluate(sources, observation_time, snapshot_id, profile=view)
    identity: dict[str, object] = {
        "provider_graph_subject": view.subject,
        "scope": view.scope,
        "observation_time": observation_time,
        "snapshot_id": snapshot_id,
        "snapshot_root": snapshot_root,
        "source_coverage_root": _digest("source-coverage-root", {"source_roots": [source["source_root"] for source in source_outputs]}, profile=view),
        "findings_root": _findings_root(findings, profile=view),
        "discrepancies_root": _digest("discrepancies-root", {"discrepancies": discrepancies}, profile=view),
    }
    if view.v2:
        identity = {"profile_id": view.profile_id, "version": view.version, "profile_digest": view.profile_digest, **identity}
    report_id = _digest("report-id", identity, profile=view)
    artifact: dict[str, object] = {
        "schema": view.schema,
        "subject": {"provider_graph_subject": view.subject, "scope": view.scope},
        "observation_snapshot": {"snapshot_id": snapshot_id, "snapshot_root": snapshot_root, "observation_time": observation_time},
        "source_coverage": source_outputs,
        "findings": findings,
        "discrepancies": discrepancies,
        "report": {"report_id": report_id, "identity_material": identity},
        "authority": {"clearance_authority": False, "payment_authority": False, "economic_mutation": False, "production_usable": False, "synthetic_only": True},
    }
    if view.v2:
        artifact["profile"] = {"profile_id": view.profile_id, "version": view.version, "profile_digest": view.profile_digest}
    _validate_output(artifact, profile=view)
    raw = _canonical(artifact)
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise ProviderTrustGraphError("artifact:byte-cap")
    return raw


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

