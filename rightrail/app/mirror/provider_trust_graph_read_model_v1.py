"""Bounded, transient staff view over an independently verified PTG artifact."""

from __future__ import annotations

import argparse
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
import json
import sys
from typing import NoReturn

from app.mirror import nc_medicaid_fhir_profile as nc_profile
from app.mirror.nc_medicaid_fhir_independent import NcMedicaidFhirVerifier
from app.mirror import provider_evidence_export_v1 as evidence_export
from app.mirror import provider_evidence_export_v1_independent as evidence_export_independent
from app.mirror import provider_trust_graph as graph_producer
from app.mirror import provider_trust_graph_independent as graph_independent
from app.mirror.error_boundary import raise_redacted
from app.mirror.source_admission import SourceAdmissionService


class ProviderTrustGraphReadModelV1Error(ValueError):
    """Raised for one bounded, redacted read-model contract failure."""


RESPONSE_DOMAIN = "BL/MIRROR/PROVIDER_TRUST_GRAPH/READ_MODEL/RESPONSE"
SCHEMA = "mirror-provider-trust-graph-read-model-v1"
VERSION = 1
MAX_RESPONSE_BYTES = 16_384
_MAPPING_PROXY_TYPE = type(MappingProxyType({}))
_SAFE_SOURCE_KINDS = frozenset({"FHIR_PRACTITIONER", "FHIR_PRACTITIONER_ROLE_LOCATION"})
_SAFE_DISCREPANCY_KINDS = frozenset({"SOURCE_CONFLICT_EVIDENCE"})
_PAGE_COLLECTIONS = frozenset({"sources", "findings", "discrepancies"})
MAX_PAGE_SIZE = 8
_READ_ONLY_STATUS = MappingProxyType({
    "absence_inference": "FORBIDDEN",
    "persisted": False,
    "actions_available": False,
    "financial_determination": False,
    "clearance_authority": False,
    "payment_authority": False,
    "economic_mutation": False,
    "production_usable": False,
    "activation": False,
    "synthetic_only": True,
    "proofSuiteId": None,
})


@dataclass(frozen=True)
class ProviderTrustGraphReadSelectionV1:
    """One explicit, caller-supplied artifact and its export-verification context."""

    graph_artifact: bytes
    profile_registry: Mapping[str, object]
    expected_profile_id: str
    expected_profile_version: int
    export_request_raw: bytes
    expected_operation_ref: str


def _fail(code: str) -> NoReturn:
    raise_redacted(ProviderTrustGraphReadModelV1Error, code)


def _canonical(value: object) -> bytes:
    try:
        raw = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (RecursionError, TypeError, ValueError, UnicodeEncodeError):
        _fail("read:v1:response-encoding")
    if len(raw) > MAX_RESPONSE_BYTES:
        _fail("read:v1:response-byte-cap")
    return raw


def _profile_registry(
    registry: Mapping[str, object],
    *,
    expected_profile_id: str,
) -> dict[str, object]:
    if type(registry) not in (dict, _MAPPING_PROXY_TYPE):
        _fail("read:v1:profile-registry")
    try:
        if len(registry) != 1:
            _fail("read:v1:profile-registry")
        copied = dict(registry)
    except ProviderTrustGraphReadModelV1Error:
        raise
    except Exception:
        _fail("read:v1:profile-registry")
    if set(copied) != {expected_profile_id}:
        _fail("read:v1:profile-registry")
    return copied


def _add_reference_role(
    references: dict[str, str],
    reference: object,
    role: str,
) -> None:
    if type(reference) is not str or not reference or reference in references:
        _fail("read:v1:reference-map")
    references[reference] = role


def _evidence_projection(
    value: object,
    references: Mapping[str, str],
    *,
    label: str,
) -> dict[str, object]:
    if type(value) is not list or len(value) > graph_independent.MAX_RECORDS_PER_SOURCE * graph_independent.MAX_SOURCES:
        _fail("read:v1:" + label + "-references")
    roles: set[str] = set()
    for reference in value:
        role = references.get(reference) if type(reference) is str else None
        if role is None:
            _fail("read:v1:" + label + "-reference-unmapped")
        roles.add(role)
    return {
        "evidence_reference_count": len(value),
        "evidence_source_roles": sorted(roles),
    }


def _project_graph(value: dict[str, object]) -> tuple[dict[str, object], int, int, int, int]:
    snapshot = value.get("observation_snapshot")
    sources = value.get("source_coverage")
    findings = value.get("findings")
    discrepancies = value.get("discrepancies")
    if (
        not isinstance(snapshot, dict)
        or type(sources) is not list
        or len(sources) > graph_independent.MAX_SOURCES
        or type(findings) is not list
        or len(findings) > graph_independent.MAX_FINDINGS
        or type(discrepancies) is not list
        or len(discrepancies) > graph_independent.MAX_DISCREPANCIES
    ):
        _fail("read:v1:graph-shape")
    observation_time = snapshot.get("observation_time")
    if type(observation_time) is not int or observation_time < 1:
        _fail("read:v1:graph-time")

    references: dict[str, str] = {}
    source_views: list[dict[str, object]] = []
    record_count = 0
    for source in sources:
        if not isinstance(source, dict):
            _fail("read:v1:source-shape")
        role = source.get("source_kind")
        if type(role) is not str or role not in _SAFE_SOURCE_KINDS:
            _fail("read:v1:source-role")
        source_id = source.get("source_id")
        records = source.get("records")
        if type(records) is not list or len(records) > graph_independent.MAX_RECORDS_PER_SOURCE:
            _fail("read:v1:source-records")
        _add_reference_role(references, source_id, role)
        for record in records:
            if not isinstance(record, dict):
                _fail("read:v1:record-shape")
            _add_reference_role(references, record.get("record_id"), role)
        record_count += len(records)
        coverage_observation_time = source.get("coverage_observation_time")
        effective_start = source.get("coverage_effective_start")
        effective_end = source.get("coverage_effective_end")
        if any(type(item) is not int for item in (coverage_observation_time, effective_start, effective_end)):
            _fail("read:v1:coverage-time")
        source_views.append(
            {
                "source_role": role,
                "graph_asserted_coverage": {
                    "observation_time": coverage_observation_time,
                    "effective_start": effective_start,
                    "effective_end": effective_end,
                },
                "observed_record_count": len(records),
                "freshness": "UNKNOWN",
                "completeness": "UNKNOWN",
                "provenance_basis": "SYNTHETIC_PROFILE_BOUND",
            }
        )

    projected_findings: list[dict[str, object]] = []
    for finding in findings:
        if not isinstance(finding, dict):
            _fail("read:v1:finding-shape")
        kind = finding.get("kind")
        if type(kind) is not str or kind not in graph_independent.FINDING_KINDS:
            _fail("read:v1:finding-kind")
        projected = {
            "graph_finding_kind": kind,
            **_evidence_projection(finding.get("evidence_refs"), references, label="finding"),
        }
        projected_findings.append(projected)
    projected_findings.sort(
        key=lambda item: (
            item["graph_finding_kind"],
            tuple(item["evidence_source_roles"]),
            item["evidence_reference_count"],
        )
    )

    projected_discrepancies: list[dict[str, object]] = []
    for discrepancy in discrepancies:
        if not isinstance(discrepancy, dict):
            _fail("read:v1:discrepancy-shape")
        kind = discrepancy.get("kind")
        boundary = discrepancy.get("responsibility_boundary")
        if type(kind) is not str or kind not in _SAFE_DISCREPANCY_KINDS or boundary != "UNKNOWN":
            _fail("read:v1:discrepancy-kind")
        projected = {
            "graph_discrepancy_kind": kind,
            "responsibility_boundary": "UNKNOWN",
            **_evidence_projection(discrepancy.get("evidence_refs"), references, label="discrepancy"),
        }
        projected_discrepancies.append(projected)
    projected_discrepancies.sort(
        key=lambda item: (
            item["graph_discrepancy_kind"],
            tuple(item["evidence_source_roles"]),
            item["evidence_reference_count"],
        )
    )
    source_views.sort(key=lambda item: item["source_role"])
    return (
        {
            "observation_time": observation_time,
            "sources": source_views,
            "findings": projected_findings,
            "discrepancies": projected_discrepancies,
        },
        len(sources),
        record_count,
        len(findings),
        len(discrepancies),
    )


def _build_read_model_value(
    graph_artifact: bytes,
    profile_registry: Mapping[str, object],
    *,
    expected_profile_id: str,
    expected_profile_version: int,
    export_request_raw: bytes,
    expected_operation_ref: str,
    now: int,
) -> tuple[dict[str, object], str]:
    """Verify one selection and return its safe projection plus private profile binding.

    The artifact and profile are independently verified on every call. The
    existing provider evidence export and its independent verifier are also
    run as a consistency gate; their outcome and completeness fields are not
    copied into this staff view. This function has no persistence or cache.
    """
    if (
        type(graph_artifact) is not bytes
        or not graph_artifact
        or len(graph_artifact) > graph_independent.MAX_ARTIFACT_BYTES
        or type(expected_profile_id) is not str
        or not expected_profile_id
        or type(expected_profile_version) is not int
        or expected_profile_version < 1
        or type(export_request_raw) is not bytes
        or not export_request_raw
        or len(export_request_raw) > evidence_export.MAX_REQUEST_BYTES
        or type(expected_operation_ref) is not str
        or len(expected_operation_ref) != 64
        or type(now) is not int
        or not 0 <= now <= evidence_export.MAX_TIME
    ):
        _fail("read:v1:input")
    try:
        profile_id_bytes = expected_profile_id.encode("utf-8")
    except UnicodeEncodeError:
        _fail("read:v1:input")
    if len(profile_id_bytes) > graph_independent.MAX_STRING_BYTES:
        _fail("read:v1:input")
    registry = _profile_registry(profile_registry, expected_profile_id=expected_profile_id)
    try:
        verified_graph = graph_independent.verify_artifact_v2(graph_artifact, registry)
    except Exception:
        _fail("read:v1:graph-reject")
    value = getattr(verified_graph, "value", None)
    profile = getattr(verified_graph, "profile", None)
    if (
        not isinstance(value, dict)
        or getattr(profile, "profile_id", None) != expected_profile_id
        or type(getattr(profile, "version", None)) is not int
        or profile.version != expected_profile_version
    ):
        _fail("read:v1:profile")

    selection = evidence_export.ProviderEvidenceSelectionV1(
        graph_artifact=graph_artifact,
        profile_registry=registry,
        authorization_evidence=evidence_export.SYNTHETIC_SELECTION_AUTHORIZATION,
    )
    try:
        export_raw = evidence_export.build_export(export_request_raw, selection, now=now)
        verified_export = evidence_export_independent.verify_export(
            export_raw,
            expected_operation_ref=expected_operation_ref,
            now=now,
        )
    except Exception:
        _fail("read:v1:export-reject")

    try:
        projected, source_count, record_count, finding_count, discrepancy_count = _project_graph(value)
    except ProviderTrustGraphReadModelV1Error:
        raise
    except Exception:
        _fail("read:v1:projection")
    if (
        verified_export.source_count != source_count
        or verified_export.record_count != record_count
        or verified_export.finding_count != finding_count
        or verified_export.discrepancy_count != discrepancy_count
        or verified_export.synthetic_only is not True
        or verified_export.production_usable is not False
        or verified_export.activation is not False
        or verified_export.clearance_authority is not False
        or verified_export.payment_authority is not False
        or verified_export.economic_mutation is not False
        or verified_export.proof_suite_id is not None
    ):
        _fail("read:v1:export-binding")

    response = {
        "domain": RESPONSE_DOMAIN,
        "schema": SCHEMA,
        "version": VERSION,
        "profile": {
            "profile_id": expected_profile_id,
            "version": expected_profile_version,
        },
        "observation": {
            "interpretation": "SYNTHETIC_GRAPH_OBSERVATION_ONLY",
            **projected,
        },
        "summary": {
            "source_count": source_count,
            "record_count": record_count,
            "finding_count": finding_count,
            "discrepancy_count": discrepancy_count,
            "count_semantics": "CURRENT_VERIFIED_PROJECTION_ONLY",
        },
        "status": {
            "artifact_validation": "SYNTHETIC_ARTIFACT_INTERNAL_CONSISTENCY",
            "caller_authorization": "UPSTREAM_REQUIRED",
            "source_truth": "NOT_ESTABLISHED",
            "freshness": "UNKNOWN",
            "completeness": "UNKNOWN",
            "artifact_durability": "CALLER_SUPPLIED_TRANSIENT",
            **_READ_ONLY_STATUS,
        },
    }
    profile_digest = getattr(profile, "profile_digest", None)
    if type(profile_digest) is not str or len(profile_digest) != 128:
        _fail("read:v1:profile")
    return response, profile_digest


def build_read_model_v1(
    graph_artifact: bytes,
    profile_registry: Mapping[str, object],
    *,
    expected_profile_id: str,
    expected_profile_version: int,
    export_request_raw: bytes,
    expected_operation_ref: str,
    now: int,
) -> bytes:
    """Return one bounded base view of a caller-supplied PTG artifact."""
    response, _profile_digest = _build_read_model_value(
        graph_artifact,
        profile_registry,
        expected_profile_id=expected_profile_id,
        expected_profile_version=expected_profile_version,
        export_request_raw=export_request_raw,
        expected_operation_ref=expected_operation_ref,
        now=now,
    )
    return _canonical(response)


def _build_selection_value(
    selection: ProviderTrustGraphReadSelectionV1,
    *,
    now: int,
) -> tuple[dict[str, object], str]:
    if not isinstance(selection, ProviderTrustGraphReadSelectionV1):
        _fail("read:v1:selection")
    return _build_read_model_value(
        selection.graph_artifact,
        selection.profile_registry,
        expected_profile_id=selection.expected_profile_id,
        expected_profile_version=selection.expected_profile_version,
        export_request_raw=selection.export_request_raw,
        expected_operation_ref=selection.expected_operation_ref,
        now=now,
    )


def _view_context(value: dict[str, object]) -> dict[str, object]:
    observation = value["observation"]
    status = value["status"]
    assert isinstance(observation, dict) and isinstance(status, dict)
    return {
        "profile": value["profile"],
        "observation_time": observation["observation_time"],
        "interpretation": observation["interpretation"],
        "source_truth": status["source_truth"],
        "freshness": status["freshness"],
        "completeness": status["completeness"],
        "artifact_durability": status["artifact_durability"],
        "caller_authorization": status["caller_authorization"],
        "provenance_basis": "SYNTHETIC_PROFILE_BOUND",
    }


def _comparison_side(value: dict[str, object], sources: list[dict[str, object]]) -> dict[str, object]:
    context = _view_context(value)
    context.pop("interpretation")
    context["source_provenance"] = sources
    return context


def _selection_view_base(value: dict[str, object], view: str) -> dict[str, object]:
    return {
        "domain": RESPONSE_DOMAIN,
        "schema": SCHEMA,
        "version": VERSION,
        "view": view,
        "context": _view_context(value),
        **_READ_ONLY_STATUS,
    }


def build_read_model_page_v1(
    selection: ProviderTrustGraphReadSelectionV1,
    *,
    collection: str,
    offset: int,
    page_size: int,
    now: int,
) -> bytes:
    """Return one bounded page from a verified source, finding, or discrepancy projection."""
    if (
        type(collection) is not str
        or collection not in _PAGE_COLLECTIONS
        or type(offset) is not int
        or offset < 0
        or type(page_size) is not int
        or not 1 <= page_size <= MAX_PAGE_SIZE
    ):
        _fail("read:v1:page-input")
    value, _profile_digest = _build_selection_value(selection, now=now)
    observation = value["observation"]
    assert isinstance(observation, dict)
    items = observation[collection]
    assert isinstance(items, list)
    if offset > len(items):
        _fail("read:v1:page-offset")
    stop = min(offset + page_size, len(items))
    next_offset = stop if stop < len(items) else None
    response = _selection_view_base(value, "PAGE")
    response["page"] = {
        "collection": collection,
        "offset": offset,
        "page_size": page_size,
        "projected_item_count": len(items),
        "items": items[offset:stop],
        "next_offset": next_offset,
        "count_semantics": "CURRENT_VERIFIED_PROJECTION_ONLY",
    }
    return _canonical(response)


def build_read_model_detail_v1(
    selection: ProviderTrustGraphReadSelectionV1,
    *,
    collection: str,
    index: int,
    now: int,
) -> bytes:
    """Return one ephemeral, identifier-free detail selected by page index."""
    if type(collection) is not str or collection not in _PAGE_COLLECTIONS or type(index) is not int or index < 0:
        _fail("read:v1:detail-input")
    value, _profile_digest = _build_selection_value(selection, now=now)
    observation = value["observation"]
    assert isinstance(observation, dict)
    items = observation[collection]
    assert isinstance(items, list)
    if index >= len(items):
        _fail("read:v1:detail-index")
    response = _selection_view_base(value, "DETAIL")
    response["detail"] = {
        "collection": collection,
        "projection_index": index,
        "stable_identity": False,
        "item": items[index],
    }
    return _canonical(response)


def _projection_counts(items: list[dict[str, object]], *, kind_key: str) -> Counter[tuple[str, tuple[str, ...], int]]:
    counts: Counter[tuple[str, tuple[str, ...], int]] = Counter()
    for item in items:
        kind = item.get(kind_key)
        roles = item.get("evidence_source_roles")
        references = item.get("evidence_reference_count")
        if type(kind) is not str or type(roles) is not list or any(type(role) is not str for role in roles) or type(references) is not int:
            _fail("read:v1:comparison-shape")
        counts[(kind, tuple(roles), references)] += 1
    return counts


def _projection_deltas(
    left_items: list[dict[str, object]],
    right_items: list[dict[str, object]],
    *,
    kind_key: str,
) -> list[dict[str, object]]:
    left_counts = _projection_counts(left_items, kind_key=kind_key)
    right_counts = _projection_counts(right_items, kind_key=kind_key)
    deltas: list[dict[str, object]] = []
    for key in sorted(set(left_counts) | set(right_counts)):
        left_count = left_counts[key]
        right_count = right_counts[key]
        if left_count != right_count:
            kind, roles, evidence_count = key
            deltas.append(
                {
                    "graph_kind": kind,
                    "evidence_source_roles": list(roles),
                    "evidence_reference_count": evidence_count,
                    "left_projection_count": left_count,
                    "right_projection_count": right_count,
                    "projection_count_delta": right_count - left_count,
                    "interpretation": "PROJECTION_COUNT_DIFFERENCE_ONLY",
                }
            )
    return deltas


def compare_read_models_v1(
    left: ProviderTrustGraphReadSelectionV1,
    right: ProviderTrustGraphReadSelectionV1,
    *,
    now: int,
) -> bytes:
    """Compare two separately supplied and independently verified synthetic observations."""
    left_value, left_profile_digest = _build_selection_value(left, now=now)
    right_value, right_profile_digest = _build_selection_value(right, now=now)
    if left_profile_digest != right_profile_digest or left_value["profile"] != right_value["profile"]:
        _fail("read:v1:comparison-profile")
    left_observation = left_value["observation"]
    right_observation = right_value["observation"]
    assert isinstance(left_observation, dict) and isinstance(right_observation, dict)
    left_sources = left_observation["sources"]
    right_sources = right_observation["sources"]
    left_findings = left_observation["findings"]
    right_findings = right_observation["findings"]
    left_discrepancies = left_observation["discrepancies"]
    right_discrepancies = right_observation["discrepancies"]
    assert all(isinstance(items, list) for items in (left_sources, right_sources, left_findings, right_findings, left_discrepancies, right_discrepancies))

    left_by_role = {item["source_role"]: item for item in left_sources if isinstance(item, dict)}
    right_by_role = {item["source_role"]: item for item in right_sources if isinstance(item, dict)}
    source_changes: list[dict[str, object]] = []
    for role in sorted(set(left_by_role) | set(right_by_role)):
        left_item = left_by_role.get(role)
        right_item = right_by_role.get(role)
        if left_item != right_item:
            changed_fields = sorted(
                field for field in (left_item or {}).keys() | (right_item or {}).keys()
                if left_item is None or right_item is None or left_item.get(field) != right_item.get(field)
            )
            source_changes.append(
                {
                    "source_role": role,
                    "left_projection": left_item,
                    "right_projection": right_item,
                    "changed_fields": changed_fields,
                    "interpretation": "GRAPH_PROJECTION_DIFFERENCE_ONLY",
                }
            )

    assert isinstance(left_value["profile"], dict) and isinstance(right_value["profile"], dict)
    return _canonical(
        {
            "domain": RESPONSE_DOMAIN,
            "schema": SCHEMA,
            "version": VERSION,
            "view": "COMPARE",
            "comparison": {
                "semantics": "EXPLICIT_VERIFIED_PROJECTION_DIFFERENCE",
                "missing_evidence_semantics": "UNKNOWN_NOT_ABSENT",
                "left": _comparison_side(left_value, left_sources),
                "right": _comparison_side(right_value, right_sources),
                "source_changes": source_changes,
                "finding_deltas": _projection_deltas(left_findings, right_findings, kind_key="graph_finding_kind"),
                "discrepancy_deltas": _projection_deltas(left_discrepancies, right_discrepancies, kind_key="graph_discrepancy_kind"),
            },
            "status": {
                "caller_authorization": "UPSTREAM_REQUIRED",
                "freshness": "UNKNOWN",
                "completeness": "UNKNOWN",
                "source_truth": "NOT_ESTABLISHED",
                "artifact_durability": "CALLER_SUPPLIED_TRANSIENT",
                **_READ_ONLY_STATUS,
            },
        }
    )


def _add_cli_selection_arguments(parser: argparse.ArgumentParser, *, prefix: str = "", required: bool = True) -> None:
    inputs = parser.add_mutually_exclusive_group(required=required)
    inputs.add_argument(f"--{prefix}artifact", help="local graph artifact path")
    inputs.add_argument(f"--{prefix}source-envelope", help="local synthetic NC FHIR capture path")
    parser.add_argument(f"--{prefix}capture-context", nargs=6, metavar=("SUBJECT", "CREDENTIAL", "ENROLLMENT", "LOCATOR", "OBSERVED", "FETCHED"), help="independently supplied expected capture context; required with source-envelope")
    parser.add_argument(f"--{prefix}request", required=required)
    parser.add_argument(f"--{prefix}operation-ref", required=required)


def load_selection(artifact_path: str, request_path: str, operation_ref: str, *, capture_context: nc_profile.DynamicCaptureContext | None = None) -> ProviderTrustGraphReadSelectionV1:
    """Load a bounded artifact, or admit an envelope against caller-owned context."""
    try:
        request = graph_producer._read_bounded(request_path, evidence_export.MAX_REQUEST_BYTES)
        profile = nc_profile.NC_MEDICAID_GRAPH_PROFILE
        if capture_context is None:
            artifact = graph_producer._read_bounded(artifact_path, graph_independent.MAX_ARTIFACT_BYTES)
        else:
            profile = nc_profile.NC_MEDICAID_PROFILE.graph_profile_for_context(capture_context)
            envelope = graph_producer._read_bounded(artifact_path, nc_profile.NC_MEDICAID_PROFILE.transport_caps["max_envelope_bytes"])
            verifier = NcMedicaidFhirVerifier(expected_context=capture_context)
            artifact = SourceAdmissionService(profile, verifier).admit(envelope).graph_artifact
    except Exception:
        _fail("read:v1:local-input")
    return ProviderTrustGraphReadSelectionV1(
        graph_artifact=artifact,
        profile_registry={profile.profile_id: profile},
        expected_profile_id=profile.profile_id,
        expected_profile_version=profile.version,
        export_request_raw=request,
        expected_operation_ref=operation_ref,
    )


def _cli_selection(args: argparse.Namespace, *, prefix: str = "") -> ProviderTrustGraphReadSelectionV1:
    source = getattr(args, f"{prefix}source_envelope")
    values = getattr(args, f"{prefix}capture_context")
    if (source is not None) != (values is not None):
        _fail("read:v1:local-input")
    try:
        context = nc_profile.DynamicCaptureContext(*values[:4], *map(int, values[4:])) if values is not None else None
    except Exception:
        _fail("read:v1:local-input")
    return load_selection(
        source if source is not None else getattr(args, f"{prefix}artifact"),
        getattr(args, f"{prefix}request"),
        getattr(args, f"{prefix}operation_ref"),
        capture_context=context,
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Serve bounded local page/detail/compare commands; no network or persistence is used."""
    parser = argparse.ArgumentParser(prog="python -m app.mirror.provider_trust_graph_read_model_v1")
    commands = parser.add_subparsers(dest="command", required=True)
    page = commands.add_parser("page")
    _add_cli_selection_arguments(page)
    page.add_argument("--now", type=int, required=True)
    page.add_argument("--collection", choices=sorted(_PAGE_COLLECTIONS), required=True)
    page.add_argument("--offset", type=int, default=0)
    page.add_argument("--page-size", type=int, default=MAX_PAGE_SIZE)
    detail = commands.add_parser("detail")
    _add_cli_selection_arguments(detail)
    detail.add_argument("--now", type=int, required=True)
    detail.add_argument("--collection", choices=sorted(_PAGE_COLLECTIONS), required=True)
    detail.add_argument("--index", type=int, required=True)
    compare = commands.add_parser("compare")
    _add_cli_selection_arguments(compare, prefix="left-")
    _add_cli_selection_arguments(compare, prefix="right-")
    compare.add_argument("--now", type=int, required=True)
    try:
        args = parser.parse_args(argv)
        if args.command == "page":
            output = build_read_model_page_v1(
                _cli_selection(args),
                collection=args.collection,
                offset=args.offset,
                page_size=args.page_size,
                now=args.now,
            )
        elif args.command == "detail":
            output = build_read_model_detail_v1(
                _cli_selection(args),
                collection=args.collection,
                index=args.index,
                now=args.now,
            )
        else:
            output = compare_read_models_v1(
                _cli_selection(args, prefix="left_"),
                _cli_selection(args, prefix="right_"),
                now=args.now,
            )
        sys.stdout.write(output.decode("ascii") + "\n")
        return 0
    except Exception:
        sys.stderr.write("REJECT read-model\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
