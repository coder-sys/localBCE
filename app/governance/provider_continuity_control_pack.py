"""Synthetic Provider Continuity Control Pack V1 producer.

This module is a small, observation-only governance seam.  It consumes one
complete Provider Trust Graph artifact as candidate evidence and produces an
immutable CANDIDATE -> TESTED -> APPROVED_OBSERVATION_ONLY chain.  The
approval is a synthetic KAT record, not a production signature and not an
automatic enforcement decision.
"""

from __future__ import annotations

from copy import deepcopy
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Mapping, Sequence

try:
    import resource
except ImportError:  # pragma: no cover - Windows has no resource module.
    resource = None  # type: ignore[assignment]

from app.mirror import provider_trust_graph_independent as mirror_independent


class ControlPackError(ValueError):
    """Raised for malformed, substituted, or semantically invalid evidence."""


SCHEMA = "provider-continuity-control-pack-v1"
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

OBSERVATION_TIME = 7_000
EFFECTIVE_START = 6_000
EFFECTIVE_END = 9_000
CANDIDATE_TIME = 7_100
TESTED_TIME = 7_200
APPROVAL_TIME = 7_300

ORIGIN_MIRROR = "MIRROR_PROVIDER_TRUST_GRAPH_V1"
ORIGIN_BEHAVIORAL_TWIN = "BEHAVIORAL_TWIN_V1"
ORIGINS = (ORIGIN_MIRROR, ORIGIN_BEHAVIORAL_TWIN)

STAGE_CANDIDATE = "CANDIDATE"
STAGE_TESTED = "TESTED"
STAGE_APPROVED = "APPROVED_OBSERVATION_ONLY"
STAGE_KINDS = (STAGE_CANDIDATE, STAGE_TESTED, STAGE_APPROVED)
STAGE_SENTINEL = "NONE"

EVIDENCE_CONTINUITY = "CONTINUITY_CONFIRMED"
EVIDENCE_EXPIRED = "CREDENTIAL_EXPIRED"
EVIDENCE_TERMINATED = "ENROLLMENT_TERMINATED"
EVIDENCE_INCOMPLETE = "EVIDENCE_INCOMPLETE"
EVIDENCE_ABSENT = "AUTHORITATIVE_RECORD_ABSENT"
EVIDENCE_CONFLICT = "SOURCE_CONFLICT"
EVIDENCE_STALE = "COVERAGE_STALE"
EVIDENCE_LABELS = (
    EVIDENCE_CONTINUITY,
    EVIDENCE_EXPIRED,
    EVIDENCE_TERMINATED,
    EVIDENCE_INCOMPLETE,
    EVIDENCE_ABSENT,
    EVIDENCE_CONFLICT,
    EVIDENCE_STALE,
)

APPROVAL_AUTHORITY_ID = "SYNTH_STATE_APPROVAL_AUTHORITY_001"
APPROVER_ID = "SYNTH_STATE_APPROVER_001"
APPROVER_ROLE = "OBSERVATION_CONTROL_PACK_APPROVER"
APPROVAL_REASON = "SYNTHETIC_OBSERVATION_ONLY_KAT_APPROVAL_V1"
SUPERSESSION_SENTINEL = "NO_SUPERSESSION_V1"
APPROVAL_SCHEMA = "provider-continuity-state-approval-v1"
APPROVAL_KEYS = {
    "schema",
    "approval_id",
    "approval_authority_id",
    "approver_id",
    "approver_role",
    "approval_reason",
    "approval_time",
    "provider_graph_subject",
    "scope",
    "effective_start",
    "effective_end",
    "tested_stage_id",
    "tested_stage_root",
    "source_contract_root",
    "suite_root",
    "supersession",
    "synthetic_kat_seal",
}
APPROVAL_CORE_KEYS = APPROVAL_KEYS - {"approval_id", "synthetic_kat_seal"}
APPROVAL_SUPERSESSION_KEYS = {"prior_approval_id", "supersession_sentinel"}
MAX_APPROVAL_BYTES = 16_384

MAX_INPUT_BYTES = 262_144
MAX_ARTIFACT_BYTES = 524_288
MAX_STRING_BYTES = 256
MAX_NODES = 8_192
MAX_DEPTH = 16
MAX_SOURCES = 2
MAX_RECORDS_PER_SOURCE = 8
MAX_STAGES = 3
MAX_CONFORMANCE_VECTORS = 4
MAX_TIMESTAMP = 2_147_483_647

FORBIDDEN_EXTERNAL_TOKENS = (
    "policyResult",
    "policy_result",
    "effectiveDirective",
    "effective_directive",
    "ClearanceDecisionRow",
    "StateAccessRow",
    "CLEAR",
    "HOLD",
    "HUMAN_REVIEW",
    "BLOCK",
    "EXCEPTION_APPROVED",
    "payment_directive",
    "payment_authorization",
)

_HEX = re.compile(r"^[0-9a-f]{128}$")


def _canonical(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise ControlPackError("json:noncanonical-value") from exc
    return rendered.encode("ascii")


def canonical_bytes(value: Mapping[str, object]) -> bytes:
    """Encode a caller-built object; strict validation occurs at each builder."""

    if not isinstance(value, dict):
        raise ControlPackError("json:top-level")
    _walk(value)
    _reject_forbidden(value)
    raw = _canonical(value)
    if len(raw) > MAX_INPUT_BYTES:
        raise ControlPackError("json:byte-cap")
    return raw


def _duplicate_reject(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ControlPackError("json:duplicate-key")
        result[key] = value
    return result


def _walk(value: object, depth: int = 0, count: list[int] | None = None) -> None:
    if count is None:
        count = [0]
    count[0] += 1
    if count[0] > MAX_NODES:
        raise ControlPackError("json:node-cap")
    if depth > MAX_DEPTH:
        raise ControlPackError("json:depth-cap")
    if isinstance(value, float):
        raise ControlPackError("json:float-forbidden")
    if isinstance(value, str):
        try:
            raw = value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ControlPackError("json:non-ascii") from exc
        if len(raw) > MAX_STRING_BYTES:
            raise ControlPackError("json:string-cap")
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ControlPackError("json:key-type")
            _walk(key, depth + 1, count)
            _walk(item, depth + 1, count)
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth + 1, count)


def _reject_forbidden(value: object) -> None:
    if isinstance(value, str):
        if any(token in value for token in FORBIDDEN_EXTERNAL_TOKENS):
            raise ControlPackError("payload:forbidden-token")
    elif isinstance(value, dict):
        for key, item in value.items():
            if any(token in key for token in FORBIDDEN_EXTERNAL_TOKENS):
                raise ControlPackError("payload:forbidden-token")
            _reject_forbidden(item)
    elif isinstance(value, list):
        for item in value:
            _reject_forbidden(item)


def parse_canonical(raw: bytes, *, artifact: bool = True) -> dict[str, object]:
    cap = MAX_ARTIFACT_BYTES if artifact else MAX_INPUT_BYTES
    if type(raw) is not bytes or not raw:
        raise ControlPackError("json:empty-or-type")
    if len(raw) > cap:
        raise ControlPackError("json:byte-cap")
    if any(byte > 0x7F for byte in raw):
        raise ControlPackError("json:ascii")
    try:
        text = raw.decode("ascii")
        value = json.loads(
            text,
            object_pairs_hook=_duplicate_reject,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ControlPackError("json:constant-forbidden")
            ),
        )
    except ControlPackError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ControlPackError("json:parse") from exc
    if not isinstance(value, dict):
        raise ControlPackError("json:top-level")
    _walk(value)
    _reject_forbidden(value)
    if _canonical(value) != raw:
        raise ControlPackError("json:not-canonical")
    return value


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update(("BL/GOVERNANCE/PROVIDER-CONTINUITY-CONTROL-PACK/" + label + "/v1\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _expect_keys(value: object, expected: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ControlPackError(f"{label}:schema")
    return value


def _text(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise ControlPackError(f"{label}:text")
    try:
        raw = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ControlPackError(f"{label}:ascii") from exc
    if len(raw) > MAX_STRING_BYTES:
        raise ControlPackError(f"{label}:length")
    return value


def _int(value: object, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= MAX_TIMESTAMP:
        raise ControlPackError(f"{label}:integer-or-range")
    return value


def _bool(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise ControlPackError(f"{label}:boolean")
    return value


def _hex(value: object, label: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if type(value) is not str or _HEX.fullmatch(value) is None:
        raise ControlPackError(f"{label}:hex")
    return value


def _sorted_unique(value: object, label: str, *, maximum: int) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ControlPackError(f"{label}:list-cap")
    result = [_text(item, label) for item in value]
    if result != sorted(result) or len(set(result)) != len(result):
        raise ControlPackError(f"{label}:order-or-duplicate")
    return result


def _fixed_contracts() -> tuple[dict[str, object], dict[str, object]]:
    bodies = (
        {
            "source_authority_id": "SYNTH_AUTHORITY_CREDENTIAL_001",
            "source_id": SOURCE_CREDENTIAL_ID,
            "source_kind": SOURCE_CREDENTIAL_KIND,
            "authority_role": "CREDENTIAL_REGISTRY_AUTHORITY",
            "record_kind": "CREDENTIAL",
            "provider_graph_subject": PROVIDER_GRAPH_SUBJECT,
            "credential_id": CREDENTIAL_ID,
            "enrollment_id": ENROLLMENT_ID,
            "scope": SCOPE,
            "schema_id": "SYNTH_PROVIDER_CREDENTIAL_SCHEMA_V1",
            "schema_version": 1,
            "expected_observation_time": OBSERVATION_TIME,
            "observation_rule": "OBSERVED_AT_EQUALS_SNAPSHOT_TIME_V1",
            "validity_rule": "ISSUED_LE_OBS_LT_VALID_UNTIL_NO_TERMINATION_V1",
            "provenance_id": "SYNTH_PROVENANCE_CREDENTIAL_001",
            "provenance_method": "SYNTH_PROVENANCE_ID_V1",
            "integrity_method": "SHA3_512_SOURCE_INTEGRITY_V1",
            "population_authority_id": "SYNTH_AUTHORITY_CREDENTIAL_001",
            "completeness_authority_id": "SYNTH_AUTHORITY_CREDENTIAL_001",
            "allowed_nonmembership_type": "SUBJECT_NONMEMBERSHIP_V1",
            "effective_start": EFFECTIVE_START,
            "effective_end": EFFECTIVE_END,
            "supersession_sentinel": SUPERSESSION_SENTINEL,
            "history_policy": "SINGLE_SNAPSHOT_NO_HISTORY_V1",
        },
        {
            "source_authority_id": "SYNTH_AUTHORITY_ENROLLMENT_001",
            "source_id": SOURCE_ENROLLMENT_ID,
            "source_kind": SOURCE_ENROLLMENT_KIND,
            "authority_role": "ENROLLMENT_REGISTRY_AUTHORITY",
            "record_kind": "ENROLLMENT",
            "provider_graph_subject": PROVIDER_GRAPH_SUBJECT,
            "credential_id": CREDENTIAL_ID,
            "enrollment_id": ENROLLMENT_ID,
            "scope": SCOPE,
            "schema_id": "SYNTH_PROVIDER_ENROLLMENT_SCHEMA_V1",
            "schema_version": 1,
            "expected_observation_time": OBSERVATION_TIME,
            "observation_rule": "OBSERVED_AT_EQUALS_SNAPSHOT_TIME_V1",
            "validity_rule": "ISSUED_LE_OBS_LT_VALID_UNTIL_OR_TERMINATED_V1",
            "provenance_id": "SYNTH_PROVENANCE_ENROLLMENT_001",
            "provenance_method": "SYNTH_PROVENANCE_ID_V1",
            "integrity_method": "SHA3_512_SOURCE_INTEGRITY_V1",
            "population_authority_id": "SYNTH_AUTHORITY_ENROLLMENT_001",
            "completeness_authority_id": "SYNTH_AUTHORITY_ENROLLMENT_001",
            "allowed_nonmembership_type": "SUBJECT_NONMEMBERSHIP_V1",
            "effective_start": EFFECTIVE_START,
            "effective_end": EFFECTIVE_END,
            "supersession_sentinel": SUPERSESSION_SENTINEL,
            "history_policy": "SINGLE_SNAPSHOT_NO_HISTORY_V1",
        },
    )
    result: list[dict[str, object]] = []
    for body in bodies:
        result.append({"contract_id": _digest("source-contract-id", body), **body})
    return result[0], result[1]


SOURCE_CONTRACTS = _fixed_contracts()
SOURCE_CONTRACT_KEYS = set(SOURCE_CONTRACTS[0])
SOURCE_CONTRACT_ROOT = _digest("source-contract-root", {"contracts": list(SOURCE_CONTRACTS)})

SUBJECT = {"provider_graph_subject": PROVIDER_GRAPH_SUBJECT, "scope": SCOPE}
AUTHORITY_FLAGS = {
    "automaticControlSetId": None,
    "automatic_enforcement_eligible": False,
    "clearance_authority": False,
    "payment_authority": False,
    "economic_mutation": False,
    "production_usable": False,
    "synthetic_only": True,
    "production_source_authentication": False,
    "proofSuiteId": None,
}
MODULE_IDENTITY_DOMAIN = "BL/GOVERNANCE/PROVIDER-CONTINUITY-CONTROL-PACK/MODULE-SHA3-512/v1\0"


def _module_identity(path: Path) -> str:
    digest = hashlib.sha3_512()
    digest.update(MODULE_IDENTITY_DOMAIN.encode("ascii"))
    digest.update(path.name.encode("ascii"))
    digest.update(b"\0")
    digest.update(path.read_bytes())
    return digest.hexdigest()


PRODUCER_MODULE_IDENTITY = _module_identity(Path(__file__))
INDEPENDENT_VERIFIER_MODULE_IDENTITY = _module_identity(Path(__file__).with_name("provider_continuity_control_pack_independent.py"))
AUTHORITY_PROFILE_ROOT = _digest("authority-profile-root", AUTHORITY_FLAGS)

CONFORMANCE_SUITE_ID = "SYNTH_PROVIDER_CONTINUITY_CONFORMANCE_SUITE_V1"
CONFORMANCE_DEFINITIONS = (
    {
        "vector_id": "SOURCE_CONTRACTS_EXACT",
        "predicate_id": "FIXED_SOURCE_CONTRACT_BINDING_V1",
        "expected_outcome": "PASS",
    },
    {
        "vector_id": "GRAPH_ARTIFACT_INDEPENDENT",
        "predicate_id": "FULL_GRAPH_RECOMPUTATION_V1",
        "expected_outcome": "PASS",
    },
    {
        "vector_id": "EVIDENCE_LABEL_ALLOWED",
        "predicate_id": "EVIDENCE_QUALIFICATION_RECOMPUTE_V1",
        "expected_outcome": "PASS",
    },
    {
        "vector_id": "OBSERVATION_ONLY_FLAGS",
        "predicate_id": "AUTHORITY_PROFILE_EXACT_V1",
        "expected_outcome": "PASS",
    },
)
CONFORMANCE_DEFINITIONS = tuple(deepcopy(CONFORMANCE_DEFINITIONS))


def _contract_root(contracts: Sequence[Mapping[str, object]]) -> str:
    return _digest("source-contract-root", {"contracts": list(contracts)})


def _validate_contracts(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) != MAX_SOURCES:
        raise ControlPackError("source-contracts:exact-count")
    for contract in value:
        _expect_keys(contract, SOURCE_CONTRACT_KEYS, "source-contract")
    if value != [dict(item) for item in SOURCE_CONTRACTS]:
        raise ControlPackError("source-contracts:fixed-identity")
    if _contract_root(value) != SOURCE_CONTRACT_ROOT:
        raise ControlPackError("source-contracts:root")
    return value


def _graph_object(graph_raw: bytes) -> dict[str, object]:
    if type(graph_raw) is not bytes or not graph_raw or len(graph_raw) > MAX_INPUT_BYTES:
        raise ControlPackError("graph:input-byte-cap")
    try:
        mirror_independent.verify_bytes(graph_raw)
    except Exception as exc:  # Keep the producer boundary independent and fail closed.
        raise ControlPackError(str(exc)) from exc
    try:
        value = json.loads(graph_raw.decode("ascii"), object_pairs_hook=_duplicate_reject)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ControlPackError("graph:parse") from exc
    if not isinstance(value, dict):
        raise ControlPackError("graph:top-level")
    return value


def _validate_graph_evidence(graph_raw: bytes) -> dict[str, object]:
    graph = _graph_object(graph_raw)
    subject = _expect_keys(graph["subject"], {"provider_graph_subject", "scope"}, "graph:subject")
    if subject != SUBJECT:
        raise ControlPackError("graph:subject-identity")
    snapshot = _expect_keys(graph["observation_snapshot"], {"snapshot_id", "snapshot_root", "observation_time"}, "graph:snapshot")
    observation_time = _int(snapshot["observation_time"], "graph:observation-time", minimum=1)
    if observation_time != OBSERVATION_TIME:
        raise ControlPackError("source:observation-time")
    _text(snapshot["snapshot_id"], "graph:snapshot-id")
    _hex(snapshot["snapshot_root"], "graph:snapshot-root")
    sources_value = graph["source_coverage"]
    if not isinstance(sources_value, list) or len(sources_value) != MAX_SOURCES:
        raise ControlPackError("source-coverage:exact-count")
    source_ids = [source.get("source_id") for source in sources_value if isinstance(source, dict)]
    if source_ids != list(SOURCE_IDS):
        raise ControlPackError("source-coverage:order-or-identity")
    contracts = {contract["source_id"]: contract for contract in SOURCE_CONTRACTS}
    any_incomplete = False
    all_empty = True
    any_conflict = False
    all_nonmembership = True
    record_values: list[dict[str, object]] = []
    for source_value in sources_value:
        source = _expect_keys(
            source_value,
            {
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
                "source_root",
            },
            "source-coverage",
        )
        source_id = _text(source["source_id"], "source:id")
        contract = contracts.get(source_id)
        if contract is None:
            raise ControlPackError("source:identity")
        if source["source_kind"] != contract["source_kind"] or source["coverage_scope"] != SCOPE:
            raise ControlPackError("source:kind-or-scope")
        if source["coverage_observation_time"] != OBSERVATION_TIME:
            raise ControlPackError("source:coverage-observation")
        if (source["coverage_effective_start"], source["coverage_effective_end"]) != (EFFECTIVE_START, EFFECTIVE_END):
            raise ControlPackError("source:effective-interval")
        if source["coverage_authority_id"] != contract["completeness_authority_id"]:
            raise ControlPackError("source:authority")
        complete = _bool(source["coverage_complete"], "source:complete")
        any_incomplete = any_incomplete or not complete
        nonmembership = _sorted_unique(source["nonmembership_keys"], "source:nonmembership", maximum=1)
        if any(key != SUBJECT_KEY for key in nonmembership):
            raise ControlPackError("source:nonmembership-identity")
        provenance = _expect_keys(source["provenance"], {"provenance_id", "integrity_digest"}, "source:provenance")
        if provenance["provenance_id"] != contract["provenance_id"]:
            raise ControlPackError("source:provenance")
        _hex(provenance["integrity_digest"], "source:integrity")
        _hex(source["source_root"], "source:root")
        records = source["records"]
        if not isinstance(records, list) or len(records) > MAX_RECORDS_PER_SOURCE:
            raise ControlPackError("source:record-cap")
        if records:
            all_empty = False
            all_nonmembership = False
        if len(records) > 1:
            any_conflict = True
        for record_value in records:
            record = _expect_keys(
                record_value,
                {
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
                },
                "source:record",
            )
            if (
                record["record_kind"] != contract["record_kind"]
                or record["provider_id"] != PROVIDER_GRAPH_SUBJECT
                or record["credential_id"] != CREDENTIAL_ID
                or record["enrollment_id"] != ENROLLMENT_ID
                or record["subject_key"] != SUBJECT_KEY
                or record["observed_at"] != OBSERVATION_TIME
            ):
                raise ControlPackError("source:record-identity-or-time")
            issued = _int(record["issued_at"], "record:issued", minimum=1)
            valid_from = _int(record["valid_from"], "record:valid-from", minimum=1)
            valid_until = _int(record["valid_until"], "record:valid-until", minimum=1)
            terminated = _int(record["terminated_at"], "record:terminated")
            if issued != valid_from or valid_until <= issued:
                raise ControlPackError("record:interval")
            status = _text(record["status"], "record:status")
            if contract["record_kind"] == "CREDENTIAL":
                expected_status = "ACTIVE" if observation_time < valid_until else "EXPIRED"
                if terminated != 0 or status != expected_status:
                    raise ControlPackError("record:credential-status")
            else:
                if terminated:
                    if not issued <= terminated <= observation_time or status != "TERMINATED":
                        raise ControlPackError("record:enrollment-termination")
                elif status != "ACTIVE" or observation_time >= valid_until:
                    raise ControlPackError("record:enrollment-status")
            if SUBJECT_KEY in nonmembership:
                raise ControlPackError("completeness:fact-nonmembership-conflict")
            record_values.append(record)
        if complete and not records and nonmembership != [SUBJECT_KEY]:
            raise ControlPackError("source:absence-nonmembership")
        if complete and records and nonmembership:
            raise ControlPackError("completeness:fact-nonmembership-conflict")
    if any_incomplete:
        expected_label = EVIDENCE_INCOMPLETE
    elif all_empty and all_nonmembership:
        expected_label = EVIDENCE_ABSENT
    elif any_conflict:
        expected_label = EVIDENCE_CONFLICT
    else:
        credential = next((item for item in record_values if item["record_kind"] == "CREDENTIAL"), None)
        enrollment = next((item for item in record_values if item["record_kind"] == "ENROLLMENT"), None)
        if credential is not None and credential["status"] == "EXPIRED":
            expected_label = EVIDENCE_EXPIRED
        elif enrollment is not None and enrollment["status"] == "TERMINATED":
            expected_label = EVIDENCE_TERMINATED
        else:
            expected_label = EVIDENCE_CONTINUITY
    findings = graph["findings"]
    if not isinstance(findings, list) or len(findings) != 1:
        raise ControlPackError("graph:finding-count")
    finding = _expect_keys(
        findings[0],
        {"finding_id", "kind", "lifecycle", "subject_key", "observation_snapshot_id", "evidence_refs"},
        "graph:finding",
    )
    if finding["kind"] != expected_label or finding["subject_key"] != SUBJECT_KEY or finding["observation_snapshot_id"] != snapshot["snapshot_id"]:
        raise ControlPackError("graph:evidence-label")
    _hex(finding["finding_id"], "graph:finding-id")
    _sorted_unique(finding["evidence_refs"], "graph:finding-refs", maximum=MAX_RECORDS_PER_SOURCE * MAX_SOURCES)
    report = _expect_keys(graph["report"], {"report_id", "identity_material", "lifecycle"}, "graph:report")
    _hex(report["report_id"], "graph:report-id")
    return {
        "graph": graph,
        "report_id": report["report_id"],
        "snapshot_id": snapshot["snapshot_id"],
        "snapshot_root": snapshot["snapshot_root"],
        "finding_id": finding["finding_id"],
        "evidence_label": expected_label,
    }


def _candidate_root(origin: str, material: Mapping[str, object]) -> str:
    return _digest(
        "candidate-root",
        {"source_contract_root": SOURCE_CONTRACT_ROOT, "subject": SUBJECT, "origin": origin, "material": dict(material)},
    )


def _stage_with_ids(body: Mapping[str, object]) -> dict[str, object]:
    body_copy = deepcopy(dict(body))
    stage_root = _digest("stage-root", body_copy)
    stage_id = _digest("stage-id", {"stage_kind": body_copy["stage_kind"], "stage_root": stage_root})
    return {"stage_id": stage_id, "stage_root": stage_root, **body_copy}


def _artifact(stages: Sequence[Mapping[str, object]]) -> dict[str, object]:
    stages_copy = deepcopy(list(stages))
    current = stages_copy[-1]
    body: dict[str, object] = {
        "schema": SCHEMA,
        "subject": deepcopy(SUBJECT),
        "source_contracts": deepcopy(list(SOURCE_CONTRACTS)),
        "stages": stages_copy,
        "current_stage_kind": current["stage_kind"],
        "current_stage_id": current["stage_id"],
        "chain_root": _digest("chain-root", {"stages": stages_copy}),
        **deepcopy(AUTHORITY_FLAGS),
    }
    return {"artifact_id": _digest("artifact-id", body), **body}


def _encode_artifact(value: Mapping[str, object]) -> bytes:
    raw = _canonical(value)
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise ControlPackError("artifact:byte-cap")
    _walk(value)
    _reject_forbidden(value)
    return raw


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
            old_argtypes = getattr(get_memory, "argtypes", None)
            old_restype = getattr(get_memory, "restype", None)
            try:
                get_memory.argtypes = [ctypes.c_void_p, ctypes.POINTER(Counters), ctypes.c_ulong]
                get_memory.restype = ctypes.c_int
                if not get_memory(process, ctypes.byref(counters), counters.cb):
                    return None
                return int(counters.peak_working_set_size)
            finally:
                get_memory.argtypes = old_argtypes
                get_memory.restype = old_restype
        except (AttributeError, OSError):
            return None
    try:
        if resource is None:
            return None
        usage = resource.getrusage(resource.RUSAGE_SELF)
        return int(usage.ru_maxrss * (1 if sys.platform == "darwin" else 1024))
    except (AttributeError, OSError):
        return None


def _telemetry(start: int, raw: bytes) -> dict[str, object]:
    return {
        "artifact_bytes": len(raw),
        "wall_time_ns": time.perf_counter_ns() - start,
        "process_tree_peak_bytes": _process_peak_bytes(),
        "process_tree_scope": "single-process; no child processes",
        "children_launched": 0,
        "governance_performance_claim": False,
        "proof_performance_claim": False,
    }


def build_candidate(graph_raw: bytes, *, origin: str = ORIGIN_MIRROR) -> tuple[bytes, dict[str, object]]:
    """Bind one independently verified graph artifact as a candidate."""

    start = time.perf_counter_ns()
    if origin not in ORIGINS:
        raise ControlPackError("candidate:origin")
    evidence = _validate_graph_evidence(graph_raw)
    material = {
        "graph_artifact": deepcopy(evidence["graph"]),
        "graph_report_id": evidence["report_id"],
        "graph_snapshot_id": evidence["snapshot_id"],
        "graph_snapshot_root": evidence["snapshot_root"],
        "evidence_qualification": evidence["evidence_label"],
    }
    body = {
        "stage_kind": STAGE_CANDIDATE,
        "prior_stage_id": STAGE_SENTINEL,
        "prior_stage_root": None,
        "stage_time": CANDIDATE_TIME,
        "provider_graph_subject": PROVIDER_GRAPH_SUBJECT,
        "scope": SCOPE,
        "effective_start": EFFECTIVE_START,
        "effective_end": EFFECTIVE_END,
        "origin": origin,
        "status": STAGE_CANDIDATE,
        "source_contract_root": SOURCE_CONTRACT_ROOT,
        "candidate_root": _candidate_root(origin, material),
        "suite_root": None,
        "approval_root": None,
        "material": material,
    }
    stage = _stage_with_ids(body)
    raw = _encode_artifact(_artifact([stage]))
    try:
        from app.governance import provider_continuity_control_pack_independent as independent

        independent.verify_bytes(raw)
    except Exception as exc:
        raise ControlPackError(str(exc)) from exc
    return raw, _telemetry(start, raw)


def build_demo_candidate(case: str = "confirmed", *, origin: str = ORIGIN_MIRROR) -> tuple[bytes, dict[str, object]]:
    """Build a candidate from an existing synthetic graph demo only."""

    from app.mirror import provider_trust_graph as graph_producer

    memory_api = None
    old_argtypes = None
    old_restype = None
    if os.name == "nt":
        try:
            memory_api = ctypes.windll.psapi.GetProcessMemoryInfo
            old_argtypes = getattr(memory_api, "argtypes", None)
            old_restype = getattr(memory_api, "restype", None)
        except (AttributeError, OSError):
            memory_api = None
    try:
        graph_raw, _ = graph_producer.build_demo_report(case)
    finally:
        if memory_api is not None:
            memory_api.argtypes = old_argtypes
            memory_api.restype = old_restype
    return build_candidate(graph_raw, origin=origin)


def _load_verified(raw: bytes, expected_stage: str) -> tuple[dict[str, object], dict[str, object]]:
    try:
        from app.governance import provider_continuity_control_pack_independent as independent

        result = independent.verify_bytes(raw)
    except Exception as exc:
        raise ControlPackError(str(exc)) from exc
    value = parse_canonical(raw, artifact=True)
    if value["current_stage_kind"] != expected_stage:
        raise ControlPackError(f"promotion:expected-{expected_stage.lower()}")
    return value, result


def _conformance(candidate: Mapping[str, object], artifact: Mapping[str, object]) -> dict[str, object]:
    material = _expect_keys(candidate["material"], {"graph_artifact", "graph_report_id", "graph_snapshot_id", "graph_snapshot_root", "evidence_qualification"}, "candidate:material")
    label = _text(material["evidence_qualification"], "candidate:evidence")
    if label not in EVIDENCE_LABELS:
        raise ControlPackError("candidate:evidence")
    contracts = _validate_contracts(artifact["source_contracts"])
    graph = material["graph_artifact"]
    graph_raw = _canonical(graph)
    graph_result = mirror_independent.verify_bytes(graph_raw)
    graph_value = _expect_keys(graph, {"schema", "subject", "observation_snapshot", "source_coverage", "findings", "discrepancies", "remediation", "parity_cases", "transition", "report", "authority"}, "conformance:graph")
    snapshot = _expect_keys(graph_value["observation_snapshot"], {"snapshot_id", "snapshot_root", "observation_time"}, "conformance:snapshot")
    report = _expect_keys(graph_value["report"], {"report_id", "identity_material", "lifecycle"}, "conformance:report")
    evidence = _validate_graph_evidence(graph_raw)
    observed_contracts = artifact["source_contracts"]
    source_result = {
        "source_contract_root": candidate["source_contract_root"],
        "contract_ids": [contract["contract_id"] for contract in observed_contracts] if isinstance(observed_contracts, list) else [],
        "contract_count": len(observed_contracts) if isinstance(observed_contracts, list) else -1,
    }
    graph_result_output = {
        "graph_report_id": report["report_id"],
        "graph_snapshot_id": snapshot["snapshot_id"],
        "graph_snapshot_root": snapshot["snapshot_root"],
    }
    evidence_result = {
        "evidence_qualification": evidence["evidence_label"],
        "finding_id": evidence["finding_id"],
    }
    observed_flags = {key: artifact.get(key) for key in AUTHORITY_FLAGS}
    authority_result = {"authority_profile_root": _digest("authority-profile-root", observed_flags)}
    predicate_values = (
        (source_result, observed_contracts == [dict(item) for item in contracts] and candidate["source_contract_root"] == SOURCE_CONTRACT_ROOT),
        (graph_result_output, bool(graph_result.get("accepted")) and graph_result.get("report_id") == report["report_id"] and material["graph_report_id"] == report["report_id"] and material["graph_snapshot_id"] == snapshot["snapshot_id"] and material["graph_snapshot_root"] == snapshot["snapshot_root"]),
        (evidence_result, evidence["evidence_label"] in EVIDENCE_LABELS and evidence["evidence_label"] == label),
        (authority_result, observed_flags == AUTHORITY_FLAGS),
    )
    results = []
    for definition, (decisive_output, passed) in zip(CONFORMANCE_DEFINITIONS, predicate_values, strict=True):
        results.append(
            {
                "vector_id": definition["vector_id"],
                "predicate_id": definition["predicate_id"],
                "expected_outcome": definition["expected_outcome"],
                "observed_outcome": "PASS" if passed else "FAIL",
                "passed": passed,
                "decisive_output": decisive_output,
            }
        )
    conformance = {
        "schema": SCHEMA,
        "suite_id": CONFORMANCE_SUITE_ID,
        "suite_version": 1,
        "producer_module_identity": _module_identity(Path(__file__)),
        "independent_verifier_module_identity": _module_identity(Path(__file__).with_name("provider_continuity_control_pack_independent.py")),
        "source_contract_root": SOURCE_CONTRACT_ROOT,
        "candidate_root": candidate["candidate_root"],
        "authority_profile": deepcopy(AUTHORITY_FLAGS),
        "authority_profile_root": AUTHORITY_PROFILE_ROOT,
        "definitions": deepcopy(list(CONFORMANCE_DEFINITIONS)),
    }
    conformance["suite_root"] = _digest("suite-root", conformance)
    conformance["results"] = results
    if not all(result["passed"] for result in results):
        failed = next(result["vector_id"] for result in results if not result["passed"])
        raise ControlPackError(f"conformance:failed:{failed}")
    return conformance


def build_tested(candidate_raw: bytes) -> tuple[bytes, dict[str, object]]:
    """Run the fixed conformance suite; no caller result or status is accepted."""

    start = time.perf_counter_ns()
    value, _ = _load_verified(candidate_raw, STAGE_CANDIDATE)
    candidate = value["stages"][0]
    assert isinstance(candidate, dict)
    if candidate["origin"] == ORIGIN_BEHAVIORAL_TWIN:
        raise ControlPackError("origin:behavioral-twin-candidate-only")
    conformance = _conformance(candidate, value)
    body = {
        "stage_kind": STAGE_TESTED,
        "prior_stage_id": candidate["stage_id"],
        "prior_stage_root": candidate["stage_root"],
        "stage_time": TESTED_TIME,
        "provider_graph_subject": PROVIDER_GRAPH_SUBJECT,
        "scope": SCOPE,
        "effective_start": EFFECTIVE_START,
        "effective_end": EFFECTIVE_END,
        "origin": candidate["origin"],
        "status": STAGE_TESTED,
        "source_contract_root": SOURCE_CONTRACT_ROOT,
        "candidate_root": candidate["candidate_root"],
        "suite_root": conformance["suite_root"],
        "approval_root": None,
        "material": {"conformance": conformance},
    }
    tested = _stage_with_ids(body)
    raw = _encode_artifact(_artifact([candidate, tested]))
    try:
        from app.governance import provider_continuity_control_pack_independent as independent

        independent.verify_bytes(raw)
    except Exception as exc:
        raise ControlPackError(str(exc)) from exc
    return raw, _telemetry(start, raw)


def _parse_approval(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or not raw:
        raise ControlPackError("approval:empty-or-type")
    if len(raw) > MAX_APPROVAL_BYTES:
        raise ControlPackError("approval:byte-cap")
    value = parse_canonical(raw, artifact=False)
    return _expect_keys(value, APPROVAL_KEYS, "approval-record")


def _validate_approval_record(raw: bytes, tested: Mapping[str, object]) -> tuple[dict[str, object], str]:
    approval = _parse_approval(raw)
    if approval["schema"] != APPROVAL_SCHEMA:
        raise ControlPackError("approval:schema")
    for field in ("approval_authority_id", "approver_id", "approver_role", "approval_reason", "provider_graph_subject", "scope"):
        _text(approval[field], f"approval:{field}")
    _int(approval["approval_time"], "approval:time", minimum=1)
    _int(approval["effective_start"], "approval:effective-start", minimum=1)
    _int(approval["effective_end"], "approval:effective-end", minimum=1)
    _hex(approval["approval_id"], "approval:id")
    _hex(approval["tested_stage_id"], "approval:tested-stage-id")
    _hex(approval["tested_stage_root"], "approval:tested-stage-root")
    _hex(approval["source_contract_root"], "approval:source-contract-root")
    _hex(approval["suite_root"], "approval:suite-root")
    _hex(approval["synthetic_kat_seal"], "approval:synthetic-kat-seal")
    supersession = _expect_keys(approval["supersession"], APPROVAL_SUPERSESSION_KEYS, "approval:supersession")
    if supersession != {"prior_approval_id": None, "supersession_sentinel": SUPERSESSION_SENTINEL}:
        raise ControlPackError("approval:supersession")
    if (
        approval["approval_authority_id"] != APPROVAL_AUTHORITY_ID
        or approval["approver_id"] != APPROVER_ID
        or approval["approver_role"] != APPROVER_ROLE
        or approval["approval_reason"] != APPROVAL_REASON
        or approval["approval_time"] != APPROVAL_TIME
        or approval["provider_graph_subject"] != PROVIDER_GRAPH_SUBJECT
        or approval["scope"] != SCOPE
        or approval["effective_start"] != EFFECTIVE_START
        or approval["effective_end"] != EFFECTIVE_END
        or approval["tested_stage_id"] != tested["stage_id"]
        or approval["tested_stage_root"] != tested["stage_root"]
        or approval["source_contract_root"] != SOURCE_CONTRACT_ROOT
        or approval["suite_root"] != tested["suite_root"]
    ):
        raise ControlPackError("approval:binding")
    core = {key: approval[key] for key in APPROVAL_CORE_KEYS}
    expected_id = _digest("approval-id", core)
    expected_seal = _digest("synthetic-kat-seal", {"approval_id": expected_id, **core})
    if approval["approval_id"] != expected_id or approval["synthetic_kat_seal"] != expected_seal:
        raise ControlPackError("approval:seal-or-id")
    return approval, _digest("approval-root", {"approval_record": approval})


def build_approved(tested_raw: bytes, approval_record_raw: bytes) -> tuple[bytes, dict[str, object]]:
    """Bind an externally supplied synthetic observation-only approval record."""

    start = time.perf_counter_ns()
    value, _ = _load_verified(tested_raw, STAGE_TESTED)
    stages = value["stages"]
    assert isinstance(stages, list) and len(stages) == 2
    candidate = stages[0]
    tested = stages[1]
    assert isinstance(candidate, dict) and isinstance(tested, dict)
    if candidate["origin"] == ORIGIN_BEHAVIORAL_TWIN:
        raise ControlPackError("origin:behavioral-twin-candidate-only")
    approval, approval_root = _validate_approval_record(approval_record_raw, tested)
    body = {
        "stage_kind": STAGE_APPROVED,
        "prior_stage_id": tested["stage_id"],
        "prior_stage_root": tested["stage_root"],
        "stage_time": APPROVAL_TIME,
        "provider_graph_subject": PROVIDER_GRAPH_SUBJECT,
        "scope": SCOPE,
        "effective_start": EFFECTIVE_START,
        "effective_end": EFFECTIVE_END,
        "origin": candidate["origin"],
        "status": STAGE_APPROVED,
        "source_contract_root": SOURCE_CONTRACT_ROOT,
        "candidate_root": candidate["candidate_root"],
        "suite_root": tested["suite_root"],
        "approval_root": approval_root,
        "material": {"approval_record": approval},
    }
    approved = _stage_with_ids(body)
    raw = _encode_artifact(_artifact([candidate, tested, approved]))
    try:
        from app.governance import provider_continuity_control_pack_independent as independent

        independent.verify_bytes(raw)
    except Exception as exc:
        raise ControlPackError(str(exc)) from exc
    return raw, _telemetry(start, raw)


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: python -m app.governance.provider_continuity_control_pack ARTIFACT.json", file=sys.stderr)
        return 2
    try:
        value = parse_canonical(Path(args[0]).read_bytes(), artifact=True)
        print(json.dumps({"accepted": True, "artifact_id": value["artifact_id"]}, sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, ControlPackError) as exc:
        print(f"REJECT {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
