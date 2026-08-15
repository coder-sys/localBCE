"""Independent verifier for the synthetic Provider Continuity Control Pack V1.

The module intentionally does not import the governance producer or the
Provider Trust Graph producer.  It independently recomputes the fixed source
contracts, graph evidence, conformance suite, promotion chain, synthetic
approval, and final artifact identity.  The only product composition is the
existing independent Provider Trust Graph verifier.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Mapping, Sequence

from app.mirror import provider_trust_graph_independent as mirror_independent


class IndependentControlPackError(ValueError):
    """Raised when the complete governance artifact cannot be authenticated."""


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
STAGE_SENTINEL = "NONE"
STAGE_KINDS = (STAGE_CANDIDATE, STAGE_TESTED, STAGE_APPROVED)

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
        raise IndependentControlPackError("json:noncanonical-value") from exc
    return rendered.encode("ascii")


def _duplicate_reject(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise IndependentControlPackError("json:duplicate-key")
        result[key] = value
    return result


def _walk(value: object, depth: int = 0, count: list[int] | None = None) -> None:
    if count is None:
        count = [0]
    count[0] += 1
    if count[0] > MAX_NODES:
        raise IndependentControlPackError("json:node-cap")
    if depth > MAX_DEPTH:
        raise IndependentControlPackError("json:depth-cap")
    if isinstance(value, float):
        raise IndependentControlPackError("json:float-forbidden")
    if isinstance(value, str):
        try:
            raw = value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise IndependentControlPackError("json:non-ascii") from exc
        if len(raw) > MAX_STRING_BYTES:
            raise IndependentControlPackError("json:string-cap")
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise IndependentControlPackError("json:key-type")
            _walk(key, depth + 1, count)
            _walk(item, depth + 1, count)
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth + 1, count)


def _reject_forbidden(value: object) -> None:
    if isinstance(value, str):
        if any(token in value for token in FORBIDDEN_EXTERNAL_TOKENS):
            raise IndependentControlPackError("payload:forbidden-token")
    elif isinstance(value, dict):
        for key, item in value.items():
            if any(token in key for token in FORBIDDEN_EXTERNAL_TOKENS):
                raise IndependentControlPackError("payload:forbidden-token")
            _reject_forbidden(item)
    elif isinstance(value, list):
        for item in value:
            _reject_forbidden(item)


def _parse(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or not raw:
        raise IndependentControlPackError("json:empty-or-type")
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise IndependentControlPackError("json:byte-cap")
    if any(byte > 0x7F for byte in raw):
        raise IndependentControlPackError("json:ascii")
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_duplicate_reject,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                IndependentControlPackError("json:constant-forbidden")
            ),
        )
    except IndependentControlPackError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IndependentControlPackError("json:parse") from exc
    if not isinstance(value, dict):
        raise IndependentControlPackError("json:top-level")
    _walk(value)
    _reject_forbidden(value)
    if _canonical(value) != raw:
        raise IndependentControlPackError("json:not-canonical")
    return value


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update(("BL/GOVERNANCE/PROVIDER-CONTINUITY-CONTROL-PACK/" + label + "/v1\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _expect_keys(value: object, expected: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise IndependentControlPackError(f"{label}:schema")
    return value


def _text(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise IndependentControlPackError(f"{label}:text")
    try:
        raw = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise IndependentControlPackError(f"{label}:ascii") from exc
    if len(raw) > MAX_STRING_BYTES:
        raise IndependentControlPackError(f"{label}:length")
    return value


def _int(value: object, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= MAX_TIMESTAMP:
        raise IndependentControlPackError(f"{label}:integer-or-range")
    return value


def _bool(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise IndependentControlPackError(f"{label}:boolean")
    return value


def _hex(value: object, label: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if type(value) is not str or _HEX.fullmatch(value) is None:
        raise IndependentControlPackError(f"{label}:hex")
    return value


def _sorted_unique(value: object, label: str, *, maximum: int) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise IndependentControlPackError(f"{label}:list-cap")
    result = [_text(item, label) for item in value]
    if result != sorted(result) or len(set(result)) != len(result):
        raise IndependentControlPackError(f"{label}:order-or-duplicate")
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
    return tuple({"contract_id": _digest("source-contract-id", body), **body} for body in bodies)  # type: ignore[return-value]


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


PRODUCER_MODULE_IDENTITY = _module_identity(Path(__file__).with_name("provider_continuity_control_pack.py"))
INDEPENDENT_VERIFIER_MODULE_IDENTITY = _module_identity(Path(__file__))
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


def _validate_contracts(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) != MAX_SOURCES:
        raise IndependentControlPackError("source-contracts:exact-count")
    for contract in value:
        _expect_keys(contract, SOURCE_CONTRACT_KEYS, "source-contract")
    if value != [dict(item) for item in SOURCE_CONTRACTS]:
        raise IndependentControlPackError("source-contracts:fixed-identity")
    if _digest("source-contract-root", {"contracts": value}) != SOURCE_CONTRACT_ROOT:
        raise IndependentControlPackError("source-contracts:root")
    return value


def _validate_graph(material: Mapping[str, object], candidate_root: str, contracts: Sequence[Mapping[str, object]]) -> dict[str, object]:
    expected_material_keys = {"graph_artifact", "graph_report_id", "graph_snapshot_id", "graph_snapshot_root", "evidence_qualification"}
    item = _expect_keys(material, expected_material_keys, "candidate:material")
    graph = item["graph_artifact"]
    try:
        graph_raw = _canonical(graph)
        if len(graph_raw) > MAX_INPUT_BYTES:
            raise IndependentControlPackError("graph:input-byte-cap")
        mirror_independent.verify_bytes(graph_raw)
    except Exception as exc:
        raise IndependentControlPackError(f"graph:{exc}") from exc
    if not isinstance(graph, dict):
        raise IndependentControlPackError("graph:top-level")
    subject = _expect_keys(graph["subject"], {"provider_graph_subject", "scope"}, "graph:subject")
    if subject != SUBJECT:
        raise IndependentControlPackError("graph:subject-identity")
    snapshot = _expect_keys(graph["observation_snapshot"], {"snapshot_id", "snapshot_root", "observation_time"}, "graph:snapshot")
    observation = _int(snapshot["observation_time"], "graph:observation-time", minimum=1)
    if observation != OBSERVATION_TIME:
        raise IndependentControlPackError("source:observation-time")
    _text(snapshot["snapshot_id"], "graph:snapshot-id")
    _hex(snapshot["snapshot_root"], "graph:snapshot-root")
    if item["graph_snapshot_id"] != snapshot["snapshot_id"] or item["graph_snapshot_root"] != snapshot["snapshot_root"]:
        raise IndependentControlPackError("candidate:graph-snapshot-binding")
    report = _expect_keys(graph["report"], {"report_id", "identity_material", "lifecycle"}, "graph:report")
    _hex(report["report_id"], "graph:report-id")
    if item["graph_report_id"] != report["report_id"]:
        raise IndependentControlPackError("candidate:graph-report-binding")
    source_values = graph["source_coverage"]
    if not isinstance(source_values, list) or len(source_values) != MAX_SOURCES:
        raise IndependentControlPackError("source-coverage:exact-count")
    ids = [source.get("source_id") for source in source_values if isinstance(source, dict)]
    if ids != list(SOURCE_IDS):
        raise IndependentControlPackError("source-coverage:order-or-identity")
    contract_map = {contract["source_id"]: contract for contract in contracts}
    all_empty = True
    all_nonmembership = True
    incomplete = False
    conflict = False
    records_all: list[dict[str, object]] = []
    for source_value in source_values:
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
        contract = contract_map.get(source_id)
        if contract is None:
            raise IndependentControlPackError("source:identity")
        if source["source_kind"] != contract["source_kind"] or source["coverage_scope"] != SCOPE:
            raise IndependentControlPackError("source:kind-or-scope")
        if source["coverage_observation_time"] != OBSERVATION_TIME:
            raise IndependentControlPackError("source:coverage-observation")
        if (source["coverage_effective_start"], source["coverage_effective_end"]) != (EFFECTIVE_START, EFFECTIVE_END):
            raise IndependentControlPackError("source:effective-interval")
        if source["coverage_authority_id"] != contract["completeness_authority_id"]:
            raise IndependentControlPackError("source:authority")
        complete = _bool(source["coverage_complete"], "source:complete")
        incomplete = incomplete or not complete
        nonmembership = _sorted_unique(source["nonmembership_keys"], "source:nonmembership", maximum=1)
        if any(key != SUBJECT_KEY for key in nonmembership):
            raise IndependentControlPackError("source:nonmembership-identity")
        provenance = _expect_keys(source["provenance"], {"provenance_id", "integrity_digest"}, "source:provenance")
        if provenance["provenance_id"] != contract["provenance_id"]:
            raise IndependentControlPackError("source:provenance")
        _hex(provenance["integrity_digest"], "source:integrity")
        _hex(source["source_root"], "source:root")
        records = source["records"]
        if not isinstance(records, list) or len(records) > MAX_RECORDS_PER_SOURCE:
            raise IndependentControlPackError("source:record-cap")
        if records:
            all_empty = False
            all_nonmembership = False
        if len(records) > 1:
            conflict = True
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
                raise IndependentControlPackError("source:record-identity-or-time")
            issued = _int(record["issued_at"], "record:issued", minimum=1)
            valid_from = _int(record["valid_from"], "record:valid-from", minimum=1)
            valid_until = _int(record["valid_until"], "record:valid-until", minimum=1)
            terminated = _int(record["terminated_at"], "record:terminated")
            if issued != valid_from or valid_until <= issued:
                raise IndependentControlPackError("record:interval")
            status = _text(record["status"], "record:status")
            if contract["record_kind"] == "CREDENTIAL":
                expected = "ACTIVE" if observation < valid_until else "EXPIRED"
                if terminated != 0 or status != expected:
                    raise IndependentControlPackError("record:credential-status")
            else:
                if terminated:
                    if not issued <= terminated <= observation or status != "TERMINATED":
                        raise IndependentControlPackError("record:enrollment-termination")
                elif status != "ACTIVE" or observation >= valid_until:
                    raise IndependentControlPackError("record:enrollment-status")
            if SUBJECT_KEY in nonmembership:
                raise IndependentControlPackError("completeness:fact-nonmembership-conflict")
            records_all.append(record)
        if complete and not records and nonmembership != [SUBJECT_KEY]:
            raise IndependentControlPackError("source:absence-nonmembership")
        if complete and records and nonmembership:
            raise IndependentControlPackError("completeness:fact-nonmembership-conflict")
    if incomplete:
        label = EVIDENCE_INCOMPLETE
    elif all_empty and all_nonmembership:
        label = EVIDENCE_ABSENT
    elif conflict:
        label = EVIDENCE_CONFLICT
    else:
        credential = next((record for record in records_all if record["record_kind"] == "CREDENTIAL"), None)
        enrollment = next((record for record in records_all if record["record_kind"] == "ENROLLMENT"), None)
        if credential is not None and credential["status"] == "EXPIRED":
            label = EVIDENCE_EXPIRED
        elif enrollment is not None and enrollment["status"] == "TERMINATED":
            label = EVIDENCE_TERMINATED
        else:
            label = EVIDENCE_CONTINUITY
    findings = graph["findings"]
    if not isinstance(findings, list) or len(findings) != 1:
        raise IndependentControlPackError("graph:finding-count")
    finding = _expect_keys(
        findings[0],
        {"finding_id", "kind", "lifecycle", "subject_key", "observation_snapshot_id", "evidence_refs"},
        "graph:finding",
    )
    if finding["kind"] != label or finding["subject_key"] != SUBJECT_KEY or finding["observation_snapshot_id"] != snapshot["snapshot_id"]:
        raise IndependentControlPackError("graph:evidence-label")
    _hex(finding["finding_id"], "graph:finding-id")
    _sorted_unique(finding["evidence_refs"], "graph:finding-refs", maximum=MAX_RECORDS_PER_SOURCE * MAX_SOURCES)
    expected_candidate_root = _digest(
        "candidate-root",
        {"source_contract_root": SOURCE_CONTRACT_ROOT, "subject": SUBJECT, "origin": None, "material": dict(material)},
    )
    return {
        "label": label,
        "report_id": report["report_id"],
        "snapshot_id": snapshot["snapshot_id"],
        "snapshot_root": snapshot["snapshot_root"],
        "finding_id": finding["finding_id"],
        "candidate_root_input": candidate_root,
        "expected_candidate_root_without_origin": expected_candidate_root,
    }


def _candidate_root(origin: str, material: Mapping[str, object]) -> str:
    return _digest(
        "candidate-root",
        {"source_contract_root": SOURCE_CONTRACT_ROOT, "subject": SUBJECT, "origin": origin, "material": dict(material)},
    )


def _validate_stage_identity(stage: Mapping[str, object]) -> tuple[str, str]:
    body = {key: value for key, value in stage.items() if key not in {"stage_id", "stage_root"}}
    stage_root = _digest("stage-root", body)
    stage_id = _digest("stage-id", {"stage_kind": body["stage_kind"], "stage_root": stage_root})
    if stage["stage_root"] != stage_root:
        raise IndependentControlPackError("stage:root-mismatch")
    if stage["stage_id"] != stage_id:
        raise IndependentControlPackError("stage:id-mismatch")
    return stage_root, stage_id


def _validate_candidate(stage: object, contracts: Sequence[Mapping[str, object]]) -> dict[str, object]:
    item = _expect_keys(
        stage,
        {
            "stage_id",
            "stage_root",
            "stage_kind",
            "prior_stage_id",
            "prior_stage_root",
            "stage_time",
            "provider_graph_subject",
            "scope",
            "effective_start",
            "effective_end",
            "origin",
            "status",
            "source_contract_root",
            "candidate_root",
            "suite_root",
            "approval_root",
            "material",
        },
        "candidate-stage",
    )
    _hex(item["stage_id"], "candidate:stage-id")
    _hex(item["stage_root"], "candidate:stage-root")
    if item["stage_kind"] != STAGE_CANDIDATE or item["status"] != STAGE_CANDIDATE:
        raise IndependentControlPackError("candidate:stage-kind-or-status")
    if item["prior_stage_id"] != STAGE_SENTINEL or item["prior_stage_root"] is not None:
        raise IndependentControlPackError("candidate:prior-sentinel")
    if item["stage_time"] != CANDIDATE_TIME:
        raise IndependentControlPackError("candidate:stage-time")
    if item["provider_graph_subject"] != PROVIDER_GRAPH_SUBJECT or item["scope"] != SCOPE:
        raise IndependentControlPackError("candidate:subject-or-scope")
    if (item["effective_start"], item["effective_end"]) != (EFFECTIVE_START, EFFECTIVE_END):
        raise IndependentControlPackError("candidate:effective-interval")
    origin = _text(item["origin"], "candidate:origin")
    if origin not in ORIGINS:
        raise IndependentControlPackError("candidate:origin")
    if item["source_contract_root"] != SOURCE_CONTRACT_ROOT:
        raise IndependentControlPackError("candidate:source-contract-root")
    _hex(item["candidate_root"], "candidate:root")
    if item["suite_root"] is not None or item["approval_root"] is not None:
        raise IndependentControlPackError("candidate:future-root")
    material = _expect_keys(item["material"], {"graph_artifact", "graph_report_id", "graph_snapshot_id", "graph_snapshot_root", "evidence_qualification"}, "candidate:material")
    evidence = _validate_graph(material, item["candidate_root"], contracts)
    label = _text(material["evidence_qualification"], "candidate:evidence")
    if label not in EVIDENCE_LABELS or label != evidence["label"]:
        raise IndependentControlPackError("candidate:evidence-label")
    expected_root = _candidate_root(origin, material)
    if item["candidate_root"] != expected_root:
        raise IndependentControlPackError("candidate:root-mismatch")
    _validate_stage_identity(item)
    return {
        "stage": item,
        "stage_id": item["stage_id"],
        "stage_root": item["stage_root"],
        "origin": origin,
        "candidate_root": item["candidate_root"],
        "suite_root": None,
        "label": label,
    }


def _definitions() -> list[dict[str, object]]:
    return [dict(item) for item in CONFORMANCE_DEFINITIONS]


def _expected_conformance(candidate: Mapping[str, object], artifact: Mapping[str, object]) -> dict[str, object]:
    label = _text(candidate["label"], "candidate:evidence")
    candidate_root = candidate["candidate_root"]
    contracts = _validate_contracts(artifact["source_contracts"])
    stage = _expect_keys(candidate["stage"], {"stage_id", "stage_root", "stage_kind", "prior_stage_id", "prior_stage_root", "stage_time", "provider_graph_subject", "scope", "effective_start", "effective_end", "origin", "status", "source_contract_root", "candidate_root", "suite_root", "approval_root", "material"}, "candidate:stage")
    material = _expect_keys(stage["material"], {"graph_artifact", "graph_report_id", "graph_snapshot_id", "graph_snapshot_root", "evidence_qualification"}, "candidate:material")
    graph = material["graph_artifact"]
    graph_raw = _canonical(graph)
    graph_result = mirror_independent.verify_bytes(graph_raw)
    graph_value = _expect_keys(graph, {"schema", "subject", "observation_snapshot", "source_coverage", "findings", "discrepancies", "remediation", "parity_cases", "transition", "report", "authority"}, "conformance:graph")
    snapshot = _expect_keys(graph_value["observation_snapshot"], {"snapshot_id", "snapshot_root", "observation_time"}, "conformance:snapshot")
    report = _expect_keys(graph_value["report"], {"report_id", "identity_material", "lifecycle"}, "conformance:report")
    evidence = _validate_graph(material, candidate_root, contracts)
    observed_contracts = artifact["source_contracts"]
    source_result = {
        "source_contract_root": stage["source_contract_root"],
        "contract_ids": [contract["contract_id"] for contract in observed_contracts] if isinstance(observed_contracts, list) else [],
        "contract_count": len(observed_contracts) if isinstance(observed_contracts, list) else -1,
    }
    graph_result_output = {
        "graph_report_id": report["report_id"],
        "graph_snapshot_id": snapshot["snapshot_id"],
        "graph_snapshot_root": snapshot["snapshot_root"],
    }
    evidence_result = {
        "evidence_qualification": evidence["label"],
        "finding_id": evidence["finding_id"],
    }
    observed_flags = {key: artifact.get(key) for key in AUTHORITY_FLAGS}
    authority_result = {"authority_profile_root": _digest("authority-profile-root", observed_flags)}
    predicate_values = (
        (source_result, observed_contracts == [dict(item) for item in contracts] and stage["source_contract_root"] == SOURCE_CONTRACT_ROOT),
        (graph_result_output, bool(graph_result.get("accepted")) and graph_result.get("report_id") == report["report_id"] and material["graph_report_id"] == report["report_id"] and material["graph_snapshot_id"] == snapshot["snapshot_id"] and material["graph_snapshot_root"] == snapshot["snapshot_root"]),
        (evidence_result, evidence["label"] in EVIDENCE_LABELS and evidence["label"] == label),
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
        "producer_module_identity": _module_identity(Path(__file__).with_name("provider_continuity_control_pack.py")),
        "independent_verifier_module_identity": _module_identity(Path(__file__)),
        "source_contract_root": SOURCE_CONTRACT_ROOT,
        "candidate_root": candidate_root,
        "authority_profile": dict(AUTHORITY_FLAGS),
        "authority_profile_root": AUTHORITY_PROFILE_ROOT,
        "definitions": _definitions(),
    }
    conformance["suite_root"] = _digest("suite-root", conformance)
    conformance["results"] = results
    return conformance


def _validate_tested(stage: object, candidate: Mapping[str, object], artifact: Mapping[str, object]) -> dict[str, object]:
    item = _expect_keys(
        stage,
        {
            "stage_id",
            "stage_root",
            "stage_kind",
            "prior_stage_id",
            "prior_stage_root",
            "stage_time",
            "provider_graph_subject",
            "scope",
            "effective_start",
            "effective_end",
            "origin",
            "status",
            "source_contract_root",
            "candidate_root",
            "suite_root",
            "approval_root",
            "material",
        },
        "tested-stage",
    )
    _hex(item["stage_id"], "tested:stage-id")
    _hex(item["stage_root"], "tested:stage-root")
    if candidate["origin"] == ORIGIN_BEHAVIORAL_TWIN:
        raise IndependentControlPackError("origin:behavioral-twin-candidate-only")
    if item["stage_kind"] != STAGE_TESTED or item["status"] != STAGE_TESTED:
        raise IndependentControlPackError("tested:stage-kind-or-status")
    if (item["prior_stage_id"], item["prior_stage_root"]) != (candidate["stage_id"], candidate["stage_root"]):
        raise IndependentControlPackError("tested:prior-binding")
    if item["stage_time"] != TESTED_TIME:
        raise IndependentControlPackError("tested:stage-time")
    if (item["provider_graph_subject"], item["scope"]) != (PROVIDER_GRAPH_SUBJECT, SCOPE):
        raise IndependentControlPackError("tested:subject-or-scope")
    if (item["effective_start"], item["effective_end"]) != (EFFECTIVE_START, EFFECTIVE_END):
        raise IndependentControlPackError("tested:effective-interval")
    if item["origin"] != candidate["origin"] or item["source_contract_root"] != SOURCE_CONTRACT_ROOT or item["candidate_root"] != candidate["candidate_root"]:
        raise IndependentControlPackError("tested:binding")
    _hex(item["suite_root"], "tested:suite-root")
    if item["approval_root"] is not None:
        raise IndependentControlPackError("tested:future-root")
    material = _expect_keys(item["material"], {"conformance"}, "tested:material")
    conformance = _expect_keys(
        material["conformance"],
        {"schema", "suite_id", "suite_version", "producer_module_identity", "independent_verifier_module_identity", "source_contract_root", "candidate_root", "authority_profile", "authority_profile_root", "suite_root", "definitions", "results"},
        "tested:conformance",
    )
    expected = _expected_conformance(candidate, artifact)
    if not all(result["passed"] for result in expected["results"]):
        failed = next(result["vector_id"] for result in expected["results"] if not result["passed"])
        raise IndependentControlPackError(f"tested:conformance-failed:{failed}")
    if conformance != expected or item["suite_root"] != expected["suite_root"]:
        raise IndependentControlPackError("tested:conformance-mismatch")
    _validate_stage_identity(item)
    return {
        "stage": item,
        "stage_id": item["stage_id"],
        "stage_root": item["stage_root"],
        "origin": candidate["origin"],
        "candidate_root": candidate["candidate_root"],
        "suite_root": item["suite_root"],
        "label": candidate["label"],
    }


def _validate_approval_record(approval: object, tested: Mapping[str, object]) -> tuple[dict[str, object], str]:
    record = _expect_keys(approval, APPROVAL_KEYS, "approval-record")
    if len(_canonical(record)) > MAX_APPROVAL_BYTES:
        raise IndependentControlPackError("approval:byte-cap")
    if record["schema"] != APPROVAL_SCHEMA:
        raise IndependentControlPackError("approval:schema")
    for field in ("approval_authority_id", "approver_id", "approver_role", "approval_reason", "provider_graph_subject", "scope"):
        _text(record[field], f"approval:{field}")
    _int(record["approval_time"], "approval:time", minimum=1)
    _int(record["effective_start"], "approval:effective-start", minimum=1)
    _int(record["effective_end"], "approval:effective-end", minimum=1)
    _hex(record["approval_id"], "approval:id")
    _hex(record["tested_stage_id"], "approval:tested-stage-id")
    _hex(record["tested_stage_root"], "approval:tested-stage-root")
    _hex(record["source_contract_root"], "approval:source-contract-root")
    _hex(record["suite_root"], "approval:suite-root")
    _hex(record["synthetic_kat_seal"], "approval:synthetic-kat-seal")
    supersession = _expect_keys(record["supersession"], APPROVAL_SUPERSESSION_KEYS, "approval:supersession")
    if supersession != {"prior_approval_id": None, "supersession_sentinel": SUPERSESSION_SENTINEL}:
        raise IndependentControlPackError("approval:supersession")
    if (
        record["approval_authority_id"] != APPROVAL_AUTHORITY_ID
        or record["approver_id"] != APPROVER_ID
        or record["approver_role"] != APPROVER_ROLE
        or record["approval_reason"] != APPROVAL_REASON
        or record["approval_time"] != APPROVAL_TIME
        or record["provider_graph_subject"] != PROVIDER_GRAPH_SUBJECT
        or record["scope"] != SCOPE
        or record["effective_start"] != EFFECTIVE_START
        or record["effective_end"] != EFFECTIVE_END
        or record["tested_stage_id"] != tested["stage_id"]
        or record["tested_stage_root"] != tested["stage_root"]
        or record["source_contract_root"] != SOURCE_CONTRACT_ROOT
        or record["suite_root"] != tested["suite_root"]
    ):
        raise IndependentControlPackError("approval:binding")
    core = {key: record[key] for key in APPROVAL_CORE_KEYS}
    expected_id = _digest("approval-id", core)
    expected_seal = _digest("synthetic-kat-seal", {"approval_id": expected_id, **core})
    if record["approval_id"] != expected_id or record["synthetic_kat_seal"] != expected_seal:
        raise IndependentControlPackError("approval:seal-or-id")
    return record, _digest("approval-root", {"approval_record": record})


def _validate_approved(stage: object, candidate: Mapping[str, object], tested: Mapping[str, object]) -> dict[str, object]:
    item = _expect_keys(
        stage,
        {
            "stage_id",
            "stage_root",
            "stage_kind",
            "prior_stage_id",
            "prior_stage_root",
            "stage_time",
            "provider_graph_subject",
            "scope",
            "effective_start",
            "effective_end",
            "origin",
            "status",
            "source_contract_root",
            "candidate_root",
            "suite_root",
            "approval_root",
            "material",
        },
        "approved-stage",
    )
    _hex(item["stage_id"], "approved:stage-id")
    _hex(item["stage_root"], "approved:stage-root")
    if candidate["origin"] == ORIGIN_BEHAVIORAL_TWIN:
        raise IndependentControlPackError("origin:behavioral-twin-candidate-only")
    if item["stage_kind"] != STAGE_APPROVED or item["status"] != STAGE_APPROVED:
        raise IndependentControlPackError("approved:stage-kind-or-status")
    if (item["prior_stage_id"], item["prior_stage_root"]) != (tested["stage_id"], tested["stage_root"]):
        raise IndependentControlPackError("approved:prior-binding")
    if item["stage_time"] != APPROVAL_TIME:
        raise IndependentControlPackError("approved:stage-time")
    if (item["provider_graph_subject"], item["scope"]) != (PROVIDER_GRAPH_SUBJECT, SCOPE):
        raise IndependentControlPackError("approved:subject-or-scope")
    if (item["effective_start"], item["effective_end"]) != (EFFECTIVE_START, EFFECTIVE_END):
        raise IndependentControlPackError("approved:effective-interval")
    if item["origin"] != candidate["origin"] or item["source_contract_root"] != SOURCE_CONTRACT_ROOT or item["candidate_root"] != candidate["candidate_root"] or item["suite_root"] != tested["suite_root"]:
        raise IndependentControlPackError("approved:binding")
    _hex(item["approval_root"], "approved:approval-root")
    material = _expect_keys(item["material"], {"approval_record"}, "approved:material")
    approval, expected_root = _validate_approval_record(material["approval_record"], tested)
    if item["approval_root"] != expected_root:
        raise IndependentControlPackError("approved:approval-mismatch")
    _validate_stage_identity(item)
    return {"stage": item, "stage_id": item["stage_id"], "stage_root": item["stage_root"]}


def _validate_artifact(value: object) -> dict[str, object]:
    item = _expect_keys(
        value,
        {
            "artifact_id",
            "schema",
            "subject",
            "source_contracts",
            "stages",
            "current_stage_kind",
            "current_stage_id",
            "chain_root",
            *AUTHORITY_FLAGS.keys(),
        },
        "artifact",
    )
    _hex(item["artifact_id"], "artifact:id")
    if item["schema"] != SCHEMA:
        raise IndependentControlPackError("artifact:schema")
    if item["subject"] != SUBJECT:
        raise IndependentControlPackError("artifact:subject")
    contracts = _validate_contracts(item["source_contracts"])
    stages_value = item["stages"]
    if not isinstance(stages_value, list) or not 1 <= len(stages_value) <= MAX_STAGES:
        raise IndependentControlPackError("stages:count")
    current_kind = _text(item["current_stage_kind"], "artifact:current-kind")
    expected_length = {STAGE_CANDIDATE: 1, STAGE_TESTED: 2, STAGE_APPROVED: 3}.get(current_kind)
    if expected_length is None or len(stages_value) != expected_length:
        raise IndependentControlPackError("stages:current-length")
    stage_kinds = [stage.get("stage_kind") for stage in stages_value if isinstance(stage, dict)]
    if stage_kinds != list((STAGE_CANDIDATE, STAGE_TESTED, STAGE_APPROVED)[: len(stages_value)]):
        raise IndependentControlPackError("stages:order-or-skip")
    stage_ids = [stage.get("stage_id") for stage in stages_value if isinstance(stage, dict)]
    if len(stage_ids) != len(set(stage_ids)):
        raise IndependentControlPackError("stages:duplicate")
    candidate = _validate_candidate(stages_value[0], contracts)
    validated = [candidate]
    if len(stages_value) >= 2:
        tested = _validate_tested(stages_value[1], candidate, item)
        validated.append(tested)
    else:
        tested = None
    if len(stages_value) == 3:
        assert tested is not None
        approved = _validate_approved(stages_value[2], candidate, tested)
        validated.append(approved)
    current = validated[-1]
    if item["current_stage_kind"] != current["stage"]["stage_kind"] or item["current_stage_id"] != current["stage_id"]:
        raise IndependentControlPackError("artifact:current-binding")
    _hex(item["chain_root"], "artifact:chain-root")
    if item["chain_root"] != _digest("chain-root", {"stages": stages_value}):
        raise IndependentControlPackError("artifact:chain-root-mismatch")
    if {key: item[key] for key in AUTHORITY_FLAGS} != AUTHORITY_FLAGS:
        raise IndependentControlPackError("artifact:authority-flags")
    body = {key: item[key] for key in item if key != "artifact_id"}
    if item["artifact_id"] != _digest("artifact-id", body):
        raise IndependentControlPackError("artifact:id-mismatch")
    return {
        "artifact_id": item["artifact_id"],
        "current_stage_kind": current["stage"]["stage_kind"],
        "current_stage_id": current["stage_id"],
        "candidate_root": candidate["candidate_root"],
        "source_contract_root": SOURCE_CONTRACT_ROOT,
        "evidence_qualification": candidate["label"],
    }


def verify_bytes(raw: bytes) -> dict[str, object]:
    """Independently accept one complete, bounded control-pack artifact."""

    value = _parse(raw)
    result = _validate_artifact(value)
    return {"accepted": True, "artifact_bytes": len(raw), **result}


def verify_file(path: str | Path) -> dict[str, object]:
    file_path = Path(path)
    try:
        if file_path.stat().st_size > MAX_ARTIFACT_BYTES:
            raise IndependentControlPackError("file:byte-cap")
        with file_path.open("rb") as handle:
            raw = handle.read(MAX_ARTIFACT_BYTES + 1)
    except OSError:
        raise
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise IndependentControlPackError("file:byte-cap")
    return verify_bytes(raw)


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: python -m app.governance.provider_continuity_control_pack_independent ARTIFACT.json", file=sys.stderr)
        return 2
    try:
        print(json.dumps(verify_file(args[0]), sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, IndependentControlPackError) as exc:
        print(f"REJECT {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
