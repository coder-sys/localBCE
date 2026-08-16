"""Independent verifier for the synthetic multi-profile Control Pack V2.

This module deliberately does not import the V2 producer.  It reconstructs the
profile commitment from an externally configured registry, independently
re-verifies the embedded Provider Trust Graph V2 artifact, and then checks the
governance and withdrawal lifecycle identities.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Mapping

from app.mirror import provider_trust_graph_independent as graph_independent


class IndependentControlPackV2Error(ValueError):
    """Raised when V2 governance evidence fails independent verification."""


SCHEMA = "provider-continuity-control-pack-v2"
WITHDRAWAL_SCHEMA = "provider-continuity-control-pack-withdrawal-v2"
APPROVAL_SCHEMA = "provider-continuity-state-approval-v2"
AUTHORIZATION_SCHEMA = "provider-continuity-withdrawal-authorization-v2"
STAGE_CANDIDATE = "CANDIDATE"
STAGE_TESTED = "TESTED"
STAGE_APPROVED = "APPROVED_OBSERVATION_ONLY"
STAGE_KINDS = (STAGE_CANDIDATE, STAGE_TESTED, STAGE_APPROVED)
STAGE_SENTINEL = "NONE"
ACTION_WITHDRAWN = "WITHDRAWN_OBSERVATION_ONLY"
ORIGIN_MIRROR = "MIRROR_PROVIDER_TRUST_GRAPH_V2"
TERMINAL_SENTINEL = "TERMINAL_NO_REACTIVATION_OR_SUPERSESSION_V2"
SUPERSESSION_SENTINEL = "NO_SUPERSESSION_V2"
APPROVAL_AUTHORITY_ID = "SYNTH_STATE_APPROVAL_AUTHORITY_V2"
APPROVER_ID = "SYNTH_STATE_APPROVER_V2"
APPROVER_ROLE = "OBSERVATION_CONTROL_PACK_APPROVER_V2"
APPROVAL_REASON = "SYNTHETIC_OBSERVATION_ONLY_PROFILE_APPROVAL_V2"
WITHDRAWAL_AUTHORITY_ID = "SYNTH_PROVIDER_CONTINUITY_WITHDRAWAL_AUTHORITY_V2"
WITHDRAWER_ID = "SYNTH_PROVIDER_CONTINUITY_WITHDRAWER_V2"
WITHDRAWER_ROLE = "OBSERVATION_CONTROL_PACK_WITHDRAWER_V2"
WITHDRAWAL_REASON = "SYNTHETIC_OBSERVATION_ONLY_PROFILE_WITHDRAWAL_V2"
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
MAX_INPUT_BYTES = 262_144
MAX_ARTIFACT_BYTES = 524_288
MAX_STRING_BYTES = 256
MAX_NODES = 16_384
MAX_DEPTH = 24
MAX_TIMESTAMP = 2_147_483_647
MAX_STAGES = 3
_HEX = "0123456789abcdef"

PROFILE_KEYS = {
    "profile_id", "version", "profile_digest", "source_registry_root",
    "verifier_id", "verifier_epoch", "evidence_mode", "require_complete",
    "allow_nonmembership",
}
STAGE_KEYS = {
    "stage_id", "stage_root", "stage_kind", "prior_stage_id", "prior_stage_root",
    "stage_time", "provider_graph_subject", "scope", "effective_start", "effective_end",
    "origin", "status", "source_registry_root", "candidate_root", "suite_root",
    "approval_root", "material",
}
ARTIFACT_KEYS = {
    "artifact_id", "schema", "profile", "subject", "stages", "current_stage_kind",
    "current_stage_id", "chain_root", *AUTHORITY_FLAGS.keys(),
}
APPROVAL_KEYS = {
    "schema", "approval_id", "approval_authority_id", "approver_id", "approver_role",
    "approval_reason", "approval_time", "profile_id", "profile_version", "profile_digest",
    "source_registry_root", "provider_graph_subject", "scope", "effective_start",
    "effective_end", "tested_stage_id", "tested_stage_root", "suite_root", "supersession",
    "synthetic_kat_seal",
}
APPROVAL_CORE_KEYS = APPROVAL_KEYS - {"approval_id", "synthetic_kat_seal"}
AUTHORIZATION_KEYS = {
    "schema", "authority_id", "withdrawer_id", "authorized_role", "reason_code",
    "withdrawal_time", "effective_time", "profile_id", "profile_version", "profile_digest",
    "source_registry_root", "provider_graph_subject", "scope", "effective_start",
    "effective_end", "prior_approved_artifact_id", "prior_approved_stage_id",
    "prior_approved_stage_root", "prior_approval_id", "prior_approval_root", "suite_root",
    "terminal_sentinel", "withdrawal_authorization_id", "synthetic_kat_seal",
}
AUTHORIZATION_CORE_KEYS = AUTHORIZATION_KEYS - {"withdrawal_authorization_id", "synthetic_kat_seal"}
WITHDRAWAL_KEYS = {
    "artifact_id", "schema", "action", "status", "profile", "approval_id", "approval_root",
    "approved_artifact", "approved_artifact_id", "approved_artifact_sha3_512", "approved_stage_id",
    "approved_stage_root", "authority_profile_root", "effective_end", "effective_start",
    "effective_time", "origin", "provider_graph_subject", "scope", "source_registry_root",
    "suite_root", "terminal", "terminal_sentinel", "withdrawal_authorization",
    "withdrawal_authorization_id", "withdrawal_authorization_root", "withdrawal_time",
    "withdrawal_id", "withdrawal_root", *AUTHORITY_FLAGS.keys(),
}


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise IndependentControlPackV2Error("json:noncanonical-value") from exc


def _duplicate_reject(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise IndependentControlPackV2Error("json:duplicate-key")
        result[key] = value
    return result


def _walk(value: object, depth: int = 0, count: list[int] | None = None) -> None:
    count = [0] if count is None else count
    count[0] += 1
    if count[0] > MAX_NODES:
        raise IndependentControlPackV2Error("json:node-cap")
    if depth > MAX_DEPTH:
        raise IndependentControlPackV2Error("json:depth-cap")
    if isinstance(value, float):
        raise IndependentControlPackV2Error("json:float-forbidden")
    if isinstance(value, str):
        try:
            if len(value.encode("ascii")) > MAX_STRING_BYTES:
                raise IndependentControlPackV2Error("json:string-cap")
        except UnicodeEncodeError as exc:
            raise IndependentControlPackV2Error("json:non-ascii") from exc
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise IndependentControlPackV2Error("json:key-type")
            _walk(key, depth + 1, count)
            _walk(item, depth + 1, count)
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth + 1, count)


def _parse(raw: bytes, *, artifact: bool = True) -> dict[str, object]:
    maximum = MAX_ARTIFACT_BYTES if artifact else MAX_INPUT_BYTES
    if type(raw) is not bytes or not raw or len(raw) > maximum:
        raise IndependentControlPackV2Error("json:byte-cap")
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_duplicate_reject, parse_constant=lambda _value: (_ for _ in ()).throw(IndependentControlPackV2Error("json:constant-forbidden")))
    except IndependentControlPackV2Error:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IndependentControlPackV2Error("json:parse") from exc
    if not isinstance(value, dict):
        raise IndependentControlPackV2Error("json:top-level")
    _walk(value)
    if _canonical(value) != raw:
        raise IndependentControlPackV2Error("json:not-canonical")
    return value


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update(("BL/GOVERNANCE/PROVIDER-CONTINUITY-CONTROL-PACK/" + label + "/v2\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _bytes_digest(label: str, raw: bytes) -> str:
    digest = hashlib.sha3_512()
    digest.update(("BL/GOVERNANCE/PROVIDER-CONTINUITY-CONTROL-PACK/" + label + "/v2\0").encode("ascii"))
    digest.update(raw)
    return digest.hexdigest()


def _expect_keys(value: object, expected: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise IndependentControlPackV2Error(f"{label}:schema")
    return value


def _text(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise IndependentControlPackV2Error(f"{label}:text")
    try:
        if len(value.encode("ascii")) > MAX_STRING_BYTES:
            raise IndependentControlPackV2Error(f"{label}:length")
    except UnicodeEncodeError as exc:
        raise IndependentControlPackV2Error(f"{label}:ascii") from exc
    return value


def _int(value: object, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= MAX_TIMESTAMP:
        raise IndependentControlPackV2Error(f"{label}:integer")
    return value


def _bool(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise IndependentControlPackV2Error(f"{label}:boolean")
    return value


def _hex(value: object, label: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if type(value) is not str or len(value) != 128 or any(char not in _HEX for char in value):
        raise IndependentControlPackV2Error(f"{label}:hex")
    return value


def _profile_material(profile: object) -> dict[str, object]:
    try:
        graph_independent._profile_view(profile)
        return graph_independent._profile_material(profile)
    except Exception as exc:
        raise IndependentControlPackV2Error("profile:configuration") from exc


def _source_registry_root(material: Mapping[str, object]) -> str:
    source_material = {
        key: material[key]
        for key in (
            "profile_id", "version", "subject", "scope", "observation_window",
            "effective_start", "effective_end", "source_roles", "require_complete",
            "credential_id", "enrollment_id", "allow_nonmembership", "canonical_order",
            "root_rule",
        )
    }
    return _digest("source-registry-root", source_material)


def _descriptor(profile: object) -> dict[str, object]:
    material = _profile_material(profile)
    return {
        "profile_id": material["profile_id"],
        "version": material["version"],
        "profile_digest": graph_independent._profile_digest(profile),
        "source_registry_root": _source_registry_root(material),
        "verifier_id": material["verifier_id"],
        "verifier_epoch": material["verifier_epoch"],
        "evidence_mode": material["evidence_mode"],
        "require_complete": material["require_complete"],
        "allow_nonmembership": material["allow_nonmembership"],
    }


def _configured_profile(value: object, profile_registry: Mapping[str, object] | None) -> tuple[object, dict[str, object]]:
    if not isinstance(profile_registry, Mapping) or not profile_registry:
        raise IndependentControlPackV2Error("profile:registry-required")
    descriptor = _expect_keys(value, PROFILE_KEYS, "profile")
    profile_id = _text(descriptor["profile_id"], "profile:id")
    profile = profile_registry.get(profile_id)
    if profile is None:
        raise IndependentControlPackV2Error("profile:registry-miss")
    expected = _descriptor(profile)
    if dict(descriptor) != expected:
        raise IndependentControlPackV2Error("profile:binding")
    _int(descriptor["version"], "profile:version", minimum=1)
    _hex(descriptor["profile_digest"], "profile:digest")
    _hex(descriptor["source_registry_root"], "profile:source-registry-root")
    _text(descriptor["verifier_id"], "profile:verifier-id")
    _int(descriptor["verifier_epoch"], "profile:verifier-epoch", minimum=1)
    _text(descriptor["evidence_mode"], "profile:evidence-mode")
    _bool(descriptor["require_complete"], "profile:require-complete")
    _bool(descriptor["allow_nonmembership"], "profile:allow-nonmembership")
    return profile, dict(descriptor)


def _stage_common(stage: object, profile: object, descriptor: Mapping[str, object], expected_kind: str, prior: Mapping[str, object] | None) -> dict[str, object]:
    item = _expect_keys(stage, STAGE_KEYS, f"stage:{expected_kind.lower()}")
    view = graph_independent._profile_view(profile)
    if item["stage_kind"] != expected_kind or item["status"] != expected_kind or item["origin"] != ORIGIN_MIRROR:
        raise IndependentControlPackV2Error("stage:kind-or-origin")
    if (item["provider_graph_subject"], item["scope"]) != (view.subject, view.scope):
        raise IndependentControlPackV2Error("stage:subject")
    if item["source_registry_root"] != descriptor["source_registry_root"]:
        raise IndependentControlPackV2Error("stage:source-registry-root")
    if (item["effective_start"], item["effective_end"]) != (view.effective_start, view.effective_end):
        raise IndependentControlPackV2Error("stage:effective-interval")
    _hex(item["stage_id"], "stage:id")
    _hex(item["stage_root"], "stage:root")
    _int(item["stage_time"], "stage:time", minimum=1)
    if prior is None:
        if item["prior_stage_id"] != STAGE_SENTINEL or item["prior_stage_root"] is not None:
            raise IndependentControlPackV2Error("stage:unexpected-prior")
    elif (item["prior_stage_id"], item["prior_stage_root"]) != (prior["stage_id"], prior["stage_root"]):
        raise IndependentControlPackV2Error("stage:prior-binding")
    if item["stage_root"] != _digest("stage-root", {key: item[key] for key in item if key not in {"stage_id", "stage_root"}}):
        raise IndependentControlPackV2Error("stage:root-mismatch")
    expected_id = _digest("stage-id", {"stage_kind": expected_kind, "stage_root": item["stage_root"]})
    if item["stage_id"] != expected_id:
        raise IndependentControlPackV2Error("stage:id-mismatch")
    return item


def _candidate_root(descriptor: Mapping[str, object], origin: str, material: Mapping[str, object]) -> str:
    return _digest(
        "candidate-root",
        {
            "profile": dict(descriptor),
            "subject": {"provider_graph_subject": material["provider_graph_subject"], "scope": material["scope"]},
            "origin": origin,
            "material": dict(material),
        },
    )


def _validate_candidate(stage_value: object, profile: object, descriptor: Mapping[str, object]) -> dict[str, object]:
    stage = _stage_common(stage_value, profile, descriptor, STAGE_CANDIDATE, None)
    material_value = _expect_keys(stage["material"], {"graph_artifact", "graph_report_id", "graph_snapshot_id", "graph_snapshot_root", "observation_time"}, "candidate:material")
    graph_value = material_value["graph_artifact"]
    graph_raw = _canonical(graph_value)
    try:
        graph_result = graph_independent.verify_bytes_v2(graph_raw, {str(descriptor["profile_id"]): profile})
    except Exception as exc:
        raise IndependentControlPackV2Error("candidate:graph-independent") from exc
    if graph_result.get("profile_id") != descriptor["profile_id"] or graph_result.get("profile_digest") != descriptor["profile_digest"]:
        raise IndependentControlPackV2Error("candidate:graph-profile")
    if not isinstance(graph_value, dict):
        raise IndependentControlPackV2Error("candidate:graph-shape")
    subject = _expect_keys(graph_value.get("subject"), {"provider_graph_subject", "scope"}, "candidate:graph-subject")
    snapshot = _expect_keys(graph_value.get("observation_snapshot"), {"snapshot_id", "snapshot_root", "observation_time"}, "candidate:graph-snapshot")
    report = _expect_keys(graph_value.get("report"), {"report_id", "identity_material", "lifecycle"}, "candidate:graph-report")
    _hex(report["report_id"], "candidate:graph-report-id")
    _hex(snapshot["snapshot_id"], "candidate:graph-snapshot-id")
    _hex(snapshot["snapshot_root"], "candidate:graph-snapshot-root")
    if subject != {"provider_graph_subject": stage["provider_graph_subject"], "scope": stage["scope"]}:
        raise IndependentControlPackV2Error("candidate:graph-subject-binding")
    if snapshot["observation_time"] != stage["stage_time"] or material_value["observation_time"] != snapshot["observation_time"]:
        raise IndependentControlPackV2Error("candidate:observation-binding")
    if material_value["graph_report_id"] != report["report_id"] or material_value["graph_snapshot_id"] != snapshot["snapshot_id"] or material_value["graph_snapshot_root"] != snapshot["snapshot_root"]:
        raise IndependentControlPackV2Error("candidate:graph-identity")
    root_material = {**material_value, "provider_graph_subject": stage["provider_graph_subject"], "scope": stage["scope"]}
    if stage["candidate_root"] != _candidate_root(descriptor, stage["origin"], root_material):
        raise IndependentControlPackV2Error("candidate:root")
    if stage["suite_root"] is not None or stage["approval_root"] is not None:
        raise IndependentControlPackV2Error("candidate:terminal-fields")
    return {"stage": stage, "material": material_value, "candidate_root": stage["candidate_root"], "graph_result": graph_result}


def _conformance(descriptor: Mapping[str, object], candidate_stage: Mapping[str, object], material: Mapping[str, object]) -> dict[str, object]:
    return {
        "schema": SCHEMA,
        "suite_id": "SYNTH_PROVIDER_CONTINUITY_CONFORMANCE_SUITE_V2",
        "suite_version": 1,
        "profile_digest": descriptor["profile_digest"],
        "source_registry_root": descriptor["source_registry_root"],
        "candidate_root": candidate_stage["candidate_root"],
        "graph_report_id": material["graph_report_id"],
        "graph_snapshot_id": material["graph_snapshot_id"],
        "graph_snapshot_root": material["graph_snapshot_root"],
        "predicates": ["PROFILE_BINDING_V2", "GRAPH_INDEPENDENT_V2", "OBSERVATION_ONLY_FLAGS_V2"],
    }


def _validate_tested(stage_value: object, candidate: Mapping[str, object], profile: object, descriptor: Mapping[str, object]) -> dict[str, object]:
    stage = _stage_common(stage_value, profile, descriptor, STAGE_TESTED, candidate["stage"])
    material = _expect_keys(stage["material"], {"candidate_artifact_id", "candidate_stage_id", "candidate_stage_root", "conformance"}, "tested:material")
    if (material["candidate_artifact_id"], material["candidate_stage_id"], material["candidate_stage_root"]) != (candidate["artifact_id"], candidate["stage"]["stage_id"], candidate["stage"]["stage_root"]):
        raise IndependentControlPackV2Error("tested:candidate-binding")
    expected_conformance = _conformance(descriptor, candidate["stage"], candidate["material"])
    if material["conformance"] != expected_conformance:
        raise IndependentControlPackV2Error("tested:conformance")
    expected_suite_root = _digest("suite-root", expected_conformance)
    if stage["suite_root"] != expected_suite_root or stage["approval_root"] is not None or stage["candidate_root"] != candidate["candidate_root"]:
        raise IndependentControlPackV2Error("tested:roots")
    if stage["stage_time"] != candidate["stage"]["stage_time"]:
        raise IndependentControlPackV2Error("tested:time")
    return {"stage": stage, "material": material}


def _validate_approval(record_value: object, profile: object, descriptor: Mapping[str, object], tested: Mapping[str, object]) -> tuple[dict[str, object], str]:
    record = _expect_keys(record_value, APPROVAL_KEYS, "approval")
    if record["schema"] != APPROVAL_SCHEMA or record["approval_authority_id"] != APPROVAL_AUTHORITY_ID or record["approver_id"] != APPROVER_ID or record["approver_role"] != APPROVER_ROLE or record["approval_reason"] != APPROVAL_REASON:
        raise IndependentControlPackV2Error("approval:authority")
    for key in ("profile_id", "profile_version", "profile_digest", "source_registry_root"):
        expected = descriptor[key if key != "profile_version" else "version"]
        if record[key] != expected:
            raise IndependentControlPackV2Error(f"approval:profile-binding:{key}")
    view = graph_independent._profile_view(profile)
    if (record["provider_graph_subject"], record["scope"]) != (view.subject, view.scope):
        raise IndependentControlPackV2Error("approval:subject")
    _int(record["approval_time"], "approval:time", minimum=1)
    _int(record["profile_version"], "approval:version", minimum=1)
    _hex(record["profile_digest"], "approval:digest")
    _hex(record["source_registry_root"], "approval:source-registry-root")
    for field in ("effective_start", "effective_end"):
        _int(record[field], f"approval:{field}", minimum=1)
    if (record["effective_start"], record["effective_end"]) != (view.effective_start, view.effective_end) or not record["effective_start"] <= record["approval_time"] < record["effective_end"]:
        raise IndependentControlPackV2Error("approval:effective-interval")
    for field in ("approval_id", "tested_stage_id", "tested_stage_root", "suite_root", "synthetic_kat_seal"):
        _hex(record[field], f"approval:{field}")
    supersession = _expect_keys(record["supersession"], {"prior_approval_id", "supersession_sentinel"}, "approval:supersession")
    if supersession["prior_approval_id"] is not None or supersession["supersession_sentinel"] != SUPERSESSION_SENTINEL:
        raise IndependentControlPackV2Error("approval:supersession")
    if (record["tested_stage_id"], record["tested_stage_root"], record["suite_root"]) != (tested["stage"]["stage_id"], tested["stage"]["stage_root"], tested["stage"]["suite_root"]):
        raise IndependentControlPackV2Error("approval:tested-binding")
    core = {key: record[key] for key in APPROVAL_CORE_KEYS}
    if record["approval_id"] != _digest("approval-id", core):
        raise IndependentControlPackV2Error("approval:id")
    if record["synthetic_kat_seal"] != _digest("synthetic-kat-seal", {"approval_id": record["approval_id"], **core}):
        raise IndependentControlPackV2Error("approval:seal")
    return record, _digest("approval-root", {"approval_record": record})


def _validate_approved(stage_value: object, tested: Mapping[str, object], profile: object, descriptor: Mapping[str, object]) -> dict[str, object]:
    stage = _stage_common(stage_value, profile, descriptor, STAGE_APPROVED, tested["stage"])
    material = _expect_keys(stage["material"], {"approval_record"}, "approved:material")
    approval, approval_root = _validate_approval(material["approval_record"], profile, descriptor, tested)
    if stage["approval_root"] != approval_root or stage["candidate_root"] != tested["stage"]["candidate_root"] or stage["suite_root"] != tested["stage"]["suite_root"]:
        raise IndependentControlPackV2Error("approved:root-binding")
    if stage["stage_time"] != approval["approval_time"]:
        raise IndependentControlPackV2Error("approved:time")
    return {"stage": stage, "approval": approval, "approval_root": approval_root}


def _validate_artifact(value: object, profile_registry: Mapping[str, object] | None) -> dict[str, object]:
    item = _expect_keys(value, ARTIFACT_KEYS, "artifact")
    if item["schema"] != SCHEMA:
        raise IndependentControlPackV2Error("artifact:schema")
    profile, descriptor = _configured_profile(item["profile"], profile_registry)
    view = graph_independent._profile_view(profile)
    if item["subject"] != {"provider_graph_subject": view.subject, "scope": view.scope}:
        raise IndependentControlPackV2Error("artifact:subject")
    stages = item["stages"]
    if not isinstance(stages, list) or not 1 <= len(stages) <= MAX_STAGES:
        raise IndependentControlPackV2Error("artifact:stages")
    kinds = [stage.get("stage_kind") for stage in stages if isinstance(stage, dict)]
    if kinds != list(STAGE_KINDS[: len(stages)]):
        raise IndependentControlPackV2Error("artifact:stage-order")
    if item["current_stage_kind"] != kinds[-1] or item["current_stage_id"] != stages[-1].get("stage_id"):
        raise IndependentControlPackV2Error("artifact:current-binding")
    candidate = _validate_candidate(stages[0], profile, descriptor)
    candidate_artifact_id = item["artifact_id"]
    if len(stages) >= 2:
        candidate_prefix = _parse(_prefix_bytes(item, 1))
        candidate_artifact_id = candidate_prefix["artifact_id"]
    tested = _validate_tested(stages[1], candidate | {"artifact_id": candidate_artifact_id}, profile, descriptor) if len(stages) >= 2 else None
    approved = _validate_approved(stages[2], tested, profile, descriptor) if len(stages) == 3 and tested is not None else None
    _hex(item["artifact_id"], "artifact:id")
    _hex(item["chain_root"], "artifact:chain-root")
    if item["chain_root"] != _digest("chain-root", {"stages": stages}):
        raise IndependentControlPackV2Error("artifact:chain-root")
    if {key: item[key] for key in AUTHORITY_FLAGS} != AUTHORITY_FLAGS:
        raise IndependentControlPackV2Error("artifact:authority-flags")
    if item["artifact_id"] != _digest("artifact-id", {key: item[key] for key in item if key != "artifact_id"}):
        raise IndependentControlPackV2Error("artifact:id-mismatch")
    current_stage = approved["stage"] if approved is not None else tested["stage"] if tested is not None else candidate["stage"]
    return {
        "accepted": True,
        "artifact_bytes": len(_canonical(item)),
        "artifact_id": item["artifact_id"],
        "schema": SCHEMA,
        "profile_id": descriptor["profile_id"],
        "profile_version": descriptor["version"],
        "profile_digest": descriptor["profile_digest"],
        "source_registry_root": descriptor["source_registry_root"],
        "current_stage_kind": current_stage["stage_kind"],
        "current_stage_id": current_stage["stage_id"],
        "provider_graph_subject": view.subject,
        "scope": view.scope,
        "effective_start": view.effective_start,
        "effective_end": view.effective_end,
        "approval_id": approved["approval"]["approval_id"] if approved is not None else None,
        "approval_root": approved["approval_root"] if approved is not None else None,
    }


def _prefix_bytes(value: Mapping[str, object], stage_count: int) -> bytes:
    stages = value.get("stages")
    if not isinstance(stages, list) or stage_count not in (1, 2) or len(stages) < stage_count:
        raise IndependentControlPackV2Error("artifact:prior-prefix")
    prefix = list(stages[:stage_count])
    current = prefix[-1]
    if not isinstance(current, dict):
        raise IndependentControlPackV2Error("artifact:prior-prefix")
    body = {
        "schema": value["schema"],
        "profile": value["profile"],
        "subject": value["subject"],
        "stages": prefix,
        "current_stage_kind": current["stage_kind"],
        "current_stage_id": current["stage_id"],
        "chain_root": _digest("chain-root", {"stages": prefix}),
        **AUTHORITY_FLAGS,
    }
    return _canonical({"artifact_id": _digest("artifact-id", body), **body})


def _validate_authorization(record_value: object, profile: object, descriptor: Mapping[str, object], approved: Mapping[str, object], stage: Mapping[str, object], approval: Mapping[str, object]) -> tuple[dict[str, object], str]:
    record = _expect_keys(record_value, AUTHORIZATION_KEYS, "authorization")
    if record["schema"] != AUTHORIZATION_SCHEMA or record["authority_id"] != WITHDRAWAL_AUTHORITY_ID or record["withdrawer_id"] != WITHDRAWER_ID or record["authorized_role"] != WITHDRAWER_ROLE or record["reason_code"] != WITHDRAWAL_REASON or record["terminal_sentinel"] != TERMINAL_SENTINEL:
        raise IndependentControlPackV2Error("authorization:authority")
    for key in ("profile_id", "profile_version", "profile_digest", "source_registry_root"):
        expected = descriptor[key if key != "profile_version" else "version"]
        if record[key] != expected:
            raise IndependentControlPackV2Error(f"authorization:profile-binding:{key}")
    view = graph_independent._profile_view(profile)
    if (record["provider_graph_subject"], record["scope"]) != (view.subject, view.scope):
        raise IndependentControlPackV2Error("authorization:subject")
    for field in ("withdrawal_time", "effective_time", "effective_start", "effective_end"):
        _int(record[field], f"authorization:{field}", minimum=1)
    if record["withdrawal_time"] != record["effective_time"] or record["withdrawal_time"] < record["effective_start"] or record["withdrawal_time"] > record["effective_end"]:
        raise IndependentControlPackV2Error("authorization:effective-time")
    if record["withdrawal_time"] <= approval["approval_time"]:
        raise IndependentControlPackV2Error("authorization:chronology")
    if (record["effective_start"], record["effective_end"]) != (stage["effective_start"], stage["effective_end"]):
        raise IndependentControlPackV2Error("authorization:effective-interval")
    expected_fields = {
        "prior_approved_artifact_id": approved["artifact_id"],
        "prior_approved_stage_id": stage["stage_id"],
        "prior_approved_stage_root": stage["stage_root"],
        "prior_approval_id": approval["approval_id"],
        "prior_approval_root": stage["approval_root"],
        "suite_root": stage["suite_root"],
    }
    for field, expected in expected_fields.items():
        if record[field] != expected:
            raise IndependentControlPackV2Error(f"authorization:binding:{field}")
    for field in ("withdrawal_authorization_id", "prior_approved_artifact_id", "prior_approved_stage_id", "prior_approved_stage_root", "prior_approval_id", "prior_approval_root", "suite_root", "synthetic_kat_seal"):
        _hex(record[field], f"authorization:{field}")
    core = {key: record[key] for key in AUTHORIZATION_CORE_KEYS}
    if record["withdrawal_authorization_id"] != _digest("withdrawal-authorization-id", core):
        raise IndependentControlPackV2Error("authorization:id")
    if record["synthetic_kat_seal"] != _digest("synthetic-kat-seal", {"withdrawal_authorization_id": record["withdrawal_authorization_id"], **core}):
        raise IndependentControlPackV2Error("authorization:seal")
    return record, _digest("withdrawal-authorization-root", {"authorization": record})


def _validate_withdrawal(value: object, profile_registry: Mapping[str, object] | None) -> dict[str, object]:
    item = _expect_keys(value, WITHDRAWAL_KEYS, "withdrawal")
    if item["schema"] != WITHDRAWAL_SCHEMA or item["action"] != ACTION_WITHDRAWN or item["status"] != ACTION_WITHDRAWN or item["origin"] != ORIGIN_MIRROR or item["terminal"] is not True or item["terminal_sentinel"] != TERMINAL_SENTINEL:
        raise IndependentControlPackV2Error("withdrawal:shape")
    profile, descriptor = _configured_profile(item["profile"], profile_registry)
    view = graph_independent._profile_view(profile)
    if (item["provider_graph_subject"], item["scope"]) != (view.subject, view.scope):
        raise IndependentControlPackV2Error("withdrawal:subject")
    if item["source_registry_root"] != descriptor["source_registry_root"]:
        raise IndependentControlPackV2Error("withdrawal:source-registry-root")
    for field in ("effective_start", "effective_end", "effective_time", "withdrawal_time"):
        _int(item[field], f"withdrawal:{field}", minimum=1)
    if (item["effective_start"], item["effective_end"]) != (view.effective_start, view.effective_end) or item["effective_time"] != item["withdrawal_time"]:
        raise IndependentControlPackV2Error("withdrawal:effective-interval")
    approved = item["approved_artifact"]
    approved_raw = _canonical(approved)
    try:
        prior_result = verify_bytes(approved_raw, profile_registry)
    except Exception as exc:
        raise IndependentControlPackV2Error("withdrawal:prior-verify") from exc
    if prior_result.get("schema") != SCHEMA or prior_result.get("current_stage_kind") != STAGE_APPROVED or prior_result.get("profile_id") != descriptor["profile_id"]:
        raise IndependentControlPackV2Error("withdrawal:prior-binding")
    stages = approved.get("stages") if isinstance(approved, dict) else None
    if not isinstance(stages, list) or len(stages) != 3 or not isinstance(stages[-1], dict):
        raise IndependentControlPackV2Error("withdrawal:prior-stage")
    stage = _expect_keys(stages[-1], STAGE_KEYS, "withdrawal:approved-stage")
    material = _expect_keys(stage["material"], {"approval_record"}, "withdrawal:approved-material")
    approval = _expect_keys(material["approval_record"], APPROVAL_KEYS, "withdrawal:approval")
    if (item["approved_artifact_id"], item["approved_stage_id"], item["approved_stage_root"], item["approval_id"], item["approval_root"], item["suite_root"]) != (
        approved["artifact_id"], stage["stage_id"], stage["stage_root"], approval["approval_id"], stage["approval_root"], stage["suite_root"]
    ):
        raise IndependentControlPackV2Error("withdrawal:approval-binding")
    _hex(item["approved_artifact_id"], "withdrawal:approved-artifact-id")
    _hex(item["approved_artifact_sha3_512"], "withdrawal:approved-artifact-sha")
    if item["approved_artifact_sha3_512"] != _bytes_digest("approved-artifact", approved_raw):
        raise IndependentControlPackV2Error("withdrawal:prior-bytes")
    if item["authority_profile_root"] != _digest("authority-profile-root", AUTHORITY_FLAGS) or {key: item[key] for key in AUTHORITY_FLAGS} != AUTHORITY_FLAGS:
        raise IndependentControlPackV2Error("withdrawal:authority-flags")
    authorization, authorization_root = _validate_authorization(item["withdrawal_authorization"], profile, descriptor, approved, stage, approval)
    if item["withdrawal_authorization_id"] != authorization["withdrawal_authorization_id"] or item["withdrawal_authorization_root"] != authorization_root or item["withdrawal_time"] != authorization["withdrawal_time"] or item["effective_time"] != authorization["effective_time"]:
        raise IndependentControlPackV2Error("withdrawal:authorization-binding")
    for field in ("artifact_id", "withdrawal_id", "withdrawal_root", "withdrawal_authorization_id", "withdrawal_authorization_root", "approval_id", "approval_root", "suite_root"):
        _hex(item[field], f"withdrawal:{field}")
    if item["withdrawal_root"] != _digest("withdrawal-root", {key: item[key] for key in item if key not in {"artifact_id", "withdrawal_id", "withdrawal_root"}}):
        raise IndependentControlPackV2Error("withdrawal:root")
    if item["withdrawal_id"] != _digest("withdrawal-id", {"action": ACTION_WITHDRAWN, "withdrawal_root": item["withdrawal_root"]}):
        raise IndependentControlPackV2Error("withdrawal:id")
    if item["artifact_id"] != _digest("artifact-id", {key: item[key] for key in item if key != "artifact_id"}):
        raise IndependentControlPackV2Error("withdrawal:artifact-id")
    return {
        "accepted": True,
        "artifact_bytes": len(_canonical(item)),
        "artifact_id": item["artifact_id"],
        "schema": WITHDRAWAL_SCHEMA,
        "profile_id": descriptor["profile_id"],
        "profile_version": descriptor["version"],
        "profile_digest": descriptor["profile_digest"],
        "source_registry_root": descriptor["source_registry_root"],
        "current_stage_kind": ACTION_WITHDRAWN,
        "current_stage_id": item["withdrawal_id"],
        "provider_graph_subject": view.subject,
        "scope": view.scope,
        "effective_start": view.effective_start,
        "effective_end": view.effective_end,
        "approval_id": approval["approval_id"],
        "approval_root": stage["approval_root"],
        "withdrawal_time": item["withdrawal_time"],
    }


def verify_bytes(raw: bytes, profile_registry: Mapping[str, object] | None = None) -> dict[str, object]:
    value = _parse(raw)
    if value.get("schema") == SCHEMA:
        return _validate_artifact(value, profile_registry)
    if value.get("schema") == WITHDRAWAL_SCHEMA:
        return _validate_withdrawal(value, profile_registry)
    raise IndependentControlPackV2Error("artifact:schema")


def prefix_bytes(value: Mapping[str, object], stage_count: int) -> bytes:
    """Reconstruct a V2 prior prefix for the independent store verifier."""

    return _prefix_bytes(value, stage_count)


def verify_file(path: str | Path, profile_registry: Mapping[str, object] | None = None) -> dict[str, object]:
    file_path = Path(path)
    if file_path.stat().st_size > MAX_ARTIFACT_BYTES:
        raise IndependentControlPackV2Error("file:byte-cap")
    with file_path.open("rb") as handle:
        raw = handle.read(MAX_ARTIFACT_BYTES + 1)
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise IndependentControlPackV2Error("file:byte-cap")
    return verify_bytes(raw, profile_registry)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(0)
