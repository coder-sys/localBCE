"""Synthetic, observation-only multi-profile Provider Continuity Control Pack V2.

V2 is an explicit governance envelope around the existing independently verified
Provider Trust Graph V2 artifact.  The configured ``SourceProfile`` is the
authority for every profile value; bytes supplied by an adapter or approval
caller are evidence and never select a profile, verifier, or completeness
policy.  This module is synthetic-only and is not a production signature or
source-authentication implementation.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
from typing import Mapping

from app.mirror import provider_trust_graph_independent as graph_independent


class ControlPackV2Error(ValueError):
    """Raised for malformed, substituted, or semantically invalid V2 evidence."""


SCHEMA = "provider-continuity-control-pack-v2"
WITHDRAWAL_SCHEMA = "provider-continuity-control-pack-withdrawal-v2"
APPROVAL_SCHEMA = "provider-continuity-state-approval-v2"
AUTHORIZATION_SCHEMA = "provider-continuity-withdrawal-authorization-v2"
SCOPE_PREFIX = "synthetic"
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
MAX_AUTHORIZATION_BYTES = 16_384
MAX_STRING_BYTES = 256
MAX_NODES = 16_384
MAX_DEPTH = 24
MAX_TIMESTAMP = 2_147_483_647
MAX_STAGES = 3
_HEX = "0123456789abcdef"

PROFILE_KEYS = {
    "profile_id",
    "version",
    "profile_digest",
    "source_registry_root",
    "verifier_id",
    "verifier_epoch",
    "evidence_mode",
    "require_complete",
    "allow_nonmembership",
}
STAGE_KEYS = {
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
    "source_registry_root",
    "candidate_root",
    "suite_root",
    "approval_root",
    "material",
}
ARTIFACT_KEYS = {
    "artifact_id",
    "schema",
    "profile",
    "subject",
    "stages",
    "current_stage_kind",
    "current_stage_id",
    "chain_root",
    *AUTHORITY_FLAGS.keys(),
}
APPROVAL_KEYS = {
    "schema",
    "approval_id",
    "approval_authority_id",
    "approver_id",
    "approver_role",
    "approval_reason",
    "approval_time",
    "profile_id",
    "profile_version",
    "profile_digest",
    "source_registry_root",
    "provider_graph_subject",
    "scope",
    "effective_start",
    "effective_end",
    "tested_stage_id",
    "tested_stage_root",
    "suite_root",
    "supersession",
    "synthetic_kat_seal",
}
APPROVAL_CORE_KEYS = APPROVAL_KEYS - {"approval_id", "synthetic_kat_seal"}
APPROVAL_SUPERSESSION_KEYS = {"prior_approval_id", "supersession_sentinel"}
AUTHORIZATION_KEYS = {
    "schema",
    "authority_id",
    "withdrawer_id",
    "authorized_role",
    "reason_code",
    "withdrawal_time",
    "effective_time",
    "profile_id",
    "profile_version",
    "profile_digest",
    "source_registry_root",
    "provider_graph_subject",
    "scope",
    "effective_start",
    "effective_end",
    "prior_approved_artifact_id",
    "prior_approved_stage_id",
    "prior_approved_stage_root",
    "prior_approval_id",
    "prior_approval_root",
    "suite_root",
    "terminal_sentinel",
    "withdrawal_authorization_id",
    "synthetic_kat_seal",
}
AUTHORIZATION_CORE_KEYS = AUTHORIZATION_KEYS - {"withdrawal_authorization_id", "synthetic_kat_seal"}
WITHDRAWAL_KEYS = {
    "artifact_id",
    "schema",
    "action",
    "status",
    "profile",
    "approval_id",
    "approval_root",
    "approved_artifact",
    "approved_artifact_id",
    "approved_artifact_sha3_512",
    "approved_stage_id",
    "approved_stage_root",
    "authority_profile_root",
    "effective_end",
    "effective_start",
    "effective_time",
    "origin",
    "provider_graph_subject",
    "scope",
    "source_registry_root",
    "suite_root",
    "terminal",
    "terminal_sentinel",
    "withdrawal_authorization",
    "withdrawal_authorization_id",
    "withdrawal_authorization_root",
    "withdrawal_time",
    "withdrawal_id",
    "withdrawal_root",
    *AUTHORITY_FLAGS.keys(),
}


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise ControlPackV2Error("json:noncanonical-value") from exc


def _duplicate_reject(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ControlPackV2Error("json:duplicate-key")
        result[key] = value
    return result


def _walk(value: object, depth: int = 0, count: list[int] | None = None) -> None:
    count = [0] if count is None else count
    count[0] += 1
    if count[0] > MAX_NODES:
        raise ControlPackV2Error("json:node-cap")
    if depth > MAX_DEPTH:
        raise ControlPackV2Error("json:depth-cap")
    if isinstance(value, float):
        raise ControlPackV2Error("json:float-forbidden")
    if isinstance(value, str):
        try:
            if len(value.encode("ascii")) > MAX_STRING_BYTES:
                raise ControlPackV2Error("json:string-cap")
        except UnicodeEncodeError as exc:
            raise ControlPackV2Error("json:non-ascii") from exc
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ControlPackV2Error("json:key-type")
            _walk(key, depth + 1, count)
            _walk(item, depth + 1, count)
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth + 1, count)


def _parse(raw: bytes, *, artifact: bool = True) -> dict[str, object]:
    maximum = MAX_ARTIFACT_BYTES if artifact else MAX_INPUT_BYTES
    if type(raw) is not bytes or not raw or len(raw) > maximum:
        raise ControlPackV2Error("json:byte-cap")
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_duplicate_reject, parse_constant=lambda _value: (_ for _ in ()).throw(ControlPackV2Error("json:constant-forbidden")))
    except ControlPackV2Error:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ControlPackV2Error("json:parse") from exc
    if not isinstance(value, dict):
        raise ControlPackV2Error("json:top-level")
    _walk(value)
    if _canonical(value) != raw:
        raise ControlPackV2Error("json:not-canonical")
    return value


def canonical_bytes(value: Mapping[str, object]) -> bytes:
    if not isinstance(value, dict):
        raise ControlPackV2Error("json:top-level")
    _walk(value)
    raw = _canonical(value)
    if len(raw) > MAX_INPUT_BYTES:
        raise ControlPackV2Error("json:byte-cap")
    return raw


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
        raise ControlPackV2Error(f"{label}:schema")
    return value


def _text(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise ControlPackV2Error(f"{label}:text")
    try:
        if len(value.encode("ascii")) > MAX_STRING_BYTES:
            raise ControlPackV2Error(f"{label}:length")
    except UnicodeEncodeError as exc:
        raise ControlPackV2Error(f"{label}:ascii") from exc
    return value


def _int(value: object, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= MAX_TIMESTAMP:
        raise ControlPackV2Error(f"{label}:integer")
    return value


def _bool(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise ControlPackV2Error(f"{label}:boolean")
    return value


def _hex(value: object, label: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if type(value) is not str or len(value) != 128 or any(char not in _HEX for char in value):
        raise ControlPackV2Error(f"{label}:hex")
    return value


def _profile_material(profile: object) -> dict[str, object]:
    try:
        graph_independent._profile_view(profile)
        material = graph_independent._profile_material(profile)
        return material
    except Exception as exc:
        raise ControlPackV2Error("profile:configuration") from exc


def _source_registry_root(material: Mapping[str, object]) -> str:
    source_material = {
        key: material[key]
        for key in (
            "profile_id",
            "version",
            "subject",
            "scope",
            "observation_window",
            "effective_start",
            "effective_end",
            "source_roles",
            "require_complete",
            "credential_id",
            "enrollment_id",
            "allow_nonmembership",
            "canonical_order",
            "root_rule",
        )
    }
    return _digest("source-registry-root", source_material)


def profile_descriptor(profile: object) -> dict[str, object]:
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


def _profile_descriptor_check(value: Mapping[str, object], profile: object) -> dict[str, object]:
    descriptor = _expect_keys(value, PROFILE_KEYS, "profile")
    expected = profile_descriptor(profile)
    for key, expected_value in expected.items():
        if descriptor.get(key) != expected_value:
            raise ControlPackV2Error(f"profile:binding:{key}")
    _text(descriptor["profile_id"], "profile:id")
    _int(descriptor["version"], "profile:version", minimum=1)
    _hex(descriptor["profile_digest"], "profile:digest")
    _hex(descriptor["source_registry_root"], "profile:source-registry-root")
    _text(descriptor["verifier_id"], "profile:verifier-id")
    _int(descriptor["verifier_epoch"], "profile:verifier-epoch", minimum=1)
    _text(descriptor["evidence_mode"], "profile:evidence-mode")
    _bool(descriptor["require_complete"], "profile:require-complete")
    _bool(descriptor["allow_nonmembership"], "profile:allow-nonmembership")
    return dict(descriptor)


def _profile_for(profile: object) -> tuple[dict[str, object], dict[str, object]]:
    descriptor = profile_descriptor(profile)
    view = graph_independent._profile_view(profile)
    return descriptor, {
        "provider_graph_subject": view.subject,
        "scope": view.scope,
    }


def _graph_evidence(graph_raw: bytes, profile: object) -> tuple[dict[str, object], dict[str, object]]:
    descriptor, subject = _profile_for(profile)
    registry = {str(descriptor["profile_id"]): profile}
    try:
        result = graph_independent.verify_bytes_v2(graph_raw, registry)
        graph_value = graph_independent._parse(graph_raw)
    except Exception as exc:
        raise ControlPackV2Error(f"graph:independent-reject:{type(exc).__name__}") from exc
    if result.get("profile_id") != descriptor["profile_id"] or result.get("profile_digest") != descriptor["profile_digest"]:
        raise ControlPackV2Error("graph:profile-binding")
    if graph_value.get("subject") != subject:
        raise ControlPackV2Error("graph:subject-binding")
    graph_profile = _expect_keys(graph_value.get("profile"), graph_independent.PROFILE_KEYS, "graph:profile")
    if graph_profile != {key: graph_profile[key] for key in graph_independent.PROFILE_KEYS}:
        raise ControlPackV2Error("graph:profile-shape")
    return graph_value, result


def _stage_with_ids(body: Mapping[str, object]) -> dict[str, object]:
    body_copy = deepcopy(dict(body))
    stage_root = _digest("stage-root", body_copy)
    stage_id = _digest("stage-id", {"stage_kind": body_copy["stage_kind"], "stage_root": stage_root})
    return {"stage_id": stage_id, "stage_root": stage_root, **body_copy}


def _artifact(profile_descriptor_value: Mapping[str, object], stages: list[Mapping[str, object]], *, schema: str = SCHEMA) -> dict[str, object]:
    stages_copy = deepcopy(stages)
    current = stages_copy[-1]
    body: dict[str, object] = {
        "schema": schema,
        "profile": deepcopy(dict(profile_descriptor_value)),
        "subject": {
            "provider_graph_subject": current["provider_graph_subject"],
            "scope": current["scope"],
        },
        "stages": stages_copy,
        "current_stage_kind": current["stage_kind"],
        "current_stage_id": current["stage_id"],
        "chain_root": _digest("chain-root", {"stages": stages_copy}),
        **deepcopy(AUTHORITY_FLAGS),
    }
    return {"artifact_id": _digest("artifact-id", body), **body}


def _encode_artifact(value: Mapping[str, object]) -> bytes:
    _walk(value)
    raw = _canonical(value)
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise ControlPackV2Error("artifact:byte-cap")
    return raw


def _candidate_root(profile_value: Mapping[str, object], origin: str, material: Mapping[str, object]) -> str:
    return _digest(
        "candidate-root",
        {
            "profile": dict(profile_value),
            "subject": {"provider_graph_subject": material["provider_graph_subject"], "scope": material["scope"]},
            "origin": origin,
            "material": dict(material),
        },
    )


def _load_verified(raw: bytes, profile: object, expected_stage: str) -> dict[str, object]:
    descriptor = profile_descriptor(profile)
    try:
        result = independent_verify(raw, {str(descriptor["profile_id"]): profile})
    except Exception as exc:
        raise ControlPackV2Error(f"promotion:verify:{type(exc).__name__}") from exc
    if result.get("current_stage_kind") != expected_stage:
        raise ControlPackV2Error(f"promotion:expected-{expected_stage.lower()}")
    value = _parse(raw)
    _profile_descriptor_check(value["profile"], profile)
    return value


def _candidate_material(value: Mapping[str, object]) -> dict[str, object]:
    stages = value.get("stages")
    if not isinstance(stages, list) or not stages or not isinstance(stages[0], dict):
        raise ControlPackV2Error("candidate:stage")
    material = _expect_keys(stages[0].get("material"), {"graph_artifact", "graph_report_id", "graph_snapshot_id", "graph_snapshot_root", "observation_time"}, "candidate:material")
    return material


def _conformance(profile_value: Mapping[str, object], candidate_stage: Mapping[str, object], material: Mapping[str, object]) -> dict[str, object]:
    return {
        "schema": SCHEMA,
        "suite_id": "SYNTH_PROVIDER_CONTINUITY_CONFORMANCE_SUITE_V2",
        "suite_version": 1,
        "profile_digest": profile_value["profile_digest"],
        "source_registry_root": profile_value["source_registry_root"],
        "candidate_root": candidate_stage["candidate_root"],
        "graph_report_id": material["graph_report_id"],
        "graph_snapshot_id": material["graph_snapshot_id"],
        "graph_snapshot_root": material["graph_snapshot_root"],
        "predicates": ["PROFILE_BINDING_V2", "GRAPH_INDEPENDENT_V2", "OBSERVATION_ONLY_FLAGS_V2"],
    }


def _approval_record(raw: bytes, profile: object, tested: Mapping[str, object]) -> tuple[dict[str, object], str]:
    record = _expect_keys(_parse(raw, artifact=False), APPROVAL_KEYS, "approval")
    descriptor = profile_descriptor(profile)
    for field in ("schema", "approval_authority_id", "approver_id", "approver_role", "approval_reason", "profile_id", "provider_graph_subject", "scope"):
        _text(record[field], f"approval:{field}")
    if record["schema"] != APPROVAL_SCHEMA or record["approval_authority_id"] != APPROVAL_AUTHORITY_ID or record["approver_id"] != APPROVER_ID or record["approver_role"] != APPROVER_ROLE or record["approval_reason"] != APPROVAL_REASON:
        raise ControlPackV2Error("approval:authority")
    if record["profile_id"] != descriptor["profile_id"] or record["profile_version"] != descriptor["version"] or record["profile_digest"] != descriptor["profile_digest"] or record["source_registry_root"] != descriptor["source_registry_root"]:
        raise ControlPackV2Error("approval:profile-binding")
    if record["provider_graph_subject"] != tested["provider_graph_subject"] or record["scope"] != tested["scope"]:
        raise ControlPackV2Error("approval:subject-binding")
    _int(record["approval_time"], "approval:time", minimum=1)
    _int(record["profile_version"], "approval:version", minimum=1)
    _hex(record["profile_digest"], "approval:digest")
    _hex(record["source_registry_root"], "approval:source-registry-root")
    for field in ("effective_start", "effective_end"):
        _int(record[field], f"approval:{field}", minimum=1)
    if (record["effective_start"], record["effective_end"]) != (tested["effective_start"], tested["effective_end"]):
        raise ControlPackV2Error("approval:effective-interval")
    if not record["effective_start"] <= record["approval_time"] < record["effective_end"]:
        raise ControlPackV2Error("approval:chronology")
    for field in ("approval_id", "tested_stage_id", "tested_stage_root", "suite_root", "synthetic_kat_seal"):
        _hex(record[field], f"approval:{field}")
    supersession = _expect_keys(record["supersession"], APPROVAL_SUPERSESSION_KEYS, "approval:supersession")
    if supersession["prior_approval_id"] is not None or supersession["supersession_sentinel"] != SUPERSESSION_SENTINEL:
        raise ControlPackV2Error("approval:supersession")
    if record["tested_stage_id"] != tested["stage_id"] or record["tested_stage_root"] != tested["stage_root"] or record["suite_root"] != tested["suite_root"]:
        raise ControlPackV2Error("approval:tested-binding")
    core = {key: record[key] for key in APPROVAL_CORE_KEYS}
    if record["approval_id"] != _digest("approval-id", core):
        raise ControlPackV2Error("approval:id")
    if record["synthetic_kat_seal"] != _digest("synthetic-kat-seal", {"approval_id": record["approval_id"], **core}):
        raise ControlPackV2Error("approval:seal")
    return record, _digest("approval-root", {"approval_record": record})


def build_candidate(graph_raw: bytes, profile: object, *, origin: str = ORIGIN_MIRROR) -> tuple[bytes, dict[str, object]]:
    """Bind one independently verified V2 graph to a configured profile."""

    if origin != ORIGIN_MIRROR:
        raise ControlPackV2Error("candidate:origin")
    descriptor, subject = _profile_for(profile)
    graph_value, _result = _graph_evidence(graph_raw, profile)
    snapshot = _expect_keys(graph_value["observation_snapshot"], {"snapshot_id", "snapshot_root", "observation_time"}, "graph:snapshot")
    material: dict[str, object] = {
        "graph_artifact": deepcopy(graph_value),
        "graph_report_id": graph_value["report"]["report_id"],
        "graph_snapshot_id": snapshot["snapshot_id"],
        "graph_snapshot_root": snapshot["snapshot_root"],
        "observation_time": snapshot["observation_time"],
        "provider_graph_subject": subject["provider_graph_subject"],
        "scope": subject["scope"],
    }
    body = {
        "stage_kind": STAGE_CANDIDATE,
        "prior_stage_id": STAGE_SENTINEL,
        "prior_stage_root": None,
        "stage_time": snapshot["observation_time"],
        "provider_graph_subject": subject["provider_graph_subject"],
        "scope": subject["scope"],
        "effective_start": getattr(profile, "effective_start"),
        "effective_end": getattr(profile, "effective_end"),
        "origin": origin,
        "status": STAGE_CANDIDATE,
        "source_registry_root": descriptor["source_registry_root"],
        "candidate_root": _candidate_root(descriptor, origin, material),
        "suite_root": None,
        "approval_root": None,
        "material": {key: value for key, value in material.items() if key not in {"provider_graph_subject", "scope"}},
    }
    stage = _stage_with_ids(body)
    raw = _encode_artifact(_artifact(descriptor, [stage]))
    try:
        independent_verify(raw, {str(descriptor["profile_id"]): profile})
    except Exception as exc:
        raise ControlPackV2Error(f"candidate:independent-reject:{type(exc).__name__}") from exc
    return raw, {"artifact_bytes": len(raw), "profile_id": descriptor["profile_id"], "production_usable": False}


def build_tested(candidate_raw: bytes, profile: object) -> tuple[bytes, dict[str, object]]:
    descriptor = profile_descriptor(profile)
    candidate = _load_verified(candidate_raw, profile, STAGE_CANDIDATE)
    stage = _expect_keys(candidate["stages"][0], STAGE_KEYS, "candidate:stage")
    material = _candidate_material(candidate)
    conformance = _conformance(descriptor, stage, material)
    body = {
        "stage_kind": STAGE_TESTED,
        "prior_stage_id": stage["stage_id"],
        "prior_stage_root": stage["stage_root"],
        "stage_time": stage["stage_time"],
        "provider_graph_subject": stage["provider_graph_subject"],
        "scope": stage["scope"],
        "effective_start": stage["effective_start"],
        "effective_end": stage["effective_end"],
        "origin": stage["origin"],
        "status": STAGE_TESTED,
        "source_registry_root": descriptor["source_registry_root"],
        "candidate_root": stage["candidate_root"],
        "suite_root": _digest("suite-root", conformance),
        "approval_root": None,
        "material": {
            "candidate_artifact_id": candidate["artifact_id"],
            "candidate_stage_id": stage["stage_id"],
            "candidate_stage_root": stage["stage_root"],
            "conformance": conformance,
        },
    }
    tested = _stage_with_ids(body)
    raw = _encode_artifact(_artifact(descriptor, [stage, tested]))
    independent_verify(raw, {str(descriptor["profile_id"]): profile})
    return raw, {"artifact_bytes": len(raw), "profile_id": descriptor["profile_id"], "production_usable": False}


def build_approval_record(tested_raw: bytes, profile: object, *, approval_time: int | None = None) -> bytes:
    descriptor = profile_descriptor(profile)
    tested = _load_verified(tested_raw, profile, STAGE_TESTED)
    stage = _expect_keys(tested["stages"][-1], STAGE_KEYS, "tested:stage")
    if approval_time is None:
        approval_time = min(int(stage["effective_end"]) - 1, int(stage["stage_time"]) + 100)
    _int(approval_time, "approval:time", minimum=1)
    record: dict[str, object] = {
        "schema": APPROVAL_SCHEMA,
        "approval_authority_id": APPROVAL_AUTHORITY_ID,
        "approver_id": APPROVER_ID,
        "approver_role": APPROVER_ROLE,
        "approval_reason": APPROVAL_REASON,
        "approval_time": approval_time,
        "profile_id": descriptor["profile_id"],
        "profile_version": descriptor["version"],
        "profile_digest": descriptor["profile_digest"],
        "source_registry_root": descriptor["source_registry_root"],
        "provider_graph_subject": stage["provider_graph_subject"],
        "scope": stage["scope"],
        "effective_start": stage["effective_start"],
        "effective_end": stage["effective_end"],
        "tested_stage_id": stage["stage_id"],
        "tested_stage_root": stage["stage_root"],
        "suite_root": stage["suite_root"],
        "supersession": {"prior_approval_id": None, "supersession_sentinel": SUPERSESSION_SENTINEL},
    }
    record["approval_id"] = _digest("approval-id", {key: record[key] for key in APPROVAL_CORE_KEYS})
    record["synthetic_kat_seal"] = _digest("synthetic-kat-seal", {"approval_id": record["approval_id"], **{key: record[key] for key in APPROVAL_CORE_KEYS}})
    raw = canonical_bytes(record)
    _approval_record(raw, profile, stage)
    return raw


def build_approved(tested_raw: bytes, approval_record_raw: bytes, profile: object) -> tuple[bytes, dict[str, object]]:
    descriptor = profile_descriptor(profile)
    tested = _load_verified(tested_raw, profile, STAGE_TESTED)
    stages = tested["stages"]
    stage = _expect_keys(stages[-1], STAGE_KEYS, "tested:stage")
    approval, approval_root = _approval_record(approval_record_raw, profile, stage)
    body = {
        "stage_kind": STAGE_APPROVED,
        "prior_stage_id": stage["stage_id"],
        "prior_stage_root": stage["stage_root"],
        "stage_time": approval["approval_time"],
        "provider_graph_subject": stage["provider_graph_subject"],
        "scope": stage["scope"],
        "effective_start": stage["effective_start"],
        "effective_end": stage["effective_end"],
        "origin": stage["origin"],
        "status": STAGE_APPROVED,
        "source_registry_root": descriptor["source_registry_root"],
        "candidate_root": stage["candidate_root"],
        "suite_root": stage["suite_root"],
        "approval_root": approval_root,
        "material": {"approval_record": approval},
    }
    approved_stage = _stage_with_ids(body)
    raw = _encode_artifact(_artifact(descriptor, [*stages, approved_stage]))
    independent_verify(raw, {str(descriptor["profile_id"]): profile})
    return raw, {"artifact_bytes": len(raw), "profile_id": descriptor["profile_id"], "production_usable": False}


def _approved_material(approved_raw: bytes, profile: object) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    approved = _load_verified(approved_raw, profile, STAGE_APPROVED)
    stages = approved["stages"]
    stage = _expect_keys(stages[-1], STAGE_KEYS, "approved:stage")
    material = _expect_keys(stage["material"], {"approval_record"}, "approved:material")
    approval = _expect_keys(material["approval_record"], APPROVAL_KEYS, "approved:record")
    return approved, stage, approval


def _authorization_record(raw: bytes, profile: object, approved: Mapping[str, object], stage: Mapping[str, object], approval: Mapping[str, object]) -> tuple[dict[str, object], str]:
    record = _expect_keys(_parse(raw, artifact=False), AUTHORIZATION_KEYS, "authorization")
    descriptor = profile_descriptor(profile)
    for field in ("schema", "authority_id", "withdrawer_id", "authorized_role", "reason_code", "profile_id", "provider_graph_subject", "scope", "terminal_sentinel"):
        _text(record[field], f"authorization:{field}")
    if record["schema"] != AUTHORIZATION_SCHEMA or record["authority_id"] != WITHDRAWAL_AUTHORITY_ID or record["withdrawer_id"] != WITHDRAWER_ID or record["authorized_role"] != WITHDRAWER_ROLE or record["reason_code"] != WITHDRAWAL_REASON or record["terminal_sentinel"] != TERMINAL_SENTINEL:
        raise ControlPackV2Error("authorization:authority")
    for key in ("profile_id", "profile_version", "profile_digest", "source_registry_root"):
        expected = descriptor["profile_id" if key == "profile_id" else "version" if key == "profile_version" else key]
        if record[key] != expected:
            raise ControlPackV2Error(f"authorization:profile-binding:{key}")
    if (record["provider_graph_subject"], record["scope"]) != (approved["subject"]["provider_graph_subject"], approved["subject"]["scope"]):
        raise ControlPackV2Error("authorization:subject-binding")
    for field in ("withdrawal_time", "effective_time", "effective_start", "effective_end"):
        _int(record[field], f"authorization:{field}", minimum=1)
    if record["withdrawal_time"] != record["effective_time"] or not record["effective_start"] <= record["withdrawal_time"] <= record["effective_end"]:
        raise ControlPackV2Error("authorization:effective-time")
    if record["withdrawal_time"] <= approval["approval_time"]:
        raise ControlPackV2Error("authorization:chronology")
    if (record["effective_start"], record["effective_end"]) != (stage["effective_start"], stage["effective_end"]):
        raise ControlPackV2Error("authorization:effective-interval")
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
            raise ControlPackV2Error(f"authorization:binding:{field}")
    for field in ("withdrawal_authorization_id", "prior_approved_artifact_id", "prior_approved_stage_id", "prior_approved_stage_root", "prior_approval_id", "prior_approval_root", "suite_root", "synthetic_kat_seal"):
        _hex(record[field], f"authorization:{field}")
    core = {key: record[key] for key in AUTHORIZATION_CORE_KEYS}
    if record["withdrawal_authorization_id"] != _digest("withdrawal-authorization-id", core):
        raise ControlPackV2Error("authorization:id")
    if record["synthetic_kat_seal"] != _digest("synthetic-kat-seal", {"withdrawal_authorization_id": record["withdrawal_authorization_id"], **core}):
        raise ControlPackV2Error("authorization:seal")
    return record, _digest("withdrawal-authorization-root", {"authorization": record})


def build_withdrawal_authorization(approved_raw: bytes, profile: object, *, withdrawal_time: int | None = None) -> bytes:
    approved, stage, approval = _approved_material(approved_raw, profile)
    descriptor = profile_descriptor(profile)
    if withdrawal_time is None:
        withdrawal_time = min(int(stage["effective_end"]), int(approval["approval_time"]) + 100)
    record: dict[str, object] = {
        "schema": AUTHORIZATION_SCHEMA,
        "authority_id": WITHDRAWAL_AUTHORITY_ID,
        "withdrawer_id": WITHDRAWER_ID,
        "authorized_role": WITHDRAWER_ROLE,
        "reason_code": WITHDRAWAL_REASON,
        "withdrawal_time": withdrawal_time,
        "effective_time": withdrawal_time,
        "profile_id": descriptor["profile_id"],
        "profile_version": descriptor["version"],
        "profile_digest": descriptor["profile_digest"],
        "source_registry_root": descriptor["source_registry_root"],
        "provider_graph_subject": approved["subject"]["provider_graph_subject"],
        "scope": approved["subject"]["scope"],
        "effective_start": stage["effective_start"],
        "effective_end": stage["effective_end"],
        "prior_approved_artifact_id": approved["artifact_id"],
        "prior_approved_stage_id": stage["stage_id"],
        "prior_approved_stage_root": stage["stage_root"],
        "prior_approval_id": approval["approval_id"],
        "prior_approval_root": stage["approval_root"],
        "suite_root": stage["suite_root"],
        "terminal_sentinel": TERMINAL_SENTINEL,
    }
    record["withdrawal_authorization_id"] = _digest("withdrawal-authorization-id", {key: record[key] for key in AUTHORIZATION_CORE_KEYS})
    record["synthetic_kat_seal"] = _digest("synthetic-kat-seal", {"withdrawal_authorization_id": record["withdrawal_authorization_id"], **{key: record[key] for key in AUTHORIZATION_CORE_KEYS}})
    raw = canonical_bytes(record)
    _authorization_record(raw, profile, approved, stage, approval)
    return raw


def _withdrawal_body(value: Mapping[str, object]) -> dict[str, object]:
    return {key: item for key, item in value.items() if key not in {"artifact_id", "withdrawal_id", "withdrawal_root"}}


def build_withdrawal(approved_raw: bytes, authorization_raw: bytes, profile: object) -> tuple[bytes, dict[str, object]]:
    approved, stage, approval = _approved_material(approved_raw, profile)
    descriptor = profile_descriptor(profile)
    authorization, authorization_root = _authorization_record(authorization_raw, profile, approved, stage, approval)
    body: dict[str, object] = {
        "schema": WITHDRAWAL_SCHEMA,
        "action": ACTION_WITHDRAWN,
        "status": ACTION_WITHDRAWN,
        "profile": descriptor,
        "approval_id": approval["approval_id"],
        "approval_root": stage["approval_root"],
        "approved_artifact": deepcopy(approved),
        "approved_artifact_id": approved["artifact_id"],
        "approved_artifact_sha3_512": _bytes_digest("approved-artifact", approved_raw),
        "approved_stage_id": stage["stage_id"],
        "approved_stage_root": stage["stage_root"],
        "authority_profile_root": _digest("authority-profile-root", AUTHORITY_FLAGS),
        "effective_end": stage["effective_end"],
        "effective_start": stage["effective_start"],
        "effective_time": authorization["effective_time"],
        "origin": ORIGIN_MIRROR,
        "provider_graph_subject": approved["subject"]["provider_graph_subject"],
        "scope": approved["subject"]["scope"],
        "source_registry_root": descriptor["source_registry_root"],
        "suite_root": stage["suite_root"],
        "terminal": True,
        "terminal_sentinel": TERMINAL_SENTINEL,
        "withdrawal_authorization": authorization,
        "withdrawal_authorization_id": authorization["withdrawal_authorization_id"],
        "withdrawal_authorization_root": authorization_root,
        "withdrawal_time": authorization["withdrawal_time"],
        **deepcopy(AUTHORITY_FLAGS),
    }
    body["withdrawal_root"] = _digest("withdrawal-root", _withdrawal_body(body))
    body["withdrawal_id"] = _digest("withdrawal-id", {"action": ACTION_WITHDRAWN, "withdrawal_root": body["withdrawal_root"]})
    body["artifact_id"] = _digest("artifact-id", {key: value for key, value in body.items() if key != "artifact_id"})
    raw = _encode_artifact(body)
    independent_verify(raw, {str(descriptor["profile_id"]): profile})
    return raw, {"artifact_bytes": len(raw), "profile_id": descriptor["profile_id"], "production_usable": False}


def independent_verify(raw: bytes, profile_registry: Mapping[str, object]) -> dict[str, object]:
    """Call the separate verifier without exposing its implementation here."""

    from app.governance import provider_continuity_control_pack_v2_independent as independent

    return independent.verify_bytes(raw, profile_registry)


def main() -> int:
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
