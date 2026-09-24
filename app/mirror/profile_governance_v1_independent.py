"""Independent verifier for the synthetic Mirror profile-governance grammar.

This module intentionally does not import the producer.  It duplicates the
canonical encoding, profile commitment, lifecycle, approval, and withdrawal
checks and accepts only a caller-supplied configured profile registry.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Mapping, Sequence

from app.mirror import provider_trust_graph_independent as graph


class IndependentProfileGovernanceError(ValueError):
    """Raised when a governance artifact cannot be reconstructed."""


SCHEMA = "mirror-profile-governance-v1"
WITHDRAWAL_SCHEMA = "mirror-profile-governance-withdrawal-v1"
APPROVAL_SCHEMA = "mirror-profile-governance-approval-v1"
AUTHORIZATION_SCHEMA = "mirror-profile-governance-withdrawal-authorization-v1"
STAGE_CANDIDATE = "CANDIDATE"
STAGE_TESTED = "TESTED"
STAGE_APPROVED = "APPROVED_OBSERVATION_ONLY"
STAGE_KINDS = (STAGE_CANDIDATE, STAGE_TESTED, STAGE_APPROVED)
STAGE_SENTINEL = "NONE"
ACTION_WITHDRAWN = "WITHDRAWN_OBSERVATION_ONLY"
ORIGIN_MIRROR = "MIRROR_PROFILE_EVIDENCE_V1"
TERMINAL_SENTINEL = "TERMINAL_NO_REACTIVATION_OR_SUPERSESSION_V1"
SUPERSESSION_SENTINEL = "NO_SUPERSESSION_V1"
APPROVAL_AUTHORITY_ID = "SYNTH_STATE_APPROVAL_AUTHORITY_V1"
APPROVER_ID = "SYNTH_STATE_APPROVER_V1"
APPROVER_ROLE = "OBSERVATION_CONTROL_PACK_APPROVER_V1"
APPROVAL_REASON = "SYNTHETIC_OBSERVATION_ONLY_PROFILE_APPROVAL_V1"
WITHDRAWAL_AUTHORITY_ID = "SYNTH_PROFILE_WITHDRAWAL_AUTHORITY_V1"
WITHDRAWER_ID = "SYNTH_PROFILE_WITHDRAWER_V1"
WITHDRAWER_ROLE = "OBSERVATION_CONTROL_PACK_WITHDRAWER_V1"
WITHDRAWAL_REASON = "SYNTHETIC_OBSERVATION_ONLY_PROFILE_WITHDRAWAL_V1"
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
    "read_only": True,
    "observation_only": True,
    "activation": False,
}
MAX_INPUT_BYTES = 262_144
MAX_ARTIFACT_BYTES = 524_288
MAX_STRING_BYTES = 256
MAX_NODES = 16_384
MAX_DEPTH = 24
MAX_TIMESTAMP = 2_147_483_647
_HEX = frozenset("0123456789abcdef")
PROFILE_KEYS = {
    "profile_id", "version", "profile_digest", "source_registry_root",
    "verifier_id", "verifier_epoch", "evidence_mode", "require_complete",
    "allow_nonmembership",
}
STAGE_KEYS = {
    "stage_id", "stage_root", "stage_kind", "prior_stage_id",
    "prior_stage_root", "stage_time", "effective_start", "effective_end",
    "origin", "status", "profile_digest", "source_registry_root",
    "candidate_root", "suite_root", "approval_root", "material",
}
ARTIFACT_KEYS = {
    "artifact_id", "schema", "profile", "stages", "current_stage_kind",
    "current_stage_id", "chain_root", *AUTHORITY_FLAGS.keys(),
}
APPROVAL_KEYS = {
    "schema", "approval_id", "approval_authority_id", "approver_id",
    "approver_role", "approval_reason", "approval_time", "profile_id",
    "profile_version", "profile_digest", "source_registry_root",
    "effective_start", "effective_end", "tested_stage_id", "tested_stage_root",
    "suite_root", "supersession", "synthetic_kat_seal",
}
APPROVAL_CORE_KEYS = APPROVAL_KEYS - {"approval_id", "synthetic_kat_seal"}
AUTHORIZATION_KEYS = {
    "schema", "authority_id", "withdrawer_id", "authorized_role", "reason_code",
    "withdrawal_time", "effective_time", "profile_id", "profile_version",
    "profile_digest", "source_registry_root", "effective_start", "effective_end",
    "prior_approved_artifact_id", "prior_approved_stage_id", "prior_approved_stage_root",
    "prior_approval_id", "prior_approval_root", "suite_root", "terminal_sentinel",
    "withdrawal_authorization_id", "synthetic_kat_seal",
}
AUTHORIZATION_CORE_KEYS = AUTHORIZATION_KEYS - {"withdrawal_authorization_id", "synthetic_kat_seal"}
WITHDRAWAL_KEYS = {
    "artifact_id", "schema", "action", "status", "profile", "approval_id",
    "approval_root", "approved_artifact", "approved_artifact_id",
    "approved_artifact_sha3_512", "approved_stage_id", "approved_stage_root",
    "effective_end", "effective_start", "effective_time", "origin",
    "source_registry_root", "suite_root", "terminal", "terminal_sentinel",
    "withdrawal_authorization", "withdrawal_authorization_id",
    "withdrawal_authorization_root", "withdrawal_time", "withdrawal_id",
    "withdrawal_root", *AUTHORITY_FLAGS.keys(),
}


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise IndependentProfileGovernanceError("json:noncanonical-value") from None


def _duplicate_reject(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise IndependentProfileGovernanceError("json:duplicate-key")
        result[key] = value
    return result


def _walk(value: object, depth: int = 0, count: list[int] | None = None) -> None:
    count = [0] if count is None else count
    count[0] += 1
    if count[0] > MAX_NODES or depth > MAX_DEPTH:
        raise IndependentProfileGovernanceError("json:bounds")
    if isinstance(value, float):
        raise IndependentProfileGovernanceError("json:float-forbidden")
    if isinstance(value, str):
        try:
            if len(value.encode("ascii")) > MAX_STRING_BYTES:
                raise IndependentProfileGovernanceError("json:string-cap")
        except UnicodeEncodeError:
            raise IndependentProfileGovernanceError("json:non-ascii") from None
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise IndependentProfileGovernanceError("json:key-type")
            _walk(key, depth + 1, count)
            _walk(item, depth + 1, count)
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth + 1, count)


def _parse(raw: bytes, *, artifact: bool = True) -> dict[str, object]:
    maximum = MAX_ARTIFACT_BYTES if artifact else MAX_INPUT_BYTES
    if type(raw) is not bytes or not raw or len(raw) > maximum:
        raise IndependentProfileGovernanceError("json:byte-cap")
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_duplicate_reject, parse_constant=lambda _value: (_ for _ in ()).throw(IndependentProfileGovernanceError("json:constant-forbidden")))
    except IndependentProfileGovernanceError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise IndependentProfileGovernanceError("json:parse") from None
    if not isinstance(value, dict):
        raise IndependentProfileGovernanceError("json:top-level")
    _walk(value)
    if _canonical(value) != raw:
        raise IndependentProfileGovernanceError("json:not-canonical")
    return value


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update(("BL/MIRROR/PROFILE-GOVERNANCE/" + label + "/v1\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _bytes_digest(label: str, raw: bytes) -> str:
    digest = hashlib.sha3_512()
    digest.update(("BL/MIRROR/PROFILE-GOVERNANCE/" + label + "/v1\0").encode("ascii"))
    digest.update(raw)
    return digest.hexdigest()


def _expect(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise IndependentProfileGovernanceError(f"{label}:schema")
    return value


def _text(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise IndependentProfileGovernanceError(f"{label}:text")
    try:
        if len(value.encode("ascii")) > MAX_STRING_BYTES:
            raise IndependentProfileGovernanceError(f"{label}:length")
    except UnicodeEncodeError:
        raise IndependentProfileGovernanceError(f"{label}:ascii") from None
    return value


def _int(value: object, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= MAX_TIMESTAMP:
        raise IndependentProfileGovernanceError(f"{label}:integer")
    return value


def _hex(value: object, label: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if type(value) is not str or len(value) != 128 or any(char not in _HEX for char in value):
        raise IndependentProfileGovernanceError(f"{label}:hex")
    return value


def _profile_material(profile: object) -> dict[str, object]:
    try:
        return graph._profile_material(profile)
    except Exception:
        raise IndependentProfileGovernanceError("profile:configuration") from None


def _source_registry_root(material: Mapping[str, object]) -> str:
    return _digest("source-registry-root", {
        key: material[key]
        for key in (
            "profile_id", "version", "subject", "scope", "observation_window",
            "effective_start", "effective_end", "source_roles",
            "require_complete", "credential_id", "enrollment_id",
            "allow_nonmembership", "canonical_order", "root_rule",
        ) if key in material
    })


def _descriptor(profile: object) -> dict[str, object]:
    material = _profile_material(profile)
    return {
        "profile_id": material["profile_id"],
        "version": material["version"],
        "profile_digest": graph._profile_digest(profile),
        "source_registry_root": _source_registry_root(material),
        "verifier_id": material["verifier_id"],
        "verifier_epoch": material["verifier_epoch"],
        "evidence_mode": material["evidence_mode"],
        "require_complete": material["require_complete"],
        "allow_nonmembership": material["allow_nonmembership"],
    }


def profile_registry_digest(profile_registry: Mapping[str, object]) -> str:
    if not isinstance(profile_registry, Mapping) or not profile_registry:
        raise IndependentProfileGovernanceError("profile:registry-required")
    descriptors = []
    for profile_id, profile in sorted(profile_registry.items()):
        descriptor = _descriptor(profile)
        if descriptor["profile_id"] != profile_id:
            raise IndependentProfileGovernanceError("profile:registry-binding")
        descriptors.append(descriptor)
    return _digest("profile-registry", descriptors)


def _configured(value: object, registry: Mapping[str, object]) -> tuple[object, dict[str, object]]:
    if not isinstance(registry, Mapping) or not registry:
        raise IndependentProfileGovernanceError("profile:registry-required")
    descriptor = _expect(value, PROFILE_KEYS, "profile")
    profile_id = _text(descriptor["profile_id"], "profile:id")
    profile = registry.get(profile_id)
    if profile is None or _descriptor(profile) != descriptor:
        raise IndependentProfileGovernanceError("profile:binding")
    return profile, descriptor


def _stage_common(value: object, profile: object, descriptor: Mapping[str, object], expected: str, prior: Mapping[str, object] | None) -> dict[str, object]:
    item = _expect(value, STAGE_KEYS, "stage")
    if item["stage_kind"] != expected or item["status"] != expected or item["origin"] != ORIGIN_MIRROR or item["profile_digest"] != descriptor["profile_digest"] or item["source_registry_root"] != descriptor["source_registry_root"]:
        raise IndependentProfileGovernanceError("stage:binding")
    _hex(item["stage_id"], "stage:id")
    _hex(item["stage_root"], "stage:root")
    _int(item["stage_time"], "stage:time", minimum=1)
    _int(item["effective_start"], "stage:start", minimum=1)
    _int(item["effective_end"], "stage:end", minimum=1)
    if item["effective_start"] >= item["effective_end"] or not item["effective_start"] <= item["stage_time"] < item["effective_end"]:
        raise IndependentProfileGovernanceError("stage:interval")
    if expected == STAGE_CANDIDATE:
        if item["prior_stage_id"] != STAGE_SENTINEL or item["prior_stage_root"] is not None:
            raise IndependentProfileGovernanceError("stage:prior")
    elif prior is None or (item["prior_stage_id"], item["prior_stage_root"]) != (prior["stage_id"], prior["stage_root"]):
        raise IndependentProfileGovernanceError("stage:prior")
    if item["stage_root"] != _digest("stage-root", {key: item[key] for key in item if key not in {"stage_id", "stage_root"}}) or item["stage_id"] != _digest("stage-id", {"stage_kind": expected, "stage_root": item["stage_root"]}):
        raise IndependentProfileGovernanceError("stage:integrity")
    return item


def _candidate_root(descriptor: Mapping[str, object], stage: Mapping[str, object]) -> str:
    material = _expect(stage["material"], {"evidence_commitment", "evidence_report_commitment", "evidence_snapshot_commitment", "evidence_root_commitment", "observation_time"}, "candidate:material")
    return _digest("candidate-root", {"profile": dict(descriptor), "origin": stage["origin"], "material": material})


def _validate_candidate(stage_value: object, profile: object, descriptor: Mapping[str, object]) -> dict[str, object]:
    stage = _stage_common(stage_value, profile, descriptor, STAGE_CANDIDATE, None)
    material = _expect(stage["material"], {"evidence_commitment", "evidence_report_commitment", "evidence_snapshot_commitment", "evidence_root_commitment", "observation_time"}, "candidate:material")
    for key in ("evidence_commitment", "evidence_report_commitment", "evidence_root_commitment"):
        _hex(material[key], "candidate:" + key)
    _text(material["evidence_snapshot_commitment"], "candidate:snapshot-commitment")
    if material["observation_time"] != stage["stage_time"] or stage["candidate_root"] != _candidate_root(descriptor, stage):
        raise IndependentProfileGovernanceError("candidate:binding")
    if stage["suite_root"] is not None or stage["approval_root"] is not None:
        raise IndependentProfileGovernanceError("candidate:roots")
    return stage


def _conformance(descriptor: Mapping[str, object], candidate: Mapping[str, object], material: Mapping[str, object]) -> dict[str, object]:
    return {
        "schema": SCHEMA, "suite_id": "SYNTH_PROFILE_GOVERNANCE_CONFORMANCE_V1",
        "suite_version": 1, "profile_digest": descriptor["profile_digest"],
        "source_registry_root": descriptor["source_registry_root"],
        "candidate_root": candidate["candidate_root"],
        "evidence_report_commitment": material["evidence_report_commitment"],
        "evidence_snapshot_commitment": material["evidence_snapshot_commitment"],
        "evidence_root_commitment": material["evidence_root_commitment"],
        "predicates": ["PROFILE_BINDING_V1", "GRAPH_INDEPENDENT_V2", "OBSERVATION_ONLY_FLAGS_V1"],
    }


def _validate_tested(stage_value: object, candidate: Mapping[str, object], profile: object, descriptor: Mapping[str, object]) -> dict[str, object]:
    stage = _stage_common(stage_value, profile, descriptor, STAGE_TESTED, candidate)
    if stage["stage_time"] != candidate["stage_time"] or stage["candidate_root"] != candidate["candidate_root"] or stage["approval_root"] is not None:
        raise IndependentProfileGovernanceError("tested:binding")
    material = _expect(stage["material"], {"candidate_artifact_id", "candidate_stage_id", "candidate_stage_root", "conformance"}, "tested:material")
    if (material["candidate_artifact_id"], material["candidate_stage_id"], material["candidate_stage_root"]) != (candidate.get("artifact_id"), candidate["stage_id"], candidate["stage_root"]):
        raise IndependentProfileGovernanceError("tested:prior")
    conformance = _expect(material["conformance"], {"schema", "suite_id", "suite_version", "profile_digest", "source_registry_root", "candidate_root", "evidence_report_commitment", "evidence_snapshot_commitment", "evidence_root_commitment", "predicates"}, "tested:conformance")
    if conformance != _conformance(descriptor, candidate, _expect(candidate["material"], {"evidence_commitment", "evidence_report_commitment", "evidence_snapshot_commitment", "evidence_root_commitment", "observation_time"}, "candidate:material")):
        raise IndependentProfileGovernanceError("tested:conformance")
    if stage["suite_root"] != _digest("suite-root", conformance):
        raise IndependentProfileGovernanceError("tested:suite")
    return stage


def _validate_approval(value: object, profile: object, descriptor: Mapping[str, object], tested: Mapping[str, object]) -> tuple[dict[str, object], str]:
    record = _expect(value, APPROVAL_KEYS, "approval")
    if record["schema"] != APPROVAL_SCHEMA or record["approval_authority_id"] != APPROVAL_AUTHORITY_ID or record["approver_id"] != APPROVER_ID or record["approver_role"] != APPROVER_ROLE or record["approval_reason"] != APPROVAL_REASON:
        raise IndependentProfileGovernanceError("approval:authority")
    for key, expected in (("profile_id", descriptor["profile_id"]), ("profile_version", descriptor["version"]), ("profile_digest", descriptor["profile_digest"]), ("source_registry_root", descriptor["source_registry_root"]), ("tested_stage_id", tested["stage_id"]), ("tested_stage_root", tested["stage_root"]), ("suite_root", tested["suite_root"])):
        if record[key] != expected:
            raise IndependentProfileGovernanceError("approval:binding")
    _int(record["approval_time"], "approval:time", minimum=1)
    _int(record["effective_start"], "approval:start", minimum=1)
    _int(record["effective_end"], "approval:end", minimum=1)
    if (record["effective_start"], record["effective_end"]) != (tested["effective_start"], tested["effective_end"]) or not record["effective_start"] <= record["approval_time"] < record["effective_end"]:
        raise IndependentProfileGovernanceError("approval:chronology")
    supersession = _expect(record["supersession"], {"prior_approval_id", "supersession_sentinel"}, "approval:supersession")
    if supersession != {"prior_approval_id": None, "supersession_sentinel": SUPERSESSION_SENTINEL}:
        raise IndependentProfileGovernanceError("approval:supersession")
    for key in ("approval_id", "tested_stage_id", "tested_stage_root", "suite_root", "synthetic_kat_seal"):
        _hex(record[key], "approval:" + key)
    core = {key: record[key] for key in APPROVAL_CORE_KEYS}
    if record["approval_id"] != _digest("approval-id", core) or record["synthetic_kat_seal"] != _digest("synthetic-kat-seal", {"approval_id": record["approval_id"], **core}):
        raise IndependentProfileGovernanceError("approval:integrity")
    return record, _digest("approval-root", {"approval_record": record})


def _validate_artifact(value: object, profile_registry: Mapping[str, object]) -> dict[str, object]:
    item = _expect(value, ARTIFACT_KEYS, "artifact")
    if item["schema"] != SCHEMA or item["current_stage_kind"] not in STAGE_KINDS:
        raise IndependentProfileGovernanceError("artifact:schema")
    profile, descriptor = _configured(item["profile"], profile_registry)
    if {key: item[key] for key in AUTHORITY_FLAGS} != AUTHORITY_FLAGS:
        raise IndependentProfileGovernanceError("artifact:authority")
    stages = item["stages"]
    if not isinstance(stages, list) or not 1 <= len(stages) <= len(STAGE_KINDS) or [stage.get("stage_kind") for stage in stages if isinstance(stage, dict)] != list(STAGE_KINDS[:len(stages)]):
        raise IndependentProfileGovernanceError("artifact:stages")
    candidate = _validate_candidate(stages[0], profile, descriptor)
    checked = [candidate]
    if len(stages) >= 2:
        tested = _validate_tested(stages[1], {**candidate, "artifact_id": _digest("artifact-id", {"schema": SCHEMA, "profile": descriptor, "stages": [candidate], "current_stage_kind": STAGE_CANDIDATE, "current_stage_id": candidate["stage_id"], "chain_root": _digest("chain-root", {"stages": [candidate]}), **AUTHORITY_FLAGS})}, profile, descriptor)
        # The exact candidate artifact id is recomputed below and rebound here.
        candidate_artifact = {"schema": SCHEMA, "profile": descriptor, "stages": [candidate], "current_stage_kind": STAGE_CANDIDATE, "current_stage_id": candidate["stage_id"], "chain_root": _digest("chain-root", {"stages": [candidate]}), **AUTHORITY_FLAGS}
        candidate_artifact["artifact_id"] = _digest("artifact-id", {key: candidate_artifact[key] for key in candidate_artifact if key != "artifact_id"})
        if stages[1]["material"]["candidate_artifact_id"] != candidate_artifact["artifact_id"]:
            raise IndependentProfileGovernanceError("tested:candidate-artifact")
        checked.append(tested)
    if len(stages) >= 3:
        tested = checked[1]
        approved = _stage_common(stages[2], profile, descriptor, STAGE_APPROVED, tested)
        if approved["stage_time"] < tested["stage_time"] or approved["candidate_root"] != candidate["candidate_root"] or approved["suite_root"] != tested["suite_root"]:
            raise IndependentProfileGovernanceError("approved:binding")
        material = _expect(approved["material"], {"approval_record"}, "approved:material")
        record, approval_root = _validate_approval(material["approval_record"], profile, descriptor, tested)
        if approved["approval_root"] != approval_root:
            raise IndependentProfileGovernanceError("approved:approval-root")
        checked.append(approved)
    if item["current_stage_kind"] != checked[-1]["stage_kind"] or item["current_stage_id"] != checked[-1]["stage_id"]:
        raise IndependentProfileGovernanceError("artifact:current")
    if item["chain_root"] != _digest("chain-root", {"stages": stages}):
        raise IndependentProfileGovernanceError("artifact:chain")
    if item["artifact_id"] != _digest("artifact-id", {key: item[key] for key in item if key != "artifact_id"}):
        raise IndependentProfileGovernanceError("artifact:id")
    return {"accepted": True, "artifact_id": item["artifact_id"], "profile_id": descriptor["profile_id"], "profile_version": descriptor["version"], "profile_digest": descriptor["profile_digest"], "current_stage_kind": checked[-1]["stage_kind"], "current_stage_id": checked[-1]["stage_id"], "stage_root": checked[-1]["stage_root"], "effective_start": checked[-1]["effective_start"], "effective_end": checked[-1]["effective_end"], "synthetic_only": True, "production_usable": False, "artifact_bytes": len(_canonical(item))}


def _validate_authorization(value: object, profile: object, descriptor: Mapping[str, object], approved: Mapping[str, object], stage: Mapping[str, object], approval: Mapping[str, object]) -> tuple[dict[str, object], str]:
    record = _expect(value, AUTHORIZATION_KEYS, "authorization")
    if record["schema"] != AUTHORIZATION_SCHEMA or record["authority_id"] != WITHDRAWAL_AUTHORITY_ID or record["withdrawer_id"] != WITHDRAWER_ID or record["authorized_role"] != WITHDRAWER_ROLE or record["reason_code"] != WITHDRAWAL_REASON or record["terminal_sentinel"] != TERMINAL_SENTINEL:
        raise IndependentProfileGovernanceError("authorization:authority")
    for key, expected in (("profile_id", descriptor["profile_id"]), ("profile_version", descriptor["version"]), ("profile_digest", descriptor["profile_digest"]), ("source_registry_root", descriptor["source_registry_root"]), ("prior_approved_artifact_id", approved["artifact_id"]), ("prior_approved_stage_id", stage["stage_id"]), ("prior_approved_stage_root", stage["stage_root"]), ("prior_approval_id", approval["approval_id"]), ("prior_approval_root", stage["approval_root"]), ("suite_root", stage["suite_root"])):
        if record[key] != expected:
            raise IndependentProfileGovernanceError("authorization:binding")
    for key in ("withdrawal_time", "effective_time", "effective_start", "effective_end"):
        _int(record[key], "authorization:" + key, minimum=1)
    if record["withdrawal_time"] != record["effective_time"] or record["withdrawal_time"] <= approval["approval_time"] or (record["effective_start"], record["effective_end"]) != (stage["effective_start"], stage["effective_end"]):
        raise IndependentProfileGovernanceError("authorization:chronology")
    for key in ("withdrawal_authorization_id", "prior_approved_artifact_id", "prior_approved_stage_id", "prior_approved_stage_root", "prior_approval_id", "prior_approval_root", "suite_root", "synthetic_kat_seal"):
        _hex(record[key], "authorization:" + key)
    core = {key: record[key] for key in AUTHORIZATION_CORE_KEYS}
    if record["withdrawal_authorization_id"] != _digest("withdrawal-authorization-id", core) or record["synthetic_kat_seal"] != _digest("synthetic-kat-seal", {"withdrawal_authorization_id": record["withdrawal_authorization_id"], **core}):
        raise IndependentProfileGovernanceError("authorization:integrity")
    return record, _digest("withdrawal-authorization-root", {"authorization": record})


def _validate_withdrawal(item: object, profile_registry: Mapping[str, object]) -> dict[str, object]:
    value = _expect(item, WITHDRAWAL_KEYS, "withdrawal")
    if value["schema"] != WITHDRAWAL_SCHEMA or value["action"] != ACTION_WITHDRAWN or value["status"] != ACTION_WITHDRAWN or value["origin"] != ORIGIN_MIRROR or value["terminal"] is not True or value["terminal_sentinel"] != TERMINAL_SENTINEL:
        raise IndependentProfileGovernanceError("withdrawal:authority")
    profile, descriptor = _configured(value["profile"], profile_registry)
    if value["source_registry_root"] != descriptor["source_registry_root"] or {key: value[key] for key in AUTHORITY_FLAGS} != AUTHORITY_FLAGS:
        raise IndependentProfileGovernanceError("withdrawal:binding")
    approved = _parse(_canonical(value["approved_artifact"]))
    approved_result = _validate_artifact(approved, profile_registry)
    if approved_result["current_stage_kind"] != STAGE_APPROVED or approved_result["profile_id"] != descriptor["profile_id"]:
        raise IndependentProfileGovernanceError("withdrawal:approved")
    stages = approved["stages"]
    stage = stages[-1]
    material = _expect(stage["material"], {"approval_record"}, "withdrawal:approved-material")
    approval, approval_root = _validate_approval(material["approval_record"], profile, descriptor, stages[-2])
    if (value["approved_artifact_id"], value["approved_stage_id"], value["approved_stage_root"], value["approval_id"], value["approval_root"], value["suite_root"]) != (approved["artifact_id"], stage["stage_id"], stage["stage_root"], approval["approval_id"], approval_root, stage["suite_root"]):
        raise IndependentProfileGovernanceError("withdrawal:approved-binding")
    if value["approved_artifact_sha3_512"] != _bytes_digest("approved-artifact", _canonical(approved)):
        raise IndependentProfileGovernanceError("withdrawal:approved-bytes")
    for key in ("effective_start", "effective_end", "effective_time", "withdrawal_time"):
        _int(value[key], "withdrawal:" + key, minimum=1)
    if (value["effective_start"], value["effective_end"]) != (stage["effective_start"], stage["effective_end"]) or value["effective_time"] != value["withdrawal_time"]:
        raise IndependentProfileGovernanceError("withdrawal:interval")
    authorization, authorization_root = _validate_authorization(value["withdrawal_authorization"], profile, descriptor, approved, stage, approval)
    if value["withdrawal_authorization_id"] != authorization["withdrawal_authorization_id"] or value["withdrawal_authorization_root"] != authorization_root:
        raise IndependentProfileGovernanceError("withdrawal:authorization")
    body = {key: value[key] for key in value if key not in {"artifact_id", "withdrawal_id", "withdrawal_root"}}
    if value["withdrawal_root"] != _digest("withdrawal-root", body) or value["withdrawal_id"] != _digest("withdrawal-id", {"action": ACTION_WITHDRAWN, "withdrawal_root": value["withdrawal_root"]}) or value["artifact_id"] != _digest("artifact-id", {key: value[key] for key in value if key != "artifact_id"}):
        raise IndependentProfileGovernanceError("withdrawal:integrity")
    return {"accepted": True, "artifact_id": value["artifact_id"], "withdrawal_id": value["withdrawal_id"], "profile_id": descriptor["profile_id"], "profile_version": descriptor["version"], "profile_digest": descriptor["profile_digest"], "current_stage_kind": ACTION_WITHDRAWN, "effective_start": value["effective_start"], "effective_end": value["effective_end"], "withdrawal_time": value["withdrawal_time"], "synthetic_only": True, "production_usable": False, "artifact_bytes": len(_canonical(value))}


def verify_bytes(raw: bytes, profile_registry: Mapping[str, object]) -> dict[str, object]:
    try:
        value = _parse(raw)
        if value.get("schema") == SCHEMA:
            return _validate_artifact(value, profile_registry)
        if value.get("schema") == WITHDRAWAL_SCHEMA:
            return _validate_withdrawal(value, profile_registry)
        raise IndependentProfileGovernanceError("artifact:schema")
    except IndependentProfileGovernanceError:
        raise
    except (KeyError, IndexError, TypeError, ValueError):
        raise IndependentProfileGovernanceError("artifact:reject") from None


def verify_file(path: str | Path, profile_registry: Mapping[str, object]) -> dict[str, object]:
    file_path = Path(path)
    if file_path.stat().st_size > MAX_ARTIFACT_BYTES:
        raise IndependentProfileGovernanceError("file:byte-cap")
    try:
        raw = file_path.read_bytes()
    except OSError:
        raise IndependentProfileGovernanceError("file:read") from None
    return verify_bytes(raw, profile_registry)


def main(argv: Sequence[str] | None = None) -> int:
    import sys
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: python -m app.mirror.profile_governance_v1_independent ARTIFACT.json", file=sys.stderr)
        return 2
    try:
        print(json.dumps(verify_file(args[0], {}), sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, IndependentProfileGovernanceError):
        print("REJECT input", file=sys.stderr)
        return 1


__all__ = [
    "IndependentProfileGovernanceError", "SCHEMA", "WITHDRAWAL_SCHEMA",
    "APPROVAL_SCHEMA", "AUTHORIZATION_SCHEMA", "STAGE_CANDIDATE",
    "STAGE_TESTED", "STAGE_APPROVED", "STAGE_KINDS", "ACTION_WITHDRAWN",
    "AUTHORITY_FLAGS", "verify_bytes", "verify_file", "_canonical", "_parse",
    "_digest", "_bytes_digest", "_descriptor", "profile_registry_digest",
    "PROFILE_KEYS", "STAGE_KEYS", "ARTIFACT_KEYS",
]
