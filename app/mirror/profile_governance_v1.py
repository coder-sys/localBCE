"""Synthetic multi-profile governance composition for the Mirror wedge.

The graph is verified and bound at this boundary, but graph bytes and subject
identity never enter the durable governance artifact.  The artifact contains
only the configured public-profile commitment, opaque graph commitments, and a
deterministic candidate -> tested -> approved lifecycle.  Withdrawal is a
terminal, separately authorized artifact.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Mapping, Sequence

from app.mirror import provider_trust_graph_independent as graph_independent


class ProfileGovernanceError(ValueError):
    """Raised for malformed, substituted, or semantically invalid governance."""


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
MAX_STAGES = 3
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


@dataclass(frozen=True)
class GraphBinding:
    """Transient graph/profile binding; no graph bytes are retained here."""

    profile_id: str
    profile_version: int
    profile_digest: str
    report_id: str
    snapshot_id: str
    snapshot_root: str
    observation_time: int
    graph_artifact_digest: str


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=True, allow_nan=False, sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise ProfileGovernanceError("json:noncanonical-value") from None


def _duplicate_reject(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ProfileGovernanceError("json:duplicate-key")
        result[key] = value
    return result


def _walk(value: object, depth: int = 0, count: list[int] | None = None) -> None:
    count = [0] if count is None else count
    count[0] += 1
    if count[0] > MAX_NODES or depth > MAX_DEPTH:
        raise ProfileGovernanceError("json:bounds")
    if isinstance(value, float):
        raise ProfileGovernanceError("json:float-forbidden")
    if isinstance(value, str):
        try:
            if len(value.encode("ascii")) > MAX_STRING_BYTES:
                raise ProfileGovernanceError("json:string-cap")
        except UnicodeEncodeError:
            raise ProfileGovernanceError("json:non-ascii") from None
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ProfileGovernanceError("json:key-type")
            _walk(key, depth + 1, count)
            _walk(item, depth + 1, count)
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth + 1, count)


def _parse(raw: bytes, *, artifact: bool = True) -> dict[str, object]:
    maximum = MAX_ARTIFACT_BYTES if artifact else MAX_INPUT_BYTES
    if type(raw) is not bytes or not raw or len(raw) > maximum:
        raise ProfileGovernanceError("json:byte-cap")
    try:
        value = json.loads(
            raw.decode("ascii"), object_pairs_hook=_duplicate_reject,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ProfileGovernanceError("json:constant-forbidden")
            ),
        )
    except ProfileGovernanceError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ProfileGovernanceError("json:parse") from None
    if not isinstance(value, dict):
        raise ProfileGovernanceError("json:top-level")
    _walk(value)
    if _canonical(value) != raw:
        raise ProfileGovernanceError("json:not-canonical")
    return value


def canonical_bytes(value: Mapping[str, object]) -> bytes:
    if not isinstance(value, dict):
        raise ProfileGovernanceError("json:top-level")
    _walk(value)
    raw = _canonical(value)
    if len(raw) > MAX_INPUT_BYTES:
        raise ProfileGovernanceError("json:byte-cap")
    return raw


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


def _expect_keys(value: object, expected: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ProfileGovernanceError(f"{label}:schema")
    return value


def _text(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise ProfileGovernanceError(f"{label}:text")
    try:
        if len(value.encode("ascii")) > MAX_STRING_BYTES:
            raise ProfileGovernanceError(f"{label}:length")
    except UnicodeEncodeError:
        raise ProfileGovernanceError(f"{label}:ascii") from None
    return value


def _int(value: object, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= MAX_TIMESTAMP:
        raise ProfileGovernanceError(f"{label}:integer")
    return value


def _bool(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise ProfileGovernanceError(f"{label}:boolean")
    return value


def _hex(value: object, label: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if type(value) is not str or len(value) != 128 or any(char not in _HEX for char in value):
        raise ProfileGovernanceError(f"{label}:hex")
    return value


def _profile_material(profile: object) -> dict[str, object]:
    try:
        return graph_independent._profile_material(profile)
    except Exception:
        raise ProfileGovernanceError("profile:configuration") from None


def _source_registry_root(material: Mapping[str, object]) -> str:
    # This is an opaque verifier commitment.  The durable artifact carries the
    # digest only; provider/subject/source fields are deliberately not copied.
    source_material = {
        key: material[key]
        for key in (
            "profile_id", "version", "subject", "scope", "observation_window",
            "effective_start", "effective_end", "source_roles",
            "require_complete", "credential_id", "enrollment_id",
            "allow_nonmembership", "canonical_order", "root_rule",
        ) if key in material
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


def profile_registry_digest(profile_registry: Mapping[str, object]) -> str:
    if not isinstance(profile_registry, Mapping) or not profile_registry:
        raise ProfileGovernanceError("profile:registry-required")
    descriptors = []
    for profile_id, profile in sorted(profile_registry.items()):
        descriptor = profile_descriptor(profile)
        if descriptor["profile_id"] != profile_id:
            raise ProfileGovernanceError("profile:registry-binding")
        descriptors.append(descriptor)
    return _digest("profile-registry", descriptors)


def _descriptor_check(value: object, profile: object) -> dict[str, object]:
    descriptor = _expect_keys(value, PROFILE_KEYS, "profile")
    expected = profile_descriptor(profile)
    if descriptor != expected:
        raise ProfileGovernanceError("profile:binding")
    _text(descriptor["profile_id"], "profile:id")
    _int(descriptor["version"], "profile:version", minimum=1)
    _hex(descriptor["profile_digest"], "profile:digest")
    _hex(descriptor["source_registry_root"], "profile:registry-root")
    _text(descriptor["verifier_id"], "profile:verifier-id")
    _int(descriptor["verifier_epoch"], "profile:verifier-epoch", minimum=0)
    _text(descriptor["evidence_mode"], "profile:evidence-mode")
    _bool(descriptor["require_complete"], "profile:complete")
    _bool(descriptor["allow_nonmembership"], "profile:nonmembership")
    return dict(descriptor)


def bind_graph(graph_raw: bytes, profile: object) -> GraphBinding:
    """Verify one graph and return only its transient opaque binding."""

    descriptor = profile_descriptor(profile)
    registry = {str(descriptor["profile_id"]): profile}
    try:
        result = graph_independent.verify_bytes_v2(graph_raw, registry)
        value = graph_independent._parse(graph_raw)
    except Exception:
        raise ProfileGovernanceError("graph:independent-reject") from None
    if result.get("profile_id") != descriptor["profile_id"] or result.get("profile_digest") != descriptor["profile_digest"]:
        raise ProfileGovernanceError("graph:profile-binding")
    snapshot = _expect_keys(value.get("observation_snapshot"), {"snapshot_id", "snapshot_root", "observation_time"}, "graph:snapshot")
    report = _expect_keys(value.get("report"), {"report_id", "identity_material"}, "graph:report")
    _hex(snapshot["snapshot_root"], "graph:snapshot-root")
    _hex(report["report_id"], "graph:report-id")
    _int(snapshot["observation_time"], "graph:observation-time", minimum=1)
    return GraphBinding(
        profile_id=str(descriptor["profile_id"]),
        profile_version=int(descriptor["version"]),
        profile_digest=str(descriptor["profile_digest"]),
        report_id=str(report["report_id"]),
        snapshot_id=str(snapshot["snapshot_id"]),
        snapshot_root=str(snapshot["snapshot_root"]),
        observation_time=int(snapshot["observation_time"]),
        graph_artifact_digest=_bytes_digest("graph-artifact", graph_raw),
    )


def _stage(body: Mapping[str, object]) -> dict[str, object]:
    value = deepcopy(dict(body))
    value["stage_root"] = _digest("stage-root", value)
    value["stage_id"] = _digest("stage-id", {"stage_kind": value["stage_kind"], "stage_root": value["stage_root"]})
    return {"stage_id": value["stage_id"], "stage_root": value["stage_root"], **{key: value[key] for key in value if key not in {"stage_id", "stage_root"}}}


def _artifact(profile_value: Mapping[str, object], stages: Sequence[Mapping[str, object]], *, schema: str = SCHEMA) -> dict[str, object]:
    copied = deepcopy(list(stages))
    current = copied[-1]
    body: dict[str, object] = {
        "schema": schema,
        "profile": deepcopy(dict(profile_value)),
        "stages": copied,
        "current_stage_kind": current["stage_kind"],
        "current_stage_id": current["stage_id"],
        "chain_root": _digest("chain-root", {"stages": copied}),
        **deepcopy(AUTHORITY_FLAGS),
    }
    return {"artifact_id": _digest("artifact-id", body), **body}


def _encode(value: Mapping[str, object]) -> bytes:
    _walk(value)
    raw = _canonical(value)
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise ProfileGovernanceError("artifact:byte-cap")
    return raw


def _candidate_material(binding: GraphBinding) -> dict[str, object]:
    return {
        "evidence_commitment": binding.graph_artifact_digest,
        "evidence_report_commitment": binding.report_id,
        "evidence_snapshot_commitment": binding.snapshot_id,
        "evidence_root_commitment": binding.snapshot_root,
        "observation_time": binding.observation_time,
    }


def _load(raw: bytes, profile: object, expected_stage: str) -> dict[str, object]:
    descriptor = profile_descriptor(profile)
    try:
        checked = independent_verify(raw, {str(descriptor["profile_id"]): profile})
    except Exception:
        raise ProfileGovernanceError("promotion:independent-reject") from None
    if checked.get("current_stage_kind") != expected_stage:
        raise ProfileGovernanceError(f"promotion:expected-{expected_stage.lower()}")
    value = _parse(raw)
    _descriptor_check(value.get("profile"), profile)
    return value


def _conformance(descriptor: Mapping[str, object], candidate: Mapping[str, object], material: Mapping[str, object]) -> dict[str, object]:
    return {
        "schema": SCHEMA,
        "suite_id": "SYNTH_PROFILE_GOVERNANCE_CONFORMANCE_V1",
        "suite_version": 1,
        "profile_digest": descriptor["profile_digest"],
        "source_registry_root": descriptor["source_registry_root"],
        "candidate_root": candidate["candidate_root"],
        "evidence_report_commitment": material["evidence_report_commitment"],
        "evidence_snapshot_commitment": material["evidence_snapshot_commitment"],
        "evidence_root_commitment": material["evidence_root_commitment"],
        "predicates": ["PROFILE_BINDING_V1", "GRAPH_INDEPENDENT_V2", "OBSERVATION_ONLY_FLAGS_V1"],
    }


def build_candidate(graph_raw: bytes, profile: object, *, origin: str = ORIGIN_MIRROR) -> tuple[bytes, dict[str, object]]:
    if origin != ORIGIN_MIRROR:
        raise ProfileGovernanceError("candidate:origin")
    descriptor = profile_descriptor(profile)
    binding = bind_graph(graph_raw, profile)
    body = {
        "stage_kind": STAGE_CANDIDATE,
        "prior_stage_id": STAGE_SENTINEL,
        "prior_stage_root": None,
        "stage_time": binding.observation_time,
        "effective_start": int(getattr(profile, "effective_start")),
        "effective_end": int(getattr(profile, "effective_end")),
        "origin": origin,
        "status": STAGE_CANDIDATE,
        "profile_digest": descriptor["profile_digest"],
        "source_registry_root": descriptor["source_registry_root"],
        "candidate_root": _digest("candidate-root", {"profile": descriptor, "origin": origin, "material": _candidate_material(binding)}),
        "suite_root": None,
        "approval_root": None,
        "material": _candidate_material(binding),
    }
    raw = _encode(_artifact(descriptor, [_stage(body)]))
    independent_verify(raw, {str(descriptor["profile_id"]): profile})
    return raw, {"artifact_bytes": len(raw), "profile_id": descriptor["profile_id"], "profile_digest": descriptor["profile_digest"], "observation_time": binding.observation_time, "production_usable": False}


def build_tested(candidate_raw: bytes, profile: object) -> tuple[bytes, dict[str, object]]:
    descriptor = profile_descriptor(profile)
    candidate = _load(candidate_raw, profile, STAGE_CANDIDATE)
    prior = _expect_keys(candidate["stages"][-1], STAGE_KEYS, "candidate:stage")
    material = _expect_keys(prior["material"], {"evidence_commitment", "evidence_report_commitment", "evidence_snapshot_commitment", "evidence_root_commitment", "observation_time"}, "candidate:material")
    conformance = _conformance(descriptor, prior, material)
    body = {
        "stage_kind": STAGE_TESTED,
        "prior_stage_id": prior["stage_id"],
        "prior_stage_root": prior["stage_root"],
        "stage_time": prior["stage_time"],
        "effective_start": prior["effective_start"],
        "effective_end": prior["effective_end"],
        "origin": prior["origin"],
        "status": STAGE_TESTED,
        "profile_digest": descriptor["profile_digest"],
        "source_registry_root": descriptor["source_registry_root"],
        "candidate_root": prior["candidate_root"],
        "suite_root": _digest("suite-root", conformance),
        "approval_root": None,
        "material": {"candidate_artifact_id": candidate["artifact_id"], "candidate_stage_id": prior["stage_id"], "candidate_stage_root": prior["stage_root"], "conformance": conformance},
    }
    raw = _encode(_artifact(descriptor, [*candidate["stages"], _stage(body)]))
    independent_verify(raw, {str(descriptor["profile_id"]): profile})
    return raw, {"artifact_bytes": len(raw), "profile_id": descriptor["profile_id"], "profile_digest": descriptor["profile_digest"], "production_usable": False}


def _approval_record(value: object, profile: object, tested: Mapping[str, object]) -> tuple[dict[str, object], str]:
    record = _expect_keys(value, APPROVAL_KEYS, "approval")
    descriptor = profile_descriptor(profile)
    if record["schema"] != APPROVAL_SCHEMA or record["approval_authority_id"] != APPROVAL_AUTHORITY_ID or record["approver_id"] != APPROVER_ID or record["approver_role"] != APPROVER_ROLE or record["approval_reason"] != APPROVAL_REASON:
        raise ProfileGovernanceError("approval:authority")
    for key, expected in (("profile_id", descriptor["profile_id"]), ("profile_version", descriptor["version"]), ("profile_digest", descriptor["profile_digest"]), ("source_registry_root", descriptor["source_registry_root"]), ("tested_stage_id", tested["stage_id"]), ("tested_stage_root", tested["stage_root"]), ("suite_root", tested["suite_root"])):
        if record[key] != expected:
            raise ProfileGovernanceError("approval:binding")
    _int(record["approval_time"], "approval:time", minimum=1)
    if (record["effective_start"], record["effective_end"]) != (tested["effective_start"], tested["effective_end"]):
        raise ProfileGovernanceError("approval:interval")
    if not record["effective_start"] <= record["approval_time"] < record["effective_end"]:
        raise ProfileGovernanceError("approval:chronology")
    supersession = _expect_keys(record["supersession"], {"prior_approval_id", "supersession_sentinel"}, "approval:supersession")
    if supersession != {"prior_approval_id": None, "supersession_sentinel": SUPERSESSION_SENTINEL}:
        raise ProfileGovernanceError("approval:supersession")
    for key in ("approval_id", "tested_stage_id", "tested_stage_root", "suite_root", "synthetic_kat_seal"):
        _hex(record[key], "approval:" + key)
    core = {key: record[key] for key in APPROVAL_CORE_KEYS}
    if record["approval_id"] != _digest("approval-id", core) or record["synthetic_kat_seal"] != _digest("synthetic-kat-seal", {"approval_id": record["approval_id"], **core}):
        raise ProfileGovernanceError("approval:integrity")
    return record, _digest("approval-root", {"approval_record": record})


def build_approval_record(tested_raw: bytes, profile: object, *, approval_time: int | None = None) -> bytes:
    descriptor = profile_descriptor(profile)
    tested = _load(tested_raw, profile, STAGE_TESTED)
    stage = _expect_keys(tested["stages"][-1], STAGE_KEYS, "tested:stage")
    if approval_time is None:
        approval_time = min(int(stage["effective_end"]) - 1, int(stage["stage_time"]) + 100)
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
    _approval_record(_parse(raw, artifact=False), profile, stage)
    return raw


def build_approved(tested_raw: bytes, approval_record_raw: bytes, profile: object) -> tuple[bytes, dict[str, object]]:
    descriptor = profile_descriptor(profile)
    tested = _load(tested_raw, profile, STAGE_TESTED)
    prior = _expect_keys(tested["stages"][-1], STAGE_KEYS, "tested:stage")
    approval, approval_root = _approval_record(_parse(approval_record_raw, artifact=False), profile, prior)
    body = {
        "stage_kind": STAGE_APPROVED,
        "prior_stage_id": prior["stage_id"],
        "prior_stage_root": prior["stage_root"],
        "stage_time": approval["approval_time"],
        "effective_start": prior["effective_start"],
        "effective_end": prior["effective_end"],
        "origin": prior["origin"],
        "status": STAGE_APPROVED,
        "profile_digest": descriptor["profile_digest"],
        "source_registry_root": descriptor["source_registry_root"],
        "candidate_root": prior["candidate_root"],
        "suite_root": prior["suite_root"],
        "approval_root": approval_root,
        "material": {"approval_record": approval},
    }
    raw = _encode(_artifact(descriptor, [*tested["stages"], _stage(body)]))
    independent_verify(raw, {str(descriptor["profile_id"]): profile})
    return raw, {"artifact_bytes": len(raw), "profile_id": descriptor["profile_id"], "profile_digest": descriptor["profile_digest"], "production_usable": False}


def _approved_material(raw: bytes, profile: object) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    value = _load(raw, profile, STAGE_APPROVED)
    stage = _expect_keys(value["stages"][-1], STAGE_KEYS, "approved:stage")
    material = _expect_keys(stage["material"], {"approval_record"}, "approved:material")
    approval = _expect_keys(material["approval_record"], APPROVAL_KEYS, "approved:approval")
    return value, stage, approval


def _authorization_record(value: object, profile: object, approved: Mapping[str, object], stage: Mapping[str, object], approval: Mapping[str, object]) -> tuple[dict[str, object], str]:
    record = _expect_keys(value, AUTHORIZATION_KEYS, "authorization")
    descriptor = profile_descriptor(profile)
    if record["schema"] != AUTHORIZATION_SCHEMA or record["authority_id"] != WITHDRAWAL_AUTHORITY_ID or record["withdrawer_id"] != WITHDRAWER_ID or record["authorized_role"] != WITHDRAWER_ROLE or record["reason_code"] != WITHDRAWAL_REASON or record["terminal_sentinel"] != TERMINAL_SENTINEL:
        raise ProfileGovernanceError("authorization:authority")
    for key, expected in (("profile_id", descriptor["profile_id"]), ("profile_version", descriptor["version"]), ("profile_digest", descriptor["profile_digest"]), ("source_registry_root", descriptor["source_registry_root"]), ("prior_approved_artifact_id", approved["artifact_id"]), ("prior_approved_stage_id", stage["stage_id"]), ("prior_approved_stage_root", stage["stage_root"]), ("prior_approval_id", approval["approval_id"]), ("prior_approval_root", stage["approval_root"]), ("suite_root", stage["suite_root"])):
        if record[key] != expected:
            raise ProfileGovernanceError("authorization:binding")
    for key in ("withdrawal_time", "effective_time", "effective_start", "effective_end"):
        _int(record[key], "authorization:" + key, minimum=1)
    if record["withdrawal_time"] != record["effective_time"] or record["withdrawal_time"] <= approval["approval_time"] or (record["effective_start"], record["effective_end"]) != (stage["effective_start"], stage["effective_end"]):
        raise ProfileGovernanceError("authorization:chronology")
    for key in ("withdrawal_authorization_id", "prior_approved_artifact_id", "prior_approved_stage_id", "prior_approved_stage_root", "prior_approval_id", "prior_approval_root", "suite_root", "synthetic_kat_seal"):
        _hex(record[key], "authorization:" + key)
    core = {key: record[key] for key in AUTHORIZATION_CORE_KEYS}
    if record["withdrawal_authorization_id"] != _digest("withdrawal-authorization-id", core) or record["synthetic_kat_seal"] != _digest("synthetic-kat-seal", {"withdrawal_authorization_id": record["withdrawal_authorization_id"], **core}):
        raise ProfileGovernanceError("authorization:integrity")
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
    _authorization_record(_parse(raw, artifact=False), profile, approved, stage, approval)
    return raw


def _withdrawal_body(value: Mapping[str, object]) -> dict[str, object]:
    return {key: item for key, item in value.items() if key not in {"artifact_id", "withdrawal_id", "withdrawal_root"}}


def build_withdrawal(approved_raw: bytes, authorization_raw: bytes, profile: object) -> tuple[bytes, dict[str, object]]:
    approved, stage, approval = _approved_material(approved_raw, profile)
    authorization, authorization_root = _authorization_record(_parse(authorization_raw, artifact=False), profile, approved, stage, approval)
    descriptor = profile_descriptor(profile)
    body: dict[str, object] = {
        "schema": WITHDRAWAL_SCHEMA,
        "action": ACTION_WITHDRAWN,
        "status": ACTION_WITHDRAWN,
        "profile": descriptor,
        "approval_id": approval["approval_id"],
        "approval_root": stage["approval_root"],
        "approved_artifact": approved,
        "approved_artifact_id": approved["artifact_id"],
        "approved_artifact_sha3_512": _bytes_digest("approved-artifact", approved_raw),
        "approved_stage_id": stage["stage_id"],
        "approved_stage_root": stage["stage_root"],
        "effective_start": stage["effective_start"],
        "effective_end": stage["effective_end"],
        "effective_time": authorization["effective_time"],
        "origin": ORIGIN_MIRROR,
        "source_registry_root": descriptor["source_registry_root"],
        "suite_root": stage["suite_root"],
        "terminal": True,
        "terminal_sentinel": TERMINAL_SENTINEL,
        "withdrawal_authorization": authorization,
        "withdrawal_authorization_id": authorization["withdrawal_authorization_id"],
        "withdrawal_authorization_root": authorization_root,
        "withdrawal_time": authorization["withdrawal_time"],
        "withdrawal_root": "",
        "withdrawal_id": "",
        **deepcopy(AUTHORITY_FLAGS),
    }
    body["withdrawal_root"] = _digest("withdrawal-root", _withdrawal_body(body))
    body["withdrawal_id"] = _digest("withdrawal-id", {"action": ACTION_WITHDRAWN, "withdrawal_root": body["withdrawal_root"]})
    body["artifact_id"] = _digest("artifact-id", {key: body[key] for key in body if key != "artifact_id"})
    raw = _encode(body)
    independent_verify(raw, {str(descriptor["profile_id"]): profile})
    return raw, {"artifact_bytes": len(raw), "profile_id": descriptor["profile_id"], "profile_digest": descriptor["profile_digest"], "withdrawal_id": body["withdrawal_id"], "production_usable": False}


def independent_verify(raw: bytes, profile_registry: Mapping[str, object]) -> dict[str, object]:
    return _independent_verify(raw, profile_registry)


def verify_bytes(raw: bytes, profile_registry: Mapping[str, object]) -> dict[str, object]:
    return independent_verify(raw, profile_registry)


def verify_file(path: str | Path, profile_registry: Mapping[str, object]) -> dict[str, object]:
    file_path = Path(path)
    if file_path.stat().st_size > MAX_ARTIFACT_BYTES:
        raise ProfileGovernanceError("file:byte-cap")
    return independent_verify(file_path.read_bytes(), profile_registry)


def _independent_verify(raw: bytes, profile_registry: Mapping[str, object]) -> dict[str, object]:
    # The actual structural verifier lives in the sibling module.  Keeping the
    # producer's public validation entry point here is useful for callers that
    # do not want to import the verifier implementation directly.
    from app.mirror import profile_governance_v1_independent as verifier
    return verifier.verify_bytes(raw, profile_registry)


__all__ = [
    "ProfileGovernanceError", "GraphBinding", "SCHEMA", "WITHDRAWAL_SCHEMA",
    "APPROVAL_SCHEMA", "AUTHORIZATION_SCHEMA", "STAGE_CANDIDATE",
    "STAGE_TESTED", "STAGE_APPROVED", "STAGE_KINDS", "ACTION_WITHDRAWN",
    "AUTHORITY_FLAGS", "profile_descriptor", "profile_registry_digest",
    "bind_graph", "build_candidate", "build_tested", "build_approval_record",
    "build_approved", "build_withdrawal_authorization", "build_withdrawal",
    "canonical_bytes", "independent_verify", "verify_bytes", "verify_file",
]
