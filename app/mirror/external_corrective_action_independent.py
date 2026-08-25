"""Independent verifier for the bounded corrective-action artifact."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Mapping

from app.mirror.error_boundary import raise_redacted


MAX_EVIDENCE_BYTES = 65_536
MAX_ARTIFACT_BYTES = 32_768
SCHEMA = "mirror-corrective-action-v1"
SCHEMA_VERSION = 1
MAX_TIMESTAMP = 2_147_483_647
FIXED_FLAGS = {
    "synthetic_only": True,
    "production_usable": False,
    "activation": False,
    "state_owned_control": True,
    "payment_authority": False,
    "clearance_authority": False,
    "settlement_authority": False,
    "adjudication_authority": False,
}
_HEX = re.compile(r"^[0-9a-f]{128}$")
_POLICY_KEYS = {"case_id", "current_case_artifact_id", "source_artifact_id", "graph_artifact_id", "graph_report_id", "target_finding_ids", "target_finding_kinds", "verifier_id", "verifier_epoch", "authority_evidence_digest", "revocation_head_digest", "terms_digest", "retention_policy_digest", "valid_from", "valid_until", "max_evidence_bytes", "flags"}
_ASSERTION_KEYS = {"action_id", "case_id", "current_case_artifact_id", "source_artifact_id", "graph_artifact_id", "graph_report_id", "target_finding_ids", "target_finding_kinds", "action_code", "observed_at", "valid_from", "valid_until", "verifier_id", "verifier_epoch", "evidence_sha3_512", "evidence_byte_length"}
_ARTIFACT_KEYS = {"schema", "schema_version", "kind", "artifact_id", "policy", "policy_digest", "assertion", "flags"}
_CONTROL_KEYS = (
    "verifier_id",
    "verifier_epoch",
    "authority_evidence_digest",
    "revocation_head_digest",
    "terms_digest",
    "retention_policy_digest",
    "valid_from",
    "valid_until",
    "max_evidence_bytes",
)


class IndependentCorrectiveActionError(ValueError):
    """Fixed independent failure."""


def _canonical(value: object) -> bytes:
    try:
        raw = json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise_redacted(IndependentCorrectiveActionError, "action:noncanonical")
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise IndependentCorrectiveActionError("action:byte-cap")
    return raw


def _digest(label: str, value: object) -> str:
    h = hashlib.sha3_512()
    h.update(("BL/MIRROR/CORRECTIVE-ACTION/V1/" + label + "\0").encode("ascii"))
    h.update(_canonical(value))
    return h.hexdigest()


def _raw_digest(raw: bytes) -> str:
    h = hashlib.sha3_512()
    h.update(b"BL/MIRROR/CORRECTIVE-ACTION/V1/evidence\0")
    h.update(raw)
    return h.hexdigest()


def _expect(value: object, keys: set[str], code: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise IndependentCorrectiveActionError(code)
    return value


def _hex(value: object, code: str) -> str:
    if not isinstance(value, str) or _HEX.fullmatch(value) is None:
        raise IndependentCorrectiveActionError(code)
    return value


def _ascii(value: object, code: str, maximum: int = 128) -> str:
    if not isinstance(value, str) or not value:
        raise IndependentCorrectiveActionError(code)
    try:
        if len(value.encode("ascii")) > maximum or any(not (char.isalnum() or char in "._:-") for char in value):
            raise IndependentCorrectiveActionError(code)
    except UnicodeEncodeError:
        raise_redacted(IndependentCorrectiveActionError, code)
    return value


def _parse(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_ARTIFACT_BYTES:
        raise IndependentCorrectiveActionError("action:byte-cap")
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_duplicate, parse_constant=lambda _value: (_ for _ in ()).throw(IndependentCorrectiveActionError("action:constant")))
    except IndependentCorrectiveActionError:
        raise
    except Exception:
        raise_redacted(IndependentCorrectiveActionError, "action:parse")
    if not isinstance(value, dict) or _canonical(value) != raw:
        raise IndependentCorrectiveActionError("action:canonical")
    return value


def _duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise IndependentCorrectiveActionError("action:duplicate")
        result[key] = value
    return result


def _validate_policy(policy: Mapping[str, object]) -> dict[str, object]:
    item = _expect(policy, _POLICY_KEYS, "policy:schema")
    for key in ("case_id", "current_case_artifact_id", "source_artifact_id", "graph_artifact_id", "graph_report_id", "authority_evidence_digest", "revocation_head_digest", "terms_digest", "retention_policy_digest"):
        _hex(item[key], "policy:identity")
    ids = item["target_finding_ids"]
    kinds = item["target_finding_kinds"]
    if not isinstance(ids, list) or not isinstance(kinds, list) or not ids or len(ids) != len(kinds) or len(ids) > 8 or ids != sorted(ids) or len(set(ids)) != len(ids):
        raise IndependentCorrectiveActionError("policy:findings")
    for value in ids:
        _hex(value, "policy:finding")
    for value in kinds:
        _ascii(value, "policy:finding-kind")
    _ascii(item["verifier_id"], "policy:verifier")
    if type(item["verifier_epoch"]) is not int or item["verifier_epoch"] < 0 or type(item["valid_from"]) is not int or type(item["valid_until"]) is not int or not 0 <= item["valid_from"] <= item["valid_until"] <= MAX_TIMESTAMP or type(item["max_evidence_bytes"]) is not int or not 1 <= item["max_evidence_bytes"] <= MAX_EVIDENCE_BYTES:
        raise IndependentCorrectiveActionError("policy:interval-or-cap")
    if item["flags"] != FIXED_FLAGS:
        raise IndependentCorrectiveActionError("policy:flags")
    return item


def control_digest_from_policy(policy: Mapping[str, object]) -> str:
    if not isinstance(policy, Mapping):
        raise IndependentCorrectiveActionError("policy:control")
    try:
        material = {key: policy[key] for key in _CONTROL_KEYS}
    except (KeyError, TypeError):
        raise_redacted(IndependentCorrectiveActionError, "policy:control")
    _ascii(material["verifier_id"], "policy:verifier")
    for key in ("authority_evidence_digest", "revocation_head_digest", "terms_digest", "retention_policy_digest"):
        _hex(material[key], "policy:control")
    if (
        type(material["verifier_epoch"]) is not int
        or material["verifier_epoch"] < 0
        or type(material["valid_from"]) is not int
        or type(material["valid_until"]) is not int
        or not 0 <= material["valid_from"] <= material["valid_until"] <= MAX_TIMESTAMP
        or type(material["max_evidence_bytes"]) is not int
        or not 1 <= material["max_evidence_bytes"] <= MAX_EVIDENCE_BYTES
    ):
        raise IndependentCorrectiveActionError("policy:control")
    return _digest("control", material)


def verify_artifact(
    raw: bytes,
    *,
    policy: Mapping[str, object] | None = None,
    evidence_raw: bytes | None = None,
    control_digest: str,
) -> dict[str, object]:
    if not isinstance(control_digest, str) or _HEX.fullmatch(control_digest) is None:
        raise IndependentCorrectiveActionError("action:control")
    artifact = _parse(raw)
    if _expect(artifact, _ARTIFACT_KEYS, "action:schema")["schema"] != SCHEMA or artifact["schema_version"] != SCHEMA_VERSION or artifact["kind"] != "CORRECTIVE_ACTION":
        raise IndependentCorrectiveActionError("action:identity")
    artifact_policy = _validate_policy(artifact["policy"])
    if artifact["flags"] != FIXED_FLAGS:
        raise IndependentCorrectiveActionError("action:flags")
    policy_digest = _digest("policy", artifact_policy)
    if artifact["policy_digest"] != policy_digest:
        raise IndependentCorrectiveActionError("action:policy-digest")
    derived_control_digest = control_digest_from_policy(artifact_policy)
    if derived_control_digest != control_digest:
        raise IndependentCorrectiveActionError("action:control")
    if policy is not None:
        supplied = _validate_policy(policy)
        if supplied != artifact_policy:
            raise IndependentCorrectiveActionError("action:policy-binding")
    assertion = _expect(artifact["assertion"], _ASSERTION_KEYS, "action:assertion")
    if assertion["case_id"] != artifact_policy["case_id"] or assertion["current_case_artifact_id"] != artifact_policy["current_case_artifact_id"] or assertion["source_artifact_id"] != artifact_policy["source_artifact_id"] or assertion["graph_artifact_id"] != artifact_policy["graph_artifact_id"] or assertion["graph_report_id"] != artifact_policy["graph_report_id"]:
        raise IndependentCorrectiveActionError("action:binding")
    if assertion["target_finding_ids"] != artifact_policy["target_finding_ids"] or assertion["target_finding_kinds"] != artifact_policy["target_finding_kinds"] or assertion["verifier_id"] != artifact_policy["verifier_id"] or assertion["verifier_epoch"] != artifact_policy["verifier_epoch"] or assertion["action_code"] != "CORRECTIVE_ACTION_RECORDED":
        raise IndependentCorrectiveActionError("action:binding")
    for key in ("action_id", "evidence_sha3_512"):
        _hex(assertion[key], "action:identity")
    if type(assertion["observed_at"]) is not int or not artifact_policy["valid_from"] <= assertion["observed_at"] <= artifact_policy["valid_until"] or assertion["valid_from"] != artifact_policy["valid_from"] or assertion["valid_until"] != artifact_policy["valid_until"]:
        raise IndependentCorrectiveActionError("action:interval")
    if type(assertion["evidence_byte_length"]) is not int or not 1 <= assertion["evidence_byte_length"] <= artifact_policy["max_evidence_bytes"]:
        raise IndependentCorrectiveActionError("action:evidence-length")
    if evidence_raw is not None:
        if type(evidence_raw) is not bytes or len(evidence_raw) != assertion["evidence_byte_length"] or _raw_digest(evidence_raw) != assertion["evidence_sha3_512"]:
            raise IndependentCorrectiveActionError("action:evidence-binding")
    expected_action_id = _digest(
        "action-id",
        {
            "policy_digest": artifact["policy_digest"],
            "evidence_sha3_512": assertion["evidence_sha3_512"],
            "action_code": assertion["action_code"],
            "observed_at": assertion["observed_at"],
        },
    )
    if assertion["action_id"] != expected_action_id:
        raise IndependentCorrectiveActionError("action:id")
    expected_id = _digest("artifact-id", {key: artifact[key] for key in _ARTIFACT_KEYS if key != "artifact_id"})
    if artifact["artifact_id"] != expected_id:
        raise IndependentCorrectiveActionError("action:id")
    return {"accepted": True, "artifact_id": artifact["artifact_id"], "policy_digest": policy_digest, "control_digest": derived_control_digest, "case_id": artifact_policy["case_id"], "current_case_artifact_id": artifact_policy["current_case_artifact_id"], "source_artifact_id": artifact_policy["source_artifact_id"], "graph_artifact_id": artifact_policy["graph_artifact_id"], "graph_report_id": artifact_policy["graph_report_id"], "target_finding_ids": tuple(artifact_policy["target_finding_ids"]), "target_finding_kinds": tuple(artifact_policy["target_finding_kinds"]), "action_code": assertion["action_code"], "observed_at": assertion["observed_at"], "verifier_id": assertion["verifier_id"], "verifier_epoch": assertion["verifier_epoch"], "evidence_sha3_512": assertion["evidence_sha3_512"], "evidence_byte_length": assertion["evidence_byte_length"], "policy": artifact_policy}


def verify_bytes(raw: bytes, *, control_digest: str, policy: Mapping[str, object] | None = None, evidence_raw: bytes | None = None) -> dict[str, object]:
    return verify_artifact(raw, policy=policy, evidence_raw=evidence_raw, control_digest=control_digest)


def main(argv: list[str] | None = None) -> int:
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
