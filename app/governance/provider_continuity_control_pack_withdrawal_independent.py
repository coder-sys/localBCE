"""Independent verifier for the terminal observation-only withdrawal artifact.

Only the independent Control Pack verifier is composed here.  This module
never imports the producer, never issues authorization, and requires the
complete approved artifact to be embedded in the withdrawal.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Mapping, Sequence

from app.governance import provider_continuity_control_pack_independent as control_pack


class IndependentWithdrawalError(ValueError):
    """Raised when a terminal withdrawal cannot be authenticated independently."""


SCHEMA = "provider-continuity-control-pack-withdrawal-v1"
AUTHORIZATION_SCHEMA = "provider-continuity-withdrawal-authorization-v1"
ACTION = "WITHDRAWN_OBSERVATION_ONLY"
STATUS = ACTION
SCOPE = control_pack.SCOPE
PROVIDER_GRAPH_SUBJECT = control_pack.PROVIDER_GRAPH_SUBJECT
ORIGIN_MIRROR = control_pack.ORIGIN_MIRROR
APPROVAL_TIME = control_pack.APPROVAL_TIME
EFFECTIVE_START = control_pack.EFFECTIVE_START
EFFECTIVE_END = control_pack.EFFECTIVE_END
WITHDRAWAL_TIME = 7_400
EFFECTIVE_TIME = WITHDRAWAL_TIME

WITHDRAWAL_AUTHORITY_ID = "SYNTH_PROVIDER_CONTINUITY_WITHDRAWAL_AUTHORITY_001"
WITHDRAWER_ID = "SYNTH_PROVIDER_CONTINUITY_WITHDRAWER_001"
WITHDRAWER_ROLE = "OBSERVATION_CONTROL_PACK_WITHDRAWER"
WITHDRAWAL_REASON = "SYNTHETIC_OBSERVATION_ONLY_EARLY_STOP_V1"
TERMINAL_SENTINEL = "TERMINAL_NO_REACTIVATION_OR_SUPERSESSION_V1"

MAX_INPUT_BYTES = 262_144
MAX_AUTHORIZATION_BYTES = 16_384
MAX_ARTIFACT_BYTES = 524_288
MAX_STRING_BYTES = 256
MAX_NODES = 8_192
MAX_DEPTH = 16
MAX_TIMESTAMP = 2_147_483_647

AUTHORIZATION_KEYS = {
    "schema",
    "withdrawal_authorization_id",
    "authority_id",
    "withdrawer_id",
    "authorized_role",
    "reason_code",
    "withdrawal_time",
    "effective_time",
    "provider_graph_subject",
    "scope",
    "effective_start",
    "effective_end",
    "prior_approved_artifact_id",
    "prior_approved_stage_id",
    "prior_approved_stage_root",
    "prior_approval_id",
    "prior_approval_root",
    "source_contract_root",
    "suite_root",
    "terminal_sentinel",
    "synthetic_kat_seal",
}
AUTHORIZATION_CORE_KEYS = AUTHORIZATION_KEYS - {
    "withdrawal_authorization_id",
    "synthetic_kat_seal",
}
AUTHORITY_FLAGS = dict(control_pack.AUTHORITY_FLAGS)
DOMAIN = "BL/GOVERNANCE/PROVIDER-CONTINUITY-WITHDRAWAL/"
FORBIDDEN_EXTERNAL_TOKENS = tuple(control_pack.FORBIDDEN_EXTERNAL_TOKENS) + (
    "reactivation",
    "withdrawal_of_withdrawal",
    "activation",
)
_HEX = re.compile(r"^[0-9a-f]{128}$")

_STAGE_KEYS = {
    "stage_id", "stage_root", "stage_kind", "prior_stage_id", "prior_stage_root",
    "stage_time", "provider_graph_subject", "scope", "effective_start", "effective_end",
    "origin", "status", "source_contract_root", "candidate_root", "suite_root",
    "approval_root", "material",
}
_CONTROL_ARTIFACT_KEYS = {
    "artifact_id", "schema", "subject", "source_contracts", "stages",
    "current_stage_kind", "current_stage_id", "chain_root", *AUTHORITY_FLAGS.keys(),
}


def _canonical(value: object) -> bytes:
    try:
        rendered = json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise IndependentWithdrawalError("json:noncanonical-value") from exc
    return rendered.encode("ascii")


def canonical_bytes(value: Mapping[str, object]) -> bytes:
    if not isinstance(value, dict):
        raise IndependentWithdrawalError("json:top-level")
    _walk(value)
    _reject_forbidden(value)
    raw = _canonical(value)
    if len(raw) > MAX_INPUT_BYTES:
        raise IndependentWithdrawalError("json:byte-cap")
    return raw


def _duplicate_reject(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise IndependentWithdrawalError("json:duplicate-key")
        result[key] = value
    return result


def _walk(value: object, depth: int = 0, count: list[int] | None = None) -> None:
    if count is None:
        count = [0]
    count[0] += 1
    if count[0] > MAX_NODES:
        raise IndependentWithdrawalError("json:node-cap")
    if depth > MAX_DEPTH:
        raise IndependentWithdrawalError("json:depth-cap")
    if isinstance(value, float):
        raise IndependentWithdrawalError("json:float-forbidden")
    if isinstance(value, str):
        try:
            encoded = value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise IndependentWithdrawalError("json:non-ascii") from exc
        if len(encoded) > MAX_STRING_BYTES:
            raise IndependentWithdrawalError("json:string-cap")
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise IndependentWithdrawalError("json:key-type")
            _walk(key, depth + 1, count)
            _walk(item, depth + 1, count)
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth + 1, count)


def _reject_forbidden(value: object) -> None:
    if isinstance(value, str):
        if any(token in value for token in FORBIDDEN_EXTERNAL_TOKENS):
            raise IndependentWithdrawalError("payload:forbidden-token")
    elif isinstance(value, dict):
        for key, item in value.items():
            if any(token in key for token in FORBIDDEN_EXTERNAL_TOKENS):
                raise IndependentWithdrawalError("payload:forbidden-token")
            _reject_forbidden(item)
    elif isinstance(value, list):
        for item in value:
            _reject_forbidden(item)


def _parse(raw: bytes, *, artifact: bool = True) -> dict[str, object]:
    cap = MAX_ARTIFACT_BYTES if artifact else MAX_INPUT_BYTES
    if type(raw) is not bytes or not raw:
        raise IndependentWithdrawalError("json:empty-or-type")
    if len(raw) > cap:
        raise IndependentWithdrawalError("json:byte-cap")
    if any(byte > 0x7F for byte in raw):
        raise IndependentWithdrawalError("json:ascii")
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_duplicate_reject,
            parse_constant=lambda _value: (_ for _ in ()).throw(IndependentWithdrawalError("json:constant-forbidden")),
        )
    except IndependentWithdrawalError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IndependentWithdrawalError("json:parse") from exc
    if not isinstance(value, dict):
        raise IndependentWithdrawalError("json:top-level")
    _walk(value)
    _reject_forbidden(value)
    if _canonical(value) != raw:
        raise IndependentWithdrawalError("json:not-canonical")
    return value


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update((DOMAIN + label + "/v1\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _bytes_digest(label: str, raw: bytes) -> str:
    digest = hashlib.sha3_512()
    digest.update((DOMAIN + label + "/v1\0").encode("ascii"))
    digest.update(raw)
    return digest.hexdigest()


def _control_digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update(("BL/GOVERNANCE/PROVIDER-CONTINUITY-CONTROL-PACK/" + label + "/v1\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


AUTHORITY_PROFILE_ROOT = _digest("authority-profile-root", AUTHORITY_FLAGS)


def _expect_keys(value: object, expected: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise IndependentWithdrawalError(f"{label}:schema")
    return value


def _text(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise IndependentWithdrawalError(f"{label}:text")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise IndependentWithdrawalError(f"{label}:ascii") from exc
    if len(encoded) > MAX_STRING_BYTES:
        raise IndependentWithdrawalError(f"{label}:string-cap")
    return value


def _int(value: object, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= MAX_TIMESTAMP:
        raise IndependentWithdrawalError(f"{label}:integer")
    return value


def _hex(value: object, label: str) -> str:
    if type(value) is not str or _HEX.fullmatch(value) is None:
        raise IndependentWithdrawalError(f"{label}:hex")
    return value


def _withdrawal_body(value: Mapping[str, object]) -> dict[str, object]:
    return {key: item for key, item in value.items() if key not in {"artifact_id", "withdrawal_id", "withdrawal_root"}}


def _validate_prior(value: object) -> tuple[dict[str, object], dict[str, object], dict[str, object], dict[str, object]]:
    prior = _expect_keys(value, _CONTROL_ARTIFACT_KEYS, "prior:artifact")
    prior_raw = _canonical(prior)
    if len(prior_raw) > control_pack.MAX_ARTIFACT_BYTES:
        raise IndependentWithdrawalError("prior:byte-cap")
    try:
        result = control_pack.verify_bytes(prior_raw)
    except Exception as exc:
        raise IndependentWithdrawalError(f"prior:verify:{exc}") from exc
    if result.get("accepted") is not True or result.get("current_stage_kind") != control_pack.STAGE_APPROVED:
        raise IndependentWithdrawalError("prior:expected-approved")
    if result.get("artifact_id") != prior.get("artifact_id") or prior.get("schema") != control_pack.SCHEMA:
        raise IndependentWithdrawalError("prior:identity")
    if prior.get("subject") != {"provider_graph_subject": PROVIDER_GRAPH_SUBJECT, "scope": SCOPE}:
        raise IndependentWithdrawalError("prior:subject")
    stages = prior.get("stages")
    if not isinstance(stages, list) or len(stages) != 3:
        raise IndependentWithdrawalError("prior:exact-approved-chain")
    expected_kinds = [control_pack.STAGE_CANDIDATE, control_pack.STAGE_TESTED, control_pack.STAGE_APPROVED]
    if [stage.get("stage_kind") for stage in stages if isinstance(stage, dict)] != expected_kinds:
        raise IndependentWithdrawalError("prior:stage-order")
    stage = _expect_keys(stages[-1], _STAGE_KEYS, "prior:approved-stage")
    if stage["stage_kind"] != control_pack.STAGE_APPROVED or stage["status"] != control_pack.STAGE_APPROVED:
        raise IndependentWithdrawalError("prior:approved-stage-kind")
    if stage["origin"] != ORIGIN_MIRROR:
        raise IndependentWithdrawalError("prior:origin")
    if (stage["provider_graph_subject"], stage["scope"]) != (PROVIDER_GRAPH_SUBJECT, SCOPE):
        raise IndependentWithdrawalError("prior:subject-or-scope")
    if (stage["effective_start"], stage["effective_end"]) != (EFFECTIVE_START, EFFECTIVE_END):
        raise IndependentWithdrawalError("prior:effective-interval")
    if prior["current_stage_kind"] != control_pack.STAGE_APPROVED or prior["current_stage_id"] != stage["stage_id"]:
        raise IndependentWithdrawalError("prior:current-binding")
    material = _expect_keys(stage["material"], {"approval_record"}, "prior:approved-material")
    approval = _expect_keys(material["approval_record"], set(control_pack.APPROVAL_KEYS), "prior:approval-record")
    if stage["approval_root"] != _control_digest("approval-root", {"approval_record": approval}):
        raise IndependentWithdrawalError("prior:approval-root")
    approval_core = {key: approval[key] for key in control_pack.APPROVAL_CORE_KEYS}
    if approval["approval_id"] != _control_digest("approval-id", approval_core):
        raise IndependentWithdrawalError("prior:approval-id")
    if approval["tested_stage_id"] != stages[1]["stage_id"] or approval["tested_stage_root"] != stages[1]["stage_root"]:
        raise IndependentWithdrawalError("prior:approval-tested-binding")
    if approval["source_contract_root"] != stage["source_contract_root"] or approval["suite_root"] != stage["suite_root"]:
        raise IndependentWithdrawalError("prior:approval-root-binding")
    if stage["stage_id"] != result.get("current_stage_id"):
        raise IndependentWithdrawalError("prior:stage-id")
    return prior, stage, approval, result


def _validate_authorization(record_value: object, prior: Mapping[str, object], stage: Mapping[str, object], approval: Mapping[str, object]) -> tuple[dict[str, object], str]:
    record = _expect_keys(record_value, AUTHORIZATION_KEYS, "authorization")
    for field in ("schema", "authority_id", "withdrawer_id", "authorized_role", "reason_code", "provider_graph_subject", "scope", "terminal_sentinel"):
        _text(record[field], f"authorization:{field}")
    if record["schema"] != AUTHORIZATION_SCHEMA:
        raise IndependentWithdrawalError("authorization:schema")
    for field in ("withdrawal_time", "effective_time", "effective_start", "effective_end"):
        _int(record[field], f"authorization:{field}", minimum=1)
    for field in ("withdrawal_authorization_id", "prior_approved_artifact_id", "prior_approved_stage_id", "prior_approved_stage_root", "prior_approval_id", "prior_approval_root", "source_contract_root", "suite_root", "synthetic_kat_seal"):
        _hex(record[field], f"authorization:{field}")
    expected = {
        "schema": AUTHORIZATION_SCHEMA,
        "authority_id": WITHDRAWAL_AUTHORITY_ID,
        "withdrawer_id": WITHDRAWER_ID,
        "authorized_role": WITHDRAWER_ROLE,
        "reason_code": WITHDRAWAL_REASON,
        "withdrawal_time": WITHDRAWAL_TIME,
        "effective_time": EFFECTIVE_TIME,
        "provider_graph_subject": PROVIDER_GRAPH_SUBJECT,
        "scope": SCOPE,
        "effective_start": EFFECTIVE_START,
        "effective_end": EFFECTIVE_END,
        "prior_approved_artifact_id": prior["artifact_id"],
        "prior_approved_stage_id": stage["stage_id"],
        "prior_approved_stage_root": stage["stage_root"],
        "prior_approval_id": approval["approval_id"],
        "prior_approval_root": stage["approval_root"],
        "source_contract_root": stage["source_contract_root"],
        "suite_root": stage["suite_root"],
        "terminal_sentinel": TERMINAL_SENTINEL,
    }
    for field, expected_value in expected.items():
        if record[field] != expected_value:
            raise IndependentWithdrawalError(f"authorization:binding:{field}")
    if not EFFECTIVE_START <= APPROVAL_TIME < WITHDRAWAL_TIME < EFFECTIVE_END:
        raise IndependentWithdrawalError("authorization:chronology-profile")
    if record["withdrawal_time"] != record["effective_time"]:
        raise IndependentWithdrawalError("authorization:effective-time")
    core = {key: record[key] for key in AUTHORIZATION_CORE_KEYS}
    expected_id = _digest("withdrawal-authorization-id", core)
    expected_seal = _digest("synthetic-kat-seal", {"withdrawal_authorization_id": expected_id, **core})
    if record["withdrawal_authorization_id"] != expected_id:
        raise IndependentWithdrawalError("authorization:id")
    if record["synthetic_kat_seal"] != expected_seal:
        raise IndependentWithdrawalError("authorization:seal")
    return record, _digest("withdrawal-authorization-root", {"authorization": record})


def _validate_artifact(value: object) -> dict[str, object]:
    expected_keys = {
        "artifact_id", "schema", "action", "status", "approved_artifact", "approved_artifact_id",
        "approved_artifact_sha3_512", "approved_stage_id", "approved_stage_root", "approval_id", "approval_root",
        "authority_profile_root", "effective_end", "effective_start", "effective_time", "origin",
        "provider_graph_subject", "scope", "source_contract_root", "suite_root", "terminal",
        "terminal_sentinel", "withdrawal_authorization", "withdrawal_authorization_id", "withdrawal_authorization_root",
        "withdrawal_time", "withdrawal_id", "withdrawal_root", *AUTHORITY_FLAGS.keys(),
    }
    item = _expect_keys(value, expected_keys, "artifact")
    for field in ("artifact_id", "withdrawal_id", "withdrawal_root", "approved_artifact_sha3_512"):
        _hex(item[field], f"artifact:{field}")
    if item["schema"] != SCHEMA or item["action"] != ACTION or item["status"] != STATUS:
        raise IndependentWithdrawalError("artifact:action-or-schema")
    if item["terminal"] is not True or item["terminal_sentinel"] != TERMINAL_SENTINEL:
        raise IndependentWithdrawalError("artifact:terminal")
    if (item["provider_graph_subject"], item["scope"], item["origin"]) != (PROVIDER_GRAPH_SUBJECT, SCOPE, ORIGIN_MIRROR):
        raise IndependentWithdrawalError("artifact:subject-or-origin")
    if (item["effective_start"], item["effective_end"]) != (EFFECTIVE_START, EFFECTIVE_END):
        raise IndependentWithdrawalError("artifact:effective-interval")
    if (item["effective_time"], item["withdrawal_time"]) != (EFFECTIVE_TIME, WITHDRAWAL_TIME):
        raise IndependentWithdrawalError("artifact:withdrawal-time")
    if {key: item[key] for key in AUTHORITY_FLAGS} != AUTHORITY_FLAGS:
        raise IndependentWithdrawalError("artifact:authority-flags")
    if item["authority_profile_root"] != AUTHORITY_PROFILE_ROOT:
        raise IndependentWithdrawalError("artifact:authority-profile-root")
    prior, stage, approval, prior_result = _validate_prior(item["approved_artifact"])
    prior_raw = _canonical(prior)
    if item["approved_artifact_id"] != prior["artifact_id"] or item["approved_artifact_id"] != prior_result["artifact_id"]:
        raise IndependentWithdrawalError("artifact:prior-id")
    if item["approved_artifact_sha3_512"] != _bytes_digest("approved-artifact", prior_raw):
        raise IndependentWithdrawalError("artifact:prior-bytes")
    if item["approved_stage_id"] != stage["stage_id"] or item["approved_stage_root"] != stage["stage_root"]:
        raise IndependentWithdrawalError("artifact:approved-stage-binding")
    if item["approval_id"] != approval["approval_id"] or item["approval_root"] != stage["approval_root"]:
        raise IndependentWithdrawalError("artifact:approval-binding")
    if item["source_contract_root"] != stage["source_contract_root"] or item["suite_root"] != stage["suite_root"]:
        raise IndependentWithdrawalError("artifact:source-or-suite-binding")
    authorization, authorization_root = _validate_authorization(item["withdrawal_authorization"], prior, stage, approval)
    if item["withdrawal_authorization_id"] != authorization["withdrawal_authorization_id"]:
        raise IndependentWithdrawalError("artifact:authorization-id")
    if item["withdrawal_authorization_root"] != authorization_root:
        raise IndependentWithdrawalError("artifact:authorization-root")
    if item["withdrawal_root"] != _digest("withdrawal-root", _withdrawal_body(item)):
        raise IndependentWithdrawalError("artifact:withdrawal-root")
    if item["withdrawal_id"] != _digest("withdrawal-id", {"action": ACTION, "withdrawal_root": item["withdrawal_root"]}):
        raise IndependentWithdrawalError("artifact:withdrawal-id")
    if item["artifact_id"] != _digest("artifact-id", {key: item[key] for key in item if key != "artifact_id"}):
        raise IndependentWithdrawalError("artifact:id-mismatch")
    return {
        "accepted": True,
        "artifact_bytes": len(_canonical(item)),
        "artifact_id": item["artifact_id"],
        "withdrawal_id": item["withdrawal_id"],
        "withdrawal_root": item["withdrawal_root"],
        "approved_artifact_id": item["approved_artifact_id"],
        "approved_stage_id": item["approved_stage_id"],
        "approval_id": item["approval_id"],
        "status": STATUS,
        "action": ACTION,
        "synthetic_only": True,
        "production_usable": False,
    }


def verify_bytes(raw: bytes) -> dict[str, object]:
    return _validate_artifact(_parse(raw))


def verify_file(path: str | Path) -> dict[str, object]:
    file_path = Path(path)
    if file_path.stat().st_size > MAX_ARTIFACT_BYTES:
        raise IndependentWithdrawalError("file:byte-cap")
    with file_path.open("rb") as handle:
        raw = handle.read(MAX_ARTIFACT_BYTES + 1)
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise IndependentWithdrawalError("file:byte-cap")
    return verify_bytes(raw)


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: python -m app.governance.provider_continuity_control_pack_withdrawal_independent ARTIFACT.json", file=sys.stderr)
        return 2
    try:
        print(json.dumps(verify_file(args[0]), sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, IndependentWithdrawalError) as exc:
        print(f"REJECT {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
