"""Synthetic terminal withdrawal for one approved observation-only Control Pack.

This module consumes a complete, independently verified Control Pack V1 artifact and a
separately supplied synthetic withdrawal-authorization KAT record.  The resulting artifact is
terminal and observation-only: there is deliberately no reactivation, replacement, supersession,
clearance, payment, or economic transition API.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import sys
import time
from typing import Mapping, Sequence

from app.governance import provider_continuity_control_pack as control_pack
from app.governance import provider_continuity_control_pack_independent as control_pack_independent


class WithdrawalError(ValueError):
    """Raised for malformed, substituted, or non-terminal withdrawal evidence."""


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

AUTHORITY_FLAGS = deepcopy(control_pack.AUTHORITY_FLAGS)
DOMAIN = "BL/GOVERNANCE/PROVIDER-CONTINUITY-WITHDRAWAL/"
FORBIDDEN_EXTERNAL_TOKENS = tuple(control_pack.FORBIDDEN_EXTERNAL_TOKENS) + (
    "reactivation",
    "withdrawal_of_withdrawal",
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
        raise WithdrawalError("json:noncanonical-value") from exc
    return rendered.encode("ascii")


def canonical_bytes(value: Mapping[str, object]) -> bytes:
    if not isinstance(value, dict):
        raise WithdrawalError("json:top-level")
    _walk(value)
    _reject_forbidden(value)
    raw = _canonical(value)
    if len(raw) > MAX_INPUT_BYTES:
        raise WithdrawalError("json:byte-cap")
    return raw


def _duplicate_reject(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise WithdrawalError("json:duplicate-key")
        result[key] = value
    return result


def _walk(value: object, depth: int = 0, count: list[int] | None = None) -> None:
    if count is None:
        count = [0]
    count[0] += 1
    if count[0] > MAX_NODES:
        raise WithdrawalError("json:node-cap")
    if depth > MAX_DEPTH:
        raise WithdrawalError("json:depth-cap")
    if isinstance(value, float):
        raise WithdrawalError("json:float-forbidden")
    if isinstance(value, str):
        try:
            encoded = value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise WithdrawalError("json:non-ascii") from exc
        if len(encoded) > MAX_STRING_BYTES:
            raise WithdrawalError("json:string-cap")
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise WithdrawalError("json:key-type")
            _walk(key, depth + 1, count)
            _walk(item, depth + 1, count)
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth + 1, count)


def _reject_forbidden(value: object) -> None:
    if isinstance(value, str):
        if any(token in value for token in FORBIDDEN_EXTERNAL_TOKENS):
            raise WithdrawalError("payload:forbidden-token")
    elif isinstance(value, dict):
        for key, item in value.items():
            if any(token in key for token in FORBIDDEN_EXTERNAL_TOKENS):
                raise WithdrawalError("payload:forbidden-token")
            _reject_forbidden(item)
    elif isinstance(value, list):
        for item in value:
            _reject_forbidden(item)


def parse_canonical(raw: bytes, *, artifact: bool = True) -> dict[str, object]:
    cap = MAX_ARTIFACT_BYTES if artifact else MAX_INPUT_BYTES
    if type(raw) is not bytes or not raw:
        raise WithdrawalError("json:empty-or-type")
    if len(raw) > cap:
        raise WithdrawalError("json:byte-cap")
    if any(byte > 0x7F for byte in raw):
        raise WithdrawalError("json:ascii")
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_duplicate_reject,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                WithdrawalError("json:constant-forbidden")
            ),
        )
    except WithdrawalError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WithdrawalError("json:parse") from exc
    if not isinstance(value, dict):
        raise WithdrawalError("json:top-level")
    _walk(value)
    _reject_forbidden(value)
    if _canonical(value) != raw:
        raise WithdrawalError("json:not-canonical")
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


AUTHORITY_PROFILE_ROOT = _digest("authority-profile-root", AUTHORITY_FLAGS)


def _expect_keys(value: object, expected: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise WithdrawalError(f"{label}:schema")
    return value


def _text(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise WithdrawalError(f"{label}:text")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise WithdrawalError(f"{label}:ascii") from exc
    if len(encoded) > MAX_STRING_BYTES:
        raise WithdrawalError(f"{label}:string-cap")
    return value


def _int(value: object, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= MAX_TIMESTAMP:
        raise WithdrawalError(f"{label}:integer")
    return value


def _bool(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise WithdrawalError(f"{label}:boolean")
    return value


def _hex(value: object, label: str) -> str:
    if type(value) is not str or _HEX.fullmatch(value) is None:
        raise WithdrawalError(f"{label}:hex")
    return value


def _approved_material(approved_raw: bytes) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    if type(approved_raw) is not bytes or not approved_raw:
        raise WithdrawalError("prior:empty-or-type")
    try:
        result = control_pack_independent.verify_bytes(approved_raw)
    except Exception as exc:
        raise WithdrawalError(f"prior:verify:{exc}") from exc
    if result.get("current_stage_kind") != control_pack.STAGE_APPROVED:
        raise WithdrawalError("prior:expected-approved")
    approved = control_pack.parse_canonical(approved_raw, artifact=True)
    stages = approved.get("stages")
    if not isinstance(stages, list) or len(stages) != 3:
        raise WithdrawalError("prior:approved-chain")
    stage = stages[-1]
    if not isinstance(stage, dict) or stage.get("stage_kind") != control_pack.STAGE_APPROVED:
        raise WithdrawalError("prior:approved-stage")
    material = _expect_keys(stage.get("material"), {"approval_record"}, "prior:approved-material")
    approval = _expect_keys(material["approval_record"], control_pack.APPROVAL_KEYS, "prior:approval-record")
    if stage.get("origin") != ORIGIN_MIRROR:
        raise WithdrawalError("prior:origin")
    return approved, stage, approval


def _parse_authorization(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or not raw:
        raise WithdrawalError("authorization:empty-or-type")
    if len(raw) > MAX_AUTHORIZATION_BYTES:
        raise WithdrawalError("authorization:byte-cap")
    return _expect_keys(parse_canonical(raw, artifact=False), AUTHORIZATION_KEYS, "authorization")


def _validate_authorization(
    raw: bytes,
    approved: Mapping[str, object],
    stage: Mapping[str, object],
    approval: Mapping[str, object],
) -> tuple[dict[str, object], str]:
    record = _parse_authorization(raw)
    for field in ("schema", "authority_id", "withdrawer_id", "authorized_role", "reason_code", "provider_graph_subject", "scope", "terminal_sentinel"):
        _text(record[field], f"authorization:{field}")
    if record["schema"] != AUTHORIZATION_SCHEMA:
        raise WithdrawalError("authorization:schema")
    _int(record["withdrawal_time"], "authorization:withdrawal-time", minimum=1)
    _int(record["effective_time"], "authorization:effective-time", minimum=1)
    _int(record["effective_start"], "authorization:effective-start", minimum=1)
    _int(record["effective_end"], "authorization:effective-end", minimum=1)
    for field in (
        "withdrawal_authorization_id",
        "prior_approved_artifact_id",
        "prior_approved_stage_id",
        "prior_approved_stage_root",
        "prior_approval_id",
        "prior_approval_root",
        "source_contract_root",
        "suite_root",
        "synthetic_kat_seal",
    ):
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
        "prior_approved_artifact_id": approved["artifact_id"],
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
            raise WithdrawalError(f"authorization:binding:{field}")
    if not APPROVAL_TIME < WITHDRAWAL_TIME < EFFECTIVE_END:
        raise WithdrawalError("authorization:chronology-profile")
    if record["withdrawal_time"] != record["effective_time"]:
        raise WithdrawalError("authorization:effective-time")
    core = {key: record[key] for key in AUTHORIZATION_CORE_KEYS}
    expected_id = _digest("withdrawal-authorization-id", core)
    expected_seal = _digest("synthetic-kat-seal", {"withdrawal_authorization_id": expected_id, **core})
    if record["withdrawal_authorization_id"] != expected_id:
        raise WithdrawalError("authorization:id")
    if record["synthetic_kat_seal"] != expected_seal:
        raise WithdrawalError("authorization:seal")
    return record, _digest("withdrawal-authorization-root", {"authorization": record})


def _withdrawal_body(value: Mapping[str, object]) -> dict[str, object]:
    return {
        key: item
        for key, item in value.items()
        if key not in {"artifact_id", "withdrawal_id", "withdrawal_root"}
    }


def _encode_artifact(value: Mapping[str, object]) -> bytes:
    _walk(value)
    _reject_forbidden(value)
    raw = _canonical(value)
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise WithdrawalError("artifact:byte-cap")
    return raw


def build_withdrawal(approved_raw: bytes, authorization_raw: bytes) -> tuple[bytes, dict[str, object]]:
    """Build one terminal withdrawal from a complete approved artifact and exact auth bytes."""

    start = time.perf_counter_ns()
    approved, stage, approval = _approved_material(approved_raw)
    authorization, authorization_root = _validate_authorization(
        authorization_raw,
        approved,
        stage,
        approval,
    )
    body: dict[str, object] = {
        "action": ACTION,
        "approval_id": approval["approval_id"],
        "approval_root": stage["approval_root"],
        "approved_artifact": deepcopy(approved),
        "approved_artifact_id": approved["artifact_id"],
        "approved_artifact_sha3_512": _bytes_digest("approved-artifact", approved_raw),
        "approved_stage_id": stage["stage_id"],
        "approved_stage_root": stage["stage_root"],
        "authority_profile_root": AUTHORITY_PROFILE_ROOT,
        "effective_end": stage["effective_end"],
        "effective_start": stage["effective_start"],
        "effective_time": EFFECTIVE_TIME,
        "origin": stage["origin"],
        "provider_graph_subject": stage["provider_graph_subject"],
        "scope": stage["scope"],
        "source_contract_root": stage["source_contract_root"],
        "status": STATUS,
        "suite_root": stage["suite_root"],
        "terminal": True,
        "terminal_sentinel": TERMINAL_SENTINEL,
        "withdrawal_authorization": authorization,
        "withdrawal_authorization_id": authorization["withdrawal_authorization_id"],
        "withdrawal_authorization_root": authorization_root,
        "withdrawal_time": WITHDRAWAL_TIME,
        "schema": SCHEMA,
        **deepcopy(AUTHORITY_FLAGS),
    }
    body["withdrawal_root"] = _digest("withdrawal-root", _withdrawal_body(body))
    body["withdrawal_id"] = _digest("withdrawal-id", {"action": ACTION, "withdrawal_root": body["withdrawal_root"]})
    body["artifact_id"] = _digest("artifact-id", {key: item for key, item in body.items() if key != "artifact_id"})
    raw = _encode_artifact(body)
    try:
        from app.governance import provider_continuity_control_pack_withdrawal_independent as independent

        independent.verify_bytes(raw)
    except Exception as exc:
        raise WithdrawalError(str(exc)) from exc
    telemetry = {
        "artifact_bytes": len(raw),
        "wall_time_ns": time.perf_counter_ns() - start,
        "process_tree_peak_bytes": control_pack._process_peak_bytes(),
        "process_tree_scope": "single-process; no child processes",
        "children_launched": 0,
        "governance_performance_claim": False,
        "proof_performance_claim": False,
    }
    return raw, telemetry


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2:
        print("usage: python -m app.governance.provider_continuity_control_pack_withdrawal APPROVED.json AUTHORIZATION.json")
        return 2
    try:
        raw, telemetry = build_withdrawal(Path(args[0]).read_bytes(), Path(args[1]).read_bytes())
        print(json.dumps({"accepted": True, "artifact_bytes": len(raw), "telemetry": telemetry}, sort_keys=True, separators=(",", ":")))
        return 0
    except Exception as exc:
        print(f"REJECT:{exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
