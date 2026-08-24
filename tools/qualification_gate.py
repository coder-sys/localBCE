"""Strict qualification and activation evaluator for the two ops authorities."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping, Sequence

from tools.ops_authority import OPS_AUTHORITY_STATUS, verify_ops_authority


ROOT = Path(__file__).resolve().parents[1]
OPS_ROOT = ROOT / "ops"
BLOCKERS_PATH = OPS_ROOT / "launch_blockers.json"
PIN_PATH = OPS_ROOT / "verifier_artifact_pin.example.json"
MAX_AUTHORITY_BYTES = 64 * 1024

BLOCKER_SCHEMA = "blind_ledger_launch_blockers_v2"
PIN_SCHEMA = "blind_ledger_verifier_artifact_pin_v2"
BLOCKER_KEYS = frozenset({"id", "classification", "gate", "status", "evidenceSha3_512"})
PIN_KEYS = frozenset(
    {
        "schema_version",
        "selection_state",
        "proofSuiteId",
        "artifactSha3_512",
        "verifierExecutableSha3_512",
        "production_usable",
        "activation",
    }
)
BLOCKER_IDENTITY = (
    ("BL-PROOF-SOUNDNESS", "internal_engineering", "qualification"),
    ("BL-PROOF-THROUGHPUT", "internal_engineering", "qualification"),
    ("BL-CLEARANCE-STATE-OWNER", "internal_engineering", "qualification"),
    ("BL-FORMAL-KERNEL", "internal_engineering", "qualification"),
    ("BL-CUSTODY-OPERATIONS", "deployment_evidence", "qualification"),
    ("BL-INDEPENDENT-AUDIT", "external_assurance", "qualification"),
    ("BL-OFFICIAL-RECEIVER", "external_integration", "activation"),
    ("BL-GOVERNMENT-CONNECTORS", "external_integration", "activation"),
)
QUALIFICATION_IDS = tuple(item[0] for item in BLOCKER_IDENTITY[:6])
ACTIVATION_IDS = tuple(item[0] for item in BLOCKER_IDENTITY)
_HEX_512 = re.compile(r"[0-9a-f]{128}\Z")
_SAFE_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z", re.ASCII)


class QualificationGateError(ValueError):
    """A malformed or incoherent authority with a deliberately fixed public message."""


def _invalid() -> None:
    raise QualificationGateError("qualification_gate_invalid")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _invalid()
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    _invalid()


def _decode_json(raw: bytes) -> Mapping[str, Any]:
    if type(raw) is not bytes or len(raw) > MAX_AUTHORITY_BYTES:
        _invalid()
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, QualificationGateError):
        _invalid()
    if type(value) is not dict:
        _invalid()
    return value


def _exact_keys(value: Mapping[str, Any], expected: frozenset[str]) -> None:
    if set(value) != expected:
        _invalid()


def _string(value: Any) -> str:
    if type(value) is not str:
        _invalid()
    return value


def _hash_or_none(value: Any) -> str | None:
    if value is None:
        return None
    value = _string(value)
    if _HEX_512.fullmatch(value) is None:
        _invalid()
    return value


def _read_authority(path: Path) -> bytes:
    try:
        if path.is_symlink() or not path.is_file():
            _invalid()
        raw = path.read_bytes()
    except (OSError, QualificationGateError):
        _invalid()
    if len(raw) > MAX_AUTHORITY_BYTES:
        _invalid()
    return raw


def parse_blockers(raw: bytes) -> tuple[dict[str, Any], ...]:
    """Parse and validate strict v2 blocker bytes."""

    document = _decode_json(raw)
    _exact_keys(document, frozenset({"schema_version", "blockers"}))
    if _string(document["schema_version"]) != BLOCKER_SCHEMA:
        _invalid()
    blockers = document["blockers"]
    if type(blockers) is not list or len(blockers) != len(BLOCKER_IDENTITY):
        _invalid()
    parsed: list[dict[str, Any]] = []
    for index, (item, identity) in enumerate(zip(blockers, BLOCKER_IDENTITY, strict=True)):
        if type(item) is not dict:
            _invalid()
        _exact_keys(item, BLOCKER_KEYS)
        if tuple(_string(item[field]) for field in ("id", "classification", "gate")) != identity:
            _invalid()
        status = _string(item["status"])
        evidence = item["evidenceSha3_512"]
        if status == "open":
            if evidence is not None:
                _invalid()
        elif status == "closed":
            if _hash_or_none(evidence) is None:
                _invalid()
        else:
            _invalid()
        parsed.append(dict(item))
    return tuple(parsed)


def parse_pin(raw: bytes) -> dict[str, Any]:
    """Parse and validate strict v2 verifier pin bytes."""

    document = _decode_json(raw)
    _exact_keys(document, PIN_KEYS)
    if _string(document["schema_version"]) != PIN_SCHEMA:
        _invalid()
    state = _string(document["selection_state"])
    if state not in {"UNSELECTED", "CANDIDATE", "QUALIFIED"}:
        _invalid()
    suite = document["proofSuiteId"]
    if suite is not None:
        suite = _string(suite)
        if _SAFE_TOKEN.fullmatch(suite) is None:
            _invalid()
    artifact = _hash_or_none(document["artifactSha3_512"])
    executable = _hash_or_none(document["verifierExecutableSha3_512"])
    production = document["production_usable"]
    activation = document["activation"]
    if type(production) is not bool or type(activation) is not bool:
        _invalid()
    identities = (suite, artifact, executable)
    if state == "UNSELECTED" and identities != (None, None, None,):
        _invalid()
    if state == "UNSELECTED" and (production is not False or activation is not False):
        _invalid()
    if state == "CANDIDATE" and any(value is None for value in identities):
        _invalid()
    if state == "CANDIDATE" and (production is not False or activation is not False):
        _invalid()
    if state == "QUALIFIED" and any(value is None for value in identities):
        _invalid()
    if production and state != "QUALIFIED":
        _invalid()
    if activation and (state != "QUALIFIED" or not production):
        _invalid()
    return dict(document)


def _validate_blockers(blockers: Sequence[Mapping[str, Any]]) -> tuple[dict[str, Any], ...]:
    try:
        if type(blockers) not in {list, tuple}:
            _invalid()
        raw = {
            "schema_version": BLOCKER_SCHEMA,
            "blockers": [dict(item) for item in blockers],
        }
        encoded = json.dumps(raw, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    except (TypeError, ValueError, OverflowError):
        _invalid()
    return parse_blockers(encoded)


def _validate_pin(pin: Mapping[str, Any]) -> dict[str, Any]:
    if type(pin) is not dict:
        _invalid()
    try:
        encoded = json.dumps(dict(pin), separators=(",", ":"), ensure_ascii=True).encode("ascii")
    except (TypeError, ValueError):
        _invalid()
    return parse_pin(encoded)


def _closed(item: Mapping[str, Any]) -> bool:
    return item["status"] == "closed" and _HEX_512.fullmatch(item["evidenceSha3_512"]) is not None


@dataclass(frozen=True)
class QualificationEvaluation:
    qualification_state: str
    activation_state: str
    qualification_open: tuple[str, ...]
    activation_open: tuple[str, ...]
    selection_state: str
    proofSuiteId: str | None
    production_usable: bool
    activation: bool


def evaluate(blockers: Sequence[Mapping[str, Any]], pin: Mapping[str, Any]) -> QualificationEvaluation:
    """Evaluate already parsed authorities and enforce monotonic state consistency."""

    checked_blockers = _validate_blockers(blockers)
    checked_pin = _validate_pin(pin)
    qualification_open = tuple(
        item["id"] for item in checked_blockers[:6] if not _closed(item)
    )
    activation_open = tuple(item["id"] for item in checked_blockers if not _closed(item))
    qualification_closed = not qualification_open
    activation_closed = not activation_open
    state = checked_pin["selection_state"]
    production = checked_pin["production_usable"]
    activation = checked_pin["activation"]
    if qualification_closed and state != "QUALIFIED":
        _invalid()
    if not qualification_closed and state == "QUALIFIED":
        _invalid()
    if production and not qualification_closed:
        _invalid()
    if activation and (not activation_closed or not production or state != "QUALIFIED"):
        _invalid()
    if activation_closed and state != "QUALIFIED":
        _invalid()
    qualification_state = "QUALIFIED" if qualification_closed and state == "QUALIFIED" and production else "NOT_QUALIFIED"
    activation_state = "ACTIVE" if activation_closed and activation and production and state == "QUALIFIED" else "INACTIVE"
    return QualificationEvaluation(
        qualification_state,
        activation_state,
        qualification_open,
        activation_open,
        state,
        checked_pin["proofSuiteId"],
        production,
        activation,
    )


def _load_current() -> tuple[bytes, bytes, QualificationEvaluation]:
    # Authority verification is deliberately first so no caller can substitute either file.
    verify_ops_authority()
    blockers_raw = _read_authority(BLOCKERS_PATH)
    pin_raw = _read_authority(PIN_PATH)
    blockers = parse_blockers(blockers_raw)
    pin = parse_pin(pin_raw)
    return blockers_raw, pin_raw, evaluate(blockers, pin)


def inspect_current() -> dict[str, Any]:
    """Return the bounded, privacy-safe current inspection object."""

    blockers_raw, pin_raw, result = _load_current()
    return {
        "qualification_state": result.qualification_state,
        "activation_state": result.activation_state,
        "qualification_open": list(result.qualification_open),
        "activation_open": list(result.activation_open),
        "selection_state": result.selection_state,
        "proofSuiteId": result.proofSuiteId,
        "production_usable": result.production_usable,
        "activation": result.activation,
        "blockersSha3_512": hashlib.sha3_512(blockers_raw).hexdigest(),
        "pinSha3_512": hashlib.sha3_512(pin_raw).hexdigest(),
        "opsAuthority": OPS_AUTHORITY_STATUS,
    }


def main(argv: Sequence[str] | None = None) -> int:
    args = tuple(sys.argv[1:] if argv is None else argv)
    if len(args) != 1 or args[0] not in {"inspect", "require-production", "require-activation"}:
        print("qualification_gate=invalid", file=sys.stderr)
        return 2
    try:
        blockers_raw, pin_raw, result = _load_current()
        if args[0] == "inspect":
            payload = {
                "qualification_state": result.qualification_state,
                "activation_state": result.activation_state,
                "qualification_open": list(result.qualification_open),
                "activation_open": list(result.activation_open),
                "selection_state": result.selection_state,
                "proofSuiteId": result.proofSuiteId,
                "production_usable": result.production_usable,
                "activation": result.activation,
                "blockersSha3_512": hashlib.sha3_512(blockers_raw).hexdigest(),
                "pinSha3_512": hashlib.sha3_512(pin_raw).hexdigest(),
                "opsAuthority": OPS_AUTHORITY_STATUS,
            }
            print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
            return 0
        if args[0] == "require-production":
            if result.qualification_state != "QUALIFIED":
                print("qualification_gate=not_production_usable", file=sys.stderr)
                return 1
            print("qualification_gate=production_usable")
            return 0
        if result.activation_state != "ACTIVE":
            print("qualification_gate=not_activated", file=sys.stderr)
            return 1
        print("qualification_gate=activated")
        return 0
    except Exception:
        print("qualification_gate=invalid", file=sys.stderr)
        return 2


__all__ = (
    "ACTIVATION_IDS",
    "BLOCKER_IDENTITY",
    "BLOCKER_SCHEMA",
    "MAX_AUTHORITY_BYTES",
    "PIN_SCHEMA",
    "QualificationEvaluation",
    "QualificationGateError",
    "evaluate",
    "inspect_current",
    "main",
    "parse_blockers",
    "parse_pin",
)


if __name__ == "__main__":
    raise SystemExit(main())
