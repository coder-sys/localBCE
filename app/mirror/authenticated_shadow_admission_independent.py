"""Independent reconstruction for authenticated shadow admission.

This module owns only the grammar and replay rules for the admission ledger.
It imports independent upstream/runtime verifiers, never their producers, and
never authenticates an external authority or emits a runtime directive.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sqlite3
from typing import Mapping

from app.mirror import authenticated_source_acquisition_independent as acquisition
from app.mirror import controlled_shadow_runtime_independent as runtime
from app.mirror import sqlite_snapshot


SCHEMA = "mirror-authenticated-shadow-admission-v1"
SCHEMA_VERSION = 1
EXPORT_SCHEMA = "mirror-authenticated-shadow-admission-export-v1"
EXPORT_VERSION = 1
DOMAIN = "BL/MIRROR/AUTHENTICATED-SHADOW-ADMISSION/"
GENESIS_TRANSITION = "0" * 128
MAX_EXPORT_BYTES = 8 * 1024 * 1024
MAX_DATABASE_BYTES = 32 * 1024 * 1024
MAX_TRANSITIONS = 2_048
MAX_OPERATIONS = 2_048
MAX_ADMISSIONS = 128
MAX_STRING_BYTES = 64 * 1024
MAX_DEPTH = 16
MAX_NODES = 16_384
HEX128 = re.compile(r"^[0-9a-f]{128}$")
SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")

STATES = (
    "DISCOVERED", "QUALIFIED", "OPEN_PENDING", "OPENED", "START_PENDING",
    "STARTED", "PAUSE_PENDING", "PAUSED",
)
PENDING_STATES = {"OPEN_PENDING", "START_PENDING", "PAUSE_PENDING"}
REASONS = (
    "SOURCE_SUPERSEDED", "QUARANTINE_WITHDRAWN", "GOVERNANCE_EXPIRED",
    "GOVERNANCE_WITHDRAWN", "PRIVACY_EXPIRED", "PRIVACY_WITHDRAWN",
    "AUTHORITY_INDETERMINATE",
)
FAILURE_CODES = (
    "AUTHORITY_INDETERMINATE", "AUTHORITY_EXPIRED", "SOURCE_SUPERSEDED",
    "QUARANTINE_WITHDRAWN", "GOVERNANCE_WITHDRAWN", "GOVERNANCE_EXPIRED",
    "PRIVACY_WITHDRAWN", "PRIVACY_EXPIRED",
    "RUNTIME_RESPONSE_LOST", "RUNTIME_BUSY", "LEASE_EXPIRED", "INTEGRITY",
)
ACTIONS = (
    "DISCOVER", "QUALIFY", "OPEN_PENDING", "OPEN", "START_PENDING", "START",
    "PAUSE_PENDING", "PAUSE", "REQUEUE",
)
FIXED_FLAGS = {
    "read_only": True,
    "observation_only": True,
    "quarantine_only": True,
    "synthetic_only": True,
    "production_source_authentication": False,
    "production_usable": False,
    "activation": False,
    "payment_authority": False,
    "clearance_authority": False,
    "settlement_authority": False,
    "adjudication_authority": False,
    "controlled_shadow_ready": False,
    "proofSuiteId": None,
}
FIXED_FLAG_STORAGE = {
    key: "1" if value is True else "0" if value is False else "null"
    for key, value in FIXED_FLAGS.items()
}

CONFIG_KEYS = {
    "admission_ledger_id", "version", "acquisition_id", "acquisition_config_digest",
    "acquisition_database_id", "acquisition_profile_digest", "source_policy_digest",
    "quarantine_database_id", "quarantine_policy_digest", "quarantine_chain_id",
    "governance_policy_digest", "governance_verifier_id", "governance_verifier_epoch",
    "privacy_policy_digest", "privacy_verifier_id", "privacy_verifier_epoch",
    "runtime_profile_digest", "runtime_database_id", "cadence_seconds",
    "freshness_grace_seconds", "lease_seconds", "max_admissions", "max_attempts",
    "busy_timeout_ms", "zero_phi", "state_owned", *FIXED_FLAGS.keys(),
}

CANDIDATE_COLUMNS = (
    "admission_id", "config_digest", "state", "slot_id", "acquisition_id",
    "acquisition_config_digest", "acquisition_database_id", "acquisition_profile_digest",
    "source_policy_digest", "scheduled_at", "observed_at", "fetched_at", "envelope_id", "envelope_digest",
    "capture_id", "artifact_id", "artifact_digest", "quarantine_database_id",
    "quarantine_policy_digest", "quarantine_chain_id", "quarantine_operation_id",
    "quarantine_transition_id", "quarantine_request_digest", "quarantine_receipt_digest", "quarantine_head_root",
    "quarantine_sequence", "governance_policy_digest", "governance_artifact_id",
    "governance_evidence_digest", "governance_verifier_id", "governance_verifier_epoch",
    "privacy_policy_digest", "privacy_artifact_id", "privacy_evidence_digest",
    "privacy_verifier_id", "privacy_verifier_epoch", "runtime_profile_digest",
    "runtime_database_id", "qualification_digest", "bundle_digest", "session_id",
    "runtime_open_operation_id", "runtime_start_operation_id", "runtime_pause_operation_id",
    "runtime_head_root", "attempt", "lease_id", "lease_until", "failure_code",
    "last_operation_id",
)
MATERIAL_COLUMNS = tuple(key for key in CANDIDATE_COLUMNS if key != "last_operation_id")
TABLE_COLUMNS = {
    "admission_meta": ("key", "value"),
    "admission_candidates": CANDIDATE_COLUMNS,
    "admission_operations": (
        "operation_id", "admission_id", "action", "attempt", "request_digest",
        "material_digest", "material_raw", "transition_id", "receipt_digest",
        "sequence", "receipt_raw",
    ),
    "admission_transitions": (
        "transition_id", "sequence", "admission_id", "operation_id", "action",
        "attempt", "request_digest", "prior_state", "next_state", "before_root",
        "after_root", "material_digest", "observed_at", "transition_raw",
    ),
}
META_KEYS = (
    "schema", "schema_version", "admission_ledger_id", "config_digest", "chain_id",
    "sequence", "state_root", "head_transition_id", *FIXED_FLAGS.keys(),
)
EXPORT_KEYS = {
    "schema", "schema_version", "config", "config_digest", "chain_id", "meta",
    "candidates", "operations", "transitions", "export_root", *FIXED_FLAGS.keys(),
}
EXPORT_ROW_KEYS = {
    "admission_meta": {"key", "value"},
    "admission_candidates": set(CANDIDATE_COLUMNS),
    "admission_operations": set(TABLE_COLUMNS["admission_operations"]) - {"material_raw", "receipt_raw"} | {"material_hex", "receipt_hex"},
    "admission_transitions": set(TABLE_COLUMNS["admission_transitions"]) - {"transition_raw"} | {"transition_hex"},
}


class IndependentAuthenticatedShadowAdmissionError(ValueError):
    """Stable, sanitized rejection from the independent boundary."""


def _fail(code: str) -> None:
    raise IndependentAuthenticatedShadowAdmissionError(code)


def _decode_hex(value: object, label: str) -> bytes:
    if not isinstance(value, str):
        _fail(f"admission:{label}")
    try:
        return bytes.fromhex(value)
    except (TypeError, ValueError):
        _fail(f"admission:{label}")


def _canonical(value: object) -> bytes:
    try:
        raw = json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError):
        _fail("admission:noncanonical")
    if len(raw) > MAX_EXPORT_BYTES:
        _fail("admission:byte-cap")
    return raw


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail("admission:duplicate-key")
        result[key] = value
    return result


def _walk(value: object, *, depth: int = 0, count: list[int] | None = None) -> None:
    count = [0] if count is None else count
    count[0] += 1
    if count[0] > MAX_NODES or depth > MAX_DEPTH:
        _fail("admission:shape-cap")
    if isinstance(value, float):
        _fail("admission:float")
    if isinstance(value, str):
        try:
            if len(value.encode("ascii")) > MAX_STRING_BYTES:
                _fail("admission:string-cap")
        except UnicodeEncodeError:
            _fail("admission:ascii")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                _fail("admission:key-type")
            _walk(key, depth=depth + 1, count=count)
            _walk(item, depth=depth + 1, count=count)
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth=depth + 1, count=count)


def _parse(raw: bytes, *, maximum: int = MAX_EXPORT_BYTES) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > maximum:
        _fail("admission:byte-cap")
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_reject_duplicate_keys, parse_constant=lambda _value: (_ for _ in ()).throw(IndependentAuthenticatedShadowAdmissionError("admission:constant")))
    except IndependentAuthenticatedShadowAdmissionError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail("admission:parse")
    if not isinstance(value, dict):
        _fail("admission:top-level")
    _walk(value)
    if _canonical(value) != raw:
        _fail("admission:not-canonical")
    return value


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update((DOMAIN + label + "/v1\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _raw_digest(raw: bytes) -> str:
    return hashlib.sha3_512(raw).hexdigest()


def _config_view(config: Mapping[str, object] | object) -> dict[str, object]:
    if isinstance(config, Mapping):
        value = dict(config)
    else:
        material = getattr(config, "material", None)
        if not callable(material):
            _fail("admission:config")
        value = dict(material())
    if set(value) != CONFIG_KEYS:
        _fail("admission:config-keys")
    for key in (
        "admission_ledger_id", "acquisition_id", "quarantine_database_id", "runtime_database_id",
        "governance_verifier_id", "privacy_verifier_id",
    ):
        if not isinstance(value[key], str) or SAFE_TOKEN.fullmatch(value[key]) is None:
            _fail("admission:config-token")
    for key in (
        "acquisition_config_digest", "acquisition_database_id", "acquisition_profile_digest",
        "source_policy_digest", "quarantine_policy_digest", "quarantine_chain_id",
        "governance_policy_digest", "privacy_policy_digest", "runtime_profile_digest",
    ):
        if not isinstance(value[key], str) or HEX128.fullmatch(value[key]) is None:
            _fail("admission:config-digest")
    for key in ("version", "governance_verifier_epoch", "privacy_verifier_epoch", "cadence_seconds", "freshness_grace_seconds", "lease_seconds", "max_admissions", "max_attempts", "busy_timeout_ms"):
        if type(value[key]) is not int or value[key] < 1:
            _fail("admission:config-number")
    if value["version"] != 1 or value["max_admissions"] > MAX_ADMISSIONS or value["max_attempts"] > 8 or value["busy_timeout_ms"] > 5_000:
        _fail("admission:config-cap")
    if value["zero_phi"] is not True or value["state_owned"] is not True:
        _fail("admission:config-controls")
    for key, expected in FIXED_FLAGS.items():
        if value[key] is not expected:
            _fail("admission:config-flags")
    return value


def config_digest(config: Mapping[str, object] | object) -> str:
    return _digest("config", _config_view(config))


def _chain_id(config_digest_value: str) -> str:
    return _digest("chain", {"config_digest": config_digest_value})


def _genesis_root(chain_id: str) -> str:
    return _digest("genesis", {"schema": SCHEMA, "chain_id": chain_id})


def _state_root(chain_id: str, sequence: int, before_root: str, transition_id: str | None) -> str:
    return _digest("state-root", {"chain_id": chain_id, "sequence": sequence, "before_root": before_root, "transition_id": transition_id})


def _safe_value(value: object, label: str) -> str:
    if not isinstance(value, str) or SAFE_TOKEN.fullmatch(value) is None:
        _fail("admission:" + label)
    return value


def _hex(value: object, label: str) -> str:
    if not isinstance(value, str) or HEX128.fullmatch(value) is None:
        _fail("admission:" + label)
    return value


def _candidate_material(row: Mapping[str, object]) -> dict[str, object]:
    return {key: row[key] for key in MATERIAL_COLUMNS}


def candidate_digest(row: Mapping[str, object]) -> str:
    return _digest("candidate", _candidate_material(row))


def _operation_id(admission_id: str, action: str, request_digest: str, material_digest: str) -> str:
    return _digest("operation", {"admission_id": admission_id, "action": action, "request_digest": request_digest, "material_digest": material_digest})


def _transition_id(sequence: int, admission_id: str, action: str, material_digest: str, before_root: str) -> str:
    return _digest("transition", {"sequence": sequence, "admission_id": admission_id, "action": action, "material_digest": material_digest, "before_root": before_root})


def _receipt(value: Mapping[str, object]) -> bytes:
    return _canonical(dict(value))


def _row_keys(rows: object, table: str) -> list[Mapping[str, object]]:
    if not isinstance(rows, list) or len(rows) > MAX_TRANSITIONS:
        _fail("admission:rows")
    expected = set(TABLE_COLUMNS[table])
    result: list[Mapping[str, object]] = []
    for row in rows:
        if not isinstance(row, Mapping) or set(row) != expected:
            _fail("admission:row-keys")
        result.append(row)
    return result


def _check_schema(connection: sqlite3.Connection, *, immutable: bool) -> None:
    journal = connection.execute("PRAGMA journal_mode").fetchone()
    if journal is None or str(journal[0]).lower() != ("delete" if immutable else "wal"):
        _fail("admission:journal-mode")
    tables = {str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
    if tables != set(TABLE_COLUMNS):
        _fail("admission:database-schema")
    for table, columns in TABLE_COLUMNS.items():
        actual = tuple(str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})"))
        if actual != columns:
            _fail("admission:table-schema")


def _verify_meta(rows: Mapping[str, list[Mapping[str, object]]], cfg: Mapping[str, object]) -> tuple[dict[str, str], str, str]:
    meta_rows = rows["admission_meta"]
    if len(meta_rows) != len(META_KEYS) or [row["key"] for row in meta_rows] != sorted(META_KEYS):
        _fail("admission:meta")
    meta = {str(row["key"]): row["value"] for row in meta_rows}
    if set(meta) != set(META_KEYS) or any(type(value) is not str for value in meta.values()):
        _fail("admission:meta")
    digest = config_digest(cfg)
    chain = _chain_id(digest)
    if meta["schema"] != SCHEMA or meta["schema_version"] != str(SCHEMA_VERSION) or meta["admission_ledger_id"] != cfg["admission_ledger_id"] or meta["config_digest"] != digest or meta["chain_id"] != chain:
        _fail("admission:meta-binding")
    for key, expected in FIXED_FLAG_STORAGE.items():
        if meta[key] != expected:
            _fail("admission:meta-flags")
    try:
        sequence = int(meta["sequence"])
    except (TypeError, ValueError):
        _fail("admission:meta-sequence")
    if sequence < 0 or sequence > MAX_TRANSITIONS:
        _fail("admission:meta-sequence")
    _hex(meta["state_root"], "state-root")
    if sequence == 0 and (meta["head_transition_id"] != GENESIS_TRANSITION or meta["state_root"] != _state_root(chain, 0, _genesis_root(chain), None)):
        _fail("admission:genesis")
    if sequence and HEX128.fullmatch(meta["head_transition_id"]) is None:
        _fail("admission:head-transition")
    return meta, chain, digest


def _verify_candidate(row: Mapping[str, object], cfg: Mapping[str, object], config_digest_value: str) -> None:
    if set(row) != set(CANDIDATE_COLUMNS):
        _fail("admission:candidate-keys")
    for key in ("admission_id", "slot_id", "acquisition_id", "quarantine_database_id", "runtime_database_id"):
        _safe_value(row[key], "candidate-token")
    if row["config_digest"] != config_digest_value or row["acquisition_id"] != cfg["acquisition_id"]:
        _fail("admission:candidate-config")
    if row["state"] not in STATES:
        _fail("admission:candidate-state")
    for key in (
        "config_digest", "acquisition_config_digest", "acquisition_database_id", "acquisition_profile_digest", "source_policy_digest",
        "envelope_id", "envelope_digest", "artifact_id", "artifact_digest", "quarantine_policy_digest", "quarantine_chain_id",
        "quarantine_operation_id", "quarantine_transition_id", "quarantine_request_digest", "quarantine_receipt_digest", "quarantine_head_root",
        "governance_policy_digest", "governance_artifact_id", "governance_evidence_digest", "privacy_policy_digest",
        "privacy_artifact_id", "privacy_evidence_digest", "runtime_profile_digest", "qualification_digest", "bundle_digest",
    ):
        _hex(row[key], "candidate-digest")
    if row["config_digest"] != config_digest_value or row["acquisition_config_digest"] != cfg["acquisition_config_digest"] or row["acquisition_database_id"] != cfg["acquisition_database_id"] or row["acquisition_profile_digest"] != cfg["acquisition_profile_digest"] or row["source_policy_digest"] != cfg["source_policy_digest"]:
        _fail("admission:acquisition-binding")
    if row["quarantine_database_id"] != cfg["quarantine_database_id"] or row["quarantine_policy_digest"] != cfg["quarantine_policy_digest"] or row["quarantine_chain_id"] != cfg["quarantine_chain_id"]:
        _fail("admission:quarantine-binding")
    if row["governance_policy_digest"] != cfg["governance_policy_digest"] or row["governance_verifier_id"] != cfg["governance_verifier_id"] or row["governance_verifier_epoch"] != cfg["governance_verifier_epoch"]:
        _fail("admission:governance-binding")
    if row["privacy_policy_digest"] != cfg["privacy_policy_digest"] or row["privacy_verifier_id"] != cfg["privacy_verifier_id"] or row["privacy_verifier_epoch"] != cfg["privacy_verifier_epoch"]:
        _fail("admission:privacy-binding")
    if row["runtime_profile_digest"] != cfg["runtime_profile_digest"] or row["runtime_database_id"] != cfg["runtime_database_id"]:
        _fail("admission:runtime-binding")
    for key in ("governance_verifier_id", "privacy_verifier_id"):
        _safe_value(row[key], "candidate-verifier")
    for key in ("governance_verifier_epoch", "privacy_verifier_epoch", "scheduled_at", "observed_at", "fetched_at", "quarantine_sequence", "attempt"):
        if type(row[key]) is not int or row[key] < 0:
            _fail("admission:candidate-number")
    if row["governance_verifier_epoch"] < 1 or row["privacy_verifier_epoch"] < 1 or row["scheduled_at"] < 1 or row["observed_at"] < 1 or row["quarantine_sequence"] < 1:
        _fail("admission:candidate-epoch")
    if row["failure_code"] not in (None, "") and row["failure_code"] not in FAILURE_CODES:
        _fail("admission:failure-code")
    for key in ("lease_id", "session_id", "runtime_open_operation_id", "runtime_start_operation_id", "runtime_pause_operation_id", "last_operation_id"):
        if row[key] not in (None, ""):
            _hex(row[key], "candidate-identity")
    if row["lease_until"] is not None and (type(row["lease_until"]) is not int or row["lease_until"] < 1):
        _fail("admission:lease")
    if row["runtime_head_root"] not in (None, ""):
        _hex(row["runtime_head_root"], "runtime-head")
    expected_open = _digest("runtime-open", {"admission_id": row["admission_id"], "qualification_digest": row["qualification_digest"]})
    expected_start = _digest("runtime-start", {"admission_id": row["admission_id"], "qualification_digest": row["qualification_digest"]})
    if row["runtime_open_operation_id"] not in (None, "") and row["runtime_open_operation_id"] != expected_open:
        _fail("admission:runtime-open-identity")
    if row["runtime_start_operation_id"] not in (None, "") and row["runtime_start_operation_id"] != expected_start:
        _fail("admission:runtime-start-identity")
    if row["runtime_pause_operation_id"] not in (None, ""):
        if row["failure_code"] not in REASONS:
            _fail("admission:runtime-pause-identity")
        expected_pause = _digest("runtime-pause", {"admission_id": row["admission_id"], "qualification_digest": row["qualification_digest"], "reason": row["failure_code"]})
        if row["runtime_pause_operation_id"] != expected_pause:
            _fail("admission:runtime-pause-identity")
    qualification_material = {
        "acquisition_id": row["acquisition_id"], "config_digest": row["acquisition_config_digest"],
        "acquisition_database_id": row["acquisition_database_id"], "source_policy_digest": row["source_policy_digest"],
        "slot_id": row["slot_id"], "scheduled_at": row["scheduled_at"], "envelope_id": row["envelope_id"],
        "envelope_digest": row["envelope_digest"], "capture_id": row["capture_id"], "artifact_id": row["artifact_id"],
        "artifact_digest": row["artifact_digest"], "quarantine_database_id": row["quarantine_database_id"],
        "quarantine_policy_digest": row["quarantine_policy_digest"], "quarantine_chain_id": row["quarantine_chain_id"],
        "quarantine_operation_id": row["quarantine_operation_id"], "quarantine_transition_id": row["quarantine_transition_id"],
        "quarantine_request_digest": row["quarantine_request_digest"],
        "quarantine_receipt_digest": row["quarantine_receipt_digest"], "quarantine_head_artifact_id": row["artifact_id"],
        "quarantine_head_root": row["quarantine_head_root"], "quarantine_sequence": row["quarantine_sequence"],
        "observed_at": row["observed_at"], "fetched_at": row["fetched_at"],
        "flags": acquisition.FIXED_FLAGS,
    }
    # The source view carries the exact observation/fetch markers.  They are
    # retained in the candidate material below, so do not accept a rehashed
    # candidate whose stable source identity no longer matches those fields.
    if row["qualification_digest"] != acquisition._digest("qualification", qualification_material):
        _fail("admission:qualification-binding")
    bundle_material = {
        "qualification_digest": row["qualification_digest"], "governance_artifact_id": row["governance_artifact_id"],
        "governance_evidence_digest": row["governance_evidence_digest"], "privacy_artifact_id": row["privacy_artifact_id"],
        "privacy_evidence_digest": row["privacy_evidence_digest"], "runtime_profile_digest": row["runtime_profile_digest"],
        "runtime_database_id": row["runtime_database_id"],
    }
    if row["bundle_digest"] != _digest("bundle", bundle_material):
        _fail("admission:bundle-binding")
    if row["admission_id"] != _digest("admission", bundle_material):
        _fail("admission:admission-id")
    if row["state"] in PENDING_STATES and (row["lease_id"] in (None, "") or row["lease_until"] is None):
        _fail("admission:pending-lease")
    if row["state"] not in PENDING_STATES and (row["lease_id"] not in (None, "") or row["lease_until"] is not None):
        _fail("admission:released-lease")
    if row["state"] in {"OPENED", "START_PENDING", "STARTED", "PAUSE_PENDING", "PAUSED"} and row["session_id"] in (None, ""):
        _fail("admission:session-binding")
    if row["state"] in {"OPENED", "START_PENDING", "STARTED", "PAUSED"} and row["runtime_open_operation_id"] in (None, ""):
        _fail("admission:open-binding")
    if row["state"] in {"STARTED", "PAUSE_PENDING", "PAUSED"} and row["runtime_start_operation_id"] in (None, ""):
        _fail("admission:start-binding")
    if row["state"] == "PAUSED" and row["runtime_pause_operation_id"] in (None, ""):
        _fail("admission:pause-binding")
    if row["observed_at"] != row["scheduled_at"] or row["fetched_at"] < row["observed_at"] or row["fetched_at"] > row["observed_at"] + cfg["cadence_seconds"] + cfg["freshness_grace_seconds"]:
        _fail("admission:chronology")
    if row["state"] in {"PAUSE_PENDING", "PAUSED"}:
        if row["failure_code"] not in REASONS:
            _fail("admission:pause-reason")
    elif row["failure_code"] not in (None, ""):
        _fail("admission:active-failure")


def _verify_rows(rows: Mapping[str, list[Mapping[str, object]]], *, config: Mapping[str, object] | object) -> dict[str, object]:
    cfg = _config_view(config)
    if set(rows) != set(TABLE_COLUMNS):
        _fail("admission:tables")
    normalized = {table: _row_keys(rows[table], table) for table in TABLE_COLUMNS}
    meta, chain, digest = _verify_meta(normalized, cfg)
    candidates = normalized["admission_candidates"]
    if len(candidates) > cfg["max_admissions"] or len(candidates) > MAX_ADMISSIONS:
        _fail("admission:admission-cap")
    candidate_map: dict[str, Mapping[str, object]] = {}
    slot_map: dict[str, str] = {}
    for row in candidates:
        key = str(row["admission_id"])
        if key in candidate_map:
            _fail("admission:duplicate-candidate")
        slot_id = str(row["slot_id"])
        if slot_id in slot_map:
            _fail("admission:duplicate-slot")
        slot_map[slot_id] = key
        candidate_map[key] = row
        _verify_candidate(row, cfg, digest)
    operations = normalized["admission_operations"]
    transitions = normalized["admission_transitions"]
    if len(operations) != len(transitions) or len(transitions) != int(meta["sequence"]):
        _fail("admission:sequence-count")
    if transitions != sorted(transitions, key=lambda row: int(row["sequence"])) or operations != sorted(operations, key=lambda row: int(row["sequence"])):
        _fail("admission:sequence-order")
    operation_map = {str(row["operation_id"]): row for row in operations}
    if len(operation_map) != len(operations):
        _fail("admission:duplicate-operation")
    replay: dict[str, dict[str, object]] = {}
    current_root = _state_root(chain, 0, _genesis_root(chain), None)
    previous_observed_at = 0
    legal = {
        ("", "DISCOVERED"): {"DISCOVER"},
        ("DISCOVERED", "QUALIFIED"): {"QUALIFY"},
        ("QUALIFIED", "OPEN_PENDING"): {"OPEN_PENDING"},
        ("OPEN_PENDING", "OPEN_PENDING"): {"REQUEUE"},
        ("OPEN_PENDING", "OPENED"): {"OPEN"},
        ("OPENED", "START_PENDING"): {"START_PENDING"},
        ("START_PENDING", "START_PENDING"): {"REQUEUE"},
        ("START_PENDING", "STARTED"): {"START"},
        ("STARTED", "PAUSE_PENDING"): {"PAUSE_PENDING"},
        ("PAUSE_PENDING", "PAUSE_PENDING"): {"REQUEUE"},
        ("PAUSE_PENDING", "PAUSED"): {"PAUSE"},
    }
    for expected_sequence, transition in enumerate(transitions, start=1):
        for key in ("sequence", "observed_at"):
            if type(transition[key]) is not int or transition[key] < 1:
                _fail("admission:transition-type")
        if type(transition["attempt"]) is not int or transition["attempt"] < 0:
            _fail("admission:transition-type")
        operation = operation_map.get(str(transition["operation_id"]))
        if operation is None or transition["sequence"] != expected_sequence or type(operation["sequence"]) is not int or operation["sequence"] != expected_sequence:
            _fail("admission:transition-order")
        if operation["transition_id"] != transition["transition_id"] or operation["action"] != transition["action"] or operation["attempt"] != transition["attempt"] or operation["request_digest"] != transition["request_digest"]:
            _fail("admission:operation-binding")
        _hex(operation["operation_id"], "operation-id")
        _hex(operation["request_digest"], "request-digest")
        material_raw = operation["material_raw"]
        if type(material_raw) is not bytes:
            _fail("admission:material")
        material = _parse(material_raw, maximum=256 * 1024)
        if set(material) != {"action", "attempt", "request_digest", "prior_state", "next_state", "candidate_after"}:
            _fail("admission:material-keys")
        if material["action"] != transition["action"] or material["attempt"] != transition["attempt"] or material["request_digest"] != transition["request_digest"] or material["prior_state"] != transition["prior_state"] or material["next_state"] != transition["next_state"]:
            _fail("admission:material-binding")
        after = material["candidate_after"]
        if not isinstance(after, Mapping) or set(after) != set(MATERIAL_COLUMNS):
            _fail("admission:material-candidate")
        _verify_candidate({**dict(after), "last_operation_id": operation["operation_id"]}, cfg, digest)
        if operation["material_digest"] != _digest("material", material) or transition["material_digest"] != operation["material_digest"]:
            _fail("admission:material-digest")
        admission_id = str(transition["admission_id"])
        if str(after["admission_id"]) != admission_id:
            _fail("admission:material-admission")
        expected_operation = _operation_id(admission_id, str(transition["action"]), str(transition["request_digest"]), str(operation["material_digest"]))
        if expected_operation != operation["operation_id"]:
            _fail("admission:operation-id")
        previous = replay.get(admission_id)
        prior_state = str(transition["prior_state"])
        next_state = str(transition["next_state"])
        if transition["action"] not in legal.get((prior_state, next_state), set()) or (previous is None and prior_state != "") or (previous is not None and previous["state"] != prior_state):
            _fail("admission:illegal-edge")
        if transition["action"] == "DISCOVER" and (previous is not None or next_state != "DISCOVERED"):
            _fail("admission:discover")
        if transition["action"] != "DISCOVER" and previous is None:
            _fail("admission:missing-predecessor")
        attempt = transition["attempt"]
        prior_attempt = 0 if previous is None else int(previous["attempt"])
        if transition["action"] in {"DISCOVER", "QUALIFY"} and attempt != 0:
            _fail("admission:attempt")
        if transition["action"] in {"OPEN_PENDING", "START_PENDING", "PAUSE_PENDING"} and attempt < 1:
            _fail("admission:attempt")
        if transition["action"] in {"OPEN", "START", "PAUSE"} and attempt != prior_attempt:
            _fail("admission:attempt")
        if transition["action"] == "REQUEUE" and attempt <= prior_attempt:
            _fail("admission:attempt")
        if transition["observed_at"] < previous_observed_at:
            _fail("admission:transition-time")
        if next_state in PENDING_STATES:
            pending_action = "REQUEUE" if transition["action"] == "REQUEUE" else transition["action"]
            expected_lease = _digest("lease", {"admission_id": admission_id, "action": pending_action, "request_digest": transition["request_digest"], "attempt": attempt})
            if after["lease_id"] != expected_lease or type(after["lease_until"]) is not int or after["lease_until"] < 1:
                _fail("admission:lease-identity")
        transition_id = _transition_id(expected_sequence, admission_id, str(transition["action"]), str(operation["material_digest"]), current_root)
        if transition["transition_id"] != transition_id:
            _fail("admission:transition-id")
        if transition["before_root"] != current_root or transition["after_root"] != _state_root(chain, expected_sequence, current_root, transition_id):
            _fail("admission:transition-root")
        transition_raw = transition["transition_raw"]
        if type(transition_raw) is not bytes:
            _fail("admission:transition-bytes")
        expected_transition = {
            "schema": SCHEMA, "schema_version": SCHEMA_VERSION, "transition_id": transition_id,
            "sequence": expected_sequence, "admission_id": admission_id, "operation_id": operation["operation_id"],
            "action": transition["action"], "attempt": transition["attempt"], "request_digest": transition["request_digest"],
            "prior_state": prior_state, "next_state": next_state, "before_root": transition["before_root"],
            "after_root": transition["after_root"], "material_digest": operation["material_digest"], "observed_at": transition["observed_at"],
        }
        if _parse(transition_raw, maximum=256 * 1024) != expected_transition:
            _fail("admission:transition-binding")
        receipt_raw = operation["receipt_raw"]
        if type(receipt_raw) is not bytes or operation["receipt_digest"] != _raw_digest(receipt_raw):
            _fail("admission:receipt")
        expected_receipt = {
            "schema": SCHEMA, "schema_version": SCHEMA_VERSION, "admission_id": admission_id,
            "operation_id": operation["operation_id"], "action": transition["action"], "attempt": transition["attempt"],
            "request_digest": transition["request_digest"], "prior_state": prior_state, "next_state": next_state,
            "sequence": expected_sequence, "before_root": transition["before_root"], "after_root": transition["after_root"],
            "transition_id": transition_id, "material_digest": operation["material_digest"], "candidate_digest": after["qualification_digest"],
            "flags": FIXED_FLAGS,
        }
        if _parse(receipt_raw, maximum=256 * 1024) != expected_receipt:
            _fail("admission:receipt-binding")
        replay[admission_id] = dict(after)
        replay[admission_id]["state"] = next_state
        replay[admission_id]["last_operation_id"] = operation["operation_id"]
        current_root = transition["after_root"]
        previous_observed_at = transition["observed_at"]
    if meta["state_root"] != current_root or (transitions and meta["head_transition_id"] != transitions[-1]["transition_id"]):
        _fail("admission:head")
    if set(replay) != set(candidate_map):
        _fail("admission:orphan-replay")
    for admission_id, row in candidate_map.items():
        after = replay.get(admission_id)
        if after is None:
            _fail("admission:candidate-orphan")
        for key in CANDIDATE_COLUMNS:
            if row[key] != after[key]:
                _fail("admission:candidate-replay")
    return {
        "accepted": True,
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "config": cfg,
        "config_digest": digest,
        "chain_id": chain,
        "sequence": int(meta["sequence"]),
        "state_root": current_root,
        "head_transition_id": meta["head_transition_id"],
        "admission_count": len(candidates),
        "operation_count": len(operations),
        "transition_count": len(transitions),
        "states": {state: sum(row["state"] == state for row in candidates) for state in STATES},
        "failure_counts": {code: sum(row["failure_code"] == code for row in candidates) for code in FAILURE_CODES},
    }


def _table_snapshot(connection: sqlite3.Connection) -> dict[str, list[dict[str, object]]]:
    return {
        table: [{column: row[column] for column in columns} for row in connection.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()]
        for table, columns in TABLE_COLUMNS.items()
    }


def snapshot_database(path: str | Path, *, config: Mapping[str, object] | object) -> dict[str, object]:
    try:
        image = sqlite_snapshot.read_only_image(path, max_database_bytes=MAX_DATABASE_BYTES, max_sidecar_bytes=MAX_DATABASE_BYTES)
    except sqlite_snapshot.SQLiteSnapshotError:
        _fail("admission:database")
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(image.uri, uri=True, timeout=5, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("BEGIN")
        _check_schema(connection, immutable=image.immutable)
        rows = _table_snapshot(connection)
        evidence = _verify_rows(rows, config=config)
        connection.commit()
        return {"evidence": evidence, "snapshot": rows}
    except IndependentAuthenticatedShadowAdmissionError:
        if connection is not None and connection.in_transaction:
            connection.rollback()
        raise
    except (sqlite3.Error, OSError, ValueError):
        if connection is not None and connection.in_transaction:
            connection.rollback()
        _fail("admission:database")
    finally:
        if connection is not None:
            connection.close()


def verify_database(path: str | Path, *, config: Mapping[str, object] | object) -> dict[str, object]:
    result = snapshot_database(path, config=config)
    return dict(result["evidence"])


def _decode_export(value: Mapping[str, object]) -> dict[str, list[dict[str, object]]]:
    mapping = {"meta": "admission_meta", "candidates": "admission_candidates", "operations": "admission_operations", "transitions": "admission_transitions"}
    result: dict[str, list[dict[str, object]]] = {}
    for key, table in mapping.items():
        rows = value[key]
        if not isinstance(rows, list):
            _fail("admission:export-rows")
        decoded: list[dict[str, object]] = []
        for item in rows:
            if not isinstance(item, Mapping) or set(item) != EXPORT_ROW_KEYS[table]:
                _fail("admission:export-row-keys")
            row = dict(item)
            if table == "admission_operations":
                row["material_raw"] = _decode_hex(row.pop("material_hex"), "export-hex")
                row["receipt_raw"] = _decode_hex(row.pop("receipt_hex"), "export-hex")
            elif table == "admission_transitions":
                row["transition_raw"] = _decode_hex(row.pop("transition_hex"), "export-hex")
            decoded.append(row)
        result[table] = decoded
    return result


def verify_export_bytes(raw: bytes, *, config: Mapping[str, object] | object) -> dict[str, object]:
    value = _parse(raw)
    if set(value) != EXPORT_KEYS or value["schema"] != EXPORT_SCHEMA or value["schema_version"] != EXPORT_VERSION:
        _fail("admission:export-schema")
    cfg = _config_view(config)
    digest = config_digest(cfg)
    if value["config"] != cfg or value["config_digest"] != digest or value["chain_id"] != _chain_id(digest):
        _fail("admission:export-config")
    for key, expected in FIXED_FLAGS.items():
        if value[key] is not expected:
            _fail("admission:export-flags")
    snapshot = _decode_export(value)
    evidence = _verify_rows(snapshot, config=cfg)
    body = dict(value)
    body.pop("export_root")
    if value["export_root"] != _digest("export-root", body):
        _fail("admission:export-root")
    return {**evidence, "export_root": value["export_root"], "snapshot": snapshot}


def support_snapshot(path: str | Path, *, config: Mapping[str, object] | object) -> dict[str, object]:
    result = snapshot_database(path, config=config)
    evidence = result["evidence"]
    return {
        "schema": "mirror-authenticated-shadow-admission-support-v1",
        "schema_version": 1,
        "state_counts": evidence["states"],
        "admission_count": evidence["admission_count"],
        "operation_count": evidence["operation_count"],
        "transition_count": evidence["transition_count"],
        "failure_counts": evidence["failure_counts"],
        **FIXED_FLAGS,
    }


__all__ = [
    "SCHEMA", "SCHEMA_VERSION", "EXPORT_SCHEMA", "EXPORT_VERSION", "STATES",
    "PENDING_STATES", "REASONS", "FAILURE_CODES", "ACTIONS", "FIXED_FLAGS",
    "FIXED_FLAG_STORAGE", "CONFIG_KEYS", "CANDIDATE_COLUMNS", "MATERIAL_COLUMNS",
    "TABLE_COLUMNS", "META_KEYS", "EXPORT_KEYS", "EXPORT_ROW_KEYS",
    "IndependentAuthenticatedShadowAdmissionError", "config_digest", "candidate_digest",
    "_canonical", "_digest", "_raw_digest", "_config_view", "_chain_id", "_genesis_root",
    "_state_root", "_candidate_material", "_operation_id", "_transition_id", "_parse",
    "snapshot_database", "verify_database", "verify_export_bytes", "support_snapshot",
]
