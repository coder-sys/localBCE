"""Independent structural verifier for the sanitized Mirror Core V4 state.

The producer stores only canonical sanitized observations, at-time verification
receipts, and derived non-PHI Core artifacts.  This module independently
reparses those bytes and reconstructs the event/stream roots.  It has no
source adapter, FHIR, external-evidence, or raw-intake replay dependency.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
from typing import Mapping

from app.mirror import ingress_v2_independent as ingress
from app.mirror import external_corrective_action_independent as corrective_action
from app.mirror.error_boundary import raise_redacted


SCHEMA = "mirror-core-v4"
SCHEMA_VERSION = 4
DOMAIN = "BL/MIRROR/CORE/V4/"
MAX_DATABASE_BYTES = 64 * 1024 * 1024
MAX_ARTIFACT_BYTES = 262_144
MAX_EVENT_BYTES = 786_432
GENESIS_ROOT = "0" * 128

TABLES = (
    "core_meta", "core_artifacts", "core_heads", "core_sessions",
    "core_slots", "core_events",
)
TABLE_COLUMNS = {
    "core_meta": (
        "meta_id", "schema", "schema_version", "database_id", "chain_id",
        "config_digest", "config_raw", "sequence", "head_root",
        "ingress_database_id", "ingress_watermark",
    ),
    "core_artifacts": (
        "artifact_id", "kind", "raw", "profile_digest", "source_artifact_id",
        "predecessor_id", "current_state", "created_event_sequence",
    ),
    "core_heads": (
        "stream_kind", "stream_id", "head_ref", "head_root", "event_sequence",
    ),
    "core_sessions": (
        "session_id", "state", "source_artifact_id", "governance_artifact_id",
        "privacy_artifact_id", "head_root", "last_slot",
    ),
    "core_slots": ("session_id", "slot_number", "result_digest", "result_raw"),
    "core_events": (
        "sequence", "event_id", "event_kind", "operation_id", "subject_id",
        "event_raw", "receipt_digest",
    ),
}
TABLE_SQL = {
    "core_meta": "CREATE TABLE core_meta(meta_id INTEGER PRIMARY KEY CHECK(meta_id=1),schema TEXT NOT NULL,schema_version INTEGER NOT NULL,database_id TEXT NOT NULL,chain_id TEXT NOT NULL,config_digest TEXT NOT NULL,config_raw BLOB NOT NULL,sequence INTEGER NOT NULL,head_root TEXT NOT NULL,ingress_database_id TEXT NOT NULL,ingress_watermark INTEGER NOT NULL)",
    "core_artifacts": "CREATE TABLE core_artifacts(artifact_id TEXT PRIMARY KEY,kind TEXT NOT NULL,raw BLOB NOT NULL,profile_digest TEXT NOT NULL,source_artifact_id TEXT,predecessor_id TEXT,current_state TEXT NOT NULL,created_event_sequence INTEGER NOT NULL)",
    "core_heads": "CREATE TABLE core_heads(stream_kind TEXT NOT NULL,stream_id TEXT NOT NULL,head_ref TEXT NOT NULL,head_root TEXT NOT NULL,event_sequence INTEGER NOT NULL,PRIMARY KEY(stream_kind,stream_id))",
    "core_sessions": "CREATE TABLE core_sessions(session_id TEXT PRIMARY KEY,state TEXT NOT NULL,source_artifact_id TEXT NOT NULL,governance_artifact_id TEXT NOT NULL,privacy_artifact_id TEXT NOT NULL,head_root TEXT NOT NULL,last_slot INTEGER NOT NULL)",
    "core_slots": "CREATE TABLE core_slots(session_id TEXT NOT NULL,slot_number INTEGER NOT NULL,result_digest TEXT NOT NULL,result_raw BLOB NOT NULL,PRIMARY KEY(session_id,slot_number),FOREIGN KEY(session_id) REFERENCES core_sessions(session_id))",
    "core_events": "CREATE TABLE core_events(sequence INTEGER PRIMARY KEY,event_id TEXT NOT NULL UNIQUE,event_kind TEXT NOT NULL,operation_id TEXT NOT NULL UNIQUE,subject_id TEXT NOT NULL,event_raw BLOB NOT NULL,receipt_digest TEXT NOT NULL)",
}
EXPLICIT_INDEX = "core_artifacts_kind_source_event_idx"
INDEX_SQL = {
    EXPLICIT_INDEX: "CREATE INDEX core_artifacts_kind_source_event_idx ON core_artifacts(kind,source_artifact_id,created_event_sequence)",
}
ARTIFACT_KINDS = (
    "GRAPH", "SOURCE_OBSERVATION", "RECONCILIATION", "GOVERNANCE",
    "PRIVACY", "CASE", "CASE_ACTION",
)
SESSION_STATES = ("OPEN", "RUNNING", "PAUSED")
OBSERVATION_RESULTS = ("PARITY", "DISCREPANCY", "INDETERMINATE")
FIXED_FLAGS = {
    "read_only": True, "observation_only": True, "synthetic_only": True,
    "production_usable": False, "activation": False, "payment_authority": False,
    "clearance_authority": False, "settlement_authority": False,
    "adjudication_authority": False, "controlled_shadow_ready": False,
    "proofSuiteId": None,
}
EVENT_KINDS = (
    "ARTIFACT", "SESSION_OPEN", "SESSION_START", "OBSERVATION", "SESSION_PAUSE",
)
EVENT_RAW_KEYS = {
    "schema", "schema_version", "database_id", "chain_id", "sequence",
    "event_id", "event_kind", "stream_kind", "stream_id", "operation_id",
    "subject_id", "request_digest", "prior_state", "next_state", "attempt",
    "observed_at", "material", "material_digest", "payload_digest",
    "payload_length", "before_root", "after_root", "stream_before_root",
    "stream_after_root",
}
_REPARSE_POINT = 0x400
_SIDECARS = ("-wal", "-shm", "-journal")
_HEX = frozenset("0123456789abcdef")


class CoreVerificationError(ValueError):
    """Fixed independent Core failure."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=True, allow_nan=False, sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise CoreVerificationError("core:noncanonical") from None


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CoreVerificationError("core:duplicate-key")
        result[key] = value
    return result


def _parse(raw: bytes, label: str = "core:parse") -> dict[str, object]:
    limit = MAX_EVENT_BYTES if "event" in label or "receipt" in label else MAX_ARTIFACT_BYTES
    if type(raw) is not bytes or not raw or len(raw) > limit:
        raise CoreVerificationError(label)
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                CoreVerificationError("core:constant")
            ),
        )
    except CoreVerificationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise CoreVerificationError(label) from None
    if not isinstance(value, dict) or _canonical(value) != raw:
        raise CoreVerificationError(label)
    return value


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update((DOMAIN + label + "\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _raw_digest(label: str, raw: bytes) -> str:
    if type(raw) is not bytes:
        raise CoreVerificationError("core:bytes")
    digest = hashlib.sha3_512()
    digest.update((DOMAIN + label + "\0").encode("ascii"))
    digest.update(raw)
    return digest.hexdigest()


def _hex(value: object, label: str) -> str:
    if type(value) is not str or len(value) != 128 or any(char not in _HEX for char in value):
        raise CoreVerificationError(label)
    return value


def _safe_identifier(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise CoreVerificationError(label)
    try:
        encoded = value.encode("ascii", "strict")
    except (UnicodeEncodeError, AttributeError):
        raise CoreVerificationError(label) from None
    if len(encoded) > 128 or any(not (char.isalnum() or char in "._:-") for char in value):
        raise CoreVerificationError(label)
    return value


def _event_root(body: Mapping[str, object]) -> str:
    keys = (
        "schema", "schema_version", "database_id", "chain_id", "sequence",
        "event_id", "event_kind", "stream_kind", "stream_id", "operation_id",
        "subject_id", "request_digest", "prior_state", "next_state",
        "attempt", "observed_at", "material_digest", "payload_digest",
        "payload_length", "before_root", "stream_before_root",
    )
    return _digest("event-root", {key: body[key] for key in keys})


def _stream_root(body: Mapping[str, object]) -> str:
    keys = (
        "schema", "schema_version", "database_id", "chain_id", "sequence",
        "event_id", "event_kind", "stream_kind", "stream_id", "operation_id",
        "subject_id", "prior_state", "next_state", "attempt", "observed_at",
        "material_digest", "payload_digest", "payload_length",
        "stream_before_root",
    )
    return _digest("stream-root", {key: body[key] for key in keys})


def _table_names(connection: sqlite3.Connection) -> tuple[str, ...]:
    return tuple(
        row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
    )


def _columns(connection: sqlite3.Connection, table: str) -> tuple[str, ...]:
    return tuple(
        row[1] for row in connection.execute(
            "SELECT * FROM pragma_table_info(?) ORDER BY cid", (table,)
        ).fetchall()
    )


def _is_reparse(info: os.stat_result) -> bool:
    return bool(getattr(info, "st_file_attributes", 0) & _REPARSE_POINT)


def _close(connection: sqlite3.Connection | None) -> None:
    if connection is None:
        return
    failed = False
    try:
        connection.close()
    except Exception:
        failed = True
    if failed:
        raise_redacted(CoreVerificationError, "core:database")


def _check_pragmas(connection: sqlite3.Connection, *, require_delete_journal: bool = True) -> None:
    try:
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
        if page_size != 4096 or page_count < 0 or page_size * page_count > MAX_DATABASE_BYTES:
            raise CoreVerificationError("core:capacity")
        if int(connection.execute("PRAGMA synchronous").fetchone()[0]) != 2:
            raise CoreVerificationError("core:database")
        if require_delete_journal and str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower() != "delete":
            raise CoreVerificationError("core:database")
        connection.execute("PRAGMA foreign_keys=ON")
        if int(connection.execute("PRAGMA foreign_keys").fetchone()[0]) != 1:
            raise CoreVerificationError("core:database")
    except CoreVerificationError:
        raise
    except (sqlite3.Error, TypeError, ValueError):
        raise CoreVerificationError("core:database") from None


def _open(path: str | Path) -> sqlite3.Connection:
    database = Path(path)
    connection: sqlite3.Connection | None = None
    try:
        parent = os.lstat(database.parent)
        info = os.lstat(database)
        if (
            not stat.S_ISDIR(parent.st_mode) or _is_reparse(parent)
            or stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode)
            or _is_reparse(info) or info.st_nlink != 1 or info.st_size <= 0
            or any(os.path.lexists(os.fspath(database) + suffix) for suffix in _SIDECARS)
        ):
            raise CoreVerificationError("core:database")
        if info.st_size > MAX_DATABASE_BYTES:
            raise CoreVerificationError("core:capacity")
        connection = sqlite3.connect(
            database.absolute().as_uri() + "?mode=ro", uri=True,
            isolation_level=None, timeout=0.25,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        main = next(
            (row[2] for row in connection.execute("PRAGMA database_list").fetchall()
             if int(row[0]) == 0), None
        )
        if type(main) is not str or not main or not os.path.samefile(main, database):
            raise CoreVerificationError("core:database")
        _check_pragmas(connection)
        connection.execute("BEGIN")
        return connection
    except CoreVerificationError:
        _close(connection)
        raise
    except (OSError, sqlite3.Error, TypeError, ValueError):
        _close(connection)
        raise CoreVerificationError("core:database") from None


def _verify_config(value: Mapping[str, object], expected_digest: str | None = None) -> dict[str, object]:
    required = {
        "schema", "schema_version", "database_id", "chain_id",
        "ingress_database_id", "ingress_chain_id", "ingress_config_digest",
        "runtime_profile_digest", "governance_policy_digest",
        "privacy_policy_digest", "corrective_action_control_digest",
        "max_sessions", "max_slots_per_session", "cadence_seconds", "flags",
    }
    if (
        set(value) != required or value.get("schema") != SCHEMA
        or value.get("schema_version") != SCHEMA_VERSION
        or value.get("flags") != FIXED_FLAGS
    ):
        raise CoreVerificationError("core:config")
    for key in ("database_id", "chain_id", "ingress_database_id", "ingress_chain_id"):
        _safe_identifier(value.get(key), "core:config")
    for key in (
        "ingress_config_digest", "runtime_profile_digest",
        "governance_policy_digest", "privacy_policy_digest",
        "corrective_action_control_digest",
    ):
        _hex(value.get(key), "core:config")
    if expected_digest is not None and _digest("config", value) != expected_digest:
        raise CoreVerificationError("core:config")
    if (
        type(value["max_sessions"]) is not int
        or not 1 <= value["max_sessions"] <= 64
        or type(value["max_slots_per_session"]) is not int
        or not 1 <= value["max_slots_per_session"] <= 256
        or type(value["cadence_seconds"]) is not int
        or value["cadence_seconds"] <= 0
    ):
        raise CoreVerificationError("core:config")
    return dict(value)


def _verify_graph(value: Mapping[str, object]) -> dict[str, object]:
    required = {"schema", "schema_version", "kind", "profile", "observation", "findings", "report", "authority"}
    if (
        set(value) != required
        or value.get("schema") != "mirror-core-graph-observation-v1"
        or value.get("schema_version") != 1
        or value.get("kind") != "GRAPH"
        or value.get("authority") != FIXED_FLAGS
    ):
        raise CoreVerificationError("core:graph")
    profile = value.get("profile")
    observation = value.get("observation")
    findings = value.get("findings")
    report = value.get("report")
    if (
        not isinstance(profile, dict)
        or set(profile) != {"profile_id", "version"}
        or not isinstance(observation, dict)
        or not isinstance(findings, list)
        or len(findings) != 1
        or not isinstance(findings[0], dict)
        or set(findings[0]) != {"finding_id", "kind"}
        or not isinstance(report, dict)
        or set(report) != {"report_id"}
    ):
        raise CoreVerificationError("core:graph")
    try:
        observation_id = ingress.verify_observation_pair(
            _canonical(observation),
            _canonical({
                "schema": "mirror-source-verification-receipt-v1",
                "schema_version": 1,
                "profile_id": observation["profile_id"],
                "profile_version": observation["profile_version"],
                "verifier_id": "SYNTH_NC_MEDICAID_FHIR_VERIFIER_V4",
                "verifier_epoch": 4,
                "evidence_mode": "observation_only",
                "verification_status": "VERIFIED_AT_TIME",
                "outcome": observation["outcome"],
                "observation_digest": ingress._raw_digest("sanitized-observation", _canonical(observation)),
                "issued_at": observation["observation_time"],
                "synthetic_only": True,
                "production_usable": False,
                "activation": False,
                "proofSuiteId": None,
            }),
        )["observation_id"]
    except Exception:
        # A GRAPH stores no receipt.  Validate its observation through the
        # independent ingress grammar with a bounded synthetic at-time receipt.
        # The producer's source receipt is checked on SOURCE_OBSERVATION.
        try:
            ingress._verify_observation(_canonical(observation))
            observation_id = ingress._raw_digest("sanitized-observation", _canonical(observation))
        except Exception:
            raise CoreVerificationError("core:graph") from None
    if profile["profile_id"] != observation["profile_id"] or profile["version"] != observation["profile_version"]:
        raise CoreVerificationError("core:graph")
    finding_id = _digest("sanitized-finding", {
        "profile_id": observation["profile_id"],
        "profile_version": observation["profile_version"],
        "observation_time": observation["observation_time"],
        "outcome": observation["outcome"],
    })
    if findings[0]["finding_id"] != finding_id or findings[0]["kind"] != observation["outcome"]:
        raise CoreVerificationError("core:graph")
    report_id = _digest("sanitized-report", {
        "profile_id": observation["profile_id"],
        "profile_version": observation["profile_version"],
        "observation_time": observation["observation_time"],
        "outcome": observation["outcome"],
        "finding_id": finding_id,
    })
    if report["report_id"] != report_id:
        raise CoreVerificationError("core:graph")
    _hex(report_id, "core:graph")
    return {"report_id": report_id, "observation_id": observation_id}


def _verify_source(value: Mapping[str, object], config: Mapping[str, object]) -> dict[str, object]:
    required = {
        "schema", "schema_version", "kind", "artifact_id",
        "ingress_database_id", "ingress_chain_id", "ingress_config_digest",
        "ingress_artifact_id", "ingress_event_sequence", "ingress_prefix_root",
        "ingress_after_root", "ingress_head_root", "observation_identity",
        "observation", "verification_receipt", "profile_id", "profile_version",
        "runtime_profile_digest", "observation_time", "source_status", "freshness",
        "page_complete", "page_count", "resource_count", "source_count",
        "complete_source_count", "record_count", "finding_count",
        "discrepancy_count", "outcome", "graph_artifact_id",
        "graph_artifact_digest", "admission_receipt", "admission_report_id",
        "observation_status", "chronology", "flags",
    }
    if (
        set(value) != required
        or value.get("schema") != "mirror-core-source-observation-v4"
        or value.get("schema_version") != 4
        or value.get("kind") != "SOURCE_OBSERVATION"
        or value.get("flags") != FIXED_FLAGS
    ):
        raise CoreVerificationError("core:source-keys")
    for key in (
        "artifact_id", "ingress_config_digest", "ingress_artifact_id",
        "ingress_prefix_root", "ingress_after_root", "ingress_head_root",
        "observation_identity", "graph_artifact_id", "graph_artifact_digest",
        "admission_report_id",
    ):
        _hex(value[key], "core:source-binding")
    for key in ("ingress_database_id", "ingress_chain_id", "profile_id"):
        _safe_identifier(value[key], "core:source-binding")
    if (
        value["ingress_database_id"] != config["ingress_database_id"]
        or value["ingress_chain_id"] != config["ingress_chain_id"]
        or value["ingress_config_digest"] != config["ingress_config_digest"]
        or value["runtime_profile_digest"] != config["runtime_profile_digest"]
        or value["profile_id"] != "ncmedicaid.provider-directory.fhir-r4.practitioner-role-location.v4"
        or value["profile_version"] != 3
    ):
        raise CoreVerificationError("core:source-config")
    if type(value["ingress_event_sequence"]) is not int or value["ingress_event_sequence"] <= 0:
        raise CoreVerificationError("core:source-sequence")
    if any(
        type(value[key]) is not int or value[key] < 0
        for key in (
            "profile_version", "observation_time", "page_count", "resource_count",
            "source_count", "complete_source_count", "record_count",
            "finding_count", "discrepancy_count",
        )
    ):
        raise CoreVerificationError("core:source-count")
    if (
        type(value["page_complete"]) is not bool
        or value["source_status"] not in {"COMPLETE", "FAILED"}
        or value["freshness"] not in {"FRESH", "UNKNOWN", "STALE"}
        or value["observation_status"] not in {"OBSERVED_NEW", "OBSERVED_CONTINUED", "OBSERVED_CHANGED", "INCOMPLETE"}
        or value["chronology"] not in {"INITIAL", "ADVANCING"}
    ):
        raise CoreVerificationError("core:source-state")
    observation = value["observation"]
    receipt = value["verification_receipt"]
    if not isinstance(observation, dict) or not isinstance(receipt, dict):
        raise CoreVerificationError("core:source-observation")
    try:
        checked = ingress.verify_observation_pair(_canonical(observation), _canonical(receipt))
    except Exception:
        raise CoreVerificationError("core:source-observation") from None
    if checked["observation"] != observation or checked["verification_receipt"] != receipt:
        raise CoreVerificationError("core:source-observation")
    if (
        value["observation_identity"] != checked["observation_id"]
        or value["admission_receipt"] != receipt
        or value["profile_id"] != observation["profile_id"]
        or value["profile_version"] != observation["profile_version"]
        or value["observation_time"] != observation["observation_time"]
        or value["source_count"] != observation["source_count"]
        or value["complete_source_count"] != observation["complete_source_count"]
        or value["record_count"] != observation["record_count"]
        or value["finding_count"] != observation["finding_count"]
        or value["discrepancy_count"] != observation["discrepancy_count"]
        or value["outcome"] != observation["outcome"]
        or value["source_status"] != observation["source_status"]
        or value["freshness"] != observation["freshness"]
        or value["page_complete"] != observation["page_complete"]
        or value["page_count"] != observation["page_count"]
        or value["resource_count"] != observation["resource_count"]
    ):
        raise CoreVerificationError("core:source-binding")
    if value["artifact_id"] != _digest(
        "source-artifact-id",
        {key: value[key] for key in required if key not in {"artifact_id", "flags"}},
    ):
        raise CoreVerificationError("core:source-id")
    return dict(value)


def _verify_reconciliation(value: Mapping[str, object]) -> dict[str, object]:
    required = {
        "schema", "schema_version", "kind", "artifact_id",
        "current_source_artifact_id", "prior_source_artifact_id",
        "current_observation_identity", "prior_observation_identity",
        "source_status", "observation_status", "chronology", "linkage", "flags",
    }
    if (
        set(value) != required
        or value.get("schema") != "mirror-core-reconciliation-v4"
        or value.get("schema_version") != 4
        or value.get("kind") != "RECONCILIATION"
        or value.get("flags") != FIXED_FLAGS
    ):
        raise CoreVerificationError("core:reconciliation-keys")
    for key in ("artifact_id", "current_source_artifact_id", "current_observation_identity"):
        _hex(value[key], "core:reconciliation")
    for key in ("prior_source_artifact_id", "prior_observation_identity"):
        if value[key] is not None:
            _hex(value[key], "core:reconciliation")
    if (
        value["source_status"] not in {"COMPLETE", "FAILED"}
        or value["observation_status"] not in {"OBSERVED_NEW", "OBSERVED_CONTINUED", "OBSERVED_CHANGED", "INCOMPLETE"}
        or value["chronology"] not in {"INITIAL", "ADVANCING"}
        or value["linkage"] not in {"UNCHANGED", "LINKED"}
    ):
        raise CoreVerificationError("core:reconciliation")
    if value["artifact_id"] != _digest(
        "reconciliation-id",
        {key: value[key] for key in required if key != "artifact_id"},
    ):
        raise CoreVerificationError("core:reconciliation-id")
    return dict(value)


def _verify_approval(value: Mapping[str, object], kind: str) -> None:
    required = (
        {"schema", "schema_version", "kind", "artifact_id", "decision",
         "policy_digest", "evidence_digest", "verifier_id", "verifier_epoch",
         "valid_from", "valid_until", "flags"}
        if kind == "GOVERNANCE" else
        {"schema", "schema_version", "kind", "artifact_id", "privacy_decision",
         "support_decision", "policy_digest", "evidence_digest", "verifier_id",
         "verifier_epoch", "valid_from", "valid_until", "flags"}
    )
    if set(value) != required or value.get("schema_version") != 3 or value.get("flags") != FIXED_FLAGS:
        raise CoreVerificationError("core:approval")
    for key in ("artifact_id", "policy_digest", "evidence_digest"):
        _hex(value[key], "core:approval")
    if (
        type(value["verifier_id"]) is not str or not value["verifier_id"]
        or type(value["verifier_epoch"]) is not int or value["verifier_epoch"] < 0
        or type(value["valid_from"]) is not int or type(value["valid_until"]) is not int
        or value["valid_from"] < 0 or value["valid_until"] < value["valid_from"]
    ):
        raise CoreVerificationError("core:approval")
    if kind == "GOVERNANCE" and value["decision"] not in {"GRANTED", "DENIED", "WITHDRAWN"}:
        raise CoreVerificationError("core:approval")
    if kind == "PRIVACY" and (
        value["privacy_decision"] not in {"GRANTED", "DENIED", "WITHDRAWN"}
        or value["support_decision"] not in {"GRANTED", "DENIED", "WITHDRAWN"}
    ):
        raise CoreVerificationError("core:approval")


def _verify_case(value: Mapping[str, object]) -> None:
    required = {
        "schema", "schema_version", "kind", "artifact_id", "case_id",
        "reconciliation_artifact_id", "source_artifact_id", "graph_artifact_id",
        "graph_report_id", "graph_profile_digest", "subject_digest",
        "target_finding_ids", "target_finding_kinds", "state", "responsibility",
        "reason", "action_artifact_id", "action_observed_at",
        "retest_source_artifact_id", "retest_graph_artifact_id",
        "retest_observation_time", "flags",
    }
    if (
        set(value) != required or value.get("schema") != "mirror-core-case-v4"
        or value.get("schema_version") != 4 or value.get("kind") != "CASE"
        or value.get("flags") != FIXED_FLAGS or value.get("responsibility") != "UNKNOWN"
    ):
        raise CoreVerificationError("core:case")
    for key in (
        "artifact_id", "case_id", "reconciliation_artifact_id",
        "source_artifact_id", "graph_artifact_id", "graph_report_id",
        "graph_profile_digest", "subject_digest",
    ):
        _hex(value[key], "core:case")
    ids = value["target_finding_ids"]
    kinds = value["target_finding_kinds"]
    if (
        not isinstance(ids, list) or not isinstance(kinds, list) or not ids
        or len(ids) != len(kinds) or ids != sorted(ids) or len(set(ids)) != len(ids)
        or any(type(item) is not str or len(item) != 128 or any(char not in _HEX for char in item) for item in ids)
        or any(type(item) is not str or not item for item in kinds)
    ):
        raise CoreVerificationError("core:case-findings")
    if value["state"] not in {"OPEN", "ACTION_RECORDED", "RETEST_FAILED_OR_INDETERMINATE", "RESOLVED"}:
        raise CoreVerificationError("core:case-state")
    if value["reason"] not in {
        "ACTIONABLE_FINDING", "ACTION_VERIFIED", "ALL_TARGET_FINDINGS_CLEARED",
        "TARGET_FINDINGS_REMAIN", "RETEST_INDETERMINATE",
    }:
        raise CoreVerificationError("core:case-reason")
    for key in ("action_artifact_id", "retest_source_artifact_id", "retest_graph_artifact_id"):
        if value[key] is not None:
            _hex(value[key], "core:case-link")
    for key in ("action_observed_at", "retest_observation_time"):
        if value[key] is not None and (type(value[key]) is not int or value[key] < 0):
            raise CoreVerificationError("core:case-time")


def _verify_artifact_value(row: Mapping[str, object], config: Mapping[str, object]) -> dict[str, object]:
    if tuple(row.keys()) != TABLE_COLUMNS["core_artifacts"]:
        raise CoreVerificationError("core:artifact-columns")
    raw = row["raw"]
    if type(raw) is not bytes or not raw or len(raw) > MAX_ARTIFACT_BYTES:
        raise CoreVerificationError("core:artifact-bytes")
    value = _parse(raw, "core:artifact")
    kind = row["kind"]
    if (
        kind not in ARTIFACT_KINDS
        or (kind != "GRAPH" and value.get("kind") != kind)
        or (kind == "GRAPH" and value.get("kind") != "GRAPH")
    ):
        raise CoreVerificationError("core:artifact-kind")
    if kind == "GRAPH":
        _verify_graph(value)
    elif kind == "SOURCE_OBSERVATION":
        _verify_source(value, config)
    elif kind == "RECONCILIATION":
        _verify_reconciliation(value)
    elif kind in {"GOVERNANCE", "PRIVACY"}:
        _verify_approval(value, kind)
    elif kind == "CASE":
        _verify_case(value)
    elif kind == "CASE_ACTION":
        try:
            corrective_action.verify_artifact(
                raw, control_digest=config["corrective_action_control_digest"]
            )
        except Exception:
            raise CoreVerificationError("core:case-action") from None
    expected_profile = {
        "GRAPH": config["runtime_profile_digest"],
        "SOURCE_OBSERVATION": config["runtime_profile_digest"],
        "RECONCILIATION": config["runtime_profile_digest"],
        "CASE": config["runtime_profile_digest"],
        "CASE_ACTION": config["runtime_profile_digest"],
        "GOVERNANCE": config["governance_policy_digest"],
        "PRIVACY": config["privacy_policy_digest"],
    }[kind]
    if row["profile_digest"] != expected_profile:
        raise CoreVerificationError("core:artifact-profile")
    _hex(row["profile_digest"], "core:artifact-profile")
    for key in ("source_artifact_id", "predecessor_id"):
        if row[key] is not None:
            _hex(row[key], "core:artifact-link")
    if type(row["created_event_sequence"]) is not int or row["created_event_sequence"] <= 0:
        raise CoreVerificationError("core:artifact-sequence")
    expected_id = _digest("artifact-row-id", {
        "kind": kind, "raw": _raw_digest("artifact-bytes", raw),
        "profile_digest": row["profile_digest"],
        "source_artifact_id": row["source_artifact_id"],
        "predecessor_id": row["predecessor_id"],
    })
    if row["artifact_id"] != expected_id:
        raise CoreVerificationError("core:artifact-id")
    if kind == "GRAPH":
        expected_state = "GRAPH"
    elif kind in {"SOURCE_OBSERVATION", "RECONCILIATION"}:
        expected_state = value["observation_status"]
    elif kind == "GOVERNANCE":
        expected_state = value["decision"]
    elif kind == "PRIVACY":
        expected_state = value["privacy_decision"]
    elif kind == "CASE_ACTION":
        expected_state = "ACTION_RECORDED"
    else:
        expected_state = value["state"]
    if row["current_state"] != expected_state:
        raise CoreVerificationError("core:artifact-state")
    return value


def _material_keys(kind: str) -> set[str]:
    if kind == "ARTIFACT":
        return {
            "artifact_id", "kind", "raw_digest", "raw_length", "profile_digest",
            "source_artifact_id", "predecessor_id", "current_state",
            "ingress_watermark",
        }
    if kind == "SESSION_OPEN":
        return {"session"}
    if kind == "SESSION_START":
        return {"delta"}
    if kind == "OBSERVATION":
        return {"observation"}
    if kind == "SESSION_PAUSE":
        return {
            "state", "reason", "trigger", "current_source_artifact_id",
            "current_governance_artifact_id", "current_privacy_artifact_id",
            "slot_number", "observation_digest",
        }
    raise CoreVerificationError("core:event-kind")


def _session_authority(
    artifacts: Mapping[str, sqlite3.Row],
    heads: Mapping[tuple[str, str], str],
    session: Mapping[str, object],
    config: Mapping[str, object],
    observed_at: int,
) -> tuple[str | None, dict[str, str | None]]:
    current_heads = {
        kind: heads.get(("ARTIFACT", kind))
        for kind in ("SOURCE_OBSERVATION", "GOVERNANCE", "PRIVACY")
    }
    if current_heads["SOURCE_OBSERVATION"] != session.get("source_artifact_id"):
        return "SOURCE_SUPERSEDED", current_heads
    if (
        current_heads["GOVERNANCE"] != session.get("governance_artifact_id")
        or current_heads["PRIVACY"] != session.get("privacy_artifact_id")
    ):
        return "AUTHORITY_INDETERMINATE", current_heads

    source_id = session.get("source_artifact_id")
    governance_id = session.get("governance_artifact_id")
    privacy_id = session.get("privacy_artifact_id")
    source_row = artifacts.get(str(source_id))
    governance_row = artifacts.get(str(governance_id))
    privacy_row = artifacts.get(str(privacy_id))
    if (
        source_row is None
        or source_row["kind"] != "SOURCE_OBSERVATION"
        or governance_row is None
        or governance_row["kind"] != "GOVERNANCE"
        or privacy_row is None
        or privacy_row["kind"] != "PRIVACY"
    ):
        return "AUTHORITY_INDETERMINATE", current_heads
    try:
        source = _parse(source_row["raw"], "core:authority-source")
        governance = _parse(governance_row["raw"], "core:authority-governance")
        privacy = _parse(privacy_row["raw"], "core:authority-privacy")
    except CoreVerificationError:
        return "AUTHORITY_INDETERMINATE", current_heads
    if (
        source.get("runtime_profile_digest") != config["runtime_profile_digest"]
        or governance.get("policy_digest") != config["governance_policy_digest"]
        or privacy.get("policy_digest") != config["privacy_policy_digest"]
        or governance.get("decision") != "GRANTED"
        or privacy.get("privacy_decision") != "GRANTED"
        or privacy.get("support_decision") != "GRANTED"
    ):
        return "AUTHORITY_INDETERMINATE", current_heads
    for authority in (governance, privacy):
        if type(authority.get("valid_from")) is not int or type(authority.get("valid_until")) is not int:
            return "AUTHORITY_INDETERMINATE", current_heads
        if observed_at < int(authority["valid_from"]) or observed_at > int(authority["valid_until"]):
            return "AUTHORITY_EXPIRED", current_heads
    return None, current_heads


def _check_event(value: Mapping[str, object], meta: Mapping[str, object], previous_root: str, previous_observed: int) -> None:
    if set(value) != EVENT_RAW_KEYS or value["schema"] != SCHEMA or value["schema_version"] != SCHEMA_VERSION:
        raise CoreVerificationError("core:event-schema")
    if value["database_id"] != meta["database_id"] or value["chain_id"] != meta["chain_id"]:
        raise CoreVerificationError("core:event-config")
    for key in (
        "event_id", "operation_id", "subject_id", "request_digest",
        "material_digest", "payload_digest", "before_root", "after_root",
        "stream_before_root", "stream_after_root",
    ):
        _hex(value[key], "core:event-hex")
    for key in ("sequence", "attempt", "observed_at", "payload_length"):
        if type(value[key]) is not int or value[key] < 0:
            raise CoreVerificationError("core:event-number")
    for key in (
        "event_kind", "stream_kind", "stream_id", "prior_state", "next_state",
    ):
        if type(value[key]) is not str or not value[key]:
            raise CoreVerificationError("core:event-field")
    if value["before_root"] != previous_root or value["observed_at"] < previous_observed:
        raise CoreVerificationError("core:event-order")
    if value["event_id"] != _digest(
        "event-id",
        {key: value[key] for key in EVENT_RAW_KEYS if key not in {"event_id", "after_root", "stream_after_root"}},
    ):
        raise CoreVerificationError("core:event-id")
    if value["material_digest"] != _digest("material", value["material"]):
        raise CoreVerificationError("core:event-material")
    if value["after_root"] != _event_root(value) or value["stream_after_root"] != _stream_root(value):
        raise CoreVerificationError("core:event-root")


def _verify_connection(
    connection: sqlite3.Connection,
    *,
    expected_database_id: str | None = None,
    expected_config_digest: str | None = None,
    ingress_path: str | Path | None = None,
    ingress_bytes: bytes | None = None,
    include_source_observation: bool = False,
) -> dict[str, object]:
    if _table_names(connection) != tuple(sorted(TABLES)):
        raise CoreVerificationError("core:tables")
    for table, columns in TABLE_COLUMNS.items():
        if _columns(connection, table) != columns:
            raise CoreVerificationError("core:columns")
        definition = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ).fetchone()
        if definition is None or definition[0] != TABLE_SQL[table]:
            raise CoreVerificationError("core:ddl")
    indexes = {
        row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='index' "
            "AND name NOT LIKE 'sqlite_autoindex_%'"
        ).fetchall()
    }
    if indexes != {EXPLICIT_INDEX}:
        raise CoreVerificationError("core:indexes")
    if connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='trigger' LIMIT 1"
    ).fetchone() is not None:
        raise CoreVerificationError("core:ddl")
    meta = connection.execute("SELECT * FROM core_meta WHERE meta_id=1").fetchone()
    if (
        meta is None or tuple(meta.keys()) != TABLE_COLUMNS["core_meta"]
        or meta["schema"] != SCHEMA or meta["schema_version"] != SCHEMA_VERSION
    ):
        raise CoreVerificationError("core:meta")
    if expected_database_id is not None and meta["database_id"] != expected_database_id:
        raise CoreVerificationError("core:database-id")
    if expected_config_digest is not None and meta["config_digest"] != expected_config_digest:
        raise CoreVerificationError("core:config")
    _hex(meta["config_digest"], "core:config")
    config = _verify_config(_parse(meta["config_raw"], "core:config"), meta["config_digest"])
    if (
        config["database_id"] != meta["database_id"]
        or config["chain_id"] != meta["chain_id"]
        or config["ingress_database_id"] != meta["ingress_database_id"]
        or type(meta["sequence"]) is not int or meta["sequence"] < 0
        or type(meta["ingress_watermark"]) is not int or meta["ingress_watermark"] < 0
    ):
        raise CoreVerificationError("core:meta")

    artifact_rows = connection.execute(
        "SELECT * FROM core_artifacts ORDER BY created_event_sequence,artifact_id"
    ).fetchall()
    actual_artifacts: dict[str, sqlite3.Row] = {}
    for row in artifact_rows:
        identifier = str(row["artifact_id"])
        if identifier in actual_artifacts:
            raise CoreVerificationError("core:artifact-duplicate")
        _verify_artifact_value(row, config)
        actual_artifacts[identifier] = row

    expected_artifacts: dict[str, sqlite3.Row] = {}
    expected_sessions: dict[str, dict[str, object]] = {}
    expected_slots: dict[tuple[str, int], dict[str, object]] = {}
    stream_roots: dict[tuple[str, str], str] = {}
    stream_refs: dict[tuple[str, str], str] = {}
    stream_sequences: dict[tuple[str, str], int] = {}
    previous_root = GENESIS_ROOT
    previous_observed = -1
    ingress_watermark = 0
    events = connection.execute("SELECT * FROM core_events ORDER BY sequence").fetchall()
    for expected_sequence, row in enumerate(events, start=1):
        if tuple(row.keys()) != TABLE_COLUMNS["core_events"] or row["sequence"] != expected_sequence:
            raise CoreVerificationError("core:event-order")
        raw_event = row["event_raw"]
        if type(raw_event) is not bytes or not raw_event or len(raw_event) > MAX_EVENT_BYTES:
            raise CoreVerificationError("core:event-bytes")
        value = _parse(raw_event, "core:event-raw")
        if any(value[key] != row[key] for key in ("sequence", "event_id", "event_kind", "operation_id", "subject_id")):
            raise CoreVerificationError("core:event-table")
        _check_event(value, meta, previous_root, previous_observed)
        previous_observed = int(value["observed_at"])
        kind = str(value["event_kind"])
        material = value["material"]
        if kind not in EVENT_KINDS or not isinstance(material, dict) or set(material) != _material_keys(kind):
            raise CoreVerificationError("core:event-material")
        if row["receipt_digest"] != _raw_digest("receipt", raw_event):
            raise CoreVerificationError("core:event-receipt")
        stream_key = (str(value["stream_kind"]), str(value["stream_id"]))
        if value["stream_before_root"] != stream_roots.get(stream_key, GENESIS_ROOT):
            raise CoreVerificationError("core:stream-order")
        stream_roots[stream_key] = str(value["stream_after_root"])
        stream_sequences[stream_key] = int(value["sequence"])
        previous_root = str(value["after_root"])
        if kind == "ARTIFACT":
            if value["prior_state"] != "NONE" or value["next_state"] not in ARTIFACT_KINDS:
                raise CoreVerificationError("core:event-artifact")
            identifier = str(material["artifact_id"])
            row_artifact = actual_artifacts.get(identifier)
            if row_artifact is None or identifier in expected_artifacts:
                raise CoreVerificationError("core:event-artifact")
            if (
                row_artifact["created_event_sequence"] != value["sequence"]
                or row_artifact["kind"] != material["kind"]
                or row_artifact["profile_digest"] != material["profile_digest"]
                or row_artifact["source_artifact_id"] != material["source_artifact_id"]
                or row_artifact["predecessor_id"] != material["predecessor_id"]
                or row_artifact["current_state"] != material["current_state"]
            ):
                raise CoreVerificationError("core:event-artifact")
            raw_artifact = row_artifact["raw"]
            if (
                material["raw_length"] != len(raw_artifact)
                or material["raw_digest"] != _raw_digest("artifact-bytes", raw_artifact)
                or value["payload_digest"] != identifier
                or value["payload_length"] != len(raw_artifact)
            ):
                raise CoreVerificationError("core:event-artifact")
            parsed = _verify_artifact_value(row_artifact, config)
            expected_artifacts[identifier] = row_artifact
            expected_stream_id = (
                str(parsed["case_id"]) if material["kind"] == "CASE"
                else str(parsed["policy"]["case_id"]) if material["kind"] == "CASE_ACTION"
                else str(material["kind"])
            )
            if value["stream_id"] != expected_stream_id:
                raise CoreVerificationError("core:event-stream")
            stream_refs[stream_key] = identifier
            predecessor = material["predecessor_id"]
            if predecessor is not None and predecessor not in expected_artifacts:
                raise CoreVerificationError("core:artifact-predecessor")
            if material["kind"] == "GRAPH":
                graph = _verify_graph(parsed)
                expected_operation = _digest(
                    "graph-operation",
                    {"graph_id": graph["report_id"], "graph_digest": _raw_digest("graph-artifact", raw_artifact)},
                )
                expected_request = _digest(
                    "graph-request",
                    {"graph_id": graph["report_id"], "graph_digest": _raw_digest("graph-artifact", raw_artifact)},
                )
            elif material["kind"] == "SOURCE_OBSERVATION":
                expected_operation = _digest(
                    "source-operation", {"ingress_artifact_id": parsed["ingress_artifact_id"]}
                )
                expected_request = _digest(
                    "source-request", {"ingress_artifact_id": parsed["ingress_artifact_id"]}
                )
                ingress_watermark = max(ingress_watermark, int(parsed["ingress_event_sequence"]))
                graph_id = str(parsed["graph_artifact_id"])
                graph_row = expected_artifacts.get(graph_id)
                if graph_row is None or graph_row["kind"] != "GRAPH":
                    raise CoreVerificationError("core:source-graph")
                graph_raw = graph_row["raw"]
                graph_value = _parse(graph_raw, "core:source-graph")
                graph_checked = _verify_graph(graph_value)
                if (
                    graph_checked["report_id"] != parsed["admission_report_id"]
                    or graph_checked["observation_id"] != parsed["observation_identity"]
                    or parsed["graph_artifact_digest"] != _raw_digest("graph-artifact", graph_raw)
                ):
                    raise CoreVerificationError("core:source-graph")
            elif material["kind"] == "RECONCILIATION":
                expected_operation = _digest(
                    "reconciliation-operation",
                    {"source_artifact_id": parsed["current_source_artifact_id"]},
                )
                expected_request = _digest(
                    "reconciliation-request",
                    {"source_artifact_id": parsed["current_source_artifact_id"]},
                )
                current_source = expected_artifacts.get(str(parsed["current_source_artifact_id"]))
                if current_source is None or current_source["kind"] != "SOURCE_OBSERVATION":
                    raise CoreVerificationError("core:reconciliation-source")
                current_value = _parse(current_source["raw"], "core:reconciliation-source")
                if current_value["observation_identity"] != parsed["current_observation_identity"]:
                    raise CoreVerificationError("core:reconciliation-source")
                if parsed["prior_source_artifact_id"] is not None:
                    prior = expected_artifacts.get(str(parsed["prior_source_artifact_id"]))
                    if prior is None or prior["kind"] != "SOURCE_OBSERVATION":
                        raise CoreVerificationError("core:reconciliation-prior")
                    prior_value = _parse(prior["raw"], "core:reconciliation-prior")
                    if prior_value["observation_identity"] != parsed["prior_observation_identity"]:
                        raise CoreVerificationError("core:reconciliation-prior")
                if predecessor is not None:
                    prior_rec = expected_artifacts.get(str(predecessor))
                    if prior_rec is None or prior_rec["kind"] != "RECONCILIATION":
                        raise CoreVerificationError("core:reconciliation-chain")
            elif material["kind"] in {"GOVERNANCE", "PRIVACY"}:
                digest = _raw_digest("approval", raw_artifact)
                expected_operation = _digest("approval-operation", {"kind": material["kind"], "raw": digest})
                expected_request = _digest("approval-request", {"kind": material["kind"], "raw": digest})
            elif material["kind"] == "CASE_ACTION":
                expected_operation = _digest(
                    "case-action-operation",
                    {"action_id": parsed["artifact_id"], "case_id": parsed["policy"]["case_id"]},
                )
                expected_request = _digest(
                    "case-action-request",
                    {
                        "action_id": parsed["artifact_id"],
                        "case_id": parsed["policy"]["case_id"],
                        "evidence_digest": parsed["assertion"]["evidence_sha3_512"],
                    },
                )
            else:
                if parsed["state"] == "OPEN":
                    expected_operation = _digest("case-operation", {"case_id": parsed["case_id"]})
                    expected_request = _digest(
                        "case-request",
                        {"reconciliation_artifact_id": parsed["reconciliation_artifact_id"], "case_id": parsed["case_id"]},
                    )
                elif parsed["state"] == "ACTION_RECORDED":
                    if predecessor is None or parsed["action_artifact_id"] is None:
                        raise CoreVerificationError("core:case-operation")
                    expected_operation = _digest(
                        "case-transition-operation",
                        {"case_artifact_id": predecessor, "action_artifact_id": parsed["action_artifact_id"], "transition": "ACTION_RECORDED"},
                    )
                    expected_request = _digest(
                        "case-transition-request",
                        {"case_artifact_id": predecessor, "action_artifact_id": parsed["action_artifact_id"], "transition": "ACTION_RECORDED"},
                    )
                elif parsed["state"] in {"RETEST_FAILED_OR_INDETERMINATE", "RESOLVED"}:
                    if predecessor is None or parsed["retest_source_artifact_id"] is None:
                        raise CoreVerificationError("core:case-operation")
                    expected_operation = _digest(
                        "case-evaluate-operation",
                        {"case_artifact_id": predecessor, "later_source_artifact_id": parsed["retest_source_artifact_id"]},
                    )
                    expected_request = _digest(
                        "case-evaluate-request",
                        {"case_artifact_id": predecessor, "later_source_artifact_id": parsed["retest_source_artifact_id"], "state": parsed["state"], "reason": parsed["reason"]},
                    )
                else:
                    raise CoreVerificationError("core:case-operation")
            if value["operation_id"] != expected_operation or value["request_digest"] != expected_request:
                raise CoreVerificationError("core:artifact-operation")
            if material["kind"] == "SOURCE_OBSERVATION":
                if row_artifact["source_artifact_id"] != parsed["ingress_artifact_id"]:
                    raise CoreVerificationError("core:source-link")
                prior_id = row_artifact["predecessor_id"]
                if prior_id is None:
                    if parsed["chronology"] != "INITIAL":
                        raise CoreVerificationError("core:source-chronology")
                else:
                    prior_row = expected_artifacts.get(str(prior_id))
                    if prior_row is None:
                        raise CoreVerificationError("core:source-predecessor")
                    prior_value = _parse(prior_row["raw"], "core:artifact")
                    if (
                        parsed["ingress_event_sequence"] <= prior_value["ingress_event_sequence"]
                        or parsed["observation_time"] <= prior_value["observation_time"]
                        or parsed["chronology"] != "ADVANCING"
                    ):
                        raise CoreVerificationError("core:source-chronology")

        elif kind == "SESSION_OPEN":
            session = material["session"]
            if (
                value["prior_state"] != "NONE" or value["next_state"] != "OPEN"
                or not isinstance(session, dict)
                or set(session) != {"session_id", "state", "source_artifact_id", "governance_artifact_id", "privacy_artifact_id", "last_slot"}
                or session["session_id"] != value["subject_id"]
                or session["state"] != "OPEN" or session["last_slot"] != -1
            ):
                raise CoreVerificationError("core:session-open")
            session_id = str(value["subject_id"])
            if (
                value["stream_kind"] != "SESSION"
                or value["stream_id"] != session_id
                or session_id in expected_sessions
            ):
                raise CoreVerificationError("core:session-open")
            for key in ("source_artifact_id", "governance_artifact_id", "privacy_artifact_id"):
                _hex(session[key], "core:session-open")
            for key, artifact_kind in (
                ("source_artifact_id", "SOURCE_OBSERVATION"),
                ("governance_artifact_id", "GOVERNANCE"),
                ("privacy_artifact_id", "PRIVACY"),
            ):
                artifact = expected_artifacts.get(str(session[key]))
                if artifact is None or artifact["kind"] != artifact_kind:
                    raise CoreVerificationError("core:session-open")
            if session_id != _digest(
                "session-id",
                {
                    "source": session["source_artifact_id"],
                    "governance": session["governance_artifact_id"],
                    "privacy": session["privacy_artifact_id"],
                    "config": _digest("config", config),
                },
            ):
                raise CoreVerificationError("core:session-open")
            if len(expected_sessions) >= int(config["max_sessions"]):
                raise CoreVerificationError("core:session-capacity")
            if value["operation_id"] != _digest("session-operation", {"session_id": value["subject_id"], "action": "OPEN"}):
                raise CoreVerificationError("core:session-open")
            if value["request_digest"] != _digest("session-request", {"session_id": value["subject_id"]}):
                raise CoreVerificationError("core:session-open")
            authority_reason, _heads = _session_authority(
                expected_artifacts,
                stream_refs,
                session,
                config,
                int(value["observed_at"]),
            )
            if authority_reason is not None:
                raise CoreVerificationError("core:session-open-authority")
            expected_sessions[session_id] = {
                "session_id": session_id,
                "state": "OPEN",
                "source_artifact_id": str(session["source_artifact_id"]),
                "governance_artifact_id": str(session["governance_artifact_id"]),
                "privacy_artifact_id": str(session["privacy_artifact_id"]),
                "head_root": str(value["stream_after_root"]),
                "last_slot": -1,
            }
        elif kind == "SESSION_START":
            if (
                value["prior_state"] != "OPEN" or value["next_state"] != "RUNNING"
                or material != {"delta": {"state": "RUNNING"}}
                or value["operation_id"] != _digest("session-operation", {"session_id": value["subject_id"], "action": "START"})
                or value["request_digest"] != _digest("session-request", {"session_id": value["subject_id"], "action": "START"})
            ):
                raise CoreVerificationError("core:session-start")
            session_id = str(value["subject_id"])
            session_state = expected_sessions.get(session_id)
            if (
                value["stream_kind"] != "SESSION"
                or value["stream_id"] != session_id
                or session_state is None
                or session_state["state"] != "OPEN"
                or value["prior_state"] != session_state["state"]
            ):
                raise CoreVerificationError("core:session-start")
            authority_reason, _heads = _session_authority(
                expected_artifacts,
                stream_refs,
                session_state,
                config,
                int(value["observed_at"]),
            )
            if authority_reason is not None:
                raise CoreVerificationError("core:session-start-authority")
            session_state["state"] = "RUNNING"
            session_state["head_root"] = str(value["stream_after_root"])
        elif kind == "OBSERVATION":
            observation = material["observation"]
            if not isinstance(observation, dict):
                raise CoreVerificationError("core:session-observation")
            required = {"schema", "schema_version", "session_id", "slot_number", "result", "counts", "flags", "result_digest"}
            if set(observation) != required or observation["schema"] != "mirror-core-observation-v3" or type(observation["schema_version"]) is not int or observation["schema_version"] != 3 or observation["flags"] != FIXED_FLAGS or observation["session_id"] != value["subject_id"] or observation["result"] not in OBSERVATION_RESULTS:
                raise CoreVerificationError("core:session-observation")
            if observation["result_digest"] != _digest("observation", {key: observation[key] for key in observation if key != "result_digest"}):
                raise CoreVerificationError("core:session-observation")
            result_raw = _canonical(observation)
            if value["payload_digest"] != observation["result_digest"] or value["payload_length"] != len(result_raw):
                raise CoreVerificationError("core:session-observation")
            session_id = str(value["subject_id"])
            session_state = expected_sessions.get(session_id)
            slot_number = observation["slot_number"]
            counts = observation["counts"]
            if (
                value["stream_kind"] != "SESSION"
                or value["stream_id"] != session_id
                or value["prior_state"] != "RUNNING"
                or value["next_state"] != "RUNNING"
                or session_state is None
                or session_state["state"] != "RUNNING"
                or type(slot_number) is not int
                or slot_number < 0
                or slot_number >= int(config["max_slots_per_session"])
                or slot_number != int(session_state["last_slot"]) + 1
                or not isinstance(counts, dict)
                or set(counts) != {"changed", "observed"}
                or any(type(item) is not int or item < 0 or item > 64 for item in counts.values())
                or (session_id, slot_number) in expected_slots
            ):
                raise CoreVerificationError("core:session-observation")
            authority_reason, _heads = _session_authority(
                expected_artifacts,
                stream_refs,
                session_state,
                config,
                int(value["observed_at"]),
            ) if session_state is not None else ("AUTHORITY_INDETERMINATE", {})
            if authority_reason is not None:
                raise CoreVerificationError("core:session-observation-authority")
            expected_slots[(session_id, slot_number)] = {
                "session_id": session_id,
                "slot_number": slot_number,
                "result_digest": str(observation["result_digest"]),
                "result_raw": result_raw,
            }
            session_state["last_slot"] = slot_number
            session_state["head_root"] = str(value["stream_after_root"])
        elif kind == "SESSION_PAUSE":
            if value["next_state"] != "PAUSED" or material["state"] != "PAUSED":
                raise CoreVerificationError("core:session-pause")
            session_id = str(value["subject_id"])
            session_state = expected_sessions.get(session_id)
            trigger = material["trigger"]
            slot_number = material["slot_number"]
            observation_digest = material["observation_digest"]
            if (
                value["stream_kind"] != "SESSION"
                or value["stream_id"] != session_id
                or session_state is None
                or session_state["state"] not in {"OPEN", "RUNNING"}
                or value["prior_state"] != session_state["state"]
                or material["reason"] not in ("SOURCE_SUPERSEDED", "AUTHORITY_INDETERMINATE", "AUTHORITY_EXPIRED")
                or trigger not in ("START", "OBSERVATION", "RECONCILE")
                or (trigger == "OBSERVATION" and (
                    type(slot_number) is not int
                    or slot_number < 0
                    or slot_number >= int(config["max_slots_per_session"])
                    or slot_number != int(session_state["last_slot"]) + 1
                    or type(observation_digest) is not str
                ))
                or (trigger != "OBSERVATION" and (slot_number is not None or observation_digest is not None))
            ):
                raise CoreVerificationError("core:session-pause")
            if trigger == "OBSERVATION":
                _hex(observation_digest, "core:session-pause")
            for key, artifact_kind in (
                ("current_source_artifact_id", "SOURCE_OBSERVATION"),
                ("current_governance_artifact_id", "GOVERNANCE"),
                ("current_privacy_artifact_id", "PRIVACY"),
            ):
                _hex(material[key], "core:session-pause")
                if material[key] != stream_refs.get(("ARTIFACT", artifact_kind)):
                    raise CoreVerificationError("core:session-pause")
            authority_reason, _heads = _session_authority(
                expected_artifacts,
                stream_refs,
                session_state,
                config,
                int(value["observed_at"]),
            )
            if authority_reason is None or material["reason"] != authority_reason:
                raise CoreVerificationError("core:session-pause-authority")
            session_state["state"] = "PAUSED"
            session_state["head_root"] = str(value["stream_after_root"])
        if kind.startswith("SESSION_") or kind == "OBSERVATION":
            stream_refs[stream_key] = str(value["subject_id"])

    if (
        meta["sequence"] != len(events)
        or meta["head_root"] != previous_root
        or meta["ingress_watermark"] != ingress_watermark
    ):
        raise CoreVerificationError("core:meta-root")
    if set(expected_artifacts) != set(actual_artifacts):
        raise CoreVerificationError("core:artifact-reconstruction")
    for identifier, row in actual_artifacts.items():
        if identifier not in expected_artifacts:
            raise CoreVerificationError("core:artifact-reconstruction")
        if any(row[key] != expected_artifacts[identifier][key] for key in TABLE_COLUMNS["core_artifacts"]):
            raise CoreVerificationError("core:artifact-reconstruction")
    actual_sessions = connection.execute("SELECT * FROM core_sessions ORDER BY session_id").fetchall()
    if len(actual_sessions) != len(expected_sessions):
        raise CoreVerificationError("core:session-reconstruction")
    for row in actual_sessions:
        identifier = row["session_id"]
        if type(identifier) is not str or identifier not in expected_sessions:
            raise CoreVerificationError("core:session-reconstruction")
        expected = expected_sessions[identifier]
        if any(row[key] != expected[key] for key in TABLE_COLUMNS["core_sessions"]):
            raise CoreVerificationError("core:session-reconstruction")
    actual_slots = connection.execute("SELECT * FROM core_slots ORDER BY session_id,slot_number").fetchall()
    if len(actual_slots) != len(expected_slots):
        raise CoreVerificationError("core:slot-reconstruction")
    for row in actual_slots:
        key = (row["session_id"], row["slot_number"])
        if key not in expected_slots:
            raise CoreVerificationError("core:slot-reconstruction")
        expected = expected_slots[key]
        if any(row[column] != expected[column] for column in TABLE_COLUMNS["core_slots"]):
            raise CoreVerificationError("core:slot-reconstruction")
    actual_heads = connection.execute("SELECT * FROM core_heads ORDER BY stream_kind,stream_id").fetchall()
    if len(actual_heads) != len(stream_roots):
        raise CoreVerificationError("core:heads")
    for row in actual_heads:
        key = (str(row["stream_kind"]), str(row["stream_id"]))
        if (
            key not in stream_roots
            or row["head_root"] != stream_roots[key]
            or row["event_sequence"] != stream_sequences[key]
            or row["head_ref"] != stream_refs.get(key, row["head_ref"])
        ):
            raise CoreVerificationError("core:heads")

    source_ids = tuple(
        identifier for identifier, row in actual_artifacts.items()
        if row["kind"] == "SOURCE_OBSERVATION"
    )
    ingress_bound = False
    if ingress_path is not None or ingress_bytes is not None:
        try:
            if ingress_bytes is not None:
                ingress_result = ingress.verify_bytes(
                    ingress_bytes,
                    expected_database_id=meta["ingress_database_id"],
                    expected_config_digest=config["ingress_config_digest"],
                    include_observation=True,
                    artifact_ids=tuple(
                        str(_parse(actual_artifacts[identifier]["raw"], "core:artifact")["ingress_artifact_id"])
                        for identifier in source_ids
                    ),
                )
            else:
                ingress_result = ingress.verify_database(
                    ingress_path,
                    expected_database_id=meta["ingress_database_id"],
                    expected_config_digest=config["ingress_config_digest"],
                    include_observation=True,
                    artifact_ids=tuple(
                        str(_parse(actual_artifacts[identifier]["raw"], "core:artifact")["ingress_artifact_id"])
                        for identifier in source_ids
                    ),
                )
        except Exception:
            raise CoreVerificationError("core:ingress-binding") from None
        selected = ingress_result.get("selected_artifacts")
        if not isinstance(selected, dict):
            raise CoreVerificationError("core:ingress-binding")
        for identifier in source_ids:
            source = _parse(actual_artifacts[identifier]["raw"], "core:artifact")
            item = selected.get(str(source["ingress_artifact_id"]))
            if not isinstance(item, dict):
                raise CoreVerificationError("core:ingress-binding")
            try:
                item_observation = _parse(item["observation"], "core:ingress-observation")
                item_receipt = _parse(item["verification_receipt"], "core:ingress-receipt")
            except Exception:
                raise CoreVerificationError("core:ingress-binding") from None
            if (
                item.get("terminal_state") != "QUARANTINED"
                or item.get("terminal_event_kind") != "ADMIT"
                or item_observation != source["observation"]
                or item_receipt != source["verification_receipt"]
                or item.get("observation_id") != source["observation_identity"]
                or item.get("event_sequence") != source["ingress_event_sequence"]
                or item.get("event_prefix_root") != source["ingress_prefix_root"]
                or item.get("event_after_root") != source["ingress_after_root"]
            ):
                raise CoreVerificationError("core:ingress-binding")
        ingress_bound = True
    current_source_artifact = None
    if include_source_observation:
        current_source_id = stream_refs.get(("ARTIFACT", "SOURCE_OBSERVATION"))
        if current_source_id is not None:
            current_source_row = actual_artifacts.get(current_source_id)
            if (
                current_source_row is None
                or current_source_row["kind"] != "SOURCE_OBSERVATION"
                or type(current_source_row["raw"]) is not bytes
            ):
                raise CoreVerificationError("core:source-head")
            current_source_artifact = _verify_source(
                _parse(current_source_row["raw"], "core:source-observation"),
                config,
            )

    result = {
        "structural_valid": True,
        "ingress_bound": ingress_bound,
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "database_id": meta["database_id"],
        "chain_id": meta["chain_id"],
        "config_digest": meta["config_digest"],
        "config_raw": bytes(meta["config_raw"]),
        "sequence": int(meta["sequence"]),
        "head_root": meta["head_root"],
        "ingress_database_id": meta["ingress_database_id"],
        "ingress_watermark": int(meta["ingress_watermark"]),
        "artifact_count": len(actual_artifacts),
        "head_count": len(stream_roots),
        "session_count": len(expected_sessions),
        "slot_count": len(expected_slots),
        "event_count": len(events),
        "latest_observed_at": previous_observed if events else 0,
        "flags": dict(FIXED_FLAGS),
        "current_source_artifact_id": stream_refs.get(("ARTIFACT", "SOURCE_OBSERVATION")),
    }
    if include_source_observation:
        result["current_source_artifact"] = current_source_artifact
    return result


def verify_database(
    path: str | Path,
    *,
    expected_database_id: str | None = None,
    expected_config_digest: str | None = None,
    ingress_path: str | Path | None = None,
    include_source_observation: bool = False,
) -> dict[str, object]:
    connection = _open(path)
    try:
        return _verify_connection(
            connection,
            expected_database_id=expected_database_id,
            expected_config_digest=expected_config_digest,
            ingress_path=ingress_path,
            include_source_observation=include_source_observation,
        )
    finally:
        _close(connection)


def verify_bytes(
    raw: bytes,
    *,
    expected_database_id: str | None = None,
    expected_config_digest: str | None = None,
    ingress_bytes: bytes | None = None,
) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_DATABASE_BYTES:
        raise CoreVerificationError("core:image")
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(":memory:", isolation_level=None, timeout=0.25)
        connection.row_factory = sqlite3.Row
        connection.deserialize(raw)
        connection.execute("PRAGMA query_only=ON")
        _check_pragmas(connection, require_delete_journal=False)
        connection.execute("BEGIN")
        return _verify_connection(
            connection,
            expected_database_id=expected_database_id,
            expected_config_digest=expected_config_digest,
            ingress_bytes=ingress_bytes,
        )
    except CoreVerificationError:
        raise
    except (sqlite3.Error, TypeError, ValueError):
        raise CoreVerificationError("core:image") from None
    finally:
        _close(connection)


def logical_export(result: Mapping[str, object]) -> bytes:
    config_raw = result.get("config_raw")
    if type(config_raw) is not bytes:
        raise CoreVerificationError("core:export")
    config = _parse(config_raw, "core:config")
    return _canonical({
        "schema": f"mirror-core-logical-export-v{SCHEMA_VERSION}",
        "schema_version": SCHEMA_VERSION,
        "database_id": result["database_id"],
        "chain_id": result["chain_id"],
        "config_digest": result["config_digest"],
        "config": config,
        "sequence": result["sequence"],
        "head_root": result["head_root"],
        "ingress_database_id": result["ingress_database_id"],
        "ingress_watermark": result["ingress_watermark"],
        "counts": {
            "artifacts": result["artifact_count"],
            "heads": result["head_count"],
            "sessions": result["session_count"],
            "slots": result["slot_count"],
            "events": result["event_count"],
        },
        "flags": dict(FIXED_FLAGS),
    })


def verify_artifact(raw: bytes, *, config: Mapping[str, object], row: Mapping[str, object]) -> dict[str, object]:
    """Verify one sanitized artifact row without opening a database."""
    _verify_config(config)
    return _verify_artifact_value(row, config)


__all__ = [
    "SCHEMA", "SCHEMA_VERSION", "DOMAIN", "MAX_DATABASE_BYTES",
    "MAX_ARTIFACT_BYTES", "MAX_EVENT_BYTES", "TABLES", "TABLE_COLUMNS",
    "TABLE_SQL", "INDEX_SQL", "EXPLICIT_INDEX", "ARTIFACT_KINDS",
    "SESSION_STATES", "OBSERVATION_RESULTS", "FIXED_FLAGS", "EVENT_KINDS",
    "EVENT_RAW_KEYS", "CoreVerificationError", "verify_database",
    "verify_bytes", "verify_artifact", "logical_export", "_canonical",
    "_digest", "_raw_digest", "_parse", "_event_root", "_stream_root",
    "GENESIS_ROOT",
]


# ---------------------------------------------------------------------------
# Core V5 clean-break grammar
# ---------------------------------------------------------------------------

V5_SCHEMA = "mirror-core-v5"
V5_SCHEMA_VERSION = 5
V5_DOMAIN = "BL/MIRROR/CORE/V5/"
V5_TABLES = (
    "core_meta", "core_profile_artifacts", "core_profile_heads",
    "core_sessions_v5", "core_slots_v5", "core_events_v5",
)
V5_TABLE_COLUMNS = {
    "core_meta": (
        "meta_id", "schema", "schema_version", "database_id", "chain_id",
        "config_digest", "config_raw", "sequence", "head_root",
        "ingress_database_id", "ingress_watermark",
    ),
    "core_profile_artifacts": (
        "artifact_id", "profile_id", "profile_version", "profile_digest",
        "kind", "raw", "current_state", "created_event_sequence",
    ),
    "core_profile_heads": (
        "stream_kind", "profile_id", "profile_version", "head_ref",
        "head_root", "event_sequence",
    ),
    "core_sessions_v5": (
        "session_id", "state", "profile_id", "profile_version",
        "profile_digest", "governance_artifact_id", "observation_artifact_id",
        "head_root", "last_slot",
    ),
    "core_slots_v5": ("session_id", "slot_number", "result_digest", "result_raw"),
    "core_events_v5": (
        "sequence", "event_id", "event_kind", "operation_id", "profile_id",
        "session_id", "event_raw", "receipt_digest",
    ),
}
V5_EXPLICIT_INDEX = "core_profile_artifacts_profile_kind_event_idx"
V5_INDEXES = {V5_EXPLICIT_INDEX}
V5_ARTIFACT_KINDS = ("GOVERNANCE", "WITHDRAWAL", "OBSERVATION")
V5_SESSION_STATES = ("OPEN", "RUNNING", "PAUSED")
V5_EVENT_KINDS = (
    "PROFILE_ARTIFACT", "OBSERVATION_ARTIFACT", "SESSION_OPEN", "SESSION_START",
    "OBSERVATION", "SESSION_PAUSE",
)
V5_FIXED_FLAGS = dict(FIXED_FLAGS)
V5_EVENT_KEYS = {
    "schema", "schema_version", "database_id", "chain_id", "sequence",
    "event_id", "event_kind", "stream_kind", "stream_id", "operation_id",
    "profile_id", "session_id", "request_digest", "prior_state", "next_state",
    "attempt", "observed_at", "material", "material_digest", "payload_digest",
    "payload_length", "before_root", "after_root", "stream_before_root",
    "stream_after_root",
}
V5_MAX_ARTIFACT_BYTES = MAX_ARTIFACT_BYTES
V5_MAX_EVENT_BYTES = MAX_EVENT_BYTES


def _v5_digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update((V5_DOMAIN + label + "\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _v5_raw_digest(label: str, raw: bytes) -> str:
    if type(raw) is not bytes:
        raise CoreVerificationError("core-v5:bytes")
    digest = hashlib.sha3_512()
    digest.update((V5_DOMAIN + label + "\0").encode("ascii"))
    digest.update(raw)
    return digest.hexdigest()


def _v5_parse(raw: bytes, label: str = "core-v5:parse") -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > (V5_MAX_EVENT_BYTES if "event" in label or "receipt" in label else V5_MAX_ARTIFACT_BYTES):
        raise CoreVerificationError(label)
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_reject_duplicate_keys, parse_constant=lambda _value: (_ for _ in ()).throw(CoreVerificationError("core-v5:constant")))
    except CoreVerificationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise CoreVerificationError(label) from None
    if not isinstance(value, dict) or _canonical(value) != raw:
        raise CoreVerificationError(label)
    return value


def _v5_hex(value: object, label: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if type(value) is not str or len(value) != 128 or any(char not in _HEX for char in value):
        raise CoreVerificationError(label)
    return value


def _v5_identifier(value: object, label: str) -> str:
    return _safe_identifier(value, label)


def _v5_table_names(connection: sqlite3.Connection) -> tuple[str, ...]:
    return _table_names(connection)


def _v5_columns(connection: sqlite3.Connection, table: str) -> tuple[str, ...]:
    return _columns(connection, table)


def _v5_config(value: Mapping[str, object], expected_digest: str | None = None) -> dict[str, object]:
    required = {
        "schema", "schema_version", "database_id", "chain_id",
        "ingress_database_id", "ingress_chain_id", "ingress_config_digest",
        "profile_registry_digest", "max_sessions", "max_slots_per_session",
        "cadence_seconds", "flags",
    }
    if not isinstance(value, Mapping) or set(value) != required or value.get("schema") != V5_SCHEMA or value.get("schema_version") != V5_SCHEMA_VERSION or value.get("flags") != V5_FIXED_FLAGS:
        raise CoreVerificationError("core-v5:config")
    for key in ("database_id", "chain_id", "ingress_database_id", "ingress_chain_id"):
        _v5_identifier(value.get(key), "core-v5:config")
    for key in ("ingress_config_digest", "profile_registry_digest"):
        _v5_hex(value.get(key), "core-v5:config")
    if type(value["max_sessions"]) is not int or not 1 <= value["max_sessions"] <= 64 or type(value["max_slots_per_session"]) is not int or not 1 <= value["max_slots_per_session"] <= 256 or type(value["cadence_seconds"]) is not int or value["cadence_seconds"] <= 0:
        raise CoreVerificationError("core-v5:config")
    if expected_digest is not None and _v5_digest("config", value) != expected_digest:
        raise CoreVerificationError("core-v5:config")
    return dict(value)


def _v5_open(path: str | Path) -> sqlite3.Connection:
    database = Path(path)
    connection: sqlite3.Connection | None = None
    try:
        parent = os.lstat(database.parent)
        info = os.lstat(database)
        if not stat.S_ISDIR(parent.st_mode) or _is_reparse(parent) or stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or any(os.path.lexists(os.fspath(database) + suffix) for suffix in _SIDECARS) or info.st_size <= 0 or info.st_size > MAX_DATABASE_BYTES:
            raise CoreVerificationError("core-v5:database")
        connection = sqlite3.connect(database.absolute().as_uri() + "?mode=ro", uri=True, isolation_level=None, timeout=0.25)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        main = next((row[2] for row in connection.execute("PRAGMA database_list").fetchall() if int(row[0]) == 0), None)
        if type(main) is not str or not main or not os.path.samefile(main, database):
            raise CoreVerificationError("core-v5:database")
        _check_pragmas(connection)
        connection.execute("BEGIN")
        return connection
    except CoreVerificationError:
        _close(connection)
        raise
    except (OSError, sqlite3.Error, TypeError, ValueError):
        _close(connection)
        raise CoreVerificationError("core-v5:database") from None


V5_OBSERVATION_SCHEMA = "mirror-core-v5-observation-v1"
V5_OBSERVATION_KEYS = {
    "schema", "schema_version", "kind", "profile_id", "profile_version",
    "profile_digest", "observation", "verification_receipt",
    "observation_digest", "ingress_database_id", "ingress_chain_id",
    "ingress_config_digest", "ingress_artifact_id", "ingress_observation_id",
    "ingress_event_sequence", "ingress_prefix_root", "ingress_after_root",
    "ingress_head_root", "flags",
}


def _v5_verify_observation(
    raw: bytes,
    profile_id: str,
    profile_version: int,
    *,
    ingress_artifact: Mapping[str, object] | None = None,
) -> dict[str, object]:
    value = _v5_parse(raw, "core-v5:observation")
    if set(value) != V5_OBSERVATION_KEYS or value["schema"] != V5_OBSERVATION_SCHEMA or value["schema_version"] != 1 or value["kind"] != "OBSERVATION" or value["profile_id"] != profile_id or value["profile_version"] != profile_version or value["flags"] != V5_FIXED_FLAGS:
        raise CoreVerificationError("core-v5:observation")
    _v5_hex(value["profile_digest"], "core-v5:observation-profile")
    _v5_identifier(value["ingress_database_id"], "core-v5:observation-ingress")
    _v5_identifier(value["ingress_chain_id"], "core-v5:observation-ingress")
    _v5_hex(value["ingress_config_digest"], "core-v5:observation-ingress")
    _v5_hex(value["ingress_artifact_id"], "core-v5:observation-ingress")
    _v5_hex(value["ingress_observation_id"], "core-v5:observation-ingress")
    _v5_hex(value["ingress_prefix_root"], "core-v5:observation-ingress")
    _v5_hex(value["ingress_after_root"], "core-v5:observation-ingress")
    _v5_hex(value["ingress_head_root"], "core-v5:observation-ingress")
    if type(value["ingress_event_sequence"]) is not int or value["ingress_event_sequence"] <= 0 or value["ingress_head_root"] != value["ingress_after_root"]:
        raise CoreVerificationError("core-v5:observation-ingress")
    observation = value["observation"]
    receipt = value["verification_receipt"]
    if not isinstance(observation, dict) or not isinstance(receipt, dict):
        raise CoreVerificationError("core-v5:observation")
    try:
        observation_raw = _canonical(observation)
        receipt_raw = _canonical(receipt)
        checked = ingress.verify_observation_pair(
            observation_raw,
            receipt_raw,
            expected_profile_id=ingress.NC_MEDICAID_PROFILE.source_profile_id,
            expected_profile_version=3,
        )
    except Exception:
        raise CoreVerificationError("core-v5:observation") from None
    expected_digest = _v5_raw_digest("sanitized-observation", observation_raw)
    if value["observation_digest"] != expected_digest or checked["observation"] != observation or checked["verification_receipt"] != receipt:
        raise CoreVerificationError("core-v5:observation-binding")
    if value["ingress_observation_id"] != checked["observation_id"]:
        raise CoreVerificationError("core-v5:observation-ingress")
    if ingress_artifact is not None:
        expected = {
            "artifact_id": value["ingress_artifact_id"],
            "profile_id": ingress.NC_MEDICAID_PROFILE.source_profile_id,
            "profile_version": 3,
            "observation": observation_raw,
            "verification_receipt": receipt_raw,
            "observation_id": checked["observation_id"],
            "event_sequence": value["ingress_event_sequence"],
            "event_prefix_root": value["ingress_prefix_root"],
            "event_after_root": value["ingress_after_root"],
            "head_root": value["ingress_head_root"],
            "database_id": value["ingress_database_id"],
            "chain_id": value["ingress_chain_id"],
            "config_digest": value["ingress_config_digest"],
            "terminal_state": "QUARANTINED",
            "terminal_event_kind": "ADMIT",
        }
        if any(ingress_artifact.get(key) != expected_value for key, expected_value in expected.items()):
            raise CoreVerificationError("core-v5:observation-ingress-binding")
    return value


def _v5_verify_artifact(row: Mapping[str, object], config: Mapping[str, object], profile_registry: Mapping[str, object]) -> dict[str, object]:
    if tuple(row.keys()) != V5_TABLE_COLUMNS["core_profile_artifacts"]:
        raise CoreVerificationError("core-v5:artifact-columns")
    profile_id = _v5_identifier(row["profile_id"], "core-v5:artifact-profile")
    if type(row["profile_version"]) is not int or row["profile_version"] <= 0:
        raise CoreVerificationError("core-v5:artifact-profile")
    _v5_hex(row["profile_digest"], "core-v5:artifact-profile")
    if row["kind"] not in V5_ARTIFACT_KINDS or type(row["raw"]) is not bytes or not row["raw"] or len(row["raw"]) > V5_MAX_ARTIFACT_BYTES:
        raise CoreVerificationError("core-v5:artifact")
    raw = bytes(row["raw"])
    kind = str(row["kind"])
    try:
        from app.mirror import profile_governance_v1_independent as governance
        profile = profile_registry.get(profile_id)
        if profile is None or governance._descriptor(profile)["profile_digest"] != row["profile_digest"]:
            raise CoreVerificationError("core-v5:artifact-profile")
        if kind in {"GOVERNANCE", "WITHDRAWAL"}:
            checked = governance.verify_bytes(raw, profile_registry)
            if checked["profile_id"] != profile_id or checked["profile_version"] != row["profile_version"] or checked["profile_digest"] != row["profile_digest"]:
                raise CoreVerificationError("core-v5:artifact-profile")
            expected_state = checked["current_stage_kind"]
        else:
            _v5_verify_observation(raw, profile_id, int(row["profile_version"]))
            parsed = _v5_parse(raw, "core-v5:observation")
            if parsed["profile_digest"] != row["profile_digest"] or parsed["profile_digest"] != governance._descriptor(profile)["profile_digest"]:
                raise CoreVerificationError("core-v5:artifact-profile")
            expected_state = "OBSERVED"
    except CoreVerificationError:
        raise
    except Exception:
        raise CoreVerificationError("core-v5:artifact") from None
    if row["current_state"] != expected_state or type(row["created_event_sequence"]) is not int or row["created_event_sequence"] <= 0:
        raise CoreVerificationError("core-v5:artifact-state")
    expected_id = _v5_digest("artifact-row-id", {"profile_id": profile_id, "profile_version": row["profile_version"], "profile_digest": row["profile_digest"], "kind": kind, "raw": _v5_raw_digest("artifact-bytes", raw), "current_state": row["current_state"]})
    if row["artifact_id"] != expected_id:
        raise CoreVerificationError("core-v5:artifact-id")
    return {"artifact_id": row["artifact_id"], "profile_id": profile_id, "profile_version": row["profile_version"], "profile_digest": row["profile_digest"], "kind": kind, "raw": raw, "current_state": row["current_state"], "created_event_sequence": row["created_event_sequence"]}


def _v5_governance_stage(value: Mapping[str, object]) -> dict[str, object]:
    if value.get("schema") == "mirror-profile-governance-withdrawal-v1":
        return {
            "stage_kind": "WITHDRAWN_OBSERVATION_ONLY",
            "stage_id": value.get("withdrawal_id"),
            "stage_root": value.get("withdrawal_root"),
        }
    stages = value.get("stages")
    if not isinstance(stages, list) or not stages or not isinstance(stages[-1], dict):
        raise CoreVerificationError("core-v5:governance-stage")
    return dict(stages[-1])


def _v5_authority_reason(
    artifacts: Mapping[str, Mapping[str, object]],
    stream_refs: Mapping[tuple[str, str], str],
    session: Mapping[str, object],
    observed_at: int,
) -> tuple[str | None, str | None, str | None]:
    profile_key = str(session["profile_id"]) + ":" + str(session["profile_version"])
    governance_ref = stream_refs.get(("GOVERNANCE", profile_key))
    observation_ref = stream_refs.get(("OBSERVATION", profile_key))
    if governance_ref is None or observation_ref is None:
        return "AUTHORITY_SUPERSEDED", governance_ref, observation_ref
    if observation_ref != session["observation_artifact_id"]:
        return "AUTHORITY_SUPERSEDED", governance_ref, observation_ref
    governance_row = artifacts.get(governance_ref)
    if governance_row is None:
        return "AUTHORITY_MISSING", governance_ref, observation_ref
    governance_value = _v5_parse(bytes(governance_row["raw"]), "core-v5:governance")
    if governance_value.get("schema") == "mirror-profile-governance-withdrawal-v1":
        return "AUTHORITY_WITHDRAWN", governance_ref, observation_ref
    if governance_ref != session["governance_artifact_id"]:
        return "AUTHORITY_SUPERSEDED", governance_ref, observation_ref
    stage = _v5_governance_stage(governance_value)
    if stage.get("stage_kind") != "APPROVED_OBSERVATION_ONLY":
        return "AUTHORITY_NOT_APPROVED", governance_ref, observation_ref
    if observed_at < int(stage["effective_start"]):
        return "AUTHORITY_NOT_EFFECTIVE", governance_ref, observation_ref
    if observed_at >= int(stage["effective_end"]):
        return "AUTHORITY_EXPIRED", governance_ref, observation_ref
    return None, governance_ref, observation_ref


def _v5_event_root(body: Mapping[str, object]) -> str:
    return _v5_digest("event-root", {key: body[key] for key in ("schema", "schema_version", "database_id", "chain_id", "sequence", "event_id", "event_kind", "stream_kind", "stream_id", "operation_id", "profile_id", "session_id", "request_digest", "prior_state", "next_state", "attempt", "observed_at", "material_digest", "payload_digest", "payload_length", "before_root", "stream_before_root")})


def _v5_stream_root(body: Mapping[str, object]) -> str:
    return _v5_digest("stream-root", {key: body[key] for key in ("schema", "schema_version", "database_id", "chain_id", "sequence", "event_id", "event_kind", "stream_kind", "stream_id", "operation_id", "profile_id", "session_id", "prior_state", "next_state", "attempt", "observed_at", "material_digest", "payload_digest", "payload_length", "stream_before_root")})


def _v5_verify_ingress_bindings(
    artifacts: Mapping[str, Mapping[str, object]],
    config: Mapping[str, object],
    *,
    ingress_path: str | Path | None = None,
    ingress_bytes: bytes | None = None,
) -> bool:
    observation_artifacts = [
        item for item in artifacts.values() if item.get("kind") == "OBSERVATION"
    ]
    if not observation_artifacts:
        return ingress_path is not None or ingress_bytes is not None
    if (ingress_path is None) == (ingress_bytes is None):
        raise CoreVerificationError("core-v5:ingress-required")
    artifact_ids: tuple[str, ...] = tuple(sorted({
        str(_v5_parse(bytes(item["raw"]), "core-v5:observation") ["ingress_artifact_id"])
        for item in observation_artifacts
    }))
    try:
        if ingress_path is not None:
            result = ingress.verify_database(
                ingress_path,
                expected_database_id=str(config["ingress_database_id"]),
                expected_config_digest=str(config["ingress_config_digest"]),
                include_observation=True,
                artifact_ids=artifact_ids,
            )
        else:
            result = ingress.verify_bytes(
                ingress_bytes,
                expected_database_id=str(config["ingress_database_id"]),
                expected_config_digest=str(config["ingress_config_digest"]),
                include_observation=True,
                artifact_ids=artifact_ids,
            )
    except Exception:
        raise CoreVerificationError("core-v5:ingress") from None
    if result.get("chain_id") != config["ingress_chain_id"] or result.get("config_digest") != config["ingress_config_digest"]:
        raise CoreVerificationError("core-v5:ingress")
    selected = result.get("selected_artifacts")
    if not isinstance(selected, dict) or set(selected) != set(artifact_ids):
        raise CoreVerificationError("core-v5:ingress")
    for item in observation_artifacts:
        value = _v5_parse(bytes(item["raw"]), "core-v5:observation")
        selected_artifact = selected.get(value.get("ingress_artifact_id"))
        if not isinstance(selected_artifact, Mapping):
            raise CoreVerificationError("core-v5:ingress")
        selected_artifact = dict(selected_artifact)
        selected_artifact.update({
            # The stored binding is to this artifact's terminal event, not
            # to a later Ingress database head.  This keeps independent
            # verification valid while Core catches up after a new admit.
            "head_root": selected_artifact.get("event_after_root"),
            "database_id": result["database_id"],
            "chain_id": result["chain_id"],
            "config_digest": result["config_digest"],
        })
        _v5_verify_observation(
            bytes(item["raw"]),
            str(item["profile_id"]),
            int(item["profile_version"]),
            ingress_artifact=selected_artifact,
        )
    return True


def _v5_verify_connection(
    connection: sqlite3.Connection,
    *,
    expected_database_id: str | None = None,
    expected_config_digest: str | None = None,
    profile_registry: Mapping[str, object] | None = None,
    ingress_path: str | Path | None = None,
    ingress_bytes: bytes | None = None,
) -> dict[str, object]:
    registry = profile_registry or {}
    if not isinstance(registry, Mapping) or not registry:
        raise CoreVerificationError("core-v5:registry")
    if _v5_table_names(connection) != tuple(sorted(V5_TABLES)):
        raise CoreVerificationError("core-v5:legacy-schema")
    for table, columns in V5_TABLE_COLUMNS.items():
        if _v5_columns(connection, table) != columns:
            raise CoreVerificationError("core-v5:legacy-schema")
    indexes = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_autoindex_%'").fetchall()}
    if indexes != V5_INDEXES or connection.execute("SELECT 1 FROM sqlite_master WHERE type='trigger' LIMIT 1").fetchone() is not None:
        raise CoreVerificationError("core-v5:legacy-schema")
    meta = connection.execute("SELECT * FROM core_meta WHERE meta_id=1").fetchone()
    if meta is None or meta["schema"] != V5_SCHEMA or meta["schema_version"] != V5_SCHEMA_VERSION:
        raise CoreVerificationError("core-v5:meta")
    config_raw = bytes(meta["config_raw"])
    config = _v5_config(_v5_parse(config_raw, "core-v5:config"), expected_config_digest)
    try:
        from app.mirror import profile_governance_v1_independent as governance
        if governance.profile_registry_digest(registry) != config["profile_registry_digest"]:
            raise CoreVerificationError("core-v5:registry")
    except CoreVerificationError:
        raise
    except Exception:
        raise CoreVerificationError("core-v5:registry") from None
    if (
        meta["database_id"] != config["database_id"]
        or meta["chain_id"] != config["chain_id"]
        or meta["config_digest"] != _v5_digest("config", config)
        or (expected_database_id is not None and meta["database_id"] != expected_database_id)
        or (expected_config_digest is not None and meta["config_digest"] != expected_config_digest)
        or meta["ingress_database_id"] != config["ingress_database_id"]
        or type(meta["ingress_watermark"]) is not int
        or meta["ingress_watermark"] < 0
        or type(meta["sequence"]) is not int
        or meta["sequence"] < 0
    ):
        raise CoreVerificationError("core-v5:meta")

    rows = connection.execute("SELECT * FROM core_profile_artifacts ORDER BY created_event_sequence,artifact_id").fetchall()
    artifacts: dict[str, dict[str, object]] = {}
    for row in rows:
        item = _v5_verify_artifact(row, config, registry)
        if item["artifact_id"] in artifacts:
            raise CoreVerificationError("core-v5:artifact-duplicate")
        artifacts[str(item["artifact_id"])] = item

    expected_artifacts: dict[str, dict[str, object]] = {}
    expected_sessions: dict[str, dict[str, object]] = {}
    expected_slots: dict[tuple[str, int], dict[str, object]] = {}
    session_last_observed: dict[str, int | None] = {}
    stream_roots: dict[tuple[str, str], str] = {}
    stream_refs: dict[tuple[str, str], str] = {}
    stream_sequences: dict[tuple[str, str], int] = {}
    previous_global = GENESIS_ROOT
    previous_observed = -1
    events = connection.execute("SELECT * FROM core_events_v5 ORDER BY sequence").fetchall()

    for expected_sequence, row in enumerate(events, 1):
        if tuple(row.keys()) != V5_TABLE_COLUMNS["core_events_v5"]:
            raise CoreVerificationError("core-v5:event-columns")
        raw = row["event_raw"]
        if type(raw) is not bytes or not raw or len(raw) > V5_MAX_EVENT_BYTES:
            raise CoreVerificationError("core-v5:event-bytes")
        value = _v5_parse(raw, "core-v5:event-raw")
        if (
            set(value) != V5_EVENT_KEYS
            or value["schema"] != V5_SCHEMA
            or value["schema_version"] != V5_SCHEMA_VERSION
            or value["sequence"] != expected_sequence
            or row["sequence"] != expected_sequence
            or value["event_id"] != row["event_id"]
            or value["event_kind"] != row["event_kind"]
            or value["operation_id"] != row["operation_id"]
            or value["profile_id"] != row["profile_id"]
            or value["session_id"] != row["session_id"]
        ):
            raise CoreVerificationError("core-v5:event-binding")
        _v5_identifier(value["database_id"], "core-v5:event-database")
        _v5_identifier(value["chain_id"], "core-v5:event-chain")
        _v5_hex(value["event_id"], "core-v5:event-id")
        _v5_hex(value["operation_id"], "core-v5:event-operation")
        _v5_hex(value["request_digest"], "core-v5:event-request")
        _v5_hex(value["payload_digest"], "core-v5:event-payload")
        _v5_hex(value["before_root"], "core-v5:event-before")
        _v5_hex(value["after_root"], "core-v5:event-after")
        _v5_hex(value["stream_before_root"], "core-v5:event-stream-before")
        _v5_hex(value["stream_after_root"], "core-v5:event-stream-after")
        if (
            value["database_id"] != config["database_id"]
            or value["chain_id"] != config["chain_id"]
            or value["before_root"] != previous_global
            or value["event_kind"] not in V5_EVENT_KINDS
            or type(value["attempt"]) is not int
            or value["attempt"] != 0
            or type(value["observed_at"]) is not int
            or value["observed_at"] < 0
            or value["observed_at"] < previous_observed
            or type(value["payload_length"]) is not int
            or value["payload_length"] < 0
            or not isinstance(value["material"], dict)
        ):
            raise CoreVerificationError("core-v5:event-semantics")
        stream_kind = value["stream_kind"]
        stream_id = value["stream_id"]
        if type(stream_kind) is not str or stream_kind not in {"GOVERNANCE", "OBSERVATION", "SESSION"} or type(stream_id) is not str or not stream_id:
            raise CoreVerificationError("core-v5:event-stream")
        stream_key = (stream_kind, stream_id)
        if value["stream_before_root"] != stream_roots.get(stream_key, GENESIS_ROOT):
            raise CoreVerificationError("core-v5:stream-order")
        if value["material_digest"] != _v5_digest("material", value["material"]):
            raise CoreVerificationError("core-v5:event-material")
        expected_id = _v5_digest("event-id", {key: value[key] for key in V5_EVENT_KEYS if key not in {"event_id", "after_root", "stream_after_root"}})
        if value["event_id"] != expected_id or value["after_root"] != _v5_event_root(value) or value["stream_after_root"] != _v5_stream_root(value) or row["receipt_digest"] != _v5_raw_digest("receipt", raw):
            raise CoreVerificationError("core-v5:event-integrity")

        material = value["material"]
        if value["event_kind"] == "PROFILE_ARTIFACT":
            required = {"artifact_id", "kind", "raw_digest", "raw_length", "profile_id", "profile_version", "profile_digest", "current_state", "prior_head_ref", "prior_head_root"}
            if set(material) != required or stream_kind != "GOVERNANCE" or value["session_id"] != "" or stream_id != str(value["profile_id"]) + ":" + str(material["profile_version"]):
                raise CoreVerificationError("core-v5:event-artifact")
            artifact_id = str(material["artifact_id"])
            artifact = artifacts.get(artifact_id)
            if artifact is None or artifact_id in expected_artifacts or artifact["kind"] not in {"GOVERNANCE", "WITHDRAWAL"}:
                raise CoreVerificationError("core-v5:event-artifact")
            if (
                artifact["created_event_sequence"] != expected_sequence
                or artifact["kind"] != material["kind"]
                or artifact["profile_id"] != material["profile_id"]
                or artifact["profile_version"] != material["profile_version"]
                or artifact["profile_digest"] != material["profile_digest"]
                or artifact["current_state"] != material["current_state"]
                or material["raw_length"] != len(artifact["raw"])
                or material["raw_digest"] != _v5_raw_digest("artifact-bytes", artifact["raw"])
                or value["payload_digest"] != artifact_id
                or value["payload_length"] != len(artifact["raw"])
                or value["next_state"] != artifact["current_state"]
            ):
                raise CoreVerificationError("core-v5:event-artifact")
            prior_ref = stream_refs.get(stream_key)
            prior_root = stream_roots.get(stream_key, GENESIS_ROOT)
            if material["prior_head_ref"] != prior_ref or material["prior_head_root"] != (None if prior_ref is None else prior_root) or value["prior_state"] != ("NONE" if prior_ref is None else prior_ref):
                raise CoreVerificationError("core-v5:event-artifact-head")
            parsed = _v5_parse(bytes(artifact["raw"]), "core-v5:governance-artifact")
            stage = _v5_governance_stage(parsed)
            if material["kind"] == "GOVERNANCE":
                if stage["stage_kind"] not in {"CANDIDATE", "TESTED", "APPROVED_OBSERVATION_ONLY"}:
                    raise CoreVerificationError("core-v5:event-artifact-stage")
                if prior_ref is None:
                    if stage["stage_kind"] != "CANDIDATE":
                        raise CoreVerificationError("core-v5:event-artifact-stage")
                else:
                    prior = expected_artifacts.get(prior_ref)
                    if prior is None or prior["kind"] != "GOVERNANCE":
                        raise CoreVerificationError("core-v5:event-artifact-predecessor")
                    prior_value = _v5_parse(bytes(prior["raw"]), "core-v5:governance-predecessor")
                    prior_stage = _v5_governance_stage(prior_value)
                    if stage["prior_stage_id"] != prior_stage["stage_id"] or stage["prior_stage_root"] != prior_stage["stage_root"]:
                        raise CoreVerificationError("core-v5:event-artifact-predecessor")
                    if (stage["stage_kind"], prior_stage["stage_kind"]) not in {("TESTED", "CANDIDATE"), ("APPROVED_OBSERVATION_ONLY", "TESTED")}:
                        raise CoreVerificationError("core-v5:event-artifact-stage")
            else:
                if prior_ref is None:
                    raise CoreVerificationError("core-v5:event-withdrawal")
                prior = expected_artifacts.get(prior_ref)
                if prior is None or prior["kind"] != "GOVERNANCE" or _v5_governance_stage(_v5_parse(bytes(prior["raw"]), "core-v5:governance-predecessor"))["stage_kind"] != "APPROVED_OBSERVATION_ONLY":
                    raise CoreVerificationError("core-v5:event-withdrawal")
                from app.mirror import profile_governance_v1_independent as governance
                prior_value = _v5_parse(bytes(prior["raw"]), "core-v5:governance-predecessor")
                if parsed.get("approved_artifact_id") != prior_value.get("artifact_id") or parsed.get("approved_artifact_sha3_512") != governance._bytes_digest("approved-artifact", bytes(prior["raw"])):
                    raise CoreVerificationError("core-v5:event-withdrawal")
            expected_artifacts[artifact_id] = artifact
            stream_refs[stream_key] = artifact_id
        elif value["event_kind"] == "OBSERVATION_ARTIFACT":
            required = {"artifact_id", "kind", "raw_digest", "raw_length", "profile_id", "profile_version", "profile_digest", "observation_time", "prior_head_ref", "prior_head_root"}
            if set(material) != required or material["kind"] != "OBSERVATION" or stream_kind != "OBSERVATION" or value["session_id"] != "" or stream_id != str(value["profile_id"]) + ":" + str(material["profile_version"]):
                raise CoreVerificationError("core-v5:event-observation-artifact")
            artifact_id = str(material["artifact_id"])
            artifact = artifacts.get(artifact_id)
            if artifact is None or artifact_id in expected_artifacts or artifact["kind"] != "OBSERVATION" or artifact["created_event_sequence"] != expected_sequence or artifact["profile_id"] != material["profile_id"] or artifact["profile_version"] != material["profile_version"] or artifact["profile_digest"] != material["profile_digest"] or artifact["current_state"] != "OBSERVED" or material["raw_length"] != len(artifact["raw"]) or material["raw_digest"] != _v5_raw_digest("artifact-bytes", artifact["raw"]) or value["payload_digest"] != artifact_id or value["payload_length"] != len(artifact["raw"]):
                raise CoreVerificationError("core-v5:event-observation-artifact")
            observation = _v5_parse(bytes(artifact["raw"]), "core-v5:observation-artifact")
            if observation["observation"]["observation_time"] != material["observation_time"] or value["observed_at"] < observation["observation"]["observation_time"] or observation["ingress_database_id"] != config["ingress_database_id"] or observation["ingress_chain_id"] != config["ingress_chain_id"] or observation["ingress_config_digest"] != config["ingress_config_digest"]:
                raise CoreVerificationError("core-v5:event-observation-artifact")
            prior_ref = stream_refs.get(stream_key)
            prior_root = stream_roots.get(stream_key, GENESIS_ROOT)
            if material["prior_head_ref"] != prior_ref or material["prior_head_root"] != (None if prior_ref is None else prior_root) or value["prior_state"] != ("NONE" if prior_ref is None else prior_ref):
                raise CoreVerificationError("core-v5:event-observation-head")
            if prior_ref is not None:
                prior_observation = _v5_parse(bytes(expected_artifacts[prior_ref]["raw"]), "core-v5:observation-predecessor")
                if observation["observation"]["observation_time"] <= prior_observation["observation"]["observation_time"]:
                    raise CoreVerificationError("core-v5:event-observation-chronology")
            expected_artifacts[artifact_id] = artifact
            stream_refs[stream_key] = artifact_id
        elif value["event_kind"] == "SESSION_OPEN":
            required = {"session_id", "state", "governance_artifact_id", "observation_artifact_id", "last_slot"}
            session_id = str(value["session_id"])
            if set(material) != required or stream_kind != "SESSION" or stream_id != session_id or value["profile_id"] not in registry or value["prior_state"] != "NONE" or value["next_state"] != "OPEN" or material["session_id"] != session_id or material["state"] != "OPEN" or material["last_slot"] != -1:
                raise CoreVerificationError("core-v5:session-open")
            governance_id = str(material["governance_artifact_id"]); observation_id = str(material["observation_artifact_id"])
            governance_row = expected_artifacts.get(governance_id); observation_row = expected_artifacts.get(observation_id)
            if governance_row is None or observation_row is None or governance_row["kind"] != "GOVERNANCE" or observation_row["kind"] != "OBSERVATION" or governance_row["profile_id"] != value["profile_id"] or observation_row["profile_id"] != value["profile_id"] or governance_row["profile_version"] != observation_row["profile_version"] or governance_row["current_state"] != "APPROVED_OBSERVATION_ONLY":
                raise CoreVerificationError("core-v5:session-open")
            profile_version = int(governance_row["profile_version"])
            if value["operation_id"] != _v5_digest("session-operation", {"session_id": session_id, "action": "OPEN"}) or value["request_digest"] != _v5_digest("session-request", {"session_id": session_id, "action": "OPEN"}) or value["payload_digest"] != session_id or value["payload_length"] != 0:
                raise CoreVerificationError("core-v5:session-open")
            if session_id != _v5_digest("session-id", {"profile_id": value["profile_id"], "profile_version": profile_version, "profile_digest": governance_row["profile_digest"], "governance_artifact_id": governance_id, "observation_artifact_id": observation_id, "config_digest": config["profile_registry_digest"]}):
                raise CoreVerificationError("core-v5:session-open")
            stage = _v5_governance_stage(_v5_parse(bytes(governance_row["raw"]), "core-v5:governance"))
            session = {"session_id": session_id, "state": "OPEN", "profile_id": value["profile_id"], "profile_version": profile_version, "profile_digest": governance_row["profile_digest"], "governance_artifact_id": governance_id, "observation_artifact_id": observation_id, "head_root": str(value["stream_after_root"]), "last_slot": -1}
            reason, _gov, _obs = _v5_authority_reason(artifacts, stream_refs, session, int(value["observed_at"]))
            if reason is not None or int(value["observed_at"]) < int(stage["stage_time"]):
                raise CoreVerificationError("core-v5:session-open-authority")
            if len(expected_sessions) >= int(config["max_sessions"]):
                raise CoreVerificationError("core-v5:session-capacity")
            expected_sessions[session_id] = session
            session_last_observed[session_id] = None
        elif value["event_kind"] == "SESSION_START":
            session_id = str(value["session_id"])
            if stream_kind != "SESSION" or stream_id != session_id or value["prior_state"] != "OPEN" or value["next_state"] != "RUNNING" or material != {"state": "RUNNING"} or value["operation_id"] != _v5_digest("session-operation", {"session_id": session_id, "action": "START"}) or value["request_digest"] != _v5_digest("session-request", {"session_id": session_id, "action": "START"}) or value["payload_digest"] != session_id or value["payload_length"] != 0:
                raise CoreVerificationError("core-v5:session-start")
            session = expected_sessions.get(session_id)
            if session is None or session["state"] != "OPEN" or session["profile_id"] != value["profile_id"]:
                raise CoreVerificationError("core-v5:session-start")
            reason, _gov, _obs = _v5_authority_reason(artifacts, stream_refs, session, int(value["observed_at"]))
            if reason is not None:
                raise CoreVerificationError("core-v5:session-start-authority")
            session["state"] = "RUNNING"; session["head_root"] = str(value["stream_after_root"])
        elif value["event_kind"] == "OBSERVATION":
            session_id = str(value["session_id"])
            if stream_kind != "SESSION" or stream_id != session_id or not isinstance(material, dict) or set(material) != {"observation"}:
                raise CoreVerificationError("core-v5:session-observation")
            observation = material["observation"]
            if not isinstance(observation, dict) or set(observation) != {"schema", "schema_version", "session_id", "slot_number", "result", "counts", "flags", "result_digest"} or observation["schema"] != "mirror-core-v5-observation-result-v1" or observation["schema_version"] != 1 or observation["session_id"] != session_id or observation["result"] not in OBSERVATION_RESULTS or observation["flags"] != V5_FIXED_FLAGS or observation["result_digest"] != _v5_digest("observation-result", {key: observation[key] for key in observation if key != "result_digest"}):
                raise CoreVerificationError("core-v5:session-observation")
            counts = observation["counts"]; slot_number = observation["slot_number"]
            if not isinstance(counts, dict) or set(counts) != {"changed", "observed"} or type(slot_number) is not int or slot_number < 0 or slot_number >= int(config["max_slots_per_session"]) or any(type(item) is not int or item < 0 or item > 64 for item in counts.values()) or value["prior_state"] != "RUNNING" or value["next_state"] != "RUNNING" or value["operation_id"] != _v5_digest("observation-operation", {"session_id": session_id, "slot_number": slot_number}) or value["request_digest"] != _v5_digest("observation-request", {"session_id": session_id, "slot_number": slot_number}) or value["payload_digest"] != observation["result_digest"] or value["payload_length"] != len(_canonical(observation)):
                raise CoreVerificationError("core-v5:session-observation")
            session = expected_sessions.get(session_id)
            if session is None or session["state"] != "RUNNING" or session["profile_id"] != value["profile_id"] or slot_number != int(session["last_slot"]) + 1 or (session_id, slot_number) in expected_slots:
                raise CoreVerificationError("core-v5:session-observation")
            reason, _gov, _obs = _v5_authority_reason(artifacts, stream_refs, session, int(value["observed_at"]))
            if reason is not None:
                raise CoreVerificationError("core-v5:session-observation-authority")
            prior_observed = session_last_observed[session_id]
            if prior_observed is not None and int(value["observed_at"]) < prior_observed + int(config["cadence_seconds"]):
                raise CoreVerificationError("core-v5:session-observation-cadence")
            result_raw = _canonical(observation)
            expected_slots[(session_id, slot_number)] = {"session_id": session_id, "slot_number": slot_number, "result_digest": observation["result_digest"], "result_raw": result_raw}
            session["last_slot"] = slot_number; session["head_root"] = str(value["stream_after_root"]); session_last_observed[session_id] = int(value["observed_at"])
        else:
            required = {"state", "reason", "trigger", "current_governance_artifact_id", "current_observation_artifact_id", "slot_number", "observation_digest"}
            session_id = str(value["session_id"])
            if set(material) != required or stream_kind != "SESSION" or stream_id != session_id or value["next_state"] != "PAUSED" or material["state"] != "PAUSED" or value["payload_digest"] != _v5_digest("pause-reason", {"reason": material["reason"]}) or value["payload_length"] != 0:
                raise CoreVerificationError("core-v5:session-pause")
            session = expected_sessions.get(session_id)
            if session is None or session["state"] not in {"OPEN", "RUNNING"} or value["prior_state"] != session["state"] or session["profile_id"] != value["profile_id"]:
                raise CoreVerificationError("core-v5:session-pause")
            trigger = material["trigger"]; slot_number = material["slot_number"]; observation_digest = material["observation_digest"]
            if trigger not in {"START", "OBSERVATION", "RECONCILE"} or (trigger == "OBSERVATION" and (type(slot_number) is not int or slot_number < 0 or slot_number >= int(config["max_slots_per_session"]) or slot_number != int(session["last_slot"]) + 1 or _v5_hex(observation_digest, "core-v5:session-pause-observation") is None)) or (trigger != "OBSERVATION" and (slot_number is not None or observation_digest is not None)):
                raise CoreVerificationError("core-v5:session-pause")
            profile_key = str(session["profile_id"]) + ":" + str(session["profile_version"])
            current_gov = stream_refs.get(("GOVERNANCE", profile_key)); current_obs = stream_refs.get(("OBSERVATION", profile_key))
            if material["current_governance_artifact_id"] != current_gov or material["current_observation_artifact_id"] != current_obs:
                raise CoreVerificationError("core-v5:session-pause")
            expected_reason, _gov, _obs = _v5_authority_reason(artifacts, stream_refs, session, int(value["observed_at"]))
            if expected_reason is None or material["reason"] != expected_reason:
                raise CoreVerificationError("core-v5:session-pause-authority")
            if trigger == "START":
                expected_operation = _v5_digest("session-operation", {"session_id": session_id, "action": "START"})
                expected_request = _v5_digest("session-request", {"session_id": session_id, "action": "START"})
            elif trigger == "OBSERVATION":
                expected_operation = _v5_digest("observation-operation", {"session_id": session_id, "slot_number": slot_number})
                expected_request = _v5_digest("observation-request", {"session_id": session_id, "slot_number": slot_number})
            else:
                expected_operation = _v5_digest("pause-operation", {"session_id": session_id, "trigger": "RECONCILE"})
                expected_request = _v5_digest("pause-request", {"session_id": session_id, "trigger": "RECONCILE"})
            if value["operation_id"] != expected_operation or value["request_digest"] != expected_request:
                raise CoreVerificationError("core-v5:session-pause")
            session["state"] = "PAUSED"; session["head_root"] = str(value["stream_after_root"])

        previous_global = str(value["after_root"])
        previous_observed = int(value["observed_at"])
        stream_roots[stream_key] = str(value["stream_after_root"])
        stream_sequences[stream_key] = expected_sequence

    if int(meta["sequence"]) != len(events) or meta["head_root"] != (previous_global if events else GENESIS_ROOT):
        raise CoreVerificationError("core-v5:chain")
    expected_ingress_watermark = max(
        (
            int(_v5_parse(bytes(item["raw"]), "core-v5:observation")["ingress_event_sequence"])
            for item in artifacts.values() if item.get("kind") == "OBSERVATION"
        ),
        default=0,
    )
    if int(meta["ingress_watermark"]) != expected_ingress_watermark:
        raise CoreVerificationError("core-v5:ingress-watermark")
    if set(expected_artifacts) != set(artifacts):
        raise CoreVerificationError("core-v5:artifact-reconstruction")
    for identifier, artifact in artifacts.items():
        if identifier not in expected_artifacts or any(artifact[key] != expected_artifacts[identifier][key] for key in V5_TABLE_COLUMNS["core_profile_artifacts"]):
            raise CoreVerificationError("core-v5:artifact-reconstruction")

    sessions = connection.execute("SELECT * FROM core_sessions_v5 ORDER BY session_id").fetchall()
    if len(sessions) != len(expected_sessions):
        raise CoreVerificationError("core-v5:session-reconstruction")
    for row in sessions:
        expected = expected_sessions.get(str(row["session_id"]))
        if expected is None or any(row[key] != expected[key] for key in V5_TABLE_COLUMNS["core_sessions_v5"]):
            raise CoreVerificationError("core-v5:session-reconstruction")

    slots = connection.execute("SELECT * FROM core_slots_v5 ORDER BY session_id,slot_number").fetchall()
    if len(slots) != len(expected_slots):
        raise CoreVerificationError("core-v5:slot-reconstruction")
    for row in slots:
        expected = expected_slots.get((str(row["session_id"]), int(row["slot_number"])))
        if expected is None or any(row[column] != expected[column] for column in V5_TABLE_COLUMNS["core_slots_v5"]):
            raise CoreVerificationError("core-v5:slot-reconstruction")

    heads = connection.execute("SELECT * FROM core_profile_heads ORDER BY stream_kind,profile_id,profile_version").fetchall()
    expected_head_keys = {key for key in stream_refs if key[0] in {"GOVERNANCE", "OBSERVATION"}}
    if len(heads) != len(expected_head_keys):
        raise CoreVerificationError("core-v5:heads")
    seen_heads: set[tuple[str, str, int]] = set()
    for row in heads:
        if tuple(row.keys()) != V5_TABLE_COLUMNS["core_profile_heads"] or row["stream_kind"] not in {"GOVERNANCE", "OBSERVATION"}:
            raise CoreVerificationError("core-v5:head-columns")
        key = (str(row["stream_kind"]), str(row["profile_id"]) + ":" + str(row["profile_version"]))
        triple = (str(row["stream_kind"]), str(row["profile_id"]), int(row["profile_version"]))
        artifact = artifacts.get(str(row["head_ref"]))
        if triple in seen_heads or key not in expected_head_keys or row["head_ref"] != stream_refs[key] or row["head_root"] != stream_roots[key] or row["event_sequence"] != stream_sequences[key] or artifact is None or artifact["profile_id"] != row["profile_id"] or artifact["profile_version"] != row["profile_version"] or (row["stream_kind"] == "GOVERNANCE" and artifact["kind"] not in {"GOVERNANCE", "WITHDRAWAL"}) or (row["stream_kind"] == "OBSERVATION" and artifact["kind"] != "OBSERVATION"):
            raise CoreVerificationError("core-v5:head-binding")
        seen_heads.add(triple)

    profiles = tuple(sorted({(str(row["profile_id"]), int(row["profile_version"]), str(artifacts[str(row["head_ref"])] ["profile_digest"])) for row in heads}))
    observation_bindings: list[dict[str, object]] = []
    latest_observed_at = 0
    for item in artifacts.values():
        if item["kind"] != "OBSERVATION":
            continue
        observation = _v5_parse(bytes(item["raw"]), "core-v5:observation-result")
        observed_at = observation["observation"]["observation_time"]
        if type(observed_at) is not int or observed_at < 0:
            raise CoreVerificationError("core-v5:observation-time")
        latest_observed_at = max(latest_observed_at, observed_at)
        observation_bindings.append({
            "profile_id": item["profile_id"],
            "profile_version": item["profile_version"],
            "artifact_id": item["artifact_id"],
            "ingress_artifact_id": observation["ingress_artifact_id"],
            "ingress_observation_id": observation["ingress_observation_id"],
            "ingress_event_sequence": observation["ingress_event_sequence"],
            "ingress_prefix_root": observation["ingress_prefix_root"],
            "ingress_after_root": observation["ingress_after_root"],
            "ingress_head_root": observation["ingress_head_root"],
            "observation_time": observed_at,
        })
    observation_bindings.sort(key=lambda value: (
        str(value["profile_id"]),
        int(value["profile_version"]),
        str(value["artifact_id"]),
    ))
    ingress_bound = _v5_verify_ingress_bindings(
        artifacts,
        config,
        ingress_path=ingress_path,
        ingress_bytes=ingress_bytes,
    )
    return {
        "structural_valid": True, "schema": V5_SCHEMA, "schema_version": V5_SCHEMA_VERSION,
        "database_id": str(meta["database_id"]), "chain_id": str(meta["chain_id"]),
        "config_digest": str(meta["config_digest"]), "config_raw": config_raw,
        "sequence": int(meta["sequence"]), "head_root": str(meta["head_root"]),
        "ingress_database_id": str(meta["ingress_database_id"]), "ingress_watermark": int(meta["ingress_watermark"]),
        "profile_head_count": len(heads), "artifact_count": len(artifacts),
        "session_count": len(sessions), "slot_count": len(slots), "event_count": len(events),
        "profiles": profiles, "ingress_bound": ingress_bound,
        "observation_bindings": tuple(
            tuple(item[key] for key in (
                "profile_id", "profile_version", "artifact_id", "ingress_artifact_id",
                "ingress_observation_id", "ingress_event_sequence", "ingress_prefix_root",
                "ingress_after_root", "ingress_head_root", "observation_time",
            ))
            for item in observation_bindings
        ),
        "latest_observed_at": latest_observed_at,
        "flags": dict(V5_FIXED_FLAGS),
    }


def verify_database_v5(path: str | Path, *, expected_database_id: str | None = None, expected_config_digest: str | None = None, profile_registry: Mapping[str, object] | None = None, ingress_path: str | Path | None = None) -> dict[str, object]:
    connection = _v5_open(path)
    try:
        try:
            return _v5_verify_connection(connection, expected_database_id=expected_database_id, expected_config_digest=expected_config_digest, profile_registry=profile_registry, ingress_path=ingress_path)
        except CoreVerificationError:
            raise
        except (KeyError, IndexError, TypeError, ValueError, sqlite3.Error):
            raise CoreVerificationError("core-v5:database") from None
    finally:
        _close(connection)


def verify_bytes_v5(raw: bytes, *, expected_database_id: str | None = None, expected_config_digest: str | None = None, profile_registry: Mapping[str, object] | None = None, ingress_bytes: bytes | None = None) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_DATABASE_BYTES:
        raise CoreVerificationError("core-v5:image")
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(":memory:", isolation_level=None, timeout=0.25)
        connection.row_factory = sqlite3.Row
        connection.deserialize(raw)
        connection.execute("PRAGMA query_only=ON")
        _check_pragmas(connection, require_delete_journal=False)
        connection.execute("BEGIN")
        return _v5_verify_connection(connection, expected_database_id=expected_database_id, expected_config_digest=expected_config_digest, profile_registry=profile_registry, ingress_bytes=ingress_bytes)
    except CoreVerificationError:
        raise
    except (sqlite3.Error, TypeError, ValueError):
        raise CoreVerificationError("core-v5:image") from None
    finally:
        _close(connection)


def logical_export_v5(result: Mapping[str, object]) -> bytes:
    config_raw = result.get("config_raw")
    if type(config_raw) is not bytes:
        raise CoreVerificationError("core-v5:export")
    config = _v5_parse(config_raw, "core-v5:config")
    return _canonical({
        "schema": "mirror-core-logical-export-v5", "schema_version": V5_SCHEMA_VERSION,
        "database_id": result["database_id"], "chain_id": result["chain_id"],
        "config_digest": result["config_digest"], "config": config,
        "sequence": result["sequence"], "head_root": result["head_root"],
        "ingress_database_id": result["ingress_database_id"],
        "ingress_watermark": result["ingress_watermark"],
        "counts": {"artifacts": result["artifact_count"], "heads": result["profile_head_count"], "sessions": result["session_count"], "slots": result["slot_count"], "events": result["event_count"]},
        "profiles": [list(item) for item in result["profiles"]],
        "flags": dict(V5_FIXED_FLAGS),
    })


__all__ += [
    "V5_SCHEMA", "V5_SCHEMA_VERSION", "V5_DOMAIN", "V5_TABLES",
    "V5_TABLE_COLUMNS", "V5_ARTIFACT_KINDS", "V5_SESSION_STATES",
    "V5_EVENT_KINDS", "V5_FIXED_FLAGS", "V5_EVENT_KEYS", "verify_database_v5",
    "V5_OBSERVATION_SCHEMA", "V5_OBSERVATION_KEYS", "verify_bytes_v5", "logical_export_v5", "_v5_digest", "_v5_raw_digest",
    "_v5_parse", "_v5_config", "_v5_event_root", "_v5_stream_root",
]
