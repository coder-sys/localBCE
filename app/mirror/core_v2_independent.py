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
            if value["operation_id"] != _digest("session-operation", {"session_id": value["subject_id"], "action": "OPEN"}):
                raise CoreVerificationError("core:session-open")
            if value["request_digest"] != _digest("session-request", {"session_id": value["subject_id"]}):
                raise CoreVerificationError("core:session-open")
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
