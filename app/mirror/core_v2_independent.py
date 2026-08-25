"""Independent V3 reconstruction for the six-table Mirror Core owner.

The producer owns SQLite mutation.  This module owns the grammar, replay, and
cross-boundary checks.  It deliberately does not import the producer.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
from typing import Mapping

from app.mirror import ingress_v2_independent as ingress
from app.mirror import external_source_adapter_independent as external
from app.mirror import nc_medicaid_fhir_independent as fhir
from app.mirror.nc_medicaid_fhir_profile import NC_MEDICAID_GRAPH_PROFILE_REGISTRY, NC_MEDICAID_PROFILE
from app.mirror import provider_trust_graph_independent as graph
from app.mirror import external_corrective_action_independent as corrective_action
from app.mirror.error_boundary import raise_redacted


SCHEMA = "mirror-core-v4"
SCHEMA_VERSION = 4
DOMAIN = "BL/MIRROR/CORE/V3/"
MAX_DATABASE_BYTES = 64 * 1024 * 1024
MAX_ARTIFACT_BYTES = 262_144
MAX_EVENT_BYTES = 786_432
MAX_COMPLETE_FRAME_BYTES = fhir.NC_MEDICAID_PROFILE.transport_caps["complete_frame_bytes"]
MAX_ADMISSION_RECEIPT_BYTES = 32_768
GENESIS_ROOT = "0" * 128
TABLES = (
    "core_meta", "core_artifacts", "core_heads", "core_sessions", "core_slots", "core_events",
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
    "core_heads": ("stream_kind", "stream_id", "head_ref", "head_root", "event_sequence"),
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
ARTIFACT_KINDS = (
    "GRAPH", "SOURCE_OBSERVATION", "RECONCILIATION", "GOVERNANCE", "PRIVACY", "CASE", "CASE_ACTION",
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
EVENT_KINDS = ("ARTIFACT", "SESSION_OPEN", "SESSION_START", "OBSERVATION", "SESSION_PAUSE")
SESSION_MATERIAL_FIELDS = (
    "session_id", "state", "source_artifact_id", "governance_artifact_id",
    "privacy_artifact_id", "last_slot",
)
EVENT_RAW_KEYS = {
    "schema", "schema_version", "database_id", "chain_id", "sequence", "event_id",
    "event_kind", "stream_kind", "stream_id", "operation_id", "subject_id",
    "request_digest", "prior_state", "next_state", "attempt", "observed_at",
    "material", "material_digest", "payload_digest", "payload_length", "before_root",
    "after_root", "stream_before_root", "stream_after_root",
}
EXPLICIT_INDEX = "core_artifacts_kind_source_event_idx"
TABLE_SQL = {
    "core_meta": "CREATE TABLE core_meta(meta_id INTEGER PRIMARY KEY CHECK(meta_id=1),schema TEXT NOT NULL,schema_version INTEGER NOT NULL,database_id TEXT NOT NULL,chain_id TEXT NOT NULL,config_digest TEXT NOT NULL,config_raw BLOB NOT NULL,sequence INTEGER NOT NULL,head_root TEXT NOT NULL,ingress_database_id TEXT NOT NULL,ingress_watermark INTEGER NOT NULL)",
    "core_artifacts": "CREATE TABLE core_artifacts(artifact_id TEXT PRIMARY KEY,kind TEXT NOT NULL,raw BLOB NOT NULL,profile_digest TEXT NOT NULL,source_artifact_id TEXT,predecessor_id TEXT,current_state TEXT NOT NULL,created_event_sequence INTEGER NOT NULL)",
    "core_heads": "CREATE TABLE core_heads(stream_kind TEXT NOT NULL,stream_id TEXT NOT NULL,head_ref TEXT NOT NULL,head_root TEXT NOT NULL,event_sequence INTEGER NOT NULL,PRIMARY KEY(stream_kind,stream_id))",
    "core_sessions": "CREATE TABLE core_sessions(session_id TEXT PRIMARY KEY,state TEXT NOT NULL,source_artifact_id TEXT NOT NULL,governance_artifact_id TEXT NOT NULL,privacy_artifact_id TEXT NOT NULL,head_root TEXT NOT NULL,last_slot INTEGER NOT NULL)",
    "core_slots": "CREATE TABLE core_slots(session_id TEXT NOT NULL,slot_number INTEGER NOT NULL,result_digest TEXT NOT NULL,result_raw BLOB NOT NULL,PRIMARY KEY(session_id,slot_number),FOREIGN KEY(session_id) REFERENCES core_sessions(session_id))",
    "core_events": "CREATE TABLE core_events(sequence INTEGER PRIMARY KEY,event_id TEXT NOT NULL UNIQUE,event_kind TEXT NOT NULL,operation_id TEXT NOT NULL UNIQUE,subject_id TEXT NOT NULL,event_raw BLOB NOT NULL,receipt_digest TEXT NOT NULL)",
}
INDEX_SQL = {
    EXPLICIT_INDEX: "CREATE INDEX core_artifacts_kind_source_event_idx ON core_artifacts(kind,source_artifact_id,created_event_sequence)",
}
_REPARSE_POINT = 0x400
_SIDECARS = ("-wal", "-shm", "-journal")


class CoreVerificationError(ValueError):
    """Fixed independent Core failure."""


def _close_readonly(
    connection: sqlite3.Connection | None,
    *,
    code: str = "core:database",
) -> None:
    """Close one verifier snapshot without exposing cleanup failures."""

    active = sys.exc_info()[1]
    cleanup_failed = False
    if connection is not None:
        try:
            connection.execute("ROLLBACK")
        except BaseException:
            cleanup_failed = True
        try:
            connection.close()
        except BaseException:
            cleanup_failed = True
    if cleanup_failed:
        raise_redacted(CoreVerificationError, code)
    if isinstance(active, CoreVerificationError):
        active.__cause__ = None
        active.__context__ = None
        active.__suppress_context__ = True


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
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
            parse_constant=lambda _value: (_ for _ in ()).throw(CoreVerificationError("core:constant")),
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
    digest = hashlib.sha3_512()
    digest.update((DOMAIN + label + "\0").encode("ascii"))
    digest.update(raw)
    return digest.hexdigest()


def _admission_digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update(("BL/MIRROR/SOURCE-ADMISSION/" + label + "/v1\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _admission_raw_digest(label: str, raw: bytes) -> str:
    digest = hashlib.sha3_512()
    digest.update(("BL/MIRROR/SOURCE-ADMISSION/" + label + "/v1\0").encode("ascii"))
    digest.update(raw)
    return digest.hexdigest()


def _hex(value: object, label: str) -> str:
    if type(value) is not str or len(value) != 128 or any(char not in "0123456789abcdef" for char in value):
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
        "schema", "schema_version", "database_id", "chain_id", "sequence", "event_id",
        "event_kind", "stream_kind", "stream_id", "operation_id", "subject_id",
        "request_digest", "prior_state", "next_state", "attempt", "observed_at",
        "material_digest", "payload_digest", "payload_length", "before_root", "stream_before_root",
    )
    return _digest("event-root", {key: body[key] for key in keys})


def _stream_root(body: Mapping[str, object]) -> str:
    keys = (
        "schema", "schema_version", "database_id", "chain_id", "sequence", "event_id",
        "event_kind", "stream_kind", "stream_id", "operation_id", "subject_id",
        "prior_state", "next_state", "attempt", "observed_at", "material_digest",
        "payload_digest", "payload_length", "stream_before_root",
    )
    return _digest("stream-root", {key: body[key] for key in keys})


def _table_names(connection: sqlite3.Connection) -> tuple[str, ...]:
    return tuple(row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").fetchall())


def _columns(connection: sqlite3.Connection, table: str) -> tuple[str, ...]:
    return tuple(row[1] for row in connection.execute("SELECT * FROM pragma_table_info(?) ORDER BY cid", (table,)).fetchall())


def _is_reparse(info: os.stat_result) -> bool:
    return bool(getattr(info, "st_file_attributes", 0) & _REPARSE_POINT)


def _sidecar_present(path: Path) -> bool:
    return any(os.path.lexists(os.fspath(path) + suffix) for suffix in _SIDECARS)


def _check_runtime_pragmas(connection: sqlite3.Connection, *, require_delete_journal: bool) -> None:
    try:
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
        if page_size != 4096 or page_count < 0 or page_size * page_count > MAX_DATABASE_BYTES:
            raise CoreVerificationError("core:capacity")
        max_pages = MAX_DATABASE_BYTES // page_size
        connection.execute(f"PRAGMA max_page_count={max_pages}")
        configured_max = int(connection.execute("PRAGMA max_page_count").fetchone()[0])
        if configured_max <= 0 or configured_max > max_pages or page_count > configured_max:
            raise CoreVerificationError("core:capacity")
        mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower()
        if require_delete_journal and mode != "delete":
            raise CoreVerificationError("core:database")
        if int(connection.execute("PRAGMA synchronous").fetchone()[0]) != 2:
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
        if not stat.S_ISDIR(parent.st_mode) or _is_reparse(parent) or stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or _is_reparse(info) or info.st_nlink != 1 or info.st_size <= 0 or _sidecar_present(database):
            raise CoreVerificationError("core:database")
        if info.st_size > MAX_DATABASE_BYTES:
            raise CoreVerificationError("core:capacity")
        connection = sqlite3.connect(database.absolute().as_uri() + "?mode=ro", uri=True, isolation_level=None, timeout=0.25)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        main = next((row[2] for row in connection.execute("PRAGMA database_list").fetchall() if int(row[0]) == 0), None)
        if type(main) is not str or not main or not os.path.samefile(main, database):
            raise CoreVerificationError("core:database")
        _check_runtime_pragmas(connection, require_delete_journal=True)
        connection.execute("BEGIN")
        return connection
    except CoreVerificationError:
        _close_readonly(connection)
        raise
    except (OSError, sqlite3.Error, TypeError, ValueError):
        _close_readonly(connection)
        raise CoreVerificationError("core:database") from None


def _verify_config(value: Mapping[str, object], expected_digest: str | None = None) -> dict[str, object]:
    required = {
        "schema", "schema_version", "database_id", "chain_id", "ingress_database_id", "ingress_chain_id",
        "ingress_config_digest", "runtime_profile_digest", "governance_policy_digest",
        "privacy_policy_digest", "corrective_action_control_digest", "max_sessions", "max_slots_per_session", "cadence_seconds",
        "flags",
    }
    if set(value) != required or value.get("schema") != SCHEMA or value.get("schema_version") != SCHEMA_VERSION or value.get("flags") != FIXED_FLAGS:
        raise CoreVerificationError("core:config")
    for key in ("database_id", "chain_id", "ingress_database_id", "ingress_chain_id"):
        _safe_identifier(value.get(key), "core:config")
    _hex(value["ingress_config_digest"], "core:config")
    for key in ("runtime_profile_digest", "governance_policy_digest", "privacy_policy_digest"):
        _hex(value[key], "core:config")
    _hex(value["corrective_action_control_digest"], "core:config")
    if type(value["max_sessions"]) is not int or not 1 <= value["max_sessions"] <= 64 or type(value["max_slots_per_session"]) is not int or not 1 <= value["max_slots_per_session"] <= 256 or type(value["cadence_seconds"]) is not int or value["cadence_seconds"] <= 0:
        raise CoreVerificationError("core:config")
    if expected_digest is not None and _digest("config", dict(value)) != expected_digest:
        raise CoreVerificationError("core:config")
    return dict(value)


def _verify_admission_receipt(value: Mapping[str, object], source: Mapping[str, object]) -> dict[str, object]:
    expected = {
        "receipt_id", "schema", "profile_id", "profile_version", "profile_digest",
        "verifier_id", "verifier_epoch", "evidence_mode", "adapter_digest",
        "source_result_digest", "graph_input_digest", "graph_artifact_digest",
        "graph_report_id", "production_source_authentication",
        "external_artifact_id", "external_artifact_digest", "capture_id",
        "capture_context_digest", "external_policy_digest",
    }
    if set(value) != expected or value.get("schema") != "mirror-source-admission-receipt-v2":
        raise CoreVerificationError("core:admission-receipt")
    graph_profile = NC_MEDICAID_PROFILE.graph_profile
    if value.get("profile_id") != graph_profile.profile_id or value.get("profile_version") != 3:
        raise CoreVerificationError("core:admission-receipt")
    if value.get("verifier_id") != graph_profile.verifier_id or value.get("verifier_epoch") != graph_profile.verifier_epoch or value.get("evidence_mode") != graph_profile.evidence_mode.value or value.get("production_source_authentication") is not False:
        raise CoreVerificationError("core:admission-receipt")
    if type(value.get("verifier_id")) is not str or type(value.get("verifier_epoch")) is not int or value["verifier_epoch"] < 0 or type(value.get("evidence_mode")) is not str:
        raise CoreVerificationError("core:admission-receipt")
    for key in (
        "receipt_id", "profile_digest", "adapter_digest", "source_result_digest", "graph_input_digest",
        "graph_artifact_digest", "graph_report_id", "external_artifact_id", "external_artifact_digest",
        "capture_id", "capture_context_digest", "external_policy_digest",
    ):
        _hex(value.get(key), "core:admission-receipt")
    body = {key: value[key] for key in expected if key != "receipt_id"}
    if value["receipt_id"] != _admission_digest("receipt-id", body):
        raise CoreVerificationError("core:admission-receipt")
    if value["graph_report_id"] != source.get("admission_report_id"):
        raise CoreVerificationError("core:admission-receipt")
    return dict(value)


def _replay_source_admission(
    envelope_raw: bytes,
    graph_raw: bytes,
    source: Mapping[str, object],
    graph_result: graph._VerifiedGraphArtifactV2 | None = None,
    *,
    external_evidence_raw: bytes | None = None,
    external_policy: Mapping[str, object] | None = None,
) -> graph._VerifiedGraphArtifactV2:
    if type(envelope_raw) is not bytes or not envelope_raw or len(envelope_raw) > fhir.NC_MEDICAID_PROFILE.transport_caps["max_envelope_bytes"]:
        raise CoreVerificationError("core:ingress-binding")
    if type(graph_raw) is not bytes or not graph_raw or len(graph_raw) > MAX_ARTIFACT_BYTES:
        raise CoreVerificationError("core:source-graph")
    try:
        fhir_result = fhir.verify_bytes(envelope_raw, profile=NC_MEDICAID_PROFILE)
        coverage = fhir.to_verified_source_coverage(fhir_result, profile=NC_MEDICAID_PROFILE)
        if type(external_evidence_raw) is not bytes or not external_evidence_raw or not isinstance(external_policy, Mapping):
            raise CoreVerificationError("core:external-evidence")
        external_result = external.verify_artifact(external_evidence_raw, policy=external_policy, capture_raw=envelope_raw)
        graph_profile = coverage.graph_profile
        if graph_profile is None:
            raise CoreVerificationError("core:source-profile")
        checked_graph_object = graph_result or graph.verify_artifact_v2(
            graph_raw,
            {graph_profile.profile_id: graph_profile},
        )
        checked_graph = checked_graph_object.summary
        graph._bind_input_to_verified_v2(
            coverage.graph_input,
            graph_raw,
            verified=checked_graph_object,
        )
    except Exception:
        raise CoreVerificationError("core:source-admission") from None
    if (
        fhir_result.get("source_status") != "COMPLETE"
        or fhir_result.get("page_complete") is not True
        or fhir_result.get("freshness") != "FRESH"
        or fhir_result.get("failure_code") is not None
        or external_result.get("derived_status") != "OBSERVATION_ADMITTED"
        or external_result.get("complete") is not True
        or external_result.get("failure_code") != "NONE"
        or external_result.get("source_contract_digest") != NC_MEDICAID_PROFILE.profile_digest
        or external_result.get("observed_at") != fhir_result.get("observation_time")
        or external_result.get("fetched_at") != fhir_result.get("fetched_at")
        or tuple(fhir_result.get("page_digests", ())) != tuple(digest for _index, digest in external_result.get("page_bindings", ()))
    ):
        raise CoreVerificationError("core:source-admission")
    if (
        checked_graph.get("accepted") is not True
        or checked_graph.get("profile_id") != graph_profile.profile_id
        or checked_graph.get("profile_version") != graph_profile.version
        or checked_graph.get("profile_digest") != graph_profile.profile_digest
        or type(checked_graph.get("report_id")) is not str
    ):
        raise CoreVerificationError("core:source-admission")
    graph_input_digest = _admission_raw_digest("graph-input", coverage.graph_input)
    graph_artifact_digest = _admission_raw_digest("graph-artifact", graph_raw)
    source_result_digest = _admission_digest(
        "source-result",
        {
            "profile_id": coverage.profile_id,
            "subject": coverage.subject,
            "scope": coverage.scope,
            "observation_time": coverage.observation_time,
            "effective_start": coverage.effective_start,
            "effective_end": coverage.effective_end,
                "complete": coverage.complete,
                "source_roles": list(coverage.source_roles),
                "evidence_mode": coverage.evidence_mode.value,
                "graph_input_digest": graph_input_digest,
                "source_contract_digest": coverage.source_contract_digest,
                "envelope_id": coverage.envelope_id,
                "page_digests": list(coverage.page_digests),
            },
        )
    body = {
        "schema": "mirror-source-admission-receipt-v2",
        "profile_id": coverage.profile_id,
        "profile_version": graph_profile.version,
        "profile_digest": graph_profile.profile_digest,
        "verifier_id": graph_profile.verifier_id,
        "verifier_epoch": graph_profile.verifier_epoch,
        "evidence_mode": coverage.evidence_mode.value,
        "adapter_digest": _admission_raw_digest("adapter", envelope_raw),
        "source_result_digest": source_result_digest,
        "graph_input_digest": graph_input_digest,
        "graph_artifact_digest": graph_artifact_digest,
        "graph_report_id": checked_graph.get("report_id"),
        "production_source_authentication": False,
    }
    body.update({
        "external_artifact_id": external_result["artifact_id"],
        "external_artifact_digest": _admission_raw_digest("external-artifact", external_evidence_raw),
        "capture_id": external_result["capture_id"],
        "capture_context_digest": _admission_digest(
            "capture-context",
            {key: external_result[key] for key in ("subject_id", "credential_id", "enrollment_id", "subject_locator_digest", "observed_at", "fetched_at")},
        ),
        "external_policy_digest": external_result["policy_digest"],
    })
    expected_receipt = {"receipt_id": _admission_digest("receipt-id", body), **body}
    if source.get("admission_receipt") != expected_receipt:
        raise CoreVerificationError("core:source-admission")
    if source.get("admission_receipt_digest") != _raw_digest("admission-receipt", _canonical(expected_receipt)):
        raise CoreVerificationError("core:source-admission")
    expected = {
        "envelope_id": fhir_result.get("envelope_id"),
        "envelope_digest": ingress._raw_digest("envelope", envelope_raw),
        "snapshot_id": fhir_result.get("snapshot_id"),
        "snapshot_root": fhir_result.get("snapshot_root"),
        "content_root": ingress.content_root(fhir_result.get("resources")),
        "profile_id": NC_MEDICAID_PROFILE.source_profile_id,
        "profile_version": NC_MEDICAID_PROFILE.version,
        "profile_digest": NC_MEDICAID_PROFILE.profile_digest,
        "source_contract_digest": external_result["source_contract_digest"],
        "external_artifact_id": external_result["artifact_id"],
        "external_artifact_digest": _admission_raw_digest("external-artifact", external_evidence_raw),
        "capture_id": external_result["capture_id"],
        "capture_context_digest": _admission_digest(
            "capture-context",
            {key: external_result[key] for key in ("subject_id", "credential_id", "enrollment_id", "subject_locator_digest", "observed_at", "fetched_at")},
        ),
        "page_digests": [digest for _index, digest in external_result["page_bindings"]],
        "observation_time": fhir_result.get("observation_time"),
        "fetched_at": fhir_result.get("fetched_at"),
        "source_status": fhir_result.get("source_status"),
        "freshness": fhir_result.get("freshness"),
        "page_complete": fhir_result.get("page_complete"),
        "page_count": fhir_result.get("page_count"),
        "resource_count": fhir_result.get("resource_count"),
        "admission_report_id": checked_graph.get("report_id"),
        "graph_artifact_digest": _raw_digest("graph-artifact", graph_raw),
    }
    if any(source.get(key) != expected_value for key, expected_value in expected.items()):
        raise CoreVerificationError("core:source-admission")
    return checked_graph_object


def _verify_source_projection(value: Mapping[str, object], config: Mapping[str, object]) -> None:
    expected = {
        "schema", "schema_version", "kind", "artifact_id", "ingress_database_id", "ingress_chain_id",
        "ingress_config_digest", "ingress_artifact_id", "ingress_event_sequence", "ingress_prefix_root",
        "ingress_after_root", "ingress_head_root", "envelope_id", "envelope_digest", "snapshot_id",
        "snapshot_root", "content_root", "profile_id", "profile_version", "profile_digest",
        "runtime_profile_digest", "observation_time", "fetched_at", "source_status", "freshness",
        "page_complete", "page_count", "resource_count", "graph_artifact_id", "graph_artifact_digest",
        "source_contract_digest", "external_artifact_id", "external_artifact_digest", "capture_id",
        "capture_context_digest", "page_digests",
        "admission_receipt", "admission_receipt_digest", "admission_report_id", "observation_status", "chronology", "flags",
    }
    if set(value) != expected or value.get("schema") != "mirror-core-source-observation-v3" or value.get("schema_version") != 3 or value.get("kind") != "SOURCE_OBSERVATION" or value.get("flags") != FIXED_FLAGS:
        raise CoreVerificationError("core:source-keys")
    for key in (
        "artifact_id", "ingress_config_digest", "ingress_prefix_root", "ingress_after_root", "ingress_head_root",
        "envelope_id", "envelope_digest", "snapshot_id", "snapshot_root", "content_root", "profile_digest",
        "runtime_profile_digest", "graph_artifact_digest", "admission_receipt_digest", "admission_report_id",
        "source_contract_digest", "external_artifact_id", "external_artifact_digest", "capture_id", "capture_context_digest",
    ):
        if key == "ingress_config_digest" and value[key] is None:
            raise CoreVerificationError("core:source-binding")
        _hex(value[key], "core:source-binding")
    if type(value["ingress_event_sequence"]) is not int or value["ingress_event_sequence"] <= 0:
        raise CoreVerificationError("core:source-count")
    for key in ("ingress_database_id", "ingress_chain_id", "ingress_artifact_id", "profile_id"):
        if type(value[key]) is not str or not value[key]:
            raise CoreVerificationError("core:source-identity")
    if value["ingress_database_id"] != config["ingress_database_id"] or value["ingress_chain_id"] != config["ingress_chain_id"] or value["runtime_profile_digest"] != config["runtime_profile_digest"]:
        raise CoreVerificationError("core:source-config")
    if value["ingress_config_digest"] != config["ingress_config_digest"]:
        raise CoreVerificationError("core:source-config")
    if any(type(value[key]) is not int or value[key] < 0 for key in ("profile_version", "observation_time", "page_count", "resource_count")):
        raise CoreVerificationError("core:source-count")
    fetched_at = value["fetched_at"]
    if type(fetched_at) is not int or fetched_at < value["observation_time"]:
        raise CoreVerificationError("core:source-time")
    if (
        type(value["page_complete"]) is not bool
        or value["source_status"] != "COMPLETE"
        or value["freshness"] != "FRESH"
        or value["page_complete"] is not True
        or value["observation_status"] not in {"OBSERVED_NEW", "OBSERVED_CONTINUED", "OBSERVED_CHANGED"}
        or value["chronology"] not in {"INITIAL", "ADVANCING"}
        or type(value["page_digests"]) is not list
        or not 1 <= len(value["page_digests"]) <= 32
        or any(type(item) is not str or len(item) != 128 or any(char not in "0123456789abcdef" for char in item) for item in value["page_digests"])
    ):
        raise CoreVerificationError("core:source-binding")
    if value["profile_id"] != NC_MEDICAID_PROFILE.source_profile_id or value["profile_version"] != NC_MEDICAID_PROFILE.version or value["profile_digest"] != NC_MEDICAID_PROFILE.profile_digest or value["source_contract_digest"] != config["runtime_profile_digest"] or value["ingress_head_root"] != value["ingress_after_root"]:
        raise CoreVerificationError("core:source-binding")
    if not isinstance(value["admission_receipt"], dict) or len(_canonical(value["admission_receipt"])) > MAX_ADMISSION_RECEIPT_BYTES:
        raise CoreVerificationError("core:admission-receipt")
    _verify_admission_receipt(value["admission_receipt"], value)
    if value["admission_receipt_digest"] != _raw_digest("admission-receipt", _canonical(value["admission_receipt"])):
        raise CoreVerificationError("core:admission-receipt")
    if value["artifact_id"] != _digest("source-artifact-id", {key: value[key] for key in expected if key not in {"artifact_id", "flags"}}):
        raise CoreVerificationError("core:source-id")


def _verify_reconciliation(value: Mapping[str, object]) -> None:
    expected = {"schema", "schema_version", "kind", "artifact_id", "current_source_artifact_id", "prior_source_artifact_id", "current_content_root", "prior_content_root", "source_status", "observation_status", "chronology", "linkage", "flags"}
    if set(value) != expected or value.get("schema") != "mirror-core-reconciliation-v3" or value.get("schema_version") != 3 or value.get("kind") != "RECONCILIATION" or value.get("flags") != FIXED_FLAGS:
        raise CoreVerificationError("core:reconciliation-keys")
    for key in ("artifact_id", "current_source_artifact_id", "current_content_root"):
        _hex(value[key], "core:reconciliation")
    if value["prior_source_artifact_id"] is not None:
        _hex(value["prior_source_artifact_id"], "core:reconciliation")
    if value["prior_content_root"] is not None:
        _hex(value["prior_content_root"], "core:reconciliation")
    if value["source_status"] not in {"COMPLETE", "PARTIAL", "FAILED", "STALE"} or value["observation_status"] not in {"OBSERVED_NEW", "OBSERVED_CONTINUED", "OBSERVED_CHANGED", "INCOMPLETE"} or value["chronology"] not in {"INITIAL", "ADVANCING"} or value["linkage"] not in {"UNCHANGED", "LINKED", "UNLINKED"}:
        raise CoreVerificationError("core:reconciliation")
    if value["artifact_id"] != _digest("reconciliation-id", {key: value[key] for key in expected if key != "artifact_id"}):
        raise CoreVerificationError("core:reconciliation-id")


def _expected_reconciliation(
    source: Mapping[str, object],
    prior: Mapping[str, object] | None,
    *,
    source_artifact_id: str,
    prior_source_artifact_id: str | None,
) -> dict[str, object]:
    if prior is None:
        status = "INCOMPLETE" if source.get("source_status") != "COMPLETE" else "OBSERVED_NEW"
        chronology = "INITIAL"
    else:
        if int(source["ingress_event_sequence"]) <= int(prior["ingress_event_sequence"]) or int(source["observation_time"]) <= int(prior["observation_time"]):
            raise CoreVerificationError("core:source-chronology")
        status = "INCOMPLETE" if source.get("source_status") != "COMPLETE" else ("OBSERVED_CONTINUED" if source.get("content_root") == prior.get("content_root") else "OBSERVED_CHANGED")
        chronology = "ADVANCING"
    body = {
        "schema": "mirror-core-reconciliation-v3",
        "schema_version": 3,
        "kind": "RECONCILIATION",
        "artifact_id": "",
        "current_source_artifact_id": source_artifact_id,
        "prior_source_artifact_id": prior_source_artifact_id,
        "current_content_root": source["content_root"],
        "prior_content_root": prior.get("content_root") if prior is not None else None,
        "source_status": source["source_status"],
        "observation_status": status,
        "chronology": chronology,
        "linkage": "UNCHANGED" if prior is not None and prior.get("graph_artifact_digest") == source.get("graph_artifact_digest") else "LINKED",
        "flags": dict(FIXED_FLAGS),
    }
    body["artifact_id"] = _digest("reconciliation-id", {key: body[key] for key in body if key != "artifact_id"})
    return body


def _authority_staleness(
    session: Mapping[str, object],
    expected_artifacts: Mapping[str, Mapping[str, object]],
    stream_refs: Mapping[tuple[str, str], str],
    observed_at: int,
) -> str | None:
    source_id = str(session["source_artifact_id"])
    governance_id = str(session["governance_artifact_id"])
    privacy_id = str(session["privacy_artifact_id"])
    if stream_refs.get(("ARTIFACT", "SOURCE_OBSERVATION")) != source_id:
        return "SOURCE_SUPERSEDED"
    if stream_refs.get(("ARTIFACT", "GOVERNANCE")) != governance_id or stream_refs.get(("ARTIFACT", "PRIVACY")) != privacy_id:
        return "AUTHORITY_INDETERMINATE"
    governance_value = _parse(expected_artifacts[governance_id]["raw"], "core:artifact")
    privacy_value = _parse(expected_artifacts[privacy_id]["raw"], "core:artifact")
    if governance_value.get("decision") != "GRANTED" or privacy_value.get("privacy_decision") != "GRANTED" or privacy_value.get("support_decision") != "GRANTED":
        return "AUTHORITY_INDETERMINATE"
    for value in (governance_value, privacy_value):
        if type(value.get("valid_from")) is not int or type(value.get("valid_until")) is not int:
            return "AUTHORITY_INDETERMINATE"
        if observed_at < int(value["valid_from"]) or observed_at > int(value["valid_until"]):
            return "AUTHORITY_EXPIRED"
    return None


def _graph_profile_from_artifact(value: Mapping[str, object]) -> graph._GraphProfile:
    """Reconstruct a bounded dynamic graph profile for structural replay.

    The profile is intentionally derived only for the structural-only Core
    lane.  When an Ingress image is supplied, source admission binds the same
    artifact to the FHIR-derived profile before Core claims ingress_bound.
    """

    subject_value = value.get("subject")
    profile_value = value.get("profile")
    snapshot_value = value.get("observation_snapshot")
    sources_value = value.get("source_coverage")
    if (
        not isinstance(subject_value, Mapping)
        or set(subject_value) != {"provider_graph_subject", "scope"}
        or not isinstance(profile_value, Mapping)
        or set(profile_value) != {"profile_id", "version", "profile_digest"}
        or not isinstance(snapshot_value, Mapping)
        or not isinstance(sources_value, list)
        or len(sources_value) != 2
    ):
        raise CoreVerificationError("core:graph")
    subject = subject_value.get("provider_graph_subject")
    scope = subject_value.get("scope")
    profile_id = profile_value.get("profile_id")
    version = profile_value.get("version")
    profile_digest = profile_value.get("profile_digest")
    observation_time = snapshot_value.get("observation_time")
    if (
        type(subject) is not str
        or type(scope) is not str
        or type(profile_id) is not str
        or type(version) is not int
        or type(profile_digest) is not str
        or type(observation_time) is not int
    ):
        raise CoreVerificationError("core:graph")
    _hex(profile_digest, "core:graph")
    role_ids: list[str] = []
    source_kinds: list[str] = []
    record_kinds: list[str] = []
    authority_ids: list[str] = []
    provenance_ids: list[str] = []
    credential_id: str | None = None
    enrollment_id: str | None = None
    effective_start: int | None = None
    effective_end: int | None = None
    for source in sources_value:
        if not isinstance(source, Mapping):
            raise CoreVerificationError("core:graph")
        records = source.get("records")
        provenance = source.get("provenance")
        if not isinstance(records, list) or len(records) != 1 or not isinstance(provenance, Mapping):
            raise CoreVerificationError("core:graph")
        record = records[0]
        role_id = source.get("source_id")
        source_kind = source.get("source_kind")
        record_kind = record.get("record_kind") if isinstance(record, Mapping) else None
        authority = source.get("coverage_authority_id")
        provenance_id = provenance.get("provenance_id")
        if not all(type(item) is str and item for item in (role_id, source_kind, record_kind, authority, provenance_id)):
            raise CoreVerificationError("core:graph")
        role_ids.append(role_id)
        source_kinds.append(source_kind)
        record_kinds.append(record_kind)
        authority_ids.append(authority)
        provenance_ids.append(provenance_id)
        if not isinstance(record, Mapping) or record.get("provider_id") != subject:
            raise CoreVerificationError("core:graph")
        credential = record.get("credential_id")
        enrollment = record.get("enrollment_id")
        if type(credential) is not str or type(enrollment) is not str:
            raise CoreVerificationError("core:graph")
        if record_kind == "CREDENTIAL":
            credential_id = credential
        elif record_kind == "ENROLLMENT":
            enrollment_id = enrollment
        else:
            raise CoreVerificationError("core:graph")
        start = source.get("coverage_effective_start")
        end = source.get("coverage_effective_end")
        if type(start) is not int or type(end) is not int:
            raise CoreVerificationError("core:graph")
        if effective_start is None:
            effective_start, effective_end = start, end
        elif (start, end) != (effective_start, effective_end):
            raise CoreVerificationError("core:graph")
    if credential_id is None or enrollment_id is None or effective_start is None or effective_end is None:
        raise CoreVerificationError("core:graph")
    try:
        return graph._GraphProfile(
            True,
            graph.SCHEMA_V2,
            profile_id,
            version,
            profile_digest,
            subject,
            scope,
            credential_id,
            enrollment_id,
            subject + "|" + credential_id + "|" + enrollment_id,
            tuple(role_ids),
            tuple(source_kinds),
            tuple(record_kinds),
            tuple(authority_ids),
            tuple(provenance_ids),
            observation_time,
            observation_time + 1,
            effective_start,
            effective_end,
            False,
            False,
        )
    except Exception:
        raise CoreVerificationError("core:graph") from None


def _verify_artifact_value(row: Mapping[str, object], config: Mapping[str, object]) -> dict[str, object]:
    if tuple(row.keys()) != TABLE_COLUMNS["core_artifacts"]:
        raise CoreVerificationError("core:artifact-columns")
    raw = row["raw"]
    if type(raw) is not bytes or not raw or len(raw) > MAX_ARTIFACT_BYTES:
        raise CoreVerificationError("core:artifact-raw")
    value = _parse(raw, "core:artifact")
    kind = row["kind"]
    if kind not in ARTIFACT_KINDS or (kind not in {"GRAPH", "CASE_ACTION"} and value.get("kind") != kind) or (kind == "CASE_ACTION" and value.get("kind") != "CORRECTIVE_ACTION"):
        raise CoreVerificationError("core:artifact-kind")
    elif kind == "SOURCE_OBSERVATION":
        _verify_source_projection(value, config)
    elif kind == "RECONCILIATION":
        _verify_reconciliation(value)
    elif kind in {"GOVERNANCE", "PRIVACY"}:
        expected = ({"schema", "schema_version", "kind", "artifact_id", "decision", "policy_digest", "evidence_digest", "verifier_id", "verifier_epoch", "valid_from", "valid_until", "flags"} if kind == "GOVERNANCE" else {"schema", "schema_version", "kind", "artifact_id", "privacy_decision", "support_decision", "policy_digest", "evidence_digest", "verifier_id", "verifier_epoch", "valid_from", "valid_until", "flags"})
        if set(value) != expected or value["schema_version"] != 3 or value["flags"] != FIXED_FLAGS:
            raise CoreVerificationError("core:approval")
        for key in ("artifact_id", "policy_digest", "evidence_digest"):
            _hex(value[key], "core:approval")
        if type(value["verifier_id"]) is not str or not value["verifier_id"] or type(value["verifier_epoch"]) is not int or value["verifier_epoch"] < 0 or type(value["valid_from"]) is not int or type(value["valid_until"]) is not int or value["valid_from"] < 0 or value["valid_until"] < value["valid_from"]:
            raise CoreVerificationError("core:approval")
        if kind == "GOVERNANCE" and value["decision"] not in {"GRANTED", "DENIED", "WITHDRAWN"}:
            raise CoreVerificationError("core:governance")
        if kind == "PRIVACY" and (value["privacy_decision"] not in {"GRANTED", "DENIED", "WITHDRAWN"} or value["support_decision"] not in {"GRANTED", "DENIED", "WITHDRAWN"}):
            raise CoreVerificationError("core:privacy")
    elif kind == "CASE":
        expected = {"schema", "schema_version", "kind", "artifact_id", "case_id", "reconciliation_artifact_id", "source_artifact_id", "graph_artifact_id", "graph_report_id", "graph_profile_digest", "subject_digest", "target_finding_ids", "target_finding_kinds", "state", "responsibility", "reason", "action_artifact_id", "action_observed_at", "retest_source_artifact_id", "retest_graph_artifact_id", "retest_observation_time", "flags"}
        if set(value) != expected or value["schema"] != "mirror-core-case-v4" or value["schema_version"] != 4 or value["flags"] != FIXED_FLAGS or value["state"] not in {"OPEN", "ACTION_RECORDED", "RETEST_FAILED_OR_INDETERMINATE", "RESOLVED"} or value["responsibility"] != "UNKNOWN":
            raise CoreVerificationError("core:case")
        for key in ("artifact_id", "case_id", "reconciliation_artifact_id", "source_artifact_id", "graph_artifact_id", "graph_report_id", "graph_profile_digest", "subject_digest"):
            _hex(value[key], "core:case")
        ids = value["target_finding_ids"]; kinds = value["target_finding_kinds"]
        if not isinstance(ids, list) or not isinstance(kinds, list) or not ids or len(ids) != len(kinds) or ids != sorted(ids) or len(set(ids)) != len(ids):
            raise CoreVerificationError("core:case-findings")
        for item in ids: _hex(item, "core:case-finding")
        for item in kinds:
            if type(item) is not str or not item:
                raise CoreVerificationError("core:case-finding")
        if value["reason"] not in {"ACTIONABLE_FINDING", "ACTION_VERIFIED", "ALL_TARGET_FINDINGS_CLEARED", "TARGET_FINDINGS_REMAIN", "RETEST_INDETERMINATE"}:
            raise CoreVerificationError("core:case-reason")
        for key in ("action_artifact_id", "retest_source_artifact_id", "retest_graph_artifact_id"):
            if value[key] is not None: _hex(value[key], "core:case-link")
        for key in ("action_observed_at", "retest_observation_time"):
            if value[key] is not None and (type(value[key]) is not int or value[key] < 0):
                raise CoreVerificationError("core:case-time")
        if value["state"] == "OPEN" and any(value[key] is not None for key in ("action_artifact_id", "action_observed_at", "retest_source_artifact_id", "retest_graph_artifact_id", "retest_observation_time")):
            raise CoreVerificationError("core:case-state")
    elif kind == "CASE_ACTION":
        try:
            corrective_action.verify_artifact(raw, control_digest=config["corrective_action_control_digest"])
        except Exception:
            raise CoreVerificationError("core:case-action")
    expected_profile = {
        "GRAPH": row["profile_digest"],
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
    expected_id = _digest("artifact-row-id", {"kind": kind, "raw": _raw_digest("artifact-bytes", raw), "profile_digest": row["profile_digest"], "source_artifact_id": row["source_artifact_id"], "predecessor_id": row["predecessor_id"]})
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


def _verify_session_material(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != set(SESSION_MATERIAL_FIELDS):
        raise CoreVerificationError("core:session-material")
    if type(value["session_id"]) is not str or not value["session_id"] or value["state"] not in SESSION_STATES:
        raise CoreVerificationError("core:session-material")
    for key in ("source_artifact_id", "governance_artifact_id", "privacy_artifact_id"):
        _hex(value[key], "core:session-material")
    if type(value["last_slot"]) is not int or value["last_slot"] < -1:
        raise CoreVerificationError("core:session-material")
    return dict(value)


def _material_keys(kind: str) -> set[str]:
    if kind == "ARTIFACT":
        return {"artifact_id", "kind", "raw_digest", "raw_length", "profile_digest", "source_artifact_id", "predecessor_id", "current_state", "ingress_watermark"}
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


def _check_common(value: Mapping[str, object]) -> None:
    if value["schema"] != SCHEMA or value["schema_version"] != SCHEMA_VERSION or type(value["database_id"]) is not str or type(value["chain_id"]) is not str:
        raise CoreVerificationError("core:event-schema")
    for key in ("request_digest", "material_digest", "payload_digest", "before_root", "after_root", "stream_before_root", "stream_after_root"):
        _hex(value[key], "core:event-hex")
    for key in ("sequence", "attempt", "observed_at", "payload_length"):
        if type(value[key]) is not int or value[key] < 0:
            raise CoreVerificationError("core:event-number")
    for key in ("event_id", "operation_id", "subject_id", "event_kind", "stream_kind", "stream_id", "prior_state", "next_state"):
        if type(value[key]) is not str or not value[key]:
            raise CoreVerificationError("core:event-field")


def _expected_case_request(raw: bytes, predecessor_id: str | None) -> tuple[str, str]:
    case = _parse(raw, "core:case")
    if predecessor_id is None:
        return _digest("case-operation", {"case_id": case["case_id"]}), _digest("case-request", {"reconciliation_artifact_id": case["reconciliation_artifact_id"], "case_id": case["case_id"]})
    material = {
        "case_artifact_id": predecessor_id,
        "action_artifact_id": case.get("action_artifact_id"),
        "retest_source_artifact_id": case.get("retest_source_artifact_id"),
        "retest_observation_time": case.get("retest_observation_time"),
        "state": case["state"],
        "reason": case["reason"],
    }
    if case["state"] == "ACTION_RECORDED":
        return _digest("case-transition-operation", {"case_artifact_id": predecessor_id, "action_artifact_id": case["action_artifact_id"], "transition": "ACTION_RECORDED"}), _digest("case-transition-request", {"case_artifact_id": predecessor_id, "action_artifact_id": case["action_artifact_id"], "transition": "ACTION_RECORDED"})
    if case["state"] in {"RESOLVED", "RETEST_FAILED_OR_INDETERMINATE"}:
        return _digest("case-evaluate-operation", {"case_artifact_id": predecessor_id, "later_source_artifact_id": case["retest_source_artifact_id"]}), _digest("case-evaluate-request", {"case_artifact_id": predecessor_id, "later_source_artifact_id": case["retest_source_artifact_id"], "state": case["state"], "reason": case["reason"]})
    return _digest("case-transition-operation", material), _digest("case-transition-request", material)


def _expected_open_case(
    case: Mapping[str, object],
    reconciliation: Mapping[str, object],
    source: Mapping[str, object],
    graph_value: Mapping[str, object],
    config: Mapping[str, object],
) -> dict[str, object]:
    if (
        reconciliation.get("kind") != "RECONCILIATION"
        or reconciliation.get("current_source_artifact_id") != case.get("source_artifact_id")
        or source.get("graph_artifact_id") != case.get("graph_artifact_id")
        or not isinstance(graph_value.get("subject"), Mapping)
        or not isinstance(graph_value.get("profile"), Mapping)
        or not isinstance(graph_value.get("report"), Mapping)
    ):
        raise CoreVerificationError("core:case-semantic")
    findings = graph_value.get("findings")
    if not isinstance(findings, list):
        raise CoreVerificationError("core:case-semantic")
    actionable = [item for item in findings if isinstance(item, Mapping) and item.get("kind") != "CONTINUITY_CONFIRMED"]
    if not actionable:
        raise CoreVerificationError("core:case-semantic")
    try:
        ordered = sorted(actionable, key=lambda item: str(item["finding_id"]))
        target_ids = [str(item["finding_id"]) for item in ordered]
        target_kinds = [str(item["kind"]) for item in ordered]
        report_id = str(graph_value["report"]["report_id"])
        graph_profile_digest = str(graph_value["profile"]["profile_digest"])
        subject_digest = _digest("case-subject", graph_value["subject"])
        case_id = _digest(
            "case-id",
            {
                "reconciliation_artifact_id": case["reconciliation_artifact_id"],
                "source_artifact_id": case["source_artifact_id"],
                "graph_artifact_id": source["graph_artifact_id"],
                "graph_report_id": report_id,
                "profile_digest": config["runtime_profile_digest"],
                "subject_digest": subject_digest,
                "target_finding_ids": target_ids,
                "target_finding_kinds": target_kinds,
            },
        )
    except (KeyError, TypeError, ValueError):
        raise CoreVerificationError("core:case-semantic") from None
    expected = {
        "schema": "mirror-core-case-v4",
        "schema_version": 4,
        "kind": "CASE",
        "artifact_id": "",
        "case_id": case_id,
        "reconciliation_artifact_id": case["reconciliation_artifact_id"],
        "source_artifact_id": case["source_artifact_id"],
        "graph_artifact_id": source["graph_artifact_id"],
        "graph_report_id": report_id,
        "graph_profile_digest": graph_profile_digest,
        "subject_digest": subject_digest,
        "target_finding_ids": target_ids,
        "target_finding_kinds": target_kinds,
        "state": "OPEN",
        "responsibility": "UNKNOWN",
        "reason": "ACTIONABLE_FINDING",
        "action_artifact_id": None,
        "action_observed_at": None,
        "retest_source_artifact_id": None,
        "retest_graph_artifact_id": None,
        "retest_observation_time": None,
        "flags": dict(FIXED_FLAGS),
    }
    expected["artifact_id"] = _digest("case-artifact", {key: expected[key] for key in expected if key != "artifact_id"})
    return expected


def _verify_connection(connection: sqlite3.Connection, *, expected_database_id: str | None = None, expected_config_digest: str | None = None, ingress_path: str | Path | None = None, ingress_bytes: bytes | None = None) -> dict[str, object]:
    try:
        if _table_names(connection) != tuple(sorted(TABLES)):
            raise CoreVerificationError("core:tables")
        for table, columns in TABLE_COLUMNS.items():
            if _columns(connection, table) != columns:
                raise CoreVerificationError("core:columns")
            definition = connection.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
            if definition is None or definition[0] != TABLE_SQL[table]:
                raise CoreVerificationError("core:ddl")
        indexes = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_autoindex_%'").fetchall()}
        if indexes != {EXPLICIT_INDEX}:
            raise CoreVerificationError("core:indexes")
        for name, expected_sql in INDEX_SQL.items():
            definition = connection.execute("SELECT sql FROM sqlite_master WHERE type='index' AND name=?", (name,)).fetchone()
            if definition is None or definition[0] != expected_sql:
                raise CoreVerificationError("core:ddl")
        if connection.execute("SELECT 1 FROM sqlite_master WHERE type='trigger' LIMIT 1").fetchone() is not None:
            raise CoreVerificationError("core:ddl")
        meta = connection.execute("SELECT * FROM core_meta WHERE meta_id=1").fetchone()
        if meta is None or tuple(meta.keys()) != TABLE_COLUMNS["core_meta"] or meta["schema"] != SCHEMA or meta["schema_version"] != SCHEMA_VERSION:
            raise CoreVerificationError("core:meta")
        for key in ("database_id", "chain_id", "ingress_database_id"):
            if type(meta[key]) is not str or not meta[key]:
                raise CoreVerificationError("core:identity")
        if expected_database_id is not None and meta["database_id"] != expected_database_id:
            raise CoreVerificationError("core:database-id")
        if expected_config_digest is not None and meta["config_digest"] != expected_config_digest:
            raise CoreVerificationError("core:config")
        _hex(meta["config_digest"], "core:config")
        if type(meta["config_raw"]) is not bytes or not meta["config_raw"] or len(meta["config_raw"]) > MAX_ARTIFACT_BYTES:
            raise CoreVerificationError("core:config")
        config = _verify_config(_parse(meta["config_raw"], "core:config"), str(meta["config_digest"]))
        if config["database_id"] != meta["database_id"] or config["chain_id"] != meta["chain_id"] or config["ingress_database_id"] != meta["ingress_database_id"]:
            raise CoreVerificationError("core:config")
        if type(meta["sequence"]) is not int or meta["sequence"] < 0 or type(meta["ingress_watermark"]) is not int or meta["ingress_watermark"] < 0:
            raise CoreVerificationError("core:meta")

        artifact_rows = connection.execute("SELECT * FROM core_artifacts ORDER BY created_event_sequence,artifact_id").fetchall()
        actual_artifacts: dict[str, sqlite3.Row] = {}
        for row in artifact_rows:
            artifact_id = str(row["artifact_id"])
            if artifact_id in actual_artifacts:
                raise CoreVerificationError("core:artifact-duplicate")
            _verify_artifact_value(row, config)
            actual_artifacts[artifact_id] = row

        expected_artifacts: dict[str, sqlite3.Row] = {}
        expected_sessions: dict[str, dict[str, object]] = {}
        expected_slots: dict[tuple[str, int], dict[str, object]] = {}
        stream_roots: dict[tuple[str, str], str] = {}
        stream_refs: dict[tuple[str, str], str] = {}
        stream_sequences: dict[tuple[str, str], int] = {}
        graph_report_ids: dict[str, str] = {}
        graph_digests: dict[str, str] = {}
        admission_graph_digests: dict[str, str] = {}
        graph_checks: dict[str, graph._VerifiedGraphArtifactV2] = {}
        observation_times: dict[str, int] = {}
        previous_root = GENESIS_ROOT
        previous_observed = 0
        ingress_watermark = 0
        events = connection.execute("SELECT * FROM core_events ORDER BY sequence").fetchall()
        for expected_sequence, row in enumerate(events, start=1):
            if tuple(row.keys()) != TABLE_COLUMNS["core_events"] or row["sequence"] != expected_sequence:
                raise CoreVerificationError("core:event-order")
            raw_event = row["event_raw"]
            if type(raw_event) is not bytes or not raw_event or len(raw_event) > MAX_EVENT_BYTES:
                raise CoreVerificationError("core:event-raw")
            value = _parse(raw_event, "core:event-raw")
            if set(value) != EVENT_RAW_KEYS:
                raise CoreVerificationError("core:event-keys")
            _check_common(value)
            if any(value[key] != row[key] for key in ("sequence", "event_id", "event_kind", "operation_id", "subject_id")):
                raise CoreVerificationError("core:event-table")
            if value["database_id"] != meta["database_id"] or value["chain_id"] != meta["chain_id"] or value["before_root"] != previous_root or value["observed_at"] < previous_observed:
                raise CoreVerificationError("core:event-order")
            previous_observed = int(value["observed_at"])
            kind = str(value["event_kind"])
            if kind not in EVENT_KINDS or not isinstance(value["material"], dict) or set(value["material"]) != _material_keys(kind):
                raise CoreVerificationError("core:event-material")
            material = value["material"]
            if value["material_digest"] != _digest("material", material) or value["event_id"] != _digest("event-id", {key: value[key] for key in EVENT_RAW_KEYS if key not in {"event_id", "after_root", "stream_after_root"}}) or row["receipt_digest"] != _raw_digest("receipt", raw_event):
                raise CoreVerificationError("core:event-digest")
            stream_key = (str(value["stream_kind"]), str(value["stream_id"]))
            if value["stream_before_root"] != stream_roots.get(stream_key, GENESIS_ROOT) or value["after_root"] != _event_root(value) or value["stream_after_root"] != _stream_root(value):
                raise CoreVerificationError("core:root")
            stream_roots[stream_key] = str(value["stream_after_root"])
            stream_sequences[stream_key] = int(value["sequence"])
            previous_root = str(value["after_root"])
            if kind == "ARTIFACT":
                if value["prior_state"] != "NONE" or value["next_state"] not in ARTIFACT_KINDS or value["stream_kind"] not in {"ARTIFACT", "CASE_ACTION"}:
                    raise CoreVerificationError("core:event-artifact")
                artifact_id = str(material["artifact_id"])
                row_artifact = actual_artifacts.get(artifact_id)
                if row_artifact is None or artifact_id in expected_artifacts:
                    raise CoreVerificationError("core:event-artifact")
                if row_artifact["created_event_sequence"] != value["sequence"] or row_artifact["kind"] != material["kind"] or row_artifact["profile_digest"] != material["profile_digest"] or row_artifact["source_artifact_id"] != material["source_artifact_id"] or row_artifact["predecessor_id"] != material["predecessor_id"] or row_artifact["current_state"] != material["current_state"]:
                    raise CoreVerificationError("core:event-artifact")
                raw_artifact = row_artifact["raw"]
                if type(raw_artifact) is not bytes or material["raw_length"] != len(raw_artifact) or material["raw_digest"] != _raw_digest("artifact-bytes", raw_artifact) or value["payload_digest"] != artifact_id or value["payload_length"] != len(raw_artifact):
                    raise CoreVerificationError("core:event-artifact")
                parsed_artifact = _verify_artifact_value(row_artifact, config)
                if material["kind"] == "CASE":
                    expected_stream_id = str(parsed_artifact["case_id"])
                elif material["kind"] == "CASE_ACTION":
                    expected_stream_id = str(parsed_artifact["policy"]["case_id"])
                else:
                    expected_stream_id = str(material["kind"])
                if value["stream_id"] != expected_stream_id:
                    raise CoreVerificationError("core:case-stream")
                predecessor_id = material["predecessor_id"]
                if predecessor_id is not None and predecessor_id not in expected_artifacts:
                    raise CoreVerificationError("core:artifact-predecessor")
                if material["kind"] == "GRAPH":
                    graph_digest = _raw_digest("graph-artifact", raw_artifact)
                    try:
                        graph_value = graph._parse(raw_artifact)
                        graph_profile = _graph_profile_from_artifact(graph_value)
                        if graph_profile.profile_id != NC_MEDICAID_PROFILE.source_profile_id or graph_profile.version != 3 or graph_profile.profile_digest != row_artifact["profile_digest"]:
                            raise CoreVerificationError("core:graph")
                        checked_graph = graph._new_graph_checked(
                            raw_artifact,
                            {graph_profile.profile_id: graph_profile},
                        )
                    except CoreVerificationError:
                        raise
                    except Exception:
                        raise CoreVerificationError("core:graph") from None
                    graph_report_id = graph_value.get("report", {}).get("report_id") if isinstance(graph_value.get("report"), dict) else None
                    if type(graph_report_id) is not str or len(graph_report_id) != 128 or any(char not in "0123456789abcdef" for char in graph_report_id):
                        raise CoreVerificationError("core:graph")
                    graph_report_ids[artifact_id] = graph_report_id
                    graph_digests[artifact_id] = graph_digest
                    admission_graph_digests[artifact_id] = _admission_raw_digest("graph-artifact", raw_artifact)
                    graph_checks[artifact_id] = checked_graph
                    expected_operation = _digest("graph-operation", {"graph_id": graph_report_id, "graph_digest": graph_digest})
                    expected_request = _digest("graph-request", {"graph_id": graph_report_id, "graph_digest": graph_digest})
                elif material["kind"] == "SOURCE_OBSERVATION":
                    expected_operation = _digest("source-operation", {"ingress_artifact_id": parsed_artifact["ingress_artifact_id"]})
                    expected_request = _digest("source-request", {"ingress_artifact_id": parsed_artifact["ingress_artifact_id"]})
                elif material["kind"] == "RECONCILIATION":
                    expected_operation = _digest("reconciliation-operation", {"source_artifact_id": parsed_artifact["current_source_artifact_id"]})
                    expected_request = _digest("reconciliation-request", {"source_artifact_id": parsed_artifact["current_source_artifact_id"]})
                elif material["kind"] in {"GOVERNANCE", "PRIVACY"}:
                    approval_digest = _raw_digest("approval", raw_artifact)
                    expected_operation = _digest("approval-operation", {"kind": material["kind"], "raw": approval_digest})
                    expected_request = _digest("approval-request", {"kind": material["kind"], "raw": approval_digest})
                elif material["kind"] == "CASE_ACTION":
                    expected_operation = _digest("case-action-operation", {"action_id": parsed_artifact["artifact_id"], "case_id": parsed_artifact["policy"]["case_id"]})
                    expected_request = _digest("case-action-request", {"action_id": parsed_artifact["artifact_id"], "case_id": parsed_artifact["policy"]["case_id"], "evidence_digest": parsed_artifact["assertion"]["evidence_sha3_512"]})
                else:
                    expected_operation, expected_request = _expected_case_request(raw_artifact, predecessor_id)
                if value["operation_id"] != expected_operation or value["request_digest"] != expected_request:
                    raise CoreVerificationError("core:artifact-operation")
                if material["kind"] == "SOURCE_OBSERVATION":
                    source = parsed_artifact
                    if row_artifact["source_artifact_id"] != source["ingress_artifact_id"]:
                        raise CoreVerificationError("core:source-ingress-link")
                    if material["ingress_watermark"] != source["ingress_event_sequence"]:
                        raise CoreVerificationError("core:source-watermark")
                    prior_source_id = row_artifact["predecessor_id"]
                    if prior_source_id is None:
                        if source["chronology"] != "INITIAL" or source["observation_status"] not in {"OBSERVED_NEW", "INCOMPLETE"}:
                            raise CoreVerificationError("core:source-chronology")
                    else:
                        prior_row = actual_artifacts.get(str(prior_source_id))
                        if prior_row is None or str(prior_source_id) not in expected_artifacts:
                            raise CoreVerificationError("core:source-predecessor")
                        prior_source = _parse(prior_row["raw"], "core:artifact")
                        if source["ingress_event_sequence"] <= prior_source["ingress_event_sequence"] or source["observation_time"] <= prior_source["observation_time"] or source["chronology"] != "ADVANCING":
                            raise CoreVerificationError("core:source-chronology")
                        expected_status = "INCOMPLETE" if source["source_status"] != "COMPLETE" else ("OBSERVED_CONTINUED" if source["content_root"] == prior_source["content_root"] else "OBSERVED_CHANGED")
                        if source["observation_status"] != expected_status:
                            raise CoreVerificationError("core:source-chronology")
                    graph_row = actual_artifacts.get(str(source["graph_artifact_id"]))
                    if graph_row is None or graph_row["kind"] != "GRAPH" or graph_report_ids.get(str(source["graph_artifact_id"])) != source["admission_report_id"] or graph_digests.get(str(source["graph_artifact_id"])) != source["graph_artifact_digest"] or admission_graph_digests.get(str(source["graph_artifact_id"])) != source["admission_receipt"]["graph_artifact_digest"]:
                        raise CoreVerificationError("core:source-graph")
                    ingress_watermark = max(ingress_watermark, int(source["ingress_event_sequence"]))
                if material["kind"] == "RECONCILIATION":
                    source_id = str(parsed_artifact["current_source_artifact_id"])
                    if row_artifact["source_artifact_id"] != source_id:
                        raise CoreVerificationError("core:reconciliation-source")
                    if source_id not in expected_artifacts or expected_artifacts[source_id]["kind"] != "SOURCE_OBSERVATION":
                        raise CoreVerificationError("core:reconciliation-source")
                    current_source = _parse(expected_artifacts[source_id]["raw"], "core:artifact")
                    prior_id = parsed_artifact["prior_source_artifact_id"]
                    prior_source = None
                    if prior_id is not None:
                        if prior_id not in expected_artifacts or expected_artifacts[prior_id]["kind"] != "SOURCE_OBSERVATION":
                            raise CoreVerificationError("core:reconciliation-prior")
                        prior_source = _parse(expected_artifacts[prior_id]["raw"], "core:artifact")
                    if predecessor_id is None:
                        if prior_id is not None:
                            raise CoreVerificationError("core:reconciliation-chain")
                    else:
                        predecessor_row = expected_artifacts.get(str(predecessor_id))
                        if predecessor_row is None or predecessor_row["kind"] != "RECONCILIATION":
                            raise CoreVerificationError("core:reconciliation-chain")
                        predecessor_value = _parse(predecessor_row["raw"], "core:artifact")
                        if predecessor_value["current_source_artifact_id"] != prior_id:
                            raise CoreVerificationError("core:reconciliation-chain")
                    expected_reconciliation = _expected_reconciliation(
                        current_source,
                        prior_source,
                        source_artifact_id=source_id,
                        prior_source_artifact_id=str(prior_id) if prior_id is not None else None,
                    )
                    if parsed_artifact != expected_reconciliation:
                        raise CoreVerificationError("core:reconciliation-semantic")
                if material["kind"] == "CASE":
                    case = parsed_artifact
                    if row_artifact["source_artifact_id"] != case["source_artifact_id"]:
                        raise CoreVerificationError("core:case-source")
                    reconciliation_row = expected_artifacts.get(str(case["reconciliation_artifact_id"]))
                    source_row = expected_artifacts.get(str(case["source_artifact_id"]))
                    if (
                        reconciliation_row is None
                        or reconciliation_row["kind"] != "RECONCILIATION"
                        or source_row is None
                        or source_row["kind"] != "SOURCE_OBSERVATION"
                    ):
                        raise CoreVerificationError("core:case-semantic")
                    reconciliation_value = _parse(reconciliation_row["raw"], "core:case-reconciliation")
                    source_value = _parse(source_row["raw"], "core:case-source")
                    graph_row = expected_artifacts.get(str(source_value["graph_artifact_id"]))
                    if graph_row is None or graph_row["kind"] != "GRAPH":
                        raise CoreVerificationError("core:case-semantic")
                    graph_value = _parse(graph_row["raw"], "core:case-graph")
                    if case["state"] == "OPEN":
                        if predecessor_id is not None or case != _expected_open_case(case, reconciliation_value, source_value, graph_value, config):
                            raise CoreVerificationError("core:case-chain")
                    else:
                        prior = expected_artifacts.get(str(predecessor_id))
                        if prior is None or prior["kind"] != "CASE":
                            raise CoreVerificationError("core:case-chain")
                        prior_case = _parse(prior["raw"], "core:artifact")
                        if case["case_id"] != prior_case["case_id"] or case["reconciliation_artifact_id"] != prior_case["reconciliation_artifact_id"] or case["source_artifact_id"] != prior_case["source_artifact_id"] or case["graph_artifact_id"] != prior_case["graph_artifact_id"] or case["target_finding_ids"] != prior_case["target_finding_ids"] or case["target_finding_kinds"] != prior_case["target_finding_kinds"]:
                            raise CoreVerificationError("core:case-chain")
                        if prior_case["state"] == "OPEN" and case["state"] != "ACTION_RECORDED":
                            raise CoreVerificationError("core:case-chain")
                        if prior_case["state"] == "ACTION_RECORDED" and case["state"] not in {"RESOLVED", "RETEST_FAILED_OR_INDETERMINATE"}:
                            raise CoreVerificationError("core:case-chain")
                        if case["state"] == "ACTION_RECORDED" and (case["action_artifact_id"] is None or case["action_observed_at"] is None):
                            raise CoreVerificationError("core:case-action")
                        if case["state"] == "ACTION_RECORDED":
                            action_value = None
                            action_row_id = None
                            for candidate_row in expected_artifacts.values():
                                if candidate_row["kind"] != "CASE_ACTION":
                                    continue
                                candidate_value = _parse(candidate_row["raw"], "core:case-action")
                                if candidate_row["artifact_id"] == case["action_artifact_id"]:
                                    action_value = candidate_value
                                    action_row_id = candidate_row["artifact_id"]
                                    break
                            if action_value is None or action_row_id is None:
                                raise CoreVerificationError("core:case-action")
                            policy = action_value.get("policy")
                            assertion = action_value.get("assertion")
                            if (
                                not isinstance(policy, Mapping)
                                or not isinstance(assertion, Mapping)
                                or policy.get("case_id") != case["case_id"]
                                or policy.get("current_case_artifact_id") != predecessor_id
                                or policy.get("source_artifact_id") != case["source_artifact_id"]
                                or policy.get("graph_artifact_id") != case["graph_artifact_id"]
                                or policy.get("graph_report_id") != case["graph_report_id"]
                                or policy.get("target_finding_ids") != case["target_finding_ids"]
                                or policy.get("target_finding_kinds") != case["target_finding_kinds"]
                                or case["action_observed_at"] != assertion.get("observed_at")
                            ):
                                raise CoreVerificationError("core:case-action")
                            expected_case = dict(prior_case)
                            expected_case.update({"artifact_id": "", "state": "ACTION_RECORDED", "reason": "ACTION_VERIFIED", "action_artifact_id": action_row_id, "action_observed_at": assertion["observed_at"]})
                            expected_case["artifact_id"] = _digest("case-artifact", {key: expected_case[key] for key in expected_case if key != "artifact_id"})
                            if case != expected_case:
                                raise CoreVerificationError("core:case-action")
                        if case["state"] in {"RESOLVED", "RETEST_FAILED_OR_INDETERMINATE"} and (case["retest_source_artifact_id"] is None or case["retest_graph_artifact_id"] is None or case["retest_observation_time"] is None):
                            raise CoreVerificationError("core:case-retest")
                        if case["state"] in {"RESOLVED", "RETEST_FAILED_OR_INDETERMINATE"}:
                            later_row = expected_artifacts.get(str(case["retest_source_artifact_id"]))
                            later_graph_row = expected_artifacts.get(str(case["retest_graph_artifact_id"]))
                            initial_row = expected_artifacts.get(str(case["source_artifact_id"]))
                            if (
                                later_row is None
                                or later_row["kind"] != "SOURCE_OBSERVATION"
                                or later_graph_row is None
                                or later_graph_row["kind"] != "GRAPH"
                                or initial_row is None
                            ):
                                raise CoreVerificationError("core:case-retest")
                            later_value = _parse(later_row["raw"], "core:case-retest")
                            initial_value = _parse(initial_row["raw"], "core:case-source")
                            later_graph_value = _parse(later_graph_row["raw"], "core:case-graph")
                            initial_graph_row = expected_artifacts.get(str(initial_value["graph_artifact_id"]))
                            if initial_graph_row is None:
                                raise CoreVerificationError("core:case-graph")
                            initial_graph_value = _parse(initial_graph_row["raw"], "core:case-graph")
                            if (
                                later_value["graph_artifact_id"] != case["retest_graph_artifact_id"]
                                or later_value["observation_time"] != case["retest_observation_time"]
                                or later_value["observation_time"] <= case["action_observed_at"]
                                or later_graph_value.get("subject") != initial_graph_value.get("subject")
                                or later_graph_value.get("scope") != initial_graph_value.get("scope")
                                or not isinstance(later_graph_value.get("profile"), Mapping)
                                or not isinstance(initial_graph_value.get("profile"), Mapping)
                                or later_graph_value["profile"].get("profile_id") != initial_graph_value["profile"].get("profile_id")
                                or later_graph_value["profile"].get("version") != initial_graph_value["profile"].get("version")
                                or later_graph_value["profile"].get("source_contract_digest") != initial_graph_value["profile"].get("source_contract_digest")
                            ):
                                raise CoreVerificationError("core:case-retest")
                            later_findings = {
                                str(item["kind"])
                                for item in later_graph_value.get("findings", [])
                                if isinstance(item, Mapping)
                            }
                            target_kinds = set(str(item) for item in case["target_finding_kinds"])
                            expected_state = "RESOLVED" if target_kinds.isdisjoint(later_findings) and "CONTINUITY_CONFIRMED" in later_findings else "RETEST_FAILED_OR_INDETERMINATE"
                            expected_reason = "ALL_TARGET_FINDINGS_CLEARED" if expected_state == "RESOLVED" else "TARGET_FINDINGS_REMAIN"
                            expected_case = dict(prior_case)
                            expected_case.update({"artifact_id": "", "state": expected_state, "reason": expected_reason, "retest_source_artifact_id": case["retest_source_artifact_id"], "retest_graph_artifact_id": case["retest_graph_artifact_id"], "retest_observation_time": case["retest_observation_time"]})
                            expected_case["artifact_id"] = _digest("case-artifact", {key: expected_case[key] for key in expected_case if key != "artifact_id"})
                            if case != expected_case:
                                raise CoreVerificationError("core:case-retest")
                if material["kind"] == "CASE_ACTION":
                    action = parsed_artifact
                    if predecessor_id is None or value["stream_kind"] != "CASE_ACTION":
                        raise CoreVerificationError("core:case-action")
                    prior = expected_artifacts.get(str(predecessor_id))
                    if prior is None or prior["kind"] != "CASE":
                        raise CoreVerificationError("core:case-action")
                    prior_case = _parse(prior["raw"], "core:case")
                    policy = action.get("policy")
                    assertion = action.get("assertion")
                    if (
                        not isinstance(policy, Mapping)
                        or not isinstance(assertion, Mapping)
                        or policy.get("case_id") != prior_case["case_id"]
                        or policy.get("current_case_artifact_id") != predecessor_id
                        or policy.get("source_artifact_id") != prior_case["source_artifact_id"]
                        or policy.get("graph_artifact_id") != prior_case["graph_artifact_id"]
                        or policy.get("graph_report_id") != prior_case["graph_report_id"]
                        or policy.get("target_finding_ids") != prior_case["target_finding_ids"]
                        or policy.get("target_finding_kinds") != prior_case["target_finding_kinds"]
                        or assertion.get("current_case_artifact_id") != predecessor_id
                    ):
                        raise CoreVerificationError("core:case-action")
                expected_artifacts[artifact_id] = row_artifact
                stream_refs[stream_key] = artifact_id
            elif kind == "SESSION_OPEN":
                session_id = str(value["subject_id"])
                if value["prior_state"] != "NONE" or value["next_state"] != "OPEN" or value["stream_kind"] != "SESSION" or session_id in expected_sessions:
                    raise CoreVerificationError("core:session-transition")
                if value["operation_id"] != _digest("session-operation", {"session_id": session_id, "action": "OPEN"}) or value["request_digest"] != _digest("session-request", {"session_id": session_id}) or value["payload_digest"] != material["session"]["source_artifact_id"]:
                    raise CoreVerificationError("core:session-transition")
                snap = _verify_session_material(material["session"])
                if snap["session_id"] != session_id or snap["state"] != "OPEN" or snap["last_slot"] != -1:
                    raise CoreVerificationError("core:session-transition")
                expected_session_id = _digest(
                    "session-id",
                    {
                        "source": snap["source_artifact_id"],
                        "governance": snap["governance_artifact_id"],
                        "privacy": snap["privacy_artifact_id"],
                        "config": meta["config_digest"],
                    },
                )
                if session_id != expected_session_id:
                    raise CoreVerificationError("core:session-id")
                for key, kind_expected in (("source_artifact_id", "SOURCE_OBSERVATION"), ("governance_artifact_id", "GOVERNANCE"), ("privacy_artifact_id", "PRIVACY")):
                    if snap[key] not in expected_artifacts or expected_artifacts[snap[key]]["kind"] != kind_expected:
                        raise CoreVerificationError("core:session-authority")
                gov = _parse(expected_artifacts[snap["governance_artifact_id"]]["raw"], "core:artifact")
                priv = _parse(expected_artifacts[snap["privacy_artifact_id"]]["raw"], "core:artifact")
                if (
                    stream_refs.get(("ARTIFACT", "SOURCE_OBSERVATION")) != snap["source_artifact_id"]
                    or stream_refs.get(("ARTIFACT", "GOVERNANCE")) != snap["governance_artifact_id"]
                    or stream_refs.get(("ARTIFACT", "PRIVACY")) != snap["privacy_artifact_id"]
                    or gov.get("policy_digest") != config["governance_policy_digest"]
                    or priv.get("policy_digest") != config["privacy_policy_digest"]
                    or gov.get("decision") != "GRANTED"
                    or priv.get("privacy_decision") != "GRANTED"
                    or priv.get("support_decision") != "GRANTED"
                    or any(
                        type(authority.get("valid_from")) is not int
                        or type(authority.get("valid_until")) is not int
                        or value["observed_at"] < authority["valid_from"]
                        or value["observed_at"] > authority["valid_until"]
                        for authority in (gov, priv)
                    )
                ):
                    raise CoreVerificationError("core:session-config")
                expected_sessions[session_id] = snap
            elif kind == "SESSION_START":
                session_id = str(value["subject_id"])
                prior = expected_sessions.get(session_id)
                if prior is None or prior["state"] != "OPEN" or value["prior_state"] != "OPEN" or value["next_state"] != "RUNNING" or material["delta"] != {"state": "RUNNING"}:
                    raise CoreVerificationError("core:session-transition")
                if value["operation_id"] != _digest("session-operation", {"session_id": session_id, "action": "START"}) or value["request_digest"] != _digest("session-request", {"session_id": session_id, "action": "START"}) or value["payload_digest"] != session_id:
                    raise CoreVerificationError("core:session-transition")
                if _authority_staleness(prior, expected_artifacts, stream_refs, int(value["observed_at"])) is not None:
                    raise CoreVerificationError("core:session-stale")
                prior = dict(prior); prior["state"] = "RUNNING"; expected_sessions[session_id] = prior
            elif kind == "SESSION_PAUSE":
                session_id = str(value["subject_id"])
                prior = expected_sessions.get(session_id)
                if prior is None or prior["state"] not in {"OPEN", "RUNNING"} or value["prior_state"] != prior["state"] or value["next_state"] != "PAUSED" or material["state"] != "PAUSED" or material["reason"] not in {"SOURCE_SUPERSEDED", "AUTHORITY_EXPIRED", "AUTHORITY_INDETERMINATE"}:
                    raise CoreVerificationError("core:session-transition")
                actual_heads = {
                    "SOURCE_OBSERVATION": stream_refs.get(("ARTIFACT", "SOURCE_OBSERVATION")),
                    "GOVERNANCE": stream_refs.get(("ARTIFACT", "GOVERNANCE")),
                    "PRIVACY": stream_refs.get(("ARTIFACT", "PRIVACY")),
                }
                for key in ("current_source_artifact_id", "current_governance_artifact_id", "current_privacy_artifact_id"):
                    _hex(material.get(key), "core:session-pause-binding")
                if any(material.get(key) != actual_heads[kind_name] for key, kind_name in (("current_source_artifact_id", "SOURCE_OBSERVATION"), ("current_governance_artifact_id", "GOVERNANCE"), ("current_privacy_artifact_id", "PRIVACY"))):
                    raise CoreVerificationError("core:session-pause-binding")
                expected_reason = _authority_staleness(prior, expected_artifacts, stream_refs, int(value["observed_at"]))
                if expected_reason != material["reason"]:
                    raise CoreVerificationError("core:session-pause-reason")
                trigger = material["trigger"]
                if trigger not in {"START", "OBSERVATION", "RECONCILE"}:
                    raise CoreVerificationError("core:session-pause-trigger")
                slot_number = material["slot_number"]
                observation_digest = material["observation_digest"]
                if trigger == "OBSERVATION":
                    if type(slot_number) is not int or slot_number < 0 or _hex(observation_digest, "core:session-pause-observation") != observation_digest:
                        raise CoreVerificationError("core:session-pause-observation")
                    request = {"session_id": session_id, "slot_number": slot_number}
                    expected_operation = _digest("observation-operation", request)
                    expected_request = _digest("observation-request", request)
                elif trigger == "START":
                    if slot_number is not None or observation_digest is not None:
                        raise CoreVerificationError("core:session-pause-trigger")
                    expected_operation = _digest("session-operation", {"session_id": session_id, "action": "START"})
                    expected_request = _digest("session-request", {"session_id": session_id, "action": "START"})
                else:
                    if slot_number is not None or observation_digest is not None:
                        raise CoreVerificationError("core:session-pause-trigger")
                    expected_operation = _digest("pause-operation", {"session_id": session_id, "trigger": "RECONCILE"})
                    expected_request = _digest("pause-request", {"session_id": session_id, "trigger": "RECONCILE"})
                if value["operation_id"] != expected_operation or value["request_digest"] != expected_request or value["payload_digest"] != _digest("pause-reason", {"reason": material["reason"]}):
                    raise CoreVerificationError("core:session-transition")
                prior = dict(prior); prior["state"] = "PAUSED"; expected_sessions[session_id] = prior
            else:
                session_id = str(value["subject_id"])
                prior = expected_sessions.get(session_id)
                observation = material["observation"]
                if prior is None or prior["state"] != "RUNNING" or value["prior_state"] != "RUNNING" or value["next_state"] != "RUNNING" or not isinstance(observation, dict):
                    raise CoreVerificationError("core:observation")
                if _authority_staleness(prior, expected_artifacts, stream_refs, int(value["observed_at"])) is not None:
                    raise CoreVerificationError("core:observation-stale")
                expected_observation = {"schema", "schema_version", "session_id", "slot_number", "result", "counts", "flags", "result_digest"}
                if set(observation) != expected_observation or observation["schema"] != "mirror-core-observation-v3" or observation["schema_version"] != 3 or observation["session_id"] != session_id or observation["result"] not in OBSERVATION_RESULTS or observation["flags"] != FIXED_FLAGS or set(observation["counts"]) != {"changed", "observed"} or observation["result_digest"] != _digest("observation", {key: observation[key] for key in observation if key != "result_digest"}):
                    raise CoreVerificationError("core:observation")
                slot = observation["slot_number"]
                if type(slot) is not int or slot != int(prior["last_slot"]) + 1 or slot < 0 or slot >= int(config["max_slots_per_session"]):
                    raise CoreVerificationError("core:observation-order")
                previous_observation = observation_times.get(session_id)
                if previous_observation is not None and value["observed_at"] < previous_observation + int(config["cadence_seconds"]):
                    raise CoreVerificationError("core:observation-cadence")
                result_raw = _canonical(observation)
                if value["payload_digest"] != observation["result_digest"] or value["payload_length"] != len(result_raw) or value["operation_id"] != _digest("observation-operation", {"session_id": session_id, "slot_number": slot}) or value["request_digest"] != _digest("observation-request", {"session_id": session_id, "slot_number": slot}):
                    raise CoreVerificationError("core:observation")
                expected_slots[(session_id, slot)] = {"session_id": session_id, "slot_number": slot, "result_digest": observation["result_digest"], "result_raw": result_raw}
                observation_times[session_id] = int(value["observed_at"])
                prior = dict(prior); prior["last_slot"] = slot; expected_sessions[session_id] = prior
            if kind in {"SESSION_OPEN", "SESSION_START", "SESSION_PAUSE", "OBSERVATION"}:
                stream_refs[stream_key] = str(value["subject_id"])

        if meta["sequence"] != len(events) or meta["head_root"] != previous_root or meta["ingress_watermark"] != ingress_watermark:
            raise CoreVerificationError("core:meta-root")
        if set(actual_artifacts) != set(expected_artifacts):
            raise CoreVerificationError("core:artifact-reconstruction")
        for artifact_id, expected in expected_artifacts.items():
            row = actual_artifacts.get(artifact_id)
            if row is None or any(row[key] != expected[key] for key in TABLE_COLUMNS["core_artifacts"]):
                raise CoreVerificationError("core:artifact-reconstruction")
        actual_sessions = connection.execute("SELECT * FROM core_sessions ORDER BY session_id").fetchall()
        if len(actual_sessions) != len(expected_sessions):
            raise CoreVerificationError("core:session-count")
        for row in actual_sessions:
            expected = expected_sessions.get(str(row["session_id"]))
            if expected is None:
                raise CoreVerificationError("core:session-reconstruction")
            expected_row = dict(expected); expected_row["head_root"] = stream_roots.get(("SESSION", str(row["session_id"])), GENESIS_ROOT)
            if any(row[key] != expected_row[key] for key in TABLE_COLUMNS["core_sessions"]):
                raise CoreVerificationError("core:session-reconstruction")
        actual_slots = connection.execute("SELECT * FROM core_slots ORDER BY session_id,slot_number").fetchall()
        if len(actual_slots) != len(expected_slots):
            raise CoreVerificationError("core:slot-count")
        for row in actual_slots:
            expected = expected_slots.get((str(row["session_id"]), int(row["slot_number"])))
            if expected is None or any(row[key] != expected[key] for key in TABLE_COLUMNS["core_slots"]):
                raise CoreVerificationError("core:slot-reconstruction")
        actual_heads = connection.execute("SELECT * FROM core_heads ORDER BY stream_kind,stream_id").fetchall()
        if len(actual_heads) != len(stream_roots) or {(str(row["stream_kind"]), str(row["stream_id"])) for row in actual_heads} != set(stream_roots):
            raise CoreVerificationError("core:head")
        for row in actual_heads:
            key = (str(row["stream_kind"]), str(row["stream_id"]))
            if row["head_root"] != stream_roots[key] or row["event_sequence"] != stream_sequences[key] or row["head_ref"] != stream_refs.get(key):
                raise CoreVerificationError("core:head")

        ingress_bound = False
        source_ids = tuple(str(_parse(expected_artifacts[aid]["raw"], "core:artifact")["ingress_artifact_id"]) for aid in expected_artifacts if expected_artifacts[aid]["kind"] == "SOURCE_OBSERVATION")
        if ingress_bytes is not None or ingress_path is not None:
            if ingress_bytes is not None:
                ingress_result = ingress.verify_bytes(ingress_bytes, expected_database_id=str(meta["ingress_database_id"]), expected_config_digest=str(config["ingress_config_digest"]), include_raw=True, artifact_ids=source_ids)
            elif ingress_path is not None:
                ingress_result = ingress.verify_database(ingress_path, expected_database_id=str(meta["ingress_database_id"]), expected_config_digest=str(config["ingress_config_digest"]), include_raw=True, artifact_ids=source_ids)
            else:
                raise CoreVerificationError("core:ingress-binding")
            if (
                ingress_result.get("database_id") != meta["ingress_database_id"]
                or ingress_result.get("config_digest") != config["ingress_config_digest"]
            ):
                raise CoreVerificationError("core:ingress-binding")
            selected = ingress_result.get("selected_artifacts", {})
            for ingress_id in source_ids:
                source_row = next((expected_artifacts[aid] for aid in expected_artifacts if expected_artifacts[aid]["kind"] == "SOURCE_OBSERVATION" and _parse(expected_artifacts[aid]["raw"], "core:artifact")["ingress_artifact_id"] == ingress_id), None)
                item = selected.get(ingress_id) if isinstance(selected, dict) else None
                if source_row is None or not isinstance(item, dict):
                    raise CoreVerificationError("core:ingress-binding")
                if (
                    item.get("terminal_state") != "QUARANTINED"
                    or item.get("terminal_event_kind") not in {"ADMIT", "QUARANTINE", "CONFIRM_QUARANTINE"}
                    or item.get("source_status") != "COMPLETE"
                    or item.get("page_complete") != 1
                    or item.get("freshness") != "FRESH"
                    or item.get("failure_code") is not None
                ):
                    raise CoreVerificationError("core:source-lifecycle")
                source_value = _parse(source_row["raw"], "core:artifact")
                envelope_bytes = item.get("envelope_raw")
                evidence_bytes = item.get("external_evidence_raw")
                intake_frame = item.get("intake_frame")
                if (
                    type(intake_frame) is not bytes
                    or len(intake_frame) > MAX_COMPLETE_FRAME_BYTES
                    or type(envelope_bytes) is not bytes
                    or type(evidence_bytes) is not bytes
                ):
                    raise CoreVerificationError("core:ingress-binding")
                if (
                    source_value["ingress_database_id"] != ingress_result.get("database_id")
                    or source_value["ingress_chain_id"] != ingress_result.get("chain_id")
                    or source_value["ingress_config_digest"] != ingress_result.get("config_digest")
                ):
                    raise CoreVerificationError("core:ingress-binding")
                for core_key, ingress_key in (("ingress_artifact_id", "artifact_id"), ("envelope_id", "envelope_id"), ("envelope_digest", "envelope_digest"), ("snapshot_id", "snapshot_id"), ("snapshot_root", "snapshot_root"), ("content_root", "content_root"), ("profile_id", "profile_id"), ("profile_version", "profile_version"), ("profile_digest", "profile_digest"), ("observation_time", "observation_time"), ("fetched_at", "fetched_at"), ("source_status", "source_status"), ("freshness", "freshness"), ("page_complete", "page_complete"), ("page_count", "page_count"), ("resource_count", "resource_count"), ("ingress_event_sequence", "event_sequence"), ("ingress_after_root", "event_after_root"), ("ingress_prefix_root", "event_prefix_root"), ("source_contract_digest", "source_contract_digest"), ("external_artifact_id", "external_artifact_id"), ("external_artifact_digest", "external_artifact_digest"), ("capture_id", "capture_id"), ("capture_context_digest", "capture_context_digest"), ("page_digests", "page_digests")):
                    expected_ingress_value = item.get(ingress_key)
                    if core_key == "external_artifact_digest":
                        expected_ingress_value = _admission_raw_digest("external-artifact", evidence_bytes)
                    elif core_key == "capture_context_digest":
                        context_value = item.get("capture_context")
                        if not isinstance(context_value, Mapping):
                            raise CoreVerificationError("core:ingress-binding")
                        expected_ingress_value = _admission_digest(
                            "capture-context",
                            {key: context_value[key] for key in ("subject_id", "credential_id", "enrollment_id", "subject_locator_digest", "observed_at", "fetched_at")},
                        )
                    if core_key == "page_digests":
                        expected_ingress_value = list(item.get("page_digests", ()))
                    if source_value[core_key] != expected_ingress_value:
                        raise CoreVerificationError("core:ingress-binding")
                receipt = source_value["admission_receipt"]
                if type(envelope_bytes) is not bytes or type(evidence_bytes) is not bytes or receipt["adapter_digest"] != _admission_raw_digest("adapter", envelope_bytes):
                    raise CoreVerificationError("core:ingress-binding")
                if source_value["ingress_head_root"] != item.get("event_after_root"):
                    raise CoreVerificationError("core:ingress-binding")
                graph_row = actual_artifacts.get(str(source_value["graph_artifact_id"]))
                if graph_row is None or type(graph_row["raw"]) is not bytes:
                    raise CoreVerificationError("core:source-graph")
                checked_source_graph = _replay_source_admission(
                    envelope_bytes,
                    graph_row["raw"],
                    source_value,
                    graph_checks.get(str(source_value["graph_artifact_id"])),
                    external_evidence_raw=evidence_bytes,
                    external_policy=ingress_result.get("external_policy"),
                )
                checked_summary = checked_source_graph.summary
                checked_graph_id = str(source_value["graph_artifact_id"])
                if checked_summary.get("report_id") != source_value["admission_report_id"] or checked_summary.get("profile_digest") != graph_row["profile_digest"]:
                    raise CoreVerificationError("core:source-graph")
                graph_checks[checked_graph_id] = checked_source_graph
                graph_report_ids[checked_graph_id] = str(checked_summary["report_id"])
            ingress_bound = True
        return {
            "structural_valid": True, "ingress_bound": ingress_bound,
            "schema": SCHEMA, "schema_version": SCHEMA_VERSION,
            "database_id": meta["database_id"], "chain_id": meta["chain_id"], "config_digest": meta["config_digest"],
            "config_raw": bytes(meta["config_raw"]), "sequence": meta["sequence"], "head_root": meta["head_root"],
            "ingress_database_id": meta["ingress_database_id"], "ingress_watermark": meta["ingress_watermark"],
            "artifact_count": len(expected_artifacts), "head_count": len(stream_roots), "session_count": len(expected_sessions),
            "slot_count": len(expected_slots), "event_count": len(events), "flags": dict(FIXED_FLAGS),
            "current_source_artifact_id": stream_refs.get(("ARTIFACT", "SOURCE_OBSERVATION")),
        }
    except CoreVerificationError:
        raise
    except (OSError, sqlite3.Error, TypeError, ValueError, KeyError):
        raise CoreVerificationError("core:database") from None


def verify_database(path: str | Path, *, expected_database_id: str | None = None, expected_config_digest: str | None = None, ingress_path: str | Path | None = None) -> dict[str, object]:
    connection = _open(path)
    try:
        return _verify_connection(connection, expected_database_id=expected_database_id, expected_config_digest=expected_config_digest, ingress_path=ingress_path)
    finally:
        _close_readonly(connection)


def verify_bytes(raw: bytes, *, expected_database_id: str | None = None, expected_config_digest: str | None = None, ingress_bytes: bytes | None = None) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_DATABASE_BYTES:
        raise CoreVerificationError("core:image")
    if ingress_bytes is not None and (type(ingress_bytes) is not bytes or not ingress_bytes or len(ingress_bytes) > ingress.MAX_DATABASE_BYTES):
        raise CoreVerificationError("core:ingress-image")
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(":memory:", isolation_level=None, timeout=0.25)
        connection.row_factory = sqlite3.Row
        connection.deserialize(raw)
        connection.execute("PRAGMA query_only=ON")
        _check_runtime_pragmas(connection, require_delete_journal=False)
        connection.execute("BEGIN")
        return _verify_connection(connection, expected_database_id=expected_database_id, expected_config_digest=expected_config_digest, ingress_bytes=ingress_bytes)
    except CoreVerificationError:
        raise
    except (OSError, sqlite3.Error, TypeError, ValueError, KeyError):
        raise CoreVerificationError("core:image") from None
    finally:
        _close_readonly(connection)


def logical_export(result: Mapping[str, object]) -> bytes:
    config_raw = result.get("config_raw")
    if type(config_raw) is not bytes:
        raise CoreVerificationError("core:export")
    config = _parse(config_raw, "core:config")
    return _canonical({
        "schema": f"mirror-core-logical-export-v{SCHEMA_VERSION}", "schema_version": SCHEMA_VERSION,
        "database_id": result["database_id"], "chain_id": result["chain_id"],
        "config_digest": result["config_digest"], "config": config, "sequence": result["sequence"],
        "head_root": result["head_root"], "ingress_database_id": result["ingress_database_id"],
        "ingress_watermark": result["ingress_watermark"],
        "counts": {"artifacts": result["artifact_count"], "heads": result["head_count"], "sessions": result["session_count"], "slots": result["slot_count"], "events": result["event_count"]},
        "flags": dict(FIXED_FLAGS),
    })


__all__ = [
    "SCHEMA", "SCHEMA_VERSION", "DOMAIN", "MAX_DATABASE_BYTES", "MAX_ARTIFACT_BYTES", "MAX_EVENT_BYTES",
    "TABLES", "TABLE_COLUMNS", "TABLE_SQL", "INDEX_SQL", "EXPLICIT_INDEX", "ARTIFACT_KINDS", "SESSION_STATES", "OBSERVATION_RESULTS",
    "FIXED_FLAGS", "EVENT_KINDS", "CoreVerificationError", "verify_database", "verify_bytes", "logical_export",
    "_canonical", "_digest", "_raw_digest", "_parse", "_event_root", "_stream_root", "GENESIS_ROOT",
]
