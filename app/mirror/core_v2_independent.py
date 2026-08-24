"""Independent reconstruction for the six-table Mirror Core V2 owner.

The event_raw column is the only canonical Core event authority.  This module
reads one SQLite snapshot, replays the typed event stream, reconstructs every
state table, and only then compares the derived state with the stored views.
It deliberately does not import the Core producer.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Mapping

from app.mirror import ingress_v2_independent as ingress
from app.mirror.nc_medicaid_fhir_profile import NC_MEDICAID_GRAPH_PROFILE_REGISTRY
from app.mirror import provider_trust_graph_independent as graph


SCHEMA = "mirror-core-v2"
SCHEMA_VERSION = 2
DOMAIN = "BL/MIRROR/CORE/V2/"
MAX_DATABASE_BYTES = 64 * 1024 * 1024
MAX_ARTIFACT_BYTES = 262_144
MAX_EVENT_BYTES = 786_432
GENESIS_ROOT = "0" * 128
TABLES = (
    "core_meta", "core_artifacts", "core_heads", "core_sessions", "core_slots", "core_events",
)
TABLE_COLUMNS = {
    "core_meta": ("meta_id", "schema", "schema_version", "database_id", "chain_id", "config_digest", "sequence", "head_root", "ingress_database_id", "ingress_watermark"),
    "core_artifacts": ("artifact_id", "kind", "raw", "profile_digest", "source_artifact_id", "predecessor_id", "current_state", "created_event_sequence"),
    "core_heads": ("stream_kind", "stream_id", "head_ref", "head_root", "event_sequence"),
    "core_sessions": ("session_id", "state", "source_artifact_id", "governance_artifact_id", "privacy_artifact_id", "head_root", "last_slot", "delivery_state", "delivery_job_id", "delivery_attempt", "delivery_lease_token_digest", "delivery_lease_until", "delivery_response_digest", "delivery_error_code"),
    "core_slots": ("session_id", "slot_number", "result_digest", "result_raw"),
    "core_events": ("sequence", "event_id", "event_kind", "operation_id", "subject_id", "event_raw", "receipt_digest"),
}
ARTIFACT_KINDS = ("GRAPH", "SOURCE_OBSERVATION", "RECONCILIATION", "GOVERNANCE", "PRIVACY", "CASE")
SESSION_STATES = ("OPEN", "RUNNING", "PAUSED")
DELIVERY_STATES = ("DUE", "INTENT", "UNKNOWN", "ACK", "EXHAUSTED")
OBSERVATION_RESULTS = ("PARITY", "DISCREPANCY", "INDETERMINATE")
FIXED_FLAGS = {
    "read_only": True, "observation_only": True, "synthetic_only": True,
    "production_usable": False, "activation": False, "payment_authority": False,
    "clearance_authority": False, "settlement_authority": False,
    "adjudication_authority": False, "controlled_shadow_ready": False, "proofSuiteId": None,
}
EVENT_KINDS = (
    "ARTIFACT", "SESSION_OPEN", "SESSION_START", "OBSERVATION", "SESSION_PAUSE",
    "DELIVERY_INTENT", "DELIVERY_REQUEUE", "DELIVERY_ACK", "DELIVERY_RESPONSE_UNKNOWN",
    "DELIVERY_EXHAUSTED",
)
CASE_EDGES = {
    "OPEN": {"RESPONSIBILITY"}, "RESPONSIBILITY": {"REMEDIATION"},
    "REMEDIATION": {"RETEST"}, "RETEST": {"PERSISTENCE"},
    "PERSISTENCE": {"RESOLVED", "SUPERSEDED"},
}
SESSION_FIELDS = (
    "session_id", "state", "source_artifact_id", "governance_artifact_id", "privacy_artifact_id",
    "last_slot", "delivery_state", "delivery_job_id", "delivery_attempt",
    "delivery_lease_token_digest", "delivery_lease_until", "delivery_response_digest", "delivery_error_code",
)
EVENT_RAW_KEYS = {
    "schema", "schema_version", "database_id", "chain_id", "sequence", "event_id", "event_kind",
    "stream_kind", "stream_id", "operation_id", "subject_id", "request_digest", "prior_state",
    "next_state", "attempt", "observed_at", "material", "material_digest", "payload_digest",
    "payload_length", "before_root", "after_root", "stream_before_root", "stream_after_root",
}
EXPLICIT_INDEX = "core_artifacts_kind_source_event_idx"


class CoreVerificationError(ValueError):
    """Fixed independent Core failure."""


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
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_reject_duplicate_keys, parse_constant=lambda _value: (_ for _ in ()).throw(CoreVerificationError("core:constant")))
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


def _hex(value: object, label: str) -> str:
    if type(value) is not str or len(value) != 128 or any(char not in "0123456789abcdef" for char in value):
        raise CoreVerificationError(label)
    return value


def _event_root(body: Mapping[str, object]) -> str:
    keys = ("schema", "schema_version", "database_id", "chain_id", "sequence", "event_id", "event_kind", "stream_kind", "stream_id", "operation_id", "subject_id", "request_digest", "prior_state", "next_state", "attempt", "observed_at", "material_digest", "payload_digest", "payload_length", "before_root", "stream_before_root")
    return _digest("event-root", {key: body[key] for key in keys})


def _stream_root(body: Mapping[str, object]) -> str:
    keys = ("schema", "schema_version", "database_id", "chain_id", "sequence", "event_id", "event_kind", "stream_kind", "stream_id", "operation_id", "subject_id", "prior_state", "next_state", "attempt", "observed_at", "material_digest", "payload_digest", "payload_length", "stream_before_root")
    return _digest("stream-root", {key: body[key] for key in keys})


def _table_names(connection: sqlite3.Connection) -> tuple[str, ...]:
    return tuple(row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").fetchall())


def _columns(connection: sqlite3.Connection, table: str) -> tuple[str, ...]:
    return tuple(row[1] for row in connection.execute("SELECT * FROM pragma_table_info(?) ORDER BY cid", (table,)).fetchall())


def _open(path: str | Path) -> sqlite3.Connection:
    database = Path(path)
    try:
        if not database.is_file() or database.stat().st_size > MAX_DATABASE_BYTES:
            raise CoreVerificationError("core:database")
        connection = sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True, isolation_level=None, timeout=0.25)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        return connection
    except CoreVerificationError:
        raise
    except (OSError, sqlite3.Error):
        raise CoreVerificationError("core:database") from None


def _verify_meta(connection: sqlite3.Connection) -> sqlite3.Row:
    row = connection.execute("SELECT * FROM core_meta WHERE meta_id=1").fetchone()
    if row is None or tuple(row.keys()) != TABLE_COLUMNS["core_meta"]:
        raise CoreVerificationError("core:meta")
    if row["meta_id"] != 1 or row["schema"] != SCHEMA or row["schema_version"] != SCHEMA_VERSION:
        raise CoreVerificationError("core:schema")
    _hex(row["config_digest"], "core:config")
    _hex(row["head_root"], "core:head-root")
    for key in ("database_id", "chain_id", "ingress_database_id"):
        if type(row[key]) is not str or not row[key]:
            raise CoreVerificationError("core:identity")
    if any(type(row[key]) is not int or row[key] < 0 for key in ("sequence", "ingress_watermark")):
        raise CoreVerificationError("core:sequence")
    return row


def _verify_source_projection(value: Mapping[str, object]) -> None:
    expected = {"schema", "schema_version", "kind", "artifact_id", "ingress_database_id", "ingress_artifact_id", "ingress_event_sequence", "ingress_head_root", "envelope_id", "envelope_digest", "snapshot_id", "snapshot_root", "content_root", "profile_id", "profile_version", "profile_digest", "source_status", "freshness", "page_count", "resource_count", "graph_artifact_id", "graph_artifact_digest", "observation_status", "chronology", "flags"}
    if set(value) != expected or value["schema"] != "mirror-core-source-observation-v2" or value["schema_version"] != 2 or value["kind"] != "SOURCE_OBSERVATION":
        raise CoreVerificationError("core:source-keys")
    for key in ("artifact_id", "ingress_head_root", "envelope_id", "envelope_digest", "snapshot_id", "snapshot_root", "content_root", "profile_digest", "graph_artifact_digest"):
        _hex(value[key], "core:source-" + key)
    if any(key in value for key in ("raw", "envelope", "resources", "resource_values", "bytes_hex")):
        raise CoreVerificationError("core:source-raw")
    if type(value["ingress_database_id"]) is not str or type(value["ingress_artifact_id"]) is not str:
        raise CoreVerificationError("core:source-identity")
    if value["source_status"] not in {"COMPLETE", "PARTIAL", "FAILED", "STALE"} or value["freshness"] not in {"FRESH", "UNKNOWN", "STALE"} or value["observation_status"] not in {"OBSERVED_NEW", "OBSERVED_CONTINUED", "OBSERVED_CHANGED", "INCOMPLETE", "FAILED"} or value["chronology"] not in {"INITIAL", "EQUAL", "ADVANCING", "UNKNOWN"} or value["flags"] != FIXED_FLAGS:
        raise CoreVerificationError("core:source-binding")
    if any(type(value[key]) is not int or value[key] < 0 for key in ("ingress_event_sequence", "page_count", "resource_count")):
        raise CoreVerificationError("core:source-count")
    if value["artifact_id"] != _digest("source-artifact-id", {key: value[key] for key in expected if key not in {"artifact_id", "flags"}}):
        raise CoreVerificationError("core:source-id")


def _verify_reconciliation(value: Mapping[str, object]) -> None:
    expected = {"schema", "schema_version", "kind", "artifact_id", "current_source_artifact_id", "prior_source_artifact_id", "current_content_root", "prior_content_root", "source_status", "observation_status", "chronology", "linkage", "flags"}
    if set(value) != expected or value["schema"] != "mirror-core-reconciliation-v2" or value["schema_version"] != 2 or value["kind"] != "RECONCILIATION":
        raise CoreVerificationError("core:reconciliation-keys")
    for key in ("artifact_id", "current_source_artifact_id", "current_content_root"):
        _hex(value[key], "core:reconciliation-id")
    if value["prior_source_artifact_id"] is not None:
        _hex(value["prior_source_artifact_id"], "core:reconciliation-prior")
    if value["prior_content_root"] is not None:
        _hex(value["prior_content_root"], "core:reconciliation-prior-root")
    if value["observation_status"] not in {"OBSERVED_NEW", "OBSERVED_CONTINUED", "OBSERVED_CHANGED", "INCOMPLETE", "FAILED"} or value["chronology"] not in {"INITIAL", "EQUAL", "ADVANCING", "UNKNOWN"} or value["linkage"] not in {"UNCHANGED", "LINKED", "UNLINKED"} or value["flags"] != FIXED_FLAGS:
        raise CoreVerificationError("core:reconciliation-binding")
    if value["artifact_id"] != _digest("reconciliation-id", {key: value[key] for key in expected if key != "artifact_id"}):
        raise CoreVerificationError("core:reconciliation-id")


def _verify_artifact_value(row: Mapping[str, object]) -> dict[str, object]:
    if tuple(row.keys()) != TABLE_COLUMNS["core_artifacts"]:
        raise CoreVerificationError("core:artifact-columns")
    raw = row["raw"]
    if type(raw) is not bytes:
        raise CoreVerificationError("core:artifact-raw")
    value = _parse(raw, "core:artifact")
    kind = row["kind"]
    if kind not in ARTIFACT_KINDS or value.get("kind") != kind:
        raise CoreVerificationError("core:artifact-kind")
    if kind == "GRAPH":
        expected = {"schema", "schema_version", "kind", "artifact_id", "graph", "graph_digest", "flags"}
        if set(value) != expected or value["schema"] != "mirror-core-graph-v2" or value["schema_version"] != 2 or value["flags"] != FIXED_FLAGS:
            raise CoreVerificationError("core:graph")
        try:
            graph_raw = _canonical(value["graph"])
            checked = graph.verify_bytes_v2(graph_raw, dict(NC_MEDICAID_GRAPH_PROFILE_REGISTRY))
        except Exception:
            raise CoreVerificationError("core:graph") from None
        if checked.get("accepted") is not True or value["graph_digest"] != _raw_digest("graph-artifact", graph_raw) or value["artifact_id"] != checked.get("report_id"):
            raise CoreVerificationError("core:graph")
    elif kind == "SOURCE_OBSERVATION":
        _verify_source_projection(value)
    elif kind == "RECONCILIATION":
        _verify_reconciliation(value)
    elif kind in {"GOVERNANCE", "PRIVACY"}:
        if value.get("kind") != kind or value.get("flags") != FIXED_FLAGS:
            raise CoreVerificationError("core:approval")
        expected = ({"schema", "schema_version", "kind", "artifact_id", "decision", "policy_digest", "evidence_digest", "verifier_id", "verifier_epoch", "valid_from", "valid_until", "flags"} if kind == "GOVERNANCE" else {"schema", "schema_version", "kind", "artifact_id", "privacy_decision", "support_decision", "policy_digest", "evidence_digest", "verifier_id", "verifier_epoch", "valid_from", "valid_until", "flags"})
        if set(value) != expected or value["schema_version"] != 2 or value["schema"] not in {"mirror-core-governance-v2", "mirror-core-privacy-v2"}:
            raise CoreVerificationError("core:approval")
        for key in ("artifact_id", "policy_digest", "evidence_digest"):
            _hex(value[key], "core:approval")
        if type(value["verifier_id"]) is not str or not value["verifier_id"] or type(value["verifier_epoch"]) is not int or value["verifier_epoch"] < 0 or any(type(value[key]) is not int or value[key] < 0 for key in ("valid_from", "valid_until")) or value["valid_until"] <= value["valid_from"]:
            raise CoreVerificationError("core:approval")
        if kind == "GOVERNANCE" and value["decision"] not in {"GRANTED", "DENIED", "WITHDRAWN"}:
            raise CoreVerificationError("core:governance")
        if kind == "PRIVACY" and (value["privacy_decision"] not in {"GRANTED", "DENIED", "WITHDRAWN"} or value["support_decision"] not in {"GRANTED", "DENIED", "WITHDRAWN"}):
            raise CoreVerificationError("core:privacy")
    else:
        expected = {"schema", "schema_version", "kind", "artifact_id", "case_id", "reconciliation_artifact_id", "source_artifact_id", "state", "responsibility", "remediation", "retest", "parity", "reason", "flags"}
        if set(value) != expected or value["schema"] != "mirror-core-case-v2" or value["schema_version"] != 2 or value["flags"] != FIXED_FLAGS or value["state"] not in {"OPEN", "RESPONSIBILITY", "REMEDIATION", "RETEST", "PERSISTENCE", "RESOLVED", "SUPERSEDED"}:
            raise CoreVerificationError("core:case")
        for key in ("artifact_id", "case_id", "reconciliation_artifact_id", "source_artifact_id"):
            _hex(value[key], "core:case")
        if value["responsibility"] not in {"UNKNOWN", "SHARED", "STATE_SOURCE", "PLAN_OR_PROVIDER", "RIGHTRAIL_PROCESSING"} or value["remediation"] not in {"UNOBSERVED", "PROPOSED", "ASSERTED", "VERIFIED"} or value["retest"] not in {"UNREQUESTED", "REQUESTED", "EXECUTED"} or value["parity"] not in {"UNKNOWN", "PARTIAL", "MATCHED", "DIVERGENT"} or value["reason"] not in {"SOURCE_CHANGED", "SOURCE_INCOMPLETE", "SOURCE_CONFLICTED", "OBSERVATION_ONLY"}:
            raise CoreVerificationError("core:case")
    for key in ("profile_digest",):
        _hex(row[key], "core:artifact-profile")
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
    else:
        expected_state = value["state"]
    if row["current_state"] != expected_state:
        raise CoreVerificationError("core:artifact-state")
    return value


def _verify_session_snapshot(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != set(SESSION_FIELDS):
        raise CoreVerificationError("core:session-material")
    if type(value["session_id"]) is not str or not value["session_id"] or value["state"] not in SESSION_STATES or value["delivery_state"] not in DELIVERY_STATES:
        raise CoreVerificationError("core:session-material")
    for key in ("source_artifact_id", "governance_artifact_id", "privacy_artifact_id"):
        _hex(value[key], "core:session-material")
    if type(value["last_slot"]) is not int or value["last_slot"] < -1 or type(value["delivery_attempt"]) is not int or value["delivery_attempt"] < 0:
        raise CoreVerificationError("core:session-material")
    if value["delivery_lease_until"] is not None and (type(value["delivery_lease_until"]) is not int or value["delivery_lease_until"] < 0):
        raise CoreVerificationError("core:session-material")
    if value["delivery_lease_token_digest"] is not None:
        _hex(value["delivery_lease_token_digest"], "core:token-digest")
    if value["delivery_response_digest"] is not None:
        _hex(value["delivery_response_digest"], "core:delivery-response")
    if value["delivery_state"] == "DUE" and any(value[key] is not None for key in ("delivery_lease_token_digest", "delivery_lease_until", "delivery_response_digest", "delivery_error_code")):
        raise CoreVerificationError("core:delivery-state")
    if value["delivery_state"] == "INTENT" and (value["delivery_job_id"] is None or value["delivery_lease_token_digest"] is None or value["delivery_lease_until"] is None or value["delivery_response_digest"] is not None or value["delivery_error_code"] is not None):
        raise CoreVerificationError("core:delivery-state")
    if value["delivery_state"] in {"ACK", "UNKNOWN", "EXHAUSTED"} and (value["delivery_job_id"] is None or value["delivery_lease_token_digest"] is None or value["delivery_lease_until"] is None):
        raise CoreVerificationError("core:delivery-state")
    if value["delivery_state"] == "ACK" and (value["delivery_response_digest"] is None or value["delivery_error_code"] is not None):
        raise CoreVerificationError("core:delivery-state")
    if value["delivery_state"] == "UNKNOWN" and (value["delivery_response_digest"] is not None or value["delivery_error_code"] not in {"RESPONSE_LOST", "TIMEOUT", "REMOTE_INDETERMINATE"}):
        raise CoreVerificationError("core:delivery-state")
    if value["delivery_state"] == "EXHAUSTED" and (value["delivery_response_digest"] is not None or value["delivery_error_code"] != "ATTEMPTS_EXHAUSTED"):
        raise CoreVerificationError("core:delivery-state")
    return dict(value)


def _material_keys(kind: str) -> set[str]:
    if kind == "ARTIFACT":
        return {"artifact_id", "kind", "raw_hex", "raw_digest", "raw_length", "profile_digest", "source_artifact_id", "predecessor_id", "current_state", "ingress_watermark"}
    if kind in {"SESSION_OPEN", "SESSION_START"}:
        return {"session"}
    if kind == "SESSION_PAUSE":
        return {"session", "current_source_artifact_id", "reason"}
    if kind == "OBSERVATION":
        return {"observation", "session"}
    if kind == "DELIVERY_INTENT":
        return {"session", "job_id", "delivery_id", "token_digest", "lease_until"}
    if kind == "DELIVERY_REQUEUE":
        return {"session", "job_id", "delivery_id", "expired_attempt", "prior_token_digest", "prior_lease_until", "reason"}
    if kind == "DELIVERY_ACK":
        return {"session", "job_id", "delivery_id", "token_digest", "response_digest"}
    if kind == "DELIVERY_RESPONSE_UNKNOWN":
        return {"session", "job_id", "delivery_id", "token_digest", "error_code"}
    if kind == "DELIVERY_EXHAUSTED":
        return {"session", "job_id", "delivery_id", "token_digest", "lease_until", "error_code", "max_attempts"}
    raise CoreVerificationError("core:event-kind")


def _check_common_types(value: Mapping[str, object]) -> None:
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


def verify_database(path: str | Path, *, expected_database_id: str | None = None, expected_config_digest: str | None = None, ingress_path: str | Path | None = None) -> dict[str, object]:
    connection = _open(path)
    try:
        if _table_names(connection) != tuple(sorted(TABLES)):
            raise CoreVerificationError("core:tables")
        for table, columns in TABLE_COLUMNS.items():
            if _columns(connection, table) != columns:
                raise CoreVerificationError("core:columns")
        indexes = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_autoindex_%'").fetchall()}
        if indexes != {EXPLICIT_INDEX}:
            raise CoreVerificationError("core:indexes")
        meta = _verify_meta(connection)
        if expected_database_id is not None and meta["database_id"] != expected_database_id:
            raise CoreVerificationError("core:database-id")
        if expected_config_digest is not None and meta["config_digest"] != expected_config_digest:
            raise CoreVerificationError("core:config")

        artifact_rows = connection.execute("SELECT * FROM core_artifacts ORDER BY created_event_sequence,artifact_id").fetchall()
        actual_artifacts: dict[str, dict[str, object]] = {}
        for row in artifact_rows:
            if row["artifact_id"] in actual_artifacts:
                raise CoreVerificationError("core:artifact-duplicate")
            actual_artifacts[str(row["artifact_id"])] = _verify_artifact_value(row)

        events = connection.execute("SELECT * FROM core_events ORDER BY sequence").fetchall()
        expected_artifacts: dict[str, dict[str, object]] = {}
        expected_sessions: dict[str, dict[str, object]] = {}
        expected_slots: dict[tuple[str, int], dict[str, object]] = {}
        stream_roots: dict[tuple[str, str], str] = {}
        stream_refs: dict[tuple[str, str], str] = {}
        stream_sequences: dict[tuple[str, str], int] = {}
        previous_root = GENESIS_ROOT
        previous_observed = 0
        ingress_watermark = 0

        for expected_sequence, row in enumerate(events, start=1):
            if tuple(row.keys()) != TABLE_COLUMNS["core_events"] or row["sequence"] != expected_sequence:
                raise CoreVerificationError("core:event-order")
            raw_event = bytes(row["event_raw"])
            value = _parse(raw_event, "core:event-raw")
            if set(value) != EVENT_RAW_KEYS:
                raise CoreVerificationError("core:event-keys")
            _check_common_types(value)
            if any(value[key] != row[key] for key in ("sequence", "event_id", "event_kind", "operation_id", "subject_id")):
                raise CoreVerificationError("core:event-table")
            if value["database_id"] != meta["database_id"] or value["chain_id"] != meta["chain_id"] or value["before_root"] != previous_root:
                raise CoreVerificationError("core:event-order")
            if value["observed_at"] < previous_observed:
                raise CoreVerificationError("core:chronology")
            previous_observed = int(value["observed_at"])
            if value["event_kind"] not in EVENT_KINDS:
                raise CoreVerificationError("core:event-kind")
            material = value["material"]
            if not isinstance(material, dict) or set(material) != _material_keys(str(value["event_kind"])):
                raise CoreVerificationError("core:event-material")
            if value["material_digest"] != _digest("material", material) or value["event_id"] != _digest("event-id", {key: value[key] for key in EVENT_RAW_KEYS if key not in {"event_id", "after_root", "stream_after_root"}}):
                raise CoreVerificationError("core:event-digest")
            if row["receipt_digest"] != _raw_digest("receipt", raw_event):
                raise CoreVerificationError("core:event-receipt")
            stream_key = (str(value["stream_kind"]), str(value["stream_id"]))
            if value["stream_before_root"] != stream_roots.get(stream_key, GENESIS_ROOT):
                raise CoreVerificationError("core:stream-order")
            if value["after_root"] != _event_root(value) or value["stream_after_root"] != _stream_root(value):
                raise CoreVerificationError("core:event-root")
            stream_roots[stream_key] = str(value["stream_after_root"])
            stream_sequences[stream_key] = int(value["sequence"])
            previous_root = str(value["after_root"])
            kind = str(value["event_kind"])

            if kind == "ARTIFACT":
                if value["prior_state"] != "NONE" or value["next_state"] not in ARTIFACT_KINDS or value["stream_kind"] != "ARTIFACT":
                    raise CoreVerificationError("core:event-artifact")
                if type(material["raw_hex"]) is not str or material["raw_hex"] != material["raw_hex"].lower() or len(material["raw_hex"]) % 2:
                    raise CoreVerificationError("core:event-artifact")
                try:
                    raw_artifact = bytes.fromhex(material["raw_hex"])
                except ValueError:
                    raise CoreVerificationError("core:event-artifact") from None
                if type(material["raw_length"]) is not int or material["raw_length"] != len(raw_artifact) or material["raw_digest"] != _raw_digest("artifact-bytes", raw_artifact):
                    raise CoreVerificationError("core:event-artifact")
                _hex(material["profile_digest"], "core:event-artifact")
                synthetic = {"artifact_id": material["artifact_id"], "kind": material["kind"], "raw": raw_artifact, "profile_digest": material["profile_digest"], "source_artifact_id": material["source_artifact_id"], "predecessor_id": material["predecessor_id"], "current_state": material["current_state"], "created_event_sequence": value["sequence"]}
                parsed_artifact = _verify_artifact_value(synthetic)
                expected_stream_id = str(parsed_artifact["case_id"]) if material["kind"] == "CASE" else str(value["next_state"])
                if value["stream_id"] != expected_stream_id:
                    raise CoreVerificationError("core:case-stream")
                if material["artifact_id"] != value["subject_id"] or material["artifact_id"] != value["payload_digest"] or material["kind"] != value["next_state"] or value["payload_length"] != len(raw_artifact) or type(material["ingress_watermark"]) is not int or material["ingress_watermark"] < 0:
                    raise CoreVerificationError("core:event-artifact")
                if material["kind"] == "GRAPH":
                    expected_operation = _digest("graph-operation", {"graph_id": parsed_artifact["artifact_id"], "graph_digest": parsed_artifact["graph_digest"]})
                    expected_request = _digest("graph-request", {"graph_id": parsed_artifact["artifact_id"], "graph_digest": parsed_artifact["graph_digest"]})
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
                elif material["predecessor_id"] is None:
                    expected_operation = _digest("case-operation", {"case_id": parsed_artifact["case_id"]})
                    expected_request = _digest("case-request", {"reconciliation_artifact_id": parsed_artifact["reconciliation_artifact_id"]})
                else:
                    prior_case = _parse(bytes(expected_artifacts[material["predecessor_id"]]["raw"])) if material["predecessor_id"] in expected_artifacts else None
                    if prior_case is None:
                        raise CoreVerificationError("core:case-chain")
                    supplied = {"responsibility": None, "remediation": None, "retest": None, "parity": None}
                    field_for_state = {"RESPONSIBILITY": "responsibility", "REMEDIATION": "remediation", "RETEST": "retest", "PERSISTENCE": "parity"}.get(parsed_artifact["state"])
                    if field_for_state is not None:
                        supplied[field_for_state] = parsed_artifact[field_for_state]
                    expected_operation = _digest("case-transition-operation", {"case_artifact_id": material["predecessor_id"], "next_state": parsed_artifact["state"], **supplied})
                    expected_request = _digest("case-transition-request", {"case_artifact_id": material["predecessor_id"], "next_state": parsed_artifact["state"], **supplied})
                if value["operation_id"] != expected_operation or value["request_digest"] != expected_request:
                    raise CoreVerificationError("core:artifact-operation")
                ingress_watermark = max(ingress_watermark, int(material["ingress_watermark"]))
                if material["artifact_id"] in expected_artifacts:
                    raise CoreVerificationError("core:event-artifact-duplicate")
                expected_artifacts[str(material["artifact_id"])] = {"artifact_id": material["artifact_id"], "kind": material["kind"], "raw": raw_artifact, "profile_digest": material["profile_digest"], "source_artifact_id": material["source_artifact_id"], "predecessor_id": material["predecessor_id"], "current_state": material["current_state"], "created_event_sequence": value["sequence"]}
                if material["predecessor_id"] is not None and material["predecessor_id"] not in expected_artifacts:
                    raise CoreVerificationError("core:artifact-predecessor")
                stream_refs[stream_key] = str(material["artifact_id"])
                if material["kind"] == "CASE":
                    prior_id = material["predecessor_id"]
                    if parsed_artifact["state"] == "OPEN" and prior_id is not None:
                        raise CoreVerificationError("core:case-chain")
                    if parsed_artifact["state"] != "OPEN":
                        if prior_id not in expected_artifacts or expected_artifacts[prior_id]["kind"] != "CASE":
                            raise CoreVerificationError("core:case-chain")
                        prior_case = _parse(bytes(expected_artifacts[prior_id]["raw"]))
                        if parsed_artifact["case_id"] != prior_case["case_id"] or parsed_artifact["reconciliation_artifact_id"] != prior_case["reconciliation_artifact_id"] or parsed_artifact["source_artifact_id"] != prior_case["source_artifact_id"] or parsed_artifact["state"] not in CASE_EDGES.get(prior_case["state"], set()):
                            raise CoreVerificationError("core:case-chain")
                        changed = [key for key in ("responsibility", "remediation", "retest", "parity") if parsed_artifact[key] != prior_case[key]]
                        required_change = {"RESPONSIBILITY": "responsibility", "REMEDIATION": "remediation", "RETEST": "retest", "PERSISTENCE": "parity"}.get(parsed_artifact["state"])
                        if (required_change is None and changed) or (required_change is not None and any(key != required_change for key in changed)):
                            raise CoreVerificationError("core:case-chain")
                        if parsed_artifact["state"] == "RETEST" and prior_case["remediation"] == "UNOBSERVED":
                            raise CoreVerificationError("core:case-chain")
                        if parsed_artifact["state"] == "PERSISTENCE" and prior_case["retest"] != "EXECUTED":
                            raise CoreVerificationError("core:case-chain")
                        if parsed_artifact["state"] == "RESOLVED" and (prior_case["parity"] != "MATCHED" or prior_case["remediation"] != "VERIFIED" or prior_case["retest"] != "EXECUTED"):
                            raise CoreVerificationError("core:case-chain")
            elif kind in {"SESSION_OPEN", "SESSION_START", "SESSION_PAUSE", "OBSERVATION"}:
                session_id = str(value["subject_id"])
                if kind == "SESSION_OPEN":
                    if value["prior_state"] != "NONE" or value["next_state"] != "OPEN" or session_id in expected_sessions:
                        raise CoreVerificationError("core:session-transition")
                    if value["operation_id"] != _digest("session-operation", {"session_id": session_id, "action": "OPEN"}) or value["request_digest"] != _digest("session-request", {"session_id": session_id}) or value["payload_digest"] != value["material"]["session"]["source_artifact_id"]:
                        raise CoreVerificationError("core:session-transition")
                    snap = _verify_session_snapshot(material["session"])
                    if snap["session_id"] != session_id or snap["state"] != "OPEN" or snap["last_slot"] != -1 or snap["delivery_state"] != "DUE":
                        raise CoreVerificationError("core:session-transition")
                    expected_sessions[session_id] = snap
                elif kind == "SESSION_START":
                    if value["prior_state"] != "OPEN" or value["next_state"] != "RUNNING" or session_id not in expected_sessions or expected_sessions[session_id]["state"] != "OPEN":
                        raise CoreVerificationError("core:session-transition")
                    if value["operation_id"] != _digest("session-operation", {"session_id": session_id, "action": "START"}) or value["request_digest"] != _digest("session-request", {"session_id": session_id, "action": "START"}) or value["payload_digest"] != session_id:
                        raise CoreVerificationError("core:session-transition")
                    snap = _verify_session_snapshot(material["session"])
                    if snap["session_id"] != session_id or snap["state"] != "RUNNING" or snap["last_slot"] != expected_sessions[session_id]["last_slot"]:
                        raise CoreVerificationError("core:session-transition")
                    expected_sessions[session_id] = snap
                elif kind == "SESSION_PAUSE":
                    if value["prior_state"] != "RUNNING" or value["next_state"] != "PAUSED" or session_id not in expected_sessions or expected_sessions[session_id]["state"] != "RUNNING" or material["reason"] not in {"SOURCE_SUPERSEDED", "AUTHORITY_EXPIRED", "AUTHORITY_INDETERMINATE"} or type(material["current_source_artifact_id"]) is not str:
                        raise CoreVerificationError("core:session-transition")
                    pause_request = {"session_id": session_id, "reason": material["reason"], "current_source_artifact_id": material["current_source_artifact_id"]}
                    if value["operation_id"] != _digest("pause-operation", pause_request) or value["request_digest"] != _digest("pause-request", pause_request) or value["payload_digest"] != _digest("pause-reason", {"reason": material["reason"]}):
                        raise CoreVerificationError("core:session-transition")
                    snap = _verify_session_snapshot(material["session"])
                    if snap["session_id"] != session_id or snap["state"] != "PAUSED":
                        raise CoreVerificationError("core:session-transition")
                    expected_sessions[session_id] = snap
                else:
                    if value["prior_state"] != "RUNNING" or value["next_state"] != "RUNNING" or session_id not in expected_sessions or expected_sessions[session_id]["state"] != "RUNNING":
                        raise CoreVerificationError("core:observation-transition")
                    observation = material["observation"]
                    if not isinstance(observation, dict) or set(observation) != {"schema", "schema_version", "session_id", "slot_number", "result", "counts", "flags", "result_digest"} or observation["session_id"] != session_id or observation["schema"] != "mirror-core-observation-v2" or observation["schema_version"] != 2 or observation["result"] not in OBSERVATION_RESULTS or observation["flags"] != FIXED_FLAGS or set(observation["counts"]) != {"changed", "observed"}:
                        raise CoreVerificationError("core:observation")
                    if observation["result_digest"] != _digest("observation", {key: observation[key] for key in observation if key != "result_digest"}) or value["payload_digest"] != observation["result_digest"]:
                        raise CoreVerificationError("core:observation")
                    if value["operation_id"] != _digest("observation-operation", {"session_id": session_id, "slot_number": observation["slot_number"]}) or value["request_digest"] != _digest("observation-request", {"session_id": session_id, "slot_number": observation["slot_number"]}):
                        raise CoreVerificationError("core:observation")
                    slot = observation["slot_number"]
                    if type(slot) is not int or slot != expected_sessions[session_id]["last_slot"] + 1 or slot < 0:
                        raise CoreVerificationError("core:observation-order")
                    result_raw = _canonical(observation)
                    if value["payload_length"] != len(result_raw):
                        raise CoreVerificationError("core:observation")
                    snap = _verify_session_snapshot(material["session"])
                    if snap["last_slot"] != slot or snap["state"] != "RUNNING":
                        raise CoreVerificationError("core:observation")
                    expected_slots[(session_id, slot)] = {"session_id": session_id, "slot_number": slot, "result_digest": observation["result_digest"], "result_raw": result_raw}
                    expected_sessions[session_id] = snap
            else:
                session_id = str(value["subject_id"])
                if session_id not in expected_sessions or value["stream_kind"] != "DELIVERY":
                    raise CoreVerificationError("core:delivery-stream")
                snap = _verify_session_snapshot(material["session"])
                if snap["session_id"] != session_id:
                    raise CoreVerificationError("core:delivery-material")
                job_id = material["job_id"]
                delivery_id = material["delivery_id"]
                if type(job_id) is not str or not job_id or delivery_id != _digest("delivery-id", {"session_id": session_id, "job_id": job_id}) or value["stream_id"] != delivery_id:
                    raise CoreVerificationError("core:delivery-material")
                prior = expected_sessions[session_id]
                prior_state = prior["delivery_state"]
                if kind == "DELIVERY_INTENT":
                    if value["prior_state"] != "DUE" or value["next_state"] != "INTENT" or prior_state != "DUE" or value["attempt"] != prior["delivery_attempt"] + 1 or material["token_digest"] != snap["delivery_lease_token_digest"] or material["lease_until"] != snap["delivery_lease_until"] or value["observed_at"] >= int(material["lease_until"]):
                        raise CoreVerificationError("core:delivery-transition")
                    if value["operation_id"] != _digest("delivery-intent-operation", {"session_id": session_id, "job_id": job_id, "attempt": value["attempt"], "token_digest": material["token_digest"]}) or value["request_digest"] != _digest("delivery-request", {"session_id": session_id, "job_id": job_id, "attempt": value["attempt"], "token_digest": material["token_digest"]}) or value["payload_digest"] != _digest("delivery-job", {"session_id": session_id, "job_id": job_id, "delivery_id": delivery_id}):
                        raise CoreVerificationError("core:delivery-operation")
                elif kind == "DELIVERY_REQUEUE":
                    if value["prior_state"] not in {"INTENT", "UNKNOWN"} or value["next_state"] != "DUE" or prior_state != value["prior_state"] or value["attempt"] != prior["delivery_attempt"] or material["expired_attempt"] != prior["delivery_attempt"] or material["prior_token_digest"] != prior["delivery_lease_token_digest"] or material["prior_lease_until"] != prior["delivery_lease_until"] or material["reason"] != "LEASE_EXPIRED":
                        raise CoreVerificationError("core:delivery-transition")
                    if value["operation_id"] != _digest("delivery-requeue-operation", {"session_id": session_id, "job_id": job_id, "attempt": value["attempt"]}) or value["request_digest"] != _digest("delivery-request", {"session_id": session_id, "job_id": job_id, "action": "REQUEUE", "attempt": value["attempt"], "prior_token_digest": material["prior_token_digest"]}) or value["payload_digest"] != _digest("delivery-requeue-payload", {"job_id": job_id, "attempt": value["attempt"]}):
                        raise CoreVerificationError("core:delivery-operation")
                elif kind in {"DELIVERY_ACK", "DELIVERY_RESPONSE_UNKNOWN"}:
                    expected_state = "ACK" if kind == "DELIVERY_ACK" else "UNKNOWN"
                    if value["prior_state"] != "INTENT" or value["next_state"] != expected_state or prior_state != "INTENT" or value["attempt"] != prior["delivery_attempt"] or material["token_digest"] != prior["delivery_lease_token_digest"] or value["observed_at"] >= int(prior["delivery_lease_until"]):
                        raise CoreVerificationError("core:delivery-transition")
                    if kind == "DELIVERY_ACK":
                        _hex(material["response_digest"], "core:delivery-response")
                        if snap["delivery_response_digest"] != material["response_digest"] or snap["delivery_error_code"] is not None:
                            raise CoreVerificationError("core:delivery-state")
                    elif material["error_code"] not in {"RESPONSE_LOST", "TIMEOUT", "REMOTE_INDETERMINATE"} or snap["delivery_error_code"] != material["error_code"] or snap["delivery_response_digest"] is not None:
                        raise CoreVerificationError("core:delivery-state")
                    action = "UNKNOWN" if kind == "DELIVERY_RESPONSE_UNKNOWN" else "ACK"
                    finish_values = {"session_id": session_id, "job_id": job_id, "attempt": value["attempt"], "action": action, "token_digest": material["token_digest"], "response_digest": None if kind == "DELIVERY_RESPONSE_UNKNOWN" else material["response_digest"], "code": material.get("error_code") if kind == "DELIVERY_RESPONSE_UNKNOWN" else None}
                    expected_request = {"session_id": session_id, "job_id": job_id, "attempt": value["attempt"], "action": kind, "token_digest": material["token_digest"]}
                    if value["operation_id"] != _digest("delivery-finish-operation", finish_values) or value["request_digest"] != _digest("delivery-request", expected_request) or value["payload_digest"] != _digest("delivery-response", {"job_id": job_id, "response_digest": finish_values["response_digest"], "code": finish_values["code"]}):
                        raise CoreVerificationError("core:delivery-operation")
                else:
                    if value["prior_state"] not in {"INTENT", "UNKNOWN"} or value["next_state"] != "EXHAUSTED" or prior_state != value["prior_state"] or value["attempt"] != prior["delivery_attempt"] or material["token_digest"] != prior["delivery_lease_token_digest"] or material["error_code"] != "ATTEMPTS_EXHAUSTED" or type(material["max_attempts"]) is not int or not 1 <= material["max_attempts"] <= 8 or value["attempt"] != material["max_attempts"] or value["observed_at"] < int(prior["delivery_lease_until"]):
                        raise CoreVerificationError("core:delivery-transition")
                    if value["operation_id"] != _digest("delivery-exhausted-operation", {"session_id": session_id, "job_id": job_id, "attempt": value["attempt"]}) or value["request_digest"] != _digest("delivery-request", {"session_id": session_id, "job_id": job_id, "action": "EXHAUSTED", "attempt": value["attempt"]}) or value["payload_digest"] != _digest("delivery-exhausted-payload", {"job_id": job_id, "attempt": value["attempt"]}):
                        raise CoreVerificationError("core:delivery-operation")
                expected_sessions[session_id] = snap
                stream_refs[stream_key] = delivery_id
            if kind in {"SESSION_OPEN", "SESSION_START", "SESSION_PAUSE", "OBSERVATION"}:
                stream_refs[stream_key] = str(value["subject_id"])
            if kind == "ARTIFACT":
                stream_refs[stream_key] = str(value["payload_digest"])

        if meta["sequence"] != len(events) or meta["head_root"] != previous_root or meta["ingress_watermark"] != ingress_watermark:
            raise CoreVerificationError("core:meta-root")
        if set(actual_artifacts) != set(expected_artifacts):
            raise CoreVerificationError("core:artifact-reconstruction")
        for artifact_id, expected in expected_artifacts.items():
            row = connection.execute("SELECT * FROM core_artifacts WHERE artifact_id=?", (artifact_id,)).fetchone()
            if row is None or any(row[key] != expected[key] for key in TABLE_COLUMNS["core_artifacts"]):
                raise CoreVerificationError("core:artifact-reconstruction")
        actual_sessions = connection.execute("SELECT * FROM core_sessions ORDER BY session_id").fetchall()
        if len(actual_sessions) != len(expected_sessions):
            raise CoreVerificationError("core:session-count")
        for row in actual_sessions:
            expected = expected_sessions.get(str(row["session_id"]))
            if expected is None:
                raise CoreVerificationError("core:session-reconstruction")
            expected_row = dict(expected)
            expected_row["head_root"] = stream_roots.get(("SESSION", str(row["session_id"])), GENESIS_ROOT)
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
        if ingress_path is not None:
            source_ids = tuple(str(actual_artifacts[aid]["ingress_artifact_id"]) for aid in expected_artifacts if expected_artifacts[aid]["kind"] == "SOURCE_OBSERVATION")
            if source_ids:
                snapshots = ingress.read_artifact_snapshots(ingress_path, source_ids)
                for aid in expected_artifacts:
                    value = actual_artifacts[aid]
                    if value.get("kind") != "SOURCE_OBSERVATION":
                        continue
                    source = snapshots.get(str(value["ingress_artifact_id"]))
                    if source is None or source["artifact_id"] != value["ingress_artifact_id"] or source["envelope_id"] != value["envelope_id"] or source["content_root"] != value["content_root"] or source["event_sequence"] != value["ingress_event_sequence"]:
                        raise CoreVerificationError("core:ingress-binding")
        return {
            "accepted": True, "schema": SCHEMA, "schema_version": SCHEMA_VERSION,
            "database_id": meta["database_id"], "chain_id": meta["chain_id"], "config_digest": meta["config_digest"],
            "sequence": meta["sequence"], "head_root": meta["head_root"], "ingress_database_id": meta["ingress_database_id"], "ingress_watermark": meta["ingress_watermark"],
            "artifact_count": len(expected_artifacts), "head_count": len(stream_roots), "session_count": len(expected_sessions), "slot_count": len(expected_slots), "event_count": len(events),
            "flags": dict(FIXED_FLAGS), "current_source_artifact_id": stream_refs.get(("ARTIFACT", "SOURCE_OBSERVATION")),
        }
    except CoreVerificationError:
        raise
    except (OSError, sqlite3.Error, TypeError, ValueError, KeyError):
        raise CoreVerificationError("core:database") from None
    finally:
        try:
            connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        connection.close()


def logical_export(result: Mapping[str, object]) -> bytes:
    return _canonical({
        "schema": "mirror-core-logical-export-v2", "schema_version": 2, "database_id": result["database_id"], "chain_id": result["chain_id"], "config_digest": result["config_digest"], "sequence": result["sequence"], "head_root": result["head_root"], "ingress_database_id": result["ingress_database_id"], "ingress_watermark": result["ingress_watermark"],
        "counts": {"artifacts": result["artifact_count"], "heads": result["head_count"], "sessions": result["session_count"], "slots": result["slot_count"], "events": result["event_count"]}, "flags": dict(FIXED_FLAGS),
    })


__all__ = ["SCHEMA", "SCHEMA_VERSION", "DOMAIN", "MAX_DATABASE_BYTES", "MAX_ARTIFACT_BYTES", "MAX_EVENT_BYTES", "TABLES", "TABLE_COLUMNS", "EXPLICIT_INDEX", "ARTIFACT_KINDS", "SESSION_STATES", "DELIVERY_STATES", "OBSERVATION_RESULTS", "FIXED_FLAGS", "EVENT_KINDS", "CoreVerificationError", "verify_database", "logical_export", "_canonical", "_digest", "_raw_digest", "_parse", "_event_root", "_stream_root", "GENESIS_ROOT"]
