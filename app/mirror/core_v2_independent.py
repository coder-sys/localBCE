"""Independent verifier for the six-table Mirror core owner."""

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
GENESIS_ROOT = "0" * 128
TABLES = (
    "core_meta",
    "core_artifacts",
    "core_heads",
    "core_sessions",
    "core_slots",
    "core_events",
)
ARTIFACT_KINDS = (
    "GRAPH",
    "SOURCE_OBSERVATION",
    "RECONCILIATION",
    "GOVERNANCE",
    "PRIVACY",
    "CASE",
)
SESSION_STATES = ("OPEN", "RUNNING", "PAUSED", "COMPLETED", "ABORTED")
OBSERVATION_RESULTS = ("PARITY", "DISCREPANCY", "INDETERMINATE")
FIXED_FLAGS = {
    "read_only": True,
    "observation_only": True,
    "synthetic_only": True,
    "production_usable": False,
    "activation": False,
    "payment_authority": False,
    "clearance_authority": False,
    "settlement_authority": False,
    "adjudication_authority": False,
    "controlled_shadow_ready": False,
    "proofSuiteId": None,
}
EVENT_KINDS = (
    "ARTIFACT",
    "SESSION_OPEN",
    "SESSION_START",
    "OBSERVATION",
    "SESSION_PAUSE",
    "CASE_ADVANCE",
    "DELIVERY_INTENT",
    "DELIVERY_ACK",
    "DELIVERY_RESPONSE_UNKNOWN",
    "DELIVERY_REQUEUE",
)
CASE_EDGES = {
    "OPEN": {"RESPONSIBILITY"},
    "RESPONSIBILITY": {"REMEDIATION"},
    "REMEDIATION": {"RETEST"},
    "RETEST": {"PERSISTENCE"},
    "PERSISTENCE": {"RESOLVED", "SUPERSEDED"},
}


class CoreVerificationError(ValueError):
    """Fixed independent core failure."""


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
    if type(raw) is not bytes or not raw or len(raw) > MAX_ARTIFACT_BYTES:
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


def _event_root(sequence: int, previous: str, event_id: str, kind: str, subject_id: str, next_state: str, material_digest: str, stream_kind: str = "OWNER", stream_id: str | None = None) -> str:
    return _digest(
        "event-root",
        {
            "sequence": sequence,
            "previous_root": previous,
            "event_id": event_id,
            "event_kind": kind,
            "subject_id": subject_id,
            "stream_kind": stream_kind,
            "stream_id": stream_id or subject_id,
            "next_state": next_state,
            "material_digest": material_digest,
        },
    )


def _stream_root(sequence: int, previous: str, event_id: str, stream_kind: str, stream_id: str, next_state: str, material_digest: str) -> str:
    return _digest(
        "stream-root",
        {
            "sequence": sequence,
            "previous_root": previous,
            "event_id": event_id,
            "stream_kind": stream_kind,
            "stream_id": stream_id,
            "next_state": next_state,
            "material_digest": material_digest,
        },
    )


def _table_names(connection: sqlite3.Connection) -> tuple[str, ...]:
    return tuple(row[0] for row in connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall())


def _columns(connection: sqlite3.Connection, table: str) -> tuple[str, ...]:
    return tuple(row[1] for row in connection.execute(
        "SELECT * FROM pragma_table_info(?) ORDER BY cid", (table,)
    ).fetchall())


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
    row = connection.execute("SELECT * FROM core_meta").fetchone()
    if row is None or tuple(row.keys()) != (
        "meta_id", "schema", "schema_version", "database_id", "chain_id",
        "config_digest", "sequence", "head_root", "ingress_database_id",
        "ingress_watermark", "session_count",
    ):
        raise CoreVerificationError("core:meta")
    if row["meta_id"] != 1 or row["schema"] != SCHEMA or row["schema_version"] != SCHEMA_VERSION:
        raise CoreVerificationError("core:schema")
    for key in ("config_digest", "head_root"):
        _hex(row[key], "core:" + key)
    if row["head_root"] != GENESIS_ROOT and len(row["head_root"]) != 128:
        raise CoreVerificationError("core:head-root")
    for key in ("database_id", "chain_id", "ingress_database_id"):
        if type(row[key]) is not str or not row[key]:
            raise CoreVerificationError("core:identity")
    if type(row["sequence"]) is not int or row["sequence"] < 0 or type(row["ingress_watermark"]) is not int or row["ingress_watermark"] < 0 or type(row["session_count"]) is not int or row["session_count"] < 0:
        raise CoreVerificationError("core:sequence")
    return row


def _verify_source_projection(value: Mapping[str, object]) -> None:
    expected = {
        "schema", "schema_version", "kind", "artifact_id", "ingress_database_id",
        "ingress_artifact_id", "ingress_event_sequence", "ingress_head_root",
        "envelope_id", "envelope_digest", "snapshot_id", "snapshot_root",
        "content_root", "profile_id", "profile_version", "profile_digest",
        "source_status", "freshness", "page_count", "resource_count",
        "graph_artifact_id", "graph_artifact_digest", "observation_status",
        "chronology", "flags",
    }
    if set(value) != expected or value["schema"] != "mirror-core-source-observation-v2" or value["schema_version"] != 2 or value["kind"] != "SOURCE_OBSERVATION":
        raise CoreVerificationError("core:source-keys")
    for key in (
        "artifact_id", "ingress_head_root", "envelope_id", "envelope_digest",
        "snapshot_id", "snapshot_root", "content_root", "profile_digest",
        "graph_artifact_digest",
    ):
        _hex(value[key], "core:source-" + key)
    if any(key in value for key in ("raw", "envelope", "resources", "resource_values", "bytes_hex")):
        raise CoreVerificationError("core:source-raw")
    if type(value["ingress_database_id"]) is not str or type(value["ingress_artifact_id"]) is not str:
        raise CoreVerificationError("core:source-identity")
    if value["source_status"] not in {"COMPLETE", "PARTIAL", "FAILED", "STALE"} or value["freshness"] not in {"FRESH", "UNKNOWN", "STALE"}:
        raise CoreVerificationError("core:source-status")
    if value["observation_status"] not in {"OBSERVED_NEW", "OBSERVED_CONTINUED", "OBSERVED_CHANGED", "INCOMPLETE", "FAILED"}:
        raise CoreVerificationError("core:source-observation")
    if value["chronology"] not in {"INITIAL", "EQUAL", "ADVANCING", "UNKNOWN"}:
        raise CoreVerificationError("core:source-chronology")
    if value["flags"] != FIXED_FLAGS:
        raise CoreVerificationError("core:source-flags")
    expected_id = _digest(
        "source-artifact-id",
        {key: value[key] for key in expected if key not in {"artifact_id", "flags"}},
    )
    if value["artifact_id"] != expected_id:
        raise CoreVerificationError("core:source-id")


def _verify_reconciliation(value: Mapping[str, object]) -> None:
    expected = {
        "schema", "schema_version", "kind", "artifact_id", "current_source_artifact_id",
        "prior_source_artifact_id", "current_content_root", "prior_content_root",
        "source_status", "observation_status", "chronology", "linkage", "flags",
    }
    if set(value) != expected or value["schema"] != "mirror-core-reconciliation-v2" or value["kind"] != "RECONCILIATION":
        raise CoreVerificationError("core:reconciliation-keys")
    for key in ("artifact_id", "current_source_artifact_id", "current_content_root"):
        _hex(value[key], "core:reconciliation-id")
    if value["prior_source_artifact_id"] is not None:
        _hex(value["prior_source_artifact_id"], "core:reconciliation-prior")
    if value["prior_content_root"] is not None:
        _hex(value["prior_content_root"], "core:reconciliation-prior-root")
    if value["observation_status"] not in {"OBSERVED_NEW", "OBSERVED_CONTINUED", "OBSERVED_CHANGED", "INCOMPLETE", "FAILED"}:
        raise CoreVerificationError("core:reconciliation-status")
    if value["chronology"] not in {"INITIAL", "EQUAL", "ADVANCING", "UNKNOWN"} or value["linkage"] not in {"UNCHANGED", "LINKED", "UNLINKED"}:
        raise CoreVerificationError("core:reconciliation-binding")
    if value["flags"] != FIXED_FLAGS:
        raise CoreVerificationError("core:reconciliation-flags")
    expected_id = _digest("reconciliation-id", {key: value[key] for key in expected if key != "artifact_id"})
    if value["artifact_id"] != expected_id:
        raise CoreVerificationError("core:reconciliation-id")


def _verify_artifact(row: sqlite3.Row) -> dict[str, object]:
    expected = (
        "artifact_id", "kind", "raw", "profile_digest", "source_artifact_id",
        "predecessor_id", "sequence", "current_state", "created_event_sequence",
    )
    if tuple(row.keys()) != expected:
        raise CoreVerificationError("core:artifact-columns")
    raw = row["raw"]
    value = _parse(raw, "core:artifact")
    if value.get("kind") != row["kind"] or row["kind"] not in ARTIFACT_KINDS:
        raise CoreVerificationError("core:artifact-kind")
    if row["kind"] == "GRAPH":
        try:
            expected_graph_keys = {"schema", "schema_version", "kind", "artifact_id", "graph", "graph_digest", "flags"}
            if set(value) != expected_graph_keys or value.get("schema") != "mirror-core-graph-v2" or value.get("schema_version") != 2 or value.get("flags") != FIXED_FLAGS:
                raise CoreVerificationError("core:graph")
            graph_value = value.get("graph")
            graph_raw = _canonical(graph_value)
            checked = graph.verify_bytes_v2(graph_raw, dict(NC_MEDICAID_GRAPH_PROFILE_REGISTRY))
            if value.get("graph_digest") != _raw_digest("graph-artifact", graph_raw) or value.get("artifact_id") != checked.get("report_id"):
                raise CoreVerificationError("core:graph")
        except Exception:
            raise CoreVerificationError("core:graph")
        if checked.get("accepted") is not True:
            raise CoreVerificationError("core:graph")
    elif row["kind"] == "SOURCE_OBSERVATION":
        _verify_source_projection(value)
    elif row["kind"] == "RECONCILIATION":
        _verify_reconciliation(value)
    elif row["kind"] in {"GOVERNANCE", "PRIVACY"}:
        if value.get("kind") != row["kind"] or value.get("flags") != FIXED_FLAGS:
            raise CoreVerificationError("core:approval")
        expected_approval_keys = (
            {"schema", "schema_version", "kind", "artifact_id", "decision", "policy_digest", "evidence_digest", "verifier_id", "verifier_epoch", "valid_from", "valid_until", "flags"}
            if row["kind"] == "GOVERNANCE" else
            {"schema", "schema_version", "kind", "artifact_id", "privacy_decision", "support_decision", "policy_digest", "evidence_digest", "verifier_id", "verifier_epoch", "valid_from", "valid_until", "flags"}
        )
        if set(value) != expected_approval_keys or value.get("schema") not in {"mirror-core-governance-v2", "mirror-core-privacy-v2"} or value.get("schema_version") != 2:
            raise CoreVerificationError("core:approval")
        if type(value.get("artifact_id")) is not str or len(value["artifact_id"]) != 128 or any(char not in "0123456789abcdef" for char in value["artifact_id"]):
            raise CoreVerificationError("core:approval")
        if type(value.get("policy_digest")) is not str or len(value["policy_digest"]) != 128 or any(char not in "0123456789abcdef" for char in value["policy_digest"]):
            raise CoreVerificationError("core:approval")
        if type(value.get("evidence_digest")) is not str or len(value["evidence_digest"]) != 128 or any(char not in "0123456789abcdef" for char in value["evidence_digest"]):
            raise CoreVerificationError("core:approval")
        if type(value.get("verifier_id")) is not str or not value["verifier_id"] or type(value.get("verifier_epoch")) is not int or value["verifier_epoch"] < 0:
            raise CoreVerificationError("core:approval")
        for key in ("valid_from", "valid_until"):
            if type(value.get(key)) is not int or value[key] < 0:
                raise CoreVerificationError("core:approval")
        if value["valid_until"] <= value["valid_from"]:
            raise CoreVerificationError("core:approval")
        if value.get("decision") not in {"GRANTED", "DENIED", "WITHDRAWN"} and row["kind"] == "GOVERNANCE":
            raise CoreVerificationError("core:governance")
        if row["kind"] == "PRIVACY" and (
            value.get("privacy_decision") not in {"GRANTED", "DENIED", "WITHDRAWN"}
            or value.get("support_decision") not in {"GRANTED", "DENIED", "WITHDRAWN"}
        ):
            raise CoreVerificationError("core:privacy")
    elif row["kind"] == "CASE":
        expected_case_keys = {"schema", "schema_version", "kind", "artifact_id", "case_id", "reconciliation_artifact_id", "source_artifact_id", "state", "responsibility", "remediation", "retest", "parity", "reason", "flags"}
        if set(value) != expected_case_keys or value.get("schema") != "mirror-core-case-v2" or value.get("schema_version") != 2 or value.get("kind") != "CASE" or value.get("state") not in {"OPEN", "RESPONSIBILITY", "REMEDIATION", "RETEST", "PERSISTENCE", "RESOLVED", "SUPERSEDED"} or value.get("flags") != FIXED_FLAGS:
            raise CoreVerificationError("core:case")
        for key in ("artifact_id", "case_id", "reconciliation_artifact_id", "source_artifact_id"):
            if type(value.get(key)) is not str or len(value[key]) != 128 or any(char not in "0123456789abcdef" for char in value[key]):
                raise CoreVerificationError("core:case")
        if value.get("responsibility") not in {"UNKNOWN", "SHARED", "STATE_SOURCE", "PLAN_OR_PROVIDER", "RIGHTRAIL_PROCESSING"} or value.get("remediation") not in {"UNOBSERVED", "PROPOSED", "ASSERTED", "VERIFIED"} or value.get("retest") not in {"UNREQUESTED", "REQUESTED", "EXECUTED"} or value.get("parity") not in {"UNKNOWN", "PARTIAL", "MATCHED", "DIVERGENT"} or value.get("reason") not in {"SOURCE_CHANGED", "SOURCE_INCOMPLETE", "SOURCE_CONFLICTED", "OBSERVATION_ONLY"}:
            raise CoreVerificationError("core:case")
    expected_id = _digest(
        "artifact-row-id",
        {"kind": row["kind"], "raw": _raw_digest("artifact-bytes", raw), "predecessor_id": row["predecessor_id"], "sequence": row["sequence"]},
    )
    if row["artifact_id"] != expected_id:
        raise CoreVerificationError("core:artifact-id")
    if (
        type(row["sequence"]) is not int
        or row["sequence"] <= 0
        or type(row["created_event_sequence"]) is not int
        or row["created_event_sequence"] != row["sequence"]
    ):
        raise CoreVerificationError("core:artifact-sequence")
    expected_state = {
        "GRAPH": "GRAPH",
        "SOURCE_OBSERVATION": value["observation_status"] if row["kind"] == "SOURCE_OBSERVATION" else None,
        "RECONCILIATION": value["observation_status"] if row["kind"] == "RECONCILIATION" else None,
        "GOVERNANCE": value["decision"] if row["kind"] == "GOVERNANCE" else None,
        "PRIVACY": value["privacy_decision"] if row["kind"] == "PRIVACY" else None,
        "CASE": value["state"] if row["kind"] == "CASE" else None,
    }[row["kind"]]
    if row["current_state"] != expected_state:
        raise CoreVerificationError("core:artifact-state")
    if type(row["profile_digest"]) is not str or len(row["profile_digest"]) != 128:
        raise CoreVerificationError("core:artifact-profile")
    return dict(value)


def verify_database(path: str | Path, *, expected_database_id: str | None = None, expected_config_digest: str | None = None, ingress_path: str | Path | None = None) -> dict[str, object]:
    connection = _open(path)
    try:
        if _table_names(connection) != tuple(sorted(TABLES)):
            raise CoreVerificationError("core:tables")
        expected_columns = {
            "core_meta": ("meta_id", "schema", "schema_version", "database_id", "chain_id", "config_digest", "sequence", "head_root", "ingress_database_id", "ingress_watermark", "session_count"),
            "core_artifacts": ("artifact_id", "kind", "raw", "profile_digest", "source_artifact_id", "predecessor_id", "sequence", "current_state", "created_event_sequence"),
            "core_heads": ("stream_kind", "stream_id", "artifact_id", "head_root", "event_sequence"),
            "core_sessions": ("session_id", "state", "source_artifact_id", "governance_artifact_id", "privacy_artifact_id", "operation_id", "head_root", "last_slot", "lease_until", "delivery_state", "delivery_job_id", "delivery_attempt", "delivery_lease_token", "delivery_lease_until", "delivery_response_digest", "delivery_error_code"),
            "core_slots": ("session_id", "slot_number", "state", "attempt", "lease_token", "lease_until", "result_digest", "result_raw"),
            "core_events": ("sequence", "event_id", "event_kind", "database_id", "chain_id", "stream_kind", "stream_id", "operation_id", "subject_id", "request_digest", "prior_state", "next_state", "attempt", "before_root", "after_root", "stream_before_root", "stream_after_root", "material_digest", "payload_digest", "payload_length", "event_raw", "receipt_digest"),
        }
        for table, columns in expected_columns.items():
            if _columns(connection, table) != columns:
                raise CoreVerificationError("core:columns")
        meta = _verify_meta(connection)
        if expected_database_id is not None and meta["database_id"] != expected_database_id:
            raise CoreVerificationError("core:database-id")
        if expected_config_digest is not None and meta["config_digest"] != expected_config_digest:
            raise CoreVerificationError("core:config")
        rows = connection.execute("SELECT * FROM core_artifacts ORDER BY sequence").fetchall()
        artifacts = {row["artifact_id"]: _verify_artifact(row) for row in rows}
        artifact_rows = {row["artifact_id"]: row for row in rows}
        if len(artifacts) != len(rows):
            raise CoreVerificationError("core:artifact-duplicate")
        for row in rows:
            if row["kind"] != "CASE":
                continue
            value = artifacts[row["artifact_id"]]
            predecessor_id = row["predecessor_id"]
            if value["state"] == "OPEN":
                if predecessor_id is not None:
                    raise CoreVerificationError("core:case-chain")
                continue
            if type(predecessor_id) is not str or predecessor_id not in artifacts or artifact_rows[predecessor_id]["kind"] != "CASE":
                raise CoreVerificationError("core:case-chain")
            predecessor = artifacts[predecessor_id]
            if predecessor["case_id"] != value["case_id"] or predecessor["reconciliation_artifact_id"] != value["reconciliation_artifact_id"] or predecessor["source_artifact_id"] != value["source_artifact_id"]:
                raise CoreVerificationError("core:case-chain")
            if value["state"] not in CASE_EDGES.get(predecessor["state"], set()):
                raise CoreVerificationError("core:case-transition")
            changed = [
                key for key in ("responsibility", "remediation", "retest", "parity")
                if predecessor[key] != value[key]
            ]
            expected_change = {
                "RESPONSIBILITY": "responsibility",
                "REMEDIATION": "remediation",
                "RETEST": "retest",
                "PERSISTENCE": "parity",
            }.get(value["state"])
            if expected_change is None:
                if changed:
                    raise CoreVerificationError("core:case-chain")
            elif any(key != expected_change for key in changed):
                raise CoreVerificationError("core:case-chain")
            if value["state"] == "RETEST" and predecessor["remediation"] == "UNOBSERVED":
                raise CoreVerificationError("core:case-chain")
            if value["state"] == "PERSISTENCE" and predecessor["retest"] != "EXECUTED":
                raise CoreVerificationError("core:case-chain")
            if value["state"] == "RESOLVED" and (predecessor["parity"] != "MATCHED" or predecessor["remediation"] != "VERIFIED" or predecessor["retest"] != "EXECUTED"):
                raise CoreVerificationError("core:case-chain")
        ingress_snapshot: dict[str, dict[str, object]] = {}
        if ingress_path is not None:
            source_ids = tuple(
                str(value["ingress_artifact_id"])
                for value in artifacts.values()
                if value.get("kind") == "SOURCE_OBSERVATION"
            )
            if source_ids:
                ingress_snapshot = ingress.read_artifact_snapshots(ingress_path, source_ids)
        for artifact_id, value in artifacts.items():
            if value.get("kind") == "SOURCE_OBSERVATION" and ingress_path is not None:
                projection = _verify_source_projection(value)
                ing = ingress_snapshot.get(str(value["ingress_artifact_id"]))
                if ing is None:
                    raise CoreVerificationError("core:ingress-binding")
                if ing["artifact_id"] != value["ingress_artifact_id"] or ing["envelope_id"] != value["envelope_id"] or ing["content_root"] != value["content_root"] or ing["event_sequence"] != value["ingress_event_sequence"]:
                    raise CoreVerificationError("core:ingress-binding")
        events = connection.execute("SELECT * FROM core_events ORDER BY sequence").fetchall()
        previous = GENESIS_ROOT
        artifact_states: dict[str, str] = {}
        session_states: dict[str, str] = {}
        slot_states: dict[tuple[str, int], str] = {}
        stream_roots: dict[tuple[str, str], str] = {}
        stream_refs: dict[tuple[str, str], str] = {}
        delivery_states: dict[str, tuple[str, int, str]] = {}
        for expected_sequence, row in enumerate(events, start=1):
            if row["sequence"] != expected_sequence or row["database_id"] != meta["database_id"] or row["chain_id"] != meta["chain_id"] or row["before_root"] != previous:
                raise CoreVerificationError("core:event-order")
            value = _parse(row["event_raw"], "core:event-raw")
            required = {
                "schema", "schema_version", "database_id", "chain_id", "sequence",
                "event_id", "event_kind", "stream_kind", "stream_id", "operation_id", "subject_id",
                "request_digest", "prior_state", "next_state", "attempt",
                "before_root", "after_root", "stream_before_root", "stream_after_root", "material_digest", "payload_digest",
                "payload_length",
            }
            row_event_keys = required - {"schema", "schema_version"}
            if set(value) != required or any(value[key] != row[key] for key in row_event_keys):
                raise CoreVerificationError("core:event-receipt")
            if row["event_kind"] not in EVENT_KINDS:
                raise CoreVerificationError("core:event-kind")
            if row["event_id"] != _digest("event-id", {key: value[key] for key in required if key not in {"event_id", "after_root", "stream_after_root"}}):
                raise CoreVerificationError("core:event-id")
            if row["receipt_digest"] != _raw_digest("receipt", row["event_raw"]):
                raise CoreVerificationError("core:event-receipt")
            expected_after = _event_root(row["sequence"], previous, row["event_id"], row["event_kind"], row["subject_id"], row["next_state"], row["material_digest"], row["stream_kind"], row["stream_id"])
            if row["after_root"] != expected_after:
                raise CoreVerificationError("core:event-root")
            stream_key = (str(row["stream_kind"]), str(row["stream_id"]))
            if row["stream_before_root"] != stream_roots.get(stream_key, GENESIS_ROOT):
                raise CoreVerificationError("core:stream-order")
            expected_stream_after = _stream_root(
                row["sequence"], row["stream_before_root"], row["event_id"],
                row["stream_kind"], row["stream_id"], row["next_state"], row["material_digest"],
            )
            if row["stream_after_root"] != expected_stream_after:
                raise CoreVerificationError("core:stream-root")
            stream_roots[stream_key] = row["stream_after_root"]
            stream_refs[stream_key] = str(row["payload_digest"] if row["event_kind"] == "ARTIFACT" else row["stream_id"])
            if row["event_kind"] == "ARTIFACT":
                if row["payload_digest"] not in artifacts or row["prior_state"] != "NONE" or row["next_state"] not in ARTIFACT_KINDS:
                    raise CoreVerificationError("core:event-artifact")
                artifact_row = artifact_rows[row["payload_digest"]]
                if (
                    row["subject_id"] != row["payload_digest"]
                    or row["stream_kind"] != "ARTIFACT"
                    or row["stream_id"] != row["next_state"]
                    or row["payload_length"] != len(bytes(artifact_row["raw"]))
                    or row["sequence"] != artifact_row["sequence"]
                    or row["sequence"] != artifact_row["created_event_sequence"]
                    or row["material_digest"] != _digest(
                        "material",
                        {
                            "kind": artifact_row["kind"],
                            "raw": _raw_digest("artifact-bytes", bytes(artifact_row["raw"])),
                            "predecessor_id": artifact_row["predecessor_id"],
                            "sequence": artifact_row["sequence"],
                        },
                    )
                ):
                    raise CoreVerificationError("core:event-artifact")
                artifact_states[row["payload_digest"]] = row["next_state"]
            elif row["event_kind"] == "SESSION_OPEN":
                if row["prior_state"] != "NONE" or row["next_state"] != "OPEN":
                    raise CoreVerificationError("core:session-transition")
                session_states[row["subject_id"]] = "OPEN"
            elif row["event_kind"] == "SESSION_START":
                if session_states.get(row["subject_id"]) != "OPEN" or row["next_state"] != "RUNNING":
                    raise CoreVerificationError("core:session-transition")
                session_states[row["subject_id"]] = "RUNNING"
            elif row["event_kind"] == "SESSION_PAUSE":
                if session_states.get(row["subject_id"]) != "RUNNING" or row["next_state"] != "PAUSED":
                    raise CoreVerificationError("core:session-transition")
                session_states[row["subject_id"]] = "PAUSED"
            elif row["event_kind"] == "OBSERVATION":
                if session_states.get(row["subject_id"]) not in {"RUNNING", "PAUSED"} or row["next_state"] != "OBSERVED":
                    raise CoreVerificationError("core:observation-transition")
            elif row["event_kind"] == "CASE_ADVANCE":
                if row["next_state"] not in {"OPEN", "RESPONSIBILITY", "REMEDIATION", "RETEST", "PERSISTENCE", "RESOLVED", "SUPERSEDED"}:
                    raise CoreVerificationError("core:case-transition")
            elif row["event_kind"] in {"DELIVERY_INTENT", "DELIVERY_REQUEUE", "DELIVERY_ACK", "DELIVERY_RESPONSE_UNKNOWN"}:
                if row["stream_kind"] != "DELIVERY" or not row["stream_id"]:
                    raise CoreVerificationError("core:delivery-stream")
                prior_delivery = delivery_states.get(row["subject_id"], ("DUE", 0, row["stream_id"]))
                prior_delivery_state, prior_attempt, prior_job = prior_delivery
                if prior_job != row["stream_id"]:
                    raise CoreVerificationError("core:delivery-job")
                if row["event_kind"] == "DELIVERY_REQUEUE":
                    if row["prior_state"] not in {"INTENT", "UNKNOWN"} or row["next_state"] != "DUE" or row["attempt"] != prior_attempt:
                        raise CoreVerificationError("core:delivery-transition")
                elif row["event_kind"] == "DELIVERY_INTENT":
                    if row["prior_state"] not in {"DUE", "UNKNOWN", "INTENT"} or row["next_state"] != "INTENT" or row["attempt"] != prior_attempt + 1:
                        raise CoreVerificationError("core:delivery-transition")
                else:
                    expected = "ACK" if row["event_kind"] == "DELIVERY_ACK" else "UNKNOWN"
                    if row["prior_state"] != "INTENT" or row["next_state"] != expected or row["attempt"] != prior_attempt:
                        raise CoreVerificationError("core:delivery-transition")
                delivery_states[row["subject_id"]] = (row["next_state"], row["attempt"], row["stream_id"])
            previous = row["after_root"]
        session_rows = connection.execute("SELECT * FROM core_sessions").fetchall()
        if meta["session_count"] != len(session_rows):
            raise CoreVerificationError("core:session-count")
        for row in session_rows:
            if session_states.get(row["session_id"]) != row["state"]:
                raise CoreVerificationError("core:session-state")
            session_stream = ("SESSION", str(row["session_id"]))
            if row["head_root"] != stream_roots.get(session_stream):
                raise CoreVerificationError("core:session-head")
            delivery = delivery_states.get(row["session_id"], ("DUE", 0, None))
            if row["delivery_state"] != delivery[0] or row["delivery_attempt"] != delivery[1] or row["delivery_job_id"] != delivery[2]:
                raise CoreVerificationError("core:delivery-state")
        for row in connection.execute("SELECT * FROM core_slots").fetchall():
            if row["state"] not in {"OBSERVED", "DUE"}:
                raise CoreVerificationError("core:slot-state")
            if row["result_raw"] is not None:
                result = _parse(row["result_raw"], "core:result")
                if result.get("result") not in OBSERVATION_RESULTS or result.get("result_digest") != row["result_digest"]:
                    raise CoreVerificationError("core:result")
        heads = connection.execute("SELECT * FROM core_heads ORDER BY stream_kind,stream_id").fetchall()
        head_keys: set[tuple[str, str]] = set()
        for row in heads:
            stream_key = (str(row["stream_kind"]), str(row["stream_id"]))
            if stream_key in head_keys or stream_key not in stream_roots or row["head_root"] != stream_roots[stream_key]:
                raise CoreVerificationError("core:head")
            head_keys.add(stream_key)
            if row["artifact_id"] != stream_refs.get(stream_key):
                raise CoreVerificationError("core:head")
            if row["stream_kind"] == "ARTIFACT" and row["artifact_id"] not in artifacts:
                raise CoreVerificationError("core:head")
        if head_keys != set(stream_roots):
            raise CoreVerificationError("core:head")
        if meta["sequence"] != len(events) or meta["head_root"] != previous:
            raise CoreVerificationError("core:meta-root")
        result = {
            "accepted": True,
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "database_id": meta["database_id"],
            "chain_id": meta["chain_id"],
            "config_digest": meta["config_digest"],
            "sequence": meta["sequence"],
            "head_root": meta["head_root"],
            "ingress_database_id": meta["ingress_database_id"],
            "ingress_watermark": meta["ingress_watermark"],
            "artifact_count": len(rows),
            "head_count": len(heads),
            "session_count": connection.execute("SELECT COUNT(*) FROM core_sessions").fetchone()[0],
            "slot_count": connection.execute("SELECT COUNT(*) FROM core_slots").fetchone()[0],
            "event_count": len(events),
            "flags": dict(FIXED_FLAGS),
            "current_source_artifact_id": next((row["artifact_id"] for row in heads if row["stream_kind"] == "ARTIFACT" and row["stream_id"] == "SOURCE_OBSERVATION"), None),
        }
        return result
    except CoreVerificationError:
        raise
    except (OSError, sqlite3.Error, TypeError, ValueError):
        raise CoreVerificationError("core:database") from None
    finally:
        try:
            connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        connection.close()


def logical_export(result: Mapping[str, object]) -> bytes:
    value = {
        "schema": "mirror-core-logical-export-v2",
        "schema_version": 2,
        "database_id": result["database_id"],
        "chain_id": result["chain_id"],
        "config_digest": result["config_digest"],
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
    }
    return _canonical(value)


__all__ = [
    "SCHEMA", "SCHEMA_VERSION", "TABLES", "ARTIFACT_KINDS",
    "SESSION_STATES", "OBSERVATION_RESULTS", "FIXED_FLAGS",
    "CoreVerificationError", "verify_database", "logical_export",
    "_canonical", "_digest", "_raw_digest", "_parse",
]
