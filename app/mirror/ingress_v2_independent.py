"""Independent verifier for the sanitized Mirror ingress state.

The ingress database is a clean-break owner of bounded non-PHI observations.
It never reparses a source capture.  The exact observation and verification
receipt grammar below is implemented independently from the source producer.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Mapping

from app.mirror.error_boundary import raise_redacted
from app.mirror.nc_medicaid_fhir_profile import NC_MEDICAID_PROFILE


SCHEMA = "mirror-ingress-v6"
SCHEMA_VERSION = 6
DOMAIN = "BL/MIRROR/INGRESS/V6/"
MAX_DATABASE_BYTES = 64 * 1024 * 1024
MAX_EVENT_BYTES = 786_432
MAX_CONFIG_BYTES = 16_384
MAX_IDENTIFIER_BYTES = 128
MAX_OBSERVATION_BYTES = 8_192
MAX_VERIFICATION_RECEIPT_BYTES = 4_096
GENESIS_ROOT = "0" * 128

TABLES = (
    "ingress_meta",
    "ingress_slots",
    "ingress_artifacts",
    "ingress_heads",
    "ingress_events",
)
STATES = (
    "DUE",
    "LEASED",
    "CAPTURED",
    "QUARANTINE_PENDING",
    "QUARANTINED",
    "HELD",
    "WITHDRAWN",
    "PURGED",
)
EVENT_KINDS = (
    "CREATE_SLOT",
    "LEASE",
    "CAPTURE",
    "BEGIN_QUARANTINE",
    "ADMIT",
    "REQUEUE",
    "HOLD",
)
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
    "proofSuiteId": None,
}
OBSERVATION_KEYS = {
    "schema", "schema_version", "profile_id", "profile_version",
    "observation_time", "effective_start", "effective_end",
    "source_count", "complete_source_count", "record_count",
    "finding_count", "discrepancy_count", "outcome", "source_status",
    "freshness", "page_complete", "page_count", "resource_count",
    "synthetic_only", "production_usable", "activation", "proofSuiteId",
}
OBSERVATION_OUTCOMES = {
    "CONTINUITY_CONFIRMED",
    "CREDENTIAL_EXPIRED",
    "ENROLLMENT_TERMINATED",
    "EVIDENCE_INCOMPLETE",
    "SOURCE_CONFLICT",
    "COVERAGE_STALE",
}
VERIFICATION_KEYS = {
    "schema", "schema_version", "profile_id", "profile_version",
    "verifier_id", "verifier_epoch", "evidence_mode",
    "verification_status", "outcome", "issued_at", "synthetic_only",
    "production_usable", "activation", "proofSuiteId", "observation_digest",
}
EVENT_KEYS = {
    "schema", "schema_version", "database_id", "chain_id", "sequence",
    "event_id", "event_kind", "stream_kind", "stream_id", "operation_id",
    "request_digest", "slot_id", "prior_state", "next_state", "attempt",
    "lease_token", "lease_until", "observed_at", "material",
    "material_digest", "payload_digest", "payload_length", "before_root",
    "after_root", "stream_before_root", "stream_after_root",
}
TABLE_COLUMNS = {
    "ingress_meta": (
        "meta_id", "schema", "schema_version", "database_id", "chain_id",
        "config_digest", "config_raw", "sequence", "head_root", "watermark",
        "slot_count",
    ),
    "ingress_slots": (
        "slot_id", "scheduled_at", "state", "attempt", "lease_token",
        "lease_until", "artifact_id", "operation_id",
    ),
    "ingress_artifacts": (
        "artifact_id", "observation", "profile_id", "profile_version",
        "observation_time", "effective_start", "effective_end", "source_count",
        "complete_source_count", "record_count", "finding_count",
        "discrepancy_count", "outcome", "source_status", "freshness",
        "page_complete", "page_count", "resource_count",
        "verification_receipt", "event_sequence",
    ),
    "ingress_heads": (
        "stream_kind", "stream_id", "artifact_id", "head_root", "event_sequence",
    ),
    "ingress_events": (
        "sequence", "event_id", "event_kind", "database_id", "chain_id",
        "stream_kind", "stream_id", "operation_id", "request_digest", "slot_id",
        "prior_state", "next_state", "attempt", "lease_token", "lease_until",
        "observed_at", "material_digest", "payload_digest", "payload_length",
        "before_root", "after_root", "stream_before_root", "stream_after_root",
        "event_raw", "receipt_digest",
    ),
}
EXPLICIT_INDEXES = (
    "ingress_events_chain_idx",
    "ingress_events_operation_idx",
    "ingress_events_observed_at_idx",
    "ingress_slots_due_idx",
)
INDEX_DEFINITIONS = {
    "ingress_events_chain_idx": (
        "ingress_events", 1, 0, ("chain_id", "sequence"),
        "create unique index ingress_events_chain_idx on ingress_events(chain_id,sequence)",
    ),
    "ingress_events_operation_idx": (
        "ingress_events", 0, 0, ("operation_id", "event_kind"),
        "create index ingress_events_operation_idx on ingress_events(operation_id,event_kind)",
    ),
    "ingress_events_observed_at_idx": (
        "ingress_events", 0, 0, ("observed_at", "sequence"),
        "create index ingress_events_observed_at_idx on ingress_events(observed_at,sequence)",
    ),
    "ingress_slots_due_idx": (
        "ingress_slots", 0, 0, ("state", "lease_until", "slot_id"),
        "create index ingress_slots_due_idx on ingress_slots(state,lease_until,slot_id)",
    ),
}


class IngressVerificationError(ValueError):
    """Fixed public-safe ingress verification failure."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=True, allow_nan=False, sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise IngressVerificationError("ingress:noncanonical") from None


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise IngressVerificationError("ingress:duplicate-key")
        result[key] = value
    return result


def _parse(raw: object, label: str, *, max_bytes: int = MAX_EVENT_BYTES) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > max_bytes:
        raise IngressVerificationError(label)
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                IngressVerificationError("ingress:constant")
            ),
        )
    except IngressVerificationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise IngressVerificationError(label) from None
    if not isinstance(value, dict) or _canonical(value) != raw:
        raise IngressVerificationError(label)
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
    if type(value) is not str or len(value) != 128 or any(c not in "0123456789abcdef" for c in value):
        raise IngressVerificationError(label)
    return value


def _safe_identifier(value: object, label: str) -> str:
    if type(value) is not str or not value or len(value) > MAX_IDENTIFIER_BYTES:
        raise IngressVerificationError(label)
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        raise IngressVerificationError(label) from None
    if any(not (c.isalnum() or c in "._:-") for c in value):
        raise IngressVerificationError(label)
    return value


def _lease_token_digest(database_id: str, config_digest: str, slot_id: str, attempt: int, raw_token: str) -> str:
    return _digest("lease-token", {
        "database_id": database_id, "config_digest": config_digest,
        "slot_id": slot_id, "attempt": attempt, "raw_token": raw_token,
    })


def _event_root(*, sequence: int, previous: str, event_id: str, event_kind: str,
                stream_kind: str, stream_id: str, slot_id: str,
                next_state: str, observed_at: int, material_digest: str) -> str:
    return _digest("event-root", {
        "sequence": sequence, "previous": previous, "event_id": event_id,
        "event_kind": event_kind, "stream_kind": stream_kind,
        "stream_id": stream_id, "slot_id": slot_id, "next_state": next_state,
        "observed_at": observed_at, "material_digest": material_digest,
    })


def _stream_root(*, sequence: int, previous: str, event_id: str,
                 stream_kind: str, stream_id: str, next_state: str,
                 observed_at: int, material_digest: str) -> str:
    return _digest("stream-root", {
        "sequence": sequence, "previous": previous, "event_id": event_id,
        "stream_kind": stream_kind, "stream_id": stream_id,
        "next_state": next_state, "observed_at": observed_at,
        "material_digest": material_digest,
    })


def _table_names(connection: sqlite3.Connection) -> tuple[str, ...]:
    return tuple(row[0] for row in connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall())


def _columns(connection: sqlite3.Connection, table: str) -> tuple[str, ...]:
    return tuple(row[1] for row in connection.execute(
        "SELECT * FROM pragma_table_info(?) ORDER BY cid", (table,)
    ).fetchall())


def _index_definitions(connection: sqlite3.Connection) -> dict[str, tuple[object, ...]]:
    result: dict[str, tuple[object, ...]] = {}
    for name in EXPLICIT_INDEXES:
        row = connection.execute(
            "SELECT name,tbl_name,sql FROM sqlite_master WHERE type='index' AND name=?",
            (name,),
        ).fetchone()
        if row is None:
            raise IngressVerificationError("ingress:indexes")
        columns = tuple(item[2] for item in connection.execute(
            "SELECT seqno,cid,name FROM pragma_index_info(?) ORDER BY seqno", (name,)
        ).fetchall())
        unique = int(connection.execute(
            'SELECT "unique" FROM pragma_index_list(?) WHERE name=?',
            (row["tbl_name"], name),
        ).fetchone()[0])
        partial = 1 if " where " in str(row["sql"]).lower() else 0
        result[name] = (
            str(row["tbl_name"]), unique, partial, columns,
            " ".join(str(row["sql"]).lower().split()),
        )
    return result


def _open(path: str | Path) -> sqlite3.Connection:
    database = Path(path)
    if not database.exists() or not database.is_file():
        raise IngressVerificationError("ingress:database")
    try:
        connection = sqlite3.connect(str(database), isolation_level=None, timeout=0.25)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        if str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower() != "delete":
            raise IngressVerificationError("ingress:database")
        return connection
    except IngressVerificationError:
        try:
            connection.close()
        except Exception:
            pass
        raise
    except (OSError, sqlite3.Error):
        raise IngressVerificationError("ingress:database") from None


def _close(connection: sqlite3.Connection | None) -> None:
    if connection is None:
        return
    failed = False
    try:
        connection.close()
    except Exception:
        failed = True
    if failed:
        raise_redacted(IngressVerificationError, "ingress:database")


def _verify_observation(observation_raw: bytes) -> dict[str, object]:
    value = _parse(observation_raw, "ingress:observation", max_bytes=MAX_OBSERVATION_BYTES)
    if set(value) != OBSERVATION_KEYS:
        raise IngressVerificationError("ingress:observation-keys")
    if value["schema"] != "mirror-source-observation-v1" or value["schema_version"] != 1:
        raise IngressVerificationError("ingress:observation-schema")
    if value["profile_id"] != NC_MEDICAID_PROFILE.source_profile_id or value["profile_version"] != 3:
        raise IngressVerificationError("ingress:observation-profile")
    for key in ("observation_time", "effective_start", "effective_end"):
        if type(value[key]) is not int or value[key] < 1:
            raise IngressVerificationError("ingress:observation-time")
    graph_profile = NC_MEDICAID_PROFILE.graph_profile
    if (value["effective_start"], value["effective_end"]) != (
        graph_profile.effective_start, graph_profile.effective_end,
    ):
        raise IngressVerificationError("ingress:observation-interval")
    bounds = {
        "source_count": (2, 2), "complete_source_count": (0, 2),
        "record_count": (0, 16), "finding_count": (1, 1),
        "discrepancy_count": (0, 1), "page_count": (1, 4),
        "resource_count": (0, 4096),
    }
    for key, (minimum, maximum) in bounds.items():
        if type(value[key]) is not int or not minimum <= value[key] <= maximum:
            raise IngressVerificationError("ingress:observation-count")
    outcome = value["outcome"]
    if outcome not in OBSERVATION_OUTCOMES:
        raise IngressVerificationError("ingress:observation-outcome")
    complete = value["complete_source_count"]
    records = value["record_count"]
    discrepancies = value["discrepancy_count"]
    if outcome == "SOURCE_CONFLICT":
        if complete != 2 or records < 3 or discrepancies != 1:
            raise IngressVerificationError("ingress:observation-shape")
    elif outcome == "EVIDENCE_INCOMPLETE":
        if complete >= 2 or discrepancies != 0:
            raise IngressVerificationError("ingress:observation-shape")
    elif outcome == "COVERAGE_STALE":
        if discrepancies != 0:
            raise IngressVerificationError("ingress:observation-shape")
    elif complete != 2 or records != 2 or discrepancies != 0:
        raise IngressVerificationError("ingress:observation-shape")
    if value["source_status"] not in {"COMPLETE", "FAILED"} or value["freshness"] not in {"FRESH", "UNKNOWN", "STALE"}:
        raise IngressVerificationError("ingress:observation-status")
    if type(value["page_complete"]) is not bool:
        raise IngressVerificationError("ingress:observation-pages")
    if value["synthetic_only"] is not True or value["production_usable"] is not False or value["activation"] is not False or value["proofSuiteId"] is not None:
        raise IngressVerificationError("ingress:observation-flags")
    return value


def _verify_receipt(receipt_raw: bytes, observation: Mapping[str, object]) -> dict[str, object]:
    value = _parse(receipt_raw, "ingress:verification-receipt", max_bytes=MAX_VERIFICATION_RECEIPT_BYTES)
    if set(value) != VERIFICATION_KEYS:
        raise IngressVerificationError("ingress:verification-keys")
    graph_profile = NC_MEDICAID_PROFILE.graph_profile
    if (
        value["schema"] != "mirror-source-verification-receipt-v1"
        or value["schema_version"] != 1
        or value["profile_id"] != observation["profile_id"]
        or value["profile_version"] != observation["profile_version"]
        or value["verifier_id"] != graph_profile.verifier_id
        or value["verifier_epoch"] != graph_profile.verifier_epoch
        or value["evidence_mode"] != "observation_only"
        or value["verification_status"] != "VERIFIED_AT_TIME"
        or value["outcome"] != observation["outcome"]
        or value["observation_digest"] != _raw_digest("sanitized-observation", _canonical(observation))
        or type(value["issued_at"]) is not int
        or value["issued_at"] < observation["observation_time"]
    ):
        raise IngressVerificationError("ingress:verification-receipt")
    if value["synthetic_only"] is not True or value["production_usable"] is not False or value["activation"] is not False or value["proofSuiteId"] is not None:
        raise IngressVerificationError("ingress:verification-flags")
    return value


def verify_observation_pair(
    observation_raw: bytes,
    verification_receipt_raw: bytes,
    *,
    expected_profile_id: str | None = None,
    expected_profile_version: int | None = None,
) -> dict[str, object]:
    observation = _verify_observation(observation_raw)
    if expected_profile_id is not None and observation["profile_id"] != expected_profile_id:
        raise IngressVerificationError("ingress:observation-profile")
    if expected_profile_version is not None and observation["profile_version"] != expected_profile_version:
        raise IngressVerificationError("ingress:observation-profile")
    receipt = _verify_receipt(verification_receipt_raw, observation)
    return {
        "observation": observation,
        "verification_receipt": receipt,
        "observation_id": _raw_digest("sanitized-observation", observation_raw),
    }


def _verify_config(
    row: sqlite3.Row,
    expected_database_id: str | None,
    expected_config_digest: str | None,
) -> tuple[sqlite3.Row, dict[str, object]]:
    if tuple(row.keys()) != TABLE_COLUMNS["ingress_meta"] or row["meta_id"] != 1:
        raise IngressVerificationError("ingress:meta")
    if row["schema"] != SCHEMA or row["schema_version"] != SCHEMA_VERSION:
        raise IngressVerificationError("ingress:schema")
    _safe_identifier(row["database_id"], "ingress:database-id")
    _safe_identifier(row["chain_id"], "ingress:chain-id")
    if expected_database_id is not None and row["database_id"] != expected_database_id:
        raise IngressVerificationError("ingress:database-id")
    if expected_config_digest is not None and row["config_digest"] != expected_config_digest:
        raise IngressVerificationError("ingress:config")
    _hex(row["config_digest"], "ingress:config")
    config = _parse(row["config_raw"], "ingress:config", max_bytes=MAX_CONFIG_BYTES)
    expected = {
        "schema", "schema_version", "database_id", "chain_id",
        "policy_digest", "authorization_digest", "terms_digest",
        "source_contract_digest", "cadence_seconds", "effective_start",
        "effective_end", "max_slots", "max_attempts", "lease_seconds", "flags",
    }
    if set(config) != expected or config["schema"] != SCHEMA or config["schema_version"] != SCHEMA_VERSION:
        raise IngressVerificationError("ingress:config")
    if config["database_id"] != row["database_id"] or config["chain_id"] != row["chain_id"] or config["flags"] != FIXED_FLAGS:
        raise IngressVerificationError("ingress:config")
    for key in ("policy_digest", "authorization_digest", "terms_digest", "source_contract_digest"):
        _hex(config[key], "ingress:config")
    if _digest("config", config) != row["config_digest"]:
        raise IngressVerificationError("ingress:config")
    if type(config["cadence_seconds"]) is not int or config["cadence_seconds"] <= 0:
        raise IngressVerificationError("ingress:config")
    if type(config["effective_start"]) is not int or type(config["effective_end"]) is not int or config["effective_start"] >= config["effective_end"]:
        raise IngressVerificationError("ingress:config")
    if type(config["max_slots"]) is not int or not 1 <= config["max_slots"] <= 4096:
        raise IngressVerificationError("ingress:config")
    if type(config["max_attempts"]) is not int or not 1 <= config["max_attempts"] <= 8:
        raise IngressVerificationError("ingress:config")
    if type(config["lease_seconds"]) is not int or not 1 <= config["lease_seconds"] <= 86_400:
        raise IngressVerificationError("ingress:config")
    return row, config


def _verify_artifact(row: sqlite3.Row) -> dict[str, object]:
    if tuple(row.keys()) != TABLE_COLUMNS["ingress_artifacts"]:
        raise IngressVerificationError("ingress:artifact-columns")
    artifact_id = _hex(row["artifact_id"], "ingress:artifact-id")
    observation_raw = row["observation"]
    if type(observation_raw) is not bytes:
        raise IngressVerificationError("ingress:observation")
    observation = _verify_observation(observation_raw)
    receipt_raw = row["verification_receipt"]
    if type(receipt_raw) is not bytes:
        raise IngressVerificationError("ingress:verification-receipt")
    receipt = _verify_receipt(receipt_raw, observation)
    expected_id = _digest("artifact-id", {
        "observation_digest": _raw_digest("sanitized-observation", observation_raw),
        "profile_id": observation["profile_id"],
        "profile_version": observation["profile_version"],
        "observation_time": observation["observation_time"],
    })
    if artifact_id != expected_id:
        raise IngressVerificationError("ingress:artifact-id")
    for key in (
        "profile_id", "profile_version", "observation_time", "effective_start",
        "effective_end", "source_count", "complete_source_count", "record_count",
        "finding_count", "discrepancy_count", "outcome", "source_status",
        "freshness", "page_complete", "page_count", "resource_count",
    ):
        if row[key] != observation[key]:
            raise IngressVerificationError("ingress:artifact-binding")
    if type(row["event_sequence"]) is not int or row["event_sequence"] <= 0:
        raise IngressVerificationError("ingress:artifact-event-sequence")
    return {
        key: row[key] for key in TABLE_COLUMNS["ingress_artifacts"]
    } | {
        "observation_id": _raw_digest("sanitized-observation", observation_raw),
        "verification": receipt,
        "_stored_event_sequence": row["event_sequence"],
        "_terminal_event_sequence": None,
        "_terminal_event_kind": None,
        "_terminal_slot_id": None,
    }


def _verify_event(
    row: sqlite3.Row,
    *,
    meta: sqlite3.Row,
    config: Mapping[str, object],
    previous_root: str,
    slot_states: dict[str, str],
    slot_schedules: dict[str, int],
    slot_operations: dict[str, str],
    slot_attempts: dict[str, int],
    slot_leases: dict[str, tuple[str | None, int | None]],
    slot_artifacts: dict[str, str | None],
    artifacts: dict[str, dict[str, object]],
    capture_operations: dict[str, str],
    stream_roots: dict[tuple[str, str], str],
    heads: dict[tuple[str, str], tuple[str | None, str, int]],
    previous_observed_at: int,
) -> str:
    if tuple(row.keys()) != TABLE_COLUMNS["ingress_events"]:
        raise IngressVerificationError("ingress:event-columns")
    raw = row["event_raw"]
    value = _parse(raw, "ingress:event-raw")
    if set(value) != EVENT_KEYS or any(
        value[key] != row[key]
        for key in TABLE_COLUMNS["ingress_events"]
        if key in EVENT_KEYS
    ):
        raise IngressVerificationError("ingress:event-binding")
    if row["sequence"] <= 0 or row["database_id"] != meta["database_id"] or row["chain_id"] != meta["chain_id"]:
        raise IngressVerificationError("ingress:event-binding")
    for key in ("event_id", "operation_id", "request_digest", "slot_id"):
        _hex(row[key], "ingress:event-id")
    if row["lease_token"] is not None:
        _hex(row["lease_token"], "ingress:lease-token")
    if not isinstance(value["material"], dict) or value["material_digest"] != _digest("material", value["material"]):
        raise IngressVerificationError("ingress:material-digest")
    if (
        row["before_root"] != previous_root
        or row["event_kind"] not in EVENT_KINDS
        or type(row["observed_at"]) is not int
        or row["observed_at"] < previous_observed_at
    ):
        raise IngressVerificationError("ingress:event-order")
    if row["event_id"] != _digest("event-id", {
        key: value[key] for key in EVENT_KEYS
        if key not in {"event_id", "after_root", "stream_after_root"}
    }):
        raise IngressVerificationError("ingress:event-id")
    if row["receipt_digest"] != _raw_digest("receipt", raw):
        raise IngressVerificationError("ingress:receipt")
    stream_key = (str(row["stream_kind"]), str(row["stream_id"]))
    if row["stream_before_root"] != stream_roots.get(stream_key, GENESIS_ROOT):
        raise IngressVerificationError("ingress:stream-order")
    if row["stream_after_root"] != _stream_root(
        sequence=row["sequence"], previous=row["stream_before_root"],
        event_id=row["event_id"], stream_kind=row["stream_kind"],
        stream_id=row["stream_id"], next_state=row["next_state"],
        observed_at=row["observed_at"], material_digest=row["material_digest"],
    ):
        raise IngressVerificationError("ingress:stream-root")
    if row["after_root"] != _event_root(
        sequence=row["sequence"], previous=row["before_root"],
        event_id=row["event_id"], event_kind=row["event_kind"],
        stream_kind=row["stream_kind"], stream_id=row["stream_id"],
        slot_id=row["slot_id"], next_state=row["next_state"],
        observed_at=row["observed_at"], material_digest=row["material_digest"],
    ):
        raise IngressVerificationError("ingress:event-root")
    kind = str(row["event_kind"])
    material = value["material"]
    prior = slot_states.get(str(row["slot_id"]))
    if row["prior_state"] != (prior or "NONE"):
        raise IngressVerificationError("ingress:event-state")
    expected_operation: str
    expected_request: str
    expected_payload: str
    expected_length = 0
    head_artifact: str | None = None
    slot_id = str(row["slot_id"])
    if kind == "CREATE_SLOT":
        if set(material) != {"slot_id", "scheduled_at", "operation_id"} or row["next_state"] != "DUE" or row["prior_state"] != "NONE":
            raise IngressVerificationError("ingress:slot-event")
        scheduled = material["scheduled_at"]
        if type(scheduled) is not int or not int(config["effective_start"]) <= scheduled <= int(config["effective_end"]) or (scheduled - int(config["effective_start"])) % int(config["cadence_seconds"]) != 0:
            raise IngressVerificationError("ingress:slot-grid")
        expected_slot = _digest("slot-id", {"config_digest": meta["config_digest"], "scheduled_at": scheduled})
        expected_operation = _digest("slot-operation", {"slot_id": expected_slot})
        expected_request = _digest("request", {"operation_id": expected_operation, "scheduled_at": scheduled})
        expected_payload = _digest("slot-payload", {"slot_id": expected_slot, "scheduled_at": scheduled})
        if row["slot_id"] != expected_slot or material["operation_id"] != expected_operation or row["attempt"] != 0 or row["lease_token"] is not None or row["lease_until"] is not None:
            raise IngressVerificationError("ingress:slot-event")
        slot_schedules[slot_id] = scheduled
        slot_operations[slot_id] = expected_operation
        slot_attempts[slot_id] = 0
        slot_states[slot_id] = "DUE"
        slot_leases[slot_id] = (None, None)
        slot_artifacts[slot_id] = None
    else:
        scheduled = slot_schedules.get(slot_id)
        operation = slot_operations.get(slot_id)
        if scheduled is None or operation is None:
            raise IngressVerificationError("ingress:event-slot")
        if kind == "LEASE":
            if set(material) != {"slot_id", "attempt", "lease_token", "lease_until", "operation_id"} or material["slot_id"] != slot_id or material["operation_id"] != operation or row["next_state"] != "LEASED":
                raise IngressVerificationError("ingress:lease")
            if prior not in {"DUE", "LEASED"} or type(scheduled) is not int or row["observed_at"] < scheduled:
                raise IngressVerificationError("ingress:lease")
            if prior == "LEASED":
                old_lease = slot_leases.get(slot_id)
                if old_lease is None or old_lease[1] is None or row["observed_at"] < old_lease[1]:
                    raise IngressVerificationError("ingress:lease")
            if type(row["attempt"]) is not int or not 1 <= row["attempt"] <= int(config["max_attempts"]) or type(row["lease_until"]) is not int or row["lease_until"] != row["observed_at"] + int(config["lease_seconds"]) or material["attempt"] != row["attempt"] or material["lease_token"] != row["lease_token"]:
                raise IngressVerificationError("ingress:lease")
            if row["attempt"] != slot_attempts[slot_id] + 1:
                raise IngressVerificationError("ingress:lease")
            expected_operation = operation
            expected_request = _digest("request", {"slot_id": slot_id, "action": "LEASE", "attempt": row["attempt"]})
            expected_payload = _digest("lease-payload", material)
            slot_attempts[slot_id] = int(row["attempt"])
            slot_leases[slot_id] = (str(row["lease_token"]), int(row["lease_until"]))
            slot_states[slot_id] = "LEASED"
        elif kind == "CAPTURE":
            if set(material) != {"slot_id", "artifact_id", "observation_id", "outcome", "operation_id", "lease_token_digest"} or row["next_state"] != "CAPTURED" or material["slot_id"] != slot_id:
                raise IngressVerificationError("ingress:capture")
            if (
                prior != "LEASED"
                or row["attempt"] != slot_attempts[slot_id]
                or (row["lease_token"], row["lease_until"]) != slot_leases[slot_id]
                or row["lease_token"] is None
                or row["lease_until"] is None
                or row["observed_at"] > row["lease_until"]
            ):
                raise IngressVerificationError("ingress:capture")
            artifact_id = str(material["artifact_id"])
            artifact = artifacts.get(artifact_id)
            if artifact is None or material["outcome"] != artifact["outcome"] or material["observation_id"] != _raw_digest("sanitized-observation", artifact["observation"]):
                raise IngressVerificationError("ingress:capture")
            if artifact_id in capture_operations:
                raise IngressVerificationError("ingress:capture")
            if artifact["observation_time"] != scheduled:
                raise IngressVerificationError("ingress:capture")
            expected_operation = _digest("capture-operation", {"slot_id": slot_id, "artifact_id": artifact_id})
            expected_request = _digest("request", {"operation_id": expected_operation, "slot_id": slot_id, "artifact_id": artifact_id})
            expected_payload = artifact_id
            expected_length = len(artifact["observation"])
            if material["operation_id"] != expected_operation or material["lease_token_digest"] != row["lease_token"]:
                raise IngressVerificationError("ingress:capture")
            capture_operations[artifact_id] = expected_operation
            slot_states[slot_id] = "CAPTURED"
            head_artifact = artifact_id
        elif kind in {"BEGIN_QUARANTINE", "ADMIT"}:
            expected_decision = "QUARANTINE_PENDING" if kind == "BEGIN_QUARANTINE" else "QUARANTINED"
            expected_next = expected_decision
            if set(material) != {"artifact_id", "decision", "operation_id"} or material["decision"] != expected_decision or row["next_state"] != expected_next:
                raise IngressVerificationError("ingress:quarantine")
            if (kind == "BEGIN_QUARANTINE" and prior != "CAPTURED") or (kind == "ADMIT" and prior != "QUARANTINE_PENDING"):
                raise IngressVerificationError("ingress:quarantine")
            if (
                row["attempt"] != slot_attempts[slot_id]
                or (row["lease_token"], row["lease_until"]) != slot_leases[slot_id]
            ):
                raise IngressVerificationError("ingress:quarantine")
            artifact_id = str(material["artifact_id"])
            if artifact_id not in artifacts or capture_operations.get(artifact_id) is None:
                raise IngressVerificationError("ingress:quarantine")
            expected_operation = _digest("quarantine-operation", {
                "capture_operation": capture_operations[artifact_id],
                "decision": "BEGIN" if kind == "BEGIN_QUARANTINE" else "ADMIT",
            })
            expected_request = _digest("request", {"operation_id": expected_operation, "slot_id": slot_id, "artifact_id": artifact_id})
            expected_payload = artifact_id
            expected_length = len(artifacts[artifact_id]["observation"])
            if material["operation_id"] != expected_operation:
                raise IngressVerificationError("ingress:quarantine")
            slot_states[slot_id] = expected_next
            if kind == "ADMIT":
                slot_leases[slot_id] = (None, None)
                slot_artifacts[slot_id] = artifact_id
                artifacts[artifact_id]["_terminal_event_sequence"] = row["sequence"]
                artifacts[artifact_id]["_terminal_event_kind"] = kind
                artifacts[artifact_id]["_terminal_slot_id"] = slot_id
                artifacts[artifact_id]["_event_prefix_root"] = row["before_root"]
                artifacts[artifact_id]["_event_after_root"] = row["after_root"]
            head_artifact = artifact_id
        elif kind in {"REQUEUE", "HOLD"}:
            if set(material) != {"slot_id", "action", "attempt", "operation_id"} or material["slot_id"] != slot_id or material["operation_id"] != operation or material["action"] != kind:
                raise IngressVerificationError("ingress:lease-recovery")
            if prior != "LEASED" or material["attempt"] != slot_attempts[slot_id]:
                raise IngressVerificationError("ingress:lease-recovery")
            if (
                row["attempt"] != slot_attempts[slot_id]
                or (row["lease_token"], row["lease_until"]) != slot_leases[slot_id]
            ):
                raise IngressVerificationError("ingress:lease-recovery")
            expected_operation = operation
            expected_request = _digest("request", {"slot_id": slot_id, "action": kind})
            expected_payload = _digest("lease-recovery", {"slot_id": slot_id, "attempt": row["attempt"]})
            if row["next_state"] not in {"DUE", "HELD"}:
                raise IngressVerificationError("ingress:lease-recovery")
            slot_states[slot_id] = str(row["next_state"])
            slot_leases[slot_id] = (None, None)
        else:
            raise IngressVerificationError("ingress:event-kind")
    if row["operation_id"] != expected_operation or row["request_digest"] != expected_request or row["payload_digest"] != expected_payload or row["payload_length"] != expected_length:
        raise IngressVerificationError("ingress:event-payload")
    if type(row["attempt"]) is not int or not 0 <= row["attempt"] <= int(config["max_attempts"]):
        raise IngressVerificationError("ingress:attempt")
    if row["next_state"] not in STATES:
        raise IngressVerificationError("ingress:event-state")
    stream_roots[stream_key] = str(row["stream_after_root"])
    prior_head = heads.get(stream_key)
    heads[stream_key] = (
        head_artifact if head_artifact is not None else (prior_head[0] if prior_head else None),
        str(row["stream_after_root"]), int(row["sequence"]),
    )
    return str(row["after_root"])


def _public_artifact(value: Mapping[str, object]) -> dict[str, object]:
    return {key: value[key] for key in (
        "profile_id", "profile_version", "observation_time",
        "effective_start", "effective_end", "source_count",
        "complete_source_count", "record_count", "finding_count",
        "discrepancy_count", "outcome", "source_status", "freshness",
        "page_complete", "page_count", "resource_count", "event_sequence",
    )}


def _verify_connection(
    connection: sqlite3.Connection,
    *,
    expected_database_id: str | None = None,
    expected_config_digest: str | None = None,
    include_observation: bool = False,
    artifact_id: str | None = None,
    artifact_ids: tuple[str, ...] | None = None,
) -> dict[str, object]:
    if _table_names(connection) != tuple(sorted(TABLES)):
        raise IngressVerificationError("ingress:tables")
    if any(_columns(connection, table) != TABLE_COLUMNS[table] for table in TABLES):
        raise IngressVerificationError("ingress:columns")
    if _index_definitions(connection) != INDEX_DEFINITIONS:
        raise IngressVerificationError("ingress:indexes")
    meta_row = connection.execute("SELECT * FROM ingress_meta").fetchone()
    if meta_row is None:
        raise IngressVerificationError("ingress:meta")
    meta, config = _verify_config(meta_row, expected_database_id, expected_config_digest)
    slot_rows = connection.execute("SELECT * FROM ingress_slots ORDER BY slot_id").fetchall()
    if len(slot_rows) != meta["slot_count"] or len(slot_rows) > int(config["max_slots"]):
        raise IngressVerificationError("ingress:slot-count")
    artifact_rows = connection.execute("SELECT * FROM ingress_artifacts ORDER BY artifact_id").fetchall()
    artifacts = {str(row["artifact_id"]): _verify_artifact(row) for row in artifact_rows}
    if len(artifacts) != len(artifact_rows):
        raise IngressVerificationError("ingress:artifact-duplicate")
    slot_states: dict[str, str] = {}
    slot_schedules: dict[str, int] = {}
    slot_operations: dict[str, str] = {}
    slot_attempts: dict[str, int] = {}
    slot_leases: dict[str, tuple[str | None, int | None]] = {}
    slot_artifacts: dict[str, str | None] = {}
    capture_operations: dict[str, str] = {}
    stream_roots: dict[tuple[str, str], str] = {}
    heads: dict[tuple[str, str], tuple[str | None, str, int]] = {}
    previous = GENESIS_ROOT
    previous_observed_at = -1
    events = connection.execute("SELECT * FROM ingress_events ORDER BY sequence").fetchall()
    for expected_sequence, row in enumerate(events, start=1):
        if row["sequence"] != expected_sequence:
            raise IngressVerificationError("ingress:event-sequence")
        previous = _verify_event(
            row, meta=meta, config=config, previous_root=previous,
            slot_states=slot_states, slot_schedules=slot_schedules,
            slot_operations=slot_operations, slot_attempts=slot_attempts,
            slot_leases=slot_leases, slot_artifacts=slot_artifacts,
            artifacts=artifacts,
            capture_operations=capture_operations, stream_roots=stream_roots,
            heads=heads, previous_observed_at=previous_observed_at,
        )
        previous_observed_at = int(row["observed_at"])
    for artifact in artifacts.values():
        if artifact["_terminal_event_sequence"] is None or artifact["_stored_event_sequence"] != artifact["_terminal_event_sequence"]:
            raise IngressVerificationError("ingress:artifact-event-sequence")
        artifact["terminal_event_sequence"] = artifact.pop("_terminal_event_sequence")
        artifact["terminal_event_kind"] = artifact.pop("_terminal_event_kind")
        artifact["terminal_slot_id"] = artifact.pop("_terminal_slot_id")
        artifact["terminal_state"] = "QUARANTINED"
        artifact["event_prefix_root"] = artifact.pop("_event_prefix_root")
        artifact["event_after_root"] = artifact.pop("_event_after_root")
        artifact.pop("_stored_event_sequence", None)
        if artifact["terminal_event_kind"] != "ADMIT":
            raise IngressVerificationError("ingress:artifact-state")
        terminal_slot_id = artifact["terminal_slot_id"]
        if (
            type(terminal_slot_id) is not str
            or slot_artifacts.get(terminal_slot_id) != artifact["artifact_id"]
        ):
            raise IngressVerificationError("ingress:artifact-slot")
    for row in slot_rows:
        slot_id = str(row["slot_id"])
        if (
            slot_id not in slot_states
            or row["state"] != slot_states[slot_id]
            or row["scheduled_at"] != slot_schedules.get(slot_id)
            or row["operation_id"] != slot_operations.get(slot_id)
            or row["attempt"] != slot_attempts.get(slot_id, 0)
            or row["artifact_id"] != slot_artifacts.get(slot_id)
        ):
            raise IngressVerificationError("ingress:slot-state")
        if (row["lease_token"], row["lease_until"]) != slot_leases.get(slot_id, (None, None)):
            raise IngressVerificationError("ingress:slot-lease")
        if row["artifact_id"] is not None and row["artifact_id"] not in artifacts:
            raise IngressVerificationError("ingress:slot-artifact")
    head_rows = connection.execute("SELECT * FROM ingress_heads ORDER BY stream_kind,stream_id").fetchall()
    if len(head_rows) != len(heads):
        raise IngressVerificationError("ingress:heads")
    for row in head_rows:
        key = (str(row["stream_kind"]), str(row["stream_id"]))
        expected = heads.get(key)
        if expected is None or tuple(row) != (key[0], key[1], expected[0], expected[1], expected[2]):
            raise IngressVerificationError("ingress:head")
    if meta["sequence"] != len(events) or meta["watermark"] != len(events) or meta["head_root"] != previous:
        raise IngressVerificationError("ingress:meta-root")
    selected: dict[str, dict[str, object]] = {}
    if artifact_ids is not None:
        if type(artifact_ids) is not tuple or len(set(artifact_ids)) != len(artifact_ids):
            raise IngressVerificationError("ingress:artifact-selector")
        for selected_id in artifact_ids:
            _hex(selected_id, "ingress:artifact-selector")
            if selected_id not in artifacts:
                raise IngressVerificationError("ingress:artifact-missing")
            item = dict(artifacts[selected_id])
            if not include_observation:
                item.pop("observation", None)
                item.pop("verification_receipt", None)
                item.pop("verification", None)
            selected[selected_id] = item
    current_id = heads.get(("QUARANTINE", meta["chain_id"]), (None, "", 0))[0]
    if artifact_id is not None:
        _hex(artifact_id, "ingress:artifact-selector")
        if artifact_id not in artifacts:
            raise IngressVerificationError("ingress:artifact-missing")
        current_id = artifact_id
    current = None
    if current_id is not None:
        current = dict(artifacts[current_id])
        if not include_observation:
            current.pop("observation", None)
            current.pop("verification_receipt", None)
            current.pop("verification", None)
    return {
        "accepted": True, "schema": SCHEMA, "schema_version": SCHEMA_VERSION,
        "database_id": meta["database_id"], "chain_id": meta["chain_id"],
        "config_digest": meta["config_digest"], "config": dict(config),
        "sequence": int(meta["sequence"]), "head_root": meta["head_root"],
        "watermark": int(meta["watermark"]), "slot_count": len(slot_rows),
        "artifact_count": len(artifact_rows), "attestation_count": 0,
        "event_count": len(events),
        "latest_observed_at": previous_observed_at if events else 0,
        "state_counts": {state: sum(1 for row in slot_rows if row["state"] == state) for state in STATES},
        "flags": dict(FIXED_FLAGS), "selected_artifacts": selected,
        "current_artifact_id": current_id, "current_artifact": current,
    }


def verify_database(path: str | Path, *, expected_database_id: str | None = None,
                    expected_config_digest: str | None = None,
                    include_observation: bool = False, artifact_id: str | None = None,
                    artifact_ids: tuple[str, ...] | None = None) -> dict[str, object]:
    connection = _open(path)
    try:
        return _verify_connection(
            connection, expected_database_id=expected_database_id,
            expected_config_digest=expected_config_digest,
            include_observation=include_observation, artifact_id=artifact_id,
            artifact_ids=artifact_ids,
        )
    finally:
        _close(connection)


def verify_bytes(raw: bytes, *, expected_database_id: str | None = None,
                 expected_config_digest: str | None = None,
                 include_observation: bool = False, artifact_id: str | None = None,
                 artifact_ids: tuple[str, ...] | None = None) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_DATABASE_BYTES:
        raise IngressVerificationError("ingress:image")
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(":memory:", isolation_level=None, timeout=0.25)
        connection.row_factory = sqlite3.Row
        connection.deserialize(raw)
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        return _verify_connection(
            connection, expected_database_id=expected_database_id,
            expected_config_digest=expected_config_digest,
            include_observation=include_observation, artifact_id=artifact_id,
            artifact_ids=artifact_ids,
        )
    except IngressVerificationError:
        raise
    except (sqlite3.Error, TypeError, ValueError):
        raise IngressVerificationError("ingress:image") from None
    finally:
        _close(connection)


def read_artifact(path: str | Path, artifact_id: str) -> dict[str, object]:
    result = verify_database(path, include_observation=True, artifact_id=artifact_id)
    artifact = result.get("current_artifact")
    if not isinstance(artifact, dict) or result.get("current_artifact_id") != artifact_id:
        raise IngressVerificationError("ingress:artifact-not-current")
    artifact.update({
        "head_root": result["head_root"], "database_id": result["database_id"],
        "chain_id": result["chain_id"], "config_digest": result["config_digest"],
        "watermark": artifact["event_sequence"],
    })
    return artifact


def read_artifact_snapshots(path: str | Path, artifact_ids: tuple[str, ...]) -> dict[str, dict[str, object]]:
    result = verify_database(path, include_observation=True, artifact_ids=artifact_ids)
    selected = result.get("selected_artifacts")
    if not isinstance(selected, dict):
        raise IngressVerificationError("ingress:artifact-selector")
    returned: dict[str, dict[str, object]] = {}
    for selected_id, artifact in selected.items():
        if not isinstance(artifact, dict):
            raise IngressVerificationError("ingress:artifact-selector")
        item = dict(artifact)
        item.update({
            "head_root": result["head_root"], "database_id": result["database_id"],
            "chain_id": result["chain_id"], "config_digest": result["config_digest"],
            "watermark": item["event_sequence"],
        })
        returned[str(selected_id)] = item
    return returned


def logical_export(result: Mapping[str, object]) -> bytes:
    current = result.get("current_artifact")
    if isinstance(current, Mapping):
        current = _public_artifact(current)
    return _canonical({
        "schema": "mirror-ingress-logical-export-v6",
        "schema_version": 6, "database_id": result["database_id"],
        "chain_id": result["chain_id"], "config_digest": result["config_digest"],
        "sequence": result["sequence"], "head_root": result["head_root"],
        "watermark": result["watermark"], "current_artifact": current,
        "counts": {
            "slots": result["slot_count"], "artifacts": result["artifact_count"],
            "events": result["event_count"],
        },
        "flags": dict(FIXED_FLAGS),
    })


__all__ = [
    "SCHEMA", "SCHEMA_VERSION", "TABLES", "STATES", "EVENT_KINDS", "FIXED_FLAGS",
    "IngressVerificationError", "OBSERVATION_KEYS", "OBSERVATION_OUTCOMES",
    "verify_observation_pair", "verify_database", "verify_bytes", "read_artifact",
    "read_artifact_snapshots", "logical_export", "_canonical", "_digest",
    "_raw_digest", "_lease_token_digest", "_event_root", "_stream_root",
    "MAX_DATABASE_BYTES", "MAX_EVENT_BYTES", "MAX_CONFIG_BYTES",
    "MAX_OBSERVATION_BYTES", "MAX_VERIFICATION_RECEIPT_BYTES",
    "MAX_IDENTIFIER_BYTES", "TABLE_COLUMNS", "EXPLICIT_INDEXES",
    "INDEX_DEFINITIONS", "_index_definitions",
]
