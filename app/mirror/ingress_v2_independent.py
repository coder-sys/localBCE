"""Independent reader for the five-table Mirror ingress owner.

This module intentionally does not import the ingress producer.  It verifies
one SQLite snapshot, replays the typed event union, and returns only bounded
state evidence.  Raw FHIR is returned only by the explicitly named internal
artifact reader used by the core owner; support/export callers use the
default raw-free projection.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Mapping

from app.mirror import nc_medicaid_fhir_independent as fhir
from app.mirror.nc_medicaid_fhir_profile import NC_MEDICAID_PROFILE


SCHEMA = "mirror-ingress-v3"
SCHEMA_VERSION = 3
DOMAIN = "BL/MIRROR/INGRESS/V3/"
MAX_DATABASE_BYTES = 64 * 1024 * 1024
MAX_RAW_ENVELOPE_BYTES = 262_144
GENESIS_ROOT = "0" * 128
TABLES = (
    "ingress_meta",
    "ingress_slots",
    "ingress_artifacts",
    "ingress_heads",
    "ingress_events",
)
STATES = (
    "DUE", "LEASED", "CAPTURED", "QUARANTINE_PENDING", "QUARANTINED",
    "HELD", "QUARANTINE_UNCONFIRMED", "WITHDRAWN", "PURGED",
)
EVENT_KINDS = (
    "CREATE_SLOT", "LEASE", "CAPTURE", "FAIL", "REQUEUE",
    "BEGIN_QUARANTINE", "RECOVER_QUARANTINE", "CONFIRM_QUARANTINE",
    "QUARANTINE_UNCONFIRMED", "FETCH_ATTESTATION", "ADMIT", "SUPERSEDE",
    "WITHDRAW", "ARTIFACT_PURGED", "QUARANTINE", "HOLD",
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
EVENT_KEYS = {
    "schema",
    "schema_version",
    "database_id",
    "chain_id",
    "sequence",
    "event_id",
    "event_kind",
    "stream_kind",
    "stream_id",
    "operation_id",
    "request_digest",
    "slot_id",
    "prior_state",
    "next_state",
    "attempt",
    "lease_token",
    "lease_until",
    "observed_at",
    "material_digest",
    "payload_digest",
    "payload_length",
    "before_root",
    "after_root",
    "stream_before_root",
    "stream_after_root",
    "source_id",
    "page_index",
    "transport_attempt",
    "receipt_bytes",
}


class IngressVerificationError(ValueError):
    """Fixed, public-safe ingress verification failure."""


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


def _parse(raw: bytes, label: str) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > 64 * 1024:
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
    if type(value) is not str or len(value) != 128 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise IngressVerificationError(label)
    return value


def content_root(resources: object) -> str:
    if not isinstance(resources, list):
        raise IngressVerificationError("ingress:resources")
    normalized: list[dict[str, object]] = []
    for resource in resources:
        if not isinstance(resource, dict):
            raise IngressVerificationError("ingress:resources")
        resource_type = resource.get("resourceType")
        resource_id = resource.get("id")
        if type(resource_type) is not str or type(resource_id) is not str:
            raise IngressVerificationError("ingress:resource-identity")
        normalized.append({"resourceType": resource_type, "id": resource_id, "resource": resource})
    normalized.sort(key=lambda value: (str(value["resourceType"]), str(value["id"])))
    return _digest("content-root", normalized)


def _attestation_digest(value: Mapping[str, object]) -> str:
    return _digest("attestation", dict(value))


def _event_root(
    *,
    sequence: int,
    previous: str,
    event_id: str,
    event_kind: str,
    stream_kind: str,
    stream_id: str,
    slot_id: str,
    next_state: str,
    observed_at: int,
    material_digest: str,
) -> str:
    return _digest(
        "event-root",
        {
            "sequence": sequence,
            "previous_root": previous,
            "event_id": event_id,
            "event_kind": event_kind,
            "stream_kind": stream_kind,
            "stream_id": stream_id,
            "slot_id": slot_id,
            "next_state": next_state,
            "observed_at": observed_at,
            "material_digest": material_digest,
        },
    )


def _stream_root(
    *,
    sequence: int,
    previous: str,
    event_id: str,
    stream_kind: str,
    stream_id: str,
    next_state: str,
    observed_at: int,
    material_digest: str,
) -> str:
    return _digest(
        "stream-root",
        {
            "sequence": sequence,
            "previous_root": previous,
            "event_id": event_id,
            "stream_kind": stream_kind,
            "stream_id": stream_id,
            "next_state": next_state,
            "observed_at": observed_at,
            "material_digest": material_digest,
        },
    )


def _table_names(connection: sqlite3.Connection) -> tuple[str, ...]:
    rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    return tuple(str(row[0]) for row in rows)


def _columns(connection: sqlite3.Connection, table: str) -> tuple[str, ...]:
    return tuple(str(row[1]) for row in connection.execute(
        "SELECT * FROM pragma_table_info(?) ORDER BY cid", (table,)
    ).fetchall())


def _open(path: str | Path) -> sqlite3.Connection:
    database = Path(path)
    try:
        if not database.is_file() or database.stat().st_size > MAX_DATABASE_BYTES:
            raise IngressVerificationError("ingress:database")
        connection = sqlite3.connect(
            database.resolve().as_uri() + "?mode=ro",
            uri=True,
            isolation_level=None,
            timeout=0.25,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        return connection
    except IngressVerificationError:
        raise
    except (OSError, sqlite3.Error):
        raise IngressVerificationError("ingress:database") from None


def _meta(connection: sqlite3.Connection) -> sqlite3.Row:
    row = connection.execute("SELECT * FROM ingress_meta").fetchone()
    if row is None:
        raise IngressVerificationError("ingress:meta")
    expected = (
        "meta_id", "schema", "schema_version", "database_id", "chain_id",
        "config_digest", "sequence", "head_root", "watermark", "slot_count",
    )
    if tuple(row.keys()) != expected or row["meta_id"] != 1:
        raise IngressVerificationError("ingress:meta")
    if row["schema"] != SCHEMA or row["schema_version"] != SCHEMA_VERSION:
        raise IngressVerificationError("ingress:schema")
    _hex(row["config_digest"], "ingress:config")
    if type(row["database_id"]) is not str or not row["database_id"]:
        raise IngressVerificationError("ingress:database-id")
    if type(row["chain_id"]) is not str or not row["chain_id"]:
        raise IngressVerificationError("ingress:chain-id")
    if type(row["sequence"]) is not int or row["sequence"] < 0:
        raise IngressVerificationError("ingress:sequence")
    if type(row["watermark"]) is not int or row["watermark"] < 0 or type(row["slot_count"]) is not int or row["slot_count"] < 0:
        raise IngressVerificationError("ingress:watermark")
    if row["head_root"] != GENESIS_ROOT and not (
        type(row["head_root"]) is str and len(row["head_root"]) == 128
    ):
        raise IngressVerificationError("ingress:head-root")
    return row


def _verify_artifact(row: sqlite3.Row) -> dict[str, object]:
    expected = (
        "artifact_id", "envelope_id", "envelope_digest", "raw", "profile_id",
        "profile_version", "profile_digest", "observation_time", "fetched_at",
        "source_status", "failure_code", "freshness", "page_complete",
        "snapshot_id", "snapshot_root", "content_root", "page_count",
        "resource_count", "event_sequence",
    )
    if tuple(row.keys()) != expected:
        raise IngressVerificationError("ingress:artifact-columns")
    raw = row["raw"]
    if type(raw) is not bytes or not raw or len(raw) > MAX_RAW_ENVELOPE_BYTES:
        raise IngressVerificationError("ingress:artifact-raw")
    if row["envelope_digest"] != _raw_digest("envelope", raw):
        raise IngressVerificationError("ingress:artifact-digest")
    try:
        result = fhir.verify_bytes(raw)
    except Exception:
        raise IngressVerificationError("ingress:envelope") from None
    checks = {
        "envelope_id": result["envelope_id"],
        "profile_id": NC_MEDICAID_PROFILE.source_profile_id,
        "profile_version": NC_MEDICAID_PROFILE.version,
        "profile_digest": NC_MEDICAID_PROFILE.profile_digest,
        "observation_time": result["observation_time"],
        "fetched_at": result["fetched_at"],
        "source_status": result["source_status"],
        "failure_code": result["failure_code"],
        "freshness": result["freshness"],
        "page_complete": result["page_complete"],
        "snapshot_id": result["snapshot_id"],
        "snapshot_root": result["snapshot_root"],
        "content_root": content_root(result["resources"]),
        "page_count": result["page_count"],
        "resource_count": result["resource_count"],
    }
    for key, value in checks.items():
        if row[key] != value:
            raise IngressVerificationError("ingress:artifact-binding")
    _hex(row["envelope_id"], "ingress:envelope-id")
    _hex(row["envelope_digest"], "ingress:envelope-digest")
    _hex(row["snapshot_id"], "ingress:snapshot-id")
    _hex(row["snapshot_root"], "ingress:snapshot-root")
    _hex(row["content_root"], "ingress:content-root")
    expected_id = _digest(
        "artifact-id",
        {
            "envelope_digest": row["envelope_digest"],
            "envelope_id": row["envelope_id"],
            "profile_digest": row["profile_digest"],
            "observation_time": row["observation_time"],
            "snapshot_id": row["snapshot_id"],
        },
    )
    if row["artifact_id"] != expected_id:
        raise IngressVerificationError("ingress:artifact-id")
    return {
        "artifact_id": row["artifact_id"],
        "envelope_id": row["envelope_id"],
        "envelope_digest": row["envelope_digest"],
        "profile_id": row["profile_id"],
        "profile_version": row["profile_version"],
        "profile_digest": row["profile_digest"],
        "observation_time": row["observation_time"],
        "fetched_at": row["fetched_at"],
        "source_status": row["source_status"],
        "failure_code": row["failure_code"],
        "freshness": row["freshness"],
        "page_complete": row["page_complete"],
        "snapshot_id": row["snapshot_id"],
        "snapshot_root": row["snapshot_root"],
        "content_root": row["content_root"],
        "page_count": row["page_count"],
        "resource_count": row["resource_count"],
        "event_sequence": row["event_sequence"],
        "raw": raw,
        "result": result,
    }


def _verify_fetch_receipt(
    receipt_raw: bytes,
    *,
    artifact: Mapping[str, object],
    slot_id: str,
    source_id: str,
    page_index: int,
    transport_attempt: int,
    lease_attempt: int,
    observed_at: int,
) -> dict[str, object]:
    value = _parse(receipt_raw, "ingress:fetch-receipt")
    expected_keys = {
        "schema", "schema_version", "artifact_id", "source_id", "slot_id",
        "page_index", "lease_attempt", "transport_attempt", "attestation_digest",
        "request_identity", "response_digest", "status", "retry_after_seconds",
        "response_url", "redirect", "failure_code", "transport_error",
        "evidence_class", "selected", "observed_at",
    }
    if set(value) != expected_keys or value["schema"] != SCHEMA or value["schema_version"] != SCHEMA_VERSION:
        raise IngressVerificationError("ingress:fetch-receipt-keys")
    page_evidence = artifact["result"].get("page_evidence") if isinstance(artifact.get("result"), Mapping) else None
    if not isinstance(page_evidence, tuple) or page_index >= len(page_evidence):
        raise IngressVerificationError("ingress:fetch-evidence")
    page = page_evidence[page_index]
    attempts = page.get("attempts") if isinstance(page, Mapping) else None
    if not isinstance(attempts, tuple) or transport_attempt >= len(attempts):
        raise IngressVerificationError("ingress:fetch-evidence")
    expected = attempts[transport_attempt]
    if not isinstance(expected, Mapping):
        raise IngressVerificationError("ingress:fetch-evidence")
    if (
        value["artifact_id"] != artifact["artifact_id"]
        or value["source_id"] != source_id
        or value["source_id"] != NC_MEDICAID_PROFILE.source_profile_id
        or value["slot_id"] != slot_id
        or value["page_index"] != page_index
        or value["lease_attempt"] != lease_attempt
        or value["transport_attempt"] != transport_attempt
        or value["request_identity"] != expected["request_identity"]
        or value["response_digest"] != expected["response_digest"]
        or value["status"] != expected["status"]
        or value["retry_after_seconds"] != expected["retry_after_seconds"]
        or value["response_url"] != expected["response_url"]
        or value["redirect"] != expected["redirect"]
        or value["failure_code"] != expected["failure_code"]
        or value["transport_error"] != expected["transport_error"]
        or value["evidence_class"] != "SYNTHETIC_FIXTURE_UNAUTHENTICATED"
        or value["selected"] != expected["selected"]
        or value["observed_at"] != observed_at
    ):
        raise IngressVerificationError("ingress:fetch-binding")
    material = {
        "artifact_id": value["artifact_id"],
        "page_index": value["page_index"],
        "lease_attempt": value["lease_attempt"],
        "transport_attempt": value["transport_attempt"],
        "request_identity": value["request_identity"],
        "response_digest": value["response_digest"],
        "status": value["status"],
        "retry_after_seconds": value["retry_after_seconds"],
        "response_url": value["response_url"],
        "redirect": value["redirect"],
        "failure_code": value["failure_code"],
        "transport_error": value["transport_error"],
        "evidence_class": value["evidence_class"],
        "selected": value["selected"],
        "observed_at": value["observed_at"],
    }
    if value["attestation_digest"] != _attestation_digest(material):
        raise IngressVerificationError("ingress:fetch-digest")
    return value


def _verify_event(
    row: sqlite3.Row,
    *,
    meta: sqlite3.Row,
    previous_root: str,
    slot_states: dict[str, str],
    slot_attempts: dict[str, int],
    slot_schedules: Mapping[str, int],
    slot_times: dict[str, int],
    global_observed_at: list[int | None],
    slot_leases: dict[str, tuple[str | None, int | None, int]],
    artifacts: Mapping[str, Mapping[str, object]],
    heads: dict[tuple[str, str], tuple[str | None, str, int]],
    stream_roots: dict[tuple[str, str], str],
    fetches: dict[str, list[dict[str, object]]],
) -> str:
    if tuple(row.keys()) != (
        "sequence", "event_id", "event_kind", "database_id", "chain_id",
        "stream_kind", "stream_id", "operation_id", "request_digest", "slot_id", "prior_state",
        "next_state", "attempt", "lease_token", "lease_until",
        "observed_at",
        "material_digest", "payload_digest", "payload_length",
        "before_root", "after_root", "stream_before_root", "stream_after_root",
        "event_raw", "receipt_digest",
        "source_id", "page_index", "transport_attempt", "receipt_bytes",
    ):
        raise IngressVerificationError("ingress:event-columns")
    if row["sequence"] <= 0 or row["database_id"] != meta["database_id"] or row["chain_id"] != meta["chain_id"]:
        raise IngressVerificationError("ingress:event-binding")
    raw = row["event_raw"]
    value = _parse(raw, "ingress:event-raw")
    if set(value) != EVENT_KEYS:
        raise IngressVerificationError("ingress:event-keys")
    for key in EVENT_KEYS:
        if key not in row.keys():
            continue
        row_value = row[key]
        if key == "receipt_bytes":
            if row_value is not None:
                if type(row_value) is not bytes:
                    raise IngressVerificationError("ingress:event-receipt")
                row_value = row_value.decode("ascii")
        if value[key] != row_value:
            raise IngressVerificationError("ingress:event-receipt")
    if row["before_root"] != previous_root or row["event_kind"] not in EVENT_KINDS:
        raise IngressVerificationError("ingress:event-order")
    if type(row["observed_at"]) is not int or row["observed_at"] < 0:
        raise IngressVerificationError("ingress:event-time")
    if row["event_id"] != _digest("event-id", {key: value[key] for key in EVENT_KEYS if key not in {"event_id", "after_root", "stream_after_root"}}):
        raise IngressVerificationError("ingress:event-id")
    if row["receipt_digest"] != _raw_digest("receipt", raw):
        raise IngressVerificationError("ingress:receipt")
    if row["stream_before_root"] != stream_roots.get((row["stream_kind"], row["stream_id"]), GENESIS_ROOT):
        raise IngressVerificationError("ingress:stream-order")
    expected_stream_after = _stream_root(
        sequence=row["sequence"],
        previous=row["stream_before_root"],
        event_id=row["event_id"],
        stream_kind=row["stream_kind"],
        stream_id=row["stream_id"],
        next_state=row["next_state"],
        observed_at=row["observed_at"],
        material_digest=row["material_digest"],
    )
    if row["stream_after_root"] != expected_stream_after:
        raise IngressVerificationError("ingress:stream-root")
    expected_after = _event_root(
        sequence=row["sequence"],
        previous=previous_root,
        event_id=row["event_id"],
        event_kind=row["event_kind"],
        stream_kind=row["stream_kind"],
        stream_id=row["stream_id"],
        slot_id=row["slot_id"],
        next_state=row["next_state"],
        observed_at=row["observed_at"],
        material_digest=row["material_digest"],
    )
    if row["after_root"] != expected_after:
        raise IngressVerificationError("ingress:event-root")
    if row["event_kind"] != "FETCH_ATTESTATION" and any(
        row[key] is not None for key in ("source_id", "page_index", "transport_attempt", "receipt_bytes")
    ):
        raise IngressVerificationError("ingress:event-receipt")
    prior = slot_states.get(row["slot_id"])
    if row["prior_state"] != (prior or "NONE"):
        raise IngressVerificationError("ingress:event-state")
    if row["next_state"] not in STATES:
        raise IngressVerificationError("ingress:event-state")
    scheduled_at = slot_schedules.get(str(row["slot_id"]))
    if scheduled_at is None:
        raise IngressVerificationError("ingress:event-time")
    if row["event_kind"] != "CREATE_SLOT" and row["observed_at"] < scheduled_at:
        raise IngressVerificationError("ingress:event-time")
    previous_observed_at = slot_times.get(str(row["slot_id"]))
    if previous_observed_at is not None and row["observed_at"] < previous_observed_at:
        raise IngressVerificationError("ingress:event-chronology")
    previous_global_observed_at = global_observed_at[0]
    if previous_global_observed_at is not None and row["observed_at"] < previous_global_observed_at:
        raise IngressVerificationError("ingress:event-chronology")
    global_observed_at[0] = int(row["observed_at"])
    if row["event_kind"] == "LEASE":
        if type(row["lease_token"]) is not str or not row["lease_token"] or type(row["lease_until"]) is not int or row["lease_until"] <= row["observed_at"]:
            raise IngressVerificationError("ingress:lease")
    if row["event_kind"] in {"REQUEUE", "HOLD"}:
        if type(row["lease_until"]) is not int or row["observed_at"] < row["lease_until"]:
            raise IngressVerificationError("ingress:lease-expiry")
    allowed = {
        "CREATE_SLOT": ("NONE", "DUE"),
        "LEASE": ("DUE", "LEASED"),
        "REQUEUE": ("LEASED", "DUE"),
        "CAPTURE": ("LEASED", "CAPTURED"),
        "FETCH_ATTESTATION": ("LEASED", "LEASED"),
        "FAIL": ("CAPTURED", "HELD"),
        "HOLD": ("LEASED", "HELD"),
        "BEGIN_QUARANTINE": ("CAPTURED", "QUARANTINE_PENDING"),
        "RECOVER_QUARANTINE": ("QUARANTINE_UNCONFIRMED", "QUARANTINE_PENDING"),
        "CONFIRM_QUARANTINE": ("QUARANTINE_PENDING", "QUARANTINED"),
        "ADMIT": ("QUARANTINE_PENDING", "QUARANTINED"),
        "QUARANTINE": ("CAPTURED", "QUARANTINED"),
        "QUARANTINE_UNCONFIRMED": ("QUARANTINE_PENDING", "QUARANTINE_UNCONFIRMED"),
        "SUPERSEDE": ("QUARANTINED", "QUARANTINED"),
        "WITHDRAW": ("QUARANTINED", "WITHDRAWN"),
        "ARTIFACT_PURGED": ("WITHDRAWN", "PURGED"),
    }
    if row["event_kind"] not in allowed:
        raise IngressVerificationError("ingress:event-transition")
    capture_edge = (row["prior_state"], row["next_state"])
    if row["event_kind"] == "CAPTURE" and capture_edge != ("LEASED", "CAPTURED"):
        raise IngressVerificationError("ingress:event-transition")
    if row["event_kind"] != "CAPTURE" and capture_edge != allowed[row["event_kind"]]:
        raise IngressVerificationError("ingress:event-transition")
    if row["event_kind"] in {
        "FAIL", "HOLD", "QUARANTINE_UNCONFIRMED", "CONFIRM_QUARANTINE", "ADMIT",
        "QUARANTINE", "SUPERSEDE", "WITHDRAW", "ARTIFACT_PURGED",
    } and (row["stream_kind"], row["stream_id"]) != ("QUARANTINE", meta["chain_id"]):
        raise IngressVerificationError("ingress:quarantine-stream")
    if row["event_kind"] == "CREATE_SLOT":
        slot_attempts[row["slot_id"]] = 0
        slot_leases[row["slot_id"]] = (None, None, 0)
    elif row["event_kind"] == "LEASE":
        if row["attempt"] != slot_attempts.get(row["slot_id"], 0) + 1:
            raise IngressVerificationError("ingress:attempt")
        slot_attempts[row["slot_id"]] = row["attempt"]
        if slot_leases.get(row["slot_id"], (None, None, 0))[0] is not None:
            raise IngressVerificationError("ingress:lease-state")
        slot_leases[row["slot_id"]] = (str(row["lease_token"]), int(row["lease_until"]), int(row["attempt"]))
    elif row["event_kind"] == "REQUEUE":
        if row["attempt"] != slot_attempts.get(row["slot_id"], 0):
            raise IngressVerificationError("ingress:attempt")
        active = slot_leases.get(row["slot_id"], (None, None, 0))
        if active[0] != row["lease_token"] or active[1] != row["lease_until"]:
            raise IngressVerificationError("ingress:lease")
        slot_leases[row["slot_id"]] = (None, None, int(row["attempt"]))
    active_lease = slot_leases.get(row["slot_id"], (None, None, 0))
    if row["event_kind"] in {
        "FETCH_ATTESTATION", "CAPTURE", "BEGIN_QUARANTINE", "RECOVER_QUARANTINE",
        "CONFIRM_QUARANTINE", "ADMIT", "QUARANTINE", "QUARANTINE_UNCONFIRMED",
        "FAIL",
    }:
        if (
            active_lease[0] is None
            or row["attempt"] != active_lease[2]
            or row["lease_token"] != active_lease[0]
            or row["lease_until"] != active_lease[1]
            or row["observed_at"] >= int(active_lease[1])
        ):
            raise IngressVerificationError("ingress:lease")
    if row["event_kind"] == "FETCH_ATTESTATION":
        if (
            row["stream_kind"] != "FETCH"
            or row["stream_id"] != row["slot_id"]
            or row["source_id"] is None
            or type(row["page_index"]) is not int
            or type(row["transport_attempt"]) is not int
            or row["page_index"] < 0
            or row["transport_attempt"] < 0
            or row["receipt_bytes"] is None
        ):
            raise IngressVerificationError("ingress:fetch-columns")
        receipt_raw = bytes(row["receipt_bytes"])
        receipt_value = _parse(receipt_raw, "ingress:fetch-receipt")
        artifact_id = receipt_value.get("artifact_id")
        if type(artifact_id) is not str or artifact_id not in artifacts:
            raise IngressVerificationError("ingress:event-artifact")
        receipt = _verify_fetch_receipt(
            receipt_raw,
            artifact=artifacts[artifact_id],
            slot_id=row["slot_id"],
            source_id=row["source_id"],
            page_index=row["page_index"],
            transport_attempt=row["transport_attempt"],
            lease_attempt=row["attempt"],
            observed_at=row["observed_at"],
        )
        material = {
            key: receipt[key]
            for key in (
                "artifact_id", "page_index", "lease_attempt", "transport_attempt",
                "request_identity", "response_digest", "status", "retry_after_seconds",
                "response_url", "redirect", "failure_code", "transport_error",
                "evidence_class", "selected", "observed_at",
            )
        }
        if (
            row["material_digest"] != _digest("material", material)
            or row["payload_digest"] != _digest("fetch-payload", material)
            or row["payload_length"] != len(row["receipt_bytes"])
        ):
            raise IngressVerificationError("ingress:fetch-payload")
        fetches.setdefault(str(receipt["artifact_id"]), []).append(receipt)
    elif row["event_kind"] == "CAPTURE":
        artifact_id = row["payload_digest"]
        if artifact_id not in artifacts:
            raise IngressVerificationError("ingress:event-artifact")
    if row["event_kind"] in {"BEGIN_QUARANTINE", "RECOVER_QUARANTINE", "CONFIRM_QUARANTINE", "ADMIT", "QUARANTINE", "HOLD", "FAIL", "QUARANTINE_UNCONFIRMED", "SUPERSEDE", "WITHDRAW", "ARTIFACT_PURGED"}:
        artifact_id = row["payload_digest"]
        if artifact_id not in artifacts:
            raise IngressVerificationError("ingress:event-artifact")
    head_key = (str(row["stream_kind"]), str(row["stream_id"]))
    prior_head = heads.get(head_key)
    head_artifact_id = None
    if row["event_kind"] == "FETCH_ATTESTATION":
        head_artifact_id = str(receipt["artifact_id"])
    elif row["event_kind"] in {"CAPTURE", "BEGIN_QUARANTINE", "RECOVER_QUARANTINE", "CONFIRM_QUARANTINE", "ADMIT", "QUARANTINE", "FAIL", "HOLD", "QUARANTINE_UNCONFIRMED", "SUPERSEDE", "WITHDRAW", "ARTIFACT_PURGED"}:
        head_artifact_id = str(row["payload_digest"])
    if head_artifact_id is None and prior_head is not None:
        head_artifact_id = prior_head[0]
    heads[head_key] = (head_artifact_id, row["stream_after_root"], row["sequence"])
    stream_roots[head_key] = row["stream_after_root"]
    if row["event_kind"] in {
        "FAIL", "HOLD", "ADMIT", "QUARANTINE", "CONFIRM_QUARANTINE",
        "QUARANTINE_UNCONFIRMED", "WITHDRAW", "ARTIFACT_PURGED",
    }:
        slot_leases[row["slot_id"]] = (None, None, int(row["attempt"]))
    slot_times[str(row["slot_id"])] = int(row["observed_at"])
    slot_states[row["slot_id"]] = row["next_state"]
    return row["after_root"]


def _verify_connection(
    connection: sqlite3.Connection,
    *,
    expected_database_id: str | None = None,
    expected_config_digest: str | None = None,
    include_raw: bool = False,
    artifact_id: str | None = None,
    artifact_ids: tuple[str, ...] | None = None,
) -> dict[str, object]:
    try:
        if _table_names(connection) != tuple(sorted(TABLES)):
            raise IngressVerificationError("ingress:tables")
        expected_columns = {
            "ingress_meta": ("meta_id", "schema", "schema_version", "database_id", "chain_id", "config_digest", "sequence", "head_root", "watermark", "slot_count"),
            "ingress_slots": ("slot_id", "scheduled_at", "state", "attempt", "lease_token", "lease_until", "artifact_id", "operation_id"),
            "ingress_artifacts": ("artifact_id", "envelope_id", "envelope_digest", "raw", "profile_id", "profile_version", "profile_digest", "observation_time", "fetched_at", "source_status", "failure_code", "freshness", "page_complete", "snapshot_id", "snapshot_root", "content_root", "page_count", "resource_count", "event_sequence"),
            "ingress_heads": ("stream_kind", "stream_id", "artifact_id", "head_root", "event_sequence"),
            "ingress_events": ("sequence", "event_id", "event_kind", "database_id", "chain_id", "stream_kind", "stream_id", "operation_id", "request_digest", "slot_id", "prior_state", "next_state", "attempt", "lease_token", "lease_until", "observed_at", "material_digest", "payload_digest", "payload_length", "before_root", "after_root", "stream_before_root", "stream_after_root", "event_raw", "receipt_digest", "source_id", "page_index", "transport_attempt", "receipt_bytes"),
        }
        for table, columns in expected_columns.items():
            if _columns(connection, table) != columns:
                raise IngressVerificationError("ingress:columns")
        meta = _meta(connection)
        if expected_database_id is not None and meta["database_id"] != expected_database_id:
            raise IngressVerificationError("ingress:database-id")
        if expected_config_digest is not None and meta["config_digest"] != expected_config_digest:
            raise IngressVerificationError("ingress:config")
        slots = connection.execute("SELECT * FROM ingress_slots ORDER BY slot_id").fetchall()
        if meta["slot_count"] != len(slots):
            raise IngressVerificationError("ingress:slot-count")
        artifacts_rows = connection.execute("SELECT * FROM ingress_artifacts ORDER BY artifact_id").fetchall()
        artifacts = {row["artifact_id"]: _verify_artifact(row) for row in artifacts_rows}
        if len(artifacts) != len(artifacts_rows):
            raise IngressVerificationError("ingress:artifact-duplicate")
        slot_states: dict[str, str] = {}
        slot_attempts: dict[str, int] = {}
        slot_schedules = {str(row["slot_id"]): int(row["scheduled_at"]) for row in slots}
        slot_times: dict[str, int] = {}
        global_observed_at: list[int | None] = [None]
        slot_leases: dict[str, tuple[str | None, int | None, int]] = {}
        previous = GENESIS_ROOT
        heads: dict[tuple[str, str], tuple[str | None, str, int]] = {}
        stream_roots: dict[tuple[str, str], str] = {}
        fetches: dict[str, list[dict[str, object]]] = {}
        events = connection.execute("SELECT * FROM ingress_events ORDER BY sequence").fetchall()
        for expected_sequence, row in enumerate(events, start=1):
            if row["sequence"] != expected_sequence:
                raise IngressVerificationError("ingress:event-sequence")
            previous = _verify_event(
                row,
                meta=meta,
                previous_root=previous,
                slot_states=slot_states,
                slot_attempts=slot_attempts,
                slot_schedules=slot_schedules,
                slot_times=slot_times,
                global_observed_at=global_observed_at,
                slot_leases=slot_leases,
                artifacts=artifacts,
                heads=heads,
                stream_roots=stream_roots,
                fetches=fetches,
            )
        for artifact_id, artifact in artifacts.items():
            selected = fetches.get(artifact_id, [])
            page_evidence = artifact["result"].get("page_evidence") if isinstance(artifact.get("result"), Mapping) else None
            if not isinstance(page_evidence, tuple):
                raise IngressVerificationError("ingress:fetch-evidence")
            expected_keys = [
                (int(page["page_index"]), int(attempt["transport_attempt"]))
                for page in page_evidence
                for attempt in page["attempts"]
            ]
            actual_keys = [(int(item["page_index"]), int(item["transport_attempt"])) for item in selected]
            if actual_keys != expected_keys:
                raise IngressVerificationError("ingress:attestation-count")
        for row in slots:
            if row["slot_id"] not in slot_states or row["state"] != slot_states[row["slot_id"]]:
                raise IngressVerificationError("ingress:slot-state")
            if row["attempt"] != slot_attempts.get(row["slot_id"], 0):
                raise IngressVerificationError("ingress:slot-attempt")
            lease = slot_leases.get(str(row["slot_id"]), (None, None, 0))
            if row["state"] == "LEASED":
                if (row["lease_token"], row["lease_until"]) != (lease[0], lease[1]):
                    raise IngressVerificationError("ingress:slot-lease")
            elif row["lease_token"] is not None or row["lease_until"] is not None:
                raise IngressVerificationError("ingress:slot-lease")
            if row["artifact_id"] is not None and row["artifact_id"] not in artifacts:
                raise IngressVerificationError("ingress:slot-artifact")
        head_rows = connection.execute("SELECT * FROM ingress_heads ORDER BY stream_kind,stream_id").fetchall()
        actual_head_keys: set[tuple[str, str]] = set()
        for row in head_rows:
            if tuple(row.keys()) != ("stream_kind", "stream_id", "artifact_id", "head_root", "event_sequence"):
                raise IngressVerificationError("ingress:head-columns")
            key = (str(row["stream_kind"]), str(row["stream_id"]))
            if key in actual_head_keys:
                raise IngressVerificationError("ingress:head-cardinality")
            actual_head_keys.add(key)
            expected_head = heads.get(key)
            if expected_head is None or tuple(row) != (key[0], key[1], expected_head[0], expected_head[1], expected_head[2]):
                raise IngressVerificationError("ingress:head-binding")
            if row["artifact_id"] is not None and row["artifact_id"] not in artifacts:
                raise IngressVerificationError("ingress:head-artifact")
        if actual_head_keys != set(heads):
            raise IngressVerificationError("ingress:head-missing")
        quarantine_head = next(
            (row for row in head_rows if row["stream_kind"] == "QUARANTINE" and row["stream_id"] == meta["chain_id"]),
            None,
        )
        if meta["sequence"] != len(events) or meta["head_root"] != previous:
            raise IngressVerificationError("ingress:meta-root")
        if meta["watermark"] != meta["sequence"]:
            raise IngressVerificationError("ingress:watermark")
        result: dict[str, object] = {
            "accepted": True,
            "schema": SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "database_id": meta["database_id"],
            "chain_id": meta["chain_id"],
            "config_digest": meta["config_digest"],
            "sequence": meta["sequence"],
            "head_root": meta["head_root"],
            "watermark": meta["watermark"],
            "slot_count": len(slots),
            "artifact_count": len(artifacts_rows),
            "attestation_count": sum(len(items) for items in fetches.values()),
            "event_count": len(events),
            "state_counts": {state: sum(1 for row in slots if row["state"] == state) for state in STATES},
            "flags": dict(FIXED_FLAGS),
        }
        if artifact_ids is not None:
            selected: dict[str, dict[str, object]] = {}
            for selected_id in artifact_ids:
                if selected_id not in artifacts:
                    raise IngressVerificationError("ingress:artifact-missing")
                selected[selected_id] = dict(artifacts[selected_id])
                if not include_raw:
                    selected[selected_id].pop("raw", None)
                    selected[selected_id].pop("result", None)
            result["selected_artifacts"] = selected
        if quarantine_head is not None and quarantine_head["artifact_id"] is not None:
            result["current_artifact_id"] = quarantine_head["artifact_id"]
            selected_id = artifact_id or quarantine_head["artifact_id"]
            if selected_id not in artifacts:
                raise IngressVerificationError("ingress:artifact-missing")
            current = artifacts[selected_id]
            result["current_artifact"] = dict(current)
            result["selected_artifact_id"] = selected_id
            if not include_raw:
                result["current_artifact"].pop("raw", None)
                result["current_artifact"].pop("result", None)
        else:
            if artifact_id is not None:
                raise IngressVerificationError("ingress:artifact-missing")
            result["current_artifact_id"] = None
            result["current_artifact"] = None
        return result
    except IngressVerificationError:
        raise
    except (sqlite3.Error, OSError, TypeError, ValueError):
        raise IngressVerificationError("ingress:database") from None


def verify_database(
    path: str | Path,
    *,
    expected_database_id: str | None = None,
    expected_config_digest: str | None = None,
    include_raw: bool = False,
    artifact_id: str | None = None,
    artifact_ids: tuple[str, ...] | None = None,
) -> dict[str, object]:
    connection = _open(path)
    try:
        return _verify_connection(
            connection,
            expected_database_id=expected_database_id,
            expected_config_digest=expected_config_digest,
            include_raw=include_raw,
            artifact_id=artifact_id,
            artifact_ids=artifact_ids,
        )
    finally:
        try:
            connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        connection.close()


def verify_bytes(
    raw: bytes,
    *,
    expected_database_id: str | None = None,
    expected_config_digest: str | None = None,
    include_raw: bool = False,
    artifact_id: str | None = None,
    artifact_ids: tuple[str, ...] | None = None,
) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_DATABASE_BYTES:
        raise IngressVerificationError("ingress:image")
    try:
        connection = sqlite3.connect(":memory:", isolation_level=None, timeout=0.25)
        connection.row_factory = sqlite3.Row
        connection.deserialize(raw)
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        return _verify_connection(
            connection,
            expected_database_id=expected_database_id,
            expected_config_digest=expected_config_digest,
            include_raw=include_raw,
            artifact_id=artifact_id,
            artifact_ids=artifact_ids,
        )
    except IngressVerificationError:
        raise
    except (OSError, sqlite3.Error, TypeError, ValueError):
        raise IngressVerificationError("ingress:image") from None
    finally:
        try:
            connection.execute("ROLLBACK")
        except (NameError, sqlite3.Error):
            pass
        try:
            connection.close()
        except (NameError, sqlite3.Error):
            pass


def read_artifact(path: str | Path, artifact_id: str) -> dict[str, object]:
    result = verify_database(path, include_raw=True, artifact_id=artifact_id)
    artifact = result.get("current_artifact")
    if not isinstance(artifact, dict) or result.get("current_artifact_id") != artifact_id:
        raise IngressVerificationError("ingress:artifact-not-current")
    returned = dict(artifact)
    returned["head_root"] = result["head_root"]
    returned["database_id"] = result["database_id"]
    returned["chain_id"] = result["chain_id"]
    return returned


def read_artifact_snapshot(path: str | Path, artifact_id: str) -> dict[str, object]:
    result = verify_database(path, include_raw=True, artifact_ids=(artifact_id,))
    selected = result.get("selected_artifacts")
    artifact = selected.get(artifact_id) if isinstance(selected, dict) else None
    if not isinstance(artifact, dict) or artifact.get("artifact_id") != artifact_id:
        raise IngressVerificationError("ingress:artifact-missing")
    returned = dict(artifact)
    returned["head_root"] = result["head_root"]
    returned["database_id"] = result["database_id"]
    returned["chain_id"] = result["chain_id"]
    returned["current_artifact_id"] = result["current_artifact_id"]
    return returned


def read_artifact_snapshots(path: str | Path, artifact_ids: tuple[str, ...]) -> dict[str, dict[str, object]]:
    if type(artifact_ids) is not tuple or any(type(value) is not str or not value for value in artifact_ids):
        raise IngressVerificationError("ingress:artifact-selector")
    if len(set(artifact_ids)) != len(artifact_ids):
        raise IngressVerificationError("ingress:artifact-selector")
    result = verify_database(path, include_raw=True, artifact_ids=artifact_ids)
    selected = result.get("selected_artifacts")
    if not isinstance(selected, dict):
        raise IngressVerificationError("ingress:artifact-selector")
    returned: dict[str, dict[str, object]] = {}
    for selected_id, artifact in selected.items():
        if not isinstance(artifact, dict):
            raise IngressVerificationError("ingress:artifact-selector")
        item = dict(artifact)
        item["head_root"] = result["head_root"]
        item["database_id"] = result["database_id"]
        item["chain_id"] = result["chain_id"]
        item["current_artifact_id"] = result["current_artifact_id"]
        returned[str(selected_id)] = item
    return returned


def logical_export(result: Mapping[str, object]) -> bytes:
    current = result.get("current_artifact")
    if isinstance(current, Mapping):
        current = {key: value for key, value in current.items() if key not in {"raw", "result"}}
    value = {
        "schema": "mirror-ingress-logical-export-v2",
        "schema_version": 2,
        "database_id": result["database_id"],
        "chain_id": result["chain_id"],
        "config_digest": result["config_digest"],
        "sequence": result["sequence"],
        "head_root": result["head_root"],
        "watermark": result["watermark"],
        "current_artifact": current,
        "counts": {
            "slots": result["slot_count"],
            "artifacts": result["artifact_count"],
            "attestations": result["attestation_count"],
            "events": result["event_count"],
        },
        "flags": dict(FIXED_FLAGS),
    }
    return _canonical(value)


__all__ = [
    "SCHEMA", "SCHEMA_VERSION", "TABLES", "STATES", "FIXED_FLAGS",
    "IngressVerificationError", "content_root", "verify_database", "verify_bytes",
    "read_artifact", "logical_export", "_canonical", "_digest", "_raw_digest",
    "read_artifact_snapshot",
    "read_artifact_snapshots",
]
