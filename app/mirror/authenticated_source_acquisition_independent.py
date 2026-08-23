"""Independent verifier for the bounded authenticated-source acquisition ledger.

The producer owns only scheduling and SQLite mutation.  This module does not
import the producer; it reconstructs the configuration, transport attestations,
slot state, append-only transition root, exports, and privacy-safe support view
from bytes and the fixed NC profile.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sqlite3
from typing import Mapping

from app.mirror import external_source_adapter_independent as adapter
from app.mirror import external_source_quarantine_independent as quarantine
from app.mirror import nc_medicaid_fhir_independent as nc_fhir
from app.mirror.nc_medicaid_fhir_profile import NC_MEDICAID_PROFILE


SCHEMA = "mirror-authenticated-source-acquisition-v1"
SCHEMA_VERSION = 1
EXPORT_SCHEMA = "mirror-authenticated-source-acquisition-export-v1"
EXPORT_VERSION = 1
DOMAIN = "BL/MIRROR/AUTHENTICATED-SOURCE-ACQUISITION/"
GENESIS_TRANSITION = "0" * 128
STATES = {"DUE", "LEASED", "CAPTURED", "QUARANTINED", "HELD"}
SAFE_FAILURES = {
    "wrong-host", "redirect", "capability-mismatch", "authorization-mismatch",
    "terms-mismatch", "request-mismatch", "response-digest", "status", "media-type",
    "timeout", "rate-limit", "server-error", "retry-exhausted", "partial-page",
    "stale", "incomplete", "verifier", "quarantine-head", "lease", "busy",
    "response-loss", "database", "profile-drift", "transport", "body-cap",
}
MAX_EXPORT_BYTES = 8 * 1024 * 1024
MAX_DATABASE_BYTES = 32 * 1024 * 1024
MAX_SLOTS = 4_096
MAX_TRANSITIONS = 16_384
MAX_ATTESTATIONS = 32_768
BUSY_TIMEOUT_MS = 500
HEX128 = re.compile(r"^[0-9a-f]{128}$")
SAFE_TEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")

CONFIG_KEYS = {
    "acquisition_id", "version", "nc_profile_digest", "external_policy_digest",
    "quarantine_policy_digest", "quarantine_chain_id", "quarantine_database_id",
    "transport_id", "transport_epoch", "authorization_artifact_digest",
    "terms_artifact_digest", "endpoint_id", "request_digest", "cadence_seconds",
    "freshness_grace_seconds", "max_body_bytes", "max_page_count", "max_attempts",
    "lease_seconds", "busy_timeout_ms", "max_slots", "zero_phi", "state_owned",
    "live_transport_authorized", "production_source_authentication", "production_usable",
    "activation", "proofSuiteId",
}
META_KEYS = {
    "schema", "schema_version", "acquisition_id", "config_digest", "chain_id",
    "sequence", "state_root", "head_transition_id", "state_owned", "zero_phi",
    "production_usable", "activation", "payment_authority", "clearance_authority",
    "settlement_authority", "proofSuiteId",
}
SLOT_COLUMNS = (
    "slot_id", "scheduled_at", "state", "lease_id", "lease_until", "attempt",
    "envelope_id", "envelope_digest", "artifact_id", "artifact_digest", "capture_id",
    "payload_digest", "snapshot_root", "observed_at", "fetched_at",
    "quarantine_expected_head", "quarantine_head", "quarantine_head_root",
    "quarantine_transition_id", "quarantine_receipt_digest", "quarantine_receipt_raw",
    "failure_code", "last_operation_id",
)
OPERATION_COLUMNS = (
    "operation_id", "slot_id", "action", "attempt", "request_digest", "material_digest",
    "transition_id", "receipt_digest", "sequence", "receipt_raw",
)
TRANSITION_COLUMNS = (
    "transition_id", "sequence", "slot_id", "operation_id", "prior_state", "next_state",
    "before_root", "after_root", "material_digest", "observed_at", "transition_raw",
)
ATTESTATION_COLUMNS = (
    "slot_id", "page_index", "attempt", "request_digest", "server_identity_digest",
    "authorization_artifact_digest", "terms_artifact_digest", "response_digest", "status",
    "media_type", "observed_at", "fetched_at", "redirect", "transport_authenticated",
    "attestation_digest",
)
TABLE_COLUMNS = {
    "acquisition_meta": {"key", "value"},
    "acquisition_slots": set(SLOT_COLUMNS),
    "acquisition_operations": set(OPERATION_COLUMNS),
    "acquisition_transitions": set(TRANSITION_COLUMNS),
    "acquisition_attestations": set(ATTESTATION_COLUMNS),
}
EXPORT_KEYS = {
    "schema", "schema_version", "config", "config_digest", "chain_id", "meta", "slots",
    "operations", "transitions", "attestations", "export_root", "state_owned", "zero_phi",
    "production_usable", "activation", "payment_authority", "clearance_authority",
    "settlement_authority", "proofSuiteId",
}
EXPORT_ROW_KEYS = {
    "acquisition_meta": {"key", "value"},
    "acquisition_slots": set(SLOT_COLUMNS) - {"quarantine_receipt_raw"} | {"quarantine_receipt_hex"},
    "acquisition_operations": set(OPERATION_COLUMNS) - {"receipt_raw"} | {"receipt_hex"},
    "acquisition_transitions": set(TRANSITION_COLUMNS) - {"transition_raw"} | {"transition_hex"},
    "acquisition_attestations": set(ATTESTATION_COLUMNS),
}
SUPPORT_KEYS = {
    "schema", "schema_version", "state", "sequence", "slot_counts", "failure_counts",
    "attempt_count", "attestation_count", "head_transition_id", "state_root", "chain_id",
    "zero_phi", "state_owned", "production_usable", "activation", "payment_authority",
    "clearance_authority", "settlement_authority", "proofSuiteId",
}


class IndependentAcquisitionError(ValueError):
    """A fail-closed acquisition database or export rejection."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise IndependentAcquisitionError("acquisition:noncanonical") from exc


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise IndependentAcquisitionError("acquisition:duplicate-key")
        result[key] = value
    return result


def _walk(value: object, *, depth: int = 0, nodes: list[int] | None = None) -> None:
    nodes = [0] if nodes is None else nodes
    nodes[0] += 1
    if nodes[0] > 65_536:
        raise IndependentAcquisitionError("acquisition:node-cap")
    if depth > 24:
        raise IndependentAcquisitionError("acquisition:depth-cap")
    if isinstance(value, float):
        raise IndependentAcquisitionError("acquisition:float")
    if isinstance(value, str):
        try:
            value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise IndependentAcquisitionError("acquisition:ascii") from exc
        if len(value.encode("ascii")) > 8_192:
            raise IndependentAcquisitionError("acquisition:string-cap")
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise IndependentAcquisitionError("acquisition:key-type")
            _walk(item, depth=depth + 1, nodes=nodes)
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth=depth + 1, nodes=nodes)


def _parse(raw: bytes, *, maximum: int = MAX_EXPORT_BYTES) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > maximum:
        raise IndependentAcquisitionError("acquisition:byte-cap")
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_reject_duplicate_keys, parse_constant=lambda _value: (_ for _ in ()).throw(IndependentAcquisitionError("acquisition:constant")))
    except IndependentAcquisitionError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IndependentAcquisitionError("acquisition:parse") from exc
    if not isinstance(value, dict):
        raise IndependentAcquisitionError("acquisition:top-level")
    _walk(value)
    if _canonical(value) != raw:
        raise IndependentAcquisitionError("acquisition:not-canonical")
    return value


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update((DOMAIN + label + "/v1\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _raw_digest(raw: bytes) -> str:
    return hashlib.sha3_512(raw).hexdigest()


def _hex(value: object, label: str) -> str:
    if not isinstance(value, str) or HEX128.fullmatch(value) is None:
        raise IndependentAcquisitionError(f"acquisition:{label}")
    return value


def _safe(value: object, label: str) -> str:
    if not isinstance(value, str) or SAFE_TEXT.fullmatch(value) is None:
        raise IndependentAcquisitionError(f"acquisition:{label}")
    lowered = value.lower()
    if any(marker in lowered for marker in ("http://", "https://", "token", "secret", "password", "credential", "header", "patient", "member", "claim", "npi", "email", "phone", "address", "path")):
        raise IndependentAcquisitionError(f"acquisition:{label}-forbidden")
    return value


def _int(value: object, label: str, *, minimum: int = 0, maximum: int = 2_147_483_647) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise IndependentAcquisitionError(f"acquisition:{label}")
    return value


def _bool(value: object, label: str, expected: bool | None = None) -> bool:
    if type(value) is not bool or expected is not None and value is not expected:
        raise IndependentAcquisitionError(f"acquisition:{label}")
    return value


def _config_view(config: Mapping[str, object] | object) -> dict[str, object]:
    try:
        material = config.material() if hasattr(config, "material") else dict(config)  # type: ignore[arg-type]
    except Exception as exc:
        raise IndependentAcquisitionError("acquisition:config") from exc
    if set(material) != CONFIG_KEYS:
        raise IndependentAcquisitionError("acquisition:config-keys")
    for key in ("acquisition_id", "quarantine_database_id", "transport_id", "endpoint_id"):
        _safe(material[key], key)
    _int(material["version"], "version", minimum=1, maximum=1)
    for key in ("nc_profile_digest", "external_policy_digest", "quarantine_policy_digest", "quarantine_chain_id", "authorization_artifact_digest", "terms_artifact_digest", "request_digest"):
        _hex(material[key], key)
    _int(material["transport_epoch"], "transport-epoch", maximum=1_000_000)
    for key in ("cadence_seconds", "freshness_grace_seconds", "max_body_bytes", "max_page_count", "max_attempts", "lease_seconds", "busy_timeout_ms", "max_slots"):
        _int(material[key], key, minimum=1)
    if material["max_body_bytes"] != 131_072 or material["max_page_count"] != 4 or material["max_attempts"] != 3 or material["max_slots"] > MAX_SLOTS:
        raise IndependentAcquisitionError("acquisition:config-cap")
    _bool(material["zero_phi"], "zero-phi", True)
    _bool(material["state_owned"], "state-owned", True)
    for key in ("live_transport_authorized", "production_source_authentication", "production_usable", "activation"):
        _bool(material[key], key, False)
    if material["proofSuiteId"] is not None:
        raise IndependentAcquisitionError("acquisition:proof-suite")
    return dict(material)


def _config_digest(config: Mapping[str, object] | object) -> str:
    return _digest("config", _config_view(config))


def _chain_id(config_digest: str) -> str:
    return _digest("chain-id", config_digest)


def _genesis_root(chain_id: str) -> str:
    return _digest("genesis", chain_id)


def _state_root(chain_id: str, sequence: int, prior_root: str, transition_id: str | None = None) -> str:
    return _digest("state-root", {"chain_id": chain_id, "sequence": sequence, "prior_root": prior_root, "transition_id": transition_id})


def _attestation_material(row: Mapping[str, object]) -> dict[str, object]:
    return {
        "transport_id": row["transport_id"],
        "transport_epoch": row["transport_epoch"],
        "page_index": row["page_index"],
        "attempt": row["attempt"],
        "request_digest": row["request_digest"],
        "server_identity_digest": row["server_identity_digest"],
        "authorization_artifact_digest": row["authorization_artifact_digest"],
        "terms_artifact_digest": row["terms_artifact_digest"],
        "response_digest": row["response_digest"],
        "status": row["status"],
        "media_type": row["media_type"],
        "observed_at": row["observed_at"],
        "fetched_at": row["fetched_at"],
        "redirect": row["redirect"],
        "transport_authenticated": row["transport_authenticated"],
    }


def verify_attestation(row: Mapping[str, object], *, config: Mapping[str, object], profile=NC_MEDICAID_PROFILE) -> None:
    expected_keys = set(ATTESTATION_COLUMNS) | {"transport_id", "transport_epoch"}
    if set(row) != expected_keys:
        raise IndependentAcquisitionError("acquisition:attestation-keys")
    _safe(row["transport_id"], "transport-id")
    _int(row["transport_epoch"], "transport-epoch", maximum=1_000_000)
    if row["transport_id"] != config["transport_id"] or row["transport_epoch"] != config["transport_epoch"]:
        raise IndependentAcquisitionError("acquisition:transport-binding")
    page_index = _int(row["page_index"], "page-index", maximum=config["max_page_count"] - 1)
    _int(row["attempt"], "attempt", maximum=config["max_attempts"])
    request_digest = _hex(row["request_digest"], "request-digest")
    expected_request = _digest("request", {"method": "GET", "url": profile.page_url(page_index), "page_index": page_index})
    if request_digest != expected_request:
        raise IndependentAcquisitionError("acquisition:request-binding")
    if page_index == 0 and request_digest != config["request_digest"]:
        raise IndependentAcquisitionError("acquisition:request-config")
    for key in ("server_identity_digest", "authorization_artifact_digest", "terms_artifact_digest", "response_digest", "attestation_digest"):
        _hex(row[key], key)
    if row["authorization_artifact_digest"] != config["authorization_artifact_digest"] or row["terms_artifact_digest"] != config["terms_artifact_digest"]:
        raise IndependentAcquisitionError("acquisition:authority-binding")
    _int(row["status"], "status", minimum=100, maximum=599)
    if row["media_type"] != profile.allowed_media_type:
        raise IndependentAcquisitionError("acquisition:media-type")
    _int(row["observed_at"], "observed-at", minimum=1)
    _int(row["fetched_at"], "fetched-at", minimum=1)
    if row["fetched_at"] < row["observed_at"]:
        raise IndependentAcquisitionError("acquisition:chronology")
    _bool(row["redirect"], "redirect", False)
    _bool(row["transport_authenticated"], "transport-authenticated")
    expected = _digest("transport-attestation", {**_attestation_material(row), "transport_id": row["transport_id"], "transport_epoch": row["transport_epoch"]})
    if row["attestation_digest"] != expected:
        raise IndependentAcquisitionError("acquisition:attestation-digest")


def _transition_id(body: Mapping[str, object]) -> str:
    unsigned = dict(body)
    unsigned.pop("transition_id", None)
    unsigned.pop("after_root", None)
    return _digest("transition", unsigned)


def _parse_blob(value: object, label: str, maximum: int) -> bytes:
    if type(value) is bytes:
        if len(value) > maximum:
            raise IndependentAcquisitionError(f"acquisition:{label}")
        return value
    if not isinstance(value, str) or len(value) > maximum * 2 or len(value) % 2:
        raise IndependentAcquisitionError(f"acquisition:{label}")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise IndependentAcquisitionError(f"acquisition:{label}") from exc
    if len(raw) > maximum:
        raise IndependentAcquisitionError(f"acquisition:{label}")
    return raw


def _verify_rows(snapshot: Mapping[str, list[dict[str, object]]], *, config: Mapping[str, object] | object) -> dict[str, object]:
    cfg = _config_view(config)
    config_digest = _digest("config", cfg)
    chain_id = _chain_id(config_digest)
    if set(snapshot) != set(TABLE_COLUMNS):
        raise IndependentAcquisitionError("acquisition:snapshot-tables")
    for table, rows in snapshot.items():
        if not isinstance(rows, list):
            raise IndependentAcquisitionError("acquisition:rows")
        if table == "acquisition_slots" and len(rows) > cfg["max_slots"]:
            raise IndependentAcquisitionError("acquisition:slot-cap")
        if table == "acquisition_transitions" and len(rows) > MAX_TRANSITIONS:
            raise IndependentAcquisitionError("acquisition:transition-cap")
        if table == "acquisition_attestations" and len(rows) > MAX_ATTESTATIONS:
            raise IndependentAcquisitionError("acquisition:attestation-cap")
        expected = TABLE_COLUMNS[table]
        if any(not isinstance(row, dict) or set(row) != expected for row in rows):
            raise IndependentAcquisitionError(f"acquisition:{table}-keys")
    meta = {str(row["key"]): str(row["value"]) for row in snapshot["acquisition_meta"] if isinstance(row, dict) and "key" in row and "value" in row}
    if len(meta) != len(snapshot["acquisition_meta"]) or set(meta) != META_KEYS:
        raise IndependentAcquisitionError("acquisition:meta")
    if meta["schema"] != SCHEMA or meta["schema_version"] != str(SCHEMA_VERSION) or meta["acquisition_id"] != cfg["acquisition_id"] or meta["config_digest"] != config_digest or meta["chain_id"] != chain_id:
        raise IndependentAcquisitionError("acquisition:meta-binding")
    if meta["state_owned"] != "1" or meta["zero_phi"] != "1" or meta["production_usable"] != "0" or meta["activation"] != "0" or meta["payment_authority"] != "0" or meta["clearance_authority"] != "0" or meta["settlement_authority"] != "0" or meta["proofSuiteId"] != "null":
        raise IndependentAcquisitionError("acquisition:meta-flags")
    sequence = _int(int(meta["sequence"]), "sequence", maximum=MAX_TRANSITIONS)
    state_root = _hex(meta["state_root"], "state-root")
    head_transition_id = _hex(meta["head_transition_id"], "head-transition") if sequence else meta["head_transition_id"]
    if sequence == 0 and head_transition_id != GENESIS_TRANSITION:
        raise IndependentAcquisitionError("acquisition:genesis-head")
    current_root = _state_root(chain_id, 0, _genesis_root(chain_id), None)
    if sequence == 0 and state_root != current_root:
        raise IndependentAcquisitionError("acquisition:genesis-root")
    slots = {str(row["slot_id"]): row for row in snapshot["acquisition_slots"]}
    if len(slots) != len(snapshot["acquisition_slots"]):
        raise IndependentAcquisitionError("acquisition:duplicate-slot")
    for slot_id, row in slots.items():
        _hex(slot_id, "slot-id")
        _int(row["scheduled_at"], "scheduled-at", minimum=1)
        if slot_id != _digest("slot", {"config_digest": config_digest, "scheduled_at": row["scheduled_at"]}):
            raise IndependentAcquisitionError("acquisition:slot-identity")
        if row["state"] not in STATES:
            raise IndependentAcquisitionError("acquisition:slot-state")
        _int(row["attempt"], "attempt", maximum=cfg["max_attempts"])
        if row["lease_id"] is not None:
            _hex(row["lease_id"], "lease-id")
        if row["lease_until"] is not None:
            _int(row["lease_until"], "lease-until", minimum=1)
        if row["failure_code"] is not None and row["failure_code"] not in SAFE_FAILURES:
            raise IndependentAcquisitionError("acquisition:failure-code")
        for key in ("envelope_id", "envelope_digest", "artifact_id", "artifact_digest", "capture_id", "payload_digest", "snapshot_root", "quarantine_expected_head", "quarantine_head", "quarantine_head_root", "quarantine_transition_id", "quarantine_receipt_digest", "last_operation_id"):
            if row[key] not in (None, ""):
                _hex(row[key], key)
        if row["quarantine_receipt_raw"] is not None:
            receipt = _parse_blob(row["quarantine_receipt_raw"], "quarantine-receipt", 128 * 1024)
            if _raw_digest(receipt) != row["quarantine_receipt_digest"]:
                raise IndependentAcquisitionError("acquisition:quarantine-receipt")
            try:
                quarantine_receipt = quarantine._parse(receipt, maximum=128 * 1024)
            except Exception as exc:
                raise IndependentAcquisitionError("acquisition:quarantine-receipt-parse") from exc
            expected_receipt_keys = {"schema", "schema_version", "receipt_id", "operation_id", "action", "policy_digest", "artifact_id", "capture_id", "prior_head", "head_artifact_id", "state", "sequence", "transition_id", "before_root", "after_root", "chain_id", "flags"}
            if set(quarantine_receipt) != expected_receipt_keys or quarantine_receipt["receipt_id"] != quarantine._receipt_id(quarantine_receipt):
                raise IndependentAcquisitionError("acquisition:quarantine-receipt-identity")
            if quarantine_receipt["flags"] != quarantine.FIXED_FLAGS or quarantine_receipt["policy_digest"] != cfg["quarantine_policy_digest"] or quarantine_receipt["chain_id"] != cfg["quarantine_chain_id"] or quarantine_receipt["artifact_id"] != row["artifact_id"] or quarantine_receipt["capture_id"] != row["capture_id"] or quarantine_receipt["head_artifact_id"] != row["quarantine_head"] or quarantine_receipt["prior_head"] != (row["quarantine_expected_head"] or "") or quarantine_receipt["state"] != "QUARANTINED" or quarantine_receipt["transition_id"] != row["quarantine_transition_id"] or quarantine_receipt["action"] not in {"ADMIT", "SUPERSEDE"}:
                raise IndependentAcquisitionError("acquisition:quarantine-receipt-binding")
        for key in ("observed_at", "fetched_at"):
            if row[key] is not None:
                _int(row[key], key, minimum=1)
        if row["state"] == "QUARANTINED" and not all(row[key] not in (None, "") for key in ("artifact_id", "quarantine_head", "quarantine_head_root", "quarantine_transition_id", "quarantine_receipt_digest", "quarantine_receipt_raw")):
            raise IndependentAcquisitionError("acquisition:quarantined-binding")
        if row["envelope_digest"] not in (None, "") and row["payload_digest"] not in (None, "") and row["envelope_digest"] != row["payload_digest"]:
            raise IndependentAcquisitionError("acquisition:envelope-payload-binding")
        if row["state"] in {"DUE", "HELD"} and row["lease_until"] is not None:
            raise IndependentAcquisitionError("acquisition:released-lease")
    operations = {str(row["operation_id"]): row for row in snapshot["acquisition_operations"]}
    if len(operations) != len(snapshot["acquisition_operations"]):
        raise IndependentAcquisitionError("acquisition:duplicate-operation")
    for operation_id, row in operations.items():
        _hex(operation_id, "operation-id")
        if row["slot_id"] not in slots or row["action"] not in {"CREATE_SLOT", "LEASE", "CAPTURE", "QUARANTINE", "FAIL", "REQUEUE"}:
            raise IndependentAcquisitionError("acquisition:operation-binding")
        _int(row["attempt"], "operation-attempt", maximum=cfg["max_attempts"])
        _hex(row["request_digest"], "operation-request")
        _hex(row["material_digest"], "operation-material")
        _hex(row["transition_id"], "operation-transition")
        _hex(row["receipt_digest"], "receipt-digest")
        _int(row["sequence"], "operation-sequence", minimum=1, maximum=MAX_TRANSITIONS)
        expected_operation = _digest("operation", {"acquisition_id": cfg["acquisition_id"], "slot_id": row["slot_id"], "action": row["action"], "attempt": row["attempt"], "request_digest": row["request_digest"], "material_digest": row["material_digest"]})
        if operation_id != expected_operation:
            raise IndependentAcquisitionError("acquisition:operation-identity")
        receipt = _parse_blob(row["receipt_raw"], "receipt", 128 * 1024)
        if _raw_digest(receipt) != row["receipt_digest"]:
            raise IndependentAcquisitionError("acquisition:receipt-digest")
        receipt_value = _parse(receipt, maximum=128 * 1024)
        if set(receipt_value) != {"schema", "schema_version", "acquisition_id", "operation_id", "slot_id", "action", "prior_state", "next_state", "sequence", "before_root", "after_root", "transition_id", "material_digest", "flags"}:
            raise IndependentAcquisitionError("acquisition:receipt-keys")
        if receipt_value["operation_id"] != operation_id or receipt_value["slot_id"] != row["slot_id"] or receipt_value["transition_id"] != row["transition_id"] or receipt_value["sequence"] != row["sequence"] or receipt_value["material_digest"] != row["material_digest"]:
            raise IndependentAcquisitionError("acquisition:receipt-binding")
        if receipt_value["schema"] != SCHEMA or receipt_value["schema_version"] != SCHEMA_VERSION or receipt_value["acquisition_id"] != cfg["acquisition_id"] or receipt_value["flags"] != {"state_owned": True, "zero_phi": True, "production_usable": False, "activation": False, "payment_authority": False, "clearance_authority": False, "settlement_authority": False, "proofSuiteId": None}:
            raise IndependentAcquisitionError("acquisition:receipt-flags")
    transitions = sorted(snapshot["acquisition_transitions"], key=lambda row: int(row["sequence"]))
    if len(transitions) != sequence:
        raise IndependentAcquisitionError("acquisition:sequence-count")
    if len({row["transition_id"] for row in transitions}) != len(transitions):
        raise IndependentAcquisitionError("acquisition:duplicate-transition")
    replay: dict[str, str] = {}
    current = _state_root(chain_id, 0, _genesis_root(chain_id), None)
    for expected_sequence, row in enumerate(transitions, start=1):
        if row["sequence"] != expected_sequence or row["slot_id"] not in slots or row["operation_id"] not in operations:
            raise IndependentAcquisitionError("acquisition:transition-order")
        _hex(row["transition_id"], "transition-id")
        _hex(row["before_root"], "before-root")
        _hex(row["after_root"], "after-root")
        _hex(row["material_digest"], "transition-material")
        if row["before_root"] != current or row["next_state"] not in STATES or row["prior_state"] not in STATES | {""}:
            if not (expected_sequence == 1 and row["prior_state"] == "" and row["before_root"] == current):
                raise IndependentAcquisitionError("acquisition:transition-state")
        if row["prior_state"] != replay.get(row["slot_id"], ""):
            raise IndependentAcquisitionError("acquisition:transition-predecessor")
        if row["next_state"] not in {"DUE", "LEASED", "CAPTURED", "QUARANTINED", "HELD"}:
            raise IndependentAcquisitionError("acquisition:transition-next")
        if row["prior_state"] == "" and row["next_state"] != "DUE":
            raise IndependentAcquisitionError("acquisition:transition-initial")
        if row["prior_state"] == "DUE" and row["next_state"] not in {"LEASED"}:
            raise IndependentAcquisitionError("acquisition:transition-due")
        if row["prior_state"] == "LEASED" and row["next_state"] not in {"CAPTURED", "DUE", "HELD"}:
            raise IndependentAcquisitionError("acquisition:transition-leased")
        if row["prior_state"] == "CAPTURED" and row["next_state"] not in {"QUARANTINED", "DUE", "HELD"}:
            raise IndependentAcquisitionError("acquisition:transition-captured")
        # The producer binds the transition ID over the complete unsigned body;
        # reconstruct that body rather than trusting either stored root.
        unsigned = {"schema": SCHEMA, "schema_version": SCHEMA_VERSION, "transition_id": "", "sequence": expected_sequence, "slot_id": row["slot_id"], "operation_id": row["operation_id"], "prior_state": row["prior_state"], "next_state": row["next_state"], "before_root": row["before_root"], "after_root": row["after_root"], "material_digest": row["material_digest"], "observed_at": row["observed_at"]}
        if row["transition_id"] != _transition_id(unsigned):
            raise IndependentAcquisitionError("acquisition:transition-id")
        expected_after = _state_root(chain_id, expected_sequence, row["before_root"], row["transition_id"])
        if row["after_root"] != expected_after:
            raise IndependentAcquisitionError("acquisition:transition-root")
        transition_raw = _parse_blob(row["transition_raw"], "transition", 128 * 1024)
        transition_value = _parse(transition_raw, maximum=128 * 1024)
        expected_transition = {"schema": SCHEMA, "schema_version": SCHEMA_VERSION, "transition_id": row["transition_id"], "sequence": expected_sequence, "slot_id": row["slot_id"], "operation_id": row["operation_id"], "prior_state": row["prior_state"], "next_state": row["next_state"], "before_root": row["before_root"], "after_root": row["after_root"], "material_digest": row["material_digest"], "observed_at": row["observed_at"]}
        if transition_value != expected_transition:
            raise IndependentAcquisitionError("acquisition:transition-bytes")
        replay[row["slot_id"]] = row["next_state"]
        current = row["after_root"]
    if state_root != current or (sequence and head_transition_id != transitions[-1]["transition_id"]):
        raise IndependentAcquisitionError("acquisition:head")
    for slot_id, state in replay.items():
        if slots[slot_id]["state"] != state:
            raise IndependentAcquisitionError("acquisition:slot-replay")
    attestations = snapshot["acquisition_attestations"]
    seen_attestations: set[tuple[str, int, int]] = set()
    for row in attestations:
        key = (str(row["slot_id"]), int(row["page_index"]), int(row["attempt"]))
        if key in seen_attestations:
            raise IndependentAcquisitionError("acquisition:duplicate-attestation")
        seen_attestations.add(key)
        if row["slot_id"] not in slots:
            raise IndependentAcquisitionError("acquisition:attestation-slot")
        row_for_verify = dict(row)
        row_for_verify["transport_id"] = cfg["transport_id"]
        row_for_verify["transport_epoch"] = cfg["transport_epoch"]
        if row_for_verify["redirect"] not in (0, 1, False, True) or row_for_verify["transport_authenticated"] not in (0, 1, False, True):
            raise IndependentAcquisitionError("acquisition:attestation-boolean")
        row_for_verify["redirect"] = bool(row_for_verify["redirect"])
        row_for_verify["transport_authenticated"] = bool(row_for_verify["transport_authenticated"])
        verify_attestation(row_for_verify, config=cfg)
    if any(row["failure_code"] == "" for row in slots.values()):
        raise IndependentAcquisitionError("acquisition:failure-empty")
    return {
        "accepted": True,
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "config": cfg,
        "config_digest": config_digest,
        "chain_id": chain_id,
        "sequence": sequence,
        "state_root": current,
        "head_transition_id": transitions[-1]["transition_id"] if transitions else GENESIS_TRANSITION,
        "slot_count": len(slots),
        "operation_count": len(operations),
        "transition_count": len(transitions),
        "attestation_count": len(attestations),
        "states": {state: sum(row["state"] == state for row in slots.values()) for state in sorted(STATES)},
    }


def _sqlite_snapshot(connection: sqlite3.Connection) -> dict[str, list[dict[str, object]]]:
    result: dict[str, list[dict[str, object]]] = {}
    for table, columns in TABLE_COLUMNS.items():
        rows = connection.execute(f"SELECT * FROM {table}").fetchall()
        result[table] = [{column: row[column] for column in columns} for row in rows]
    return result


def _check_shape(connection: sqlite3.Connection) -> None:
    tables = {str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
    if tables != set(TABLE_COLUMNS):
        raise IndependentAcquisitionError("acquisition:database-schema")
    for table, columns in TABLE_COLUMNS.items():
        actual = {str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})")}
        if actual != columns:
            raise IndependentAcquisitionError(f"acquisition:{table}-schema")


def verify_database(path: str | Path, *, config: Mapping[str, object] | object) -> dict[str, object]:
    database = Path(path)
    if not database.is_file() or database.stat().st_size > MAX_DATABASE_BYTES:
        raise IndependentAcquisitionError("acquisition:database")
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(f"file:{database.resolve().as_posix()}?mode=ro", uri=True, timeout=BUSY_TIMEOUT_MS / 1000.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
        _check_shape(connection)
        return _verify_rows(_sqlite_snapshot(connection), config=config)
    except IndependentAcquisitionError:
        raise
    except (sqlite3.Error, OSError, ValueError) as exc:
        raise IndependentAcquisitionError("acquisition:database-corrupt") from exc
    finally:
        if connection is not None:
            connection.close()


def _decode_export(value: Mapping[str, object]) -> dict[str, list[dict[str, object]]]:
    mapping = {"meta": "acquisition_meta", "slots": "acquisition_slots", "operations": "acquisition_operations", "transitions": "acquisition_transitions", "attestations": "acquisition_attestations"}
    result: dict[str, list[dict[str, object]]] = {}
    for name, table in mapping.items():
        rows = value[name]
        if not isinstance(rows, list):
            raise IndependentAcquisitionError("acquisition:export-rows")
        decoded: list[dict[str, object]] = []
        for item in rows:
            if not isinstance(item, dict) or set(item) != EXPORT_ROW_KEYS[table]:
                raise IndependentAcquisitionError(f"acquisition:export-{table}-keys")
            row = dict(item)
            if table == "acquisition_slots":
                encoded = row.pop("quarantine_receipt_hex")
                row["quarantine_receipt_raw"] = None if encoded is None else _parse_blob(encoded, "quarantine-receipt", 128 * 1024)
            elif table == "acquisition_operations":
                row["receipt_raw"] = _parse_blob(row.pop("receipt_hex"), "receipt", 128 * 1024)
            elif table == "acquisition_transitions":
                row["transition_raw"] = _parse_blob(row.pop("transition_hex"), "transition", 128 * 1024)
            decoded.append(row)
        result[table] = decoded
    return result


def verify_export_bytes(raw: bytes, *, config: Mapping[str, object] | object) -> dict[str, object]:
    value = _parse(raw)
    if set(value) != EXPORT_KEYS or value["schema"] != EXPORT_SCHEMA or value["schema_version"] != EXPORT_VERSION:
        raise IndependentAcquisitionError("acquisition:export-schema")
    cfg = _config_view(config)
    config_digest = _digest("config", cfg)
    if value["config"] != cfg or value["config_digest"] != config_digest or value["chain_id"] != _chain_id(config_digest):
        raise IndependentAcquisitionError("acquisition:export-config")
    if value["state_owned"] is not True or value["zero_phi"] is not True or value["production_usable"] is not False or value["activation"] is not False or value["payment_authority"] is not False or value["clearance_authority"] is not False or value["settlement_authority"] is not False or value["proofSuiteId"] is not None:
        raise IndependentAcquisitionError("acquisition:export-flags")
    snapshot = _decode_export(value)
    result = _verify_rows(snapshot, config=cfg)
    body = dict(value)
    body.pop("export_root")
    if value["export_root"] != _digest("export-root", body):
        raise IndependentAcquisitionError("acquisition:export-root")
    return {**result, "export_root": value["export_root"], "snapshot": snapshot}


def support_snapshot(path: str | Path, *, config: Mapping[str, object] | object) -> dict[str, object]:
    evidence = verify_database(path, config=config)
    counts = evidence["states"]
    connection = sqlite3.connect(f"file:{Path(path).resolve().as_posix()}?mode=ro", uri=True, timeout=BUSY_TIMEOUT_MS / 1000.0)
    try:
        failure_counts = {str(row[0]): int(row[1]) for row in connection.execute("SELECT failure_code,COUNT(*) FROM acquisition_slots WHERE failure_code IS NOT NULL GROUP BY failure_code ORDER BY failure_code")}
        attempt_count = int(connection.execute("SELECT COALESCE(SUM(attempt),0) FROM acquisition_slots").fetchone()[0])
    finally:
        connection.close()
    return {
        "schema": "mirror-authenticated-source-acquisition-support-v1",
        "schema_version": 1,
        "state": "EMPTY" if evidence["slot_count"] == 0 else "NONEMPTY",
        "sequence": evidence["sequence"],
        "slot_counts": counts,
        "failure_counts": failure_counts,
        "attempt_count": attempt_count,
        "attestation_count": evidence["attestation_count"],
        "head_transition_id": evidence["head_transition_id"],
        "state_root": evidence["state_root"],
        "chain_id": evidence["chain_id"],
        "zero_phi": True,
        "state_owned": True,
        "production_usable": False,
        "activation": False,
        "payment_authority": False,
        "clearance_authority": False,
        "settlement_authority": False,
        "proofSuiteId": None,
    }


__all__ = [
    "SCHEMA", "SCHEMA_VERSION", "EXPORT_SCHEMA", "EXPORT_VERSION", "STATES", "SAFE_FAILURES",
    "CONFIG_KEYS", "META_KEYS", "SLOT_COLUMNS", "OPERATION_COLUMNS", "TRANSITION_COLUMNS",
    "ATTESTATION_COLUMNS", "TABLE_COLUMNS", "EXPORT_KEYS", "EXPORT_ROW_KEYS", "IndependentAcquisitionError",
    "_canonical", "_digest", "_raw_digest", "_config_view", "_config_digest", "_chain_id", "_genesis_root",
    "_state_root", "verify_attestation", "verify_database", "verify_export_bytes", "support_snapshot",
]
