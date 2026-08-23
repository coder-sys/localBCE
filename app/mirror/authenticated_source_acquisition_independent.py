"""Independent verifier for the authenticated NC source-acquisition ledger."""

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
SCHEMA_VERSION = 2
EXPORT_SCHEMA = "mirror-authenticated-source-acquisition-export-v1"
EXPORT_VERSION = 2
DOMAIN = "BL/MIRROR/AUTHENTICATED-SOURCE-ACQUISITION/"
GENESIS_TRANSITION = "0" * 128
BUSY_TIMEOUT_MS = 500
MAX_EXPORT_BYTES = 8 * 1024 * 1024
MAX_DATABASE_BYTES = 32 * 1024 * 1024
MAX_SLOTS = 4_096
MAX_TRANSITIONS = 16_384
MAX_ATTESTATIONS = 32_768
HEX128 = re.compile(r"^[0-9a-f]{128}$")
SAFE_TEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
STATES = {"DUE", "LEASED", "CAPTURED", "QUARANTINE_PENDING", "QUARANTINE_UNCONFIRMED", "QUARANTINED", "HELD"}
SAFE_FAILURES = {
    "wrong-host", "redirect", "capability-mismatch", "authorization-mismatch", "terms-mismatch",
    "request-mismatch", "response-digest", "status", "media-type", "timeout", "rate-limit",
    "server-error", "retry-exhausted", "partial-page", "stale", "incomplete", "verifier",
    "quarantine-head", "quarantine-database", "quarantine-lookup", "quarantine-unconfirmed",
    "lease", "busy", "response-loss", "database", "profile-drift", "transport", "body-cap",
    "slot-grid", "slot-cap", "future-slot", "observation-time", "server-identity", "authentication",
    "reorder",
}
ACTIONS = {"CREATE_SLOT", "LEASE", "CAPTURE", "FAIL", "REQUEUE", "BEGIN_QUARANTINE", "RECOVER_QUARANTINE", "CONFIRM_QUARANTINE", "QUARANTINE_UNCONFIRMED"}
CONFIG_KEYS = {
    "acquisition_id", "version", "nc_profile_digest", "external_policy_digest", "quarantine_policy_digest",
    "quarantine_chain_id", "quarantine_database_id", "transport_id", "transport_epoch",
    "authorization_artifact_digest", "terms_artifact_digest", "endpoint_id", "request_digest",
    "effective_start", "effective_end", "expected_server_identity_digest", "cadence_seconds",
    "freshness_grace_seconds", "max_body_bytes", "max_page_count", "max_attempts", "lease_seconds",
    "busy_timeout_ms", "max_slots", "zero_phi", "state_owned", "live_transport_authorized",
    "production_source_authentication", "production_usable", "activation", "proofSuiteId",
}
META_KEYS = {
    "schema", "schema_version", "acquisition_id", "config_digest", "chain_id", "sequence", "state_root",
    "head_transition_id", "state_owned", "zero_phi", "production_usable", "activation",
    "payment_authority", "clearance_authority", "settlement_authority", "proofSuiteId",
}
SLOT_COLUMNS = (
    "slot_id", "scheduled_at", "state", "lease_id", "lease_until", "attempt", "envelope_id", "envelope_digest",
    "artifact_id", "artifact_digest", "capture_id", "payload_digest", "snapshot_root", "observed_at", "fetched_at",
    "quarantine_expected_head", "quarantine_head", "quarantine_head_root", "quarantine_transition_id",
    "quarantine_receipt_digest", "quarantine_receipt_raw", "failure_code", "last_operation_id", "capture_attempt",
    "page_count", "page_digests_raw", "selected_pages_raw", "quarantine_request_digest", "quarantine_material_digest",
    "quarantine_database_id", "quarantine_policy_digest", "quarantine_chain_id", "quarantine_dispatch_attempt",
)
OPERATION_COLUMNS = ("operation_id", "slot_id", "action", "attempt", "request_digest", "material_digest", "material_raw", "transition_id", "receipt_digest", "sequence", "receipt_raw")
TRANSITION_COLUMNS = ("transition_id", "sequence", "slot_id", "operation_id", "action", "attempt", "request_digest", "prior_state", "next_state", "before_root", "after_root", "material_digest", "observed_at", "transition_raw")
ATTESTATION_COLUMNS = ("slot_id", "page_index", "attempt", "transport_id", "transport_epoch", "request_digest", "server_identity_digest", "authorization_artifact_digest", "terms_artifact_digest", "response_digest", "status", "media_type", "observed_at", "fetched_at", "redirect", "transport_authenticated", "attestation_digest")
TABLE_COLUMNS = {
    "acquisition_meta": ("key", "value"), "acquisition_slots": SLOT_COLUMNS, "acquisition_operations": OPERATION_COLUMNS,
    "acquisition_transitions": TRANSITION_COLUMNS, "acquisition_attestations": ATTESTATION_COLUMNS,
}
EXPORT_KEYS = {"schema", "schema_version", "config", "config_digest", "chain_id", "meta", "slots", "operations", "transitions", "attestations", "export_root", "state_owned", "zero_phi", "production_usable", "activation", "payment_authority", "clearance_authority", "settlement_authority", "proofSuiteId"}
EXPORT_ROW_KEYS = {
    "acquisition_meta": set(TABLE_COLUMNS["acquisition_meta"]),
    "acquisition_slots": set(SLOT_COLUMNS) - {"quarantine_receipt_raw", "page_digests_raw", "selected_pages_raw"} | {"quarantine_receipt_hex", "page_digests_hex", "selected_pages_hex"},
    "acquisition_operations": set(OPERATION_COLUMNS) - {"material_raw", "receipt_raw"} | {"material_hex", "receipt_hex"},
    "acquisition_transitions": set(TRANSITION_COLUMNS) - {"transition_raw"} | {"transition_hex"},
    "acquisition_attestations": set(ATTESTATION_COLUMNS),
}
FIXED_FLAGS = {"state_owned": True, "zero_phi": True, "production_usable": False, "activation": False, "payment_authority": False, "clearance_authority": False, "settlement_authority": False, "proofSuiteId": None}


class IndependentAcquisitionError(ValueError):
    pass


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


def _walk(value: object, *, depth: int = 0, nodes: list[int] | None = None, string_limit: int = 8_192) -> None:
    nodes = [0] if nodes is None else nodes
    nodes[0] += 1
    if nodes[0] > 65_536 or depth > 24:
        raise IndependentAcquisitionError("acquisition:structure-cap")
    if isinstance(value, float):
        raise IndependentAcquisitionError("acquisition:float")
    if isinstance(value, str):
        try:
            if len(value.encode("ascii")) > string_limit:
                raise IndependentAcquisitionError("acquisition:string-cap")
        except UnicodeEncodeError as exc:
            raise IndependentAcquisitionError("acquisition:ascii") from exc
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise IndependentAcquisitionError("acquisition:key-type")
            _walk(item, depth=depth + 1, nodes=nodes, string_limit=string_limit)
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth=depth + 1, nodes=nodes, string_limit=string_limit)


def _parse(raw: bytes, *, maximum: int = MAX_EXPORT_BYTES, string_limit: int = 8_192) -> object:
    if type(raw) is not bytes or not raw or len(raw) > maximum:
        raise IndependentAcquisitionError("acquisition:byte-cap")
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_reject_duplicate_keys, parse_constant=lambda _value: (_ for _ in ()).throw(IndependentAcquisitionError("acquisition:constant")))
    except IndependentAcquisitionError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise IndependentAcquisitionError("acquisition:parse") from exc
    if not isinstance(value, (dict, list)):
        raise IndependentAcquisitionError("acquisition:top-level")
    _walk(value, string_limit=string_limit)
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
    for key in ("nc_profile_digest", "external_policy_digest", "quarantine_policy_digest", "quarantine_chain_id", "authorization_artifact_digest", "terms_artifact_digest", "expected_server_identity_digest", "request_digest"):
        _hex(material[key], key)
    _int(material["transport_epoch"], "transport-epoch", maximum=1_000_000)
    _int(material["effective_start"], "effective-start", minimum=1)
    _int(material["effective_end"], "effective-end", minimum=1)
    if material["effective_start"] > material["effective_end"]:
        raise IndependentAcquisitionError("acquisition:effective-interval")
    _int(material["cadence_seconds"], "cadence-seconds", minimum=1)
    _int(material["freshness_grace_seconds"], "freshness-grace-seconds", minimum=0)
    for key in ("max_body_bytes", "max_page_count", "max_attempts", "lease_seconds", "busy_timeout_ms", "max_slots"):
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
    return {key: row[key] for key in ("transport_id", "transport_epoch", "page_index", "attempt", "request_digest", "server_identity_digest", "authorization_artifact_digest", "terms_artifact_digest", "response_digest", "status", "media_type", "observed_at", "fetched_at", "redirect", "transport_authenticated")}


def verify_attestation(row: Mapping[str, object], *, config: Mapping[str, object], profile=NC_MEDICAID_PROFILE, scheduled_at: int | None = None) -> None:
    if set(row) != set(ATTESTATION_COLUMNS):
        raise IndependentAcquisitionError("acquisition:attestation-keys")
    _safe(row["transport_id"], "transport-id")
    _int(row["transport_epoch"], "transport-epoch", maximum=1_000_000)
    if row["transport_id"] != config["transport_id"] or row["transport_epoch"] != config["transport_epoch"]:
        raise IndependentAcquisitionError("acquisition:transport-binding")
    page_index = _int(row["page_index"], "page-index", maximum=config["max_page_count"] - 1)
    _int(row["attempt"], "transport-attempt", maximum=3)
    request_digest = _hex(row["request_digest"], "request-digest")
    expected_request = _digest("request", {"method": "GET", "url": profile.page_url(page_index), "page_index": page_index})
    if request_digest != expected_request or page_index == 0 and request_digest != config["request_digest"]:
        raise IndependentAcquisitionError("acquisition:request-binding")
    for key in ("server_identity_digest", "authorization_artifact_digest", "terms_artifact_digest", "response_digest", "attestation_digest"):
        _hex(row[key], key)
    if row["server_identity_digest"] != config["expected_server_identity_digest"]:
        raise IndependentAcquisitionError("acquisition:server-identity")
    if row["authorization_artifact_digest"] != config["authorization_artifact_digest"] or row["terms_artifact_digest"] != config["terms_artifact_digest"]:
        raise IndependentAcquisitionError("acquisition:authority-binding")
    if row["status"] != 200 or row["media_type"] != profile.allowed_media_type:
        raise IndependentAcquisitionError("acquisition:response-status")
    _int(row["observed_at"], "observed-at", minimum=1)
    _int(row["fetched_at"], "fetched-at", minimum=1)
    if row["fetched_at"] < row["observed_at"] or scheduled_at is not None and row["observed_at"] != scheduled_at:
        raise IndependentAcquisitionError("acquisition:chronology")
    if scheduled_at is not None and (row["fetched_at"] > scheduled_at + config["cadence_seconds"] + config["freshness_grace_seconds"] or row["fetched_at"] > config["effective_end"] + config["freshness_grace_seconds"]):
        raise IndependentAcquisitionError("acquisition:stale")
    if row["redirect"] not in (0, 1, False, True) or row["transport_authenticated"] not in (0, 1, False, True):
        raise IndependentAcquisitionError("acquisition:attestation-boolean")
    normalized = dict(row)
    normalized["redirect"] = bool(row["redirect"])
    normalized["transport_authenticated"] = bool(row["transport_authenticated"])
    if normalized["redirect"] is not False or normalized["transport_authenticated"] is not True:
        raise IndependentAcquisitionError("acquisition:attestation-authentication")
    if row["attestation_digest"] != _digest("transport-attestation", _attestation_material(normalized)):
        raise IndependentAcquisitionError("acquisition:attestation-digest")


def _parse_blob(value: object, label: str, maximum: int) -> bytes:
    if type(value) is bytes:
        raw = value
    elif isinstance(value, str):
        try:
            raw = bytes.fromhex(value)
        except ValueError as exc:
            raise IndependentAcquisitionError(f"acquisition:{label}") from exc
        if raw.hex() != value:
            raise IndependentAcquisitionError(f"acquisition:{label}")
    else:
        raise IndependentAcquisitionError(f"acquisition:{label}")
    if len(raw) > maximum:
        raise IndependentAcquisitionError(f"acquisition:{label}")
    return raw


def _safe_row(row: Mapping[str, object]) -> dict[str, object]:
    return {key: row[key].hex() if isinstance(row[key], bytes) else row[key] for key in SLOT_COLUMNS}


def _decode_safe_row(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != set(SLOT_COLUMNS):
        raise IndependentAcquisitionError("acquisition:material-slot-keys")
    result = dict(value)
    for key in ("page_digests_raw", "selected_pages_raw", "quarantine_receipt_raw"):
        result[key] = None if result[key] is None else _parse_blob(result[key], "material-" + key, 128 * 1024)
    return result


def _material_value(row: Mapping[str, object], *, action: str, attempt: int, request_digest: str, prior_state: str, next_state: str) -> dict[str, object]:
    return {"action": action, "attempt": attempt, "request_digest": request_digest, "prior_state": prior_state, "next_state": next_state, "slot_after": _safe_row(row)}


def _quarantine_request_digest(slot_id: str) -> str:
    return quarantine._digest("request", "AQ" + slot_id[:30])


def _verify_q_receipt(row: Mapping[str, object], cfg: Mapping[str, object]) -> None:
    raw = row["quarantine_receipt_raw"]
    if type(raw) is not bytes or row["quarantine_receipt_digest"] != _raw_digest(raw):
        raise IndependentAcquisitionError("acquisition:quarantine-receipt")
    try:
        receipt = quarantine._parse(raw, maximum=128 * 1024)
    except Exception as exc:
        raise IndependentAcquisitionError("acquisition:quarantine-receipt-parse") from exc
    if set(receipt) != quarantine.RECEIPT_KEYS or receipt["receipt_id"] != quarantine._receipt_id(receipt):
        raise IndependentAcquisitionError("acquisition:quarantine-receipt-identity")
    if receipt["flags"] != quarantine.FIXED_FLAGS or receipt["database_id"] != cfg["quarantine_database_id"]:
        raise IndependentAcquisitionError("acquisition:quarantine-receipt-flags")
    if receipt["policy_digest"] != cfg["quarantine_policy_digest"] or receipt["chain_id"] != cfg["quarantine_chain_id"]:
        raise IndependentAcquisitionError("acquisition:quarantine-receipt-policy")
    action = quarantine.ACTION_ADMIT if row["quarantine_expected_head"] in (None, "") else quarantine.ACTION_SUPERSEDE
    expected_operation_id = quarantine._operation_id(action, row["quarantine_request_digest"], cfg["quarantine_database_id"])
    if receipt["action"] != action or receipt["operation_id"] != expected_operation_id:
        raise IndependentAcquisitionError("acquisition:quarantine-receipt-action")
    if not isinstance(receipt["sequence"], int) or isinstance(receipt["sequence"], bool) or receipt["sequence"] < 1:
        raise IndependentAcquisitionError("acquisition:quarantine-receipt-sequence")
    for key in ("before_root", "after_root"):
        _hex(receipt[key], "quarantine-receipt-" + key)
    for key, expected in (("artifact_id", row["artifact_id"]), ("capture_id", row["capture_id"]), ("head_artifact_id", row["quarantine_head"]), ("prior_head", row["quarantine_expected_head"] or ""), ("transition_id", row["quarantine_transition_id"]), ("state", "QUARANTINED")):
        if receipt[key] != expected:
            raise IndependentAcquisitionError("acquisition:quarantine-receipt-binding")
    if receipt["after_root"] != row["quarantine_head_root"]:
        raise IndependentAcquisitionError("acquisition:quarantine-after-root")


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
        expected = set(TABLE_COLUMNS[table])
        if any(not isinstance(row, dict) or set(row) != expected for row in rows):
            raise IndependentAcquisitionError(f"acquisition:{table}-keys")
    meta_rows = snapshot["acquisition_meta"]
    if meta_rows != sorted(meta_rows, key=lambda row: str(row["key"])):
        raise IndependentAcquisitionError("acquisition:meta-order")
    meta = {str(row["key"]): row["value"] for row in meta_rows}
    if set(meta) != META_KEYS or len(meta) != len(meta_rows):
        raise IndependentAcquisitionError("acquisition:meta")
    if meta["schema"] != SCHEMA or meta["schema_version"] != str(SCHEMA_VERSION) or meta["acquisition_id"] != cfg["acquisition_id"] or meta["config_digest"] != config_digest or meta["chain_id"] != chain_id:
        raise IndependentAcquisitionError("acquisition:meta-binding")
    expected_flags = {"state_owned": "1", "zero_phi": "1", "production_usable": "0", "activation": "0", "payment_authority": "0", "clearance_authority": "0", "settlement_authority": "0", "proofSuiteId": "null"}
    if any(meta[key] != value for key, value in expected_flags.items()):
        raise IndependentAcquisitionError("acquisition:meta-flags")
    sequence = _int(int(meta["sequence"]), "sequence", maximum=MAX_TRANSITIONS)
    state_root = _hex(meta["state_root"], "state-root")
    head_transition_id = meta["head_transition_id"]
    if sequence == 0 and (head_transition_id != GENESIS_TRANSITION or state_root != _state_root(chain_id, 0, _genesis_root(chain_id), None)):
        raise IndependentAcquisitionError("acquisition:genesis")
    if sequence:
        _hex(head_transition_id, "head-transition")

    slots = {str(row["slot_id"]): row for row in snapshot["acquisition_slots"]}
    if len(slots) != len(snapshot["acquisition_slots"]):
        raise IndependentAcquisitionError("acquisition:duplicate-slot")
    for slot_id, row in slots.items():
        _hex(slot_id, "slot-id")
        scheduled = _int(row["scheduled_at"], "scheduled-at", minimum=1)
        if slot_id != _digest("slot", {"config_digest": config_digest, "scheduled_at": scheduled}):
            raise IndependentAcquisitionError("acquisition:slot-identity")
        if row["state"] not in STATES:
            raise IndependentAcquisitionError("acquisition:slot-state")
        if scheduled < cfg["effective_start"] or scheduled > cfg["effective_end"] or (scheduled - cfg["effective_start"]) % cfg["cadence_seconds"]:
            raise IndependentAcquisitionError("acquisition:slot-grid")
        _int(row["attempt"], "attempt", maximum=cfg["max_attempts"])
        for key in ("lease_id", "envelope_id", "envelope_digest", "artifact_id", "artifact_digest", "capture_id", "payload_digest", "snapshot_root", "quarantine_expected_head", "quarantine_head", "quarantine_head_root", "quarantine_transition_id", "quarantine_receipt_digest", "last_operation_id"):
            if row[key] not in (None, ""):
                _hex(row[key], key)
        if row["lease_until"] is not None:
            _int(row["lease_until"], "lease-until", minimum=1)
        if row["failure_code"] not in (None, "") and row["failure_code"] not in SAFE_FAILURES:
            raise IndependentAcquisitionError("acquisition:failure-code")
        if row["quarantine_database_id"] not in (None, cfg["quarantine_database_id"]):
            raise IndependentAcquisitionError("acquisition:quarantine-database")
        if row["quarantine_policy_digest"] not in (None, cfg["quarantine_policy_digest"]) or row["quarantine_chain_id"] not in (None, cfg["quarantine_chain_id"]):
            raise IndependentAcquisitionError("acquisition:quarantine-config")
        if row["capture_attempt"] is not None:
            _int(row["capture_attempt"], "capture-attempt", minimum=1, maximum=cfg["max_attempts"])
        if row["page_count"] is not None:
            _int(row["page_count"], "page-count", minimum=1, maximum=cfg["max_page_count"])
        if row["page_count"] is not None:
            page_digests = _parse(row["page_digests_raw"], maximum=128 * 1024)
            selected = _parse(row["selected_pages_raw"], maximum=128 * 1024)
            if not isinstance(page_digests, list) or len(page_digests) != row["page_count"] or any(HEX128.fullmatch(str(item)) is None for item in page_digests) or len(set(page_digests)) != len(page_digests):
                raise IndependentAcquisitionError("acquisition:page-digests")
            if not isinstance(selected, list) or len(selected) != row["page_count"]:
                raise IndependentAcquisitionError("acquisition:selected-pages")
            if [item.get("page_index") for item in selected if isinstance(item, dict)] != list(range(row["page_count"])):
                raise IndependentAcquisitionError("acquisition:selected-page-order")
            for item in selected:
                if not isinstance(item, dict) or set(item) != {"page_index", "lease_attempt", "transport_attempt", "attestation_digest", "request_digest", "response_digest"}:
                    raise IndependentAcquisitionError("acquisition:selected-page-keys")
                _int(item["lease_attempt"], "selected-lease-attempt", minimum=1, maximum=cfg["max_attempts"])
                _int(item["transport_attempt"], "selected-transport-attempt", maximum=3)
                for key in ("attestation_digest", "request_digest", "response_digest"):
                    _hex(item[key], "selected-" + key)
                if item["response_digest"] != page_digests[item["page_index"]]:
                    raise IndependentAcquisitionError("acquisition:page-response-binding")
        if row["state"] in {"CAPTURED", "QUARANTINE_PENDING", "QUARANTINE_UNCONFIRMED", "QUARANTINED"}:
            required_capture = (
                "envelope_id", "envelope_digest", "artifact_id", "artifact_digest", "capture_id",
                "payload_digest", "snapshot_root", "observed_at", "fetched_at", "capture_attempt",
                "page_count", "page_digests_raw", "selected_pages_raw",
            )
            if any(row[key] in (None, "") for key in required_capture):
                raise IndependentAcquisitionError("acquisition:capture-binding")
            _int(row["observed_at"], "observed-at", minimum=1)
            _int(row["fetched_at"], "fetched-at", minimum=1)
            if row["fetched_at"] < row["observed_at"] or int(row["capture_attempt"]) > int(row["attempt"]):
                raise IndependentAcquisitionError("acquisition:capture-chronology")
            if row["state"] == "CAPTURED" and int(row["capture_attempt"]) != int(row["attempt"]):
                raise IndependentAcquisitionError("acquisition:capture-attempt")
            if row["state"] in {"QUARANTINE_PENDING", "QUARANTINE_UNCONFIRMED", "QUARANTINED"}:
                required_dispatch = (
                    "quarantine_request_digest", "quarantine_material_digest", "quarantine_database_id",
                    "quarantine_policy_digest", "quarantine_chain_id", "quarantine_dispatch_attempt",
                )
                if any(row[key] in (None, "") for key in required_dispatch):
                    raise IndependentAcquisitionError("acquisition:dispatch-binding")
                if row["quarantine_request_digest"] != _quarantine_request_digest(str(row["slot_id"])):
                    raise IndependentAcquisitionError("acquisition:dispatch-request")
                if row["quarantine_material_digest"] != row["artifact_digest"]:
                    raise IndependentAcquisitionError("acquisition:dispatch-material")
                if row["quarantine_database_id"] != cfg["quarantine_database_id"] or row["quarantine_policy_digest"] != cfg["quarantine_policy_digest"] or row["quarantine_chain_id"] != cfg["quarantine_chain_id"]:
                    raise IndependentAcquisitionError("acquisition:dispatch-config")
                if int(row["quarantine_dispatch_attempt"]) != int(row["capture_attempt"]):
                    raise IndependentAcquisitionError("acquisition:dispatch-attempt")
        if row["state"] == "QUARANTINED":
            required = ("artifact_id", "artifact_digest", "capture_id", "quarantine_head", "quarantine_head_root", "quarantine_transition_id", "quarantine_receipt_digest", "quarantine_receipt_raw", "quarantine_request_digest", "quarantine_material_digest", "quarantine_database_id", "quarantine_policy_digest", "quarantine_chain_id")
            if any(row[key] in (None, "") for key in required):
                raise IndependentAcquisitionError("acquisition:quarantined-binding")
            _verify_q_receipt(row, cfg)
        if row["state"] in {"DUE", "HELD", "QUARANTINE_UNCONFIRMED"} and row["lease_until"] is not None:
            raise IndependentAcquisitionError("acquisition:released-lease")

    operation_rows = snapshot["acquisition_operations"]
    transition_rows = snapshot["acquisition_transitions"]
    if operation_rows != sorted(operation_rows, key=lambda row: int(row["sequence"])) or transition_rows != sorted(transition_rows, key=lambda row: int(row["sequence"])):
        raise IndependentAcquisitionError("acquisition:transition-order")
    operations = {str(row["operation_id"]): row for row in operation_rows}
    if len(operations) != len(operation_rows):
        raise IndependentAcquisitionError("acquisition:duplicate-operation")
    transitions = transition_rows
    transition_ids: set[str] = set()
    if len(transitions) != sequence or len(operations) != sequence:
        raise IndependentAcquisitionError("acquisition:sequence-count")
    replay: dict[str, dict[str, object]] = {}
    last_operation_ids: dict[str, str] = {}
    current_root = _state_root(chain_id, 0, _genesis_root(chain_id), None)
    legal = {
        ("", "DUE"): {"CREATE_SLOT"}, ("DUE", "LEASED"): {"LEASE"}, ("LEASED", "CAPTURED"): {"CAPTURE"},
        ("LEASED", "DUE"): {"REQUEUE", "FAIL"}, ("LEASED", "HELD"): {"FAIL"},
        ("CAPTURED", "QUARANTINE_PENDING"): {"BEGIN_QUARANTINE"}, ("CAPTURED", "DUE"): {"REQUEUE", "FAIL"},
        ("CAPTURED", "HELD"): {"FAIL"}, ("QUARANTINE_PENDING", "QUARANTINE_PENDING"): {"RECOVER_QUARANTINE"},
        ("QUARANTINE_PENDING", "QUARANTINED"): {"CONFIRM_QUARANTINE"},
        ("QUARANTINE_PENDING", "QUARANTINE_UNCONFIRMED"): {"QUARANTINE_UNCONFIRMED"},
    }
    for expected_sequence, transition in enumerate(transitions, start=1):
        operation = operations.get(str(transition["operation_id"]))
        if operation is None or transition["sequence"] != expected_sequence or operation["sequence"] != expected_sequence or operation["transition_id"] != transition["transition_id"]:
            raise IndependentAcquisitionError("acquisition:transition-order")
        if transition["action"] not in ACTIONS or operation["action"] != transition["action"] or operation["attempt"] != transition["attempt"] or transition["request_digest"] != cfg["request_digest"] or operation["request_digest"] != cfg["request_digest"]:
            raise IndependentAcquisitionError("acquisition:action-binding")
        material_raw = operation["material_raw"]
        if type(material_raw) is not bytes:
            raise IndependentAcquisitionError("acquisition:material")
        material = _parse(material_raw, maximum=128 * 1024)
        expected_material_keys = {"action", "attempt", "request_digest", "prior_state", "next_state", "slot_after"}
        if set(material) != expected_material_keys or material["action"] != transition["action"] or material["attempt"] != transition["attempt"] or material["request_digest"] != cfg["request_digest"] or material["prior_state"] != transition["prior_state"] or material["next_state"] != transition["next_state"]:
            raise IndependentAcquisitionError("acquisition:material-binding")
        if operation["material_digest"] != _digest("material", material) or transition["material_digest"] != operation["material_digest"]:
            raise IndependentAcquisitionError("acquisition:material-digest")
        expected_operation_id = _digest("operation", {"acquisition_id": cfg["acquisition_id"], "slot_id": transition["slot_id"], "action": transition["action"], "attempt": transition["attempt"], "request_digest": cfg["request_digest"], "material_digest": operation["material_digest"]})
        if operation["operation_id"] != expected_operation_id:
            raise IndependentAcquisitionError("acquisition:operation-id")
        if transition["transition_id"] in transition_ids:
            raise IndependentAcquisitionError("acquisition:duplicate-transition")
        transition_ids.add(str(transition["transition_id"]))
        after_slot = _decode_safe_row(material["slot_after"])
        prior = str(transition["prior_state"])
        nxt = str(transition["next_state"])
        previous = replay.get(str(transition["slot_id"]))
        if (previous is None and prior != "") or (previous is not None and previous["state"] != prior) or transition["action"] not in legal.get((prior, nxt), set()):
            raise IndependentAcquisitionError("acquisition:illegal-edge")
        if transition["action"] == "CREATE_SLOT":
            if previous is not None or transition["attempt"] != 0 or after_slot["attempt"] != 0:
                raise IndependentAcquisitionError("acquisition:create-attempt")
        elif previous is None:
            raise IndependentAcquisitionError("acquisition:missing-predecessor")
        elif transition["action"] == "LEASE":
            if transition["attempt"] != int(previous["attempt"]) + 1 or after_slot["attempt"] != transition["attempt"]:
                raise IndependentAcquisitionError("acquisition:lease-attempt")
        elif transition["attempt"] != int(previous["attempt"]) or after_slot["attempt"] != transition["attempt"]:
            raise IndependentAcquisitionError("acquisition:attempt-progression")
        if after_slot["state"] in {"LEASED", "CAPTURED", "QUARANTINE_PENDING"}:
            if after_slot["lease_id"] in (None, "") or after_slot["lease_until"] is None or int(after_slot["lease_until"]) <= int(transition["observed_at"]):
                raise IndependentAcquisitionError("acquisition:lease-fields")
            recovery = transition["action"] == "RECOVER_QUARANTINE"
            expected_lease_id = _digest("lease", {"slot_id": transition["slot_id"], "attempt": transition["attempt"], "recovery": recovery})
            if after_slot["lease_id"] != expected_lease_id:
                raise IndependentAcquisitionError("acquisition:lease-identity")
        elif after_slot["lease_id"] is not None or after_slot["lease_until"] is not None:
            raise IndependentAcquisitionError("acquisition:released-lease")
        if after_slot["state"] in {"LEASED", "CAPTURED"} and after_slot["failure_code"] not in (None, ""):
            raise IndependentAcquisitionError("acquisition:active-failure")
        if after_slot["state"] == "QUARANTINE_PENDING" and after_slot["failure_code"] != "response-loss":
            raise IndependentAcquisitionError("acquisition:pending-failure")
        if after_slot["state"] == "QUARANTINE_UNCONFIRMED" and after_slot["failure_code"] != "quarantine-unconfirmed":
            raise IndependentAcquisitionError("acquisition:unconfirmed-failure")
        if after_slot["state"] == "QUARANTINED" and after_slot["failure_code"] not in (None, ""):
            raise IndependentAcquisitionError("acquisition:quarantined-failure")
        if transition["before_root"] != current_root or transition["after_root"] != _state_root(chain_id, expected_sequence, current_root, transition["transition_id"]):
            raise IndependentAcquisitionError("acquisition:transition-root")
        raw = transition["transition_raw"]
        if type(raw) is not bytes:
            raise IndependentAcquisitionError("acquisition:transition-bytes")
        expected_transition = {"schema": SCHEMA, "schema_version": SCHEMA_VERSION, "transition_id": transition["transition_id"], "sequence": expected_sequence, "slot_id": transition["slot_id"], "operation_id": transition["operation_id"], "action": transition["action"], "attempt": transition["attempt"], "request_digest": cfg["request_digest"], "prior_state": prior, "next_state": nxt, "before_root": transition["before_root"], "after_root": transition["after_root"], "material_digest": transition["material_digest"], "observed_at": transition["observed_at"]}
        value = _parse(raw, maximum=128 * 1024)
        transition_preimage = {key: item for key, item in value.items() if key != "transition_id"}
        transition_preimage["after_root"] = ""
        if value != expected_transition or _digest("transition", transition_preimage) != transition["transition_id"]:
            raise IndependentAcquisitionError("acquisition:transition-binding")
        receipt_raw = operation["receipt_raw"]
        if type(receipt_raw) is not bytes or operation["receipt_digest"] != _raw_digest(receipt_raw):
            raise IndependentAcquisitionError("acquisition:receipt")
        expected_receipt = {"schema": SCHEMA, "schema_version": SCHEMA_VERSION, "acquisition_id": cfg["acquisition_id"], "operation_id": operation["operation_id"], "slot_id": transition["slot_id"], "action": transition["action"], "attempt": transition["attempt"], "request_digest": cfg["request_digest"], "prior_state": prior, "next_state": nxt, "sequence": expected_sequence, "before_root": transition["before_root"], "after_root": transition["after_root"], "transition_id": transition["transition_id"], "material_digest": transition["material_digest"], "flags": FIXED_FLAGS}
        if _parse(receipt_raw, maximum=128 * 1024) != expected_receipt:
            raise IndependentAcquisitionError("acquisition:receipt-binding")
        if after_slot["slot_id"] != transition["slot_id"] or after_slot["state"] != nxt:
            raise IndependentAcquisitionError("acquisition:material-slot")
        replay[str(transition["slot_id"])] = after_slot
        last_operation_ids[str(transition["slot_id"])] = str(operation["operation_id"])
        current_root = transition["after_root"]
    if state_root != current_root or sequence and head_transition_id != transitions[-1]["transition_id"]:
        raise IndependentAcquisitionError("acquisition:head")
    for slot_id, row in slots.items():
        after = replay.get(slot_id)
        if after is None:
            raise IndependentAcquisitionError("acquisition:slot-orphan")
        for key in SLOT_COLUMNS:
            if key != "last_operation_id" and row[key] != after[key]:
                raise IndependentAcquisitionError("acquisition:slot-replay")
        if row["last_operation_id"] not in (None, "") and row["last_operation_id"] not in operations:
            raise IndependentAcquisitionError("acquisition:last-operation")
        if row["last_operation_id"] != last_operation_ids.get(slot_id):
            raise IndependentAcquisitionError("acquisition:last-operation")
    attestations = snapshot["acquisition_attestations"]
    seen: set[tuple[str, int, int]] = set()
    for row in attestations:
        key = (str(row["slot_id"]), int(row["page_index"]), int(row["attempt"]))
        if key in seen or row["slot_id"] not in slots:
            raise IndependentAcquisitionError("acquisition:attestation-identity")
        seen.add(key)
        verify_attestation(row, config=cfg, scheduled_at=slots[row["slot_id"]]["scheduled_at"])
    for slot_id, slot in slots.items():
        selected = [] if slot["selected_pages_raw"] is None else _parse(slot["selected_pages_raw"], maximum=128 * 1024)
        actual = [row for row in attestations if row["slot_id"] == slot_id]
        if slot["page_count"] is None and actual:
            raise IndependentAcquisitionError("acquisition:orphan-attestation")
        if slot["page_count"] is not None:
            selected_keys = {(item["page_index"], item["transport_attempt"]) for item in selected}
            for item in selected:
                if item["lease_attempt"] != slot["capture_attempt"]:
                    raise IndependentAcquisitionError("acquisition:selected-lease-binding")
                matching_attempts = [int(row["attempt"]) for row in actual if int(row["page_index"]) == item["page_index"]]
                if not matching_attempts or item["transport_attempt"] != max(matching_attempts):
                    raise IndependentAcquisitionError("acquisition:selected-attempt")
                match = next((row for row in actual if (row["page_index"], row["attempt"]) == (item["page_index"], item["transport_attempt"])), None)
                if match is None or match["attestation_digest"] != item["attestation_digest"] or match["request_digest"] != item["request_digest"] or match["response_digest"] != item["response_digest"]:
                    raise IndependentAcquisitionError("acquisition:selected-attestation-binding")
            if len(selected_keys) != slot["page_count"]:
                raise IndependentAcquisitionError("acquisition:selected-attestation-count")
            pages = _parse(slot["page_digests_raw"], maximum=128 * 1024)
            if any(int(row["page_index"]) >= slot["page_count"] for row in actual):
                raise IndependentAcquisitionError("acquisition:extra-page-attestation")
            if any(item["response_digest"] != pages[item["page_index"]] for item in selected):
                raise IndependentAcquisitionError("acquisition:page-response-binding")
    return {"accepted": True, "schema": SCHEMA, "schema_version": SCHEMA_VERSION, "config": cfg, "config_digest": config_digest, "chain_id": chain_id, "sequence": sequence, "state_root": current_root, "head_transition_id": transitions[-1]["transition_id"] if transitions else GENESIS_TRANSITION, "slot_count": len(slots), "operation_count": len(operations), "transition_count": len(transitions), "attestation_count": len(attestations), "states": {state: sum(row["state"] == state for row in slots.values()) for state in sorted(STATES)}, "failure_counts": {code: sum(row["failure_code"] == code for row in slots.values()) for code in sorted({str(row["failure_code"]) for row in slots.values() if row["failure_code"] not in (None, "")})}}


def _sqlite_snapshot(connection: sqlite3.Connection) -> dict[str, list[dict[str, object]]]:
    return {table: [{column: row[column] for column in columns} for row in connection.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()] for table, columns in TABLE_COLUMNS.items()}


def _check_shape(connection: sqlite3.Connection) -> None:
    tables = {str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
    if tables != set(TABLE_COLUMNS):
        raise IndependentAcquisitionError("acquisition:database-schema")
    for table, columns in TABLE_COLUMNS.items():
        actual = tuple(str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})"))
        if actual != tuple(columns):
            raise IndependentAcquisitionError(f"acquisition:{table}-schema")


def snapshot_database(path: str | Path, *, config: Mapping[str, object] | object) -> dict[str, object]:
    database = Path(path)
    if not database.is_file() or database.stat().st_size > MAX_DATABASE_BYTES:
        raise IndependentAcquisitionError("acquisition:database")
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(f"file:{database.resolve().as_posix()}?mode=ro", uri=True, timeout=BUSY_TIMEOUT_MS / 1000.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
        _check_shape(connection)
        connection.execute("BEGIN")
        snapshot = _sqlite_snapshot(connection)
        evidence = _verify_rows(snapshot, config=config)
        connection.commit()
        return {"evidence": evidence, "snapshot": snapshot}
    except IndependentAcquisitionError:
        if connection is not None and connection.in_transaction:
            connection.rollback()
        raise
    except (sqlite3.Error, OSError, ValueError) as exc:
        if connection is not None and connection.in_transaction:
            connection.rollback()
        raise IndependentAcquisitionError("acquisition:database-corrupt") from exc
    finally:
        if connection is not None:
            connection.close()


def verify_database(path: str | Path, *, config: Mapping[str, object] | object) -> dict[str, object]:
    return dict(snapshot_database(path, config=config)["evidence"])  # type: ignore[arg-type]


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
                encoded_pages = row.pop("page_digests_hex")
                encoded_selected = row.pop("selected_pages_hex")
                row["page_digests_raw"] = None if encoded_pages is None else _parse_blob(encoded_pages, "page-digests", 128 * 1024)
                row["selected_pages_raw"] = None if encoded_selected is None else _parse_blob(encoded_selected, "selected-pages", 128 * 1024)
            elif table == "acquisition_operations":
                row["material_raw"] = _parse_blob(row.pop("material_hex"), "material", 128 * 1024)
                row["receipt_raw"] = _parse_blob(row.pop("receipt_hex"), "receipt", 128 * 1024)
            elif table == "acquisition_transitions":
                row["transition_raw"] = _parse_blob(row.pop("transition_hex"), "transition", 128 * 1024)
            decoded.append(row)
        result[table] = decoded
    return result


def verify_export_bytes(raw: bytes, *, config: Mapping[str, object] | object) -> dict[str, object]:
    value = _parse(raw, string_limit=2 * 128 * 1024)
    if set(value) != EXPORT_KEYS or value["schema"] != EXPORT_SCHEMA or value["schema_version"] != EXPORT_VERSION:
        raise IndependentAcquisitionError("acquisition:export-schema")
    cfg = _config_view(config)
    config_digest = _digest("config", cfg)
    if value["config"] != cfg or value["config_digest"] != config_digest or value["chain_id"] != _chain_id(config_digest):
        raise IndependentAcquisitionError("acquisition:export-config")
    for key, expected in FIXED_FLAGS.items():
        if value[key] != expected:
            raise IndependentAcquisitionError("acquisition:export-flags")
    snapshot = _decode_export(value)
    evidence = _verify_rows(snapshot, config=cfg)
    body = dict(value)
    body.pop("export_root")
    if value["export_root"] != _digest("export-root", body):
        raise IndependentAcquisitionError("acquisition:export-root")
    return {**evidence, "export_root": value["export_root"], "snapshot": snapshot}


def support_snapshot(path: str | Path, *, config: Mapping[str, object] | object) -> dict[str, object]:
    result = snapshot_database(path, config=config)
    evidence = result["evidence"]
    snapshot = result["snapshot"]
    return {"schema": "mirror-authenticated-source-acquisition-support-v2", "schema_version": 2, "state": "EMPTY" if evidence["slot_count"] == 0 else "NONEMPTY", "sequence": evidence["sequence"], "slot_counts": evidence["states"], "failure_counts": evidence["failure_counts"], "attempt_count": sum(int(row["attempt"]) for row in snapshot["acquisition_slots"]), "attestation_count": evidence["attestation_count"], "head_transition_id": evidence["head_transition_id"], "state_root": evidence["state_root"], "chain_id": evidence["chain_id"], **FIXED_FLAGS}


__all__ = ["SCHEMA", "SCHEMA_VERSION", "EXPORT_SCHEMA", "EXPORT_VERSION", "STATES", "SAFE_FAILURES", "CONFIG_KEYS", "META_KEYS", "SLOT_COLUMNS", "OPERATION_COLUMNS", "TRANSITION_COLUMNS", "ATTESTATION_COLUMNS", "TABLE_COLUMNS", "EXPORT_KEYS", "EXPORT_ROW_KEYS", "FIXED_FLAGS", "IndependentAcquisitionError", "_canonical", "_digest", "_raw_digest", "_config_view", "_config_digest", "_chain_id", "_genesis_root", "_state_root", "_parse", "verify_attestation", "snapshot_database", "verify_database", "verify_export_bytes", "support_snapshot"]
