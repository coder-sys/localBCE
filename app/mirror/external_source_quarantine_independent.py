"""Independent verifier for the durable external-evidence quarantine.

This module deliberately has no import from ``external_source_quarantine``.
It reconstructs the database and export chain from canonical bytes, and it
delegates only the source-artifact grammar to the already independent adapter
verifier.  It never treats quarantine as approval, source truth, or a bridge
to another Mirror component.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
import re
import sqlite3
from typing import Mapping

from app.mirror import external_source_adapter_independent as adapter
from app.mirror import sqlite_snapshot


SCHEMA = "mirror-external-source-quarantine-v1"
SCHEMA_VERSION = 3
EXPORT_SCHEMA = "mirror-external-source-quarantine-export-v1"
EXPORT_VERSION = 3
DOMAIN = "BL/MIRROR/EXTERNAL_SOURCE_QUARANTINE/"
QUARANTINE_STATUS = "QUARANTINED"
HEAD_STATES = ("QUARANTINED", "WITHDRAWN")
ACTION_ADMIT = "ADMIT"
ACTION_SUPERSEDE = "SUPERSEDE"
ACTION_WITHDRAW = "WITHDRAW"
ACTIONS = (ACTION_ADMIT, ACTION_SUPERSEDE, ACTION_WITHDRAW)
WITHDRAW_REASONS = ("SOURCE_WITHDRAWN", "POLICY_REVOKED", "INTEGRITY_REVIEW")
GENESIS_TRANSITION = "GENESIS"
MAX_ARTIFACTS = 1_024
MAX_TRANSITIONS = 2_048
MAX_OPERATIONS = 2_048
MAX_EXPORT_BYTES = 32 * 1024 * 1024
MAX_DATABASE_BYTES = 64 * 1024 * 1024
MAX_WAL_BYTES = 64 * 1024 * 1024
BUSY_TIMEOUT_MS = 250
HEX128 = re.compile(r"^[0-9a-f]{128}$")
SAFE_REQUEST_DIGEST = HEX128

META_KEYS = (
    "schema",
    "schema_version",
    "policy_digest",
    "database_id",
    "chain_id",
    "sequence",
    "head_root",
    "head_transition_id",
    "state_root",
)
TABLE_COLUMNS = {
    "quarantine_meta": ("key", "value"),
    "quarantine_artifacts": (
        "policy_digest", "artifact_id", "capture_id", "artifact_digest", "artifact_raw",
        "status", "observed_at", "fetched_at",
    ),
    "quarantine_operations": (
        "operation_id", "policy_digest", "action", "request_digest", "request_material_digest",
        "artifact_id", "expected_head", "reason", "transition_id", "receipt_digest", "sequence",
        "receipt_raw",
    ),
    "quarantine_transitions": (
        "transition_id", "policy_digest", "database_id", "sequence", "action", "artifact_id", "prior_head",
        "next_head", "prior_state", "next_state", "observed_at", "reason", "operation_id",
        "before_root", "after_root", "transition_raw",
    ),
    "quarantine_heads": (
        "policy_digest", "head_artifact_id", "state", "sequence", "head_root",
        "head_transition_id", "observed_at", "capture_id",
    ),
}
SNAPSHOT_TABLES = tuple(TABLE_COLUMNS)
EXPORT_KEYS = {
    "schema", "schema_version", "policy_digest", "database_id", "chain_id", "meta", "artifacts",
    "operations", "transitions", "heads", "state_owned", "synthetic_only",
    "support_safe", "read_only", "observation_only", "quarantine_only", "production_usable",
    "activation", "payment_authority", "clearance_authority", "settlement_authority",
    "adjudication_authority", "downstream_bridge", "proofSuiteId", "export_root",
}
EXPORT_ROW_KEYS = {
    "quarantine_meta": {"key", "value"},
    "quarantine_artifacts": {
        "policy_digest", "artifact_id", "capture_id", "artifact_digest", "artifact_hex",
        "status", "observed_at", "fetched_at",
    },
    "quarantine_operations": {
        "operation_id", "policy_digest", "action", "request_digest", "request_material_digest",
        "artifact_id", "expected_head", "reason", "transition_id", "receipt_digest", "sequence",
        "receipt_hex",
    },
    "quarantine_transitions": {
        "transition_id", "policy_digest", "database_id", "sequence", "action", "artifact_id", "prior_head",
        "next_head", "prior_state", "next_state", "observed_at", "reason", "operation_id",
        "before_root", "after_root", "transition_hex",
    },
    "quarantine_heads": {
        "policy_digest", "head_artifact_id", "state", "sequence", "head_root",
        "head_transition_id", "observed_at", "capture_id",
    },
}
FIXED_FLAGS = {
    "state_owned": True,
    "synthetic_only": True,
    "read_only": True,
    "observation_only": True,
    "quarantine_only": True,
    "production_usable": False,
    "activation": False,
    "payment_authority": False,
    "clearance_authority": False,
    "settlement_authority": False,
    "adjudication_authority": False,
    "downstream_bridge": False,
    "proofSuiteId": None,
}
SAFE_DATABASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
TRANSITION_KEYS = {
    "schema", "schema_version", "transition_id", "sequence", "action", "policy_digest",
    "database_id",
    "artifact_id", "prior_head", "next_head", "prior_state", "next_state", "observed_at",
    "reason", "operation_id", "before_root", "after_root", "flags",
}
RECEIPT_KEYS = {
    "schema", "schema_version", "receipt_id", "operation_id", "action", "policy_digest",
    "database_id",
    "artifact_id", "artifact_digest", "capture_id", "prior_head", "head_artifact_id", "state", "sequence",
    "transition_id", "before_root", "after_root", "chain_id", "flags",
}
FOREIGN_KEY_MANIFEST = {
    "quarantine_meta": (),
    "quarantine_artifacts": (),
    "quarantine_operations": (
        ("quarantine_artifacts", (("policy_digest", "policy_digest"), ("artifact_id", "artifact_id")), "NO ACTION", "NO ACTION", "NONE"),
    ),
    "quarantine_transitions": (
        ("quarantine_artifacts", (("policy_digest", "policy_digest"), ("artifact_id", "artifact_id")), "NO ACTION", "NO ACTION", "NONE"),
        ("quarantine_operations", (("operation_id", "operation_id"),), "NO ACTION", "NO ACTION", "NONE"),
    ),
    "quarantine_heads": (
        ("quarantine_artifacts", (("policy_digest", "policy_digest"), ("head_artifact_id", "artifact_id")), "NO ACTION", "NO ACTION", "NONE"),
        ("quarantine_transitions", (("head_transition_id", "transition_id"),), "NO ACTION", "NO ACTION", "NONE"),
    ),
}


class IndependentQuarantineError(ValueError):
    """A bounded independent quarantine rejection."""


@dataclass(frozen=True)
class VerifiedAdmissionReceiptV1:
    """Opaque, independently reconstructed admission result.

    The value is deliberately produced by this independent module.  It binds
    the receipt bytes to the operation, transition, artifact, and post-action
    head; callers cannot manufacture a receipt by rebinding a JSON fragment.
    """

    schema: str
    schema_version: int
    receipt_id: str
    receipt_digest: str
    receipt_raw: bytes
    operation_id: str
    action: str
    policy_digest: str
    database_id: str
    chain_id: str
    artifact_id: str
    artifact_digest: str
    capture_id: str
    prior_head: str
    head_artifact_id: str
    state: str
    sequence: int
    transition_id: str
    before_root: str
    after_root: str

    @property
    def result(self) -> str:
        return self.state


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise IndependentQuarantineError("quarantine:noncanonical") from exc


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise IndependentQuarantineError("quarantine:duplicate-key")
        result[key] = value
    return result


def _walk(value: object, *, depth: int = 0, nodes: list[int] | None = None, max_string_bytes: int = 4_096) -> None:
    nodes = [0] if nodes is None else nodes
    nodes[0] += 1
    if nodes[0] > 32_768:
        raise IndependentQuarantineError("quarantine:node-cap")
    if depth > 24:
        raise IndependentQuarantineError("quarantine:depth-cap")
    if isinstance(value, float):
        raise IndependentQuarantineError("quarantine:float")
    if isinstance(value, str):
        try:
            value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise IndependentQuarantineError("quarantine:ascii") from exc
        if len(value.encode("ascii")) > max_string_bytes:
            raise IndependentQuarantineError("quarantine:string-cap")
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise IndependentQuarantineError("quarantine:key-type")
            _walk(item, depth=depth + 1, nodes=nodes, max_string_bytes=max_string_bytes)
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth=depth + 1, nodes=nodes, max_string_bytes=max_string_bytes)


def _parse(raw: bytes, *, maximum: int, max_string_bytes: int = 4_096) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > maximum:
        raise IndependentQuarantineError("quarantine:byte-cap")
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(IndependentQuarantineError("quarantine:constant")),
        )
    except IndependentQuarantineError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise IndependentQuarantineError("quarantine:parse") from exc
    if not isinstance(value, dict):
        raise IndependentQuarantineError("quarantine:top-level")
    _walk(value, max_string_bytes=max_string_bytes)
    if _canonical(value) != raw:
        raise IndependentQuarantineError("quarantine:not-canonical")
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
        raise IndependentQuarantineError(f"quarantine:{label}")
    return value


def _database_id(value: object) -> str:
    if not isinstance(value, str) or SAFE_DATABASE_ID.fullmatch(value) is None:
        raise IndependentQuarantineError("quarantine:database-id")
    lowered = value.lower()
    if any(marker in lowered for marker in ("http://", "https://", "path", "token", "secret", "password", "credential", "patient", "member", "claim", "npi", "email", "phone", "address")):
        raise IndependentQuarantineError("quarantine:database-id-forbidden")
    return value


def _integer(value: object, label: str, *, minimum: int = 0, maximum: int = 10**12) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise IndependentQuarantineError(f"quarantine:{label}")
    return value


def _policy_view(policy: Mapping[str, object] | object) -> dict[str, object]:
    try:
        material = policy.material() if hasattr(policy, "material") else dict(policy)  # type: ignore[arg-type]
        normalized = adapter._policy_material(material)
    except Exception as exc:
        raise IndependentQuarantineError("quarantine:policy") from exc
    return dict(normalized)


def _policy_digest(policy: Mapping[str, object] | object) -> str:
    return adapter._digest("policy", _policy_view(policy))


def _chain_id(policy: Mapping[str, object], database_id: str) -> str:
    database = _database_id(database_id)
    return _digest("chain-id", {"policy_digest": _policy_digest(policy), "database_id": database})


def _genesis_root(chain_id: str) -> str:
    return _digest("genesis-root", {"chain_id": chain_id, "transition_id": GENESIS_TRANSITION})


def _state_root(chain_id: str, sequence: int, head_root: str) -> str:
    return _digest("state-root", {"chain_id": chain_id, "sequence": sequence, "head_root": head_root})


def _after_root(chain_id: str, sequence: int, transition_id: str, head_artifact_id: str, state: str, before_root: str) -> str:
    return _digest(
        "head-root",
        {
            "chain_id": chain_id,
            "sequence": sequence,
            "transition_id": transition_id,
            "head_artifact_id": head_artifact_id,
            "state": state,
            "before_root": before_root,
        },
    )


def _request_material_digest(
    *,
    operation_id: str,
    policy_digest: str,
    artifact_id: str,
    expected_head: str,
    reason: str,
) -> str:
    return _digest(
        "request-material",
        {
            "operation_id": operation_id,
            "policy_digest": policy_digest,
            "artifact_id": artifact_id,
            "expected_head": expected_head,
            "reason": reason,
        },
    )


def _operation_id(action: str, request_digest: str, database_id: str) -> str:
    return _digest("operation-id", {"action": action, "request_digest": request_digest, "database_id": _database_id(database_id)})


def _transition_id(body: Mapping[str, object]) -> str:
    # ``after_root`` is derived from the transition identity, so it is not
    # part of the preimage that creates that identity.
    without_id = {key: value for key, value in body.items() if key not in {"transition_id", "after_root"}}
    return _digest("transition-id", without_id)


def _receipt_id(body: Mapping[str, object]) -> str:
    without_id = {key: value for key, value in body.items() if key != "receipt_id"}
    return _digest("receipt-id", without_id)


def verify_receipt_bytes(
    raw: bytes,
    *,
    policy_digest: str,
    database_id: str,
    chain_id: str,
    artifact_id: str,
    artifact_digest: str,
    capture_id: str,
    action: str,
    operation_id: str,
    prior_head: str,
    head_artifact_id: str,
    state: str,
    sequence: int | None,
    transition_id: str,
    before_root: str | None,
    after_root: str | None,
) -> VerifiedAdmissionReceiptV1:
    """Verify one receipt against caller-supplied, already-bound row facts.

    This is the public pure boundary used by acquisition's independent
    verifier.  It never accepts a caller status or root as authority: every
    supplied fact is compared with the canonical receipt and its identity.
    The stronger database form below additionally reconstructs the operation,
    transition, artifact, and head rows.
    """

    if type(raw) is not bytes or not raw or len(raw) > MAX_EXPORT_BYTES:
        raise IndependentQuarantineError("quarantine:receipt-bytes")
    try:
        value = _parse(raw, maximum=MAX_EXPORT_BYTES)
    except Exception as exc:
        raise IndependentQuarantineError("quarantine:receipt-parse") from exc
    if set(value) != RECEIPT_KEYS:
        raise IndependentQuarantineError("quarantine:receipt-keys")
    database = _database_id(database_id)
    policy = _hex(policy_digest, "receipt-policy")
    chain = _hex(chain_id, "receipt-chain")
    if sequence is None:
        sequence = value.get("sequence")
    if before_root is None:
        before_root = value.get("before_root")
    if after_root is None:
        after_root = value.get("after_root")
    expected = {
        "schema": f"{SCHEMA}-receipt",
        "schema_version": SCHEMA_VERSION,
        "operation_id": operation_id,
        "action": action,
        "policy_digest": policy,
        "database_id": database,
        "artifact_id": artifact_id,
        "artifact_digest": artifact_digest,
        "capture_id": capture_id,
        "prior_head": prior_head,
        "head_artifact_id": head_artifact_id,
        "state": state,
        "sequence": sequence,
        "transition_id": transition_id,
        "before_root": before_root,
        "after_root": after_root,
        "chain_id": chain,
        "flags": FIXED_FLAGS,
    }
    if value != {**expected, "receipt_id": value.get("receipt_id")}:
        raise IndependentQuarantineError("quarantine:receipt-binding")
    receipt_id = value.get("receipt_id")
    if not isinstance(receipt_id, str) or _receipt_id(value) != receipt_id:
        raise IndependentQuarantineError("quarantine:receipt-identity")
    for label, item in (
        ("receipt-operation", operation_id), ("receipt-artifact", artifact_id),
        ("receipt-transition", transition_id), ("receipt-before", before_root),
        ("receipt-after", after_root), ("receipt-artifact-digest", artifact_digest),
    ):
        _hex(item, label)
    if not isinstance(capture_id, str) or not capture_id or not isinstance(action, str) or action not in ACTIONS:
        raise IndependentQuarantineError("quarantine:receipt-fields")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1 or sequence > MAX_TRANSITIONS:
        raise IndependentQuarantineError("quarantine:receipt-sequence")
    return VerifiedAdmissionReceiptV1(
        schema=str(value["schema"]), schema_version=int(value["schema_version"]),
        receipt_id=receipt_id, receipt_digest=_raw_digest(raw), receipt_raw=bytes(raw),
        operation_id=operation_id, action=action, policy_digest=policy, database_id=database,
        chain_id=chain, artifact_id=artifact_id, artifact_digest=artifact_digest,
        capture_id=capture_id, prior_head=prior_head, head_artifact_id=head_artifact_id,
        state=state, sequence=sequence, transition_id=transition_id,
        before_root=before_root, after_root=after_root,
    )


def verify_admission_receipt(
    raw: bytes,
    *,
    policy: Mapping[str, object] | object,
    database_id: str,
    operation: Mapping[str, object],
    transition: Mapping[str, object],
    artifact: Mapping[str, object],
    head: Mapping[str, object],
) -> VerifiedAdmissionReceiptV1:
    """Reconstruct one receipt from all authoritative quarantine rows."""

    configured = _policy_view(policy)
    database = _database_id(database_id)
    policy_digest = _policy_digest(configured)
    chain_id = _chain_id(configured, database)
    if set(operation) != set(TABLE_COLUMNS["quarantine_operations"]):
        raise IndependentQuarantineError("quarantine:receipt-operation-row")
    if set(transition) != set(TABLE_COLUMNS["quarantine_transitions"]):
        raise IndependentQuarantineError("quarantine:receipt-transition-row")
    if set(artifact) != set(TABLE_COLUMNS["quarantine_artifacts"]):
        raise IndependentQuarantineError("quarantine:receipt-artifact-row")
    if set(head) != set(TABLE_COLUMNS["quarantine_heads"]):
        raise IndependentQuarantineError("quarantine:receipt-head-row")
    action = operation["action"]
    if action not in ACTIONS or transition["action"] != action:
        raise IndependentQuarantineError("quarantine:receipt-action")
    operation_id = _hex(operation["operation_id"], "receipt-operation")
    request_digest = _hex(operation["request_digest"], "receipt-request")
    if operation_id != _operation_id(str(action), request_digest, database):
        raise IndependentQuarantineError("quarantine:receipt-operation-id")
    artifact_id = _hex(operation["artifact_id"], "receipt-artifact")
    if transition["artifact_id"] != artifact_id or artifact["artifact_id"] != artifact_id:
        raise IndependentQuarantineError("quarantine:receipt-artifact-binding")
    if operation["policy_digest"] != policy_digest or transition["policy_digest"] != policy_digest or artifact["policy_digest"] != policy_digest or head["policy_digest"] != policy_digest:
        raise IndependentQuarantineError("quarantine:receipt-policy")
    if transition["database_id"] != database:
        raise IndependentQuarantineError("quarantine:receipt-database")
    expected_head = operation["expected_head"]
    if not isinstance(expected_head, str) or expected_head != transition["prior_head"]:
        raise IndependentQuarantineError("quarantine:receipt-prior-head")
    reason = operation["reason"]
    if action == ACTION_WITHDRAW:
        if reason not in WITHDRAW_REASONS:
            raise IndependentQuarantineError("quarantine:receipt-reason")
    elif reason != "":
        raise IndependentQuarantineError("quarantine:receipt-reason")
    if operation["request_material_digest"] != _request_material_digest(
        operation_id=operation_id, policy_digest=policy_digest, artifact_id=artifact_id,
        expected_head=expected_head, reason=reason,
    ):
        raise IndependentQuarantineError("quarantine:receipt-request-material")
    if operation["transition_id"] != transition["transition_id"]:
        raise IndependentQuarantineError("quarantine:receipt-transition")
    transition_id = _hex(transition["transition_id"], "receipt-transition")
    transition_raw = transition["transition_raw"]
    if type(transition_raw) is not bytes:
        raise IndependentQuarantineError("quarantine:receipt-transition-bytes")
    transition_value = _parse(transition_raw, maximum=MAX_EXPORT_BYTES)
    if set(transition_value) != TRANSITION_KEYS:
        raise IndependentQuarantineError("quarantine:receipt-transition-keys")
    if transition_value["schema"] != SCHEMA or transition_value["schema_version"] != SCHEMA_VERSION or any(
        transition_value[key] != transition[key]
        for key in (set(transition) & TRANSITION_KEYS) - {"flags"}
    ) or transition_value["flags"] != FIXED_FLAGS:
        raise IndependentQuarantineError("quarantine:receipt-transition-binding")
    if _transition_id(transition_value) != transition_id:
        raise IndependentQuarantineError("quarantine:receipt-transition-id")
    sequence = int(transition["sequence"])
    if sequence < 1 or operation["sequence"] != sequence:
        raise IndependentQuarantineError("quarantine:receipt-sequence")
    next_state = "WITHDRAWN" if action == ACTION_WITHDRAW else QUARANTINE_STATUS
    if transition["next_state"] != next_state:
        raise IndependentQuarantineError("quarantine:receipt-state")
    before_root = _hex(transition["before_root"], "receipt-before")
    after_root = _after_root(chain_id, sequence, transition_id, artifact_id, next_state, before_root)
    if transition["after_root"] != after_root:
        raise IndependentQuarantineError("quarantine:receipt-after")
    artifact_raw = artifact["artifact_raw"]
    if type(artifact_raw) is not bytes:
        raise IndependentQuarantineError("quarantine:receipt-artifact-bytes")
    artifact_result, capture = _adapter_value(artifact_raw, configured)
    artifact_digest = _raw_digest(artifact_raw)
    capture_id = str(artifact_result["capture_id"])
    if artifact_result["artifact_id"] != artifact_id or artifact["artifact_digest"] != artifact_digest or artifact["capture_id"] != capture_id:
        raise IndependentQuarantineError("quarantine:receipt-artifact-integrity")
    if artifact["status"] != QUARANTINE_STATUS or artifact["observed_at"] != capture.get("observed_at") or artifact["fetched_at"] != capture.get("fetched_at"):
        raise IndependentQuarantineError("quarantine:receipt-artifact-state")
    if head["head_artifact_id"] != artifact_id or head["state"] != next_state or int(head["sequence"]) != sequence or head["head_root"] != after_root or head["head_transition_id"] != transition_id or head["observed_at"] != artifact["observed_at"] or head["capture_id"] != capture_id:
        raise IndependentQuarantineError("quarantine:receipt-head")
    receipt_raw = operation["receipt_raw"]
    if type(raw) is not bytes or raw != receipt_raw:
        raise IndependentQuarantineError("quarantine:receipt-input")
    if type(receipt_raw) is not bytes or operation["receipt_digest"] != _raw_digest(receipt_raw):
        raise IndependentQuarantineError("quarantine:receipt-digest")
    return verify_receipt_bytes(
        receipt_raw, policy_digest=policy_digest, database_id=database, chain_id=chain_id,
        artifact_id=artifact_id, artifact_digest=artifact_digest, capture_id=capture_id,
        action=str(action), operation_id=operation_id, prior_head=expected_head,
        head_artifact_id=artifact_id, state=next_state, sequence=sequence,
        transition_id=transition_id, before_root=before_root, after_root=after_root,
    )


def _adapter_value(raw: bytes, policy: Mapping[str, object]) -> tuple[dict[str, object], dict[str, object]]:
    try:
        result = adapter.verify_artifact(raw, policy=policy)
        value = adapter._parse(raw)
    except adapter.IndependentExternalSourceError as exc:
        raise IndependentQuarantineError(str(exc)) from exc
    except Exception as exc:
        raise IndependentQuarantineError("quarantine:adapter-verification") from exc
    capture = value.get("capture")
    if not isinstance(capture, dict):
        raise IndependentQuarantineError("quarantine:adapter-capture")
    return result, capture


def _row_keys(rows: list[Mapping[str, object]], table: str) -> None:
    expected = set(TABLE_COLUMNS[table])
    for row in rows:
        if not isinstance(row, Mapping) or set(row) != expected:
            raise IndependentQuarantineError(f"quarantine:row-keys:{table}")


def _hex_bytes(value: object, label: str, *, maximum: int) -> bytes:
    if not isinstance(value, str) or len(value) % 2 or len(value) > maximum * 2:
        raise IndependentQuarantineError(f"quarantine:{label}-hex")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise IndependentQuarantineError(f"quarantine:{label}-hex") from exc
    if raw.hex() != value:
        raise IndependentQuarantineError(f"quarantine:{label}-canonical")
    return raw


def _verify_artifacts(
    rows: list[Mapping[str, object]],
    *,
    policy: Mapping[str, object],
    policy_digest: str,
) -> tuple[dict[str, dict[str, object]], dict[str, bytes]]:
    if len(rows) > MAX_ARTIFACTS:
        raise IndependentQuarantineError("quarantine:artifact-count")
    if rows != sorted(rows, key=lambda row: (str(row["policy_digest"]), str(row["artifact_id"]))):
        raise IndependentQuarantineError("quarantine:artifact-order")
    artifacts: dict[str, dict[str, object]] = {}
    raws: dict[str, bytes] = {}
    captures: set[str] = set()
    for row in rows:
        if row["policy_digest"] != policy_digest:
            raise IndependentQuarantineError("quarantine:artifact-policy")
        artifact_id = _hex(row["artifact_id"], "artifact-id")
        if artifact_id in artifacts:
            raise IndependentQuarantineError("quarantine:artifact-duplicate")
        raw = row["artifact_raw"]
        if type(raw) is not bytes or len(raw) > adapter.MAX_ARTIFACT_BYTES:
            raise IndependentQuarantineError("quarantine:artifact-bytes")
        expected_digest = _raw_digest(raw)
        if row["artifact_digest"] != expected_digest:
            raise IndependentQuarantineError("quarantine:artifact-digest")
        result, capture = _adapter_value(raw, policy)
        if result["artifact_id"] != artifact_id or result["policy_digest"] != policy_digest:
            raise IndependentQuarantineError("quarantine:artifact-binding")
        if row["capture_id"] != result["capture_id"] or row["capture_id"] in captures:
            raise IndependentQuarantineError("quarantine:capture-identity")
        if row["status"] != QUARANTINE_STATUS:
            raise IndependentQuarantineError("quarantine:durable-status")
        if row["observed_at"] != capture.get("observed_at") or row["fetched_at"] != capture.get("fetched_at"):
            raise IndependentQuarantineError("quarantine:time-binding")
        captures.add(str(row["capture_id"]))
        artifacts[artifact_id] = {
            "artifact_id": artifact_id,
            "artifact_digest": expected_digest,
            "capture_id": str(row["capture_id"]),
            "observed_at": int(row["observed_at"]),
            "fetched_at": int(row["fetched_at"]),
            "status": QUARANTINE_STATUS,
        }
        raws[artifact_id] = raw
    return artifacts, raws


def _verify_rows(
    snapshot: Mapping[str, object],
    *,
    policy: Mapping[str, object] | object,
    database_id: str,
) -> dict[str, object]:
    if set(snapshot) != set(SNAPSHOT_TABLES):
        raise IndependentQuarantineError("quarantine:snapshot-tables")
    rows: dict[str, list[Mapping[str, object]]] = {}
    for table in SNAPSHOT_TABLES:
        value = snapshot[table]
        if not isinstance(value, list):
            raise IndependentQuarantineError(f"quarantine:snapshot:{table}")
        _row_keys(value, table)
        rows[table] = value
    if len(rows["quarantine_meta"]) != len(META_KEYS):
        raise IndependentQuarantineError("quarantine:meta-count")
    if rows["quarantine_meta"] != sorted(rows["quarantine_meta"], key=lambda row: str(row["key"])):
        raise IndependentQuarantineError("quarantine:meta-order")
    metadata = {str(row["key"]): row["value"] for row in rows["quarantine_meta"]}
    if tuple(metadata) != tuple(sorted(META_KEYS)) or set(metadata) != set(META_KEYS):
        raise IndependentQuarantineError("quarantine:meta-keys")
    if any(type(value) is not str for value in metadata.values()):
        raise IndependentQuarantineError("quarantine:meta-values")
    configured = _policy_view(policy)
    database = _database_id(database_id)
    policy_digest = _policy_digest(configured)
    if metadata["schema"] != SCHEMA or metadata["schema_version"] != str(SCHEMA_VERSION):
        raise IndependentQuarantineError("quarantine:schema")
    if metadata["policy_digest"] != policy_digest:
        raise IndependentQuarantineError("quarantine:policy-drift")
    if metadata["database_id"] != database:
        raise IndependentQuarantineError("quarantine:database-id")
    chain_id = _chain_id(configured, database)
    if metadata["chain_id"] != chain_id:
        raise IndependentQuarantineError("quarantine:chain-id")
    sequence = int(metadata["sequence"]) if metadata["sequence"].isdigit() else -1
    if sequence < 0 or sequence > MAX_TRANSITIONS:
        raise IndependentQuarantineError("quarantine:sequence")
    head_root = _hex(metadata["head_root"], "head-root")
    head_transition_id = metadata["head_transition_id"]
    if sequence == 0:
        if head_root != _genesis_root(chain_id) or head_transition_id != GENESIS_TRANSITION:
            raise IndependentQuarantineError("quarantine:genesis")
    else:
        _hex(head_transition_id, "head-transition")

    artifacts, artifact_raws = _verify_artifacts(
        rows["quarantine_artifacts"], policy=configured, policy_digest=policy_digest,
    )
    transitions = rows["quarantine_transitions"]
    operations = rows["quarantine_operations"]
    if len(transitions) != sequence or len(operations) != sequence:
        raise IndependentQuarantineError("quarantine:chain-count")
    if len(transitions) > MAX_TRANSITIONS or len(operations) > MAX_OPERATIONS:
        raise IndependentQuarantineError("quarantine:chain-cap")
    if transitions != sorted(transitions, key=lambda row: int(row["sequence"])):
        raise IndependentQuarantineError("quarantine:transition-order")
    if operations != sorted(operations, key=lambda row: int(row["sequence"])):
        raise IndependentQuarantineError("quarantine:operation-order")
    if rows["quarantine_heads"] != sorted(rows["quarantine_heads"], key=lambda row: str(row["policy_digest"])):
        raise IndependentQuarantineError("quarantine:head-order")
    if len(rows["quarantine_heads"]) > 1:
        raise IndependentQuarantineError("quarantine:head-count")

    operation_map: dict[str, Mapping[str, object]] = {}
    transition_map: dict[str, Mapping[str, object]] = {}
    current_head = ""
    current_state = "EMPTY"
    current_observed = -1
    current_capture = ""
    current_root = _genesis_root(chain_id)
    seen_operation_ids: set[str] = set()
    seen_transition_ids: set[str] = set()
    admitted_artifacts: set[str] = set()
    for index, (operation, transition) in enumerate(zip(operations, transitions), start=1):
        if int(operation["sequence"]) != index or int(transition["sequence"]) != index:
            raise IndependentQuarantineError("quarantine:sequence-order")
        operation_id = _hex(operation["operation_id"], "operation-id")
        transition_id = _hex(transition["transition_id"], "transition-id")
        if operation_id in seen_operation_ids or transition_id in seen_transition_ids:
            raise IndependentQuarantineError("quarantine:identity-duplicate")
        seen_operation_ids.add(operation_id)
        seen_transition_ids.add(transition_id)
        action = operation["action"]
        if action not in ACTIONS or transition["action"] != action:
            raise IndependentQuarantineError("quarantine:action")
        request_digest = _hex(operation["request_digest"], "request-digest")
        if operation_id != _operation_id(str(action), request_digest, database):
            raise IndependentQuarantineError("quarantine:operation-binding")
        artifact_id = _hex(operation["artifact_id"], "operation-artifact")
        if artifact_id not in artifacts:
            raise IndependentQuarantineError("quarantine:operation-artifact")
        expected_head = operation["expected_head"]
        if expected_head != "":
            _hex(expected_head, "expected-head")
        reason = operation["reason"]
        if action == ACTION_WITHDRAW and reason not in WITHDRAW_REASONS:
            raise IndependentQuarantineError("quarantine:withdraw-reason")
        if action != ACTION_WITHDRAW and reason != "":
            raise IndependentQuarantineError("quarantine:admission-reason")
        expected_material = _request_material_digest(
            operation_id=operation_id,
            policy_digest=policy_digest,
            artifact_id=artifact_id,
            expected_head=str(expected_head),
            reason=str(reason),
        )
        if operation["request_material_digest"] != expected_material:
            raise IndependentQuarantineError("quarantine:request-binding")
        if operation["policy_digest"] != policy_digest or transition["policy_digest"] != policy_digest:
            raise IndependentQuarantineError("quarantine:chain-policy")
        if operation["transition_id"] != transition_id:
            raise IndependentQuarantineError("quarantine:operation-transition")
        if int(operation["sequence"]) != int(transition["sequence"]):
            raise IndependentQuarantineError("quarantine:operation-sequence")

        transition_value_raw = transition["transition_raw"]
        if type(transition_value_raw) is not bytes:
            raise IndependentQuarantineError("quarantine:transition-bytes")
        transition_value = _parse(transition_value_raw, maximum=MAX_EXPORT_BYTES)
        if set(transition_value) != TRANSITION_KEYS:
            raise IndependentQuarantineError("quarantine:transition-keys")
        if transition_value["schema"] != SCHEMA or transition_value["schema_version"] != SCHEMA_VERSION:
            raise IndependentQuarantineError("quarantine:transition-schema")
        for key in TRANSITION_KEYS - {"schema", "schema_version", "flags"}:
            if transition_value[key] != transition[key]:
                raise IndependentQuarantineError("quarantine:transition-row-binding")
        if transition_value["flags"] != FIXED_FLAGS or transition_value["database_id"] != database:
            raise IndependentQuarantineError("quarantine:transition-flags")
        if _transition_id(transition_value) != transition_id:
            raise IndependentQuarantineError("quarantine:transition-id")
        if transition["before_root"] != current_root:
            raise IndependentQuarantineError("quarantine:before-root")
        if transition["prior_head"] != current_head or transition["prior_state"] != current_state:
            raise IndependentQuarantineError("quarantine:prior-head")
        if transition["next_head"] != artifact_id or transition["artifact_id"] != artifact_id:
            raise IndependentQuarantineError("quarantine:next-head")
        if int(transition["observed_at"]) != artifacts[artifact_id]["observed_at"]:
            raise IndependentQuarantineError("quarantine:transition-time")
        if action == ACTION_ADMIT:
            if index != 1 or current_head or current_state != "EMPTY" or expected_head != "":
                raise IndependentQuarantineError("quarantine:initial-action")
            next_state = "QUARANTINED"
        elif action == ACTION_SUPERSEDE:
            if index == 1 or current_state != "QUARANTINED" or not current_head or expected_head != current_head:
                raise IndependentQuarantineError("quarantine:supersede-action")
            if artifact_id == current_head or artifacts[artifact_id]["observed_at"] <= current_observed:
                raise IndependentQuarantineError("quarantine:supersede-chronology")
            next_state = "QUARANTINED"
        else:
            if index == 1 or current_state != "QUARANTINED" or expected_head != current_head or artifact_id != current_head:
                raise IndependentQuarantineError("quarantine:withdraw-action")
            next_state = "WITHDRAWN"
        if transition["next_state"] != next_state:
            raise IndependentQuarantineError("quarantine:next-state")
        expected_after = _after_root(
            chain_id, index, transition_id, artifact_id, next_state, current_root,
        )
        if transition["after_root"] != expected_after or transition_value["after_root"] != expected_after:
            raise IndependentQuarantineError("quarantine:after-root")
        receipt_raw = operation["receipt_raw"]
        if type(receipt_raw) is not bytes:
            raise IndependentQuarantineError("quarantine:receipt-bytes")
        if operation["receipt_digest"] != _raw_digest(receipt_raw):
            raise IndependentQuarantineError("quarantine:receipt-digest")
        receipt = _parse(receipt_raw, maximum=MAX_EXPORT_BYTES)
        if set(receipt) != RECEIPT_KEYS:
            raise IndependentQuarantineError("quarantine:receipt-keys")
        if receipt["schema"] != f"{SCHEMA}-receipt" or receipt["schema_version"] != SCHEMA_VERSION:
            raise IndependentQuarantineError("quarantine:receipt-schema")
        if receipt["flags"] != FIXED_FLAGS or receipt["database_id"] != database:
            raise IndependentQuarantineError("quarantine:receipt-flags")
        if receipt["receipt_id"] != _receipt_id(receipt):
            raise IndependentQuarantineError("quarantine:receipt-id")
        receipt_bindings = {
            "operation_id": operation_id,
            "action": action,
            "policy_digest": policy_digest,
            "database_id": database,
            "artifact_id": artifact_id,
            "artifact_digest": artifacts[artifact_id]["artifact_digest"],
            "capture_id": artifacts[artifact_id]["capture_id"],
            "prior_head": current_head,
            "head_artifact_id": artifact_id,
            "state": next_state,
            "sequence": index,
            "transition_id": transition_id,
            "before_root": current_root,
            "after_root": expected_after,
            "chain_id": chain_id,
        }
        if any(receipt[key] != value for key, value in receipt_bindings.items()):
            raise IndependentQuarantineError("quarantine:receipt-binding")
        current_head = artifact_id
        current_state = next_state
        current_observed = int(artifacts[artifact_id]["observed_at"])
        current_capture = str(artifacts[artifact_id]["capture_id"])
        current_root = expected_after
        admitted_artifacts.add(artifact_id) if action in (ACTION_ADMIT, ACTION_SUPERSEDE) else None
        operation_map[operation_id] = operation
        transition_map[transition_id] = transition

    if sequence > 0 and head_root != current_root:
        raise IndependentQuarantineError("quarantine:metadata-head-root")
    if sequence > 0 and head_transition_id != str(transitions[-1]["transition_id"]):
        raise IndependentQuarantineError("quarantine:metadata-head-transition")
    if len(artifacts) != len(admitted_artifacts):
        raise IndependentQuarantineError("quarantine:artifact-conservation")
    head_rows = rows["quarantine_heads"]
    if sequence == 0:
        if head_rows:
            raise IndependentQuarantineError("quarantine:empty-head")
    else:
        if len(head_rows) != 1:
            raise IndependentQuarantineError("quarantine:head-missing")
        head = head_rows[0]
        expected_head = {
            "policy_digest": policy_digest,
            "head_artifact_id": current_head,
            "state": current_state,
            "sequence": sequence,
            "head_root": current_root,
            "head_transition_id": head_transition_id,
            "observed_at": current_observed,
            "capture_id": current_capture,
        }
        if dict(head) != expected_head:
            raise IndependentQuarantineError("quarantine:head-binding")
        if current_state not in HEAD_STATES:
            raise IndependentQuarantineError("quarantine:head-state")
    expected_state_root = _state_root(chain_id, sequence, current_root)
    if metadata["state_root"] != expected_state_root:
        raise IndependentQuarantineError("quarantine:state-root")
    return {
        "accepted": True,
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "policy_digest": policy_digest,
        "database_id": database,
        "chain_id": chain_id,
        "sequence": sequence,
        "head_artifact_id": current_head or None,
        "head_state": current_state,
        "head_root": current_root,
        "state_root": expected_state_root,
        "artifact_count": len(artifacts),
        "operation_count": len(operations),
        "transition_count": len(transitions),
        "withdrawn": current_state == "WITHDRAWN",
        "artifact_raws": artifact_raws,
    }


def _snapshot_from_connection(connection: sqlite3.Connection) -> dict[str, list[dict[str, object]]]:
    caps = {
        "quarantine_meta": len(META_KEYS),
        "quarantine_artifacts": MAX_ARTIFACTS,
        "quarantine_operations": MAX_OPERATIONS,
        "quarantine_transitions": MAX_TRANSITIONS,
        "quarantine_heads": 1,
    }
    result: dict[str, list[dict[str, object]]] = {}
    for table in SNAPSHOT_TABLES:
        count = int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
        if count > caps[table]:
            raise IndependentQuarantineError(f"quarantine:{table}-count")
        order_by = {
            "quarantine_meta": "key",
            "quarantine_artifacts": "policy_digest,artifact_id",
            "quarantine_operations": "sequence",
            "quarantine_transitions": "sequence",
            "quarantine_heads": "policy_digest",
        }[table]
        result[table] = [dict(row) for row in connection.execute(f"SELECT * FROM {table} ORDER BY {order_by} LIMIT {caps[table] + 1}")]
    return result


TABLE_INFO = {
    "quarantine_meta": (
        ("key", "TEXT", 0, None, 1), ("value", "TEXT", 1, None, 0),
    ),
    "quarantine_artifacts": (
        ("policy_digest", "TEXT", 1, None, 1), ("artifact_id", "TEXT", 1, None, 2),
        ("capture_id", "TEXT", 1, None, 0), ("artifact_digest", "TEXT", 1, None, 0),
        ("artifact_raw", "BLOB", 1, None, 0), ("status", "TEXT", 1, None, 0),
        ("observed_at", "INTEGER", 1, None, 0), ("fetched_at", "INTEGER", 1, None, 0),
    ),
    "quarantine_operations": (
        ("operation_id", "TEXT", 0, None, 1), ("policy_digest", "TEXT", 1, None, 0),
        ("action", "TEXT", 1, None, 0), ("request_digest", "TEXT", 1, None, 0),
        ("request_material_digest", "TEXT", 1, None, 0), ("artifact_id", "TEXT", 1, None, 0),
        ("expected_head", "TEXT", 1, "''", 0), ("reason", "TEXT", 1, "''", 0),
        ("transition_id", "TEXT", 1, None, 0), ("receipt_digest", "TEXT", 1, None, 0),
        ("sequence", "INTEGER", 1, None, 0), ("receipt_raw", "BLOB", 1, None, 0),
    ),
    "quarantine_transitions": (
        ("transition_id", "TEXT", 0, None, 1), ("policy_digest", "TEXT", 1, None, 0), ("database_id", "TEXT", 1, None, 0),
        ("sequence", "INTEGER", 1, None, 0), ("action", "TEXT", 1, None, 0),
        ("artifact_id", "TEXT", 1, None, 0), ("prior_head", "TEXT", 1, "''", 0),
        ("next_head", "TEXT", 1, None, 0), ("prior_state", "TEXT", 1, None, 0),
        ("next_state", "TEXT", 1, None, 0), ("observed_at", "INTEGER", 1, None, 0),
        ("reason", "TEXT", 1, "''", 0), ("operation_id", "TEXT", 1, None, 0),
        ("before_root", "TEXT", 1, None, 0), ("after_root", "TEXT", 1, None, 0),
        ("transition_raw", "BLOB", 1, None, 0),
    ),
    "quarantine_heads": (
        ("policy_digest", "TEXT", 0, None, 1), ("head_artifact_id", "TEXT", 1, None, 0),
        ("state", "TEXT", 1, None, 0), ("sequence", "INTEGER", 1, None, 0),
        ("head_root", "TEXT", 1, None, 0), ("head_transition_id", "TEXT", 1, None, 0),
        ("observed_at", "INTEGER", 1, None, 0), ("capture_id", "TEXT", 1, None, 0),
    ),
}
EXPLICIT_INDEXES = {
    "quarantine_artifacts_capture_idx": ("quarantine_artifacts", ("policy_digest", "capture_id")),
    "quarantine_operations_request_idx": ("quarantine_operations", ("policy_digest", "action", "request_digest")),
    "quarantine_transitions_sequence_idx": ("quarantine_transitions", ("sequence",)),
}


def _check_sqlite_shape(connection: sqlite3.Connection, *, allow_immutable: bool = False) -> None:
    for pragma, expected in (("foreign_keys", 1), ("trusted_schema", 0), ("synchronous", 2), ("busy_timeout", BUSY_TIMEOUT_MS)):
        row = connection.execute(f"PRAGMA {pragma}").fetchone()
        if row is None or int(row[0]) != expected:
            raise IndependentQuarantineError(f"quarantine:pragma-{pragma}")
    journal = connection.execute("PRAGMA journal_mode").fetchone()
    expected_journal = "delete" if allow_immutable else "wal"
    if journal is None or str(journal[0]).lower() != expected_journal:
        raise IndependentQuarantineError("quarantine:journal-mode")
    tables = {str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
    if tables != set(TABLE_COLUMNS):
        raise IndependentQuarantineError("quarantine:tables")
    extras = list(connection.execute("SELECT type,name FROM sqlite_master WHERE type IN ('view','trigger')"))
    if extras:
        raise IndependentQuarantineError("quarantine:unknown-object")
    for table, expected in TABLE_INFO.items():
        actual = tuple(
            (str(row[1]), str(row[2]), int(row[3]), row[4], int(row[5]))
            for row in connection.execute(f"PRAGMA table_info({table})")
        )
        if actual != expected:
            raise IndependentQuarantineError(f"quarantine:table-info:{table}")
    seen: set[str] = set()
    for table in TABLE_COLUMNS:
        for row in connection.execute(f"PRAGMA index_list({table})"):
            name, unique, origin, partial = str(row[1]), int(row[2]), str(row[3]), int(row[4])
            columns = tuple(str(info[2]) for info in sorted(connection.execute(f'PRAGMA index_info("{name.replace(chr(34), chr(34) * 2)}")'), key=lambda item: int(item[0])))
            if origin == "c":
                expected = EXPLICIT_INDEXES.get(name)
                if expected is None or expected[0] != table or unique != 0 or partial != 0 or columns != expected[1]:
                    raise IndependentQuarantineError(f"quarantine:index:{name}")
                seen.add(name)
            elif origin not in {"pk", "u"}:
                raise IndependentQuarantineError(f"quarantine:index-origin:{table}")
    if seen != set(EXPLICIT_INDEXES):
        raise IndependentQuarantineError("quarantine:index-set")
    for table, expected in FOREIGN_KEY_MANIFEST.items():
        grouped: dict[int, list[tuple[int, str, str]]] = {}
        metadata: dict[int, tuple[str, str, str, str]] = {}
        for row in connection.execute(f"PRAGMA foreign_key_list({table})"):
            if len(row) < 8:
                raise IndependentQuarantineError(f"quarantine:foreign-key-shape:{table}")
            grouped.setdefault(int(row[0]), []).append((int(row[1]), str(row[3]), str(row[4])))
            metadata[int(row[0])] = (str(row[2]), str(row[5]), str(row[6]), str(row[7]))
        actual = tuple(sorted(
            (
                metadata[fk_id][0],
                tuple((source, target) for _, source, target in sorted(parts, key=lambda item: item[0])),
                metadata[fk_id][1], metadata[fk_id][2], metadata[fk_id][3],
            )
            for fk_id, parts in grouped.items()
        ))
        if actual != tuple(sorted(expected)):
            raise IndependentQuarantineError(f"quarantine:foreign-key-definition:{table}")
    if list(connection.execute("PRAGMA foreign_key_check")):
        raise IndependentQuarantineError("quarantine:foreign-key")


def snapshot_database(
    path: str | Path,
    *,
    policy: Mapping[str, object] | object,
    database_id: str,
) -> dict[str, object]:
    try:
        image = sqlite_snapshot.read_only_image(
            path, max_database_bytes=MAX_DATABASE_BYTES, max_sidecar_bytes=MAX_WAL_BYTES,
        )
    except sqlite_snapshot.SQLiteSnapshotError as exc:
        code = "journal-mode" if str(exc) == "journal-mode" else "database"
        raise IndependentQuarantineError(f"quarantine:{code}") from exc
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(image.uri, uri=True, timeout=BUSY_TIMEOUT_MS / 1000.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
        connection.execute("BEGIN")
        _check_sqlite_shape(connection, allow_immutable=image.immutable)
        snapshot = _snapshot_from_connection(connection)
        result = _verify_rows(snapshot, policy=policy, database_id=database_id)
        connection.commit()
        return {**result, "snapshot": snapshot}
    except IndependentQuarantineError:
        raise
    except (sqlite3.DatabaseError, OSError, ValueError) as exc:
        raise IndependentQuarantineError("quarantine:database-corrupt") from exc
    finally:
        if connection is not None:
            connection.close()


def verify_database(
    path: str | Path,
    *,
    policy: Mapping[str, object] | object,
    database_id: str,
) -> dict[str, object]:
    result = snapshot_database(path, policy=policy, database_id=database_id)
    return {key: value for key, value in result.items() if key != "snapshot"}


def _decode_export_rows(value: Mapping[str, object]) -> dict[str, list[dict[str, object]]]:
    mapping = {
        "meta": "quarantine_meta", "artifacts": "quarantine_artifacts", "operations": "quarantine_operations",
        "transitions": "quarantine_transitions", "heads": "quarantine_heads",
    }
    result: dict[str, list[dict[str, object]]] = {}
    caps = {
        "quarantine_meta": len(META_KEYS), "quarantine_artifacts": MAX_ARTIFACTS,
        "quarantine_operations": MAX_OPERATIONS, "quarantine_transitions": MAX_TRANSITIONS,
        "quarantine_heads": 1,
    }
    for export_name, table in mapping.items():
        rows = value[export_name]
        if not isinstance(rows, list) or len(rows) > caps[table]:
            raise IndependentQuarantineError(f"quarantine:export-count:{table}")
        expected_keys = EXPORT_ROW_KEYS[table]
        decoded: list[dict[str, object]] = []
        for item in rows:
            if not isinstance(item, dict) or set(item) != expected_keys:
                raise IndependentQuarantineError(f"quarantine:export-keys:{table}")
            row = dict(item)
            if table == "quarantine_artifacts":
                row["artifact_raw"] = _hex_bytes(row.pop("artifact_hex"), "artifact", maximum=adapter.MAX_ARTIFACT_BYTES)
            elif table == "quarantine_operations":
                row["receipt_raw"] = _hex_bytes(row.pop("receipt_hex"), "receipt", maximum=MAX_EXPORT_BYTES)
            elif table == "quarantine_transitions":
                row["transition_raw"] = _hex_bytes(row.pop("transition_hex"), "transition", maximum=MAX_EXPORT_BYTES)
            decoded.append(row)
        result[table] = decoded
    return result


def verify_export_bytes(
    raw: bytes,
    *,
    policy: Mapping[str, object] | object,
    database_id: str,
) -> dict[str, object]:
    value = _parse(raw, maximum=MAX_EXPORT_BYTES, max_string_bytes=MAX_EXPORT_BYTES)
    if set(value) != EXPORT_KEYS:
        raise IndependentQuarantineError("quarantine:export-keys")
    if value["schema"] != EXPORT_SCHEMA or value["schema_version"] != EXPORT_VERSION:
        raise IndependentQuarantineError("quarantine:export-schema")
    if value["synthetic_only"] is not True or value["support_safe"] is not False:
        raise IndependentQuarantineError("quarantine:export-flags")
    for key, expected in FIXED_FLAGS.items():
        if value[key] != expected:
            raise IndependentQuarantineError("quarantine:export-flags")
    configured = _policy_view(policy)
    database = _database_id(database_id)
    policy_digest = _policy_digest(configured)
    if value["policy_digest"] != policy_digest:
        raise IndependentQuarantineError("quarantine:export-policy")
    if value["database_id"] != database or value["chain_id"] != _chain_id(configured, database):
        raise IndependentQuarantineError("quarantine:export-chain")
    snapshot = _decode_export_rows(value)
    result = _verify_rows(snapshot, policy=configured, database_id=database)
    if result["policy_digest"] != value["policy_digest"] or result["database_id"] != value["database_id"] or result["chain_id"] != value["chain_id"]:
        raise IndependentQuarantineError("quarantine:export-state-binding")
    body = dict(value)
    body.pop("export_root")
    if value["export_root"] != _digest("export-root", body):
        raise IndependentQuarantineError("quarantine:export-root")
    return {**result, "export_root": value["export_root"], "snapshot": snapshot}


def verify_snapshot(
    snapshot: Mapping[str, object],
    *,
    policy: Mapping[str, object] | object,
    database_id: str,
) -> dict[str, object]:
    return _verify_rows(snapshot, policy=policy, database_id=database_id)


__all__ = [
    "SCHEMA", "SCHEMA_VERSION", "EXPORT_SCHEMA", "EXPORT_VERSION", "QUARANTINE_STATUS",
    "HEAD_STATES", "ACTION_ADMIT", "ACTION_SUPERSEDE", "ACTION_WITHDRAW", "ACTIONS",
    "WITHDRAW_REASONS", "GENESIS_TRANSITION", "MAX_ARTIFACTS", "MAX_TRANSITIONS", "MAX_OPERATIONS",
    "MAX_EXPORT_BYTES", "MAX_DATABASE_BYTES", "MAX_WAL_BYTES", "BUSY_TIMEOUT_MS", "TABLE_COLUMNS",
    "SNAPSHOT_TABLES", "TABLE_INFO", "EXPLICIT_INDEXES", "FOREIGN_KEY_MANIFEST", "FIXED_FLAGS", "IndependentQuarantineError",
    "VerifiedAdmissionReceiptV1", "verify_receipt_bytes", "verify_admission_receipt", "snapshot_database", "verify_database", "verify_export_bytes", "verify_snapshot", "_canonical", "_digest", "_raw_digest",
    "_policy_view", "_policy_digest", "_chain_id", "_genesis_root", "_state_root", "_after_root",
    "_operation_id", "_request_material_digest", "_transition_id", "_receipt_id", "_parse", "_database_id",
]
