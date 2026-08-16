"""Independent read-only conformance checks for the Mirror continuity store.

This module intentionally does not import the producer store or either producer.
It repeats the bounded wire, identity, SQLite schema, event-chain, receipt, head,
and state-root rules and composes only with the independently verified graph,
control-pack, and terminal-withdrawal artifact verifiers.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sqlite3
import sys
from typing import Any, Mapping

from app.governance import provider_continuity_control_pack_independent as governance_independent
from app.governance import provider_continuity_control_pack_withdrawal_independent as withdrawal_independent
from app.mirror import provider_trust_graph_independent as graph_independent


STORE_SCHEMA = "mirror-continuity-operational-foundation-v2"
SCHEMA_VERSION = 2
ARTIFACT_GRAPH = "PROVIDER_TRUST_GRAPH_V1"
ARTIFACT_GOVERNANCE = "PROVIDER_CONTINUITY_CONTROL_PACK_V1"
ARTIFACT_KINDS = (ARTIFACT_GRAPH, ARTIFACT_GOVERNANCE)
GENESIS_EVENT_ROOT = "GENESIS_EVENT_ROOT_V2"
NO_PRIOR = "NO_PRIOR_V2"
RECEIPT_EVENT_PLACEHOLDER = "EVENT_ROOT_PENDING_V2"
MAX_ARTIFACT_BYTES = 524_288
MAX_ARTIFACTS = 16
MAX_EVENTS = 32
MAX_RECEIPT_BYTES = 32_768
MAX_DB_BYTES = 64 * 1024 * 1024
MAX_WAL_BYTES = 64 * 1024 * 1024
BUSY_TIMEOUT_MS = 250
STORE_DOMAIN = "BL/MIRROR/CONTINUITY-STORE-V2/"
AUTHORITY_FLAGS = {
    "automaticControlSetId": None,
    "automatic_enforcement_eligible": False,
    "clearance_authority": False,
    "payment_authority": False,
    "economic_mutation": False,
    "production_usable": False,
    "synthetic_only": True,
    "production_source_authentication": False,
    "proofSuiteId": None,
}

TABLE_COLUMNS = {
    "store_meta": ("key", "value"),
    "artifacts": (
        "kind", "artifact_id", "payload_hash", "payload", "artifact_schema", "report_id",
        "current_stage_id", "transition_id", "prior_artifact_id", "prior_stage_id", "subject",
        "scope", "stage_kind", "authority_json",
    ),
    "operations": (
        "operation_id", "chain_id", "artifact_kind", "artifact_id", "payload_hash", "request_hash",
        "prior_artifact_id", "prior_stage_id", "expected_head_artifact_id", "expected_head_stage_id",
        "event_sequence", "receipt_hash", "commit_state_root",
    ),
    "receipts": ("operation_id", "receipt_hash", "receipt"),
    "events": (
        "sequence", "chain_id", "previous_event_root", "event_root", "operation_id", "artifact_kind",
        "artifact_id", "payload_hash", "prior_artifact_id", "prior_stage_id", "receipt_hash",
        "commit_state_root",
    ),
    "heads": (
        "chain_id", "artifact_kind", "artifact_id", "current_stage_id", "stage_kind", "transition_id",
        "event_sequence", "head_root", "state_root",
    ),
}
TABLES = tuple(TABLE_COLUMNS)
SNAPSHOT_TABLES = ("meta", "artifacts", "operations", "receipts", "events", "heads")
EXPLICIT_INDEXES = {
    "artifacts_payload_hash_idx",
    "operations_request_idx",
    "events_chain_idx",
}
_HEX128 = re.compile(r"^[0-9a-f]{128}$")

# Complete SQLite schema manifest.  The independent verifier pins column
# affinity/nullability/primary-key positions, every explicit index definition,
# every implicit PK/UNIQUE index signature, and every foreign-key relation.
TABLE_INFO = {
    "store_meta": (
        ("key", "TEXT", 1, None, 1),
        ("value", "TEXT", 1, None, 0),
    ),
    "artifacts": (
        ("kind", "TEXT", 1, None, 1),
        ("artifact_id", "TEXT", 1, None, 2),
        ("payload_hash", "TEXT", 1, None, 0),
        ("payload", "BLOB", 1, None, 0),
        ("artifact_schema", "TEXT", 1, None, 0),
        ("report_id", "TEXT", 0, None, 0),
        ("current_stage_id", "TEXT", 1, None, 0),
        ("transition_id", "TEXT", 1, None, 0),
        ("prior_artifact_id", "TEXT", 0, None, 0),
        ("prior_stage_id", "TEXT", 0, None, 0),
        ("subject", "TEXT", 1, None, 0),
        ("scope", "TEXT", 1, None, 0),
        ("stage_kind", "TEXT", 1, None, 0),
        ("authority_json", "TEXT", 1, None, 0),
    ),
    "operations": (
        ("operation_id", "TEXT", 1, None, 1),
        ("chain_id", "TEXT", 1, None, 0),
        ("artifact_kind", "TEXT", 1, None, 0),
        ("artifact_id", "TEXT", 1, None, 0),
        ("payload_hash", "TEXT", 1, None, 0),
        ("request_hash", "TEXT", 1, None, 0),
        ("prior_artifact_id", "TEXT", 0, None, 0),
        ("prior_stage_id", "TEXT", 0, None, 0),
        ("expected_head_artifact_id", "TEXT", 1, None, 0),
        ("expected_head_stage_id", "TEXT", 1, None, 0),
        ("event_sequence", "INTEGER", 1, None, 0),
        ("receipt_hash", "TEXT", 1, None, 0),
        ("commit_state_root", "TEXT", 1, None, 0),
    ),
    "receipts": (
        ("operation_id", "TEXT", 1, None, 1),
        ("receipt_hash", "TEXT", 1, None, 0),
        ("receipt", "BLOB", 1, None, 0),
    ),
    "events": (
        ("sequence", "INTEGER", 1, None, 1),
        ("chain_id", "TEXT", 1, None, 0),
        ("previous_event_root", "TEXT", 1, None, 0),
        ("event_root", "TEXT", 1, None, 0),
        ("operation_id", "TEXT", 1, None, 0),
        ("artifact_kind", "TEXT", 1, None, 0),
        ("artifact_id", "TEXT", 1, None, 0),
        ("payload_hash", "TEXT", 1, None, 0),
        ("prior_artifact_id", "TEXT", 0, None, 0),
        ("prior_stage_id", "TEXT", 0, None, 0),
        ("receipt_hash", "TEXT", 1, None, 0),
        ("commit_state_root", "TEXT", 1, None, 0),
    ),
    "heads": (
        ("chain_id", "TEXT", 1, None, 1),
        ("artifact_kind", "TEXT", 1, None, 0),
        ("artifact_id", "TEXT", 1, None, 0),
        ("current_stage_id", "TEXT", 1, None, 0),
        ("stage_kind", "TEXT", 1, None, 0),
        ("transition_id", "TEXT", 1, None, 0),
        ("event_sequence", "INTEGER", 1, None, 0),
        ("head_root", "TEXT", 1, None, 0),
        ("state_root", "TEXT", 1, None, 0),
    ),
}
EXPLICIT_INDEX_MANIFEST = {
    "artifacts_payload_hash_idx": ("artifacts", 0, 0, ("kind", "payload_hash")),
    "operations_request_idx": ("operations", 0, 0, ("chain_id", "artifact_kind", "artifact_id", "payload_hash", "prior_artifact_id", "prior_stage_id")),
    "events_chain_idx": ("events", 0, 0, ("chain_id", "sequence")),
}
AUTO_INDEX_MANIFEST = {
    "store_meta": {("pk", 1, 0, ("key",))},
    "artifacts": {
        ("pk", 1, 0, ("kind", "artifact_id")),
        ("u", 1, 0, ("kind", "payload_hash")),
    },
    "operations": {
        ("pk", 1, 0, ("operation_id",)),
        ("u", 1, 0, ("event_sequence",)),
        ("u", 1, 0, ("receipt_hash",)),
    },
    "receipts": {
        ("pk", 1, 0, ("operation_id",)),
        ("u", 1, 0, ("receipt_hash",)),
    },
    "events": {
        ("u", 1, 0, ("event_root",)),
        ("u", 1, 0, ("operation_id",)),
    },
    "heads": {("pk", 1, 0, ("chain_id",))},
}
FOREIGN_KEY_MANIFEST = {
    "store_meta": (),
    "artifacts": (),
    "operations": (
        ("artifacts", (("artifact_kind", "kind"), ("artifact_id", "artifact_id")), "NO ACTION", "NO ACTION", "NONE"),
    ),
    "receipts": (),
    "events": (
        ("receipts", (("receipt_hash", "receipt_hash"),), "NO ACTION", "NO ACTION", "NONE"),
        ("artifacts", (("artifact_kind", "kind"), ("artifact_id", "artifact_id")), "NO ACTION", "NO ACTION", "NONE"),
        ("operations", (("operation_id", "operation_id"),), "NO ACTION", "NO ACTION", "NONE"),
    ),
    "heads": (
        ("artifacts", (("artifact_kind", "kind"), ("artifact_id", "artifact_id")), "NO ACTION", "NO ACTION", "NONE"),
    ),
}


class IndependentStoreError(ValueError):
    """A bounded, stable rejection from the independent store verifier."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise IndependentStoreError("json:noncanonical-value") from exc


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise IndependentStoreError("json:duplicate-key")
        result[key] = value
    return result


def _walk(value: object, *, depth: int = 0, count: list[int] | None = None, max_string_bytes: int = 512) -> None:
    count = [0] if count is None else count
    count[0] += 1
    if count[0] > 16_384:
        raise IndependentStoreError("json:node-cap")
    if depth > 24:
        raise IndependentStoreError("json:depth-cap")
    if isinstance(value, float):
        raise IndependentStoreError("json:float-forbidden")
    if isinstance(value, str):
        try:
            if len(value.encode("ascii")) > max_string_bytes:
                raise IndependentStoreError("json:string-cap")
        except UnicodeEncodeError as exc:
            raise IndependentStoreError("json:ascii") from exc
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise IndependentStoreError("json:key-type")
            _walk(key, depth=depth + 1, count=count, max_string_bytes=max_string_bytes)
            _walk(item, depth=depth + 1, count=count, max_string_bytes=max_string_bytes)
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth=depth + 1, count=count, max_string_bytes=max_string_bytes)


def _parse_canonical(raw: bytes, *, maximum: int = MAX_ARTIFACT_BYTES, max_string_bytes: int = 512) -> dict[str, object]:
    if type(raw) is not bytes or not raw:
        raise IndependentStoreError("json:empty-or-type")
    if len(raw) > maximum:
        raise IndependentStoreError("json:byte-cap")
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(IndependentStoreError("json:constant-forbidden")),
        )
    except IndependentStoreError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IndependentStoreError("json:parse") from exc
    if not isinstance(value, dict):
        raise IndependentStoreError("json:top-level")
    _walk(value, max_string_bytes=max_string_bytes)
    if _canonical(value) != raw:
        raise IndependentStoreError("json:not-canonical")
    return value


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update((STORE_DOMAIN + label + "/v2\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _payload_hash(raw: bytes) -> str:
    digest = hashlib.sha3_512()
    digest.update((STORE_DOMAIN + "CANONICAL-PAYLOAD/v2\0").encode("ascii"))
    digest.update(raw)
    return digest.hexdigest()


def _chain_id(artifact_kind: str, subject: str, scope: str, profile_id: str | None = None) -> str:
    if not all(type(value) is str and value for value in (artifact_kind, subject, scope)):
        raise IndependentStoreError("chain:identity")
    if profile_id is not None and (type(profile_id) is not str or not profile_id):
        raise IndependentStoreError("chain:profile")
    material: dict[str, object] = {"artifact_kind": artifact_kind, "scope": scope, "subject": subject}
    if profile_id is not None:
        material["profile_id"] = profile_id
    return _digest(
        "chain-id",
        material,
    )


def _receipt_hash(raw: bytes) -> str:
    value = _parse_canonical(raw, maximum=MAX_RECEIPT_BYTES)
    if "event_root" not in value:
        raise IndependentStoreError("receipt:event-root")
    identity = dict(value)
    identity.pop("event_root")
    return _digest("receipt-hash", identity)


def _event_root(material: Mapping[str, object]) -> str:
    return _digest("event-root", dict(material))


def _state_root(sequence: int, heads: list[Mapping[str, object]]) -> str:
    fields = (
        "chain_id", "artifact_kind", "artifact_id", "current_stage_id", "stage_kind",
        "transition_id", "event_sequence", "head_root",
    )
    ordered = sorted(
        ({key: item[key] for key in fields} for item in heads),
        key=lambda item: str(item["chain_id"]),
    )
    return _digest("state-root", {"event_sequence": sequence, "heads": ordered})


def _expect_keys(value: object, expected: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise IndependentStoreError(f"{label}:keys")
    return value


def _governance_prefix(value: Mapping[str, object], stage_count: int) -> tuple[bytes, dict[str, object]]:
    stages = value.get("stages")
    if not isinstance(stages, list) or stage_count not in (1, 2) or len(stages) < stage_count:
        raise IndependentStoreError("artifact:governance-prior-prefix")
    prefix_stages = list(stages[:stage_count])
    current = prefix_stages[-1]
    if not isinstance(current, dict):
        raise IndependentStoreError("artifact:governance-prior-prefix")
    body: dict[str, object] = {
        "schema": value["schema"],
        "subject": value["subject"],
        "source_contracts": value["source_contracts"],
        "stages": prefix_stages,
        "current_stage_kind": current["stage_kind"],
        "current_stage_id": current["stage_id"],
        "chain_root": governance_independent._digest("chain-root", {"stages": prefix_stages}),
        **{key: value[key] for key in governance_independent.AUTHORITY_FLAGS},
    }
    artifact = {"artifact_id": governance_independent._digest("artifact-id", body), **body}
    return governance_independent._canonical(artifact), artifact


def _authority_json(value: Mapping[str, object], kind: str) -> str:
    if kind == ARTIFACT_GRAPH:
        expected = {
            "clearance_authority": False,
            "payment_authority": False,
            "economic_mutation": False,
            "production_usable": False,
            "synthetic_only": True,
        }
        if dict(value) != expected:
            raise IndependentStoreError("artifact:authority-flags")
    elif dict(value) != governance_independent.AUTHORITY_FLAGS:
        raise IndependentStoreError("artifact:authority-flags")
    return _canonical(AUTHORITY_FLAGS).decode("ascii")


def _normalize_artifact(
    kind: str,
    raw: bytes,
    *,
    graph_profile_registry: Mapping[str, object] | None = None,
) -> dict[str, object]:
    if kind not in ARTIFACT_KINDS:
        raise IndependentStoreError("artifact:kind")
    if type(raw) is not bytes or not raw or len(raw) > MAX_ARTIFACT_BYTES:
        raise IndependentStoreError("artifact:byte-cap")
    value = _parse_canonical(raw)
    try:
        if kind == ARTIFACT_GRAPH:
            if value.get("schema") == graph_independent.SCHEMA_V2:
                result = graph_independent.verify_bytes_v2(raw, graph_profile_registry or {})
            else:
                result = graph_independent.verify_bytes(raw)
        elif value.get("schema") == withdrawal_independent.SCHEMA:
            result = withdrawal_independent.verify_bytes(raw)
        else:
            result = governance_independent.verify_bytes(raw)
    except Exception as exc:
        raise IndependentStoreError(f"artifact:independent-reject:{type(exc).__name__}") from exc
    try:
        if kind == ARTIFACT_GRAPH:
            subject = _expect_keys(value["subject"], {"provider_graph_subject", "scope"}, "artifact:graph-subject")
            snapshot = value["observation_snapshot"]
            transition = value["transition"]
            report = value["report"]
            identity = report["identity_material"] if isinstance(report, dict) else None
            if not isinstance(snapshot, dict) or not isinstance(transition, dict) or not isinstance(report, dict) or not isinstance(identity, dict):
                raise IndependentStoreError("artifact:graph-shape")
            artifact_id = report["report_id"]
            report_id = artifact_id
            current_stage_id = snapshot["snapshot_id"]
            transition_id = transition["transition_id"]
            stage_kind = transition["transition_kind"]
            prior_artifact_id = identity["prior_report_id"]
            prior_stage_id = identity["prior_snapshot_id"]
            authority_json = _authority_json(value["authority"], kind)
            subject_id = subject["provider_graph_subject"]
            scope = subject["scope"]
            schema = value["schema"]
            profile_id = None
            if schema == graph_independent.SCHEMA_V2:
                profile_value = graph_independent._expect_keys(value.get("profile"), graph_independent.PROFILE_KEYS, "artifact:profile")
                profile_id = profile_value["profile_id"]
        elif value.get("schema") == withdrawal_independent.SCHEMA:
            result_artifact_id = result.get("artifact_id")
            if not isinstance(result_artifact_id, str):
                raise IndependentStoreError("artifact:withdrawal-id")
            artifact_id = result_artifact_id
            report_id = None
            current_stage_id = value["withdrawal_id"]
            transition_id = value["withdrawal_root"]
            stage_kind = value["action"]
            prior_artifact_id = value["approved_artifact_id"]
            prior_stage_id = value["approved_stage_id"]
            authority_json = _authority_json(
                {key: value[key] for key in withdrawal_independent.AUTHORITY_FLAGS}, kind
            )
            subject_id = value["provider_graph_subject"]
            scope = value["scope"]
            schema = value["schema"]
        else:
            result_artifact_id = result.get("artifact_id")
            if not isinstance(result_artifact_id, str):
                raise IndependentStoreError("artifact:governance-id")
            subject = _expect_keys(value["subject"], {"provider_graph_subject", "scope"}, "artifact:governance-subject")
            stages = value["stages"]
            if not isinstance(stages, list) or not stages or len(stages) > governance_independent.MAX_STAGES:
                raise IndependentStoreError("artifact:governance-stages")
            current = stages[-1]
            if not isinstance(current, dict):
                raise IndependentStoreError("artifact:governance-stage")
            artifact_id = result_artifact_id
            report_id = None
            current_stage_id = current["stage_id"]
            transition_id = value["chain_root"]
            stage_kind = current["stage_kind"]
            prior_artifact_id = None
            prior_stage_id = None
            if len(stages) > 1:
                prefix_raw, prefix = _governance_prefix(value, len(stages) - 1)
                try:
                    governance_independent.verify_bytes(prefix_raw)
                except Exception as exc:
                    raise IndependentStoreError("artifact:governance-prior-prefix") from exc
                prior_artifact_id = prefix["artifact_id"]
                previous = stages[-2]
                if not isinstance(previous, dict):
                    raise IndependentStoreError("artifact:governance-prior-stage")
                prior_stage_id = previous["stage_id"]
            authority_json = _authority_json({key: value[key] for key in governance_independent.AUTHORITY_FLAGS}, kind)
            subject_id = subject["provider_graph_subject"]
            scope = subject["scope"]
            schema = value["schema"]
        if not all(isinstance(item, str) and item for item in (schema, artifact_id, subject_id, scope, current_stage_id, transition_id, stage_kind)):
            raise IndependentStoreError("artifact:identity-empty")
        if prior_artifact_id is not None and (not isinstance(prior_artifact_id, str) or not prior_artifact_id):
            raise IndependentStoreError("artifact:prior-artifact")
        if prior_stage_id is not None and (not isinstance(prior_stage_id, str) or not prior_stage_id):
            raise IndependentStoreError("artifact:prior-stage")
    except (KeyError, TypeError, ValueError) as exc:
        raise IndependentStoreError("artifact:identity-shape") from exc
    return {
        "kind": kind,
        "schema": schema,
        "artifact_id": artifact_id,
        "payload_hash": _payload_hash(raw),
        "payload": raw,
        "subject": subject_id,
        "scope": scope,
        "report_id": report_id,
        "current_stage_id": current_stage_id,
        "transition_id": transition_id,
        "stage_kind": stage_kind,
        "prior_artifact_id": prior_artifact_id,
        "prior_stage_id": prior_stage_id,
        "authority_json": authority_json,
        "profile_id": profile_id if kind == ARTIFACT_GRAPH else None,
    }


def _operation_id(artifact: Mapping[str, object], chain_id: str, expected_head: tuple[str, str]) -> str:
    return _digest(
        "operation-id",
        {
            "chain_id": chain_id,
            "artifact_kind": artifact["kind"],
            "artifact_id": artifact["artifact_id"],
            "payload_hash": artifact["payload_hash"],
            "prior_artifact_id": artifact["prior_artifact_id"] or NO_PRIOR,
            "prior_stage_id": artifact["prior_stage_id"] or NO_PRIOR,
            "expected_head_artifact_id": expected_head[0],
            "expected_head_stage_id": expected_head[1],
        },
    )


def _head_root(chain_id: str, artifact: Mapping[str, object], sequence: int) -> str:
    return _digest(
        "head-root",
        {
            "chain_id": chain_id,
            "artifact_kind": artifact["kind"],
            "artifact_id": artifact["artifact_id"],
            "current_stage_id": artifact["current_stage_id"],
            "stage_kind": artifact["stage_kind"],
            "transition_id": artifact["transition_id"],
            "event_sequence": sequence,
        },
    )


def _expected_receipt(artifact: Mapping[str, object], *, operation_id: str, sequence: int, previous_event_root: str,
                      event_root: str, chain_id: str, expected_head: tuple[str, str], head_root: str,
                      state_root: str) -> dict[str, object]:
    return {
        "schema": "mirror-continuity-receipt-v2",
        "operation_id": operation_id,
        "event_sequence": sequence,
        "previous_event_root": previous_event_root,
        "event_root": event_root,
        "chain_id": chain_id,
        "artifact_kind": artifact["kind"],
        "artifact_id": artifact["artifact_id"],
        "payload_hash": artifact["payload_hash"],
        "prior_artifact_id": artifact["prior_artifact_id"] or NO_PRIOR,
        "prior_stage_id": artifact["prior_stage_id"] or NO_PRIOR,
        "expected_head_artifact_id": expected_head[0],
        "expected_head_stage_id": expected_head[1],
        "resulting_head_artifact_id": artifact["artifact_id"],
        "resulting_head_stage_id": artifact["current_stage_id"],
        "resulting_head_root": head_root,
        "state_root": state_root,
        "authority": dict(AUTHORITY_FLAGS),
    }


def _row_bytes(row: Mapping[str, object], key: str) -> bytes:
    value = row.get(key)
    if type(value) is not bytes:
        raise IndependentStoreError(f"database:{key}-bytes")
    return value


def _require_row_keys(rows: list[Mapping[str, object]], table: str) -> None:
    schema_table = "store_meta" if table == "meta" else table
    expected = set(TABLE_COLUMNS[schema_table])
    for row in rows:
        if set(row) != expected:
            raise IndependentStoreError(f"database:{table}-columns")


def _verify_rows(
    snapshot: Mapping[str, object],
    *,
    graph_profile_registry: Mapping[str, object] | None = None,
) -> dict[str, object]:
    if set(snapshot) != set(SNAPSHOT_TABLES):
        raise IndependentStoreError("database:snapshot-tables")
    rows = {table: snapshot[table] for table in SNAPSHOT_TABLES}
    if any(not isinstance(rows[table], list) for table in SNAPSHOT_TABLES):
        raise IndependentStoreError("database:snapshot-shape")
    for table in SNAPSHOT_TABLES:
        _require_row_keys(rows[table], table)
    if len(rows["artifacts"]) > MAX_ARTIFACTS or len(rows["events"]) > MAX_EVENTS:
        raise IndependentStoreError("database:count-cap")
    if len(rows["operations"]) != len(rows["events"]) or len(rows["receipts"]) != len(rows["events"]):
        raise IndependentStoreError("database:chain-counts")
    if len(rows["meta"]) != 2:
        raise IndependentStoreError("database:meta-count")
    meta = {row["key"]: row["value"] for row in rows["meta"]}
    if set(meta) != {"schema", "schema_version"} or meta["schema"] != STORE_SCHEMA or meta["schema_version"] != str(SCHEMA_VERSION):
        raise IndependentStoreError("database:schema-version")

    artifacts: dict[tuple[str, str], dict[str, object]] = {}
    artifact_hashes: set[tuple[str, str]] = set()
    for row in rows["artifacts"]:
        kind = row["kind"]
        artifact_id = row["artifact_id"]
        if kind not in ARTIFACT_KINDS or not isinstance(artifact_id, str):
            raise IndependentStoreError("database:artifact-identity")
        key = (kind, artifact_id)
        if key in artifacts:
            raise IndependentStoreError("database:artifact-duplicate")
        raw = _row_bytes(row, "payload")
        artifact = _normalize_artifact(kind, raw, graph_profile_registry=graph_profile_registry)
        for field in ("artifact_id", "payload_hash", "artifact_schema", "report_id", "current_stage_id", "transition_id", "prior_artifact_id", "prior_stage_id", "subject", "scope", "stage_kind", "authority_json"):
            stored = row[field]
            expected = artifact[field] if field != "artifact_schema" else artifact["schema"]
            if stored != expected:
                raise IndependentStoreError(f"database:artifact-{field}")
        hash_key = (kind, str(row["payload_hash"]))
        if hash_key in artifact_hashes:
            raise IndependentStoreError("database:artifact-hash-duplicate")
        artifact_hashes.add(hash_key)
        artifacts[key] = artifact

    operations = {row["operation_id"]: row for row in rows["operations"]}
    receipts = {row["operation_id"]: row for row in rows["receipts"]}
    events = {row["sequence"]: row for row in rows["events"]}
    heads = {row["chain_id"]: row for row in rows["heads"]}
    if len(operations) != len(rows["operations"]) or len(receipts) != len(rows["receipts"]):
        raise IndependentStoreError("database:operation-duplicate")
    if len(events) != len(rows["events"]) or len(heads) != len(rows["heads"]):
        raise IndependentStoreError("database:event-or-head-duplicate")
    for row in rows["operations"]:
        if not isinstance(row["chain_id"], str) or not _HEX128.fullmatch(row["chain_id"]):
            raise IndependentStoreError("database:chain-id")
        if row["artifact_kind"] not in ARTIFACT_KINDS:
            raise IndependentStoreError("database:operation-kind")
    for row in rows["heads"]:
        if not isinstance(row["chain_id"], str) or not _HEX128.fullmatch(row["chain_id"]):
            raise IndependentStoreError("database:chain-id")
    if set(artifacts) != {(row["artifact_kind"], row["artifact_id"]) for row in rows["events"]}:
        raise IndependentStoreError("database:orphan-artifact")

    state_heads: dict[str, dict[str, object]] = {}
    previous_event_root = GENESIS_EVENT_ROOT
    final_state_root = _state_root(0, [])
    seen_operations: set[str] = set()
    for sequence in range(1, len(rows["events"]) + 1):
        event = events.get(sequence)
        if event is None:
            raise IndependentStoreError("database:event-sequence")
        if event["previous_event_root"] != previous_event_root:
            raise IndependentStoreError("database:event-previous-root")
        operation_id = event["operation_id"]
        if operation_id in seen_operations:
            raise IndependentStoreError("database:event-replay")
        seen_operations.add(operation_id)
        operation = operations.get(operation_id)
        if operation is None:
            raise IndependentStoreError("database:event-operation")
        artifact = artifacts.get((event["artifact_kind"], event["artifact_id"]))
        if artifact is None:
            raise IndependentStoreError("database:event-artifact")
        if any(event[field] != operation[field] for field in ("chain_id", "artifact_kind", "artifact_id", "payload_hash", "prior_artifact_id", "prior_stage_id", "receipt_hash", "commit_state_root")):
            raise IndependentStoreError("database:event-operation-binding")
        if event["prior_artifact_id"] != artifact["prior_artifact_id"] or event["prior_stage_id"] != artifact["prior_stage_id"]:
            raise IndependentStoreError("database:event-artifact-prior")
        chain_id = _chain_id(artifact["kind"], artifact["subject"], artifact["scope"], artifact.get("profile_id"))
        if event["chain_id"] != chain_id or operation["chain_id"] != chain_id:
            raise IndependentStoreError("database:chain-id-binding")
        prior_artifact_id = artifact["prior_artifact_id"]
        prior_stage_id = artifact["prior_stage_id"]
        old_head = state_heads.get(chain_id)
        if prior_artifact_id is None:
            if old_head is not None:
                raise IndependentStoreError("database:unexpected-existing-head")
            expected_head = (NO_PRIOR, NO_PRIOR)
        else:
            if old_head is None or old_head["artifact_id"] != prior_artifact_id or old_head["current_stage_id"] != prior_stage_id:
                raise IndependentStoreError("database:stale-prior")
            expected_head = (str(old_head["artifact_id"]), str(old_head["current_stage_id"]))
        if operation["event_sequence"] != sequence or operation["expected_head_artifact_id"] != expected_head[0] or operation["expected_head_stage_id"] != expected_head[1]:
            raise IndependentStoreError("database:operation-head")
        if operation["prior_artifact_id"] != prior_artifact_id or operation["prior_stage_id"] != prior_stage_id:
            raise IndependentStoreError("database:operation-prior")
        expected_operation_id = _operation_id(artifact, chain_id, expected_head)
        if operation_id != expected_operation_id or operation["request_hash"] != artifact["payload_hash"]:
            raise IndependentStoreError("database:operation-identity")
        head_root = _head_root(chain_id, artifact, sequence)
        next_head = {
            "chain_id": chain_id,
            "artifact_kind": artifact["kind"],
            "artifact_id": artifact["artifact_id"],
            "current_stage_id": artifact["current_stage_id"],
            "stage_kind": artifact["stage_kind"],
            "transition_id": artifact["transition_id"],
            "event_sequence": sequence,
            "head_root": head_root,
        }
        candidate_heads = [*state_heads.values(), next_head]
        candidate_heads = [item for item in candidate_heads if item["chain_id"] != chain_id or item is next_head]
        final_state_root = _state_root(sequence, candidate_heads)
        if event["commit_state_root"] != final_state_root or operation["commit_state_root"] != final_state_root:
            raise IndependentStoreError("database:state-root")
        receipt_row = receipts.get(operation_id)
        if receipt_row is None:
            raise IndependentStoreError("database:receipt-missing")
        receipt_raw = _row_bytes(receipt_row, "receipt")
        receipt = _parse_canonical(receipt_raw, maximum=MAX_RECEIPT_BYTES)
        expected_receipt = _expected_receipt(
            artifact,
            operation_id=operation_id,
            sequence=sequence,
            previous_event_root=previous_event_root,
            event_root=event["event_root"],
            chain_id=chain_id,
            expected_head=expected_head,
            head_root=head_root,
            state_root=final_state_root,
        )
        if receipt != expected_receipt or receipt_row["receipt_hash"] != event["receipt_hash"] or _receipt_hash(receipt_raw) != receipt_row["receipt_hash"]:
            raise IndependentStoreError("database:receipt-binding")
        expected_event_material = {
            "sequence": sequence,
            "chain_id": chain_id,
            "previous_event_root": previous_event_root,
            "operation_id": operation_id,
            "artifact_kind": artifact["kind"],
            "artifact_id": artifact["artifact_id"],
            "payload_hash": artifact["payload_hash"],
            "prior_artifact_id": prior_artifact_id or NO_PRIOR,
            "prior_stage_id": prior_stage_id or NO_PRIOR,
            "receipt_hash": receipt_row["receipt_hash"],
            "commit_state_root": final_state_root,
        }
        expected_event_root = _event_root(expected_event_material)
        if event["event_root"] != expected_event_root:
            raise IndependentStoreError("database:event-root")
        if receipt["event_root"] != event["event_root"]:
            raise IndependentStoreError("database:receipt-event-root")
        if operation["receipt_hash"] != receipt_row["receipt_hash"]:
            raise IndependentStoreError("database:operation-receipt")
        if receipt_row["operation_id"] != operation_id:
            raise IndependentStoreError("database:receipt-operation")
        state_heads[chain_id] = {**next_head, "state_root": final_state_root}
        previous_event_root = event["event_root"]

    if set(operations) != seen_operations:
        raise IndependentStoreError("database:orphan-operation")
    if set(heads) != set(state_heads):
        raise IndependentStoreError("database:head-set")
    for chain_id, expected in state_heads.items():
        actual = heads[chain_id]
        if actual != expected:
            raise IndependentStoreError("database:head-binding")
    return {
        "accepted": True,
        "schema_version": SCHEMA_VERSION,
        "artifact_count": len(rows["artifacts"]),
        "event_count": len(rows["events"]),
        "receipt_count": len(rows["receipts"]),
        "head_count": len(rows["heads"]),
        "state_root": final_state_root,
    }


def _snapshot_from_connection(connection: sqlite3.Connection) -> dict[str, list[dict[str, object]]]:
    caps = {
        "store_meta": 2,
        "artifacts": MAX_ARTIFACTS,
        "operations": MAX_EVENTS,
        "receipts": MAX_EVENTS,
        "events": MAX_EVENTS,
        "heads": MAX_ARTIFACTS,
    }
    for table, cap in caps.items():
        count = int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
        if count > cap:
            raise IndependentStoreError(f"database:{table}-count-cap")

    def bounded(query: str, table: str) -> list[dict[str, object]]:
        return [dict(row) for row in connection.execute(f"{query} LIMIT {caps[table] + 1}")]

    return {
        "meta": bounded("SELECT key,value FROM store_meta ORDER BY key", "store_meta"),
        "artifacts": bounded("SELECT * FROM artifacts ORDER BY kind,artifact_id", "artifacts"),
        "operations": bounded("SELECT * FROM operations ORDER BY event_sequence", "operations"),
        "receipts": bounded("SELECT * FROM receipts ORDER BY operation_id", "receipts"),
        "events": bounded("SELECT * FROM events ORDER BY sequence", "events"),
        "heads": bounded("SELECT * FROM heads ORDER BY chain_id", "heads"),
    }


def _check_sqlite_shape(connection: sqlite3.Connection) -> None:
    for pragma, expected in (("foreign_keys", 1), ("trusted_schema", 0), ("synchronous", 2), ("busy_timeout", BUSY_TIMEOUT_MS)):
        row = connection.execute(f"PRAGMA {pragma}").fetchone()
        if row is None or int(row[0]) != expected:
            raise IndependentStoreError(f"database:pragma-{pragma}")
    journal = connection.execute("PRAGMA journal_mode").fetchone()
    if journal is None or str(journal[0]).lower() != "wal":
        raise IndependentStoreError("database:journal-mode")
    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
    if tables != set(TABLES):
        raise IndependentStoreError("database:tables")
    views_triggers = list(connection.execute("SELECT type,name FROM sqlite_master WHERE type IN ('view','trigger')"))
    if views_triggers:
        raise IndependentStoreError("database:unknown-object")
    for table, expected in TABLE_INFO.items():
        actual = tuple(
            (str(row[1]), str(row[2]), int(row[3]), row[4], int(row[5]))
            for row in connection.execute(f"PRAGMA table_info({table})")
        )
        if actual != expected:
            raise IndependentStoreError(f"database:table-info-{table}")

    explicit_seen: set[str] = set()
    for table in TABLES:
        auto_seen: set[tuple[str, int, int, tuple[str, ...]]] = set()
        for row in connection.execute(f"PRAGMA index_list({table})"):
            if len(row) < 5:
                raise IndependentStoreError(f"database:index-shape-{table}")
            name = str(row[1])
            unique = int(row[2])
            origin = str(row[3])
            partial = int(row[4])
            quoted_name = name.replace('"', '""')
            columns = tuple(
                str(info[2])
                for info in sorted(
                    connection.execute(f'PRAGMA index_info("{quoted_name}")'),
                    key=lambda info: int(info[0]),
                )
            )
            signature = (origin, unique, partial, columns)
            if origin == "c":
                expected = EXPLICIT_INDEX_MANIFEST.get(name)
                if expected is None or expected[0] != table or signature != ("c", expected[1], expected[2], expected[3]):
                    raise IndependentStoreError(f"database:index-definition-{name}")
                explicit_seen.add(name)
            elif origin in {"pk", "u"}:
                auto_seen.add(signature)
            else:
                raise IndependentStoreError(f"database:index-origin-{table}")
        if auto_seen != AUTO_INDEX_MANIFEST[table]:
            raise IndependentStoreError(f"database:auto-index-definition-{table}")
    if explicit_seen != set(EXPLICIT_INDEX_MANIFEST):
        raise IndependentStoreError("database:indexes")

    for table, expected in FOREIGN_KEY_MANIFEST.items():
        grouped: dict[int, list[tuple[int, str, str]]] = {}
        metadata: dict[int, tuple[str, str, str, str]] = {}
        for row in connection.execute(f"PRAGMA foreign_key_list({table})"):
            if len(row) < 8:
                raise IndependentStoreError(f"database:foreign-key-shape-{table}")
            grouped.setdefault(int(row[0]), []).append((int(row[1]), str(row[3]), str(row[4])))
            metadata[int(row[0])] = (str(row[2]), str(row[5]), str(row[6]), str(row[7]))
        actual_fk = tuple(
            sorted(
                (
                    metadata[fk_id][0],
                    tuple((source, target) for _, source, target in sorted(rows, key=lambda item: item[0])),
                    metadata[fk_id][1],
                    metadata[fk_id][2],
                    metadata[fk_id][3],
                )
                for fk_id, rows in grouped.items()
            )
        )
        if actual_fk != tuple(sorted(expected)):
            raise IndependentStoreError(f"database:foreign-key-definition-{table}")
    if list(connection.execute("PRAGMA foreign_key_check")):
        raise IndependentStoreError("database:foreign-key")


def verify_database(
    path: str | Path,
    graph_profile_registry: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Open a database read-only and return only compact conformance evidence."""

    database = Path(path)
    if not database.is_file():
        raise IndependentStoreError("database:missing")
    wal = Path(str(database) + "-wal")
    if database.stat().st_size > MAX_DB_BYTES or (wal.exists() and wal.stat().st_size > MAX_WAL_BYTES):
        raise IndependentStoreError("database:byte-cap")
    try:
        uri = f"file:{database.resolve().as_posix()}?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=BUSY_TIMEOUT_MS / 1000.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
        _check_sqlite_shape(connection)
        snapshot = _snapshot_from_connection(connection)
        result = _verify_rows(snapshot, graph_profile_registry=graph_profile_registry)
        return result
    except IndependentStoreError:
        raise
    except (sqlite3.DatabaseError, OSError, ValueError) as exc:
        raise IndependentStoreError("database:corrupt-or-unreadable") from exc
    finally:
        try:
            connection.close()
        except UnboundLocalError:
            pass


def verify_snapshot(
    snapshot: Mapping[str, object],
    graph_profile_registry: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Verify an already decoded complete snapshot, used by export validation."""

    return _verify_rows(snapshot, graph_profile_registry=graph_profile_registry)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("REJECT usage", file=sys.stderr)
        return 2
    try:
        result = verify_database(args[0])
    except Exception as exc:
        print(f"REJECT {type(exc).__name__}:{exc}", file=sys.stderr)
        return 1
    print(_canonical(result).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
