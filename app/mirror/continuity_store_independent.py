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
from app.governance import provider_continuity_control_pack_v2_independent as governance_v2_independent
from app.governance import provider_continuity_control_pack_withdrawal_independent as withdrawal_independent
from app.mirror import contract_mirror_independent as contract_independent
from app.mirror import discrepancy_case_independent as case_independent
from app.mirror import denominator_ledger_independent as denominator_independent
from app.mirror import provider_trust_graph_independent as graph_independent
from app.mirror import source_evidence_custody_independent as source_independent
from app.mirror import source_reconciliation_independent as reconciliation_independent
from app.mirror import transaction_mirror_independent as transaction_independent
from app.mirror import money_mirror_independent as money_independent
from app.mirror import transition_mirror_independent as transition_independent
from app.mirror import state_value_ledger_independent as state_value_independent
from app.mirror import qualification_independent
from app.mirror import sqlite_snapshot


STORE_SCHEMA = "mirror-continuity-operational-foundation-v2"
SCHEMA_VERSION = 2
ARTIFACT_GRAPH = "PROVIDER_TRUST_GRAPH_V1"
ARTIFACT_GOVERNANCE = "PROVIDER_CONTINUITY_CONTROL_PACK_V1"
ARTIFACT_SOURCE_EVIDENCE = source_independent.ARTIFACT_KIND
ARTIFACT_RECONCILIATION = reconciliation_independent.ARTIFACT_KIND
ARTIFACT_CASE = case_independent.ARTIFACT_KIND
ARTIFACT_DENOMINATOR = denominator_independent.ARTIFACT_KIND
ARTIFACT_CONTRACT = contract_independent.ARTIFACT_KIND
ARTIFACT_TRANSACTION_OBSERVATION = transaction_independent.OBSERVATION_ARTIFACT_KIND
ARTIFACT_TRANSACTION_TRACE = transaction_independent.TRACE_ARTIFACT_KIND
ARTIFACT_MONEY_OBSERVATION = money_independent.ARTIFACT_KIND
ARTIFACT_TRANSITION = transition_independent.ARTIFACT_KIND
ARTIFACT_STATE_VALUE = state_value_independent.ARTIFACT_KIND
ARTIFACT_QUALIFICATION = qualification_independent.ARTIFACT_KIND
ARTIFACT_KINDS = (
    ARTIFACT_GRAPH,
    ARTIFACT_GOVERNANCE,
    ARTIFACT_SOURCE_EVIDENCE,
    ARTIFACT_RECONCILIATION,
    ARTIFACT_CASE,
    ARTIFACT_DENOMINATOR,
    ARTIFACT_CONTRACT,
    ARTIFACT_TRANSACTION_OBSERVATION,
    ARTIFACT_TRANSACTION_TRACE,
    ARTIFACT_MONEY_OBSERVATION,
    ARTIFACT_TRANSITION,
    ARTIFACT_STATE_VALUE,
    ARTIFACT_QUALIFICATION,
)
GENESIS_EVENT_ROOT = "GENESIS_EVENT_ROOT_V2"
NO_PRIOR = "NO_PRIOR_V2"
RECEIPT_EVENT_PLACEHOLDER = "EVENT_ROOT_PENDING_V2"
MAX_ARTIFACT_BYTES = 524_288
MAX_ARTIFACTS = 32
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
    if value.get("schema") == governance_v2_independent.SCHEMA:
        raw = governance_v2_independent.prefix_bytes(value, stage_count)
        return raw, _parse_canonical(raw)
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
    elif kind == ARTIFACT_SOURCE_EVIDENCE:
        if dict(value) != source_independent.AUTHORITY_FLAGS:
            raise IndependentStoreError("artifact:authority-flags")
    elif kind == ARTIFACT_RECONCILIATION:
        if dict(value) != reconciliation_independent.AUTHORITY_FLAGS:
            raise IndependentStoreError("artifact:authority-flags")
    elif kind == ARTIFACT_CASE:
        if dict(value) != case_independent.AUTHORITY_FLAGS:
            raise IndependentStoreError("artifact:authority-flags")
    elif kind == ARTIFACT_DENOMINATOR:
        if dict(value) != denominator_independent.AUTHORITY_FLAGS:
            raise IndependentStoreError("artifact:authority-flags")
    elif kind == ARTIFACT_CONTRACT:
        if dict(value) != contract_independent.AUTHORITY_FLAGS:
            raise IndependentStoreError("artifact:authority-flags")
    elif kind in (ARTIFACT_TRANSACTION_OBSERVATION, ARTIFACT_TRANSACTION_TRACE):
        if dict(value) != transaction_independent.AUTHORITY_FLAGS:
            raise IndependentStoreError("artifact:authority-flags")
    elif kind == ARTIFACT_MONEY_OBSERVATION:
        if dict(value) != money_independent.AUTHORITY_FLAGS:
            raise IndependentStoreError("artifact:authority-flags")
    elif kind == ARTIFACT_TRANSITION:
        if dict(value) != transition_independent.AUTHORITY_FLAGS:
            raise IndependentStoreError("artifact:authority-flags")
    elif kind == ARTIFACT_STATE_VALUE:
        if dict(value) != state_value_independent.AUTHORITY_FLAGS:
            raise IndependentStoreError("artifact:authority-flags")
    elif kind == ARTIFACT_QUALIFICATION:
        if dict(value) != qualification_independent.AUTHORITY_FLAGS:
            raise IndependentStoreError("artifact:authority-flags")
    elif dict(value) != governance_independent.AUTHORITY_FLAGS:
        raise IndependentStoreError("artifact:authority-flags")
    return _canonical(AUTHORITY_FLAGS).decode("ascii")


def _normalize_artifact(
    kind: str,
    raw: bytes,
    *,
    graph_profile_registry: Mapping[str, object] | None = None,
    reconciliation_context: Mapping[str, object] | None = None,
    denominator_context: Mapping[str, object] | None = None,
    contract_context: Mapping[str, object] | None = None,
    transaction_context: Mapping[str, object] | None = None,
    transition_context: Mapping[str, object] | None = None,
    state_value_context: Mapping[str, object] | None = None,
) -> dict[str, object]:
    if kind not in ARTIFACT_KINDS:
        raise IndependentStoreError("artifact:kind")
    if type(raw) is not bytes or not raw or len(raw) > MAX_ARTIFACT_BYTES:
        raise IndependentStoreError("artifact:byte-cap")
    try:
        if kind == ARTIFACT_SOURCE_EVIDENCE:
            value = source_independent._parse(raw)
        elif kind == ARTIFACT_RECONCILIATION:
            value = reconciliation_independent._parse(raw)
        elif kind == ARTIFACT_CASE:
            value = case_independent._parse(raw)
        elif kind == ARTIFACT_DENOMINATOR:
            value = denominator_independent._parse(raw)
        elif kind == ARTIFACT_CONTRACT:
            value = contract_independent._parse(raw)
        elif kind in (ARTIFACT_TRANSACTION_OBSERVATION, ARTIFACT_TRANSACTION_TRACE):
            value = transaction_independent._parse(raw)
        elif kind == ARTIFACT_MONEY_OBSERVATION:
            value = money_independent._parse(raw)
        elif kind == ARTIFACT_TRANSITION:
            value = transition_independent._parse(raw)
        elif kind == ARTIFACT_STATE_VALUE:
            value = state_value_independent._parse(raw)
        elif kind == ARTIFACT_QUALIFICATION:
            value = qualification_independent._parse(raw)
        else:
            value = _parse_canonical(raw)
    except (
        source_independent.IndependentSourceCustodyError,
        reconciliation_independent.IndependentSourceReconciliationError,
        case_independent.IndependentDiscrepancyCaseError,
        denominator_independent.IndependentDenominatorError,
        contract_independent.IndependentContractMirrorError,
        transaction_independent.IndependentTransactionMirrorError,
        money_independent.IndependentMoneyMirrorError,
        transition_independent.IndependentTransitionMirrorError,
        state_value_independent.IndependentStateValueLedgerError,
        qualification_independent.IndependentQualificationError,
    ) as exc:
        raise IndependentStoreError(str(exc)) from exc
    try:
        if kind == ARTIFACT_SOURCE_EVIDENCE:
            result = source_independent.verify_artifact(raw, graph_profile_registry=graph_profile_registry, allow_unresolved_graph=True)
        elif kind == ARTIFACT_RECONCILIATION:
            if not isinstance(reconciliation_context, Mapping):
                raise IndependentStoreError("reconciliation:context-required")
            result = reconciliation_independent.verify_artifact(
                raw,
                current_custody_raw=reconciliation_context["current_custody_raw"],
                prior_custody_raw=reconciliation_context.get("prior_custody_raw"),
                current_graph_raw=reconciliation_context.get("current_graph_raw"),
                prior_graph_raw=reconciliation_context.get("prior_graph_raw"),
                prior_reconciliation_raw=reconciliation_context.get("prior_reconciliation_raw"),
                qualified_baseline_custody_raw=reconciliation_context.get("qualified_baseline_custody_raw"),
                chronology_anchor_custody_raw=reconciliation_context.get("chronology_anchor_custody_raw"),
                graph_profile_registry=graph_profile_registry,
            )
        elif kind == ARTIFACT_GRAPH:
            if value.get("schema") == graph_independent.SCHEMA_V2:
                result = graph_independent.verify_bytes_v2(raw, graph_profile_registry or {})
            else:
                result = graph_independent.verify_bytes(raw)
        elif kind == ARTIFACT_CASE:
            if not isinstance(reconciliation_context, Mapping):
                raise IndependentStoreError("case:context-required")
            result = case_independent.verify_artifact(
                raw,
                graph_raw=reconciliation_context["graph_raw"],
                reconciliation_raw=reconciliation_context["reconciliation_raw"],
                reconciliation_context=reconciliation_context["reconciliation_context"],
                governance_raw=reconciliation_context["governance_raw"],
                graph_profile_registry=graph_profile_registry or {},
                prior_case_raw=reconciliation_context.get("prior_case_raw"),
                retest_reconciliation_raw=reconciliation_context.get("retest_reconciliation_raw"),
                retest_context=reconciliation_context.get("retest_context"),
            )
        elif kind == ARTIFACT_DENOMINATOR:
            if not isinstance(denominator_context, Mapping):
                raise IndependentStoreError("denominator:context-required")
            result = denominator_independent.verify_artifact(
                raw,
                source_raw=denominator_context["source_raw"],
                graph_raw=denominator_context.get("graph_raw"),
                governance_raw=denominator_context["governance_raw"],
                registry=graph_profile_registry or {},
                prior_denominator_raw=denominator_context.get("prior_denominator_raw"),
            )
        elif kind == ARTIFACT_CONTRACT:
            if not isinstance(contract_context, Mapping):
                raise IndependentStoreError("contract:context-required")
            result = contract_independent.verify_artifact(
                raw,
                denominator_raw=contract_context["denominator_raw"],
                denominator_context=contract_context["denominator_context"],
                case_raw=contract_context["case_raw"],
                case_context=contract_context["case_context"],
                registry=graph_profile_registry or {},
                prior_contract_raw=contract_context.get("prior_contract_raw"),
            )
        elif kind == ARTIFACT_TRANSACTION_OBSERVATION:
            if not isinstance(transaction_context, Mapping):
                raise IndependentStoreError("transaction:context-required")
            result = transaction_independent.verify_observation_artifact(
                raw,
                source_raw=transaction_context["source_raw"],
                contract_raw=transaction_context["contract_raw"],
                contract_context=transaction_context["contract_context"],
                registry=graph_profile_registry or {},
                prior_observation_raw=transaction_context.get("prior_observation_raw"),
            )
        elif kind == ARTIFACT_TRANSACTION_TRACE:
            if not isinstance(transaction_context, Mapping):
                raise IndependentStoreError("transaction:context-required")
            result = transaction_independent.verify_trace_artifact(
                raw,
                source_raw=transaction_context["source_raw"],
                contract_raw=transaction_context["contract_raw"],
                contract_context=transaction_context["contract_context"],
                observation_raw=transaction_context["observation_raw"],
                registry=graph_profile_registry or {},
                prior_trace_raw=transaction_context.get("prior_trace_raw"),
                prior_observation_raw=transaction_context.get("prior_observation_raw"),
            )
        elif kind == ARTIFACT_MONEY_OBSERVATION:
            if not isinstance(transaction_context, Mapping):
                raise IndependentStoreError("money:context-required")
            result = money_independent.verify_artifact(
                raw,
                transaction_raw=transaction_context["transaction_raw"],
                transaction_context=transaction_context["transaction_context"],
                prior_money_raw=transaction_context.get("prior_money_raw"),
                registry=graph_profile_registry,
            )
        elif kind == ARTIFACT_TRANSITION:
            if not isinstance(transition_context, Mapping):
                raise IndependentStoreError("transition:context-required")
            result = transition_independent.verify_artifact(
                raw,
                money_raw=transition_context["money_raw"],
                money_context=transition_context["money_context"],
                prior_transition_raw=transition_context.get("prior_transition_raw"),
                registry=graph_profile_registry,
            )
        elif kind == ARTIFACT_STATE_VALUE:
            if not isinstance(state_value_context, Mapping):
                raise IndependentStoreError("state-value:context-required")
            result = state_value_independent.verify_artifact(
                raw,
                money_contexts=state_value_context["money_contexts"],
                prior_value_raw=state_value_context.get("prior_value_raw"),
                transition_contexts=state_value_context.get("transition_contexts"),
                registry=graph_profile_registry,
            )
        elif kind == ARTIFACT_QUALIFICATION:
            result = qualification_independent.inspect_artifact(raw)
        elif value.get("schema") in (governance_v2_independent.SCHEMA, governance_v2_independent.WITHDRAWAL_SCHEMA):
            result = governance_v2_independent.verify_bytes(raw, graph_profile_registry or {})
        elif value.get("schema") == withdrawal_independent.SCHEMA:
            result = withdrawal_independent.verify_bytes(raw)
        else:
            result = governance_independent.verify_bytes(raw)
    except Exception as exc:
        raise IndependentStoreError(f"artifact:independent-reject:{type(exc).__name__}") from exc
    profile_id: str | None = None
    profile_version: int | None = None
    try:
        if kind == ARTIFACT_SOURCE_EVIDENCE:
            artifact_id = result["artifact_id"]
            report_id = result["report_id"]
            current_stage_id = result["current_stage_id"]
            transition_id = result["transition_id"]
            stage_kind = result["stage_kind"]
            prior_artifact_id = result["prior_artifact_id"]
            prior_stage_id = result["prior_stage_id"]
            authority_json = _authority_json(value["authority"], kind)
            subject_id = result["subject"]
            scope = result["scope"]
            schema = result["schema"]
            profile_id = result["profile_id"]
            profile_version = result["profile_version"]
        elif kind == ARTIFACT_RECONCILIATION:
            artifact_id = result["artifact_id"]
            report_id = None
            current_stage_id = result["current_stage_id"]
            transition_id = result["transition_id"]
            stage_kind = result["stage_kind"]
            prior_artifact_id = result["prior_artifact_id"]
            prior_stage_id = result["prior_stage_id"]
            authority_json = _authority_json(value["authority"], kind)
            subject_id = result["subject"]
            scope = result["scope"]
            schema = result["schema"]
            profile_id = result["profile_id"]
            profile_version = result["profile_version"]
        elif kind == ARTIFACT_GRAPH:
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
                profile_version = profile_value.get("version")
        elif kind == ARTIFACT_CASE:
            artifact_id = result["artifact_id"]
            report_id = result["case_id"]
            current_stage_id = result["current_stage_id"]
            transition_id = result["transition_id"]
            stage_kind = result["stage_kind"]
            prior_artifact_id = result["prior_artifact_id"]
            prior_stage_id = result["prior_stage_id"]
            schema = result["schema"]
            subject_id = result["subject"]
            scope = result["scope"]
            profile_id = result["profile_id"]
            profile_version = result["profile_version"]
            authority_json = _authority_json(value["authority"], kind)
        elif kind == ARTIFACT_DENOMINATOR:
            artifact_id = result["artifact_id"]
            report_id = result["report_id"]
            current_stage_id = result["current_stage_id"]
            transition_id = result["transition_id"]
            stage_kind = result["stage_kind"]
            prior_artifact_id = result["prior_artifact_id"]
            prior_stage_id = result["prior_stage_id"]
            schema = result["schema"]
            subject_id = result["subject"]
            scope = result["scope"]
            profile_id = result["profile_id"]
            profile_version = result["profile_version"]
            authority_json = _authority_json(value["authority"], kind)
        elif kind == ARTIFACT_CONTRACT:
            artifact_id = result["artifact_id"]
            report_id = result["report_id"]
            current_stage_id = result["current_stage_id"]
            transition_id = result["transition_id"]
            stage_kind = result["stage_kind"]
            prior_artifact_id = result["prior_artifact_id"]
            prior_stage_id = result["prior_stage_id"]
            schema = result["schema"]
            subject_id = result["subject"]
            scope = result["scope"]
            profile_id = result["profile_id"]
            profile_version = result["profile_version"]
            authority_json = _authority_json(value["authority"], kind)
        elif kind in (ARTIFACT_TRANSACTION_OBSERVATION, ARTIFACT_TRANSACTION_TRACE):
            artifact_id = str(result["artifact_id"])
            report_id = str(result["report_id"])
            current_stage_id = str(result["current_stage_id"])
            transition_id = str(result["transition_id"])
            stage_kind = str(result["stage_kind"])
            prior_artifact_id = result["prior_artifact_id"]
            prior_stage_id = result["prior_stage_id"]
            schema = str(result["schema"])
            subject_id = str(result["subject"])
            scope = str(result["scope"])
            profile_id = str(result["profile_id"])
            profile_version = int(result["profile_version"])
            authority_json = _authority_json(value["authority"], kind)
        elif kind == ARTIFACT_MONEY_OBSERVATION:
            artifact_id = str(result["artifact_id"])
            report_id = str(result["report_id"])
            current_stage_id = str(result["current_stage_id"])
            transition_id = str(result["transition_id"])
            stage_kind = str(result["stage_kind"])
            prior_artifact_id = result["prior_artifact_id"]
            prior_stage_id = result["prior_stage_id"]
            schema = str(result["schema"])
            subject_id = str(result["subject"])
            scope = str(result["scope"])
            profile_id = str(result["profile_id"])
            profile_version = int(result["profile_version"])
            authority_json = _authority_json(value["authority"], kind)
        elif kind == ARTIFACT_TRANSITION:
            artifact_id = str(result["artifact_id"])
            report_id = str(result["report_id"])
            current_stage_id = str(result["current_stage_id"])
            transition_id = str(result["transition_id"])
            stage_kind = str(result["stage_kind"])
            prior_artifact_id = result["prior_artifact_id"]
            prior_stage_id = result["prior_stage_id"]
            schema = str(result["schema"])
            subject_id = str(result["subject"])
            scope = str(result["scope"])
            profile_id = str(result["profile_id"])
            profile_version = int(result["profile_version"])
            authority_json = _authority_json(value["authority"], kind)
        elif kind == ARTIFACT_STATE_VALUE:
            artifact_id = str(result["artifact_id"])
            report_id = str(result["report_id"])
            current_stage_id = str(result["current_stage_id"])
            transition_id = str(result["transition_id"])
            stage_kind = str(result["stage_kind"])
            prior_artifact_id = result["prior_artifact_id"]
            prior_stage_id = result["prior_stage_id"]
            schema = str(result["schema"])
            subject_id = str(result["subject"])
            scope = str(result["scope"])
            profile_id = str(result["profile_id"])
            profile_version = int(result["profile_version"])
            authority_json = _authority_json(value["authority"], kind)
        elif kind == ARTIFACT_QUALIFICATION:
            artifact_id = str(result["artifact_id"])
            report_id = str(result["manifest_id"])
            current_stage_id = str(result["current_stage_id"])
            transition_id = str(result["transition_id"])
            stage_kind = str(result["stage_kind"])
            prior_artifact_id = result["prior_artifact_id"]
            prior_stage_id = result["prior_stage_id"]
            schema = str(result["schema"])
            subject_id = str(result["subject"])
            scope = str(result["scope"])
            profile_id = str(result["profile_id"])
            profile_version = int(result["profile_version"])
            authority_json = _authority_json(value["authority"], kind)
        elif value.get("schema") in (withdrawal_independent.SCHEMA, governance_v2_independent.WITHDRAWAL_SCHEMA):
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
            schema = value["schema"]
            authority_flags = governance_v2_independent.AUTHORITY_FLAGS if schema == governance_v2_independent.WITHDRAWAL_SCHEMA else withdrawal_independent.AUTHORITY_FLAGS
            authority_json = _authority_json({key: value[key] for key in authority_flags}, kind)
            subject_id = value["provider_graph_subject"]
            scope = value["scope"]
            if schema == governance_v2_independent.WITHDRAWAL_SCHEMA:
                profile_value = governance_v2_independent._expect_keys(value.get("profile"), governance_v2_independent.PROFILE_KEYS, "artifact:profile")
                profile_id = profile_value["profile_id"]
                profile_version = profile_value["version"]
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
            schema = value["schema"]
            prior_artifact_id = None
            prior_stage_id = None
            if len(stages) > 1:
                prefix_raw, prefix = _governance_prefix(value, len(stages) - 1)
                try:
                    if value.get("schema") == governance_v2_independent.SCHEMA:
                        governance_v2_independent.verify_bytes(prefix_raw, graph_profile_registry or {})
                    else:
                        governance_independent.verify_bytes(prefix_raw)
                except Exception as exc:
                    raise IndependentStoreError("artifact:governance-prior-prefix") from exc
                prior_artifact_id = prefix["artifact_id"]
                previous = stages[-2]
                if not isinstance(previous, dict):
                    raise IndependentStoreError("artifact:governance-prior-stage")
                prior_stage_id = previous["stage_id"]
            authority_flags = governance_v2_independent.AUTHORITY_FLAGS if schema == governance_v2_independent.SCHEMA else governance_independent.AUTHORITY_FLAGS
            authority_json = _authority_json({key: value[key] for key in authority_flags}, kind)
            subject_id = subject["provider_graph_subject"]
            scope = subject["scope"]
            if schema == governance_v2_independent.SCHEMA:
                profile_value = governance_v2_independent._expect_keys(value.get("profile"), governance_v2_independent.PROFILE_KEYS, "artifact:profile")
                profile_id = profile_value["profile_id"]
                profile_version = profile_value["version"]
        if not all(isinstance(item, str) and item for item in (schema, artifact_id, subject_id, scope, current_stage_id, transition_id, stage_kind)):
            raise IndependentStoreError("artifact:identity-empty")
        if prior_artifact_id is not None and (not isinstance(prior_artifact_id, str) or not prior_artifact_id):
            raise IndependentStoreError("artifact:prior-artifact")
        if prior_stage_id is not None and (not isinstance(prior_stage_id, str) or not prior_stage_id):
            raise IndependentStoreError("artifact:prior-stage")
    except (KeyError, TypeError, ValueError) as exc:
        raise IndependentStoreError("artifact:identity-shape") from exc
    normalized = {
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
        "profile_id": profile_id,
        "profile_version": profile_version,
    }
    if kind == ARTIFACT_SOURCE_EVIDENCE:
        normalized.update(
            {
                "source_profile_id": result["source_profile_id"],
                "source_profile_version": result["source_profile_version"],
                "envelope_digest": result["envelope_digest"],
                "linked_graph_artifact_id": result["linked_graph_artifact_id"],
                "linked_graph_payload_hash": result["linked_graph_payload_hash"],
                "linked_graph_report_id": result["linked_graph_report_id"],
                "source_status": result["source_status"],
            }
        )
    elif kind == ARTIFACT_RECONCILIATION:
        normalized.update(
            {
                "current_custody_artifact_id": result["current_custody_artifact_id"],
                "current_custody_stage_id": result["current_custody_stage_id"],
                "predecessor_custody_artifact_id": result["predecessor_custody_artifact_id"],
                "predecessor_custody_stage_id": result["predecessor_custody_stage_id"],
                "result_status": result["result_status"],
                "current_snapshot_root": result["current_snapshot_root"],
                "current_content_root": result["current_content_root"],
                "current_source_status": result["current_source_status"],
                "qualified_baseline_custody_artifact_id": result["qualified_baseline_custody_artifact_id"],
                "qualified_baseline_custody_stage_id": result["qualified_baseline_custody_stage_id"],
                "chronology_anchor_custody_artifact_id": result["chronology_anchor_custody_artifact_id"],
                "chronology_anchor_custody_stage_id": result["chronology_anchor_custody_stage_id"],
            }
        )
    elif kind == ARTIFACT_CASE:
        normalized.update(
            {
                "case_id": result["case_id"],
                "graph_artifact_id": result["graph_artifact_id"],
                "reconciliation_artifact_id": result["reconciliation_artifact_id"],
                "finding_id": result["finding_id"],
                "result_status": result["result_status"],
                "retest_reconciliation_artifact_id": result["retest_reconciliation_artifact_id"],
                "responsibility_boundary": result["responsibility_boundary"],
                "parity_status": result["parity_status"],
            }
        )
    elif kind == ARTIFACT_DENOMINATOR:
        normalized.update(
            {
                "denominator_stage": result["denominator_stage"],
                "source_artifact_id": result["source_artifact_id"],
                "population_root": result["population_root"],
                "child_population_root": result["child_population_root"],
                "input_record_count": result["input_record_count"],
                "outcome_counts": result["outcome_counts"],
            }
        )
    elif kind == ARTIFACT_CONTRACT:
        normalized.update(
            {
                "contract_stage": result["contract_stage"],
                "denominator_artifact_id": result["denominator_artifact_id"],
                "denominator_population_root": result["denominator_population_root"],
                "case_artifact_id": result["case_artifact_id"],
                "case_id": result["case_id"],
                "reconciliation_artifact_id": result["reconciliation_artifact_id"],
                "evaluation_status": result["evaluation_status"],
            }
        )
    elif kind == ARTIFACT_TRANSACTION_OBSERVATION:
        normalized.update(
            {
                "transaction_stage": value["stage_kind"],
                "transaction_trace_id": result["trace_id"],
                "transaction_fixture_id": result["fixture_id"],
                "transaction_source_artifact_id": result["source_artifact_id"],
                "transaction_contract_artifact_id": result["contract_artifact_id"],
            }
        )
    elif kind == ARTIFACT_TRANSACTION_TRACE:
        normalized.update(
            {
                "transaction_stage": result["trace_stage"],
                "transaction_trace_id": result["trace_id"],
                "transaction_observation_artifact_id": result["observation_artifact_id"],
                "transaction_contract_artifact_id": result["contract_artifact_id"],
                "transaction_divergence_status": result["divergence_status"],
                "transaction_case_artifact_id": result["case_artifact_id"],
            }
        )
    elif kind == ARTIFACT_MONEY_OBSERVATION:
        normalized.update(
            {
                "money_stage": value["stage_kind"],
                "money_trace_id": result["money_trace_id"],
                "money_transaction_trace_artifact_id": result["transaction_trace_artifact_id"],
                "money_transaction_contract_artifact_id": result["transaction_contract_artifact_id"],
                "money_result_status": result["result_status"],
                "money_event_status": result["event_status"],
                "money_report_status": result["report_status"],
                "money_case_artifact_id": result["case_artifact_id"],
            }
        )
    elif kind == ARTIFACT_TRANSITION:
        normalized.update(
            {
                "transition_status": result["transition_status"],
                "transition_money_artifact_id": result["transition_money_artifact_id"],
                "transition_contract_artifact_id": result["transition_contract_artifact_id"],
                "transition_case_artifact_id": result["transition_case_artifact_id"],
            }
        )
    return normalized


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


def _case_reconciliation_context(
    artifacts: Mapping[tuple[str, str], Mapping[str, object]],
    raw_by_key: Mapping[tuple[str, str], bytes],
    reconciliation_raw: bytes,
    graph_profile_registry: Mapping[str, object] | None,
) -> dict[str, object]:
    try:
        value = reconciliation_independent._parse(reconciliation_raw)
        current_summary = value["current_custody"]
        if not isinstance(current_summary, dict):
            raise IndependentStoreError("database:case-reconciliation-current")
        current_key = (ARTIFACT_SOURCE_EVIDENCE, str(current_summary["artifact_id"]))
        current = artifacts.get(current_key)
        if current is None or current["current_stage_id"] != current_summary["stage_id"]:
            raise IndependentStoreError("database:case-reconciliation-current-custody")
        current_graph = None
        linked_graph_id = current.get("linked_graph_artifact_id")
        if linked_graph_id is not None:
            current_graph = artifacts.get((ARTIFACT_GRAPH, str(linked_graph_id)))
            if current_graph is None:
                raise IndependentStoreError("database:case-current-graph")
            source_independent.verify_artifact(
                raw_by_key[current_key],
                graph_raw=raw_by_key[(ARTIFACT_GRAPH, str(linked_graph_id))],
                graph_profile_registry=graph_profile_registry,
            )
        prior_key = None
        prior = None
        prior_id = current.get("prior_artifact_id")
        if prior_id is not None:
            prior_key = (ARTIFACT_SOURCE_EVIDENCE, str(prior_id))
            prior = artifacts.get(prior_key)
            if prior is None or prior["current_stage_id"] != current.get("prior_stage_id"):
                raise IndependentStoreError("database:case-prior-custody")
        prior_graph = None
        if prior is not None and prior.get("linked_graph_artifact_id") is not None:
            prior_graph = artifacts.get((ARTIFACT_GRAPH, str(prior["linked_graph_artifact_id"])))
            if prior_graph is None:
                raise IndependentStoreError("database:case-prior-graph")
        prior_reconciliation_raw = None
        prior_reconciliation_id = value.get("prior_artifact_id")
        if prior_reconciliation_id is not None:
            prior_reconciliation_raw = raw_by_key.get((ARTIFACT_RECONCILIATION, str(prior_reconciliation_id)))
            if prior_reconciliation_raw is None:
                raise IndependentStoreError("database:case-prior-reconciliation")
        qualified_baseline_raw = None
        chronology_anchor_raw = None
        if prior_reconciliation_raw is not None:
            prior_value = reconciliation_independent._parse(prior_reconciliation_raw)
            anchors = reconciliation_independent._validate_anchors(prior_value["anchors"])
            for name, target in (
                ("qualified_content_baseline", anchors["qualified_content_baseline"]),
                ("chronology_anchor", anchors["chronology_anchor"]),
            ):
                if target is None:
                    continue
                anchor_key = (ARTIFACT_SOURCE_EVIDENCE, str(target["custody_artifact_id"]))
                anchor = artifacts.get(anchor_key)
                if anchor is None or anchor["current_stage_id"] != target["custody_stage_id"]:
                    raise IndependentStoreError(f"database:case-{name}")
                if name == "qualified_content_baseline":
                    qualified_baseline_raw = raw_by_key[anchor_key]
                else:
                    chronology_anchor_raw = raw_by_key[anchor_key]
        return {
            "current_custody_raw": raw_by_key[current_key],
            "prior_custody_raw": raw_by_key[prior_key] if prior_key is not None else None,
            "current_graph_raw": raw_by_key[(ARTIFACT_GRAPH, str(linked_graph_id))] if linked_graph_id is not None else None,
            "prior_graph_raw": raw_by_key[(ARTIFACT_GRAPH, str(prior["linked_graph_artifact_id"]))] if prior is not None and prior.get("linked_graph_artifact_id") is not None else None,
            "prior_reconciliation_raw": prior_reconciliation_raw,
            "qualified_baseline_custody_raw": qualified_baseline_raw,
            "chronology_anchor_custody_raw": chronology_anchor_raw,
        }
    except IndependentStoreError:
        raise
    except Exception as exc:
        raise IndependentStoreError("database:case-reconciliation-context") from exc


def _case_governance_raw(
    artifacts: Mapping[tuple[str, str], Mapping[str, object]],
    raw_by_key: Mapping[tuple[str, str], bytes],
    event_sequence_by_key: Mapping[tuple[str, str], int],
    graph_artifact: Mapping[str, object],
    graph_profile_registry: Mapping[str, object] | None,
) -> bytes:
    graph_key = (ARTIFACT_GRAPH, str(graph_artifact["artifact_id"]))
    graph_sequence = event_sequence_by_key.get(graph_key)
    if graph_sequence is None:
        raise IndependentStoreError("database:case-graph-event")
    graph_value = _parse_canonical(graph_artifact["payload"])
    profile = graph_value.get("profile")
    if not isinstance(profile, dict):
        raise IndependentStoreError("database:case-graph-profile")
    selected = None
    for key, sequence in sorted(event_sequence_by_key.items(), key=lambda item: item[1]):
        if sequence >= graph_sequence or key[0] != ARTIFACT_GOVERNANCE:
            continue
        candidate = artifacts.get(key)
        if candidate is None or candidate["subject"] != graph_artifact["subject"] or candidate["scope"] != graph_artifact["scope"] or candidate.get("profile_id") != profile.get("profile_id"):
            continue
        raw = raw_by_key[key]
        value = _parse_canonical(raw)
        if value.get("schema") not in (governance_v2_independent.SCHEMA, governance_v2_independent.WITHDRAWAL_SCHEMA):
            continue
        governed = governance_v2_independent.verify_bytes(raw, graph_profile_registry or {})
        if value.get("schema") == governance_v2_independent.SCHEMA and governed.get("current_stage_kind") == governance_v2_independent.STAGE_APPROVED:
            selected = raw
        elif value.get("schema") == governance_v2_independent.WITHDRAWAL_SCHEMA:
            selected = None
    if selected is None:
        raise IndependentStoreError("database:case-governance-not-effective")
    return selected


def _case_context(
    artifacts: Mapping[tuple[str, str], Mapping[str, object]],
    raw_by_key: Mapping[tuple[str, str], bytes],
    event_sequence_by_key: Mapping[tuple[str, str], int],
    case_raw: bytes,
    graph_profile_registry: Mapping[str, object] | None,
) -> dict[str, object]:
    value = case_independent._parse(case_raw)
    upstream = value["upstream"]
    graph_key = (ARTIFACT_GRAPH, str(upstream["graph"]["artifact_id"]))
    recon_key = (ARTIFACT_RECONCILIATION, str(upstream["reconciliation"]["artifact_id"]))
    graph_artifact = artifacts.get(graph_key)
    if graph_artifact is None or recon_key not in artifacts:
        raise IndependentStoreError("database:case-upstream-missing")
    graph_raw = raw_by_key[graph_key]
    reconciliation_raw = raw_by_key[recon_key]
    reconciliation_context = _case_reconciliation_context(artifacts, raw_by_key, reconciliation_raw, graph_profile_registry)
    governance_raw = _case_governance_raw(artifacts, raw_by_key, event_sequence_by_key, graph_artifact, graph_profile_registry)
    result: dict[str, object] = {
        "graph_raw": graph_raw,
        "reconciliation_raw": reconciliation_raw,
        "reconciliation_context": reconciliation_context,
        "governance_raw": governance_raw,
    }
    retest_id = value["retest"].get("reconciliation_artifact_id") if isinstance(value.get("retest"), dict) else None
    if retest_id is not None:
        retest_key = (ARTIFACT_RECONCILIATION, str(retest_id))
        if retest_key not in artifacts:
            raise IndependentStoreError("database:case-retest-reconciliation")
        retest_raw = raw_by_key[retest_key]
        result["retest_reconciliation_raw"] = retest_raw
        result["retest_context"] = _case_reconciliation_context(artifacts, raw_by_key, retest_raw, graph_profile_registry)
    prior_id = value["transition"].get("prior_artifact_id")
    if prior_id is not None:
        prior_key = (ARTIFACT_CASE, str(prior_id))
        if prior_key not in raw_by_key:
            raise IndependentStoreError("database:case-prior")
        result["prior_case_raw"] = raw_by_key[prior_key]
    return result


def _contract_context(
    artifacts: Mapping[tuple[str, str], Mapping[str, object]],
    raw_by_key: Mapping[tuple[str, str], bytes],
    event_sequence_hint: Mapping[tuple[str, str], int],
    contract_raw: bytes,
    graph_profile_registry: Mapping[str, object] | None,
) -> dict[str, object]:
    """Reconstruct all stored bytes named by one Contract Mirror artifact."""

    try:
        value = contract_independent._parse(contract_raw)
        denominator_binding = value["denominator"]
        case_link = value["case_link"]
        denominator_key = (ARTIFACT_DENOMINATOR, str(denominator_binding["artifact_id"]))
        case_key = (ARTIFACT_CASE, str(case_link["artifact_id"]))
        denominator_artifact = artifacts.get(denominator_key)
        case_artifact = artifacts.get(case_key)
        if denominator_artifact is None or case_artifact is None:
            raise IndependentStoreError("database:contract-upstream-missing")
        denominator_raw = raw_by_key[denominator_key]
        denominator_value = denominator_independent._parse(denominator_raw)
        source_binding = denominator_value.get("source_binding")
        governance_binding = denominator_value.get("governance_binding")
        if not isinstance(source_binding, dict) or not isinstance(governance_binding, dict):
            raise IndependentStoreError("database:contract-denominator-binding")
        source_key = (ARTIFACT_SOURCE_EVIDENCE, str(source_binding["artifact_id"]))
        source_artifact = artifacts.get(source_key)
        if source_artifact is None or source_artifact["current_stage_id"] != source_binding["stage_id"]:
            raise IndependentStoreError("database:contract-source-missing")
        graph_id = source_binding.get("graph_artifact_id")
        graph_key = (ARTIFACT_GRAPH, str(graph_id)) if graph_id is not None else None
        if graph_key is not None and graph_key not in artifacts:
            raise IndependentStoreError("database:contract-graph-missing")
        governance_key = (ARTIFACT_GOVERNANCE, str(governance_binding["artifact_id"]))
        governance_artifact = artifacts.get(governance_key)
        if governance_artifact is None or governance_artifact["current_stage_id"] != governance_binding["stage_id"]:
            raise IndependentStoreError("database:contract-governance-missing")
        prior_denominator_raw = None
        prior_id = denominator_value.get("prior_artifact_id")
        if prior_id is not None:
            prior_key = (ARTIFACT_DENOMINATOR, str(prior_id))
            if prior_key not in raw_by_key:
                raise IndependentStoreError("database:contract-denominator-prior")
            prior_denominator_raw = raw_by_key[prior_key]
        denominator_context = {
            "source_raw": raw_by_key[source_key],
            "graph_raw": raw_by_key[graph_key] if graph_key is not None else None,
            "governance_raw": raw_by_key[governance_key],
            "prior_denominator_raw": prior_denominator_raw,
        }
        case_raw = raw_by_key[case_key]
        case_context = _case_context(
            artifacts,
            raw_by_key,
            event_sequence_hint,
            case_raw,
            graph_profile_registry,
        )
        prior_contract_raw = None
        prior_contract_id = value.get("prior_artifact_id")
        if prior_contract_id is not None:
            prior_contract_key = (ARTIFACT_CONTRACT, str(prior_contract_id))
            if prior_contract_key not in raw_by_key:
                raise IndependentStoreError("database:contract-prior")
            prior_contract_raw = raw_by_key[prior_contract_key]
        return {
            "denominator_raw": denominator_raw,
            "denominator_context": denominator_context,
            "case_raw": case_raw,
            "case_context": case_context,
            "prior_contract_raw": prior_contract_raw,
        }
    except IndependentStoreError:
        raise
    except Exception as exc:
        raise IndependentStoreError("database:contract-context") from exc


def _transaction_context(
    artifacts: Mapping[tuple[str, str], Mapping[str, object]],
    raw_by_key: Mapping[tuple[str, str], bytes],
    event_sequence_hint: Mapping[tuple[str, str], int],
    transaction_raw: bytes,
    graph_profile_registry: Mapping[str, object] | None,
) -> dict[str, object]:
    """Reconstruct source, Contract, observation, and trace predecessor bytes."""

    try:
        value = transaction_independent._parse(transaction_raw)
        contract_binding = value["contract_binding"]
        contract_key = (ARTIFACT_CONTRACT, str(contract_binding["artifact_id"]))
        if contract_key not in artifacts:
            raise IndependentStoreError("database:transaction-contract-missing")
        contract_raw = raw_by_key[contract_key]
        contract_context = _contract_context(
            artifacts,
            raw_by_key,
            event_sequence_hint,
            contract_raw,
            graph_profile_registry,
        )
        source_raw = contract_context["denominator_context"]["source_raw"]
        if not isinstance(source_raw, bytes):
            raise IndependentStoreError("database:transaction-source-missing")
        result: dict[str, object] = {
            "source_raw": source_raw,
            "contract_raw": contract_raw,
            "contract_context": contract_context,
            "prior_observation_raw": None,
            "prior_trace_raw": None,
            "observation_raw": None,
        }
        if value["schema"] == transaction_independent.OBSERVATION_SCHEMA:
            prior_id = value.get("prior_artifact_id")
            if prior_id is not None:
                prior_key = (ARTIFACT_TRANSACTION_OBSERVATION, str(prior_id))
                if prior_key not in raw_by_key:
                    raise IndependentStoreError("database:transaction-observation-prior")
                result["prior_observation_raw"] = raw_by_key[prior_key]
        elif value["schema"] == transaction_independent.TRACE_SCHEMA:
            observation_id = value["observation_binding"]["artifact_id"]
            observation_key = (ARTIFACT_TRANSACTION_OBSERVATION, str(observation_id))
            if observation_key not in raw_by_key:
                raise IndependentStoreError("database:transaction-observation-missing")
            result["observation_raw"] = raw_by_key[observation_key]
            prior_id = value.get("prior_artifact_id")
            if prior_id is not None:
                prior_key = (ARTIFACT_TRANSACTION_TRACE, str(prior_id))
                if prior_key not in raw_by_key:
                    raise IndependentStoreError("database:transaction-trace-prior")
                prior_raw = raw_by_key[prior_key]
                result["prior_trace_raw"] = prior_raw
                prior_value = transaction_independent._parse(prior_raw)
                prior_observation_id = prior_value["observation_binding"]["artifact_id"]
                prior_observation_key = (ARTIFACT_TRANSACTION_OBSERVATION, str(prior_observation_id))
                if prior_observation_key not in raw_by_key:
                    raise IndependentStoreError("database:transaction-prior-observation")
                result["prior_observation_raw"] = raw_by_key[prior_observation_key]
        else:
            raise IndependentStoreError("database:transaction-schema")
        return result
    except IndependentStoreError:
        raise
    except Exception as exc:
        raise IndependentStoreError("database:transaction-context") from exc


def _money_context(
    artifacts: Mapping[tuple[str, str], Mapping[str, object]],
    raw_by_key: Mapping[tuple[str, str], bytes],
    event_sequence_hint: Mapping[tuple[str, str], int],
    money_raw: bytes,
    graph_profile_registry: Mapping[str, object] | None,
) -> dict[str, object]:
    """Reconstruct the exact stored Transaction Trace and prior money bytes."""

    try:
        value = money_independent._parse(money_raw)
        binding = value["transaction_binding"]
        trace_key = (ARTIFACT_TRANSACTION_TRACE, str(binding["trace_artifact_id"]))
        if trace_key not in artifacts:
            raise IndependentStoreError("database:money-trace-missing")
        trace_artifact = artifacts[trace_key]
        if trace_artifact["current_stage_id"] != binding["trace_stage_id"]:
            raise IndependentStoreError("database:money-trace-stage")
        trace_raw = raw_by_key[trace_key]
        transaction_context = _transaction_context(
            artifacts,
            raw_by_key,
            event_sequence_hint,
            trace_raw,
            graph_profile_registry,
        )
        prior_money_raw = None
        prior_id = value.get("prior_artifact_id")
        if prior_id is not None:
            prior_key = (ARTIFACT_MONEY_OBSERVATION, str(prior_id))
            if prior_key not in raw_by_key:
                raise IndependentStoreError("database:money-prior-missing")
            prior_money_raw = raw_by_key[prior_key]
        return {
            "transaction_raw": trace_raw,
            "transaction_context": transaction_context,
            "prior_money_raw": prior_money_raw,
        }
    except IndependentStoreError:
        raise
    except Exception as exc:
        raise IndependentStoreError("database:money-context") from exc


def _transition_context(
    artifacts: Mapping[tuple[str, str], Mapping[str, object]],
    raw_by_key: Mapping[tuple[str, str], bytes],
    event_sequence_hint: Mapping[tuple[str, str], int],
    transition_raw: bytes,
    graph_profile_registry: Mapping[str, object] | None,
) -> dict[str, object]:
    """Reconstruct the exact Money artifact and optional Transition predecessor."""

    try:
        value = transition_independent._parse(transition_raw)
        shared = value["shared_binding"]
        money_id = shared["money"]["artifact_id"]
        money_key = (ARTIFACT_MONEY_OBSERVATION, str(money_id))
        if money_key not in artifacts:
            raise IndependentStoreError("database:transition-money-missing")
        money_raw = raw_by_key[money_key]
        money_context = _money_context(
            artifacts,
            raw_by_key,
            event_sequence_hint,
            money_raw,
            graph_profile_registry,
        )
        prior_transition_raw = None
        prior_id = value.get("prior_artifact_id")
        if prior_id is not None:
            prior_key = (ARTIFACT_TRANSITION, str(prior_id))
            if prior_key not in raw_by_key:
                raise IndependentStoreError("database:transition-prior-missing")
            prior_transition_raw = raw_by_key[prior_key]
        return {
            "money_raw": money_raw,
            "money_context": money_context,
            "prior_transition_raw": prior_transition_raw,
        }
    except IndependentStoreError:
        raise
    except Exception as exc:
        raise IndependentStoreError("database:transition-context") from exc


def _state_value_context(
    artifacts: Mapping[tuple[str, str], Mapping[str, object]],
    raw_by_key: Mapping[tuple[str, str], bytes],
    event_sequence_hint: Mapping[tuple[str, str], int],
    state_value_raw: bytes,
    graph_profile_registry: Mapping[str, object] | None,
) -> dict[str, object]:
    """Reconstruct all Money and optional Transition bytes named by a value artifact."""

    try:
        value = state_value_independent._parse(state_value_raw)
        money_contexts: dict[str, dict[str, object]] = {}
        transition_contexts: dict[str, dict[str, object]] = {}
        for entry in value["entries"]:
            upstream = entry["upstream"]
            money_id = str(upstream["money"]["artifact_id"])
            money_key = (ARTIFACT_MONEY_OBSERVATION, money_id)
            if money_key not in artifacts:
                raise IndependentStoreError("database:state-value-money-missing")
            money_raw = raw_by_key[money_key]
            money_contexts[money_id] = {
                "money_raw": money_raw,
                "money_context": _money_context(artifacts, raw_by_key, event_sequence_hint, money_raw, graph_profile_registry),
            }
            transition_ref = upstream.get("transition")
            if transition_ref is not None:
                transition_id = str(transition_ref["artifact_id"])
                transition_key = (ARTIFACT_TRANSITION, transition_id)
                if transition_key not in artifacts:
                    raise IndependentStoreError("database:state-value-transition-missing")
                transition_raw = raw_by_key[transition_key]
                transition_contexts[transition_id] = {
                    "transition_raw": transition_raw,
                    "transition_context": _transition_context(
                        artifacts,
                        raw_by_key,
                        event_sequence_hint,
                        transition_raw,
                        graph_profile_registry,
                    ),
                }
        prior_value_raw = None
        prior_id = value.get("prior_artifact_id")
        if prior_id is not None:
            prior_key = (ARTIFACT_STATE_VALUE, str(prior_id))
            if prior_key not in artifacts:
                raise IndependentStoreError("database:state-value-prior-missing")
            prior_artifact = artifacts[prior_key]
            if prior_artifact["current_stage_id"] != value.get("prior_stage_id"):
                raise IndependentStoreError("database:state-value-prior-stage")
            prior_value_raw = raw_by_key[prior_key]
            prior_value = state_value_independent._parse(prior_value_raw)
            for prior_entry in prior_value["entries"]:
                prior_upstream = prior_entry["upstream"]
                prior_money_id = str(prior_upstream["money"]["artifact_id"])
                prior_money_key = (ARTIFACT_MONEY_OBSERVATION, prior_money_id)
                if prior_money_key not in artifacts:
                    raise IndependentStoreError("database:state-value-prior-money-missing")
                prior_money_raw = raw_by_key[prior_money_key]
                money_contexts.setdefault(
                    prior_money_id,
                    {
                        "money_raw": prior_money_raw,
                        "money_context": _money_context(artifacts, raw_by_key, event_sequence_hint, prior_money_raw, graph_profile_registry),
                    },
                )
                prior_transition_ref = prior_upstream.get("transition")
                if prior_transition_ref is not None:
                    prior_transition_id = str(prior_transition_ref["artifact_id"])
                    prior_transition_key = (ARTIFACT_TRANSITION, prior_transition_id)
                    if prior_transition_key not in artifacts:
                        raise IndependentStoreError("database:state-value-prior-transition-missing")
                    prior_transition_raw = raw_by_key[prior_transition_key]
                    transition_contexts.setdefault(
                        prior_transition_id,
                        {
                            "transition_raw": prior_transition_raw,
                            "transition_context": _transition_context(
                                artifacts,
                                raw_by_key,
                                event_sequence_hint,
                                prior_transition_raw,
                                graph_profile_registry,
                            ),
                        },
                    )
        return {
            "money_contexts": money_contexts,
            "prior_value_raw": prior_value_raw,
            "transition_contexts": transition_contexts,
        }
    except IndependentStoreError:
        raise
    except Exception as exc:
        raise IndependentStoreError("database:state-value-context") from exc


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
    raw_by_key: dict[tuple[str, str], bytes] = {}
    reconciliation_rows: list[tuple[Mapping[str, object], bytes, tuple[str, str]]] = []
    case_rows: list[tuple[Mapping[str, object], bytes, tuple[str, str]]] = []
    denominator_rows: list[tuple[Mapping[str, object], bytes, tuple[str, str]]] = []
    contract_rows: list[tuple[Mapping[str, object], bytes, tuple[str, str]]] = []
    transaction_observation_rows: list[tuple[Mapping[str, object], bytes, tuple[str, str]]] = []
    transaction_trace_rows: list[tuple[Mapping[str, object], bytes, tuple[str, str]]] = []
    money_rows: list[tuple[Mapping[str, object], bytes, tuple[str, str]]] = []
    transition_rows: list[tuple[Mapping[str, object], bytes, tuple[str, str]]] = []
    state_value_rows: list[tuple[Mapping[str, object], bytes, tuple[str, str]]] = []
    qualification_rows: list[tuple[Mapping[str, object], bytes, tuple[str, str]]] = []
    event_sequence_hint = {
        (str(row["artifact_kind"]), str(row["artifact_id"])): int(row["sequence"])
        for row in rows["events"]
    }
    artifact_hashes: set[tuple[str, str]] = set()
    for row in rows["artifacts"]:
        kind = row["kind"]
        artifact_id = row["artifact_id"]
        if kind not in ARTIFACT_KINDS or not isinstance(artifact_id, str):
            raise IndependentStoreError("database:artifact-identity")
        key = (kind, artifact_id)
        if key in artifacts or key in raw_by_key:
            raise IndependentStoreError("database:artifact-duplicate")
        raw = _row_bytes(row, "payload")
        raw_by_key[key] = raw
        if kind == ARTIFACT_RECONCILIATION:
            reconciliation_rows.append((row, raw, key))
            continue
        if kind == ARTIFACT_CASE:
            case_rows.append((row, raw, key))
            continue
        if kind == ARTIFACT_DENOMINATOR:
            denominator_rows.append((row, raw, key))
            continue
        if kind == ARTIFACT_CONTRACT:
            contract_rows.append((row, raw, key))
            continue
        if kind == ARTIFACT_TRANSACTION_OBSERVATION:
            transaction_observation_rows.append((row, raw, key))
            continue
        if kind == ARTIFACT_TRANSACTION_TRACE:
            transaction_trace_rows.append((row, raw, key))
            continue
        if kind == ARTIFACT_MONEY_OBSERVATION:
            money_rows.append((row, raw, key))
            continue
        if kind == ARTIFACT_TRANSITION:
            transition_rows.append((row, raw, key))
            continue
        if kind == ARTIFACT_STATE_VALUE:
            state_value_rows.append((row, raw, key))
            continue
        if kind == ARTIFACT_QUALIFICATION:
            qualification_rows.append((row, raw, key))

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

    # Qualification transitions are normalized before the event-chain pass,
    # but their predecessor legality is rechecked here from the independently
    # stored predecessor bytes.  This keeps the producer's candidate builder
    # from being an authority and makes restore/reopen verify the same chain.
    for row, raw, key in sorted(qualification_rows, key=lambda item: int(event_sequence_hint.get(item[2], 0))):
        artifact = artifacts.get(key)
        if artifact is None:
            raise IndependentStoreError("database:qualification-artifact")
        prior_raw = None
        prior_id = artifact["prior_artifact_id"]
        if prior_id is not None:
            prior_key = (ARTIFACT_QUALIFICATION, str(prior_id))
            prior_raw = raw_by_key.get(prior_key)
            current_sequence = event_sequence_hint.get(key)
            prior_sequence = event_sequence_hint.get(prior_key)
            if prior_raw is None or current_sequence is None or prior_sequence is None or prior_sequence >= current_sequence:
                raise IndependentStoreError("database:qualification-prior-order")
        try:
            qualification_independent.verify_artifact(raw, prior_raw=prior_raw)
        except qualification_independent.IndependentQualificationError as exc:
            raise IndependentStoreError("database:qualification-reject") from exc

    # A source artifact may point at exactly one graph artifact.  Re-run the
    # full source-to-graph binding here with the independently stored graph
    # bytes; the source artifact's own link fields are not authority by
    # themselves.
    for artifact in artifacts.values():
        if artifact["kind"] != ARTIFACT_SOURCE_EVIDENCE:
            continue
        linked_id = artifact.get("linked_graph_artifact_id")
        if linked_id is None:
            continue
        linked = artifacts.get((ARTIFACT_GRAPH, str(linked_id)))
        if linked is None:
            raise IndependentStoreError("database:source-graph-missing")
        if linked["payload_hash"] != artifact.get("linked_graph_payload_hash") or linked.get("report_id") != artifact.get("linked_graph_report_id"):
            raise IndependentStoreError("database:source-graph-link")
        try:
            source_independent.verify_artifact(
                artifact["payload"],
                graph_raw=linked["payload"],
                graph_profile_registry=graph_profile_registry,
            )
        except Exception as exc:
            raise IndependentStoreError("database:source-graph-binding") from exc

    # Denominator artifacts are checked only after their source, optional
    # graph, and governing approval bytes have been independently normalized.
    # The denominator payload carries labels for audit, but those labels are
    # never used as authority without reconstructing the named rows here.
    for row, raw, key in sorted(denominator_rows, key=lambda item: int(event_sequence_hint.get(item[2], 0))):
        try:
            value = denominator_independent._parse(raw)
            source_binding = value["source_binding"]
            governance_binding = value["governance_binding"]
            if not isinstance(source_binding, dict) or not isinstance(governance_binding, dict):
                raise IndependentStoreError("database:denominator-binding")
            source_key = (ARTIFACT_SOURCE_EVIDENCE, str(source_binding["artifact_id"]))
            source_artifact = artifacts.get(source_key)
            if source_artifact is None or source_artifact["current_stage_id"] != source_binding["stage_id"]:
                raise IndependentStoreError("database:denominator-source")
            graph_id = source_binding.get("graph_artifact_id")
            graph_artifact = None
            if graph_id is not None:
                graph_artifact = artifacts.get((ARTIFACT_GRAPH, str(graph_id)))
                if graph_artifact is None:
                    raise IndependentStoreError("database:denominator-graph")
                if graph_artifact["current_stage_id"] != source_binding.get("graph_stage_id"):
                    raise IndependentStoreError("database:denominator-graph-stage")
            governance_key = (ARTIFACT_GOVERNANCE, str(governance_binding["artifact_id"]))
            governance_artifact = artifacts.get(governance_key)
            if governance_artifact is None or governance_artifact["current_stage_id"] != governance_binding["stage_id"]:
                raise IndependentStoreError("database:denominator-governance")
            prior_raw = None
            prior_id = value.get("prior_artifact_id")
            if prior_id is not None:
                prior_key = (ARTIFACT_DENOMINATOR, str(prior_id))
                if prior_key not in raw_by_key:
                    raise IndependentStoreError("database:denominator-prior")
                prior_raw = raw_by_key[prior_key]
                if prior_key not in artifacts:
                    raise IndependentStoreError("database:denominator-prior-order")
            context = {
                "source_raw": raw_by_key[source_key],
                "graph_raw": graph_artifact["payload"] if graph_artifact is not None else None,
                "governance_raw": governance_artifact["payload"],
                "prior_denominator_raw": prior_raw,
            }
            artifact = _normalize_artifact(
                ARTIFACT_DENOMINATOR,
                raw,
                graph_profile_registry=graph_profile_registry,
                denominator_context=context,
            )
        except IndependentStoreError:
            raise
        except Exception as exc:
            raise IndependentStoreError("database:denominator-context") from exc
        for field in ("artifact_id", "payload_hash", "artifact_schema", "report_id", "current_stage_id", "transition_id", "prior_artifact_id", "prior_stage_id", "subject", "scope", "stage_kind", "authority_json"):
            stored = row[field]
            expected = artifact[field] if field != "artifact_schema" else artifact["schema"]
            if stored != expected:
                raise IndependentStoreError(f"database:artifact-{field}")
        hash_key = (ARTIFACT_DENOMINATOR, str(row["payload_hash"]))
        if hash_key in artifact_hashes:
            raise IndependentStoreError("database:artifact-hash-duplicate")
        artifact_hashes.add(hash_key)
        artifacts[key] = artifact

    # Reconciliation artifacts are verified only after all source and graph
    # payloads are available.  Their carried labels are not authority: the
    # verifier reconstructs each custody context from the independently stored
    # source/graph bytes and then checks the transition binding.
    for row, raw, key in reconciliation_rows:
        try:
            value = reconciliation_independent._parse(raw)
            current_summary = value["current_custody"]
            if not isinstance(current_summary, dict):
                raise IndependentStoreError("database:reconciliation-current")
            current_key = (ARTIFACT_SOURCE_EVIDENCE, str(current_summary["artifact_id"]))
            current = artifacts.get(current_key)
            if current is None or current["current_stage_id"] != current_summary["stage_id"]:
                raise IndependentStoreError("database:reconciliation-current-custody")
            predecessor_id = current.get("prior_artifact_id")
            predecessor_stage = current.get("prior_stage_id")
            predecessor = None
            if predecessor_id is not None:
                predecessor = artifacts.get((ARTIFACT_SOURCE_EVIDENCE, str(predecessor_id)))
                if predecessor is None or predecessor["current_stage_id"] != predecessor_stage:
                    raise IndependentStoreError("database:reconciliation-predecessor-custody")
            current_graph = artifacts.get((ARTIFACT_GRAPH, str(current["linked_graph_artifact_id"]))) if current.get("linked_graph_artifact_id") is not None else None
            prior_graph = artifacts.get((ARTIFACT_GRAPH, str(predecessor["linked_graph_artifact_id"]))) if predecessor is not None and predecessor.get("linked_graph_artifact_id") is not None else None
            prior_reconciliation_raw = None
            prior_reconciliation_id = value.get("prior_artifact_id")
            if prior_reconciliation_id is not None:
                prior_reconciliation_raw = raw_by_key.get((ARTIFACT_RECONCILIATION, str(prior_reconciliation_id)))
                if prior_reconciliation_raw is None:
                    raise IndependentStoreError("database:reconciliation-prior")
            anchors = reconciliation_independent._validate_anchors(value.get("anchors"))
            context_anchors = anchors
            if prior_reconciliation_raw is not None:
                prior_value = reconciliation_independent._parse(prior_reconciliation_raw)
                context_anchors = reconciliation_independent._validate_anchors(prior_value.get("anchors"))
            anchor_raws: dict[str, bytes | None] = {}
            for anchor_name in ("qualified_content_baseline", "chronology_anchor"):
                anchor = context_anchors[anchor_name]
                if anchor is None:
                    anchor_raws[anchor_name] = None
                    continue
                anchor_key = (ARTIFACT_SOURCE_EVIDENCE, str(anchor["custody_artifact_id"]))
                anchor_artifact = artifacts.get(anchor_key)
                if anchor_artifact is None or anchor_artifact["current_stage_id"] != anchor["custody_stage_id"]:
                    raise IndependentStoreError(f"database:reconciliation-{anchor_name}")
                anchor_raws[anchor_name] = raw_by_key[anchor_key]
            context = {
                "current_custody_raw": raw_by_key[current_key],
                "prior_custody_raw": raw_by_key[(ARTIFACT_SOURCE_EVIDENCE, str(predecessor_id))] if predecessor_id is not None else None,
                "current_graph_raw": current_graph["payload"] if current_graph is not None else None,
                "prior_graph_raw": prior_graph["payload"] if prior_graph is not None else None,
                "prior_reconciliation_raw": prior_reconciliation_raw,
                "qualified_baseline_custody_raw": anchor_raws["qualified_content_baseline"],
                "chronology_anchor_custody_raw": anchor_raws["chronology_anchor"],
            }
            artifact = _normalize_artifact(
                ARTIFACT_RECONCILIATION,
                raw,
                graph_profile_registry=graph_profile_registry,
                reconciliation_context=context,
            )
        except IndependentStoreError:
            raise
        except Exception as exc:
            raise IndependentStoreError("database:reconciliation-context") from exc
        for field in ("artifact_id", "payload_hash", "artifact_schema", "report_id", "current_stage_id", "transition_id", "prior_artifact_id", "prior_stage_id", "subject", "scope", "stage_kind", "authority_json"):
            stored = row[field]
            expected = artifact[field] if field != "artifact_schema" else artifact["schema"]
            if stored != expected:
                raise IndependentStoreError(f"database:artifact-{field}")
        hash_key = (ARTIFACT_RECONCILIATION, str(row["payload_hash"]))
        if hash_key in artifact_hashes:
            raise IndependentStoreError("database:artifact-hash-duplicate")
        artifact_hashes.add(hash_key)
        artifacts[key] = artifact

    # Cases are processed after graph/source/reconciliation rows are available.
    # Their governance selection is based on the event sequence that will be
    # checked again by the complete event-chain verifier below.
    for row, raw, key in case_rows:
        try:
            context = _case_context(
                artifacts,
                raw_by_key,
                event_sequence_hint,
                raw,
                graph_profile_registry,
            )
            artifact = _normalize_artifact(
                ARTIFACT_CASE,
                raw,
                graph_profile_registry=graph_profile_registry,
                reconciliation_context=context,
            )
        except IndependentStoreError:
            raise
        except Exception as exc:
            raise IndependentStoreError("database:case-context") from exc
        for field in ("artifact_id", "payload_hash", "artifact_schema", "report_id", "current_stage_id", "transition_id", "prior_artifact_id", "prior_stage_id", "subject", "scope", "stage_kind", "authority_json"):
            stored = row[field]
            expected = artifact[field] if field != "artifact_schema" else artifact["schema"]
            if stored != expected:
                raise IndependentStoreError(f"database:artifact-{field}")
        hash_key = (ARTIFACT_CASE, str(row["payload_hash"]))
        if hash_key in artifact_hashes:
            raise IndependentStoreError("database:artifact-hash-duplicate")
        artifact_hashes.add(hash_key)
        artifacts[key] = artifact

    # Contract artifacts are checked only after their denominator and case
    # bytes have been independently reconstructed.  The carried IDs are
    # labels; the context loader above selects and verifies the actual rows.
    for row, raw, key in sorted(contract_rows, key=lambda item: int(event_sequence_hint.get(item[2], 0))):
        try:
            context = _contract_context(
                artifacts,
                raw_by_key,
                event_sequence_hint,
                raw,
                graph_profile_registry,
            )
            artifact = _normalize_artifact(
                ARTIFACT_CONTRACT,
                raw,
                graph_profile_registry=graph_profile_registry,
                contract_context=context,
            )
        except IndependentStoreError:
            raise
        except Exception as exc:
            raise IndependentStoreError("database:contract-context") from exc
        for field in ("artifact_id", "payload_hash", "artifact_schema", "report_id", "current_stage_id", "transition_id", "prior_artifact_id", "prior_stage_id", "subject", "scope", "stage_kind", "authority_json"):
            stored = row[field]
            expected = artifact[field] if field != "artifact_schema" else artifact["schema"]
            if stored != expected:
                raise IndependentStoreError(f"database:artifact-{field}")
        hash_key = (ARTIFACT_CONTRACT, str(row["payload_hash"]))
        if hash_key in artifact_hashes:
            raise IndependentStoreError("database:artifact-hash-duplicate")
        artifact_hashes.add(hash_key)
        artifacts[key] = artifact

    # Transaction boundary observations and traces are reconstructed only
    # after Contract Mirror and all of its source/case dependencies exist.
    # Their carried bindings are labels; the independent verifier receives the
    # exact stored upstream bytes selected here.
    for row, raw, key in sorted(transaction_observation_rows, key=lambda item: int(event_sequence_hint.get(item[2], 0))):
        try:
            context = _transaction_context(
                artifacts,
                raw_by_key,
                event_sequence_hint,
                raw,
                graph_profile_registry,
            )
            artifact = _normalize_artifact(
                ARTIFACT_TRANSACTION_OBSERVATION,
                raw,
                graph_profile_registry=graph_profile_registry,
                transaction_context=context,
            )
        except IndependentStoreError:
            raise
        except Exception as exc:
            raise IndependentStoreError("database:transaction-observation-context") from exc
        for field in ("artifact_id", "payload_hash", "artifact_schema", "report_id", "current_stage_id", "transition_id", "prior_artifact_id", "prior_stage_id", "subject", "scope", "stage_kind", "authority_json"):
            stored = row[field]
            expected = artifact[field] if field != "artifact_schema" else artifact["schema"]
            if stored != expected:
                raise IndependentStoreError(f"database:artifact-{field}")
        hash_key = (ARTIFACT_TRANSACTION_OBSERVATION, str(row["payload_hash"]))
        if hash_key in artifact_hashes:
            raise IndependentStoreError("database:artifact-hash-duplicate")
        artifact_hashes.add(hash_key)
        artifacts[key] = artifact

    for row, raw, key in sorted(transaction_trace_rows, key=lambda item: int(event_sequence_hint.get(item[2], 0))):
        try:
            context = _transaction_context(
                artifacts,
                raw_by_key,
                event_sequence_hint,
                raw,
                graph_profile_registry,
            )
            artifact = _normalize_artifact(
                ARTIFACT_TRANSACTION_TRACE,
                raw,
                graph_profile_registry=graph_profile_registry,
                transaction_context=context,
            )
        except IndependentStoreError:
            raise
        except Exception as exc:
            raise IndependentStoreError("database:transaction-trace-context") from exc
        for field in ("artifact_id", "payload_hash", "artifact_schema", "report_id", "current_stage_id", "transition_id", "prior_artifact_id", "prior_stage_id", "subject", "scope", "stage_kind", "authority_json"):
            stored = row[field]
            expected = artifact[field] if field != "artifact_schema" else artifact["schema"]
            if stored != expected:
                raise IndependentStoreError(f"database:artifact-{field}")
        hash_key = (ARTIFACT_TRANSACTION_TRACE, str(row["payload_hash"]))
        if hash_key in artifact_hashes:
            raise IndependentStoreError("database:artifact-hash-duplicate")
        artifact_hashes.add(hash_key)
        artifacts[key] = artifact

    # Money observations are derived from a stored Transaction Trace and are
    # checked only after the complete transaction ancestry is available.  The
    # money payload's selector and amount fields are labels; this pass supplies
    # the exact stored bytes to the independent verifier.
    for row, raw, key in sorted(money_rows, key=lambda item: int(event_sequence_hint.get(item[2], 0))):
        try:
            context = _money_context(
                artifacts,
                raw_by_key,
                event_sequence_hint,
                raw,
                graph_profile_registry,
            )
            artifact = _normalize_artifact(
                ARTIFACT_MONEY_OBSERVATION,
                raw,
                graph_profile_registry=graph_profile_registry,
                transaction_context=context,
            )
        except IndependentStoreError:
            raise
        except Exception as exc:
            raise IndependentStoreError("database:money-context") from exc
        for field in ("artifact_id", "payload_hash", "artifact_schema", "report_id", "current_stage_id", "transition_id", "prior_artifact_id", "prior_stage_id", "subject", "scope", "stage_kind", "authority_json"):
            stored = row[field]
            expected = artifact[field] if field != "artifact_schema" else artifact["schema"]
            if stored != expected:
                raise IndependentStoreError(f"database:artifact-{field}")
        hash_key = (ARTIFACT_MONEY_OBSERVATION, str(row["payload_hash"]))
        if hash_key in artifact_hashes:
            raise IndependentStoreError("database:artifact-hash-duplicate")
        artifact_hashes.add(hash_key)
        artifacts[key] = artifact

    # Transition comparisons are derived from the exact stored Money bytes.
    # The lane labels and comparison summaries are independently reconstructed;
    # no producer acceptance flag is used as authority.
    for row, raw, key in sorted(transition_rows, key=lambda item: int(event_sequence_hint.get(item[2], 0))):
        try:
            context = _transition_context(
                artifacts,
                raw_by_key,
                event_sequence_hint,
                raw,
                graph_profile_registry,
            )
            artifact = _normalize_artifact(
                ARTIFACT_TRANSITION,
                raw,
                graph_profile_registry=graph_profile_registry,
                transition_context=context,
            )
        except IndependentStoreError:
            raise
        except Exception as exc:
            raise IndependentStoreError("database:transition-context") from exc
        for field in ("artifact_id", "payload_hash", "artifact_schema", "report_id", "current_stage_id", "transition_id", "prior_artifact_id", "prior_stage_id", "subject", "scope", "stage_kind", "authority_json"):
            stored = row[field]
            expected = artifact[field] if field != "artifact_schema" else artifact["schema"]
            if stored != expected:
                raise IndependentStoreError(f"database:artifact-{field}")
        hash_key = (ARTIFACT_TRANSITION, str(row["payload_hash"]))
        if hash_key in artifact_hashes:
            raise IndependentStoreError("database:artifact-hash-duplicate")
        artifact_hashes.add(hash_key)
        artifacts[key] = artifact

    # State Value artifacts consume the exact stored Money/Contract/Denominator/
    # Transaction/governance bytes above, plus an optional current Transition
    # artifact.  Their own predecessor is reconstructed from this same state
    # map before the event-chain pass checks head order.
    for row, raw, key in sorted(state_value_rows, key=lambda item: int(event_sequence_hint.get(item[2], 0))):
        try:
            context = _state_value_context(
                artifacts,
                raw_by_key,
                event_sequence_hint,
                raw,
                graph_profile_registry,
            )
            artifact = _normalize_artifact(
                ARTIFACT_STATE_VALUE,
                raw,
                graph_profile_registry=graph_profile_registry,
                state_value_context=context,
            )
        except IndependentStoreError:
            raise
        except Exception as exc:
            raise IndependentStoreError("database:state-value-context") from exc
        for field in ("artifact_id", "payload_hash", "artifact_schema", "report_id", "current_stage_id", "transition_id", "prior_artifact_id", "prior_stage_id", "subject", "scope", "stage_kind", "authority_json"):
            stored = row[field]
            expected = artifact[field] if field != "artifact_schema" else artifact["schema"]
            if stored != expected:
                raise IndependentStoreError(f"database:artifact-{field}")
        hash_key = (ARTIFACT_STATE_VALUE, str(row["payload_hash"]))
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
    artifact_event_sequence: dict[tuple[str, str], int] = {}
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
        artifact_event_sequence[(artifact["kind"], artifact["artifact_id"])] = sequence
        previous_event_root = event["event_root"]

    if set(operations) != seen_operations:
        raise IndependentStoreError("database:orphan-operation")

    # A transaction observation must follow its independently stored source
    # custody and Contract Mirror bytes.  A trace must follow its observation
    # and the same upstream bytes.  These checks make phase ancestry and
    # correction/appeal ordering independent of the producer's labels.
    for transaction_artifact in artifacts.values():
        if transaction_artifact["kind"] not in (ARTIFACT_TRANSACTION_OBSERVATION, ARTIFACT_TRANSACTION_TRACE):
            continue
        transaction_key = (transaction_artifact["kind"], str(transaction_artifact["artifact_id"]))
        transaction_sequence = artifact_event_sequence.get(transaction_key)
        if transaction_sequence is None:
            raise IndependentStoreError("database:transaction-event")
        value = transaction_independent._parse(transaction_artifact["payload"])
        contract_id = str(value["contract_binding"]["artifact_id"])
        contract_sequence = artifact_event_sequence.get((ARTIFACT_CONTRACT, contract_id))
        if contract_sequence is None or contract_sequence >= transaction_sequence:
            raise IndependentStoreError("database:transaction-contract-order")
        source_id = str(value["input_binding"]["artifact_id"] if value["schema"] == transaction_independent.TRACE_SCHEMA else value["source_binding"]["artifact_id"])
        source_sequence = artifact_event_sequence.get((ARTIFACT_SOURCE_EVIDENCE, source_id))
        if source_sequence is None or source_sequence >= transaction_sequence:
            raise IndependentStoreError("database:transaction-source-order")
        prior_id = value.get("prior_artifact_id")
        if prior_id is not None:
            prior_kind = ARTIFACT_TRANSACTION_OBSERVATION if value["schema"] == transaction_independent.OBSERVATION_SCHEMA else ARTIFACT_TRANSACTION_TRACE
            prior_sequence = artifact_event_sequence.get((prior_kind, str(prior_id)))
            if prior_sequence is None or prior_sequence >= transaction_sequence:
                raise IndependentStoreError("database:transaction-prior-order")
        if value["schema"] == transaction_independent.TRACE_SCHEMA:
            observation_id = str(value["observation_binding"]["artifact_id"])
            observation_sequence = artifact_event_sequence.get((ARTIFACT_TRANSACTION_OBSERVATION, observation_id))
            if observation_sequence is None or observation_sequence >= transaction_sequence:
                raise IndependentStoreError("database:transaction-observation-order")
            if value["case_link"] is not None:
                case_id = str(value["case_link"]["artifact_id"])
                case_sequence = artifact_event_sequence.get((ARTIFACT_CASE, case_id))
                if case_sequence is None or case_sequence >= transaction_sequence:
                    raise IndependentStoreError("database:transaction-case-order")

    # Money observations may only follow the exact Transaction Trace they
    # bind.  A prior money stage must be the current head at the append point;
    # a divergence routes to the existing discrepancy case rather than making
    # a second case authority.
    for money_artifact in artifacts.values():
        if money_artifact["kind"] != ARTIFACT_MONEY_OBSERVATION:
            continue
        money_key = (ARTIFACT_MONEY_OBSERVATION, str(money_artifact["artifact_id"]))
        money_sequence = artifact_event_sequence.get(money_key)
        if money_sequence is None:
            raise IndependentStoreError("database:money-event")
        value = money_independent._parse(money_artifact["payload"])
        binding = value["transaction_binding"]
        trace_key = (ARTIFACT_TRANSACTION_TRACE, str(binding["trace_artifact_id"]))
        trace_sequence = artifact_event_sequence.get(trace_key)
        if trace_sequence is None or trace_sequence >= money_sequence:
            raise IndependentStoreError("database:money-trace-order")
        trace_artifact = artifacts.get(trace_key)
        if trace_artifact is None or trace_artifact["current_stage_id"] != binding["trace_stage_id"]:
            raise IndependentStoreError("database:money-trace-binding")
        if value["prior_artifact_id"] is None:
            if value["fixture_id"] not in money_independent.INITIAL_FIXTURES:
                raise IndependentStoreError("database:money-missing-prior")
        else:
            prior_key = (ARTIFACT_MONEY_OBSERVATION, str(value["prior_artifact_id"]))
            prior = artifacts.get(prior_key)
            prior_sequence = artifact_event_sequence.get(prior_key)
            if prior is None or prior_sequence is None or prior_sequence >= money_sequence or prior["current_stage_id"] != value["prior_stage_id"]:
                raise IndependentStoreError("database:money-prior-order")
            money_chain = _chain_id(ARTIFACT_MONEY_OBSERVATION, str(prior["subject"]), str(prior["scope"]), prior.get("profile_id"))
            prior_head_at_append: Mapping[str, object] | None = None
            for sequence in range(1, money_sequence):
                event = events.get(sequence)
                if event is not None and event["chain_id"] == money_chain:
                    prior_head_at_append = artifacts.get((ARTIFACT_MONEY_OBSERVATION, str(event["artifact_id"])))
            if prior_head_at_append is None or prior_head_at_append["artifact_id"] != prior["artifact_id"] or prior_head_at_append["current_stage_id"] != prior["current_stage_id"]:
                raise IndependentStoreError("database:money-prior-not-head")
        if value["case_link"] is not None:
            case_id = str(value["case_link"]["artifact_id"])
            case_sequence = artifact_event_sequence.get((ARTIFACT_CASE, case_id))
            if case_sequence is None or case_sequence >= money_sequence:
                raise IndependentStoreError("database:money-case-order")

    # Transition comparisons consume the current Money head and form their own
    # append-only chain.  The existing event/head verifier owns atomic order;
    # these checks bind the comparison to the exact upstream evidence it names.
    for transition_artifact in artifacts.values():
        if transition_artifact["kind"] != ARTIFACT_TRANSITION:
            continue
        transition_key = (ARTIFACT_TRANSITION, str(transition_artifact["artifact_id"]))
        transition_sequence = artifact_event_sequence.get(transition_key)
        if transition_sequence is None:
            raise IndependentStoreError("database:transition-event")
        value = transition_independent._parse(transition_artifact["payload"])
        money_id = str(value["shared_binding"]["money"]["artifact_id"])
        money_key = (ARTIFACT_MONEY_OBSERVATION, money_id)
        money_sequence = artifact_event_sequence.get(money_key)
        if money_sequence is None or money_sequence >= transition_sequence:
            raise IndependentStoreError("database:transition-money-order")
        money_artifact = artifacts.get(money_key)
        if money_artifact is None or money_artifact["current_stage_id"] != value["shared_binding"]["money"]["stage_id"]:
            raise IndependentStoreError("database:transition-money-binding")
        money_chain = _chain_id(ARTIFACT_MONEY_OBSERVATION, str(money_artifact["subject"]), str(money_artifact["scope"]), money_artifact.get("profile_id"))
        money_head_at_append: Mapping[str, object] | None = None
        for sequence in range(1, transition_sequence):
            event = events.get(sequence)
            if event is not None and event["chain_id"] == money_chain:
                money_head_at_append = artifacts.get((ARTIFACT_MONEY_OBSERVATION, str(event["artifact_id"])))
        if money_head_at_append is None or money_head_at_append["artifact_id"] != money_artifact["artifact_id"] or money_head_at_append["current_stage_id"] != money_artifact["current_stage_id"]:
            raise IndependentStoreError("database:transition-money-not-head")
        if value["prior_artifact_id"] is None:
            if value["stage_kind"] != transition_independent.STAGE_COMPARED:
                raise IndependentStoreError("database:transition-missing-prior")
        else:
            prior_key = (ARTIFACT_TRANSITION, str(value["prior_artifact_id"]))
            prior = artifacts.get(prior_key)
            prior_sequence = artifact_event_sequence.get(prior_key)
            if prior is None or prior_sequence is None or prior_sequence >= transition_sequence or prior["current_stage_id"] != value["prior_stage_id"]:
                raise IndependentStoreError("database:transition-prior-order")
            transition_chain = _chain_id(ARTIFACT_TRANSITION, str(prior["subject"]), str(prior["scope"]), prior.get("profile_id"))
            prior_head_at_append: Mapping[str, object] | None = None
            for sequence in range(1, transition_sequence):
                event = events.get(sequence)
                if event is not None and event["chain_id"] == transition_chain:
                    prior_head_at_append = artifacts.get((ARTIFACT_TRANSITION, str(event["artifact_id"])))
            if prior_head_at_append is None or prior_head_at_append["artifact_id"] != prior["artifact_id"] or prior_head_at_append["current_stage_id"] != prior["current_stage_id"]:
                raise IndependentStoreError("database:transition-prior-not-head")
        case_link = value["discrepancy"]["case_link"]
        if case_link is not None:
            case_sequence = artifact_event_sequence.get((ARTIFACT_CASE, str(case_link["artifact_id"])))
            if case_sequence is None or case_sequence >= transition_sequence:
                raise IndependentStoreError("database:transition-case-order")

    # State Value observations consume the current Money head and any named
    # optional Transition head.  Their own predecessor is the current value
    # head, so an old snapshot cannot be rebound into a second counting chain.
    for state_value_artifact in artifacts.values():
        if state_value_artifact["kind"] != ARTIFACT_STATE_VALUE:
            continue
        state_value_key = (ARTIFACT_STATE_VALUE, str(state_value_artifact["artifact_id"]))
        state_value_sequence = artifact_event_sequence.get(state_value_key)
        if state_value_sequence is None:
            raise IndependentStoreError("database:state-value-event")
        value = state_value_independent._parse(state_value_artifact["payload"])
        for entry in value["entries"]:
            upstream = entry["upstream"]
            for kind, reference in (
                (ARTIFACT_MONEY_OBSERVATION, upstream["money"]),
                (ARTIFACT_TRANSACTION_TRACE, upstream["transaction"]),
                (ARTIFACT_CONTRACT, upstream["contract"]),
                (ARTIFACT_DENOMINATOR, upstream["denominator"]),
                (ARTIFACT_GOVERNANCE, upstream["governance"]),
            ):
                artifact_id = str(reference["artifact_id"])
                upstream_key = (kind, artifact_id)
                upstream_artifact = artifacts.get(upstream_key)
                upstream_sequence = artifact_event_sequence.get(upstream_key)
                if upstream_artifact is None or upstream_sequence is None or upstream_sequence >= state_value_sequence:
                    raise IndependentStoreError("database:state-value-upstream-order")
                if upstream_artifact["current_stage_id"] != reference["stage_id"]:
                    raise IndependentStoreError("database:state-value-upstream-stage")
            money_id = str(upstream["money"]["artifact_id"])
            money_artifact = artifacts[(ARTIFACT_MONEY_OBSERVATION, money_id)]
            money_chain = _chain_id(ARTIFACT_MONEY_OBSERVATION, str(money_artifact["subject"]), str(money_artifact["scope"]), money_artifact.get("profile_id"))
            money_head_at_append: Mapping[str, object] | None = None
            for sequence in range(1, state_value_sequence):
                event = events.get(sequence)
                if event is not None and event["chain_id"] == money_chain:
                    money_head_at_append = artifacts.get((ARTIFACT_MONEY_OBSERVATION, str(event["artifact_id"])))
            if money_head_at_append is None or money_head_at_append["artifact_id"] != money_artifact["artifact_id"] or money_head_at_append["current_stage_id"] != money_artifact["current_stage_id"]:
                raise IndependentStoreError("database:state-value-money-not-head")
            transition_ref = upstream.get("transition")
            if transition_ref is not None:
                transition_id = str(transition_ref["artifact_id"])
                transition_artifact = artifacts.get((ARTIFACT_TRANSITION, transition_id))
                transition_sequence = artifact_event_sequence.get((ARTIFACT_TRANSITION, transition_id))
                if transition_artifact is None or transition_sequence is None or transition_sequence >= state_value_sequence:
                    raise IndependentStoreError("database:state-value-transition-order")
                if transition_artifact["current_stage_id"] != transition_ref["stage_id"]:
                    raise IndependentStoreError("database:state-value-transition-stage")
                transition_chain = _chain_id(ARTIFACT_TRANSITION, str(transition_artifact["subject"]), str(transition_artifact["scope"]), transition_artifact.get("profile_id"))
                transition_head_at_append: Mapping[str, object] | None = None
                for sequence in range(1, state_value_sequence):
                    event = events.get(sequence)
                    if event is not None and event["chain_id"] == transition_chain:
                        transition_head_at_append = artifacts.get((ARTIFACT_TRANSITION, str(event["artifact_id"])))
                if transition_head_at_append is None or transition_head_at_append["artifact_id"] != transition_artifact["artifact_id"] or transition_head_at_append["current_stage_id"] != transition_artifact["current_stage_id"]:
                    raise IndependentStoreError("database:state-value-transition-not-head")
        prior_id = value.get("prior_artifact_id")
        if prior_id is None:
            if value["stage_kind"] != state_value_independent.STAGE_OBSERVED:
                raise IndependentStoreError("database:state-value-missing-prior")
        else:
            prior_key = (ARTIFACT_STATE_VALUE, str(prior_id))
            prior = artifacts.get(prior_key)
            prior_sequence = artifact_event_sequence.get(prior_key)
            if prior is None or prior_sequence is None or prior_sequence >= state_value_sequence or prior["current_stage_id"] != value["prior_stage_id"]:
                raise IndependentStoreError("database:state-value-prior-order")
            state_chain = _chain_id(ARTIFACT_STATE_VALUE, str(prior["subject"]), str(prior["scope"]), prior.get("profile_id"))
            prior_head_at_append: Mapping[str, object] | None = None
            for sequence in range(1, state_value_sequence):
                event = events.get(sequence)
                if event is not None and event["chain_id"] == state_chain:
                    prior_head_at_append = artifacts.get((ARTIFACT_STATE_VALUE, str(event["artifact_id"])))
            if prior_head_at_append is None or prior_head_at_append["artifact_id"] != prior["artifact_id"] or prior_head_at_append["current_stage_id"] != prior["current_stage_id"]:
                raise IndependentStoreError("database:state-value-prior-not-head")
            if value["stage_kind"] != state_value_independent.STAGE_RECALCULATED:
                raise IndependentStoreError("database:state-value-prior-stage")

    # A case may only be appended after every evidence and governance byte it
    # names.  This is separate from the generic case-chain head check: the
    # case chain owns lifecycle ordering, while these checks own evidence
    # ordering and prevent a future-dated or rebound case from becoming a
    # second authority.
    for case_artifact in artifacts.values():
        if case_artifact["kind"] != ARTIFACT_CASE:
            continue
        case_key = (ARTIFACT_CASE, str(case_artifact["artifact_id"]))
        case_sequence = artifact_event_sequence.get(case_key)
        if case_sequence is None:
            raise IndependentStoreError("database:case-event")
        case_value = case_independent._parse(case_artifact["payload"])
        upstream = case_value["upstream"]
        for artifact_kind, artifact_id in (
            (ARTIFACT_GRAPH, upstream["graph"]["artifact_id"]),
            (ARTIFACT_RECONCILIATION, upstream["reconciliation"]["artifact_id"]),
        ):
            upstream_sequence = artifact_event_sequence.get((artifact_kind, str(artifact_id)))
            if upstream_sequence is None or upstream_sequence >= case_sequence:
                raise IndependentStoreError("database:case-upstream-order")
        graph_sequence = artifact_event_sequence[(ARTIFACT_GRAPH, str(upstream["graph"]["artifact_id"]))]
        governance_sequence = artifact_event_sequence.get((ARTIFACT_GOVERNANCE, str(upstream["graph"]["governance_artifact_id"])))
        if governance_sequence is None or governance_sequence >= graph_sequence:
            raise IndependentStoreError("database:case-governance-order")
        retest_id = case_value["retest"].get("reconciliation_artifact_id")
        if retest_id is not None:
            retest_sequence = artifact_event_sequence.get((ARTIFACT_RECONCILIATION, str(retest_id)))
            if retest_sequence is None or retest_sequence >= case_sequence:
                raise IndependentStoreError("database:case-retest-order")

    # A reconciliation transition may only consume the current source head at
    # the moment its own event is committed.  This prevents a late replay from
    # becoming a second temporal authority while still preserving the source
    # custody artifact as durable evidence.
    for reconciliation_artifact in artifacts.values():
        if reconciliation_artifact["kind"] != ARTIFACT_RECONCILIATION:
            continue
        reconciliation_sequence = artifact_event_sequence.get((ARTIFACT_RECONCILIATION, str(reconciliation_artifact["artifact_id"])))
        current_id = reconciliation_artifact.get("current_custody_artifact_id")
        current_key = (ARTIFACT_SOURCE_EVIDENCE, str(current_id))
        current_source = artifacts.get(current_key)
        current_sequence = artifact_event_sequence.get(current_key)
        if reconciliation_sequence is None or current_source is None or current_sequence is None or current_sequence >= reconciliation_sequence:
            raise IndependentStoreError("database:reconciliation-event-order")
        source_chain = _chain_id(
            ARTIFACT_SOURCE_EVIDENCE,
            str(current_source["subject"]),
            str(current_source["scope"]),
            current_source.get("profile_id"),
        )
        source_events_before = [
            sequence
            for key, sequence in artifact_event_sequence.items()
            if key[0] == ARTIFACT_SOURCE_EVIDENCE
            and sequence < reconciliation_sequence
            and _chain_id(
                ARTIFACT_SOURCE_EVIDENCE,
                str(artifacts[key]["subject"]),
                str(artifacts[key]["scope"]),
                artifacts[key].get("profile_id"),
            ) == source_chain
        ]
        if not source_events_before or max(source_events_before) != current_sequence:
            raise IndependentStoreError("database:reconciliation-source-not-head")
        for anchor_field in ("qualified_baseline_custody_artifact_id", "chronology_anchor_custody_artifact_id"):
            anchor_id = reconciliation_artifact.get(anchor_field)
            if anchor_id is None:
                continue
            anchor_key = (ARTIFACT_SOURCE_EVIDENCE, str(anchor_id))
            anchor_artifact = artifacts.get(anchor_key)
            anchor_sequence = artifact_event_sequence.get(anchor_key)
            if anchor_artifact is None or anchor_sequence is None or anchor_sequence >= reconciliation_sequence:
                raise IndependentStoreError("database:reconciliation-anchor-order")
            if _chain_id(
                ARTIFACT_SOURCE_EVIDENCE,
                str(anchor_artifact["subject"]),
                str(anchor_artifact["scope"]),
                anchor_artifact.get("profile_id"),
            ) != source_chain:
                raise IndependentStoreError("database:reconciliation-anchor-profile")
        predecessor_id = reconciliation_artifact.get("predecessor_custody_artifact_id")
        if predecessor_id is not None:
            predecessor_key = (ARTIFACT_SOURCE_EVIDENCE, str(predecessor_id))
            predecessor = artifacts.get(predecessor_key)
            if predecessor is None or artifact_event_sequence.get(predecessor_key, 0) >= current_sequence:
                raise IndependentStoreError("database:reconciliation-predecessor-order")
        prior_reconciliation_id = reconciliation_artifact.get("prior_artifact_id")
        if prior_reconciliation_id is None:
            if predecessor_id is not None:
                raise IndependentStoreError("database:reconciliation-missing-prior")
        else:
            prior_reconciliation = artifacts.get((ARTIFACT_RECONCILIATION, str(prior_reconciliation_id)))
            if prior_reconciliation is None or prior_reconciliation.get("current_custody_artifact_id") != predecessor_id:
                raise IndependentStoreError("database:reconciliation-prior-binding")
            if artifact_event_sequence.get((ARTIFACT_RECONCILIATION, str(prior_reconciliation_id)), 0) >= reconciliation_sequence:
                raise IndependentStoreError("database:reconciliation-prior-order")

    # Denominator events consume state-owned source/governance evidence and
    # append to one fixed denominator chain.  A narrowing transition must
    # follow its baseline; a later withdrawal cannot erase either history.
    for denominator_artifact in artifacts.values():
        if denominator_artifact["kind"] != ARTIFACT_DENOMINATOR:
            continue
        denominator_sequence = artifact_event_sequence.get((ARTIFACT_DENOMINATOR, str(denominator_artifact["artifact_id"])))
        value = denominator_independent._parse(denominator_artifact["payload"])
        source_id = denominator_artifact.get("source_artifact_id")
        source_key = (ARTIFACT_SOURCE_EVIDENCE, str(source_id))
        source_artifact = artifacts.get(source_key)
        source_sequence = artifact_event_sequence.get(source_key)
        governance_id = value.get("governance_binding", {}).get("artifact_id") if isinstance(value.get("governance_binding"), dict) else None
        governance_key = (ARTIFACT_GOVERNANCE, str(governance_id))
        governance_sequence = artifact_event_sequence.get(governance_key)
        if denominator_sequence is None or source_artifact is None or source_sequence is None or source_sequence >= denominator_sequence:
            raise IndependentStoreError("database:denominator-source-order")
        if governance_sequence is None or governance_sequence >= denominator_sequence:
            raise IndependentStoreError("database:denominator-governance-order")
        source_chain = _chain_id(
            ARTIFACT_SOURCE_EVIDENCE,
            str(source_artifact["subject"]),
            str(source_artifact["scope"]),
            source_artifact.get("profile_id"),
        )
        source_events_before = [
            sequence
            for key, sequence in artifact_event_sequence.items()
            if key[0] == ARTIFACT_SOURCE_EVIDENCE
            and sequence < denominator_sequence
            and _chain_id(
                ARTIFACT_SOURCE_EVIDENCE,
                str(artifacts[key]["subject"]),
                str(artifacts[key]["scope"]),
                artifacts[key].get("profile_id"),
            ) == source_chain
        ]
        if not source_events_before or max(source_events_before) != source_sequence:
            raise IndependentStoreError("database:denominator-source-not-head")
        graph_id = value.get("source_binding", {}).get("graph_artifact_id") if isinstance(value.get("source_binding"), dict) else None
        if graph_id is not None:
            graph_sequence = artifact_event_sequence.get((ARTIFACT_GRAPH, str(graph_id)))
            if graph_sequence is None or graph_sequence >= denominator_sequence:
                raise IndependentStoreError("database:denominator-graph-order")
        prior_id = denominator_artifact.get("prior_artifact_id")
        if prior_id is None:
            if denominator_artifact.get("denominator_stage") != denominator_independent.STAGE_BASELINE:
                raise IndependentStoreError("database:denominator-missing-prior")
        else:
            prior_key = (ARTIFACT_DENOMINATOR, str(prior_id))
            prior = artifacts.get(prior_key)
            prior_sequence = artifact_event_sequence.get(prior_key)
            if prior is None or prior_sequence is None or prior_sequence >= denominator_sequence:
                raise IndependentStoreError("database:denominator-prior-order")
            if value.get("prior_stage_id") != prior.get("current_stage_id") or prior.get("denominator_stage") != denominator_independent.STAGE_BASELINE:
                raise IndependentStoreError("database:denominator-prior-binding")

    # Contract evaluation is a derived observation.  It may only appear after
    # the exact denominator, case, and governing Control Pack bytes it names;
    # a retest also remains append-only on the Contract chain.
    for contract_artifact in artifacts.values():
        if contract_artifact["kind"] != ARTIFACT_CONTRACT:
            continue
        contract_sequence = artifact_event_sequence.get((ARTIFACT_CONTRACT, str(contract_artifact["artifact_id"])))
        contract_value = contract_independent._parse(contract_artifact["payload"])
        denominator_id = contract_value["denominator"]["artifact_id"]
        case_artifact_id = contract_value["case_link"]["artifact_id"]
        governance_id = contract_value["governance_binding"]["artifact_id"]
        denominator_sequence = artifact_event_sequence.get((ARTIFACT_DENOMINATOR, str(denominator_id)))
        case_sequence = artifact_event_sequence.get((ARTIFACT_CASE, str(case_artifact_id)))
        governance_sequence = artifact_event_sequence.get((ARTIFACT_GOVERNANCE, str(governance_id)))
        if contract_sequence is None or denominator_sequence is None or case_sequence is None or governance_sequence is None:
            raise IndependentStoreError("database:contract-dependency-missing")
        if denominator_sequence >= contract_sequence or case_sequence >= contract_sequence or governance_sequence >= contract_sequence:
            raise IndependentStoreError("database:contract-dependency-order")
        case_artifact = artifacts.get((ARTIFACT_CASE, str(case_artifact_id)))
        if case_artifact is None:
            raise IndependentStoreError("database:contract-case-missing")
        case_chain = _chain_id(
            ARTIFACT_CASE,
            str(case_artifact["subject"]),
            str(case_artifact["scope"]),
            case_artifact.get("profile_id"),
        )
        case_head_at_contract: Mapping[str, object] | None = None
        for sequence in range(1, contract_sequence):
            event = events.get(sequence)
            if event is not None and event["chain_id"] == case_chain:
                case_head_at_contract = artifacts.get((ARTIFACT_CASE, str(event["artifact_id"])))
        if case_head_at_contract is None or case_head_at_contract["artifact_id"] != case_artifact_id or case_head_at_contract["current_stage_id"] != case_artifact["current_stage_id"]:
            raise IndependentStoreError("database:contract-case-head")
        if contract_value["stage_kind"] == contract_independent.STAGE_EVALUATED:
            if contract_artifact["prior_artifact_id"] is not None:
                raise IndependentStoreError("database:contract-initial-prior")
        elif contract_value["stage_kind"] == contract_independent.STAGE_RETESTED:
            prior_id = contract_artifact["prior_artifact_id"]
            prior = artifacts.get((ARTIFACT_CONTRACT, str(prior_id))) if prior_id is not None else None
            prior_sequence = artifact_event_sequence.get((ARTIFACT_CONTRACT, str(prior_id))) if prior_id is not None else None
            if prior is None or prior_sequence is None or prior_sequence >= contract_sequence or contract_independent._parse(prior["payload"])["stage_kind"] != contract_independent.STAGE_EVALUATED:
                raise IndependentStoreError("database:contract-prior-order")
        else:
            raise IndependentStoreError("database:contract-stage")

    # A linked V2 graph is independently eligible only while a matching
    # verifier-owned approval was effective at the source-custody event.  This
    # preserves historical verification after withdrawal while rejecting a
    # forged/rebound source link that appears after withdrawal.
    for source_artifact in artifacts.values():
        if source_artifact["kind"] != ARTIFACT_SOURCE_EVIDENCE or source_artifact.get("linked_graph_artifact_id") is None:
            continue
        graph_key = (ARTIFACT_GRAPH, str(source_artifact["linked_graph_artifact_id"]))
        graph_artifact = artifacts.get(graph_key)
        if graph_artifact is None:
            raise IndependentStoreError("database:source-graph-missing")
        source_sequence = artifact_event_sequence.get((ARTIFACT_SOURCE_EVIDENCE, str(source_artifact["artifact_id"])))
        graph_sequence = artifact_event_sequence.get(graph_key)
        if source_sequence is None or graph_sequence is None:
            raise IndependentStoreError("database:source-graph-event-missing")
        graph_value = _parse_canonical(graph_artifact["payload"])
        graph_profile = graph_value.get("profile")
        graph_snapshot = graph_value.get("observation_snapshot")
        if not isinstance(graph_profile, dict) or not isinstance(graph_snapshot, dict):
            raise IndependentStoreError("database:source-graph-profile")
        graph_profile_id = graph_profile.get("profile_id")
        graph_profile_digest = graph_profile.get("profile_digest")
        observation_time = graph_snapshot.get("observation_time")
        if not isinstance(graph_profile_id, str) or not isinstance(graph_profile_digest, str) or type(observation_time) is not int:
            raise IndependentStoreError("database:source-graph-profile")
        approved = False
        for sequence in sorted(artifact_event_sequence.values()):
            if sequence >= source_sequence:
                break
            governance_artifacts = [
                item for item in artifacts.values()
                if item["kind"] == ARTIFACT_GOVERNANCE
                and item["subject"] == graph_artifact["subject"]
                and item["scope"] == graph_artifact["scope"]
                and item.get("profile_id") == graph_profile_id
                and artifact_event_sequence.get((item["kind"], item["artifact_id"])) == sequence
            ]
            for governance_artifact in governance_artifacts:
                try:
                    governed_value = _parse_canonical(governance_artifact["payload"])
                    governed = governance_v2_independent.verify_bytes(governance_artifact["payload"], graph_profile_registry or {})
                except Exception as exc:
                    raise IndependentStoreError("database:source-governance-reject") from exc
                if governed_value.get("schema") == governance_v2_independent.SCHEMA and governed.get("current_stage_kind") == governance_v2_independent.STAGE_APPROVED:
                    if (
                        governed.get("profile_id") == graph_profile_id
                        and governed.get("profile_digest") == graph_profile_digest
                        and type(governed.get("effective_start")) is int
                        and type(governed.get("effective_end")) is int
                        and governed["effective_start"] <= observation_time <= governed["effective_end"]
                    ):
                        approved = True
                elif governed_value.get("schema") == governance_v2_independent.WITHDRAWAL_SCHEMA:
                    approved = False
        if not approved:
            raise IndependentStoreError("database:source-governance-ineligible")

    if set(heads) != set(state_heads):
        raise IndependentStoreError("database:head-set")
    for chain_id, expected in state_heads.items():
        actual = heads[chain_id]
        if actual != expected:
            raise IndependentStoreError("database:head-binding")
    governed_profiles = sorted(
        (
            {"profile_id": artifact["profile_id"], "version": artifact["profile_version"]}
            for artifact in artifacts.values()
            if artifact.get("profile_id") is not None and artifact.get("profile_version") is not None
        ),
        key=lambda item: (str(item["profile_id"]), int(item["version"])),
    )
    deduplicated_profiles: list[dict[str, object]] = []
    for profile in governed_profiles:
        if profile not in deduplicated_profiles:
            deduplicated_profiles.append(profile)
    return {
        "accepted": True,
        "schema_version": SCHEMA_VERSION,
        "artifact_count": len(rows["artifacts"]),
        "event_count": len(rows["events"]),
        "receipt_count": len(rows["receipts"]),
        "head_count": len(rows["heads"]),
        "state_root": final_state_root,
        "governed_profiles": deduplicated_profiles,
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


def _check_sqlite_shape(connection: sqlite3.Connection, *, allow_immutable: bool = False) -> None:
    for pragma, expected in (("foreign_keys", 1), ("trusted_schema", 0), ("synchronous", 2), ("busy_timeout", BUSY_TIMEOUT_MS)):
        row = connection.execute(f"PRAGMA {pragma}").fetchone()
        if row is None or int(row[0]) != expected:
            raise IndependentStoreError(f"database:pragma-{pragma}")
    journal = connection.execute("PRAGMA journal_mode").fetchone()
    expected_journal = "delete" if allow_immutable else "wal"
    if journal is None or str(journal[0]).lower() != expected_journal:
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


def snapshot_database(
    path: str | Path,
    graph_profile_registry: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Verify schema and rows from one explicit SQLite read snapshot."""

    try:
        image = sqlite_snapshot.read_only_image(
            path, max_database_bytes=MAX_DB_BYTES, max_sidecar_bytes=MAX_WAL_BYTES,
        )
    except sqlite_snapshot.SQLiteSnapshotError as exc:
        code = "journal-mode" if str(exc) == "journal-mode" else "image"
        raise IndependentStoreError(f"database:{code}") from exc
    connection: sqlite3.Connection | None = None
    try:
        # A closed image with no WAL/SHM sidecars can be opened immutable so
        # SQLite cannot create a new shared-memory sidecar during read-only
        # verification.  When a live WAL exists, ordinary read-only mode is
        # required to include that snapshot; its owner must checkpoint before
        # publication.
        connection = sqlite3.connect(image.uri, uri=True, timeout=BUSY_TIMEOUT_MS / 1000.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
        connection.execute("BEGIN")
        _check_sqlite_shape(connection, allow_immutable=image.immutable)
        snapshot = _snapshot_from_connection(connection)
        result = _verify_rows(snapshot, graph_profile_registry=graph_profile_registry)
        return {"evidence": result, "snapshot": snapshot}
    except IndependentStoreError:
        raise
    except (sqlite3.DatabaseError, OSError, ValueError) as exc:
        raise IndependentStoreError("database:corrupt-or-unreadable") from exc
    finally:
        if connection is not None:
            try:
                if connection.in_transaction:
                    connection.rollback()
            finally:
                connection.close()


def verify_database(
    path: str | Path,
    graph_profile_registry: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Open a database read-only and return only compact conformance evidence."""

    return dict(snapshot_database(path, graph_profile_registry=graph_profile_registry)["evidence"])


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
    except Exception:
        print("REJECT verification", file=sys.stderr)
        return 1
    print(_canonical(result).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
