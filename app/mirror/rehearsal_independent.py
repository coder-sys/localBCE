"""Independent reconstruction for the synthetic end-to-end Mirror rehearsal.

This module consumes only a canonical rehearsal receipt and a canonical
ContinuityStore export.  It does not import producer services, read SQLite,
or accept the receipt's summaries as authority: the store-independent
verifier reconstructs the artifact/event/head state first, then this module
derives the bounded component outcomes from the retained payload bytes.
"""

from __future__ import annotations

import hashlib
import json
from typing import Mapping

from app.mirror import continuity_store_independent as store
from app.mirror import contract_mirror_independent as contract
from app.mirror import discrepancy_case_independent as case
from app.mirror import denominator_ledger_independent as denominator
from app.mirror import money_mirror_independent as money
from app.mirror import qualification_independent as qualification
from app.mirror import state_value_ledger_independent as state_value
from app.mirror import transaction_mirror_independent as transaction
from app.mirror import transition_mirror_independent as transition


DOMAIN = "BL/MIRROR/END-TO-END-REHEARSAL/"
SCHEMA = "mirror-end-to-end-rehearsal-receipt-v1"
SCHEMA_VERSION = 1
EVIDENCE_SCHEMA = "mirror-end-to-end-rehearsal-evidence-ledger-v2"
EVIDENCE_SCHEMA_VERSION = 2
PROFILE_ID = "mirror.rehearsal.synthetic-end-to-end.v1"
PROFILE_VERSION = 1
SUBJECT = "SYNTH_MIRROR_REHEARSAL_SCOPE_V1"
SCOPE = "MIRROR_SYNTHETIC_REHEARSAL_V1"
SOURCE_PROFILE_ID = "ncmedicaid.provider-directory.fhir-r4.practitioner-role-location.v1"
SOURCE_PROFILE_VERSION = 1
MAX_RECEIPT_BYTES = 262_144
MAX_LEDGER_BYTES = 262_144
MAX_EXPORT_BYTES = 20 * 1024 * 1024
MAX_EXPORT_HEX_BYTES = 2 * store.MAX_ARTIFACT_BYTES
MAX_LEDGER_ITEMS = 64
MAX_COMMAND_BYTES = 512
MAX_REASON_BYTES = 512

MATRIX_CASE_OPERATIONS = (
    "export_omitted", "export_duplicated", "export_reordered", "export_substituted",
    "export_truncated", "export_corrupt", "export_stale", "export_cross_profile",
    "export_cross_subject", "receipt_cross_rehearsal", "duplicate_json_key", "oversized_receipt",
    "deep_receipt", "wrong_control_pack_version", "withdrawn_approval", "incomplete_source",
    "forged_absence", "responsibility_mismatch", "remediation_mismatch", "retest_mismatch",
    "parity_mismatch", "transaction_identity", "money_counting", "transition_identity",
    "contract_identity", "denominator_conservation", "state_value_counting", "controlled_relabel",
    "production_relabel", "backup_corrupt", "backup_truncated", "stale_backup_target",
    "wrong_database_registry", "custody_key_rotation_revocation", "cap_33", "selector_wrong_kind",
    "selector_wrong_id", "selector_cap", "selector_corrupt",
)
MATRIX_CASE_CATEGORIES = {
    **{operation: "artifact-chain" for operation in MATRIX_CASE_OPERATIONS[:13]},
    **{operation: "governance-source" for operation in MATRIX_CASE_OPERATIONS[13:17]},
    **{operation: "lifecycle" for operation in MATRIX_CASE_OPERATIONS[17:21]},
    **{operation: "economic-views" for operation in MATRIX_CASE_OPERATIONS[21:27]},
    **{operation: "qualification" for operation in MATRIX_CASE_OPERATIONS[27:29]},
    **{operation: "backup-restore" for operation in MATRIX_CASE_OPERATIONS[29:34]},
    **{operation: "cap-selector" for operation in MATRIX_CASE_OPERATIONS[34:]},
}
STORE_FAULT_POINTS = (
    "before_transaction", "after_begin", "after_artifact_insert",
    "after_event_receipt_before_commit", "after_commit_before_response",
)
RESTORE_FAULT_POINTS = (
    "before_staging_creation", "after_empty_staging_db_creation", "after_snapshot_transaction",
    "after_independent_verification_checkpoint", "after_atomic_publication_before_response",
)
REQUIRED_CASE_IDS = tuple(
    [f"matrix:{operation}" for operation in MATRIX_CASE_OPERATIONS]
    + ["concurrency:IDENTICAL_CONVERGENCE", "concurrency:CONFLICTING_SINGLE_WINNER"]
    + [f"fault:store:{point}" for point in STORE_FAULT_POINTS]
    + [f"fault:restore:{point}" for point in RESTORE_FAULT_POINTS]
    + [f"recovery:store:{point}" for point in STORE_FAULT_POINTS]
    + [f"recovery:restore:{point}" for point in RESTORE_FAULT_POINTS]
    + ["recovery:reopen", "recovery:restore-roundtrip"]
)
CASE_RESULT_KEYS = {"case_id", "category", "kind", "outcome", "verifier_result"}
BASELINE_CASE_IDS = ("baseline:full-chain",)

PROFILE_MATERIAL = {
    "profile_id": PROFILE_ID,
    "version": PROFILE_VERSION,
    "subject": SUBJECT,
    "scope": SCOPE,
    "source_profile_id": SOURCE_PROFILE_ID,
    "source_profile_version": SOURCE_PROFILE_VERSION,
    "required_component_labels": [
        "governance",
        "source_custody",
        "provider_trust_graph",
        "source_reconciliation",
        "denominator",
        "case_lifecycle",
        "contract",
        "transaction",
        "money",
        "transition",
        "state_value",
        "qualification",
    ],
    "claim": qualification.SYNTHETIC_REHEARSAL_READY,
}

AUTHORITY_FLAGS = {
    "clearance_authority": False,
    "payment_authority": False,
    "economic_mutation": False,
    "production_usable": False,
    "production_source_authentication": False,
    "controlled_shadow_ready": False,
    "production_ready": False,
    "activation": False,
    "proofSuiteId": None,
    "synthetic_only": True,
}

NONCLAIMS = [
    "live_source_qualification",
    "state_authorization",
    "production_custody",
    "production_ha_dr",
    "controlled_shadow_pilot",
    "payment_or_clearance_authority",
    "economic_mutation",
    "causal_value_proof",
    "record_truth_or_completeness",
]

EXTERNAL_BLOCKERS = [
    "live_source_terms_and_authorization",
    "state_governance_and_privacy_approval",
    "production_key_custody_hsm_or_fips",
    "production_ha_backup_dr_monitoring_and_rollback",
    "controlled_shadow_operational_qualification",
]

OWNER_MAP = [
    {"component": "governance", "owner": "provider-continuity-control-pack-v2"},
    {"component": "source_custody", "owner": "source-evidence-custody"},
    {"component": "provider_trust_graph", "owner": "provider-trust-graph"},
    {"component": "source_reconciliation", "owner": "source-reconciliation"},
    {"component": "denominator", "owner": "denominator-ledger"},
    {"component": "case_lifecycle", "owner": "discrepancy-case"},
    {"component": "contract", "owner": "contract-mirror"},
    {"component": "transaction", "owner": "transaction-mirror"},
    {"component": "money", "owner": "money-mirror"},
    {"component": "transition", "owner": "transition-mirror"},
    {"component": "state_value", "owner": "state-value-ledger"},
    {"component": "qualification", "owner": "qualification-rehearsal"},
    {"component": "durability", "owner": "continuity-store-and-export"},
]

COMPONENT_KINDS = {
    "governance": (store.ARTIFACT_GOVERNANCE,),
    "source_custody": (store.ARTIFACT_SOURCE_EVIDENCE,),
    "provider_trust_graph": (store.ARTIFACT_GRAPH,),
    "source_reconciliation": (store.ARTIFACT_RECONCILIATION,),
    "denominator": (store.ARTIFACT_DENOMINATOR,),
    "case_lifecycle": (store.ARTIFACT_CASE,),
    "contract": (store.ARTIFACT_CONTRACT,),
    "transaction": (store.ARTIFACT_TRANSACTION_OBSERVATION, store.ARTIFACT_TRANSACTION_TRACE),
    "money": (store.ARTIFACT_MONEY_OBSERVATION,),
    "transition": (store.ARTIFACT_TRANSITION,),
    "state_value": (store.ARTIFACT_STATE_VALUE,),
    "qualification": (store.ARTIFACT_QUALIFICATION,),
}

RECEIPT_KEYS = {
    "schema", "schema_version", "profile_binding", "subject", "scope", "components",
    "outcomes", "chain", "recovery", "authority", "nonclaims", "export_binding", "receipt_id",
}
PROFILE_KEYS = {"profile_id", "version", "profile_digest"}
EXPORT_SCHEMA = "mirror-continuity-state-export-v2"
EXPORT_KEYS = {
    "schema", "schema_version", "software", "meta", "artifacts", "operations", "receipts",
    "events", "heads", "state_root", "state_owned", "support_safe", "synthetic_only",
    "production_usable", "export_root",
}
EXPORT_ROW_KEYS = {
    "meta": set(store.TABLE_COLUMNS["store_meta"]),
    "artifacts": set(store.TABLE_COLUMNS["artifacts"]) - {"payload"} | {"payload_hex"},
    "operations": set(store.TABLE_COLUMNS["operations"]),
    "receipts": set(store.TABLE_COLUMNS["receipts"]) - {"receipt"} | {"receipt_hex"},
    "events": set(store.TABLE_COLUMNS["events"]),
    "heads": set(store.TABLE_COLUMNS["heads"]),
}


class IndependentRehearsalError(ValueError):
    """Raised when a receipt/export cannot be independently reconstructed."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise IndependentRehearsalError("rehearsal:noncanonical") from exc


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update((DOMAIN + label + "/v1\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _raw_digest(label: str, raw: bytes) -> str:
    digest = hashlib.sha3_512()
    digest.update((DOMAIN + label + "/v1\0").encode("ascii"))
    digest.update(raw)
    return digest.hexdigest()


def _parse(raw: bytes, *, maximum: int) -> dict[str, object]:
    if type(raw) is not bytes or not raw or len(raw) > maximum:
        raise IndependentRehearsalError("rehearsal:byte-cap")
    try:
        value = store._parse_canonical(raw, maximum=maximum, max_string_bytes=MAX_EXPORT_HEX_BYTES * 2)
    except Exception as exc:
        raise IndependentRehearsalError("rehearsal:canonical-json") from exc
    if not isinstance(value, dict):
        raise IndependentRehearsalError("rehearsal:top-level")
    return value


def _hex(value: object, label: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if type(value) is not str or not store._HEX128.fullmatch(value):
        raise IndependentRehearsalError(f"rehearsal:{label}")
    return value


def _text(value: object, label: str, *, maximum: int = MAX_REASON_BYTES) -> str:
    if type(value) is not str or not value:
        raise IndependentRehearsalError(f"rehearsal:{label}")
    try:
        if len(value.encode("ascii")) > maximum:
            raise IndependentRehearsalError(f"rehearsal:{label}")
    except UnicodeEncodeError as exc:
        raise IndependentRehearsalError(f"rehearsal:{label}") from exc
    return value


def _decode_hex(value: object, label: str, *, maximum: int) -> bytes:
    if type(value) is not str or len(value) % 2 or len(value) > maximum * 2:
        raise IndependentRehearsalError(f"export:{label}-hex")
    try:
        result = bytes.fromhex(value)
    except ValueError as exc:
        raise IndependentRehearsalError(f"export:{label}-hex") from exc
    if result.hex() != value:
        raise IndependentRehearsalError(f"export:{label}-canonical")
    return result


def _decode_export(raw: bytes, graph_profile_registry: Mapping[str, object]) -> tuple[dict[str, object], dict[str, list[dict[str, object]]], dict[str, object]]:
    value = _parse(raw, maximum=MAX_EXPORT_BYTES)
    if set(value) != EXPORT_KEYS or value["schema"] != EXPORT_SCHEMA or value["schema_version"] != store.SCHEMA_VERSION:
        raise IndependentRehearsalError("export:schema")
    if not isinstance(value["software"], dict):
        raise IndependentRehearsalError("export:software")
    if value["state_owned"] is not True or value["support_safe"] is not False or value["synthetic_only"] is not True or value["production_usable"] is not False:
        raise IndependentRehearsalError("export:authority")
    _hex(value["state_root"], "state-root")
    snapshot: dict[str, list[dict[str, object]]] = {}
    caps = {
        "meta": 2,
        "artifacts": store.MAX_ARTIFACTS,
        "operations": store.MAX_EVENTS,
        "receipts": store.MAX_EVENTS,
        "events": store.MAX_EVENTS,
        "heads": store.MAX_ARTIFACTS,
    }
    for table in store.SNAPSHOT_TABLES:
        rows = value[table]
        if not isinstance(rows, list) or len(rows) > caps[table]:
            raise IndependentRehearsalError(f"export:{table}-count")
        decoded: list[dict[str, object]] = []
        for item in rows:
            if not isinstance(item, dict) or set(item) != EXPORT_ROW_KEYS[table]:
                raise IndependentRehearsalError(f"export:{table}-keys")
            row = dict(item)
            if table == "artifacts":
                row["payload"] = _decode_hex(row.pop("payload_hex"), "artifact", maximum=store.MAX_ARTIFACT_BYTES)
            elif table == "receipts":
                row["receipt"] = _decode_hex(row.pop("receipt_hex"), "receipt", maximum=store.MAX_RECEIPT_BYTES)
            decoded.append(row)
        snapshot[table] = decoded
    if snapshot["meta"] != sorted(snapshot["meta"], key=lambda item: str(item["key"])):
        raise IndependentRehearsalError("export:meta-order")
    if snapshot["artifacts"] != sorted(snapshot["artifacts"], key=lambda item: (str(item["kind"]), str(item["artifact_id"]))):
        raise IndependentRehearsalError("export:artifact-order")
    if snapshot["operations"] != sorted(snapshot["operations"], key=lambda item: int(item["event_sequence"])):
        raise IndependentRehearsalError("export:operation-order")
    if snapshot["receipts"] != sorted(snapshot["receipts"], key=lambda item: str(item["operation_id"])):
        raise IndependentRehearsalError("export:receipt-order")
    if snapshot["events"] != sorted(snapshot["events"], key=lambda item: int(item["sequence"])):
        raise IndependentRehearsalError("export:event-order")
    if snapshot["heads"] != sorted(snapshot["heads"], key=lambda item: str(item["chain_id"])):
        raise IndependentRehearsalError("export:head-order")
    body = dict(value)
    body.pop("export_root")
    if value["export_root"] != _digest_export("export-root", body):
        raise IndependentRehearsalError("export:root")
    try:
        result = store.verify_snapshot(snapshot, graph_profile_registry=graph_profile_registry)
    except Exception as exc:
        raise IndependentRehearsalError("export:state") from exc
    if result.get("state_root") != value["state_root"]:
        raise IndependentRehearsalError("export:state-root")
    return value, snapshot, result


def _digest_export(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update(("BL/MIRROR/CONTINUITY-EXPORT-V2/" + label + "/v2\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _payload(row: Mapping[str, object]) -> dict[str, object]:
    raw = row.get("payload")
    if type(raw) is not bytes:
        raise IndependentRehearsalError("rehearsal:payload")
    try:
        return store._parse_canonical(raw, maximum=store.MAX_ARTIFACT_BYTES, max_string_bytes=MAX_EXPORT_HEX_BYTES * 2)
    except Exception as exc:
        raise IndependentRehearsalError("rehearsal:payload-canonical") from exc


def component_projection(snapshot: Mapping[str, list[Mapping[str, object]]]) -> dict[str, list[dict[str, object]]]:
    events = {
        (str(row["artifact_kind"]), str(row["artifact_id"])): row
        for row in snapshot["events"]
    }
    projected: dict[str, list[dict[str, object]]] = {key: [] for key in COMPONENT_KINDS}
    for row in snapshot["artifacts"]:
        kind = str(row["kind"])
        label = next((key for key, kinds in COMPONENT_KINDS.items() if kind in kinds), None)
        if label is None:
            raise IndependentRehearsalError("rehearsal:unexpected-artifact-kind")
        event = events.get((kind, str(row["artifact_id"])))
        if event is None:
            raise IndependentRehearsalError("rehearsal:artifact-event-missing")
        projected[label].append(
            {
                "artifact_id": str(row["artifact_id"]),
                "artifact_kind": kind,
                "payload_hash": str(row["payload_hash"]),
                "current_stage_id": str(row["current_stage_id"]),
                "transition_id": str(row["transition_id"]),
                "prior_artifact_id": row["prior_artifact_id"],
                "prior_stage_id": row["prior_stage_id"],
                "stage_kind": str(row["stage_kind"]),
                "event_sequence": int(event["sequence"]),
            }
        )
    for values in projected.values():
        values.sort(key=lambda item: int(item["event_sequence"]))
    return projected


def _artifact_rows(snapshot: Mapping[str, list[Mapping[str, object]]], kind: str) -> list[Mapping[str, object]]:
    return [row for row in snapshot["artifacts"] if row["kind"] == kind]


def _one(snapshot: Mapping[str, list[Mapping[str, object]]], kind: str, *, stage: str | None = None) -> dict[str, object]:
    rows = _artifact_rows(snapshot, kind)
    if stage is not None:
        rows = [row for row in rows if row["stage_kind"] == stage]
    if len(rows) != 1:
        raise IndependentRehearsalError(f"rehearsal:artifact-cardinality:{kind}")
    return _payload(rows[0])


def _final(snapshot: Mapping[str, list[Mapping[str, object]]], kind: str) -> dict[str, object]:
    rows = _artifact_rows(snapshot, kind)
    if not rows:
        raise IndependentRehearsalError(f"rehearsal:artifact-missing:{kind}")
    events = {(str(row["artifact_kind"]), str(row["artifact_id"])): int(row["sequence"]) for row in snapshot["events"]}
    row = max(rows, key=lambda item: events[(str(item["kind"]), str(item["artifact_id"]))])
    return _payload(row)


def derive_outcomes(snapshot: Mapping[str, list[Mapping[str, object]]]) -> dict[str, object]:
    source_value = _one(snapshot, store.ARTIFACT_SOURCE_EVIDENCE)
    graph_value = _one(snapshot, store.ARTIFACT_GRAPH)
    case_value = _final(snapshot, store.ARTIFACT_CASE)
    contract_value = _one(snapshot, store.ARTIFACT_CONTRACT)
    transaction_value = _one(snapshot, store.ARTIFACT_TRANSACTION_TRACE)
    money_value = _one(snapshot, store.ARTIFACT_MONEY_OBSERVATION)
    transition_value = _one(snapshot, store.ARTIFACT_TRANSITION)
    state_value_value = _one(snapshot, store.ARTIFACT_STATE_VALUE)
    qualification_value = _final(snapshot, store.ARTIFACT_QUALIFICATION)
    responsibility = case_value.get("responsibility")
    retest = case_value.get("retest")
    parity = retest.get("parity") if isinstance(retest, dict) else None
    aggregate = state_value_value.get("aggregate")
    if not isinstance(responsibility, dict) or not isinstance(retest, dict) or not isinstance(parity, dict) or not isinstance(aggregate, dict):
        raise IndependentRehearsalError("rehearsal:outcome-shape")
    terms = money_value.get("terms")
    comparisons = money_value.get("comparisons")
    if not isinstance(terms, dict) or not isinstance(comparisons, dict) or not isinstance(comparisons.get("overall"), dict):
        raise IndependentRehearsalError("rehearsal:money-outcome")
    aggregate_keys = (
        "counted_minor", "excluded_minor", "disputed_minor", "unknown_minor", "reversed_minor",
        "counted_entries", "excluded_entries", "disputed_entries", "unknown_entries", "reversed_entries",
    )
    if any(key not in aggregate for key in aggregate_keys):
        raise IndependentRehearsalError("rehearsal:value-outcome")
    return {
        "source_status": source_value["source_status"],
        "source_completeness": source_value["source_completeness"],
        "allow_nonmembership": source_value["allow_nonmembership"],
        "finding_kinds": sorted(str(item["kind"]) for item in graph_value["findings"]),
        "graph_discrepancy_count": len(graph_value["discrepancies"]),
        "case_lifecycle_state": case_value["lifecycle_state"],
        "case_responsibility_boundary": responsibility["boundary"],
        "case_retest_status": retest["status"],
        "case_parity_status": parity["status"],
        "case_resolution_state": case_value["resolution"]["state"],
        "contract_status": contract_value["evaluation"]["status"],
        "transaction_divergence_status": transaction_value["divergence"]["status"],
        "money_overall_status": comparisons["overall"]["status"],
        "money_terms": {key: terms[key] for key in ("currency", "gross_official_posted_minor", "signed_adjustments_minor", "voided_amount_minor", "net_official_observed_minor", "report_amount_minor")},
        "transition_overall_status": transition_value["comparison"]["overall"]["status"],
        "state_value_aggregate": {key: aggregate[key] for key in aggregate_keys},
        "qualification_claim": qualification_value["readiness"]["final_claim"],
        "qualification_state": qualification_value["pilot_state"],
    }


def _head_projection(snapshot: Mapping[str, list[Mapping[str, object]]]) -> list[dict[str, object]]:
    keys = ("chain_id", "artifact_id", "current_stage_id", "stage_kind", "transition_id", "event_sequence", "head_root", "state_root")
    return [{key: row[key] for key in keys} for row in snapshot["heads"]]


def _validate_components(value: object, snapshot: Mapping[str, list[Mapping[str, object]]]) -> dict[str, list[dict[str, object]]]:
    if not isinstance(value, dict) or set(value) != set(COMPONENT_KINDS):
        raise IndependentRehearsalError("rehearsal:components")
    actual = component_projection(snapshot)
    if value != actual:
        raise IndependentRehearsalError("rehearsal:component-binding")
    required_stages = {
        "governance": {"CANDIDATE", "TESTED", "APPROVED_OBSERVATION_ONLY"},
        "source_custody": {"SOURCE_EVIDENCE_CUSTODIED"},
        "provider_trust_graph": {"INITIAL"},
        "source_reconciliation": {"SOURCE_RECONCILIATION"},
        "denominator": {denominator.STAGE_KIND},
        "case_lifecycle": {case.STAGE_OPEN, case.STAGE_RESPONSIBILITY, case.STAGE_REMEDIATION_PROPOSED, case.STAGE_REMEDIATION_EVIDENCE, case.STAGE_RETEST, case.STAGE_PERSISTS},
        "contract": {contract.STAGE_KIND},
        "transaction": {transaction.OBSERVATION_STAGE_KIND, transaction.TRACE_STAGE_KIND},
        "money": {money.STAGE_OBSERVED},
        "transition": {transition.STAGE_COMPARED},
        "state_value": {state_value.STAGE_OBSERVED},
        "qualification": {qualification.REHEARSAL_NOT_READY, qualification.REHEARSAL_READY, qualification.REHEARSAL_RUNNING, qualification.REHEARSAL_COMPLETED},
    }
    for label, stages in required_stages.items():
        observed = {str(item["stage_kind"]) for item in actual[label]}
        if not stages.issubset(observed):
            raise IndependentRehearsalError(f"rehearsal:component-stage:{label}")
    denominator_payload_stages = {
        _payload(row).get("stage_kind") for row in _artifact_rows(snapshot, store.ARTIFACT_DENOMINATOR)
    }
    if denominator_payload_stages != {denominator.STAGE_BASELINE, denominator.STAGE_NARROWED}:
        raise IndependentRehearsalError("rehearsal:denominator-payload-stages")
    contract_payload_stages = {
        _payload(row).get("stage_kind") for row in _artifact_rows(snapshot, store.ARTIFACT_CONTRACT)
    }
    if contract_payload_stages != {contract.STAGE_EVALUATED}:
        raise IndependentRehearsalError("rehearsal:contract-payload-stages")
    return actual


def verify_receipt(raw: bytes, export_raw: bytes, *, graph_profile_registry: Mapping[str, object]) -> dict[str, object]:
    value = _parse(raw, maximum=MAX_RECEIPT_BYTES)
    if set(value) != RECEIPT_KEYS or value["schema"] != SCHEMA or value["schema_version"] != SCHEMA_VERSION:
        raise IndependentRehearsalError("rehearsal:receipt-schema")
    profile_binding = value["profile_binding"]
    expected_profile = {"profile_id": PROFILE_ID, "version": PROFILE_VERSION, "profile_digest": _digest("profile", PROFILE_MATERIAL)}
    if profile_binding != expected_profile or value["subject"] != SUBJECT or value["scope"] != SCOPE:
        raise IndependentRehearsalError("rehearsal:profile-binding")
    body = dict(value)
    receipt_id = body.pop("receipt_id", None)
    if receipt_id != _digest("receipt-id", body):
        raise IndependentRehearsalError("rehearsal:receipt-id")
    export_value, snapshot, database_result = _decode_export(export_raw, graph_profile_registry)
    components = _validate_components(value["components"], snapshot)
    outcomes = derive_outcomes(snapshot)
    if value["outcomes"] != outcomes:
        raise IndependentRehearsalError("rehearsal:outcome-binding")
    chain = value["chain"]
    expected_chain = {
        "artifact_count": database_result["artifact_count"],
        "event_count": database_result["event_count"],
        "receipt_count": database_result["receipt_count"],
        "head_count": database_result["head_count"],
        "state_root": database_result["state_root"],
        "last_event_root": snapshot["events"][-1]["event_root"] if snapshot["events"] else store.GENESIS_EVENT_ROOT,
        "heads": _head_projection(snapshot),
    }
    if chain != expected_chain:
        raise IndependentRehearsalError("rehearsal:chain-binding")
    export_binding = value["export_binding"]
    expected_export_binding = {
        "export_root": export_value["export_root"],
        "state_root": export_value["state_root"],
        "export_digest": _raw_digest("export", export_raw),
    }
    if export_binding != expected_export_binding:
        raise IndependentRehearsalError("rehearsal:export-binding")
    if value["authority"] != AUTHORITY_FLAGS or value["nonclaims"] != NONCLAIMS:
        raise IndependentRehearsalError("rehearsal:authority")
    recovery = value["recovery"]
    if not isinstance(recovery, dict) or set(recovery) != {"export_verified", "restore_verified", "reopen_verified", "rollback_safe", "production_ha", "production_dr"}:
        raise IndependentRehearsalError("rehearsal:recovery-shape")
    if any(type(recovery[key]) is not bool for key in recovery) or not all(recovery[key] for key in ("export_verified", "restore_verified", "reopen_verified", "rollback_safe")) or recovery["production_ha"] or recovery["production_dr"]:
        raise IndependentRehearsalError("rehearsal:recovery-claim")
    return {
        "accepted": True,
        "schema": SCHEMA,
        "receipt_id": receipt_id,
        "export_root": export_value["export_root"],
        "state_root": database_result["state_root"],
        "artifact_count": database_result["artifact_count"],
        "event_count": database_result["event_count"],
        "component_counts": {key: len(items) for key, items in components.items()},
        "qualification_claim": outcomes["qualification_claim"],
    }


def _validate_items(value: object, label: str, *, maximum: int = MAX_LEDGER_ITEMS) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) > maximum:
        raise IndependentRehearsalError(f"ledger:{label}")
    result: list[dict[str, object]] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"scope", "reason"}:
            raise IndependentRehearsalError(f"ledger:{label}")
        _text(item["scope"], f"ledger:{label}-scope")
        _text(item["reason"], f"ledger:{label}-reason")
        result.append(dict(item))
    return result


def _validate_case_results(value: object, *, execution_scope: str) -> tuple[list[dict[str, object]], dict[str, int], dict[str, int]]:
    required_ids = BASELINE_CASE_IDS if execution_scope == "chain" else REQUIRED_CASE_IDS if execution_scope == "matrix" else ()
    if not required_ids or not isinstance(value, list) or len(value) != len(required_ids):
        raise IndependentRehearsalError("ledger:case-results-count")
    required = set(required_ids)
    seen: set[str] = set()
    records: list[dict[str, object]] = []
    category_counts: dict[str, int] = {}
    kind_counts = {"mutation": 0, "fault": 0, "recovery": 0, "concurrency": 0, "chain": 0}
    for item in value:
        if not isinstance(item, dict) or set(item) != CASE_RESULT_KEYS:
            raise IndependentRehearsalError("ledger:case-result-shape")
        case_id = _text(item["case_id"], "case-id")
        if case_id not in required or case_id in seen:
            raise IndependentRehearsalError("ledger:case-result-id")
        seen.add(case_id)
        category = item["category"]
        kind = item["kind"]
        outcome = item["outcome"]
        verifier_result = item["verifier_result"]
        if execution_scope == "chain" and case_id == "baseline:full-chain":
            expected = ("baseline", "chain", "VERIFIED", "VERIFIED")
        elif case_id.startswith("matrix:"):
            operation = case_id.removeprefix("matrix:")
            expected = (MATRIX_CASE_CATEGORIES.get(operation), "mutation", "REJECTED", "REJECTED")
        elif case_id == "concurrency:IDENTICAL_CONVERGENCE":
            expected = ("concurrency", "concurrency", "CONVERGED", "CONVERGED")
        elif case_id == "concurrency:CONFLICTING_SINGLE_WINNER":
            expected = ("concurrency", "concurrency", "SINGLE_WINNER", "SINGLE_WINNER")
        elif case_id.startswith("fault:"):
            expected = ("fault", "fault", "FAULT_HANDLED", "FAULT_HANDLED")
        elif case_id.startswith("recovery:"):
            expected = ("recovery", "recovery", "RECOVERED", "RECOVERED")
        else:
            raise IndependentRehearsalError("ledger:case-result-unknown")
        expected_category, expected_kind, expected_outcome, expected_status = expected
        if (category, kind, outcome) != (expected_category, expected_kind, expected_outcome):
            raise IndependentRehearsalError("ledger:case-result-relabel")
        if not isinstance(verifier_result, dict) or set(verifier_result) != {"status", "error_code"}:
            raise IndependentRehearsalError("ledger:case-result-verifier")
        if verifier_result["status"] != expected_status:
            raise IndependentRehearsalError("ledger:case-result-status")
        _text(verifier_result["error_code"], "case-result-error")
        records.append(dict(item))
        category_counts[expected_category] = category_counts.get(expected_category, 0) + 1
        kind_counts[expected_kind] += 1
    if seen != required:
        raise IndependentRehearsalError("ledger:case-result-missing")
    return records, category_counts, kind_counts


def verify_evidence_ledger(raw: bytes, receipt_raw: bytes) -> dict[str, object]:
    value = _parse(raw, maximum=MAX_LEDGER_BYTES)
    expected_keys = {
        "schema", "schema_version", "execution_scope", "receipt_id", "receipt_digest", "owner_map", "counts",
        "canonical_identities", "canonical_roots", "worker_commands", "warnings", "failures", "skips", "external_blockers", "nonclaims",
        "case_results", "category_counts", "resource_telemetry", "ledger_id",
    }
    if set(value) != expected_keys or value["schema"] != EVIDENCE_SCHEMA or value["schema_version"] != EVIDENCE_SCHEMA_VERSION:
        raise IndependentRehearsalError("ledger:schema")
    if value["execution_scope"] not in {"chain", "matrix"}:
        raise IndependentRehearsalError("ledger:execution-scope")
    receipt = _parse(receipt_raw, maximum=MAX_RECEIPT_BYTES)
    if set(receipt) != RECEIPT_KEYS or receipt.get("schema") != SCHEMA or receipt.get("schema_version") != SCHEMA_VERSION:
        raise IndependentRehearsalError("ledger:receipt-schema")
    if value["receipt_id"] != receipt["receipt_id"] or value["receipt_digest"] != _raw_digest("receipt", receipt_raw):
        raise IndependentRehearsalError("ledger:receipt-binding")
    if value["owner_map"] != OWNER_MAP or value["external_blockers"] != EXTERNAL_BLOCKERS or value["nonclaims"] != NONCLAIMS:
        raise IndependentRehearsalError("ledger:authority-map")
    components = receipt.get("components")
    if not isinstance(components, dict) or set(components) != set(COMPONENT_KINDS):
        raise IndependentRehearsalError("ledger:component-source")
    expected_identities = {
        label: [item["artifact_id"] for item in items]
        for label, items in components.items()
        if isinstance(items, list) and all(isinstance(item, dict) and type(item.get("artifact_id")) is str for item in items)
    }
    if set(expected_identities) != set(COMPONENT_KINDS) or value["canonical_identities"] != expected_identities:
        raise IndependentRehearsalError("ledger:canonical-identities")
    chain = receipt.get("chain")
    export_binding = receipt.get("export_binding")
    if not isinstance(chain, dict) or not isinstance(export_binding, dict):
        raise IndependentRehearsalError("ledger:canonical-roots")
    expected_roots = {
        "receipt_id": receipt["receipt_id"],
        "receipt_digest": _raw_digest("receipt", receipt_raw),
        "export_digest": export_binding.get("export_digest"),
        "export_root": export_binding.get("export_root"),
        "state_root": chain.get("state_root"),
        "last_event_root": chain.get("last_event_root"),
    }
    if value["canonical_roots"] != expected_roots:
        raise IndependentRehearsalError("ledger:canonical-roots")
    _case_results, category_counts, kind_counts = _validate_case_results(
        value["case_results"], execution_scope=str(value["execution_scope"])
    )
    if value["category_counts"] != category_counts:
        raise IndependentRehearsalError("ledger:category-counts")
    counts = value["counts"]
    count_keys = {"artifact_count", "event_count", "transition_count", "mutation_cases", "fault_cases", "recovery_cases", "concurrency_cases"}
    if not isinstance(counts, dict) or set(counts) != count_keys or any(type(item) is not int or item < 0 or item > 10_000 for item in counts.values()):
        raise IndependentRehearsalError("ledger:counts")
    expected_counts = {
        "artifact_count": chain["artifact_count"],
        "event_count": chain["event_count"],
        "transition_count": chain["event_count"],
        "mutation_cases": kind_counts["mutation"],
        "fault_cases": kind_counts["fault"],
        "recovery_cases": kind_counts["recovery"],
        "concurrency_cases": kind_counts["concurrency"],
    }
    if counts != expected_counts:
        raise IndependentRehearsalError("ledger:counts-binding")
    commands = value["worker_commands"]
    if not isinstance(commands, list) or len(commands) > MAX_LEDGER_ITEMS:
        raise IndependentRehearsalError("ledger:commands")
    for item in commands:
        if not isinstance(item, dict) or set(item) != {"command", "exit_code"} or type(item["exit_code"]) is not int or item["exit_code"] < 0:
            raise IndependentRehearsalError("ledger:command")
        _text(item["command"], "ledger:command-text", maximum=MAX_COMMAND_BYTES)
    _validate_items(value["warnings"], "warnings")
    _validate_items(value["failures"], "failures")
    _validate_items(value["skips"], "skips")
    telemetry = value["resource_telemetry"]
    if not isinstance(telemetry, dict) or set(telemetry) != {
        "counter_name", "semantics", "cap_bytes", "cap_enforced", "measured", "process_tree_peak_bytes", "exit_code",
    } or telemetry["counter_name"] != "PeakJobMemoryUsed" or telemetry["semantics"] != "job_commit_charge_bytes":
        raise IndependentRehearsalError("ledger:telemetry")
    if telemetry["cap_bytes"] != 5_000_000_000 or type(telemetry["cap_enforced"]) is not bool or type(telemetry["measured"]) is not bool:
        raise IndependentRehearsalError("ledger:telemetry")
    if value["execution_scope"] == "matrix" and (telemetry["cap_enforced"] is not True or telemetry["measured"] is not True):
        raise IndependentRehearsalError("ledger:telemetry-unmeasured")
    peak = telemetry["process_tree_peak_bytes"]
    if telemetry["measured"] is True and (type(peak) is not int or peak < 0 or peak > 5_000_000_000):
        raise IndependentRehearsalError("ledger:telemetry")
    if telemetry["measured"] is False and peak is not None:
        raise IndependentRehearsalError("ledger:telemetry")
    if type(telemetry["exit_code"]) is not int or (telemetry["measured"] is True and telemetry["exit_code"] != 0):
        raise IndependentRehearsalError("ledger:telemetry")
    body = dict(value)
    ledger_id = body.pop("ledger_id", None)
    if ledger_id != _digest("ledger-id", body):
        raise IndependentRehearsalError("ledger:id")
    return {
        "accepted": True,
        "schema": EVIDENCE_SCHEMA,
        "ledger_id": ledger_id,
        "receipt_id": receipt["receipt_id"],
        "counts": dict(counts),
        "category_counts": dict(category_counts),
    }


__all__ = [
    "AUTHORITY_FLAGS", "BASELINE_CASE_IDS", "CASE_RESULT_KEYS", "COMPONENT_KINDS", "EVIDENCE_SCHEMA", "EVIDENCE_SCHEMA_VERSION",
    "EXTERNAL_BLOCKERS", "IndependentRehearsalError", "NONCLAIMS", "OWNER_MAP", "PROFILE_ID", "PROFILE_MATERIAL",
    "PROFILE_VERSION", "RECEIPT_KEYS", "REQUIRED_CASE_IDS", "MATRIX_CASE_CATEGORIES", "MATRIX_CASE_OPERATIONS", "SCHEMA", "SCHEMA_VERSION", "SCOPE", "SOURCE_PROFILE_ID", "SUBJECT",
    "component_projection", "derive_outcomes", "verify_evidence_ledger", "verify_receipt", "_canonical", "_digest",
    "_parse", "_raw_digest",
]
