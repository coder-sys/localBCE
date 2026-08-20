"""Thin composition root for one complete synthetic Mirror rehearsal.

The component modules remain the owners of source admission, graph and
governance semantics, custody, reconciliation, case lifecycle, each Mirror
view, qualification, and ContinuityStore durability.  This module only
selects the fixed synthetic profile, passes immutable artifact selectors
between those owners, and derives a receipt from the final canonical export.
It never introduces another semantic engine or store.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import tempfile
from typing import Callable, Mapping, Sequence

from app.governance import provider_continuity_control_pack_v2 as governance
from app.mirror import continuity_export as continuity_export
from app.mirror import continuity_store as store
from app.mirror import continuity_store_independent as store_independent
from app.mirror import contract_mirror as contract
from app.mirror import discrepancy_case as case
from app.mirror import discrepancy_case_independent as case_independent
from app.mirror import denominator_ledger as denominator
from app.mirror import money_mirror as money
from app.mirror import nc_medicaid_fhir_independent as fhir_independent
from app.mirror import nc_medicaid_fhir_profile as source_profile
from app.mirror import qualification as qualification
from app.mirror import qualification_fixtures as qualification_fixtures
from app.mirror import qualification_independent as qualification_independent
from app.mirror import rehearsal_independent as independent
from app.mirror import source_admission
from app.mirror import source_evidence_custody as custody
from app.mirror import source_evidence_custody_independent as custody_independent
from app.mirror import source_reconciliation as reconciliation
from app.mirror import state_value_ledger as state_value
from app.mirror import transaction_mirror as transaction
from app.mirror import transition_mirror as transition
from app.mirror import support_boundary as support


class RehearsalError(ValueError):
    """Stable composition failure; no fallback or authority downgrade is made."""


@dataclass(frozen=True)
class RehearsalResult:
    receipt_raw: bytes
    evidence_ledger_raw: bytes
    export_raw: bytes
    support_raw: bytes
    recovery: Mapping[str, bool]


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise RehearsalError("rehearsal:noncanonical") from exc


def _selector(receipt: store.AdmissionReceipt) -> str:
    value = receipt.value
    artifact_id = value.get("artifact_id")
    if type(artifact_id) is not str or not artifact_id:
        raise RehearsalError("rehearsal:receipt-artifact")
    return artifact_id


def _payload(instance: store.ContinuityStore, receipt: store.AdmissionReceipt) -> bytes:
    value = receipt.value
    kind = value.get("artifact_kind")
    artifact_id = value.get("artifact_id")
    if type(kind) is not str or type(artifact_id) is not str:
        raise RehearsalError("rehearsal:receipt-selector")
    try:
        return instance.artifact_raw(kind, artifact_id)
    except Exception as exc:
        raise RehearsalError("rehearsal:stored-payload") from exc


def _store_owned_call(
    operation: Callable[[], object],
    *,
    wrapped_error: type[Exception] | None = None,
) -> object:
    """Use the ContinuityStore busy policy without reclassifying conflicts.

    A few older component facades wrap a terminal StoreBusyError in their
    component exception after a local probe. Unwrap only that exact cause so
    the shared bounded store policy can retry; all integrity/conflict errors
    continue to propagate unchanged.
    """

    def attempt() -> object:
        try:
            return operation()
        except Exception as exc:
            if (
                wrapped_error is not None
                and isinstance(exc, wrapped_error)
                and isinstance(exc.__cause__, store.StoreBusyError)
            ):
                raise exc.__cause__
            raise

    return store.run_with_busy_recovery(attempt)


def _store(store_or_path: object) -> store.ContinuityStore:
    registry = dict(source_profile.NC_MEDICAID_GRAPH_PROFILE_REGISTRY)
    if isinstance(store_or_path, store.ContinuityStore):
        if dict(store_or_path.graph_profile_registry) != registry:
            raise RehearsalError("rehearsal:registry-mismatch")
        return store_or_path
    if not isinstance(store_or_path, (str, Path)):
        raise RehearsalError("rehearsal:store")
    try:
        # Opening a shared SQLite database changes WAL state before any
        # component admission.  Keep that contention under the same bounded,
        # store-owned busy policy as every later atomic admission.
        return store.run_with_busy_recovery(
            lambda: store.ContinuityStore(store_or_path, graph_profile_registry=registry)
        )
    except Exception as exc:
        raise RehearsalError("rehearsal:store-open") from exc


def _admit_governance(instance: store.ContinuityStore, graph_raw: bytes) -> None:
    profile = source_profile.NC_MEDICAID_PROFILE.graph_profile
    candidate, _ = governance.build_candidate(graph_raw, profile)
    tested, _ = governance.build_tested(candidate, profile)
    approval_record = governance.build_approval_record(tested, profile, approval_time=7_300)
    approved, _ = governance.build_approved(tested, approval_record, profile)
    for raw in (candidate, tested, approved):
        store.run_with_busy_recovery(lambda raw=raw: instance.admit(store.ARTIFACT_GOVERNANCE, raw))


def _case_head(instance: store.ContinuityStore, case_id: str) -> bytes:
    profile = source_profile.NC_MEDICAID_PROFILE.graph_profile
    try:
        raw = instance.artifact_head_raw(store.ARTIFACT_CASE, case_id, profile.scope, profile.profile_id)
    except Exception as exc:
        raise RehearsalError("rehearsal:case-head") from exc
    if raw is None:
        raise RehearsalError("rehearsal:case-head-missing")
    return raw


def _advance_case(instance: store.ContinuityStore, service: case.DiscrepancyCaseService, case_id: str) -> bytes:
    """Advance only the next legal case stage; later exact retries are no-ops."""

    for _ in range(6):
        current_raw = _case_head(instance, case_id)
        current = case_independent._parse(current_raw)
        stage = current["lifecycle_state"]
        if stage in {case_independent.STAGE_PARITY, case_independent.STAGE_PERSISTS, case_independent.STAGE_RESOLVED, case_independent.STAGE_SUPERSEDED}:
            return current_raw
        method = {
            case_independent.STAGE_OPEN: service.record_responsibility,
            case_independent.STAGE_RESPONSIBILITY: service.propose_remediation,
            case_independent.STAGE_REMEDIATION_PROPOSED: service.attach_remediation_evidence,
            case_independent.STAGE_REMEDIATION_EVIDENCE: service.execute_retest,
            case_independent.STAGE_RETEST: service.observe_parity_or_persistence,
        }.get(stage)
        if method is None:
            raise RehearsalError("rehearsal:case-stage")
        try:
            _store_owned_call(lambda: method(case_id), wrapped_error=case.DiscrepancyCaseError)
        except case.DiscrepancyCaseError:
            # A peer may have committed the exact next stage after the read.
            # Re-read the state and continue only if the immutable head proves
            # that this requested transition is already behind it.
            after = case_independent._parse(_case_head(instance, case_id))
            if after["lifecycle_state"] == stage:
                raise
    raise RehearsalError("rehearsal:case-progress")


def _advance_qualification(service: qualification_fixtures.QualificationRehearsalService) -> None:
    evidence = qualification_fixtures.complete_evidence()
    operations = qualification_fixtures.complete_operations()
    states = (
        qualification_independent.REHEARSAL_NOT_READY,
        qualification_independent.REHEARSAL_READY,
        qualification_independent.REHEARSAL_RUNNING,
        qualification_independent.REHEARSAL_COMPLETED,
    )
    current_raw = service.current_raw()
    if current_raw is None:
        service.initialize(evidence=evidence, operations=operations, as_of=1_000)
        current_index = 0
    else:
        current = qualification_independent._parse(current_raw)
        current_state = current["pilot_state"]
        if current_state not in states:
            raise RehearsalError("rehearsal:qualification-state")
        current_index = states.index(current_state)
    for index, target in enumerate(states[1:], start=1):
        if current_index >= index:
            continue
        try:
            service.advance(target, evidence=evidence, operations=operations, as_of=1_000 + index)
        except qualification.QualificationError:
            # Only a proved peer advancement may make this target redundant.
            after_raw = service.current_raw()
            if after_raw is None:
                raise
            after = qualification_independent._parse(after_raw)
            if after["pilot_state"] not in states or states.index(after["pilot_state"]) < index:
                raise
        current_index = index


def _build_receipt(export_raw: bytes, recovery: Mapping[str, bool], registry: Mapping[str, object]) -> bytes:
    export_value, snapshot, database_result = independent._decode_export(export_raw, registry)
    components = independent.component_projection(snapshot)
    outcomes = independent.derive_outcomes(snapshot)
    chain = {
        "artifact_count": database_result["artifact_count"],
        "event_count": database_result["event_count"],
        "receipt_count": database_result["receipt_count"],
        "head_count": database_result["head_count"],
        "state_root": database_result["state_root"],
        "last_event_root": snapshot["events"][-1]["event_root"] if snapshot["events"] else store.GENESIS_EVENT_ROOT,
        "heads": independent._head_projection(snapshot),
    }
    profile_material = independent.PROFILE_MATERIAL
    body: dict[str, object] = {
        "schema": independent.SCHEMA,
        "schema_version": independent.SCHEMA_VERSION,
        "profile_binding": {
            "profile_id": independent.PROFILE_ID,
            "version": independent.PROFILE_VERSION,
            "profile_digest": independent._digest("profile", profile_material),
        },
        "subject": independent.SUBJECT,
        "scope": independent.SCOPE,
        "components": components,
        "outcomes": outcomes,
        "chain": chain,
        "recovery": dict(recovery),
        "authority": dict(independent.AUTHORITY_FLAGS),
        "nonclaims": list(independent.NONCLAIMS),
        "export_binding": {
            "export_root": export_value["export_root"],
            "state_root": export_value["state_root"],
            "export_digest": independent._raw_digest("export", export_raw),
        },
    }
    receipt_id = independent._digest("receipt-id", body)
    return _canonical({**body, "receipt_id": receipt_id})


def build_evidence_ledger(
    receipt_raw: bytes,
    *,
    execution_scope: str,
    case_results: Sequence[Mapping[str, object]],
    resource_telemetry: Mapping[str, object],
    worker_commands: Sequence[Mapping[str, object]] = (),
    warnings: Sequence[Mapping[str, object]] = (),
    failures: Sequence[Mapping[str, object]] = (),
    skips: Sequence[Mapping[str, object]] = (),
) -> bytes:
    """Build the non-Markdown machine ledger for one worker run.

    Operational counts are derived from canonical executed case records and the
    independently checked receipt chain.  Callers cannot supply summary counts.
    """

    receipt = independent._parse(receipt_raw, maximum=independent.MAX_RECEIPT_BYTES)
    records, category_counts, kind_counts = independent._validate_case_results(
        [dict(item) for item in case_results], execution_scope=execution_scope
    )
    chain = receipt.get("chain")
    if not isinstance(chain, dict):
        raise RehearsalError("rehearsal:ledger-chain")
    counts = {
        "artifact_count": chain.get("artifact_count"),
        "event_count": chain.get("event_count"),
        "transition_count": chain.get("event_count"),
        "mutation_cases": kind_counts["mutation"],
        "fault_cases": kind_counts["fault"],
        "recovery_cases": kind_counts["recovery"],
        "concurrency_cases": kind_counts["concurrency"],
    }
    if any(type(value) is not int or value < 0 for value in counts.values()):
        raise RehearsalError("rehearsal:ledger-counts")
    components = receipt.get("components")
    export_binding = receipt.get("export_binding")
    if not isinstance(components, dict) or not isinstance(chain, dict) or not isinstance(export_binding, dict):
        raise RehearsalError("rehearsal:ledger-source")
    ledger_body: dict[str, object] = {
        "schema": independent.EVIDENCE_SCHEMA,
        "schema_version": independent.EVIDENCE_SCHEMA_VERSION,
        "execution_scope": execution_scope,
        "receipt_id": receipt["receipt_id"],
        "receipt_digest": independent._raw_digest("receipt", receipt_raw),
        "owner_map": list(independent.OWNER_MAP),
        "counts": counts,
        "case_results": records,
        "category_counts": category_counts,
        "canonical_identities": {
            label: [item["artifact_id"] for item in items]
            for label, items in components.items()
        },
        "canonical_roots": {
            "receipt_id": receipt["receipt_id"],
            "receipt_digest": independent._raw_digest("receipt", receipt_raw),
            "export_digest": export_binding["export_digest"],
            "export_root": export_binding["export_root"],
            "state_root": chain["state_root"],
            "last_event_root": chain["last_event_root"],
        },
        "worker_commands": [dict(item) for item in worker_commands],
        "warnings": [dict(item) for item in warnings],
        "failures": [dict(item) for item in failures],
        "skips": [dict(item) for item in skips],
        "external_blockers": list(independent.EXTERNAL_BLOCKERS),
        "nonclaims": list(independent.NONCLAIMS),
        "resource_telemetry": dict(resource_telemetry),
    }
    return _canonical({**ledger_body, "ledger_id": independent._digest("ledger-id", ledger_body)})


def run_rehearsal(source_envelope: bytes, store_or_path: object) -> RehearsalResult:
    """Run the fixed synthetic chain and return independently checked bytes."""

    if type(source_envelope) is not bytes or not source_envelope:
        raise RehearsalError("rehearsal:source-bytes")
    instance = _store(store_or_path)
    registry = dict(source_profile.NC_MEDICAID_GRAPH_PROFILE_REGISTRY)
    graph_profile = source_profile.NC_MEDICAID_PROFILE.graph_profile

    try:
        configured_admission = source_admission.SourceAdmissionService(
            graph_profile,
            fhir_independent.NcMedicaidFhirVerifier(),
        ).admit(source_envelope)
        _admit_governance(instance, configured_admission.graph_artifact)

        custody_service = custody.SourceEvidenceCustodyService(instance, graph_profile_registry=registry)
        fixed_envelope_digest = custody_independent._raw_digest("envelope", source_envelope)
        custody_admission = store.run_with_busy_recovery(
            lambda: custody_service.ingest(
                source_envelope,
                fixed_envelope_digest=fixed_envelope_digest,
            )
        )
        if not custody_admission.graph_admitted or custody_admission.graph_receipt is None:
            raise RehearsalError("rehearsal:graph-not-admitted")
        graph_id = _selector(custody_admission.graph_receipt)
        if graph_id != configured_admission.report_id:
            raise RehearsalError("rehearsal:graph-rebound")
        custody_id = _selector(custody_admission.custody_receipt)
        custody_raw = _payload(instance, custody_admission.custody_receipt)

        reconciliation_receipt = _store_owned_call(
            lambda: reconciliation.SourceReconciliationService(
                instance, graph_profile_registry=registry
            ).reconcile(custody_raw),
            wrapped_error=reconciliation.SourceReconciliationError,
        )
        reconciliation_id = _selector(reconciliation_receipt)

        denominator_service = denominator.DenominatorLedgerService(instance, graph_profile_registry=registry)
        baseline_receipt = _store_owned_call(lambda: denominator_service.create_baseline(custody_id))
        narrowed_receipt = _store_owned_call(lambda: denominator_service.narrow(_selector(baseline_receipt)))
        denominator_id = _selector(narrowed_receipt)

        graph_value = json.loads(_payload(instance, custody_admission.graph_receipt).decode("ascii"))
        finding_id = graph_value["findings"][0]["finding_id"]
        case_service = case.DiscrepancyCaseService(instance, graph_profile_registry=registry)
        opened_receipt = _store_owned_call(
            lambda: case_service.open_case(graph_id, finding_id, reconciliation_id),
            wrapped_error=case.DiscrepancyCaseError,
        )
        opened_value = case_independent._parse(_payload(instance, opened_receipt))
        case_id = opened_value["case_id"]
        if type(case_id) is not str or not case_id:
            raise RehearsalError("rehearsal:case-id")

        contract_receipt = _store_owned_call(
            lambda: contract.ContractMirrorService(instance, graph_profile_registry=registry).evaluate(
                denominator_id,
                reconciliation_id,
                finding_id,
            ),
            wrapped_error=contract.ContractMirrorError,
        )
        contract_id = _selector(contract_receipt)

        transaction_receipt = _store_owned_call(
            lambda: transaction.TransactionMirrorService(instance, graph_profile_registry=registry).trace(contract_id),
            wrapped_error=transaction.TransactionMirrorError,
        )
        transaction_value = json.loads(_payload(instance, transaction_receipt).decode("ascii"))
        transaction_id = transaction_value["artifact_id"]
        money_receipt = _store_owned_call(
            lambda: money.MoneyMirrorService(instance, graph_profile_registry=registry).observe(transaction_id),
            wrapped_error=money.MoneyMirrorError,
        )
        money_value = json.loads(_payload(instance, money_receipt).decode("ascii"))
        money_id = money_value["artifact_id"]
        _store_owned_call(lambda: transition.TransitionMirrorService(instance, graph_profile_registry=registry).compare(money_id))
        _store_owned_call(lambda: state_value.StateValueLedgerService(instance, graph_profile_registry=registry).observe(money_id))
        _advance_case(instance, case_service, case_id)

        _advance_qualification(qualification_fixtures.QualificationRehearsalService(instance))

        database_result = store_independent.verify_database(instance.path, registry)
        export_raw = continuity_export.export_database(instance.path, registry)
        continuity_export.verify_export_bytes(export_raw, registry)
        with tempfile.TemporaryDirectory(prefix="mirror-rehearsal-restore-") as temporary:
            restored_path = Path(temporary) / "state.db"
            continuity_export.import_export(export_raw, restored_path, registry)
            restored_result = store_independent.verify_database(restored_path, registry)
            restored_export = continuity_export.export_database(restored_path, registry)
        recovery = {
            "export_verified": True,
            "restore_verified": restored_export == export_raw and restored_result == database_result,
            "reopen_verified": restored_result == database_result,
            "rollback_safe": restored_export == export_raw,
            "production_ha": False,
            "production_dr": False,
        }
        if not all(recovery[key] for key in ("export_verified", "restore_verified", "reopen_verified", "rollback_safe")):
            raise RehearsalError("rehearsal:recovery")
        support_raw = support.build_support_bundle(instance.path, graph_profile_registry=registry)
        support.verify_support_bytes(support_raw)
        receipt_raw = _build_receipt(export_raw, recovery, registry)
        independent.verify_receipt(receipt_raw, export_raw, graph_profile_registry=registry)
        ledger_raw = build_evidence_ledger(
            receipt_raw,
            execution_scope="chain",
            case_results=(
                {
                    "case_id": "baseline:full-chain",
                    "category": "baseline",
                    "kind": "chain",
                    "outcome": "VERIFIED",
                    "verifier_result": {"status": "VERIFIED", "error_code": "independent-reconstruction"},
                },
            ),
            resource_telemetry={
                "counter_name": "PeakJobMemoryUsed",
                "semantics": "job_commit_charge_bytes",
                "cap_bytes": 5_000_000_000,
                "cap_enforced": False,
                "measured": False,
                "process_tree_peak_bytes": None,
                "exit_code": -1,
            },
        )
        independent.verify_evidence_ledger(ledger_raw, receipt_raw)
        return RehearsalResult(receipt_raw, ledger_raw, export_raw, support_raw, recovery)
    except (RehearsalError, store.StoreConflictError, store.StoreBusyError, store.IndeterminateCommitError):
        raise
    except Exception as exc:
        raise RehearsalError("rehearsal:failed") from exc


__all__ = [
    "RehearsalError",
    "RehearsalResult",
    "build_evidence_ledger",
    "run_rehearsal",
]
