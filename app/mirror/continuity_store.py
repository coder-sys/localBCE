"""Bounded local operational candidate for Mirror continuity artifacts.

This module is deliberately separate from the Blind Ledger clearance database.  It
stores only independently verified synthetic Provider Trust Graph and observation-only
Governance V1/V2 lineage artifacts, including the terminal withdrawal stage.  Storage
admission is not a policy, payment, proof, or source truth decision.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sqlite3
import time
from typing import Any, Callable, Mapping, TypeVar
from types import MappingProxyType

from app.governance import provider_continuity_control_pack_independent as governance_independent
from app.governance import provider_continuity_control_pack_v2_independent as governance_v2_independent
from app.governance import provider_continuity_control_pack_withdrawal_independent as withdrawal_independent
from app.mirror import contract_mirror_independent as contract_independent
from app.mirror import denominator_ledger_independent as denominator_independent
from app.mirror import discrepancy_case_independent as case_independent
from app.mirror import nc_medicaid_fhir_profile as nc_profile
from app.mirror import provider_trust_graph_independent as graph_independent
from app.mirror import continuity_store_independent as store_independent
from app.mirror import source_evidence_custody_independent as source_independent
from app.mirror import source_reconciliation_independent as reconciliation_independent
from app.mirror import transaction_mirror_independent as transaction_independent
from app.mirror import money_mirror_independent as money_independent
from app.mirror import transition_mirror_independent as transition_independent
from app.mirror import state_value_ledger_independent as state_value_independent
from app.mirror import qualification_independent


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
MAX_ARTIFACT_BYTES = 524_288
MAX_ARTIFACTS = 16
MAX_EVENTS = 32
MAX_RECEIPT_BYTES = 32_768
MAX_DB_BYTES = 64 * 1024 * 1024
MAX_WAL_BYTES = 64 * 1024 * 1024
BUSY_TIMEOUT_MS = 250
# Transition and State Value both own the same BEGIN IMMEDIATE admission and
# exact-retry contract.  Keep their busy recovery here, beside SQLite's
# bounded busy timeout, so callers cannot copy or silently extend the policy.
BUSY_RECOVERY_MAX_ATTEMPTS = 10
BUSY_RECOVERY_INITIAL_BACKOFF_MS = 100
BUSY_RECOVERY_MAX_BACKOFF_MS = 900
BUSY_RECOVERY_BACKOFF_MS = tuple(
    min(BUSY_RECOVERY_INITIAL_BACKOFF_MS * attempt, BUSY_RECOVERY_MAX_BACKOFF_MS)
    for attempt in range(1, BUSY_RECOVERY_MAX_ATTEMPTS)
)
# The finite nominal budget is ten bounded SQLite waits plus the deterministic
# capped backoff schedule: 10*250ms + (100+...+900)ms = 7,000ms.  The
# monotonic deadline below prevents a slow scheduler from adding another
# unbounded retry; the SQLite timeout remains bounded by BUSY_TIMEOUT_MS.
BUSY_RECOVERY_BUDGET_MS = (
    BUSY_RECOVERY_MAX_ATTEMPTS * BUSY_TIMEOUT_MS
    + sum(BUSY_RECOVERY_BACKOFF_MS)
)
STORE_DOMAIN = "BL/MIRROR/CONTINUITY-STORE-V2/"
RECEIPT_EVENT_PLACEHOLDER = "EVENT_ROOT_PENDING_V2"
LIFECYCLE_STATUS_ABSENT = "ABSENT"
LIFECYCLE_STATUS_NOT_APPROVED = "NOT_APPROVED"
LIFECYCLE_STATUS_APPROVED = governance_independent.STAGE_APPROVED
LIFECYCLE_STATUS_WITHDRAWN = withdrawal_independent.ACTION
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
FAULT_POINTS = (
    "before_transaction",
    "after_begin",
    "after_artifact_insert",
    "after_event_receipt_before_commit",
    "after_commit_before_response",
)


class ContinuityStoreError(ValueError):
    """Base class for bounded store failures."""


class ArtifactAdmissionError(ContinuityStoreError):
    pass


class StoreConflictError(ContinuityStoreError):
    pass


class GovernanceObservationOnly(StoreConflictError):
    """Typed verifier-owned result for an explicitly ineligible V2 governance head."""

    _REASONS = frozenset({"not-approved", "withdrawn"})

    def __init__(self, reason: str) -> None:
        if reason not in self._REASONS:
            raise ValueError("governance:observation-reason")
        self.reason = reason
        super().__init__(f"governance:{reason}")


class StoreBusyError(ContinuityStoreError):
    pass


_BusyResult = TypeVar("_BusyResult")


def run_with_busy_recovery(operation: Callable[[], _BusyResult]) -> _BusyResult:
    """Run one exact admission with the store-owned bounded busy policy.

    Only StoreBusyError is retryable.  StoreConflictError and every other
    failure propagate unchanged, so contention recovery cannot turn an
    integrity, identity, or concurrent-writer conflict into observation-only
    success.  The fixed attempts, capped schedule, and monotonic deadline are
    deliberately owned by this SQLite store boundary.
    """

    if not callable(operation):
        raise TypeError("busy-recovery:operation")
    started = time.monotonic()
    for attempt in range(BUSY_RECOVERY_MAX_ATTEMPTS):
        try:
            return operation()
        except StoreBusyError:
            if attempt + 1 >= BUSY_RECOVERY_MAX_ATTEMPTS:
                raise
            elapsed_ms = (time.monotonic() - started) * 1000
            backoff_ms = BUSY_RECOVERY_BACKOFF_MS[attempt]
            if elapsed_ms + backoff_ms + BUSY_TIMEOUT_MS > BUSY_RECOVERY_BUDGET_MS:
                raise
            time.sleep(backoff_ms / 1000)
    raise AssertionError("busy-recovery:unreachable")


class InjectedFault(ContinuityStoreError):
    pass


class IndeterminateCommitError(ContinuityStoreError):
    def __init__(self, operation_id: str) -> None:
        super().__init__(f"commit:indeterminate:{operation_id}")
        self.operation_id = operation_id


class StoreSchemaError(ContinuityStoreError):
    pass


@dataclass(frozen=True)
class VerifiedArtifact:
    kind: str
    schema: str
    artifact_id: str
    payload_hash: str
    payload: bytes
    subject: str
    scope: str
    report_id: str | None
    current_stage_id: str
    transition_id: str
    stage_kind: str
    prior_artifact_id: str | None
    prior_stage_id: str | None
    authority_json: str
    profile_id: str | None = None


@dataclass(frozen=True)
class AdmissionReceipt:
    raw: bytes

    @property
    def value(self) -> dict[str, object]:
        value = json.loads(self.raw.decode("ascii"))
        if not isinstance(value, dict):
            raise StoreSchemaError("receipt:top-level")
        return value

    @property
    def operation_id(self) -> str:
        return str(self.value["operation_id"])


@dataclass(frozen=True)
class SourceCustodyAdmission:
    """Atomic source-custody result and optional graph continuity receipt."""

    custody_receipt: AdmissionReceipt
    graph_receipt: AdmissionReceipt | None
    graph_admitted: bool


@dataclass(frozen=True)
class ProviderContinuityLifecycleHead:
    """Durable state-owned interpretation of the current governance-lineage head."""

    chain_id: str
    provider_graph_subject: str
    scope: str
    artifact_id: str
    stage_id: str
    stage_kind: str
    transition_id: str
    event_sequence: int
    head_root: str
    state_root: str
    status: str
    active: bool
    terminal: bool
    profile_id: str | None = None
    profile_version: int | None = None


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise ContinuityStoreError("json:noncanonical-value") from exc


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ContinuityStoreError("json:duplicate-key")
        result[key] = value
    return result


def _walk(value: object, *, depth: int = 0, count: list[int] | None = None) -> None:
    count = [0] if count is None else count
    count[0] += 1
    if count[0] > 16_384:
        raise ContinuityStoreError("json:node-cap")
    if depth > 24:
        raise ContinuityStoreError("json:depth-cap")
    if isinstance(value, float):
        raise ContinuityStoreError("json:float-forbidden")
    if isinstance(value, str) and len(value.encode("ascii", "strict")) > 512:
        raise ContinuityStoreError("json:string-cap")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ContinuityStoreError("json:key-type")
            _walk(key, depth=depth + 1, count=count)
            _walk(item, depth=depth + 1, count=count)
    elif isinstance(value, list):
        for item in value:
            _walk(item, depth=depth + 1, count=count)


def _parse_canonical(raw: bytes, *, maximum: int = MAX_ARTIFACT_BYTES) -> dict[str, object]:
    if type(raw) is not bytes or not raw:
        raise ContinuityStoreError("json:empty-or-type")
    if len(raw) > maximum:
        raise ContinuityStoreError("json:byte-cap")
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(ContinuityStoreError("json:constant-forbidden")),
        )
    except ContinuityStoreError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContinuityStoreError("json:parse") from exc
    if not isinstance(value, dict):
        raise ContinuityStoreError("json:top-level")
    _walk(value)
    if _canonical(value) != raw:
        raise ContinuityStoreError("json:not-canonical")
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
        raise StoreConflictError("chain:identity")
    if profile_id is not None and (type(profile_id) is not str or not profile_id):
        raise StoreConflictError("chain:profile")
    material: dict[str, object] = {"artifact_kind": artifact_kind, "scope": scope, "subject": subject}
    if profile_id is not None:
        material["profile_id"] = profile_id
    return _digest(
        "chain-id",
        material,
    )


def _authority_json(value: Mapping[str, object], *, kind: str) -> str:
    if kind == ARTIFACT_GRAPH:
        expected = {
            "clearance_authority": False,
            "payment_authority": False,
            "economic_mutation": False,
            "production_usable": False,
            "synthetic_only": True,
        }
        if dict(value) != expected:
            raise ArtifactAdmissionError("artifact:authority-flags")
    elif kind == ARTIFACT_SOURCE_EVIDENCE:
        if dict(value) != source_independent.AUTHORITY_FLAGS:
            raise ArtifactAdmissionError("artifact:authority-flags")
    elif kind == ARTIFACT_RECONCILIATION:
        if dict(value) != reconciliation_independent.AUTHORITY_FLAGS:
            raise ArtifactAdmissionError("artifact:authority-flags")
    elif kind == ARTIFACT_CASE:
        if dict(value) != case_independent.AUTHORITY_FLAGS:
            raise ArtifactAdmissionError("artifact:authority-flags")
    elif kind == ARTIFACT_DENOMINATOR:
        if dict(value) != denominator_independent.AUTHORITY_FLAGS:
            raise ArtifactAdmissionError("artifact:authority-flags")
    elif kind == ARTIFACT_CONTRACT:
        if dict(value) != contract_independent.AUTHORITY_FLAGS:
            raise ArtifactAdmissionError("artifact:authority-flags")
    elif kind in (ARTIFACT_TRANSACTION_OBSERVATION, ARTIFACT_TRANSACTION_TRACE):
        if dict(value) != transaction_independent.AUTHORITY_FLAGS:
            raise ArtifactAdmissionError("artifact:authority-flags")
    elif kind == ARTIFACT_MONEY_OBSERVATION:
        if dict(value) != money_independent.AUTHORITY_FLAGS:
            raise ArtifactAdmissionError("artifact:authority-flags")
    elif kind == ARTIFACT_TRANSITION:
        if dict(value) != transition_independent.AUTHORITY_FLAGS:
            raise ArtifactAdmissionError("artifact:authority-flags")
    elif kind == ARTIFACT_STATE_VALUE:
        if dict(value) != state_value_independent.AUTHORITY_FLAGS:
            raise ArtifactAdmissionError("artifact:authority-flags")
    elif kind == ARTIFACT_QUALIFICATION:
        if dict(value) != qualification_independent.AUTHORITY_FLAGS:
            raise ArtifactAdmissionError("artifact:authority-flags")
    elif dict(value) != governance_independent.AUTHORITY_FLAGS:
        raise ArtifactAdmissionError("artifact:authority-flags")
    return _canonical(AUTHORITY_FLAGS).decode("ascii")


def _governance_prefix(value: Mapping[str, object], stage_count: int) -> tuple[bytes, dict[str, object]]:
    if value.get("schema") == governance_v2_independent.SCHEMA:
        raw = governance_v2_independent.prefix_bytes(value, stage_count)
        return raw, _parse_canonical(raw)
    stages = value.get("stages")
    if not isinstance(stages, list) or len(stages) < stage_count or stage_count not in (1, 2):
        raise ArtifactAdmissionError("governance:prior-prefix")
    prefix_stages = list(stages[:stage_count])
    current = prefix_stages[-1]
    if not isinstance(current, dict):
        raise ArtifactAdmissionError("governance:prior-prefix")
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
    raw = governance_independent._canonical(artifact)
    return raw, artifact


def verify_artifact(
    artifact_kind: str,
    raw: bytes,
    *,
    graph_profile_registry: Mapping[str, object] | None = None,
    reconciliation_context: Mapping[str, object] | None = None,
    denominator_context: Mapping[str, object] | None = None,
    contract_context: Mapping[str, object] | None = None,
    transaction_context: Mapping[str, object] | None = None,
    transition_context: Mapping[str, object] | None = None,
    state_value_context: Mapping[str, object] | None = None,
) -> VerifiedArtifact:
    """Run the matching independent verifier and normalize its exact identities."""

    if artifact_kind not in ARTIFACT_KINDS:
        raise ArtifactAdmissionError("artifact:kind")
    if type(raw) is not bytes or not raw or len(raw) > MAX_ARTIFACT_BYTES:
        raise ArtifactAdmissionError("artifact:byte-cap")
    try:
        if artifact_kind == ARTIFACT_SOURCE_EVIDENCE:
            value = source_independent._parse(raw)
        elif artifact_kind == ARTIFACT_RECONCILIATION:
            value = reconciliation_independent._parse(raw)
        elif artifact_kind == ARTIFACT_CASE:
            value = case_independent._parse(raw)
        elif artifact_kind == ARTIFACT_DENOMINATOR:
            value = denominator_independent._parse(raw)
        elif artifact_kind == ARTIFACT_CONTRACT:
            value = contract_independent._parse(raw)
        elif artifact_kind in (ARTIFACT_TRANSACTION_OBSERVATION, ARTIFACT_TRANSACTION_TRACE):
            value = transaction_independent._parse(raw)
        elif artifact_kind == ARTIFACT_MONEY_OBSERVATION:
            value = money_independent._parse(raw)
        elif artifact_kind == ARTIFACT_TRANSITION:
            value = transition_independent._parse(raw)
        elif artifact_kind == ARTIFACT_STATE_VALUE:
            value = state_value_independent._parse(raw)
        elif artifact_kind == ARTIFACT_QUALIFICATION:
            value = qualification_independent._parse(raw)
        else:
            value = _parse_canonical(raw)
    except (
        ContinuityStoreError,
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
        raise ArtifactAdmissionError(str(exc)) from exc
    try:
        if artifact_kind == ARTIFACT_SOURCE_EVIDENCE:
            result = source_independent.verify_artifact(raw, graph_profile_registry=graph_profile_registry, allow_unresolved_graph=True)
        elif artifact_kind == ARTIFACT_RECONCILIATION:
            if not isinstance(reconciliation_context, Mapping):
                raise ArtifactAdmissionError("reconciliation:context-required")
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
        elif artifact_kind == ARTIFACT_GRAPH:
            if value.get("schema") == graph_independent.SCHEMA_V2:
                result = graph_independent.verify_bytes_v2(raw, graph_profile_registry or {})
            else:
                result = graph_independent.verify_bytes(raw)
        elif artifact_kind == ARTIFACT_CASE:
            if not isinstance(reconciliation_context, Mapping):
                raise ArtifactAdmissionError("case:context-required")
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
        elif artifact_kind == ARTIFACT_DENOMINATOR:
            if not isinstance(denominator_context, Mapping):
                raise ArtifactAdmissionError("denominator:context-required")
            result = denominator_independent.verify_artifact(
                raw,
                source_raw=denominator_context["source_raw"],
                graph_raw=denominator_context.get("graph_raw"),
                governance_raw=denominator_context["governance_raw"],
                registry=graph_profile_registry or {},
                prior_denominator_raw=denominator_context.get("prior_denominator_raw"),
            )
        elif artifact_kind == ARTIFACT_CONTRACT:
            if not isinstance(contract_context, Mapping):
                raise ArtifactAdmissionError("contract:context-required")
            result = contract_independent.verify_artifact(
                raw,
                denominator_raw=contract_context["denominator_raw"],
                denominator_context=contract_context["denominator_context"],
                case_raw=contract_context["case_raw"],
                case_context=contract_context["case_context"],
                registry=graph_profile_registry or {},
                prior_contract_raw=contract_context.get("prior_contract_raw"),
            )
        elif artifact_kind == ARTIFACT_TRANSACTION_OBSERVATION:
            if not isinstance(transaction_context, Mapping):
                raise ArtifactAdmissionError("transaction:context-required")
            result = transaction_independent.verify_observation_artifact(
                raw,
                source_raw=transaction_context["source_raw"],
                contract_raw=transaction_context["contract_raw"],
                contract_context=transaction_context["contract_context"],
                registry=graph_profile_registry or {},
                prior_observation_raw=transaction_context.get("prior_observation_raw"),
            )
        elif artifact_kind == ARTIFACT_TRANSACTION_TRACE:
            if not isinstance(transaction_context, Mapping):
                raise ArtifactAdmissionError("transaction:context-required")
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
        elif artifact_kind == ARTIFACT_MONEY_OBSERVATION:
            if not isinstance(transaction_context, Mapping):
                raise ArtifactAdmissionError("money:context-required")
            result = money_independent.verify_artifact(
                raw,
                transaction_raw=transaction_context["transaction_raw"],
                transaction_context=transaction_context["transaction_context"],
                prior_money_raw=transaction_context.get("prior_money_raw"),
                registry=graph_profile_registry,
            )
        elif artifact_kind == ARTIFACT_TRANSITION:
            if not isinstance(transition_context, Mapping):
                raise ArtifactAdmissionError("transition:context-required")
            result = transition_independent.verify_artifact(
                raw,
                money_raw=transition_context["money_raw"],
                money_context=transition_context["money_context"],
                prior_transition_raw=transition_context.get("prior_transition_raw"),
                registry=graph_profile_registry,
            )
        elif artifact_kind == ARTIFACT_STATE_VALUE:
            if not isinstance(state_value_context, Mapping):
                raise ArtifactAdmissionError("state-value:context-required")
            result = state_value_independent.verify_artifact(
                raw,
                money_contexts=state_value_context["money_contexts"],
                prior_value_raw=state_value_context.get("prior_value_raw"),
                transition_contexts=state_value_context.get("transition_contexts"),
                registry=graph_profile_registry,
            )
        elif artifact_kind == ARTIFACT_QUALIFICATION:
            result = qualification_independent.inspect_artifact(raw)
        elif value.get("schema") in (governance_v2_independent.SCHEMA, governance_v2_independent.WITHDRAWAL_SCHEMA):
            result = governance_v2_independent.verify_bytes(raw, graph_profile_registry or {})
        elif value.get("schema") == withdrawal_independent.SCHEMA:
            result = withdrawal_independent.verify_bytes(raw)
        else:
            result = governance_independent.verify_bytes(raw)
    except Exception as exc:
        raise ArtifactAdmissionError(f"artifact:independent-reject:{type(exc).__name__}") from exc
    payload_hash = _payload_hash(raw)
    profile_id: str | None = None
    try:
        if artifact_kind == ARTIFACT_SOURCE_EVIDENCE:
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
            authority_json = _authority_json(value["authority"], kind=artifact_kind)
        elif artifact_kind == ARTIFACT_RECONCILIATION:
            artifact_id = result["artifact_id"]
            report_id = None
            current_stage_id = result["current_stage_id"]
            transition_id = result["transition_id"]
            stage_kind = result["stage_kind"]
            prior_artifact_id = result["prior_artifact_id"]
            prior_stage_id = result["prior_stage_id"]
            schema = result["schema"]
            subject_id = result["subject"]
            scope = result["scope"]
            profile_id = result["profile_id"]
            authority_json = _authority_json(value["authority"], kind=artifact_kind)
        elif artifact_kind == ARTIFACT_GRAPH:
            subject = value["subject"]
            snapshot = value["observation_snapshot"]
            transition = value["transition"]
            report = value["report"]
            identity = report["identity_material"]
            if not isinstance(subject, dict) or not isinstance(snapshot, dict) or not isinstance(transition, dict) or not isinstance(report, dict) or not isinstance(identity, dict):
                raise ArtifactAdmissionError("artifact:graph-shape")
            artifact_id = str(report["report_id"])
            report_id = artifact_id
            current_stage_id = str(snapshot["snapshot_id"])
            transition_id = str(transition["transition_id"])
            stage_kind = str(transition["transition_kind"])
            prior_artifact_id = identity["prior_report_id"]
            prior_stage_id = identity["prior_snapshot_id"]
            schema = str(value["schema"])
            subject_id = str(subject["provider_graph_subject"])
            scope = str(subject["scope"])
            authority_json = _authority_json(value["authority"], kind=artifact_kind)
            if schema == graph_independent.SCHEMA_V2:
                profile_value = graph_independent._expect_keys(value.get("profile"), graph_independent.PROFILE_KEYS, "artifact:profile")
                profile_id = profile_value["profile_id"]
        elif artifact_kind == ARTIFACT_CASE:
            artifact_id = str(result["artifact_id"])
            report_id = str(result["case_id"])
            current_stage_id = str(result["current_stage_id"])
            transition_id = str(result["transition_id"])
            stage_kind = str(result["stage_kind"])
            prior_artifact_id = result["prior_artifact_id"]
            prior_stage_id = result["prior_stage_id"]
            schema = str(result["schema"])
            subject_id = str(result["subject"])
            scope = str(result["scope"])
            profile_id = str(result["profile_id"])
            authority_json = _authority_json(value["authority"], kind=artifact_kind)
        elif artifact_kind == ARTIFACT_DENOMINATOR:
            artifact_id = str(result["artifact_id"])
            report_id = artifact_id
            current_stage_id = str(result["current_stage_id"])
            transition_id = str(result["transition_id"])
            stage_kind = str(result["stage_kind"])
            prior_artifact_id = result["prior_artifact_id"]
            prior_stage_id = result["prior_stage_id"]
            schema = str(result["schema"])
            subject_id = str(result["subject"])
            scope = str(result["scope"])
            profile_id = str(result["profile_id"])
            authority_json = _authority_json(value["authority"], kind=artifact_kind)
        elif artifact_kind == ARTIFACT_CONTRACT:
            artifact_id = str(result["artifact_id"])
            report_id = artifact_id
            current_stage_id = str(result["current_stage_id"])
            transition_id = str(result["transition_id"])
            stage_kind = str(result["stage_kind"])
            prior_artifact_id = result["prior_artifact_id"]
            prior_stage_id = result["prior_stage_id"]
            schema = str(result["schema"])
            subject_id = str(result["subject"])
            scope = str(result["scope"])
            profile_id = str(result["profile_id"])
            authority_json = _authority_json(value["authority"], kind=artifact_kind)
        elif artifact_kind in (ARTIFACT_TRANSACTION_OBSERVATION, ARTIFACT_TRANSACTION_TRACE):
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
            authority_json = _authority_json(value["authority"], kind=artifact_kind)
        elif artifact_kind == ARTIFACT_MONEY_OBSERVATION:
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
            authority_json = _authority_json(value["authority"], kind=artifact_kind)
        elif artifact_kind == ARTIFACT_TRANSITION:
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
            authority_json = _authority_json(value["authority"], kind=artifact_kind)
        elif artifact_kind == ARTIFACT_STATE_VALUE:
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
            authority_json = _authority_json(value["authority"], kind=artifact_kind)
        elif artifact_kind == ARTIFACT_QUALIFICATION:
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
            authority_json = _authority_json(value["authority"], kind=artifact_kind)
        elif value.get("schema") in (withdrawal_independent.SCHEMA, governance_v2_independent.WITHDRAWAL_SCHEMA):
            result_artifact_id = result.get("artifact_id")
            if not isinstance(result_artifact_id, str):
                raise ArtifactAdmissionError("artifact:withdrawal-id")
            artifact_id = result_artifact_id
            report_id = None
            current_stage_id = str(value["withdrawal_id"])
            transition_id = str(value["withdrawal_root"])
            stage_kind = str(value["action"])
            prior_artifact_id = str(value["approved_artifact_id"])
            prior_stage_id = str(value["approved_stage_id"])
            schema = str(value["schema"])
            subject_id = str(value["provider_graph_subject"])
            scope = str(value["scope"])
            authority_flags = governance_v2_independent.AUTHORITY_FLAGS if schema == governance_v2_independent.WITHDRAWAL_SCHEMA else withdrawal_independent.AUTHORITY_FLAGS
            authority_json = _authority_json({key: value[key] for key in authority_flags}, kind=artifact_kind)
            if schema == governance_v2_independent.WITHDRAWAL_SCHEMA:
                profile_value = governance_v2_independent._expect_keys(value.get("profile"), governance_v2_independent.PROFILE_KEYS, "artifact:profile")
                profile_id = str(profile_value["profile_id"])
        else:
            result_artifact_id = result.get("artifact_id")
            if not isinstance(result_artifact_id, str):
                raise ArtifactAdmissionError("artifact:governance-id")
            subject = value["subject"]
            stages = value["stages"]
            current_stage = stages[-1] if isinstance(stages, list) and stages else None
            if not isinstance(subject, dict) or not isinstance(stages, list) or not isinstance(current_stage, dict):
                raise ArtifactAdmissionError("artifact:governance-shape")
            artifact_id = result_artifact_id
            report_id = None
            current_stage_id = str(current_stage["stage_id"])
            transition_id = str(value["chain_root"])
            stage_kind = str(current_stage["stage_kind"])
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
                    raise ArtifactAdmissionError("governance:prior-prefix") from exc
                prior_artifact_id = str(prefix["artifact_id"])
                prior_stage = stages[-2]
                if not isinstance(prior_stage, dict):
                    raise ArtifactAdmissionError("governance:prior-stage")
                prior_stage_id = str(prior_stage["stage_id"])
            schema = str(value["schema"])
            subject_id = str(subject["provider_graph_subject"])
            scope = str(subject["scope"])
            authority_flags = governance_v2_independent.AUTHORITY_FLAGS if schema == governance_v2_independent.SCHEMA else governance_independent.AUTHORITY_FLAGS
            authority_json = _authority_json({key: value[key] for key in authority_flags}, kind=artifact_kind)
            if schema == governance_v2_independent.SCHEMA:
                profile_value = governance_v2_independent._expect_keys(value.get("profile"), governance_v2_independent.PROFILE_KEYS, "artifact:profile")
                profile_id = str(profile_value["profile_id"])
        if not subject_id or not scope or not artifact_id or not current_stage_id or not transition_id:
            raise ArtifactAdmissionError("artifact:identity-empty")
        if prior_artifact_id is not None and not isinstance(prior_artifact_id, str):
            raise ArtifactAdmissionError("artifact:prior-id")
        if prior_stage_id is not None and not isinstance(prior_stage_id, str):
            raise ArtifactAdmissionError("artifact:prior-stage")
    except (KeyError, TypeError, ValueError) as exc:
        raise ArtifactAdmissionError("artifact:identity-shape") from exc
    return VerifiedArtifact(
        kind=artifact_kind,
        schema=schema,
        artifact_id=artifact_id,
        payload_hash=payload_hash,
        payload=raw,
        subject=subject_id,
        scope=scope,
        report_id=report_id,
        current_stage_id=current_stage_id,
        transition_id=transition_id,
        stage_kind=stage_kind,
        prior_artifact_id=prior_artifact_id,
        prior_stage_id=prior_stage_id,
        authority_json=authority_json,
        profile_id=profile_id,
    )


def _operation_id(artifact: VerifiedArtifact, chain_id: str, expected_head: tuple[str, str]) -> str:
    return _digest(
        "operation-id",
        {
            "chain_id": chain_id,
            "artifact_kind": artifact.kind,
            "artifact_id": artifact.artifact_id,
            "payload_hash": artifact.payload_hash,
            "prior_artifact_id": artifact.prior_artifact_id or NO_PRIOR,
            "prior_stage_id": artifact.prior_stage_id or NO_PRIOR,
            "expected_head_artifact_id": expected_head[0],
            "expected_head_stage_id": expected_head[1],
        },
    )


def _receipt_hash(raw: bytes) -> str:
    """Hash receipt identity material without making event-root hashing circular."""

    value = _parse_canonical(raw, maximum=MAX_RECEIPT_BYTES)
    if "event_root" not in value:
        raise StoreSchemaError("receipt:event-root")
    identity = dict(value)
    identity.pop("event_root")
    return _digest("receipt-hash", identity)


def _event_root(material: Mapping[str, object]) -> str:
    return _digest("event-root", dict(material))


def _state_root(sequence: int, heads: list[Mapping[str, object]]) -> str:
    # A head's state_root is the result of this calculation, not an input to it.
    # Excluding it keeps the state root deterministic and non-circular.
    fields = (
        "chain_id",
        "artifact_kind",
        "artifact_id",
        "current_stage_id",
        "stage_kind",
        "transition_id",
        "event_sequence",
        "head_root",
    )
    ordered = sorted(
        ({key: item[key] for key in fields} for item in heads),
        key=lambda item: str(item["chain_id"]),
    )
    return _digest("state-root", {"event_sequence": sequence, "heads": ordered})


class ContinuityStore:
    """Small transactional SQLite candidate with immutable artifacts and events."""

    def __init__(self, path: str | Path, *, graph_profile_registry: Mapping[str, object] | None = None) -> None:
        self.path = Path(path)
        if self.path.name in {"", ".", ".."}:
            raise StoreSchemaError("database:path")
        if self.path.parent.exists() is False:
            raise StoreSchemaError("database:parent-missing")
        self.graph_profile_registry = MappingProxyType(dict(graph_profile_registry or {}))
        self._fault_point: str | None = None
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        if self.path.is_file() and self.path.stat().st_size > MAX_DB_BYTES:
            raise StoreSchemaError("database:byte-cap")
        wal_path = Path(str(self.path) + "-wal")
        try:
            wal_size = wal_path.stat().st_size if wal_path.is_file() else 0
        except FileNotFoundError:
            # A concurrent FULL checkpoint may remove the WAL between the
            # existence check and stat; reopening the bounded database is safe.
            wal_size = 0
        if wal_size > MAX_WAL_BYTES:
            raise StoreSchemaError("database:wal-byte-cap")
        try:
            connection = sqlite3.connect(self.path, timeout=BUSY_TIMEOUT_MS / 1000, isolation_level=None)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
            journal = connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            if str(journal).lower() != "wal":
                connection.close()
                raise StoreSchemaError("sqlite:wal-required")
            connection.execute("PRAGMA synchronous=FULL")
            if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
                raise StoreSchemaError("sqlite:foreign-keys")
            if connection.execute("PRAGMA trusted_schema").fetchone()[0] != 0:
                raise StoreSchemaError("sqlite:trusted-schema")
            if connection.execute("PRAGMA synchronous").fetchone()[0] != 2:
                raise StoreSchemaError("sqlite:synchronous")
            return connection
        except sqlite3.OperationalError as exc:
            raise StoreBusyError("sqlite:open-busy") from exc

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            expected = {"store_meta", "artifacts", "operations", "receipts", "events", "heads"}
            if tables and tables != expected:
                raise StoreSchemaError("database:unknown-tables")
            if tables:
                self._validate_transaction_snapshot(connection)
            statements = (
                """
                CREATE TABLE IF NOT EXISTS store_meta(
                    key TEXT NOT NULL PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS artifacts(
                    kind TEXT NOT NULL,
                    artifact_id TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    payload BLOB NOT NULL,
                    artifact_schema TEXT NOT NULL,
                    report_id TEXT,
                    current_stage_id TEXT NOT NULL,
                    transition_id TEXT NOT NULL,
                    prior_artifact_id TEXT,
                    prior_stage_id TEXT,
                    subject TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    stage_kind TEXT NOT NULL,
                    authority_json TEXT NOT NULL,
                    PRIMARY KEY(kind, artifact_id),
                    UNIQUE(kind, payload_hash)
                )
                """,
                "CREATE INDEX IF NOT EXISTS artifacts_payload_hash_idx ON artifacts(kind, payload_hash)",
                """
                CREATE TABLE IF NOT EXISTS operations(
                    operation_id TEXT NOT NULL PRIMARY KEY,
                    chain_id TEXT NOT NULL,
                    artifact_kind TEXT NOT NULL,
                    artifact_id TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    prior_artifact_id TEXT,
                    prior_stage_id TEXT,
                    expected_head_artifact_id TEXT NOT NULL,
                    expected_head_stage_id TEXT NOT NULL,
                    event_sequence INTEGER NOT NULL UNIQUE,
                    receipt_hash TEXT NOT NULL UNIQUE,
                    commit_state_root TEXT NOT NULL,
                    FOREIGN KEY(artifact_kind, artifact_id) REFERENCES artifacts(kind, artifact_id)
                )
                """,
                "CREATE INDEX IF NOT EXISTS operations_request_idx ON operations(chain_id, artifact_kind, artifact_id, payload_hash, prior_artifact_id, prior_stage_id)",
                """
                CREATE TABLE IF NOT EXISTS receipts(
                    operation_id TEXT NOT NULL PRIMARY KEY,
                    receipt_hash TEXT NOT NULL UNIQUE,
                    receipt BLOB NOT NULL
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS events(
                    sequence INTEGER NOT NULL PRIMARY KEY,
                    chain_id TEXT NOT NULL,
                    previous_event_root TEXT NOT NULL,
                    event_root TEXT NOT NULL UNIQUE,
                    operation_id TEXT NOT NULL UNIQUE,
                    artifact_kind TEXT NOT NULL,
                    artifact_id TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    prior_artifact_id TEXT,
                    prior_stage_id TEXT,
                    receipt_hash TEXT NOT NULL,
                    commit_state_root TEXT NOT NULL,
                    FOREIGN KEY(operation_id) REFERENCES operations(operation_id),
                    FOREIGN KEY(artifact_kind, artifact_id) REFERENCES artifacts(kind, artifact_id),
                    FOREIGN KEY(receipt_hash) REFERENCES receipts(receipt_hash)
                )
                """,
                "CREATE INDEX IF NOT EXISTS events_chain_idx ON events(chain_id, sequence)",
                """
                CREATE TABLE IF NOT EXISTS heads(
                    chain_id TEXT NOT NULL PRIMARY KEY,
                    artifact_kind TEXT NOT NULL,
                    artifact_id TEXT NOT NULL,
                    current_stage_id TEXT NOT NULL,
                    stage_kind TEXT NOT NULL,
                    transition_id TEXT NOT NULL,
                    event_sequence INTEGER NOT NULL,
                    head_root TEXT NOT NULL,
                    state_root TEXT NOT NULL,
                    FOREIGN KEY(artifact_kind, artifact_id) REFERENCES artifacts(kind, artifact_id)
                )
                """,
            )
            for statement in statements:
                connection.execute(statement)
            row = connection.execute("SELECT value FROM store_meta WHERE key='schema_version'").fetchone()
            if row is None:
                connection.execute("INSERT INTO store_meta(key,value) VALUES('schema_version',?)", (str(SCHEMA_VERSION),))
                connection.execute("INSERT INTO store_meta(key,value) VALUES('schema',?)", (STORE_SCHEMA,))
            elif row[0] != str(SCHEMA_VERSION):
                raise StoreSchemaError("database:schema-version")
            schema_row = connection.execute("SELECT value FROM store_meta WHERE key='schema'").fetchone()
            if schema_row is None or schema_row[0] != STORE_SCHEMA:
                raise StoreSchemaError("database:schema")
            self._validate_transaction_snapshot(connection)
            connection.commit()
        except sqlite3.IntegrityError as exc:
            connection.rollback()
            raise StoreSchemaError("database:schema-integrity") from exc
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def close(self) -> None:
        """Connections are operation-scoped; this is an explicit lifecycle no-op."""

    def _fault(self, point: str) -> None:
        if self._fault_point == point:
            self._fault_point = None
            raise InjectedFault(point)

    def _validate_transaction_snapshot(self, connection: sqlite3.Connection) -> None:
        """Validate schema and all logical rows while this transaction is held."""

        try:
            store_independent._check_sqlite_shape(connection)
            snapshot = store_independent._snapshot_from_connection(connection)
            store_independent._verify_rows(snapshot, graph_profile_registry=self.graph_profile_registry)
        except store_independent.IndependentStoreError as exc:
            raise StoreSchemaError(f"database:conformance:{exc}") from exc

    def _head(self, connection: sqlite3.Connection, chain_id: str) -> sqlite3.Row | None:
        return connection.execute("SELECT * FROM heads WHERE chain_id=?", (chain_id,)).fetchone()

    def _require_active_v2_governance(self, connection: sqlite3.Connection, artifact: VerifiedArtifact) -> None:
        """Require the state-owned approved V2 profile before a new graph write."""

        if artifact.kind != ARTIFACT_GRAPH or artifact.schema != graph_independent.SCHEMA_V2:
            return
        if artifact.profile_id is None:
            raise StoreConflictError("governance:profile-missing")
        governance_chain = _chain_id(ARTIFACT_GOVERNANCE, artifact.subject, artifact.scope, artifact.profile_id)
        row = connection.execute(
            "SELECT h.*, a.payload, a.artifact_schema FROM heads h JOIN artifacts a ON a.kind=h.artifact_kind AND a.artifact_id=h.artifact_id WHERE h.chain_id=?",
            (governance_chain,),
        ).fetchone()
        if row is None:
            raise GovernanceObservationOnly("not-approved")
        if row["artifact_schema"] not in (governance_v2_independent.SCHEMA, governance_v2_independent.WITHDRAWAL_SCHEMA):
            raise StoreConflictError("governance:v1-not-v2")
        try:
            governed = governance_v2_independent.verify_bytes(bytes(row["payload"]), self.graph_profile_registry)
            graph_value = _parse_canonical(artifact.payload)
            observation = graph_value["observation_snapshot"]["observation_time"]
        except Exception as exc:
            raise StoreSchemaError("governance:independent-reject") from exc
        if governed.get("schema") == governance_v2_independent.WITHDRAWAL_SCHEMA:
            raise GovernanceObservationOnly("withdrawn")
        if governed.get("current_stage_kind") != governance_v2_independent.STAGE_APPROVED:
            raise GovernanceObservationOnly("not-approved")
        if governed.get("profile_id") != artifact.profile_id or governed.get("profile_digest") != graph_value["profile"]["profile_digest"]:
            raise StoreConflictError("governance:profile-binding")
        if type(observation) is not int or not governed["effective_start"] <= observation <= governed["effective_end"]:
            raise StoreConflictError("governance:effective-interval")

    def provider_continuity_lifecycle_head(
        self,
        provider_graph_subject: str,
        scope: str,
        profile_id: str | None = None,
    ) -> ProviderContinuityLifecycleHead | None:
        """Return the verified governance-lineage head used for active-status decisions.

        An approved artifact is active only while it remains the current head.  A terminal
        withdrawal is admitted as the next immutable governance-lineage stage and therefore
        makes the same approval non-active without any caller-selected status flag.
        """

        chain_id = _chain_id(ARTIFACT_GOVERNANCE, provider_graph_subject, scope, profile_id)
        connection = self._connect()
        try:
            try:
                connection.execute("BEGIN")
            except sqlite3.OperationalError as exc:
                raise StoreBusyError("transaction:read-busy") from exc
            self._validate_transaction_snapshot(connection)
            row = connection.execute(
                "SELECT h.*, a.subject, a.scope, a.payload, a.artifact_schema FROM heads h JOIN artifacts a ON a.kind=h.artifact_kind AND a.artifact_id=h.artifact_id WHERE h.chain_id=?",
                (chain_id,),
            ).fetchone()
            if row is None:
                connection.commit()
                return None
            if row["artifact_kind"] != ARTIFACT_GOVERNANCE or (row["subject"], row["scope"]) != (provider_graph_subject, scope):
                raise StoreSchemaError("lifecycle:head-binding")
            stage_kind = str(row["stage_kind"])
            if stage_kind == governance_independent.STAGE_APPROVED:
                status, active, terminal = LIFECYCLE_STATUS_APPROVED, True, False
            elif stage_kind == withdrawal_independent.ACTION:
                status, active, terminal = LIFECYCLE_STATUS_WITHDRAWN, False, True
            elif stage_kind in (governance_independent.STAGE_CANDIDATE, governance_independent.STAGE_TESTED):
                status, active, terminal = LIFECYCLE_STATUS_NOT_APPROVED, False, False
            else:
                raise StoreSchemaError("lifecycle:stage-kind")
            result = ProviderContinuityLifecycleHead(
                chain_id=chain_id,
                provider_graph_subject=provider_graph_subject,
                scope=scope,
                artifact_id=str(row["artifact_id"]),
                stage_id=str(row["current_stage_id"]),
                stage_kind=stage_kind,
                transition_id=str(row["transition_id"]),
                event_sequence=int(row["event_sequence"]),
                head_root=str(row["head_root"]),
                state_root=str(row["state_root"]),
                status=status,
                active=active,
                terminal=terminal,
                profile_id=profile_id,
                profile_version=(
                    int(governance_v2_independent.verify_bytes(bytes(row["payload"]), self.graph_profile_registry)["profile_version"])
                    if row["artifact_schema"] in (governance_v2_independent.SCHEMA, governance_v2_independent.WITHDRAWAL_SCHEMA)
                    else None
                ),
            )
            connection.commit()
            return result
        except (StoreSchemaError, StoreBusyError):
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise
        except sqlite3.OperationalError as exc:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise StoreBusyError("transaction:read-operational") from exc
        finally:
            connection.close()

    def _heads_for_state(self, connection: sqlite3.Connection, replacement: Mapping[str, object]) -> list[dict[str, object]]:
        rows = [dict(row) for row in connection.execute("SELECT * FROM heads ORDER BY chain_id")]
        rows = [row for row in rows if row["chain_id"] != replacement["chain_id"]]
        rows.append(dict(replacement))
        return rows

    def _artifact_matches(self, row: sqlite3.Row, artifact: VerifiedArtifact) -> bool:
        return (
            row["payload_hash"] == artifact.payload_hash
            and bytes(row["payload"]) == artifact.payload
            and row["artifact_schema"] == artifact.schema
            and row["current_stage_id"] == artifact.current_stage_id
            and row["transition_id"] == artifact.transition_id
            and row["authority_json"] == artifact.authority_json
        )

    def _insert_or_check_artifact(self, connection: sqlite3.Connection, artifact: VerifiedArtifact) -> None:
        row = connection.execute("SELECT * FROM artifacts WHERE kind=? AND artifact_id=?", (artifact.kind, artifact.artifact_id)).fetchone()
        if row is not None:
            if not self._artifact_matches(row, artifact):
                raise StoreConflictError("artifact:immutable-mismatch")
            return
        collision = connection.execute("SELECT kind,artifact_id FROM artifacts WHERE kind=? AND payload_hash=?", (artifact.kind, artifact.payload_hash)).fetchone()
        if collision is not None:
            raise StoreConflictError("artifact:hash-identity-conflict")
        if connection.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0] >= MAX_ARTIFACTS:
            raise StoreConflictError("artifact:count-cap")
        connection.execute(
            "INSERT INTO artifacts(kind,artifact_id,payload_hash,payload,artifact_schema,report_id,current_stage_id,transition_id,prior_artifact_id,prior_stage_id,subject,scope,stage_kind,authority_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                artifact.kind,
                artifact.artifact_id,
                artifact.payload_hash,
                sqlite3.Binary(artifact.payload),
                artifact.schema,
                artifact.report_id,
                artifact.current_stage_id,
                artifact.transition_id,
                artifact.prior_artifact_id,
                artifact.prior_stage_id,
                artifact.subject,
                artifact.scope,
                artifact.stage_kind,
                artifact.authority_json,
            ),
        )

    def _make_receipt(
        self,
        *,
        operation_id: str,
        event_sequence: int,
        previous_event_root: str,
        event_root: str,
        chain_id: str,
        artifact: VerifiedArtifact,
        expected_head: tuple[str, str],
        head_root: str,
        state_root: str,
        receipt_hash: str | None = None,
    ) -> tuple[bytes, str]:
        value: dict[str, object] = {
            "schema": "mirror-continuity-receipt-v2",
            "operation_id": operation_id,
            "event_sequence": event_sequence,
            "previous_event_root": previous_event_root,
            "event_root": event_root,
            "chain_id": chain_id,
            "artifact_kind": artifact.kind,
            "artifact_id": artifact.artifact_id,
            "payload_hash": artifact.payload_hash,
            "prior_artifact_id": artifact.prior_artifact_id or NO_PRIOR,
            "prior_stage_id": artifact.prior_stage_id or NO_PRIOR,
            "expected_head_artifact_id": expected_head[0],
            "expected_head_stage_id": expected_head[1],
            "resulting_head_artifact_id": artifact.artifact_id,
            "resulting_head_stage_id": artifact.current_stage_id,
            "resulting_head_root": head_root,
            "state_root": state_root,
            "authority": dict(AUTHORITY_FLAGS),
        }
        raw = _canonical(value)
        if len(raw) > MAX_RECEIPT_BYTES:
            raise StoreConflictError("receipt:byte-cap")
        return raw, _receipt_hash(raw)

    def _admit_in_transaction(
        self,
        connection: sqlite3.Connection,
        artifact: VerifiedArtifact,
        request_hash: str,
        *,
        enforce_governance: bool = True,
    ) -> AdmissionReceipt:
        """Insert one artifact while the caller owns BEGIN IMMEDIATE."""

        chain_id = _chain_id(artifact.kind, artifact.subject, artifact.scope, artifact.profile_id)
        existing = connection.execute(
            "SELECT operation_id,request_hash FROM operations WHERE chain_id=? AND artifact_kind=? AND artifact_id=? AND payload_hash=? AND (prior_artifact_id IS ? OR prior_artifact_id=?) AND (prior_stage_id IS ? OR prior_stage_id=?)",
            (
                chain_id, artifact.kind, artifact.artifact_id, artifact.payload_hash,
                artifact.prior_artifact_id, artifact.prior_artifact_id,
                artifact.prior_stage_id, artifact.prior_stage_id,
            ),
        ).fetchone()
        if existing is not None:
            if existing["request_hash"] != request_hash:
                raise StoreConflictError("operation:request-conflict")
            receipt_row = connection.execute("SELECT receipt FROM receipts WHERE operation_id=?", (existing["operation_id"],)).fetchone()
            if receipt_row is None:
                raise StoreSchemaError("operation:receipt-missing")
            return AdmissionReceipt(bytes(receipt_row[0]))
        if enforce_governance:
            self._require_active_v2_governance(connection, artifact)
        head = self._head(connection, chain_id)
        if artifact.prior_artifact_id is None:
            if head is not None:
                raise StoreConflictError("head:unexpected-existing")
            expected_head = (NO_PRIOR, NO_PRIOR)
        else:
            if head is None or (head["artifact_id"], head["current_stage_id"]) != (artifact.prior_artifact_id, artifact.prior_stage_id):
                raise StoreConflictError("head:stale-or-wrong-prior")
            expected_head = (str(head["artifact_id"]), str(head["current_stage_id"]))
        if artifact.kind == ARTIFACT_QUALIFICATION:
            prior_raw: bytes | None = None
            if artifact.prior_artifact_id is not None:
                prior_row = connection.execute(
                    "SELECT payload FROM artifacts WHERE kind=? AND artifact_id=?",
                    (ARTIFACT_QUALIFICATION, artifact.prior_artifact_id),
                ).fetchone()
                if prior_row is None:
                    raise StoreConflictError("qualification:prior-missing")
                prior_raw = bytes(prior_row[0])
            try:
                qualification_independent.verify_artifact(artifact.payload, prior_raw=prior_raw)
            except qualification_independent.IndependentQualificationError as exc:
                raise StoreConflictError(str(exc)) from exc
        operation_id = _operation_id(artifact, chain_id, expected_head)
        by_operation = connection.execute("SELECT request_hash FROM operations WHERE operation_id=?", (operation_id,)).fetchone()
        if by_operation is not None:
            if by_operation["request_hash"] != request_hash:
                raise StoreConflictError("operation:request-conflict")
            receipt_row = connection.execute("SELECT receipt FROM receipts WHERE operation_id=?", (operation_id,)).fetchone()
            if receipt_row is None:
                raise StoreSchemaError("operation:receipt-missing")
            return AdmissionReceipt(bytes(receipt_row[0]))
        self._insert_or_check_artifact(connection, artifact)
        self._fault("after_artifact_insert")
        event_sequence = int(connection.execute("SELECT COALESCE(MAX(sequence),0)+1 FROM events").fetchone()[0])
        if event_sequence > MAX_EVENTS:
            raise StoreConflictError("event:count-cap")
        previous_row = connection.execute("SELECT event_root FROM events ORDER BY sequence DESC LIMIT 1").fetchone()
        previous_event_root = str(previous_row[0]) if previous_row is not None else GENESIS_EVENT_ROOT
        head_root = _digest(
            "head-root",
            {
                "chain_id": chain_id,
                "artifact_kind": artifact.kind,
                "artifact_id": artifact.artifact_id,
                "current_stage_id": artifact.current_stage_id,
                "stage_kind": artifact.stage_kind,
                "transition_id": artifact.transition_id,
                "event_sequence": event_sequence,
            },
        )
        head_material = {
            "chain_id": chain_id,
            "artifact_kind": artifact.kind,
            "artifact_id": artifact.artifact_id,
            "current_stage_id": artifact.current_stage_id,
            "stage_kind": artifact.stage_kind,
            "transition_id": artifact.transition_id,
            "event_sequence": event_sequence,
            "head_root": head_root,
        }
        state_root = _state_root(event_sequence, self._heads_for_state(connection, head_material))
        event_material = {
            "sequence": event_sequence,
            "chain_id": chain_id,
            "previous_event_root": previous_event_root,
            "operation_id": operation_id,
            "artifact_kind": artifact.kind,
            "artifact_id": artifact.artifact_id,
            "payload_hash": artifact.payload_hash,
            "prior_artifact_id": artifact.prior_artifact_id or NO_PRIOR,
            "prior_stage_id": artifact.prior_stage_id or NO_PRIOR,
            "receipt_hash": RECEIPT_EVENT_PLACEHOLDER,
            "commit_state_root": state_root,
        }
        _receipt_template, receipt_hash = self._make_receipt(
            operation_id=operation_id,
            event_sequence=event_sequence,
            previous_event_root=previous_event_root,
            event_root=RECEIPT_EVENT_PLACEHOLDER,
            chain_id=chain_id,
            artifact=artifact,
            expected_head=expected_head,
            head_root=head_root,
            state_root=state_root,
        )
        event_material["receipt_hash"] = receipt_hash
        event_root = _event_root(event_material)
        receipt_raw, final_receipt_hash = self._make_receipt(
            operation_id=operation_id,
            event_sequence=event_sequence,
            previous_event_root=previous_event_root,
            event_root=event_root,
            chain_id=chain_id,
            artifact=artifact,
            expected_head=expected_head,
            head_root=head_root,
            state_root=state_root,
        )
        if final_receipt_hash != receipt_hash:
            raise StoreSchemaError("receipt:identity-binding")
        if _event_root({**event_material, "receipt_hash": final_receipt_hash}) != event_root:
            raise StoreSchemaError("event:receipt-binding")
        connection.execute(
            "INSERT INTO operations(operation_id,chain_id,artifact_kind,artifact_id,payload_hash,request_hash,prior_artifact_id,prior_stage_id,expected_head_artifact_id,expected_head_stage_id,event_sequence,receipt_hash,commit_state_root) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (operation_id, chain_id, artifact.kind, artifact.artifact_id, artifact.payload_hash, request_hash, artifact.prior_artifact_id, artifact.prior_stage_id, expected_head[0], expected_head[1], event_sequence, receipt_hash, state_root),
        )
        connection.execute("INSERT INTO receipts(operation_id,receipt_hash,receipt) VALUES(?,?,?)", (operation_id, receipt_hash, sqlite3.Binary(receipt_raw)))
        connection.execute(
            "INSERT INTO events(sequence,chain_id,previous_event_root,event_root,operation_id,artifact_kind,artifact_id,payload_hash,prior_artifact_id,prior_stage_id,receipt_hash,commit_state_root) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (event_sequence, chain_id, previous_event_root, event_root, operation_id, artifact.kind, artifact.artifact_id, artifact.payload_hash, artifact.prior_artifact_id, artifact.prior_stage_id, receipt_hash, state_root),
        )
        connection.execute(
            "INSERT INTO heads(chain_id,artifact_kind,artifact_id,current_stage_id,stage_kind,transition_id,event_sequence,head_root,state_root) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(chain_id) DO UPDATE SET artifact_kind=excluded.artifact_kind,artifact_id=excluded.artifact_id,current_stage_id=excluded.current_stage_id,stage_kind=excluded.stage_kind,transition_id=excluded.transition_id,event_sequence=excluded.event_sequence,head_root=excluded.head_root,state_root=excluded.state_root",
            (chain_id, artifact.kind, artifact.artifact_id, artifact.current_stage_id, artifact.stage_kind, artifact.transition_id, event_sequence, head_root, state_root),
        )
        return AdmissionReceipt(receipt_raw)

    def admit(self, artifact_kind: str, artifact_raw: bytes) -> AdmissionReceipt:
        """Verify and atomically admit one artifact, or replay its exact receipt."""

        if artifact_kind == ARTIFACT_RECONCILIATION:
            raise StoreConflictError("reconciliation:transaction-required")
        if artifact_kind == ARTIFACT_DENOMINATOR:
            raise StoreConflictError("denominator:transaction-required")
        if artifact_kind in (ARTIFACT_TRANSACTION_OBSERVATION, ARTIFACT_TRANSACTION_TRACE):
            raise StoreConflictError("transaction:transaction-required")
        if artifact_kind == ARTIFACT_MONEY_OBSERVATION:
            raise StoreConflictError("money:transaction-required")
        if artifact_kind == ARTIFACT_TRANSITION:
            raise StoreConflictError("transition:transaction-required")
        if artifact_kind == ARTIFACT_STATE_VALUE:
            raise StoreConflictError("state-value:transaction-required")
        artifact = verify_artifact(artifact_kind, artifact_raw, graph_profile_registry=self.graph_profile_registry)
        if artifact_kind == ARTIFACT_SOURCE_EVIDENCE and source_independent.has_graph_link(artifact_raw):
            raise StoreConflictError("custody:graph-link-transaction-required")
        request_hash = _payload_hash(artifact_raw)
        self._fault("before_transaction")
        connection = self._connect()
        try:
            try:
                connection.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as exc:
                raise StoreBusyError("transaction:busy") from exc
            self._fault("after_begin")
            self._validate_transaction_snapshot(connection)
            receipt = self._admit_in_transaction(
                connection,
                artifact,
                request_hash,
                enforce_governance=artifact_kind != ARTIFACT_QUALIFICATION,
            )
            self._validate_transaction_snapshot(connection)
            self._fault("after_event_receipt_before_commit")
            connection.commit()
            try:
                self._fault("after_commit_before_response")
            except InjectedFault as exc:
                raise IndeterminateCommitError(receipt.operation_id) from exc
            return receipt
        except IndeterminateCommitError:
            raise
        except (InjectedFault, StoreConflictError, StoreSchemaError, StoreBusyError):
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise
        except sqlite3.IntegrityError as exc:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise StoreConflictError("transaction:integrity") from exc
        except sqlite3.OperationalError as exc:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise StoreBusyError("transaction:operational") from exc
        finally:
            connection.close()

    def source_evidence_head(
        self,
        subject: str,
        scope: str,
        profile_id: str,
        graph_profile_registry: Mapping[str, object] | None = None,
    ) -> tuple[str, str] | None:
        """Return the state-owned source-evidence head for canonical retry binding."""

        if graph_profile_registry is not None and dict(graph_profile_registry) != dict(self.graph_profile_registry):
            raise StoreConflictError("profile:registry-mismatch")
        chain_id = _chain_id(ARTIFACT_SOURCE_EVIDENCE, subject, scope, profile_id)
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            self._validate_transaction_snapshot(connection)
            row = connection.execute("SELECT artifact_id,current_stage_id FROM heads WHERE chain_id=?", (chain_id,)).fetchone()
            connection.commit()
            return None if row is None else (str(row["artifact_id"]), str(row["current_stage_id"]))
        except Exception:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()

    def _receipt_for_artifact(self, connection: sqlite3.Connection, artifact: VerifiedArtifact) -> AdmissionReceipt:
        row = connection.execute(
            "SELECT o.operation_id,r.receipt FROM operations o JOIN receipts r ON r.operation_id=o.operation_id WHERE o.artifact_kind=? AND o.artifact_id=? AND o.payload_hash=?",
            (artifact.kind, artifact.artifact_id, artifact.payload_hash),
        ).fetchone()
        if row is None:
            raise StoreSchemaError("operation:artifact-receipt-missing")
        return AdmissionReceipt(bytes(row["receipt"]))

    def find_source_evidence(
        self,
        envelope_raw: bytes,
        graph_profile_registry: Mapping[str, object] | None = None,
    ) -> SourceCustodyAdmission | None:
        """Find an immutable envelope retry without exposing its payload."""

        if type(envelope_raw) is not bytes or not envelope_raw:
            raise StoreConflictError("custody:envelope-bytes")
        if graph_profile_registry is not None and dict(graph_profile_registry) != dict(self.graph_profile_registry):
            raise StoreConflictError("profile:registry-mismatch")
        expected_digest = source_independent._raw_digest("envelope", envelope_raw)
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            self._validate_transaction_snapshot(connection)
            rows = connection.execute(
                "SELECT * FROM artifacts WHERE kind=? ORDER BY artifact_id",
                (ARTIFACT_SOURCE_EVIDENCE,),
            ).fetchall()
            for row in rows:
                candidate_raw = bytes(row["payload"])
                if source_independent.envelope_digest_from_artifact(candidate_raw) != expected_digest:
                    continue
                source_artifact = verify_artifact(ARTIFACT_SOURCE_EVIDENCE, candidate_raw, graph_profile_registry=self.graph_profile_registry)
                source_receipt = self._receipt_for_artifact(connection, source_artifact)
                graph_receipt = None
                if source_independent.has_graph_link(candidate_raw):
                    normalized = source_independent.verify_artifact(candidate_raw, graph_profile_registry=self.graph_profile_registry, allow_unresolved_graph=True)
                    linked_row = connection.execute(
                        "SELECT * FROM artifacts WHERE kind=? AND artifact_id=?",
                        (ARTIFACT_GRAPH, normalized["linked_graph_artifact_id"]),
                    ).fetchone()
                    if linked_row is None:
                        raise StoreSchemaError("custody:linked-graph-missing")
                    linked = verify_artifact(ARTIFACT_GRAPH, bytes(linked_row["payload"]), graph_profile_registry=self.graph_profile_registry)
                    source_independent.verify_artifact(candidate_raw, graph_raw=linked.payload, graph_profile_registry=self.graph_profile_registry)
                    graph_receipt = self._receipt_for_artifact(connection, linked)
                connection.commit()
                return SourceCustodyAdmission(source_receipt, graph_receipt, graph_receipt is not None)
            connection.commit()
            return None
        except Exception:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()

    def _load_source_reconciliation_context(
        self,
        connection: sqlite3.Connection,
        custody_raw: bytes,
        *,
        require_source_head: bool = True,
    ) -> dict[str, object]:
        """Load the verifier-owned custody chain needed for one delta.

        This runs under the caller's transaction.  The returned bytes are
        state-owned rows, never caller-selected predecessor or graph payloads.
        """

        registry = self.graph_profile_registry
        try:
            preview = source_independent.verify_artifact(
                custody_raw,
                graph_profile_registry=registry,
                allow_unresolved_graph=True,
            )
            source_artifact = verify_artifact(
                ARTIFACT_SOURCE_EVIDENCE,
                custody_raw,
                graph_profile_registry=registry,
            )
        except Exception as exc:
            raise StoreConflictError("reconciliation:custody-reject") from exc
        source_row = connection.execute(
            "SELECT * FROM artifacts WHERE kind=? AND artifact_id=?",
            (ARTIFACT_SOURCE_EVIDENCE, source_artifact.artifact_id),
        ).fetchone()
        if source_row is None or bytes(source_row["payload"]) != custody_raw or source_row["payload_hash"] != _payload_hash(custody_raw):
            raise StoreConflictError("reconciliation:custody-not-stored")

        current_graph_raw: bytes | None = None
        if preview.get("linked_graph_artifact_id") is not None:
            graph_row = connection.execute(
                "SELECT * FROM artifacts WHERE kind=? AND artifact_id=?",
                (ARTIFACT_GRAPH, preview["linked_graph_artifact_id"]),
            ).fetchone()
            if graph_row is None:
                raise StoreConflictError("reconciliation:current-graph-missing")
            current_graph_raw = bytes(graph_row["payload"])
            try:
                source_independent.verify_artifact(
                    custody_raw,
                    graph_raw=current_graph_raw,
                    graph_profile_registry=registry,
                )
            except Exception as exc:
                raise StoreConflictError("reconciliation:current-graph-binding") from exc

        source_chain = _chain_id(
            ARTIFACT_SOURCE_EVIDENCE,
            source_artifact.subject,
            source_artifact.scope,
            source_artifact.profile_id,
        )
        source_head = self._head(connection, source_chain)
        if require_source_head and (source_head is None or (source_head["artifact_id"], source_head["current_stage_id"]) != (source_artifact.artifact_id, source_artifact.current_stage_id)):
            raise StoreConflictError("reconciliation:source-not-head")

        prior_custody_raw: bytes | None = None
        prior_graph_raw: bytes | None = None
        prior_source_artifact: VerifiedArtifact | None = None
        if source_artifact.prior_artifact_id is not None:
            prior_row = connection.execute(
                "SELECT * FROM artifacts WHERE kind=? AND artifact_id=?",
                (ARTIFACT_SOURCE_EVIDENCE, source_artifact.prior_artifact_id),
            ).fetchone()
            if prior_row is None or prior_row["current_stage_id"] != source_artifact.prior_stage_id:
                raise StoreConflictError("reconciliation:prior-custody-missing")
            prior_custody_raw = bytes(prior_row["payload"])
            prior_preview = source_independent.verify_artifact(
                prior_custody_raw,
                graph_profile_registry=registry,
                allow_unresolved_graph=True,
            )
            if prior_preview.get("linked_graph_artifact_id") is not None:
                prior_graph_row = connection.execute(
                    "SELECT * FROM artifacts WHERE kind=? AND artifact_id=?",
                    (ARTIFACT_GRAPH, prior_preview["linked_graph_artifact_id"]),
                ).fetchone()
                if prior_graph_row is None:
                    raise StoreConflictError("reconciliation:prior-graph-missing")
                prior_graph_raw = bytes(prior_graph_row["payload"])
            try:
                prior_source_artifact = verify_artifact(
                    ARTIFACT_SOURCE_EVIDENCE,
                    prior_custody_raw,
                    graph_profile_registry=registry,
                )
                source_independent.verify_artifact(
                    prior_custody_raw,
                    graph_raw=prior_graph_raw,
                    graph_profile_registry=registry,
                )
            except Exception as exc:
                raise StoreConflictError("reconciliation:prior-custody-binding") from exc
            if prior_source_artifact.artifact_id != source_artifact.prior_artifact_id or prior_source_artifact.current_stage_id != source_artifact.prior_stage_id:
                raise StoreConflictError("reconciliation:prior-custody-binding")

        recon_chain = _chain_id(
            ARTIFACT_RECONCILIATION,
            source_artifact.subject,
            source_artifact.scope,
            source_artifact.profile_id,
        )
        recon_head = self._head(connection, recon_chain)
        prior_reconciliation_raw: bytes | None = None
        qualified_baseline_custody_raw: bytes | None = None
        chronology_anchor_custody_raw: bytes | None = None
        if prior_source_artifact is None:
            if recon_head is not None:
                raise StoreConflictError("reconciliation:unexpected-existing-head")
        else:
            if recon_head is None:
                raise StoreConflictError("reconciliation:prior-head-missing")
            prior_recon_row = connection.execute(
                "SELECT * FROM artifacts WHERE kind=? AND artifact_id=?",
                (ARTIFACT_RECONCILIATION, recon_head["artifact_id"]),
            ).fetchone()
            if prior_recon_row is None or prior_recon_row["current_stage_id"] != recon_head["current_stage_id"]:
                raise StoreSchemaError("reconciliation:head-artifact-missing")
            prior_reconciliation_raw = bytes(prior_recon_row["payload"])
            try:
                prior_value = reconciliation_independent._parse(prior_reconciliation_raw)
            except Exception as exc:
                raise StoreSchemaError("reconciliation:head-artifact-invalid") from exc
            prior_current = prior_value.get("current_custody")
            if not isinstance(prior_current, dict) or prior_current.get("artifact_id") != source_artifact.prior_artifact_id or prior_current.get("stage_id") != source_artifact.prior_stage_id:
                raise StoreConflictError("reconciliation:prior-head-binding")
            try:
                anchors = reconciliation_independent._validate_anchors(prior_value.get("anchors"))
            except Exception as exc:
                raise StoreSchemaError("reconciliation:prior-anchors") from exc
            for anchor_name, target in (
                ("qualified_content_baseline", anchors["qualified_content_baseline"]),
                ("chronology_anchor", anchors["chronology_anchor"]),
            ):
                if target is None:
                    continue
                anchor_row = connection.execute(
                    "SELECT * FROM artifacts WHERE kind=? AND artifact_id=?",
                    (ARTIFACT_SOURCE_EVIDENCE, target["custody_artifact_id"]),
                ).fetchone()
                if anchor_row is None or anchor_row["current_stage_id"] != target["custody_stage_id"]:
                    raise StoreConflictError(f"reconciliation:{anchor_name}-missing")
                anchor_raw = bytes(anchor_row["payload"])
                try:
                    source_independent.verify_artifact(
                        anchor_raw,
                        graph_profile_registry=registry,
                        allow_unresolved_graph=True,
                    )
                    reconciliation_independent._anchor_view(target, anchor_raw, registry)
                except Exception as exc:
                    raise StoreConflictError(f"reconciliation:{anchor_name}-binding") from exc
                if anchor_name == "qualified_content_baseline":
                    qualified_baseline_custody_raw = anchor_raw
                else:
                    chronology_anchor_custody_raw = anchor_raw

        return {
            "current_custody_raw": custody_raw,
            "prior_custody_raw": prior_custody_raw,
            "current_graph_raw": current_graph_raw,
            "prior_graph_raw": prior_graph_raw,
            "prior_reconciliation_raw": prior_reconciliation_raw,
            "qualified_baseline_custody_raw": qualified_baseline_custody_raw,
            "chronology_anchor_custody_raw": chronology_anchor_custody_raw,
            "source_artifact": source_artifact,
            "source_preview": preview,
            "reconciliation_head": recon_head,
        }

    def source_reconciliation_context(
        self,
        custody_raw: bytes,
        graph_profile_registry: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        """Return an immutable read context for the configured reconciliation service."""

        if graph_profile_registry is not None and dict(graph_profile_registry) != dict(self.graph_profile_registry):
            raise StoreConflictError("profile:registry-mismatch")
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            self._validate_transaction_snapshot(connection)
            context = self._load_source_reconciliation_context(connection, custody_raw)
            connection.commit()
            return {key: value for key, value in context.items() if key not in {"source_artifact", "source_preview", "reconciliation_head"}}
        except Exception:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()

    def find_source_reconciliation(
        self,
        custody_raw: bytes,
        graph_profile_registry: Mapping[str, object] | None = None,
    ) -> AdmissionReceipt | None:
        """Find an exact retry by its already-stored current custody identity."""

        if graph_profile_registry is not None and dict(graph_profile_registry) != dict(self.graph_profile_registry):
            raise StoreConflictError("profile:registry-mismatch")
        try:
            preview = source_independent.verify_artifact(
                custody_raw,
                graph_profile_registry=self.graph_profile_registry,
                allow_unresolved_graph=True,
            )
        except Exception as exc:
            raise StoreConflictError("reconciliation:custody-reject") from exc
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            self._validate_transaction_snapshot(connection)
            source_row = connection.execute(
                "SELECT payload,payload_hash FROM artifacts WHERE kind=? AND artifact_id=?",
                (ARTIFACT_SOURCE_EVIDENCE, preview["artifact_id"]),
            ).fetchone()
            if source_row is None or bytes(source_row["payload"]) != custody_raw or source_row["payload_hash"] != _payload_hash(custody_raw):
                connection.commit()
                return None
            for row in connection.execute("SELECT * FROM artifacts WHERE kind=? ORDER BY artifact_id", (ARTIFACT_RECONCILIATION,)):
                value = reconciliation_independent._parse(bytes(row["payload"]))
                current = value.get("current_custody")
                if isinstance(current, dict) and current.get("artifact_id") == preview["artifact_id"]:
                    receipt_row = connection.execute(
                        "SELECT r.receipt FROM operations o JOIN receipts r ON r.operation_id=o.operation_id WHERE o.artifact_kind=? AND o.artifact_id=? AND o.payload_hash=?",
                        (ARTIFACT_RECONCILIATION, row["artifact_id"], row["payload_hash"]),
                    ).fetchone()
                    if receipt_row is None:
                        raise StoreSchemaError("reconciliation:receipt-missing")
                    receipt = AdmissionReceipt(bytes(receipt_row["receipt"]))
                    connection.commit()
                    return receipt
            connection.commit()
            return None
        except Exception:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()

    def admit_source_reconciliation(
        self,
        custody_raw: bytes,
        reconciliation_raw: bytes,
        graph_profile_registry: Mapping[str, object] | None = None,
    ) -> AdmissionReceipt:
        """Atomically admit one verifier-bound temporal delta over custody state."""

        if graph_profile_registry is not None and dict(graph_profile_registry) != dict(self.graph_profile_registry):
            raise StoreConflictError("profile:registry-mismatch")
        if type(custody_raw) is not bytes or type(reconciliation_raw) is not bytes:
            raise StoreConflictError("reconciliation:bytes")
        self._fault("before_transaction")
        connection = self._connect()
        try:
            try:
                connection.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as exc:
                raise StoreBusyError("transaction:busy") from exc
            self._fault("after_begin")
            self._validate_transaction_snapshot(connection)
            try:
                current_preview = source_independent.verify_artifact(
                    custody_raw,
                    graph_profile_registry=self.graph_profile_registry,
                    allow_unresolved_graph=True,
                )
            except Exception as exc:
                raise StoreConflictError("reconciliation:custody-reject") from exc
            current_source_row = connection.execute(
                "SELECT payload,payload_hash FROM artifacts WHERE kind=? AND artifact_id=?",
                (ARTIFACT_SOURCE_EVIDENCE, current_preview["artifact_id"]),
            ).fetchone()
            if current_source_row is not None and (bytes(current_source_row["payload"]) != custody_raw or current_source_row["payload_hash"] != _payload_hash(custody_raw)):
                raise StoreConflictError("reconciliation:custody-identity-conflict")
            if current_source_row is not None:
                for existing_row in connection.execute("SELECT * FROM artifacts WHERE kind=? ORDER BY artifact_id", (ARTIFACT_RECONCILIATION,)):
                    existing_value = reconciliation_independent._parse(bytes(existing_row["payload"]))
                    existing_current = existing_value.get("current_custody")
                    if isinstance(existing_current, dict) and existing_current.get("artifact_id") == current_preview["artifact_id"]:
                        if bytes(existing_row["payload"]) != reconciliation_raw:
                            raise StoreConflictError("reconciliation:identity-conflict")
                        receipt_row = connection.execute(
                            "SELECT r.receipt FROM operations o JOIN receipts r ON r.operation_id=o.operation_id WHERE o.artifact_kind=? AND o.artifact_id=? AND o.payload_hash=?",
                            (ARTIFACT_RECONCILIATION, existing_row["artifact_id"], existing_row["payload_hash"]),
                        ).fetchone()
                        if receipt_row is None:
                            raise StoreSchemaError("reconciliation:receipt-missing")
                        connection.commit()
                        return AdmissionReceipt(bytes(receipt_row["receipt"]))
            context = self._load_source_reconciliation_context(connection, custody_raw)
            artifact = verify_artifact(
                ARTIFACT_RECONCILIATION,
                reconciliation_raw,
                graph_profile_registry=self.graph_profile_registry,
                reconciliation_context=context,
            )
            receipt = self._admit_in_transaction(
                connection,
                artifact,
                _payload_hash(reconciliation_raw),
                enforce_governance=False,
            )
            self._validate_transaction_snapshot(connection)
            self._fault("after_event_receipt_before_commit")
            connection.commit()
            try:
                self._fault("after_commit_before_response")
            except InjectedFault as exc:
                raise IndeterminateCommitError(receipt.operation_id) from exc
            return receipt
        except IndeterminateCommitError:
            raise
        except (InjectedFault, StoreConflictError, StoreSchemaError, StoreBusyError):
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise
        except sqlite3.IntegrityError as exc:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise StoreConflictError("transaction:integrity") from exc
        except sqlite3.OperationalError as exc:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise StoreBusyError("transaction:operational") from exc
        finally:
            connection.close()

    def _denominator_active_governance(
        self,
        connection: sqlite3.Connection,
        observation_time: int,
    ) -> bytes:
        """Select the verifier-owned current approval for a new baseline."""

        profile_value = nc_profile.NC_MEDICAID_GRAPH_PROFILE
        chain_id = _chain_id(
            ARTIFACT_GOVERNANCE,
            profile_value.subject,
            profile_value.scope,
            profile_value.profile_id,
        )
        row = connection.execute(
            "SELECT h.*, a.payload, a.artifact_schema FROM heads h JOIN artifacts a ON a.kind=h.artifact_kind AND a.artifact_id=h.artifact_id WHERE h.chain_id=?",
            (chain_id,),
        ).fetchone()
        if row is None:
            raise GovernanceObservationOnly("not-approved")
        if row["artifact_schema"] not in (governance_v2_independent.SCHEMA, governance_v2_independent.WITHDRAWAL_SCHEMA):
            raise StoreConflictError("governance:v1-not-v2")
        raw = bytes(row["payload"])
        try:
            value = _parse_canonical(raw)
            result = governance_v2_independent.verify_bytes(raw, self.graph_profile_registry)
        except Exception as exc:
            raise StoreSchemaError("governance:independent-reject") from exc
        if value.get("schema") == governance_v2_independent.WITHDRAWAL_SCHEMA:
            raise GovernanceObservationOnly("withdrawn")
        if result.get("current_stage_kind") != governance_v2_independent.STAGE_APPROVED:
            raise GovernanceObservationOnly("not-approved")
        if result.get("profile_id") != profile_value.profile_id or result.get("profile_digest") != profile_value.profile_digest:
            raise StoreConflictError("governance:profile-binding")
        if type(observation_time) is not int or not result["effective_start"] <= observation_time <= result["effective_end"]:
            raise StoreConflictError("governance:effective-interval")
        return raw

    def _denominator_source_context(
        self,
        connection: sqlite3.Connection,
        source_artifact_id: str,
        *,
        governance_raw: bytes | None = None,
        require_current_source_head: bool = True,
    ) -> dict[str, object]:
        """Load source, optional graph, and governing approval inside a transaction."""

        row = connection.execute(
            "SELECT * FROM artifacts WHERE kind=? AND artifact_id=?",
            (ARTIFACT_SOURCE_EVIDENCE, source_artifact_id),
        ).fetchone()
        if row is None:
            raise StoreConflictError("denominator:source-missing")
        source_raw = bytes(row["payload"])
        try:
            source_value = source_independent._parse(source_raw)
            preview = source_independent.verify_artifact(
                source_raw,
                graph_profile_registry=self.graph_profile_registry,
                allow_unresolved_graph=True,
            )
        except Exception as exc:
            raise StoreConflictError("denominator:source-reject") from exc
        if preview["artifact_id"] != source_artifact_id or row["current_stage_id"] != preview["current_stage_id"]:
            raise StoreConflictError("denominator:source-identity")
        source_chain = _chain_id(ARTIFACT_SOURCE_EVIDENCE, preview["subject"], preview["scope"], preview["profile_id"])
        source_head = self._head(connection, source_chain)
        if require_current_source_head and (source_head is None or (source_head["artifact_id"], source_head["current_stage_id"]) != (source_artifact_id, preview["current_stage_id"])):
            raise StoreConflictError("denominator:source-not-head")
        graph_raw: bytes | None = None
        linked_graph_id = preview.get("linked_graph_artifact_id")
        if linked_graph_id is not None:
            graph_row = connection.execute(
                "SELECT * FROM artifacts WHERE kind=? AND artifact_id=?",
                (ARTIFACT_GRAPH, linked_graph_id),
            ).fetchone()
            if graph_row is None:
                raise StoreConflictError("denominator:graph-missing")
            graph_raw = bytes(graph_row["payload"])
            try:
                source_independent.verify_artifact(
                    source_raw,
                    graph_raw=graph_raw,
                    graph_profile_registry=self.graph_profile_registry,
                )
            except Exception as exc:
                raise StoreConflictError("denominator:graph-binding") from exc
        if governance_raw is None:
            governance_raw = self._denominator_active_governance(connection, int(source_value["observation_time"]))
        else:
            try:
                governed = governance_v2_independent.verify_bytes(governance_raw, self.graph_profile_registry)
            except Exception as exc:
                raise StoreConflictError("denominator:governance-reject") from exc
            if governed.get("current_stage_kind") != governance_v2_independent.STAGE_APPROVED:
                raise StoreConflictError("denominator:governance-history")
        return {
            "source_raw": source_raw,
            "graph_raw": graph_raw,
            "governance_raw": governance_raw,
            "source_preview": preview,
        }

    def _denominator_context_for_prior(
        self,
        connection: sqlite3.Connection,
        prior_raw: bytes,
    ) -> dict[str, object]:
        value = denominator_independent._parse(prior_raw)
        source_binding = value.get("source_binding")
        governance_binding = value.get("governance_binding")
        if not isinstance(source_binding, dict) or not isinstance(governance_binding, dict):
            raise StoreConflictError("denominator:prior-binding")
        governance_row = connection.execute(
            "SELECT payload,current_stage_id FROM artifacts WHERE kind=? AND artifact_id=?",
            (ARTIFACT_GOVERNANCE, governance_binding["artifact_id"]),
        ).fetchone()
        if governance_row is None or governance_row["current_stage_id"] != governance_binding["stage_id"]:
            raise StoreConflictError("denominator:prior-governance")
        return self._denominator_source_context(
            connection,
            str(source_binding["artifact_id"]),
            governance_raw=bytes(governance_row["payload"]),
            require_current_source_head=False,
        ) | {"prior_denominator_raw": prior_raw}

    def _contract_denominator_context(
        self,
        connection: sqlite3.Connection,
        denominator_raw: bytes,
    ) -> dict[str, object]:
        """Load every source/governance byte named by a stored denominator."""

        try:
            value = denominator_independent._parse(denominator_raw)
            source_binding = value["source_binding"]
            governance_binding = value["governance_binding"]
            if not isinstance(source_binding, dict) or not isinstance(governance_binding, dict):
                raise StoreConflictError("contract:denominator-binding")
            governance_row = connection.execute(
                "SELECT payload,current_stage_id FROM artifacts WHERE kind=? AND artifact_id=?",
                (ARTIFACT_GOVERNANCE, governance_binding["artifact_id"]),
            ).fetchone()
            if governance_row is None or governance_row["current_stage_id"] != governance_binding["stage_id"]:
                raise StoreConflictError("contract:governance-missing")
            prior_raw = None
            prior_id = value.get("prior_artifact_id")
            if prior_id is not None:
                prior_row = connection.execute(
                    "SELECT payload FROM artifacts WHERE kind=? AND artifact_id=?",
                    (ARTIFACT_DENOMINATOR, prior_id),
                ).fetchone()
                if prior_row is None:
                    raise StoreConflictError("contract:denominator-prior")
                prior_raw = bytes(prior_row["payload"])
            loaded_context = self._denominator_source_context(
                connection,
                str(source_binding["artifact_id"]),
                governance_raw=bytes(governance_row["payload"]),
                require_current_source_head=False,
            )
            # Contract Mirror receives only the exact independently verified
            # denominator inputs it consumes.  The source preview is useful
            # to the denominator owner, but it is not part of this seam.
            return {
                "source_raw": loaded_context["source_raw"],
                "graph_raw": loaded_context.get("graph_raw"),
                "governance_raw": loaded_context["governance_raw"],
                "prior_denominator_raw": prior_raw,
            }
        except StoreConflictError:
            raise
        except Exception as exc:
            raise StoreConflictError("contract:denominator-context") from exc

    def _contract_case_context_for_raw(
        self,
        connection: sqlite3.Connection,
        case_raw: bytes,
    ) -> dict[str, object]:
        """Load the exact case predecessor/retest context for Contract verification."""

        value = case_independent._parse(case_raw)
        upstream = value["upstream"]
        context = self._case_upstream_context(
            connection,
            str(upstream["graph"]["artifact_id"]),
            str(upstream["reconciliation"]["artifact_id"]),
            str(upstream["finding"]["finding_id"]),
        )
        prior_case_raw = None
        prior_id = value["transition"].get("prior_artifact_id")
        if prior_id is not None:
            row = connection.execute(
                "SELECT payload FROM artifacts WHERE kind=? AND artifact_id=?",
                (ARTIFACT_CASE, prior_id),
            ).fetchone()
            if row is None:
                raise StoreConflictError("contract:case-prior")
            prior_case_raw = bytes(row["payload"])
        retest_raw = None
        retest_context = None
        retest_id = value["retest"].get("reconciliation_artifact_id")
        if retest_id is not None:
            row = connection.execute(
                "SELECT payload FROM artifacts WHERE kind=? AND artifact_id=?",
                (ARTIFACT_RECONCILIATION, retest_id),
            ).fetchone()
            if row is None:
                raise StoreConflictError("contract:case-retest")
            retest_raw = bytes(row["payload"])
            retest_context = self._case_reconciliation_context_for_raw(connection, retest_raw)
        return {
            **context,
            "prior_case_raw": prior_case_raw,
            "retest_reconciliation_raw": retest_raw,
            "retest_context": retest_context,
        }

    def _contract_reconciliation_context(
        self,
        connection: sqlite3.Connection,
        reconciliation_artifact_id: str,
    ) -> tuple[bytes, dict[str, object]]:
        row = connection.execute(
            "SELECT payload FROM artifacts WHERE kind=? AND artifact_id=?",
            (ARTIFACT_RECONCILIATION, reconciliation_artifact_id),
        ).fetchone()
        if row is None:
            raise StoreConflictError("contract:reconciliation-missing")
        raw = bytes(row["payload"])
        context = self._case_reconciliation_context_for_raw(connection, raw)
        try:
            value = reconciliation_independent._parse(raw)
            recon_result = reconciliation_independent.verify_artifact(
                raw,
                current_custody_raw=context["current_custody_raw"],
                prior_custody_raw=context.get("prior_custody_raw"),
                current_graph_raw=context.get("current_graph_raw"),
                prior_graph_raw=context.get("prior_graph_raw"),
                prior_reconciliation_raw=context.get("prior_reconciliation_raw"),
                qualified_baseline_custody_raw=context.get("qualified_baseline_custody_raw"),
                chronology_anchor_custody_raw=context.get("chronology_anchor_custody_raw"),
                graph_profile_registry=self.graph_profile_registry,
            )
            profile_id = recon_result["profile_id"]
            chain_id = _chain_id(ARTIFACT_RECONCILIATION, value["subject"], value["scope"], profile_id)
            head = self._head(connection, chain_id)
            if head is None or head["artifact_id"] != value["artifact_id"] or head["current_stage_id"] != value["current_stage_id"]:
                raise StoreConflictError("contract:reconciliation-not-head")
        except StoreConflictError:
            raise
        except Exception as exc:
            raise StoreConflictError("contract:reconciliation-reject") from exc
        return raw, context

    def _contract_active_governance(self, connection: sqlite3.Connection, observation_raw: bytes) -> bytes:
        try:
            value = reconciliation_independent._parse(observation_raw)
            current = value["current_custody"]
            source_row = connection.execute(
                "SELECT payload FROM artifacts WHERE kind=? AND artifact_id=?",
                (ARTIFACT_SOURCE_EVIDENCE, current["artifact_id"]),
            ).fetchone()
            if source_row is None:
                raise StoreConflictError("contract:observation-source")
            source_value = source_independent._parse(bytes(source_row["payload"]))
            return self._denominator_active_governance(connection, int(source_value["observation_time"]))
        except GovernanceObservationOnly:
            raise
        except StoreConflictError:
            raise
        except Exception as exc:
            raise StoreConflictError("contract:governance-context") from exc

    def _contract_context_for_raw(
        self,
        connection: sqlite3.Connection,
        contract_raw: bytes,
    ) -> dict[str, object]:
        value = contract_independent._parse(contract_raw)
        denominator_id = value["denominator"]["artifact_id"]
        case_artifact_id = value["case_link"]["artifact_id"]
        denominator_row = connection.execute(
            "SELECT payload FROM artifacts WHERE kind=? AND artifact_id=?",
            (ARTIFACT_DENOMINATOR, denominator_id),
        ).fetchone()
        case_row = connection.execute(
            "SELECT payload FROM artifacts WHERE kind=? AND artifact_id=?",
            (ARTIFACT_CASE, case_artifact_id),
        ).fetchone()
        if denominator_row is None or case_row is None:
            raise StoreConflictError("contract:upstream-missing")
        denominator_raw = bytes(denominator_row["payload"])
        case_raw = bytes(case_row["payload"])
        prior_contract_raw = None
        prior_id = value.get("prior_artifact_id")
        if prior_id is not None:
            prior_row = connection.execute(
                "SELECT payload FROM artifacts WHERE kind=? AND artifact_id=?",
                (ARTIFACT_CONTRACT, prior_id),
            ).fetchone()
            if prior_row is None:
                raise StoreConflictError("contract:prior-missing")
            prior_contract_raw = bytes(prior_row["payload"])
        return {
            "denominator_raw": denominator_raw,
            "denominator_context": self._contract_denominator_context(connection, denominator_raw),
            "case_raw": case_raw,
            "case_context": self._contract_case_context_for_raw(connection, case_raw),
            "prior_contract_raw": prior_contract_raw,
        }

    def _contract_head_row(self, connection: sqlite3.Connection, contract_artifact_id: str) -> sqlite3.Row:
        row = connection.execute(
            "SELECT h.*, a.payload FROM heads h JOIN artifacts a ON a.kind=h.artifact_kind AND a.artifact_id=h.artifact_id WHERE h.artifact_kind=? AND h.artifact_id=?",
            (ARTIFACT_CONTRACT, contract_artifact_id),
        ).fetchone()
        if row is None:
            raise StoreConflictError("contract:head-missing")
        return row

    def _transaction_contract_context(
        self,
        connection: sqlite3.Connection,
        contract_artifact_id: str,
        *,
        require_head: bool,
    ) -> dict[str, object]:
        row = connection.execute(
            "SELECT payload,current_stage_id FROM artifacts WHERE kind=? AND artifact_id=?",
            (ARTIFACT_CONTRACT, contract_artifact_id),
        ).fetchone()
        if row is None:
            raise StoreConflictError("transaction:contract-missing")
        contract_raw = bytes(row["payload"])
        contract_value = contract_independent._parse(contract_raw)
        if require_head:
            head = self._contract_head_row(connection, contract_artifact_id)
            if head["current_stage_id"] != row["current_stage_id"]:
                raise StoreConflictError("transaction:contract-not-head")
        contract_context = self._contract_context_for_raw(connection, contract_raw)
        verify_artifact(
            ARTIFACT_CONTRACT,
            contract_raw,
            graph_profile_registry=self.graph_profile_registry,
            contract_context=contract_context,
        )
        source_raw = contract_context["denominator_context"]["source_raw"]
        if not isinstance(source_raw, bytes):
            raise StoreConflictError("transaction:source-missing")
        return {
            "source_raw": source_raw,
            "contract_raw": contract_raw,
            "contract_value": contract_value,
            "contract_context": contract_context,
        }

    def _transaction_context_for_raw(
        self,
        connection: sqlite3.Connection,
        transaction_raw: bytes,
        *,
        require_contract_head: bool,
    ) -> dict[str, object]:
        value = transaction_independent._parse(transaction_raw)
        contract_id = str(value["contract_binding"]["artifact_id"])
        context = self._transaction_contract_context(
            connection,
            contract_id,
            require_head=require_contract_head,
        )
        result: dict[str, object] = {
            "source_raw": context["source_raw"],
            "contract_raw": context["contract_raw"],
            "contract_value": context["contract_value"],
            "contract_context": context["contract_context"],
            "prior_observation_raw": None,
            "prior_trace_raw": None,
            "observation_raw": None,
        }
        if value["schema"] == transaction_independent.OBSERVATION_SCHEMA:
            prior_id = value.get("prior_artifact_id")
            if prior_id is not None:
                row = connection.execute(
                    "SELECT payload FROM artifacts WHERE kind=? AND artifact_id=?",
                    (ARTIFACT_TRANSACTION_OBSERVATION, prior_id),
                ).fetchone()
                if row is None:
                    raise StoreConflictError("transaction:observation-prior-missing")
                result["prior_observation_raw"] = bytes(row["payload"])
        elif value["schema"] == transaction_independent.TRACE_SCHEMA:
            observation_id = str(value["observation_binding"]["artifact_id"])
            observation_row = connection.execute(
                "SELECT payload FROM artifacts WHERE kind=? AND artifact_id=?",
                (ARTIFACT_TRANSACTION_OBSERVATION, observation_id),
            ).fetchone()
            if observation_row is None:
                raise StoreConflictError("transaction:observation-missing")
            result["observation_raw"] = bytes(observation_row["payload"])
            prior_id = value.get("prior_artifact_id")
            if prior_id is not None:
                prior_row = connection.execute(
                    "SELECT payload FROM artifacts WHERE kind=? AND artifact_id=?",
                    (ARTIFACT_TRANSACTION_TRACE, prior_id),
                ).fetchone()
                if prior_row is None:
                    raise StoreConflictError("transaction:trace-prior-missing")
                prior_raw = bytes(prior_row["payload"])
                result["prior_trace_raw"] = prior_raw
                prior_value = transaction_independent._parse(prior_raw)
                prior_observation_id = str(prior_value["observation_binding"]["artifact_id"])
                prior_observation_row = connection.execute(
                    "SELECT payload FROM artifacts WHERE kind=? AND artifact_id=?",
                    (ARTIFACT_TRANSACTION_OBSERVATION, prior_observation_id),
                ).fetchone()
                if prior_observation_row is None:
                    raise StoreConflictError("transaction:prior-observation-missing")
                result["prior_observation_raw"] = bytes(prior_observation_row["payload"])
        else:
            raise StoreConflictError("transaction:schema")
        return result

    def _transaction_require_active(self, connection: sqlite3.Connection, context: Mapping[str, object]) -> None:
        contract_context = context["contract_context"]
        case_context = contract_context["case_context"]
        reconciliation_raw = case_context.get("reconciliation_raw")
        if not isinstance(reconciliation_raw, bytes):
            raise StoreConflictError("transaction:reconciliation-missing")
        self._contract_active_governance(connection, reconciliation_raw)

    def _transaction_existing_receipt(
        self,
        connection: sqlite3.Connection,
        artifact: VerifiedArtifact,
        request_hash: str,
    ) -> AdmissionReceipt | None:
        chain_id = _chain_id(artifact.kind, artifact.subject, artifact.scope, artifact.profile_id)
        row = connection.execute(
            "SELECT operation_id,request_hash FROM operations WHERE chain_id=? AND artifact_kind=? AND artifact_id=? AND payload_hash=? AND (prior_artifact_id IS ? OR prior_artifact_id=?) AND (prior_stage_id IS ? OR prior_stage_id=?)",
            (
                chain_id,
                artifact.kind,
                artifact.artifact_id,
                artifact.payload_hash,
                artifact.prior_artifact_id,
                artifact.prior_artifact_id,
                artifact.prior_stage_id,
                artifact.prior_stage_id,
            ),
        ).fetchone()
        if row is None:
            return None
        if row["request_hash"] != request_hash:
            raise StoreConflictError("transaction:request-conflict")
        receipt_row = connection.execute("SELECT receipt FROM receipts WHERE operation_id=?", (row["operation_id"],)).fetchone()
        if receipt_row is None:
            raise StoreSchemaError("transaction:receipt-missing")
        return AdmissionReceipt(bytes(receipt_row["receipt"]))

    def admit_transaction(
        self,
        action: str,
        *,
        contract_artifact_id: str | None = None,
        trace_artifact_id: str | None = None,
        fixture_id: str | None = None,
        graph_profile_registry: Mapping[str, object] | None = None,
    ) -> AdmissionReceipt:
        """Atomically append a fixed synthetic boundary observation and trace."""

        if graph_profile_registry is not None and dict(graph_profile_registry) != dict(self.graph_profile_registry):
            raise StoreConflictError("profile:registry-mismatch")
        if action == "TRACE_INITIAL":
            if not isinstance(contract_artifact_id, str) or not contract_artifact_id or not isinstance(fixture_id, str) or fixture_id not in transaction_independent.FIXTURES[:3] or trace_artifact_id is not None:
                raise StoreConflictError("transaction:initial-selectors")
        elif action == "TRACE_CORRECTION":
            if not isinstance(trace_artifact_id, str) or not trace_artifact_id or fixture_id != transaction_independent.FIXTURE_CORRECTION or contract_artifact_id is not None:
                raise StoreConflictError("transaction:correction-selectors")
        elif action == "TRACE_APPEAL":
            if not isinstance(trace_artifact_id, str) or not trace_artifact_id or fixture_id != transaction_independent.FIXTURE_APPEAL or contract_artifact_id is not None:
                raise StoreConflictError("transaction:appeal-selectors")
        else:
            raise StoreConflictError("transaction:action")

        self._fault("before_transaction")
        connection = self._connect()
        try:
            try:
                connection.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as exc:
                raise StoreBusyError("transaction:busy") from exc
            self._fault("after_begin")
            self._validate_transaction_snapshot(connection)

            if action == "TRACE_INITIAL":
                assert contract_artifact_id is not None and fixture_id is not None
                context = self._transaction_contract_context(connection, contract_artifact_id, require_head=False)
                from app.mirror import transaction_mirror as producer

                observation_raw = producer.build_observation_artifact(
                    fixture_id,
                    source_raw=context["source_raw"],
                    contract_raw=context["contract_raw"],
                )
                observation_context = {
                    "source_raw": context["source_raw"],
                    "contract_raw": context["contract_raw"],
                    "contract_context": context["contract_context"],
                    "prior_observation_raw": None,
                }
                observation = verify_artifact(
                    ARTIFACT_TRANSACTION_OBSERVATION,
                    observation_raw,
                    graph_profile_registry=self.graph_profile_registry,
                    transaction_context=observation_context,
                )
                trace_raw = producer.build_trace_artifact(
                    source_raw=context["source_raw"],
                    contract_raw=context["contract_raw"],
                    observation_raw=observation_raw,
                )
                trace_context = {
                    **observation_context,
                    "observation_raw": observation_raw,
                    "prior_trace_raw": None,
                    "prior_observation_raw": None,
                }
                trace = verify_artifact(
                    ARTIFACT_TRANSACTION_TRACE,
                    trace_raw,
                    graph_profile_registry=self.graph_profile_registry,
                    transaction_context=trace_context,
                )
                observation_request_hash = _payload_hash(observation_raw)
                trace_request_hash = _payload_hash(trace_raw)
                existing_observation = self._transaction_existing_receipt(connection, observation, observation_request_hash)
                existing_trace = self._transaction_existing_receipt(connection, trace, trace_request_hash)
                if existing_observation is not None and existing_trace is not None:
                    connection.commit()
                    return existing_trace
                self._transaction_contract_context(connection, contract_artifact_id, require_head=True)
                self._transaction_require_active(connection, context)
                self._admit_in_transaction(connection, observation, observation_request_hash, enforce_governance=False)
                receipt = self._admit_in_transaction(connection, trace, trace_request_hash, enforce_governance=False)
            else:
                assert trace_artifact_id is not None and fixture_id is not None
                prior_row = connection.execute(
                    "SELECT payload,current_stage_id FROM artifacts WHERE kind=? AND artifact_id=?",
                    (ARTIFACT_TRANSACTION_TRACE, trace_artifact_id),
                ).fetchone()
                if prior_row is None:
                    raise StoreConflictError("transaction:trace-missing")
                prior_trace_raw = bytes(prior_row["payload"])
                prior_trace_value = transaction_independent._parse(prior_trace_raw)
                if prior_trace_value["stage_kind"] not in transaction_independent.TRACE_STAGES[:2]:
                    raise StoreConflictError("transaction:trace-stage")
                prior_context = self._transaction_context_for_raw(connection, prior_trace_raw, require_contract_head=False)
                prior_observation_raw = prior_context["observation_raw"]
                if not isinstance(prior_observation_raw, bytes):
                    raise StoreConflictError("transaction:prior-observation")
                from app.mirror import transaction_mirror as producer

                observation_raw = producer.build_observation_artifact(
                    fixture_id,
                    source_raw=prior_context["source_raw"],
                    contract_raw=prior_context["contract_raw"],
                    prior_observation_raw=prior_observation_raw,
                )
                observation_context = {
                    "source_raw": prior_context["source_raw"],
                    "contract_raw": prior_context["contract_raw"],
                    "contract_context": prior_context["contract_context"],
                    "prior_observation_raw": prior_observation_raw,
                }
                observation = verify_artifact(
                    ARTIFACT_TRANSACTION_OBSERVATION,
                    observation_raw,
                    graph_profile_registry=self.graph_profile_registry,
                    transaction_context=observation_context,
                )
                trace_raw = producer.build_trace_artifact(
                    source_raw=prior_context["source_raw"],
                    contract_raw=prior_context["contract_raw"],
                    observation_raw=observation_raw,
                    prior_trace_raw=prior_trace_raw,
                )
                trace_context = {
                    **observation_context,
                    "observation_raw": observation_raw,
                    "prior_trace_raw": prior_trace_raw,
                    "prior_observation_raw": prior_observation_raw,
                }
                trace = verify_artifact(
                    ARTIFACT_TRANSACTION_TRACE,
                    trace_raw,
                    graph_profile_registry=self.graph_profile_registry,
                    transaction_context=trace_context,
                )
                observation_request_hash = _payload_hash(observation_raw)
                trace_request_hash = _payload_hash(trace_raw)
                existing_observation = self._transaction_existing_receipt(connection, observation, observation_request_hash)
                existing_trace = self._transaction_existing_receipt(connection, trace, trace_request_hash)
                if existing_observation is not None and existing_trace is not None:
                    connection.commit()
                    return existing_trace
                self._transaction_contract_context(connection, prior_context["contract_value"]["artifact_id"], require_head=True)
                self._transaction_require_active(connection, prior_context)
                self._admit_in_transaction(connection, observation, observation_request_hash, enforce_governance=False)
                receipt = self._admit_in_transaction(connection, trace, trace_request_hash, enforce_governance=False)

            self._validate_transaction_snapshot(connection)
            self._fault("after_event_receipt_before_commit")
            connection.commit()
            try:
                self._fault("after_commit_before_response")
            except InjectedFault as exc:
                raise IndeterminateCommitError(receipt.operation_id) from exc
            return receipt
        except IndeterminateCommitError:
            raise
        except (InjectedFault, StoreConflictError, StoreSchemaError, StoreBusyError):
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise
        except sqlite3.IntegrityError as exc:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise StoreConflictError("transaction:integrity") from exc
        except sqlite3.OperationalError as exc:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise StoreBusyError("transaction:operational") from exc
        finally:
            connection.close()

    def _transaction_trace_for_money(
        self,
        connection: sqlite3.Connection,
        trace_artifact_id: str,
        *,
        require_contract_head: bool,
    ) -> tuple[bytes, dict[str, object], VerifiedArtifact]:
        row = connection.execute(
            "SELECT payload FROM artifacts WHERE kind=? AND artifact_id=?",
            (ARTIFACT_TRANSACTION_TRACE, trace_artifact_id),
        ).fetchone()
        if row is None:
            raise StoreConflictError("money:trace-missing")
        trace_raw = bytes(row["payload"])
        context = self._transaction_context_for_raw(connection, trace_raw, require_contract_head=require_contract_head)
        trace = verify_artifact(
            ARTIFACT_TRANSACTION_TRACE,
            trace_raw,
            graph_profile_registry=self.graph_profile_registry,
            transaction_context=context,
        )
        chain_id = _chain_id(trace.kind, trace.subject, trace.scope, trace.profile_id)
        head = self._head(connection, chain_id)
        if head is None or (head["artifact_id"], head["current_stage_id"]) != (trace.artifact_id, trace.current_stage_id):
            raise StoreConflictError("money:trace-not-head")
        return trace_raw, context, trace

    def _money_context_for_raw(self, connection: sqlite3.Connection, money_raw: bytes) -> dict[str, object]:
        value = money_independent._parse(money_raw)
        binding = value.get("transaction_binding")
        if not isinstance(binding, Mapping):
            raise StoreConflictError("money:transaction-binding")
        trace_id = binding.get("trace_artifact_id")
        if not isinstance(trace_id, str) or not trace_id:
            raise StoreConflictError("money:trace-selector")
        trace_raw, transaction_context, _trace = self._transaction_trace_for_money(
            connection,
            trace_id,
            require_contract_head=False,
        )
        prior_money_raw = None
        prior_id = value.get("prior_artifact_id")
        if prior_id is not None:
            row = connection.execute(
                "SELECT payload FROM artifacts WHERE kind=? AND artifact_id=?",
                (ARTIFACT_MONEY_OBSERVATION, prior_id),
            ).fetchone()
            if row is None:
                raise StoreConflictError("money:prior-missing")
            prior_money_raw = bytes(row["payload"])
        return {
            "transaction_raw": trace_raw,
            "transaction_context": {
                **transaction_context,
                "prior_money_raw": prior_money_raw,
            },
            "prior_money_raw": prior_money_raw,
        }

    def admit_money(
        self,
        action: str,
        *,
        trace_artifact_id: str | None = None,
        money_artifact_id: str | None = None,
        fixture_id: str | None = None,
        graph_profile_registry: Mapping[str, object] | None = None,
    ) -> AdmissionReceipt:
        """Atomically append one selector-driven synthetic official-money observation."""

        if graph_profile_registry is not None and dict(graph_profile_registry) != dict(self.graph_profile_registry):
            raise StoreConflictError("profile:registry-mismatch")
        if action == "MONEY_INITIAL":
            if not isinstance(trace_artifact_id, str) or not trace_artifact_id or money_artifact_id is not None or fixture_id not in money_independent.INITIAL_FIXTURES:
                raise StoreConflictError("money:initial-selectors")
        elif action in {"MONEY_VOID", "MONEY_ADJUSTMENT", "MONEY_REPORT_MISMATCH", "MONEY_CORRECTION"}:
            expected_fixture = {
                "MONEY_VOID": money_independent.FIXTURE_VOID,
                "MONEY_ADJUSTMENT": money_independent.FIXTURE_ADJUSTMENT,
                "MONEY_REPORT_MISMATCH": money_independent.FIXTURE_REPORT_MISMATCH,
                "MONEY_CORRECTION": money_independent.FIXTURE_CORRECTION,
            }[action]
            if not isinstance(money_artifact_id, str) or not money_artifact_id or trace_artifact_id is not None or fixture_id != expected_fixture:
                raise StoreConflictError("money:transition-selectors")
        else:
            raise StoreConflictError("money:action")

        self._fault("before_transaction")
        connection = self._connect()
        try:
            try:
                connection.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as exc:
                raise StoreBusyError("money:busy") from exc
            self._fault("after_begin")
            self._validate_transaction_snapshot(connection)
            from app.mirror import money_mirror as producer

            if action == "MONEY_INITIAL":
                assert trace_artifact_id is not None and fixture_id is not None
                trace_raw, transaction_context, _trace = self._transaction_trace_for_money(
                    connection,
                    trace_artifact_id,
                    require_contract_head=True,
                )
                money_raw = producer.build_artifact(
                    fixture_id,
                    transaction_raw=trace_raw,
                    transaction_context=transaction_context,
                )
                money_context = {
                    "transaction_raw": trace_raw,
                    "transaction_context": transaction_context,
                    "prior_money_raw": None,
                }
            else:
                assert money_artifact_id is not None and fixture_id is not None
                prior_row = connection.execute(
                    "SELECT payload FROM artifacts WHERE kind=? AND artifact_id=?",
                    (ARTIFACT_MONEY_OBSERVATION, money_artifact_id),
                ).fetchone()
                if prior_row is None:
                    raise StoreConflictError("money:prior-missing")
                prior_money_raw = bytes(prior_row["payload"])
                prior_context = self._money_context_for_raw(connection, prior_money_raw)
                prior_verified = verify_artifact(
                    ARTIFACT_MONEY_OBSERVATION,
                    prior_money_raw,
                    graph_profile_registry=self.graph_profile_registry,
                    transaction_context=prior_context,
                )
                trace_raw = prior_context["transaction_raw"]
                transaction_context = prior_context["transaction_context"]
                money_raw = producer.build_artifact(
                    fixture_id,
                    transaction_raw=trace_raw,
                    transaction_context=transaction_context,
                    prior_money_raw=prior_money_raw,
                )
                money_context = {
                    "transaction_raw": trace_raw,
                    "transaction_context": transaction_context,
                    "prior_money_raw": prior_money_raw,
                }

            money = verify_artifact(
                ARTIFACT_MONEY_OBSERVATION,
                money_raw,
                graph_profile_registry=self.graph_profile_registry,
                transaction_context=money_context,
            )
            request_hash = _payload_hash(money_raw)
            existing = self._transaction_existing_receipt(connection, money, request_hash)
            if existing is not None:
                connection.commit()
                return existing
            if action != "MONEY_INITIAL":
                chain_id = _chain_id(prior_verified.kind, prior_verified.subject, prior_verified.scope, prior_verified.profile_id)
                head = self._head(connection, chain_id)
                if head is None or (head["artifact_id"], head["current_stage_id"]) != (prior_verified.artifact_id, prior_verified.current_stage_id):
                    raise StoreConflictError("money:prior-not-head")
            self._transaction_require_active(connection, money_context["transaction_context"])
            receipt = self._admit_in_transaction(connection, money, request_hash, enforce_governance=False)
            self._validate_transaction_snapshot(connection)
            self._fault("after_event_receipt_before_commit")
            connection.commit()
            try:
                self._fault("after_commit_before_response")
            except InjectedFault as exc:
                raise IndeterminateCommitError(receipt.operation_id) from exc
            return receipt
        except IndeterminateCommitError:
            raise
        except (InjectedFault, StoreConflictError, StoreSchemaError, StoreBusyError):
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise
        except sqlite3.IntegrityError as exc:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise StoreConflictError("money:integrity") from exc
        except sqlite3.OperationalError as exc:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise StoreBusyError("money:operational") from exc
        finally:
            connection.close()

    def _transition_context_for_raw(self, connection: sqlite3.Connection, transition_raw: bytes) -> dict[str, object]:
        value = transition_independent._parse(transition_raw)
        shared = value.get("shared_binding")
        if not isinstance(shared, Mapping) or not isinstance(shared.get("money"), Mapping):
            raise StoreConflictError("transition:money-binding")
        money_id = shared["money"].get("artifact_id")
        if not isinstance(money_id, str) or not money_id:
            raise StoreConflictError("transition:money-selector")
        money_row = connection.execute(
            "SELECT payload FROM artifacts WHERE kind=? AND artifact_id=?",
            (ARTIFACT_MONEY_OBSERVATION, money_id),
        ).fetchone()
        if money_row is None:
            raise StoreConflictError("transition:money-missing")
        money_raw = bytes(money_row["payload"])
        money_context = self._money_context_for_raw(connection, money_raw)
        prior_transition_raw = None
        prior_id = value.get("prior_artifact_id")
        if prior_id is not None:
            prior_row = connection.execute(
                "SELECT payload FROM artifacts WHERE kind=? AND artifact_id=?",
                (ARTIFACT_TRANSITION, prior_id),
            ).fetchone()
            if prior_row is None:
                raise StoreConflictError("transition:prior-missing")
            prior_transition_raw = bytes(prior_row["payload"])
        return {
            "money_raw": money_raw,
            "money_context": money_context,
            "prior_transition_raw": prior_transition_raw,
        }

    def admit_transition(
        self,
        action: str,
        *,
        money_artifact_id: str | None = None,
        transition_artifact_id: str | None = None,
        fixture_id: str | None = None,
        graph_profile_registry: Mapping[str, object] | None = None,
    ) -> AdmissionReceipt:
        """Atomically compare two fixed synthetic lanes from a store-selected Money artifact."""

        if graph_profile_registry is not None and dict(graph_profile_registry) != dict(self.graph_profile_registry):
            raise StoreConflictError("profile:registry-mismatch")
        if action == "TRANSITION_INITIAL":
            if not isinstance(money_artifact_id, str) or not money_artifact_id or transition_artifact_id is not None or fixture_id not in transition_independent.INITIAL_FIXTURES:
                raise StoreConflictError("transition:initial-selectors")
        elif action == "TRANSITION_RETEST":
            if not isinstance(transition_artifact_id, str) or not transition_artifact_id or money_artifact_id is not None or fixture_id not in transition_independent.RETEST_FIXTURES:
                raise StoreConflictError("transition:retest-selectors")
        else:
            raise StoreConflictError("transition:action")

        self._fault("before_transaction")
        connection = self._connect()
        try:
            try:
                connection.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as exc:
                raise StoreBusyError("transition:busy") from exc
            self._fault("after_begin")
            self._validate_transaction_snapshot(connection)
            from app.mirror import transition_mirror as producer

            prior_verified: VerifiedArtifact | None = None
            money_verified: VerifiedArtifact | None = None
            if action == "TRANSITION_INITIAL":
                assert money_artifact_id is not None and fixture_id is not None
                money_row = connection.execute(
                    "SELECT payload FROM artifacts WHERE kind=? AND artifact_id=?",
                    (ARTIFACT_MONEY_OBSERVATION, money_artifact_id),
                ).fetchone()
                if money_row is None:
                    raise StoreConflictError("transition:money-missing")
                money_raw = bytes(money_row["payload"])
                money_context = self._money_context_for_raw(connection, money_raw)
                money_verified = verify_artifact(
                    ARTIFACT_MONEY_OBSERVATION,
                    money_raw,
                    graph_profile_registry=self.graph_profile_registry,
                    transaction_context=money_context,
                )
                transition_context = {"money_raw": money_raw, "money_context": money_context, "prior_transition_raw": None}
                candidate_raw = producer.build_artifact(
                    fixture_id,
                    money_raw=money_raw,
                    money_context=money_context,
                )
            else:
                assert transition_artifact_id is not None and fixture_id is not None
                prior_row = connection.execute(
                    "SELECT payload,current_stage_id FROM artifacts WHERE kind=? AND artifact_id=?",
                    (ARTIFACT_TRANSITION, transition_artifact_id),
                ).fetchone()
                if prior_row is None:
                    raise StoreConflictError("transition:prior-missing")
                prior_raw = bytes(prior_row["payload"])
                prior_context = self._transition_context_for_raw(connection, prior_raw)
                prior_verified = verify_artifact(
                    ARTIFACT_TRANSITION,
                    prior_raw,
                    graph_profile_registry=self.graph_profile_registry,
                    transition_context=prior_context,
                )
                money_verified = verify_artifact(
                    ARTIFACT_MONEY_OBSERVATION,
                    prior_context["money_raw"],
                    graph_profile_registry=self.graph_profile_registry,
                    transaction_context=prior_context["money_context"],
                )
                if prior_verified.stage_kind != transition_independent.STAGE_COMPARED:
                    raise StoreConflictError("transition:prior-stage")
                transition_context = {**prior_context, "prior_transition_raw": prior_raw}
                candidate_raw = producer.build_artifact(
                    fixture_id,
                    money_raw=transition_context["money_raw"],
                    money_context=transition_context["money_context"],
                    prior_transition_raw=prior_raw,
                )

            artifact = verify_artifact(
                ARTIFACT_TRANSITION,
                candidate_raw,
                graph_profile_registry=self.graph_profile_registry,
                transition_context=transition_context,
            )
            request_hash = _payload_hash(candidate_raw)
            existing = self._transaction_existing_receipt(connection, artifact, request_hash)
            if existing is not None:
                connection.commit()
                return existing
            assert money_verified is not None
            money_chain = _chain_id(money_verified.kind, money_verified.subject, money_verified.scope, money_verified.profile_id)
            money_head = self._head(connection, money_chain)
            if money_head is None or (money_head["artifact_id"], money_head["current_stage_id"]) != (money_verified.artifact_id, money_verified.current_stage_id):
                raise StoreConflictError("transition:money-not-head")
            if prior_verified is not None:
                chain_id = _chain_id(prior_verified.kind, prior_verified.subject, prior_verified.scope, prior_verified.profile_id)
                head = self._head(connection, chain_id)
                if head is None or (head["artifact_id"], head["current_stage_id"]) != (prior_verified.artifact_id, prior_verified.current_stage_id):
                    raise StoreConflictError("transition:prior-not-head")
            self._transaction_require_active(connection, transition_context["money_context"]["transaction_context"])
            receipt = self._admit_in_transaction(connection, artifact, request_hash, enforce_governance=False)
            self._validate_transaction_snapshot(connection)
            self._fault("after_event_receipt_before_commit")
            connection.commit()
            try:
                self._fault("after_commit_before_response")
            except InjectedFault as exc:
                raise IndeterminateCommitError(receipt.operation_id) from exc
            return receipt
        except IndeterminateCommitError:
            raise
        except (ArtifactAdmissionError, InjectedFault, StoreConflictError, StoreSchemaError, StoreBusyError):
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise
        except sqlite3.IntegrityError as exc:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise StoreConflictError("transition:integrity") from exc
        except sqlite3.OperationalError as exc:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise StoreBusyError("transition:operational") from exc
        finally:
            connection.close()

    def _state_value_context_for_raw(
        self,
        connection: sqlite3.Connection,
        state_value_raw: bytes,
    ) -> dict[str, object]:
        """Reconstruct every exact upstream byte named by a value artifact."""

        try:
            value = state_value_independent._parse(state_value_raw)
            money_contexts: dict[str, dict[str, object]] = {}
            transition_contexts: dict[str, dict[str, object]] = {}
            for entry in value["entries"]:
                upstream = entry["upstream"]
                money_ref = upstream["money"]
                money_id = str(money_ref["artifact_id"])
                money_row = connection.execute(
                    "SELECT payload FROM artifacts WHERE kind=? AND artifact_id=?",
                    (ARTIFACT_MONEY_OBSERVATION, money_id),
                ).fetchone()
                if money_row is None:
                    raise StoreConflictError("state-value:money-missing")
                money_raw = bytes(money_row["payload"])
                money_contexts[money_id] = {
                    "money_raw": money_raw,
                    "money_context": self._money_context_for_raw(connection, money_raw),
                }
                transition_ref = upstream.get("transition")
                if transition_ref is not None:
                    transition_id = str(transition_ref["artifact_id"])
                    transition_row = connection.execute(
                        "SELECT payload FROM artifacts WHERE kind=? AND artifact_id=?",
                        (ARTIFACT_TRANSITION, transition_id),
                    ).fetchone()
                    if transition_row is None:
                        raise StoreConflictError("state-value:transition-missing")
                    transition_raw = bytes(transition_row["payload"])
                    transition_contexts[transition_id] = {
                        "transition_raw": transition_raw,
                        "transition_context": self._transition_context_for_raw(connection, transition_raw),
                    }
            prior_value_raw = None
            prior_id = value.get("prior_artifact_id")
            if prior_id is not None:
                prior_row = connection.execute(
                    "SELECT payload,current_stage_id FROM artifacts WHERE kind=? AND artifact_id=?",
                    (ARTIFACT_STATE_VALUE, prior_id),
                ).fetchone()
                if prior_row is None or prior_row["current_stage_id"] != value.get("prior_stage_id"):
                    raise StoreConflictError("state-value:prior-missing")
                prior_value_raw = bytes(prior_row["payload"])
                prior_value = state_value_independent._parse(prior_value_raw)
                for prior_entry in prior_value["entries"]:
                    prior_upstream = prior_entry["upstream"]
                    prior_money_id = str(prior_upstream["money"]["artifact_id"])
                    if prior_money_id not in money_contexts:
                        prior_money_row = connection.execute(
                            "SELECT payload FROM artifacts WHERE kind=? AND artifact_id=?",
                            (ARTIFACT_MONEY_OBSERVATION, prior_money_id),
                        ).fetchone()
                        if prior_money_row is None:
                            raise StoreConflictError("state-value:prior-money-missing")
                        prior_money_raw = bytes(prior_money_row["payload"])
                        money_contexts[prior_money_id] = {
                            "money_raw": prior_money_raw,
                            "money_context": self._money_context_for_raw(connection, prior_money_raw),
                        }
                    prior_transition_ref = prior_upstream.get("transition")
                    if prior_transition_ref is not None:
                        prior_transition_id = str(prior_transition_ref["artifact_id"])
                        if prior_transition_id not in transition_contexts:
                            prior_transition_row = connection.execute(
                                "SELECT payload FROM artifacts WHERE kind=? AND artifact_id=?",
                                (ARTIFACT_TRANSITION, prior_transition_id),
                            ).fetchone()
                            if prior_transition_row is None:
                                raise StoreConflictError("state-value:prior-transition-missing")
                            prior_transition_raw = bytes(prior_transition_row["payload"])
                            transition_contexts[prior_transition_id] = {
                                "transition_raw": prior_transition_raw,
                                "transition_context": self._transition_context_for_raw(connection, prior_transition_raw),
                            }
            return {
                "money_contexts": money_contexts,
                "prior_value_raw": prior_value_raw,
                "transition_contexts": transition_contexts,
            }
        except StoreConflictError:
            raise
        except Exception as exc:
            raise StoreConflictError("state-value:context") from exc

    def admit_state_value(
        self,
        action: str,
        *,
        money_artifact_id: str | None = None,
        value_artifact_id: str | None = None,
        transition_artifact_id: str | None = None,
        graph_profile_registry: Mapping[str, object] | None = None,
    ) -> AdmissionReceipt:
        """Atomically append or recalculate the fixed counting-once artifact."""

        if graph_profile_registry is not None and dict(graph_profile_registry) != dict(self.graph_profile_registry):
            raise StoreConflictError("profile:registry-mismatch")
        if action == "STATE_VALUE_INITIAL":
            if not isinstance(money_artifact_id, str) or not money_artifact_id or value_artifact_id is not None:
                raise StoreConflictError("state-value:initial-selectors")
        elif action == "STATE_VALUE_RECALCULATE":
            if not isinstance(money_artifact_id, str) or not money_artifact_id or not isinstance(value_artifact_id, str) or not value_artifact_id:
                raise StoreConflictError("state-value:recalculation-selectors")
        else:
            raise StoreConflictError("state-value:action")
        if transition_artifact_id is not None and (not isinstance(transition_artifact_id, str) or not transition_artifact_id):
            raise StoreConflictError("state-value:transition-selector")

        self._fault("before_transaction")
        connection = self._connect()
        try:
            try:
                connection.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as exc:
                raise StoreBusyError("state-value:busy") from exc
            self._fault("after_begin")
            self._validate_transaction_snapshot(connection)
            from app.mirror import state_value_ledger as producer

            assert money_artifact_id is not None
            money_row = connection.execute(
                "SELECT payload FROM artifacts WHERE kind=? AND artifact_id=?",
                (ARTIFACT_MONEY_OBSERVATION, money_artifact_id),
            ).fetchone()
            if money_row is None:
                raise StoreConflictError("state-value:money-missing")
            money_raw = bytes(money_row["payload"])
            money_context = self._money_context_for_raw(connection, money_raw)
            money_verified = verify_artifact(
                ARTIFACT_MONEY_OBSERVATION,
                money_raw,
                graph_profile_registry=self.graph_profile_registry,
                transaction_context=money_context,
            )
            transition_raw = None
            transition_verified: VerifiedArtifact | None = None
            if transition_artifact_id is not None:
                transition_row = connection.execute(
                    "SELECT payload FROM artifacts WHERE kind=? AND artifact_id=?",
                    (ARTIFACT_TRANSITION, transition_artifact_id),
                ).fetchone()
                if transition_row is None:
                    raise StoreConflictError("state-value:transition-missing")
                transition_raw = bytes(transition_row["payload"])
                transition_context = self._transition_context_for_raw(connection, transition_raw)
                transition_verified = verify_artifact(
                    ARTIFACT_TRANSITION,
                    transition_raw,
                    graph_profile_registry=self.graph_profile_registry,
                    transition_context=transition_context,
                )
                if transition_verified.transition_id != transition_independent._parse(transition_raw)["transition_id"]:
                    raise StoreConflictError("state-value:transition-identity")

            prior_value_raw = None
            prior_verified: VerifiedArtifact | None = None
            if action == "STATE_VALUE_RECALCULATE":
                assert value_artifact_id is not None
                prior_row = connection.execute(
                    "SELECT payload FROM artifacts WHERE kind=? AND artifact_id=?",
                    (ARTIFACT_STATE_VALUE, value_artifact_id),
                ).fetchone()
                if prior_row is None:
                    raise StoreConflictError("state-value:prior-missing")
                prior_value_raw = bytes(prior_row["payload"])
                prior_context = self._state_value_context_for_raw(connection, prior_value_raw)
                prior_verified = verify_artifact(
                    ARTIFACT_STATE_VALUE,
                    prior_value_raw,
                    graph_profile_registry=self.graph_profile_registry,
                    state_value_context=prior_context,
                )

            candidate_raw = producer.build_artifact(
                money_raw,
                money_context=money_context,
                prior_value_raw=prior_value_raw,
                transition_raw=transition_raw,
            )
            candidate_context = self._state_value_context_for_raw(connection, candidate_raw)
            artifact = verify_artifact(
                ARTIFACT_STATE_VALUE,
                candidate_raw,
                graph_profile_registry=self.graph_profile_registry,
                state_value_context=candidate_context,
            )
            request_hash = _payload_hash(candidate_raw)
            existing = self._transaction_existing_receipt(connection, artifact, request_hash)
            if existing is not None:
                connection.commit()
                return existing

            money_chain = _chain_id(money_verified.kind, money_verified.subject, money_verified.scope, money_verified.profile_id)
            money_head = self._head(connection, money_chain)
            if money_head is None or (money_head["artifact_id"], money_head["current_stage_id"]) != (money_verified.artifact_id, money_verified.current_stage_id):
                raise StoreConflictError("state-value:money-not-head")
            if prior_verified is not None:
                value_chain = _chain_id(prior_verified.kind, prior_verified.subject, prior_verified.scope, prior_verified.profile_id)
                value_head = self._head(connection, value_chain)
                if value_head is None or (value_head["artifact_id"], value_head["current_stage_id"]) != (prior_verified.artifact_id, prior_verified.current_stage_id):
                    raise StoreConflictError("state-value:prior-not-head")
            self._transaction_require_active(connection, money_context["transaction_context"])
            if transition_verified is not None:
                transition_chain = _chain_id(transition_verified.kind, transition_verified.subject, transition_verified.scope, transition_verified.profile_id)
                transition_head = self._head(connection, transition_chain)
                if transition_head is None or (transition_head["artifact_id"], transition_head["current_stage_id"]) != (transition_verified.artifact_id, transition_verified.current_stage_id):
                    raise StoreConflictError("state-value:transition-not-head")
            receipt = self._admit_in_transaction(connection, artifact, request_hash, enforce_governance=False)
            self._validate_transaction_snapshot(connection)
            self._fault("after_event_receipt_before_commit")
            connection.commit()
            try:
                self._fault("after_commit_before_response")
            except InjectedFault as exc:
                raise IndeterminateCommitError(receipt.operation_id) from exc
            return receipt
        except IndeterminateCommitError:
            raise
        except (ArtifactAdmissionError, InjectedFault, StoreConflictError, StoreSchemaError, StoreBusyError):
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise
        except sqlite3.IntegrityError as exc:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise StoreConflictError("state-value:integrity") from exc
        except sqlite3.OperationalError as exc:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise StoreBusyError("state-value:operational") from exc
        finally:
            connection.close()

    def admit_contract(
        self,
        stage: str,
        *,
        denominator_artifact_id: str | None = None,
        reconciliation_artifact_id: str | None = None,
        finding_id: str | None = None,
        contract_artifact_id: str | None = None,
        graph_profile_registry: Mapping[str, object] | None = None,
    ) -> AdmissionReceipt:
        """Atomically append one Contract Mirror evaluation and its case seam."""

        if graph_profile_registry is not None and dict(graph_profile_registry) != dict(self.graph_profile_registry):
            raise StoreConflictError("profile:registry-mismatch")
        if stage not in contract_independent.STAGES:
            raise StoreConflictError("contract:stage")
        if stage == contract_independent.STAGE_EVALUATED:
            if not all(isinstance(item, str) and item for item in (denominator_artifact_id, reconciliation_artifact_id, finding_id)) or contract_artifact_id is not None:
                raise StoreConflictError("contract:evaluation-selectors")
        elif not isinstance(contract_artifact_id, str) or not contract_artifact_id or any(item is not None for item in (denominator_artifact_id, reconciliation_artifact_id, finding_id)):
            raise StoreConflictError("contract:retest-selector")

        self._fault("before_transaction")
        connection = self._connect()
        try:
            try:
                connection.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as exc:
                raise StoreBusyError("transaction:busy") from exc
            self._fault("after_begin")
            self._validate_transaction_snapshot(connection)

            if stage == contract_independent.STAGE_EVALUATED:
                assert denominator_artifact_id is not None and reconciliation_artifact_id is not None and finding_id is not None
                # Exact evaluation retry is resolved before the current
                # governance check, so withdrawal cannot make a committed
                # receipt disappear.
                existing_eval: sqlite3.Row | None = None
                for row in connection.execute("SELECT * FROM artifacts WHERE kind=? ORDER BY artifact_id", (ARTIFACT_CONTRACT,)):
                    candidate_value = contract_independent._parse(bytes(row["payload"]))
                    if (
                        candidate_value.get("stage_kind") == contract_independent.STAGE_EVALUATED
                        and candidate_value.get("denominator", {}).get("artifact_id") == denominator_artifact_id
                        and candidate_value.get("observation", {}).get("reconciliation_artifact_id") == reconciliation_artifact_id
                        and candidate_value.get("case_link", {}).get("finding_id") == finding_id
                    ):
                        existing_eval = row
                        break
                if existing_eval is not None:
                    existing_raw = bytes(existing_eval["payload"])
                    existing_context = self._contract_context_for_raw(connection, existing_raw)
                    artifact = verify_artifact(
                        ARTIFACT_CONTRACT,
                        existing_raw,
                        graph_profile_registry=self.graph_profile_registry,
                        contract_context=existing_context,
                    )
                    receipt = self._receipt_for_artifact(connection, artifact)
                    connection.commit()
                    return receipt

                denominator_row = connection.execute(
                    "SELECT payload,current_stage_id FROM artifacts WHERE kind=? AND artifact_id=?",
                    (ARTIFACT_DENOMINATOR, denominator_artifact_id),
                ).fetchone()
                if denominator_row is None:
                    raise StoreConflictError("contract:denominator-missing")
                denominator_raw = bytes(denominator_row["payload"])
                denominator_value = denominator_independent._parse(denominator_raw)
                denominator_chain = _chain_id(
                    ARTIFACT_DENOMINATOR,
                    denominator_independent.SUBJECT,
                    denominator_independent.SCOPE,
                    denominator_independent.PROFILE_ID,
                )
                denominator_head = self._head(connection, denominator_chain)
                if denominator_head is None or denominator_head["artifact_id"] != denominator_artifact_id or denominator_head["current_stage_id"] != denominator_row["current_stage_id"]:
                    raise StoreConflictError("contract:denominator-not-head")
                denominator_context = self._contract_denominator_context(connection, denominator_raw)
                reconciliation_raw, reconciliation_context = self._contract_reconciliation_context(connection, reconciliation_artifact_id)
                self._contract_active_governance(connection, reconciliation_raw)
                source_binding = denominator_value.get("source_binding")
                if not isinstance(source_binding, dict) or not isinstance(source_binding.get("graph_artifact_id"), str):
                    raise StoreConflictError("contract:graph-required")
                graph_artifact_id = str(source_binding["graph_artifact_id"])
                case_context = self._case_upstream_context(connection, graph_artifact_id, reconciliation_artifact_id, finding_id)
                case_candidate = case_independent.build_artifact(
                    case_independent.STAGE_OPEN,
                    graph_raw=case_context["graph_raw"],
                    reconciliation_raw=case_context["reconciliation_raw"],
                    reconciliation_context=case_context["reconciliation_context"],
                    governance_raw=case_context["governance_raw"],
                    graph_profile_registry=self.graph_profile_registry,
                    finding_id=finding_id,
                )
                case_value = case_independent._parse(case_candidate)
                case_id = str(case_value["case_id"])
                case_head_rows = connection.execute(
                    "SELECT h.*, a.payload FROM heads h JOIN artifacts a ON a.kind=h.artifact_kind AND a.artifact_id=h.artifact_id WHERE h.artifact_kind=? AND a.report_id=?",
                    (ARTIFACT_CASE, case_id),
                ).fetchall()
                if len(case_head_rows) > 1:
                    raise StoreConflictError("contract:case-head-ambiguous")
                if case_head_rows:
                    case_raw = bytes(case_head_rows[0]["payload"])
                    case_context = self._contract_case_context_for_raw(connection, case_raw)
                else:
                    case_context = {
                        **case_context,
                        "prior_case_raw": None,
                        "retest_reconciliation_raw": None,
                        "retest_context": None,
                    }
                    case_artifact = verify_artifact(
                        ARTIFACT_CASE,
                        case_candidate,
                        graph_profile_registry=self.graph_profile_registry,
                        reconciliation_context=case_context,
                    )
                    self._admit_in_transaction(connection, case_artifact, _payload_hash(case_candidate), enforce_governance=False)
                    case_raw = case_candidate
                contract_context = {
                    "denominator_raw": denominator_raw,
                    "denominator_context": denominator_context,
                    "case_raw": case_raw,
                    "case_context": case_context,
                    "prior_contract_raw": None,
                }
                from app.mirror import contract_mirror as producer
                candidate_raw = producer.build_artifact(
                    stage,
                    denominator_raw=denominator_raw,
                    denominator_context=denominator_context,
                    case_raw=case_raw,
                    case_context=case_context,
                    registry=self.graph_profile_registry,
                )
                artifact = verify_artifact(
                    ARTIFACT_CONTRACT,
                    candidate_raw,
                    graph_profile_registry=self.graph_profile_registry,
                    contract_context=contract_context,
                )
            else:
                assert contract_artifact_id is not None
                # A committed retest is returned exactly even after a later
                # governance withdrawal.  This lookup remains transactional.
                existing_retest: sqlite3.Row | None = None
                for row in connection.execute("SELECT * FROM artifacts WHERE kind=? ORDER BY artifact_id", (ARTIFACT_CONTRACT,)):
                    candidate_value = contract_independent._parse(bytes(row["payload"]))
                    if candidate_value.get("stage_kind") == contract_independent.STAGE_RETESTED and candidate_value.get("prior_artifact_id") == contract_artifact_id:
                        existing_retest = row
                        break
                if existing_retest is not None:
                    existing_raw = bytes(existing_retest["payload"])
                    existing_context = self._contract_context_for_raw(connection, existing_raw)
                    artifact = verify_artifact(
                        ARTIFACT_CONTRACT,
                        existing_raw,
                        graph_profile_registry=self.graph_profile_registry,
                        contract_context=existing_context,
                    )
                    receipt = self._receipt_for_artifact(connection, artifact)
                    connection.commit()
                    return receipt
                prior_row = connection.execute(
                    "SELECT payload,current_stage_id FROM artifacts WHERE kind=? AND artifact_id=?",
                    (ARTIFACT_CONTRACT, contract_artifact_id),
                ).fetchone()
                if prior_row is None:
                    raise StoreConflictError("contract:prior-missing")
                prior_raw = bytes(prior_row["payload"])
                prior_value = contract_independent._parse(prior_raw)
                if prior_value.get("stage_kind") != contract_independent.STAGE_EVALUATED:
                    raise StoreConflictError("contract:prior-stage")
                prior_head = self._contract_head_row(connection, contract_artifact_id)
                if prior_head["current_stage_id"] != prior_row["current_stage_id"]:
                    raise StoreConflictError("contract:prior-identity")
                prior_context = self._contract_context_for_raw(connection, prior_raw)
                verify_artifact(
                    ARTIFACT_CONTRACT,
                    prior_raw,
                    graph_profile_registry=self.graph_profile_registry,
                    contract_context=prior_context,
                )
                denominator_raw = prior_context["denominator_raw"]
                denominator_context = prior_context["denominator_context"]
                case_id = str(prior_value["case_link"]["case_id"])
                case_head = self._case_head_row(connection, case_id)
                case_raw = bytes(case_head["payload"])
                case_value = case_independent._parse(case_raw)
                case_context = self._contract_case_context_for_raw(connection, case_raw)
                latest_recon_raw, latest_recon_context = self._case_latest_reconciliation(
                    connection,
                    case_context["reconciliation_raw"],
                )
                self._contract_active_governance(connection, latest_recon_raw)
                if case_value["lifecycle_state"] == case_independent.STAGE_REMEDIATION_EVIDENCE:
                    retest_candidate = case_independent.build_artifact(
                        case_independent.STAGE_RETEST,
                        graph_raw=case_context["graph_raw"],
                        reconciliation_raw=case_context["reconciliation_raw"],
                        reconciliation_context=case_context["reconciliation_context"],
                        governance_raw=case_context["governance_raw"],
                        graph_profile_registry=self.graph_profile_registry,
                        prior_case_raw=case_raw,
                        retest_reconciliation_raw=latest_recon_raw,
                        retest_context=latest_recon_context,
                    )
                    retest_context_for_case = {
                        **case_context,
                        "prior_case_raw": case_raw,
                        "retest_reconciliation_raw": latest_recon_raw,
                        "retest_context": latest_recon_context,
                    }
                    retest_artifact = verify_artifact(
                        ARTIFACT_CASE,
                        retest_candidate,
                        graph_profile_registry=self.graph_profile_registry,
                        reconciliation_context=retest_context_for_case,
                    )
                    self._admit_in_transaction(connection, retest_artifact, _payload_hash(retest_candidate), enforce_governance=False)
                    case_raw = retest_candidate
                    case_value = case_independent._parse(case_raw)
                    case_context = retest_context_for_case
                elif case_value["lifecycle_state"] == case_independent.STAGE_RETEST:
                    case_context = {
                        **case_context,
                        "retest_reconciliation_raw": latest_recon_raw,
                        "retest_context": latest_recon_context,
                    }
                elif case_value["lifecycle_state"] not in {case_independent.STAGE_PARITY, case_independent.STAGE_PERSISTS}:
                    raise StoreConflictError("contract:case-retest-state")
                if case_value["lifecycle_state"] in {case_independent.STAGE_RETEST, case_independent.STAGE_REMEDIATION_EVIDENCE}:
                    parity = case_value["retest"].get("parity")
                    if not isinstance(parity, dict):
                        raise StoreConflictError("contract:case-retest-result")
                    final_action = case_independent.STAGE_PARITY if parity["status"] == case_independent.PARITY_FULL else case_independent.STAGE_PERSISTS
                    final_candidate = case_independent.build_artifact(
                        final_action,
                        graph_raw=case_context["graph_raw"],
                        reconciliation_raw=case_context["reconciliation_raw"],
                        reconciliation_context=case_context["reconciliation_context"],
                        governance_raw=case_context["governance_raw"],
                        graph_profile_registry=self.graph_profile_registry,
                        prior_case_raw=case_raw,
                        retest_reconciliation_raw=latest_recon_raw,
                        retest_context=latest_recon_context,
                    )
                    final_context = {
                        **case_context,
                        "prior_case_raw": case_raw,
                        "retest_reconciliation_raw": latest_recon_raw,
                        "retest_context": latest_recon_context,
                    }
                    final_artifact = verify_artifact(
                        ARTIFACT_CASE,
                        final_candidate,
                        graph_profile_registry=self.graph_profile_registry,
                        reconciliation_context=final_context,
                    )
                    self._admit_in_transaction(connection, final_artifact, _payload_hash(final_candidate), enforce_governance=False)
                    case_raw = final_candidate
                    case_context = final_context
                contract_context = {
                    "denominator_raw": denominator_raw,
                    "denominator_context": denominator_context,
                    "case_raw": case_raw,
                    "case_context": case_context,
                    "prior_contract_raw": prior_raw,
                }
                from app.mirror import contract_mirror as producer
                candidate_raw = producer.build_artifact(
                    stage,
                    denominator_raw=denominator_raw,
                    denominator_context=denominator_context,
                    case_raw=case_raw,
                    case_context=case_context,
                    registry=self.graph_profile_registry,
                    prior_contract_raw=prior_raw,
                )
                artifact = verify_artifact(
                    ARTIFACT_CONTRACT,
                    candidate_raw,
                    graph_profile_registry=self.graph_profile_registry,
                    contract_context=contract_context,
                )

            receipt = self._admit_in_transaction(connection, artifact, _payload_hash(candidate_raw), enforce_governance=False)
            self._validate_transaction_snapshot(connection)
            self._fault("after_event_receipt_before_commit")
            connection.commit()
            try:
                self._fault("after_commit_before_response")
            except InjectedFault as exc:
                raise IndeterminateCommitError(receipt.operation_id) from exc
            return receipt
        except IndeterminateCommitError:
            raise
        except (InjectedFault, GovernanceObservationOnly, StoreConflictError, StoreSchemaError, StoreBusyError):
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise
        except sqlite3.IntegrityError as exc:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise StoreConflictError("transaction:integrity") from exc
        except sqlite3.OperationalError as exc:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise StoreBusyError("transaction:operational") from exc
        finally:
            connection.close()

    def admit_denominator(
        self,
        stage: str,
        *,
        source_artifact_id: str | None = None,
        denominator_artifact_id: str | None = None,
        graph_profile_registry: Mapping[str, object] | None = None,
    ) -> AdmissionReceipt:
        """Atomically append a verifier-bound baseline or explicit narrowing."""

        if graph_profile_registry is not None and dict(graph_profile_registry) != dict(self.graph_profile_registry):
            raise StoreConflictError("profile:registry-mismatch")
        if stage not in (denominator_independent.STAGE_BASELINE, denominator_independent.STAGE_NARROWED):
            raise StoreConflictError("denominator:stage")
        if stage == denominator_independent.STAGE_BASELINE and (not isinstance(source_artifact_id, str) or not source_artifact_id or denominator_artifact_id is not None):
            raise StoreConflictError("denominator:source-selector")
        if stage == denominator_independent.STAGE_NARROWED and (not isinstance(denominator_artifact_id, str) or not denominator_artifact_id or source_artifact_id is not None):
            raise StoreConflictError("denominator:artifact-selector")
        self._fault("before_transaction")
        connection = self._connect()
        try:
            try:
                connection.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as exc:
                raise StoreBusyError("transaction:busy") from exc
            self._fault("after_begin")
            self._validate_transaction_snapshot(connection)
            prior_raw: bytes | None = None
            if stage == denominator_independent.STAGE_BASELINE:
                assert source_artifact_id is not None
                existing = None
                for row in connection.execute("SELECT * FROM artifacts WHERE kind=? ORDER BY artifact_id", (ARTIFACT_DENOMINATOR,)):
                    value = denominator_independent._parse(bytes(row["payload"]))
                    if value.get("stage_kind") == denominator_independent.STAGE_BASELINE and value.get("source_binding", {}).get("artifact_id") == source_artifact_id:
                        existing = row
                        break
                if existing is not None:
                    artifact = verify_artifact(
                        ARTIFACT_DENOMINATOR,
                        bytes(existing["payload"]),
                        graph_profile_registry=self.graph_profile_registry,
                        denominator_context=self._denominator_context_for_prior(connection, bytes(existing["payload"])) | {"prior_denominator_raw": None},
                    )
                    receipt = self._receipt_for_artifact(connection, artifact)
                    connection.commit()
                    return receipt
                context = self._denominator_source_context(connection, source_artifact_id)
                from app.mirror import denominator_ledger as producer
                candidate_raw = producer.build_artifact(
                    stage,
                    source_raw=context["source_raw"],
                    graph_raw=context["graph_raw"],
                    governance_raw=context["governance_raw"],
                    registry=self.graph_profile_registry,
                )
            else:
                assert denominator_artifact_id is not None
                # The requested baseline is the immutable transition input.
                # Once that transition has committed, an exact retry must
                # return its receipt even though the chain head is now the
                # narrowed artifact.  This lookup is inside BEGIN IMMEDIATE,
                # so a concurrent caller cannot observe a half-written event.
                existing_narrow: sqlite3.Row | None = None
                for row in connection.execute("SELECT * FROM artifacts WHERE kind=? ORDER BY artifact_id", (ARTIFACT_DENOMINATOR,)):
                    candidate_value = denominator_independent._parse(bytes(row["payload"]))
                    if candidate_value.get("stage_kind") == denominator_independent.STAGE_NARROWED and candidate_value.get("prior_artifact_id") == denominator_artifact_id:
                        existing_narrow = row
                        break
                if existing_narrow is not None:
                    existing_raw = bytes(existing_narrow["payload"])
                    baseline_row = connection.execute(
                        "SELECT payload FROM artifacts WHERE kind=? AND artifact_id=?",
                        (ARTIFACT_DENOMINATOR, denominator_artifact_id),
                    ).fetchone()
                    if baseline_row is None:
                        raise StoreConflictError("denominator:prior-missing")
                    context = self._denominator_context_for_prior(connection, bytes(baseline_row["payload"]))
                    artifact = verify_artifact(
                        ARTIFACT_DENOMINATOR,
                        existing_raw,
                        graph_profile_registry=self.graph_profile_registry,
                        denominator_context=context,
                    )
                    receipt = self._receipt_for_artifact(connection, artifact)
                    connection.commit()
                    return receipt
                head_chain = _chain_id(ARTIFACT_DENOMINATOR, denominator_independent.SUBJECT, denominator_independent.SCOPE, denominator_independent.PROFILE_ID)
                head = self._head(connection, head_chain)
                if head is None or head["artifact_id"] != denominator_artifact_id:
                    raise StoreConflictError("denominator:head-stale")
                prior_row = connection.execute("SELECT * FROM artifacts WHERE kind=? AND artifact_id=?", (ARTIFACT_DENOMINATOR, denominator_artifact_id)).fetchone()
                if prior_row is None or prior_row["current_stage_id"] != head["current_stage_id"]:
                    raise StoreConflictError("denominator:prior-missing")
                prior_raw = bytes(prior_row["payload"])
                prior_value = denominator_independent._parse(prior_raw)
                if prior_value.get("stage_kind") == denominator_independent.STAGE_NARROWED:
                    artifact = verify_artifact(
                        ARTIFACT_DENOMINATOR,
                        prior_raw,
                        graph_profile_registry=self.graph_profile_registry,
                        denominator_context=self._denominator_context_for_prior(connection, prior_raw),
                    )
                    receipt = self._receipt_for_artifact(connection, artifact)
                    connection.commit()
                    return receipt
                context = self._denominator_context_for_prior(connection, prior_raw)
                from app.mirror import denominator_ledger as producer
                candidate_raw = producer.build_artifact(
                    stage,
                    source_raw=context["source_raw"],
                    graph_raw=context["graph_raw"],
                    governance_raw=context["governance_raw"],
                    registry=self.graph_profile_registry,
                    prior_denominator_raw=prior_raw,
                )
            context_for_verify = {
                "source_raw": context["source_raw"],
                "graph_raw": context.get("graph_raw"),
                "governance_raw": context["governance_raw"],
                "prior_denominator_raw": prior_raw,
            }
            artifact = verify_artifact(
                ARTIFACT_DENOMINATOR,
                candidate_raw,
                graph_profile_registry=self.graph_profile_registry,
                denominator_context=context_for_verify,
            )
            receipt = self._admit_in_transaction(connection, artifact, _payload_hash(candidate_raw), enforce_governance=False)
            self._validate_transaction_snapshot(connection)
            self._fault("after_event_receipt_before_commit")
            connection.commit()
            try:
                self._fault("after_commit_before_response")
            except InjectedFault as exc:
                raise IndeterminateCommitError(receipt.operation_id) from exc
            return receipt
        except IndeterminateCommitError:
            raise
        except (InjectedFault, GovernanceObservationOnly, StoreConflictError, StoreSchemaError, StoreBusyError):
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise
        except sqlite3.IntegrityError as exc:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise StoreConflictError("transaction:integrity") from exc
        except sqlite3.OperationalError as exc:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise StoreBusyError("transaction:operational") from exc
        finally:
            connection.close()

    def _case_reconciliation_context_for_raw(
        self,
        connection: sqlite3.Connection,
        reconciliation_raw: bytes,
    ) -> dict[str, object]:
        """Load one stored reconciliation and every custody byte it names."""

        registry = self.graph_profile_registry
        try:
            value = reconciliation_independent._parse(reconciliation_raw)
            current_summary = value["current_custody"]
            if not isinstance(current_summary, dict):
                raise StoreConflictError("case:reconciliation-current")
            current_id = current_summary["artifact_id"]
            current_row = connection.execute(
                "SELECT * FROM artifacts WHERE kind=? AND artifact_id=?",
                (ARTIFACT_SOURCE_EVIDENCE, current_id),
            ).fetchone()
            if current_row is None or current_row["current_stage_id"] != current_summary["stage_id"]:
                raise StoreConflictError("case:reconciliation-current-custody")
            current_raw = bytes(current_row["payload"])
            current_preview = source_independent.verify_artifact(
                current_raw,
                graph_profile_registry=registry,
                allow_unresolved_graph=True,
            )
            current_graph_raw: bytes | None = None
            linked_graph_id = current_preview.get("linked_graph_artifact_id")
            if linked_graph_id is not None:
                graph_row = connection.execute(
                    "SELECT * FROM artifacts WHERE kind=? AND artifact_id=?",
                    (ARTIFACT_GRAPH, linked_graph_id),
                ).fetchone()
                if graph_row is None:
                    raise StoreConflictError("case:current-graph-missing")
                current_graph_raw = bytes(graph_row["payload"])
                source_independent.verify_artifact(
                    current_raw,
                    graph_raw=current_graph_raw,
                    graph_profile_registry=registry,
                )

            prior_raw: bytes | None = None
            prior_graph_raw: bytes | None = None
            prior_id = current_preview.get("prior_artifact_id")
            if prior_id is not None:
                prior_row = connection.execute(
                    "SELECT * FROM artifacts WHERE kind=? AND artifact_id=?",
                    (ARTIFACT_SOURCE_EVIDENCE, prior_id),
                ).fetchone()
                if prior_row is None or prior_row["current_stage_id"] != current_preview.get("prior_stage_id"):
                    raise StoreConflictError("case:prior-custody-missing")
                prior_raw = bytes(prior_row["payload"])
                prior_preview = source_independent.verify_artifact(
                    prior_raw,
                    graph_profile_registry=registry,
                    allow_unresolved_graph=True,
                )
                prior_graph_id = prior_preview.get("linked_graph_artifact_id")
                if prior_graph_id is not None:
                    prior_graph_row = connection.execute(
                        "SELECT * FROM artifacts WHERE kind=? AND artifact_id=?",
                        (ARTIFACT_GRAPH, prior_graph_id),
                    ).fetchone()
                    if prior_graph_row is None:
                        raise StoreConflictError("case:prior-graph-missing")
                    prior_graph_raw = bytes(prior_graph_row["payload"])
                    source_independent.verify_artifact(
                        prior_raw,
                        graph_raw=prior_graph_raw,
                        graph_profile_registry=registry,
                    )

            prior_reconciliation_raw: bytes | None = None
            prior_reconciliation_id = value.get("prior_artifact_id")
            if prior_reconciliation_id is not None:
                prior_reconciliation_row = connection.execute(
                    "SELECT payload FROM artifacts WHERE kind=? AND artifact_id=?",
                    (ARTIFACT_RECONCILIATION, prior_reconciliation_id),
                ).fetchone()
                if prior_reconciliation_row is None:
                    raise StoreConflictError("case:prior-reconciliation-missing")
                prior_reconciliation_raw = bytes(prior_reconciliation_row["payload"])

            qualified_baseline_raw: bytes | None = None
            chronology_anchor_raw: bytes | None = None
            if prior_reconciliation_raw is not None:
                prior_value = reconciliation_independent._parse(prior_reconciliation_raw)
                anchors = reconciliation_independent._validate_anchors(prior_value.get("anchors"))
                for name, target in (
                    ("qualified_content_baseline", anchors["qualified_content_baseline"]),
                    ("chronology_anchor", anchors["chronology_anchor"]),
                ):
                    if target is None:
                        continue
                    anchor_row = connection.execute(
                        "SELECT payload,current_stage_id FROM artifacts WHERE kind=? AND artifact_id=?",
                        (ARTIFACT_SOURCE_EVIDENCE, target["custody_artifact_id"]),
                    ).fetchone()
                    if anchor_row is None or anchor_row["current_stage_id"] != target["custody_stage_id"]:
                        raise StoreConflictError(f"case:{name}-missing")
                    if name == "qualified_content_baseline":
                        qualified_baseline_raw = bytes(anchor_row["payload"])
                    else:
                        chronology_anchor_raw = bytes(anchor_row["payload"])
        except StoreConflictError:
            raise
        except Exception as exc:
            raise StoreConflictError("case:reconciliation-context") from exc
        context = {
            "current_custody_raw": current_raw,
            "prior_custody_raw": prior_raw,
            "current_graph_raw": current_graph_raw,
            "prior_graph_raw": prior_graph_raw,
            "prior_reconciliation_raw": prior_reconciliation_raw,
            "qualified_baseline_custody_raw": qualified_baseline_raw,
            "chronology_anchor_custody_raw": chronology_anchor_raw,
        }
        try:
            reconciliation_independent.verify_artifact(
                reconciliation_raw,
                current_custody_raw=context["current_custody_raw"],
                prior_custody_raw=context["prior_custody_raw"],
                current_graph_raw=context["current_graph_raw"],
                prior_graph_raw=context["prior_graph_raw"],
                prior_reconciliation_raw=context["prior_reconciliation_raw"],
                qualified_baseline_custody_raw=context["qualified_baseline_custody_raw"],
                chronology_anchor_custody_raw=context["chronology_anchor_custody_raw"],
                graph_profile_registry=registry,
            )
        except Exception as exc:
            raise StoreConflictError("case:reconciliation-reject") from exc
        return context

    def _case_governance_for_graph(self, connection: sqlite3.Connection, graph_raw: bytes) -> bytes:
        """Select the approved governance artifact effective when the graph was admitted."""

        try:
            graph_value = graph_independent._parse(graph_raw)
            graph_result = graph_independent.verify_bytes_v2(graph_raw, self.graph_profile_registry)
            graph_event = connection.execute(
                "SELECT sequence FROM events WHERE artifact_kind=? AND artifact_id=?",
                (ARTIFACT_GRAPH, graph_result["report_id"]),
            ).fetchone()
            if graph_event is None:
                raise StoreConflictError("case:graph-event-missing")
            selected: bytes | None = None
            for event in connection.execute(
                "SELECT * FROM events WHERE sequence < ? ORDER BY sequence",
                (int(graph_event["sequence"]),),
            ):
                if event["artifact_kind"] != ARTIFACT_GOVERNANCE:
                    continue
                row = connection.execute(
                    "SELECT * FROM artifacts WHERE kind=? AND artifact_id=?",
                    (ARTIFACT_GOVERNANCE, event["artifact_id"]),
                ).fetchone()
                if row is None:
                    raise StoreSchemaError("case:governance-row-missing")
                candidate = bytes(row["payload"])
                candidate_value = _parse_canonical(candidate)
                if candidate_value.get("schema") not in (governance_v2_independent.SCHEMA, governance_v2_independent.WITHDRAWAL_SCHEMA):
                    continue
                governed = governance_v2_independent.verify_bytes(candidate, self.graph_profile_registry)
                if (
                    governed.get("profile_id") == graph_value["profile"]["profile_id"]
                    and row["subject"] == graph_value["subject"]["provider_graph_subject"]
                    and row["scope"] == graph_value["subject"]["scope"]
                ):
                    if candidate_value.get("schema") == governance_v2_independent.SCHEMA and governed.get("current_stage_kind") == governance_v2_independent.STAGE_APPROVED:
                        selected = candidate
                    elif candidate_value.get("schema") == governance_v2_independent.WITHDRAWAL_SCHEMA:
                        selected = None
            if selected is None:
                raise StoreConflictError("case:governance-not-effective")
            return selected
        except StoreConflictError:
            raise
        except Exception as exc:
            raise StoreConflictError("case:governance-context") from exc

    def _case_upstream_context(
        self,
        connection: sqlite3.Connection,
        graph_artifact_id: str,
        reconciliation_artifact_id: str,
        finding_id: str,
    ) -> dict[str, object]:
        graph_row = connection.execute(
            "SELECT * FROM artifacts WHERE kind=? AND artifact_id=?",
            (ARTIFACT_GRAPH, graph_artifact_id),
        ).fetchone()
        recon_row = connection.execute(
            "SELECT * FROM artifacts WHERE kind=? AND artifact_id=?",
            (ARTIFACT_RECONCILIATION, reconciliation_artifact_id),
        ).fetchone()
        if graph_row is None or recon_row is None:
            raise StoreConflictError("case:upstream-missing")
        graph_raw = bytes(graph_row["payload"])
        reconciliation_raw = bytes(recon_row["payload"])
        try:
            graph_result = graph_independent.verify_bytes_v2(graph_raw, self.graph_profile_registry)
        except Exception as exc:
            raise StoreConflictError("case:graph-independent-reject") from exc
        if graph_result["report_id"] != graph_artifact_id:
            raise StoreConflictError("case:graph-identity")
        reconciliation_context = self._case_reconciliation_context_for_raw(connection, reconciliation_raw)
        governance_raw = self._case_governance_for_graph(connection, graph_raw)
        return {
            "graph_raw": graph_raw,
            "reconciliation_raw": reconciliation_raw,
            "reconciliation_context": reconciliation_context,
            "governance_raw": governance_raw,
            "finding_id": finding_id,
        }

    def _case_head_row(self, connection: sqlite3.Connection, case_id: str) -> sqlite3.Row:
        rows = connection.execute(
            "SELECT h.*, a.payload, a.scope FROM heads h JOIN artifacts a ON a.kind=h.artifact_kind AND a.artifact_id=h.artifact_id WHERE h.artifact_kind=? AND a.report_id=? ORDER BY h.chain_id",
            (ARTIFACT_CASE, case_id),
        ).fetchall()
        if len(rows) != 1:
            raise StoreConflictError("case:head-missing-or-ambiguous")
        return rows[0]

    def _case_latest_reconciliation(
        self,
        connection: sqlite3.Connection,
        original_reconciliation_raw: bytes,
    ) -> tuple[bytes, dict[str, object]]:
        value = reconciliation_independent._parse(original_reconciliation_raw)
        current = value.get("current_custody")
        if not isinstance(current, dict):
            raise StoreConflictError("case:latest-reconciliation-current")
        source_row = connection.execute(
            "SELECT payload FROM artifacts WHERE kind=? AND artifact_id=?",
            (ARTIFACT_SOURCE_EVIDENCE, current["artifact_id"]),
        ).fetchone()
        if source_row is None:
            raise StoreConflictError("case:latest-reconciliation-source")
        source_preview = source_independent.verify_artifact(
            bytes(source_row["payload"]),
            graph_profile_registry=self.graph_profile_registry,
            allow_unresolved_graph=True,
        )
        chain_id = _chain_id(
            ARTIFACT_RECONCILIATION,
            source_preview["subject"],
            source_preview["scope"],
            source_preview["profile_id"],
        )
        head = self._head(connection, chain_id)
        if head is None or head["artifact_kind"] != ARTIFACT_RECONCILIATION:
            raise StoreConflictError("case:latest-reconciliation-head")
        row = connection.execute(
            "SELECT payload FROM artifacts WHERE kind=? AND artifact_id=?",
            (ARTIFACT_RECONCILIATION, head["artifact_id"]),
        ).fetchone()
        if row is None:
            raise StoreSchemaError("case:latest-reconciliation-row")
        raw = bytes(row["payload"])
        return raw, self._case_reconciliation_context_for_raw(connection, raw)

    def admit_discrepancy_case(
        self,
        action: str,
        *,
        graph_artifact_id: str | None = None,
        finding_id: str | None = None,
        reconciliation_artifact_id: str | None = None,
        case_id: str | None = None,
        graph_profile_registry: Mapping[str, object] | None = None,
    ) -> AdmissionReceipt:
        """Select stored upstream bytes and atomically append one case transition."""

        if graph_profile_registry is not None and dict(graph_profile_registry) != dict(self.graph_profile_registry):
            raise StoreConflictError("profile:registry-mismatch")
        if action not in {case_independent.STAGE_OPEN, *case_independent.ACTIONS, "ADVANCE_RETEST"}:
            raise StoreConflictError("case:action")
        self._fault("before_transaction")
        connection = self._connect()
        try:
            try:
                connection.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as exc:
                raise StoreBusyError("transaction:busy") from exc
            self._fault("after_begin")
            self._validate_transaction_snapshot(connection)
            prior_case_raw: bytes | None = None
            retest_raw: bytes | None = None
            retest_context: dict[str, object] | None = None
            if action == case_independent.STAGE_OPEN:
                if not all(isinstance(item, str) and item for item in (graph_artifact_id, finding_id, reconciliation_artifact_id)):
                    raise StoreConflictError("case:open-selectors")
                context = self._case_upstream_context(connection, graph_artifact_id, reconciliation_artifact_id, finding_id)
                candidate = case_independent.build_artifact(
                    action,
                    graph_raw=context["graph_raw"],
                    reconciliation_raw=context["reconciliation_raw"],
                    reconciliation_context=context["reconciliation_context"],
                    governance_raw=context["governance_raw"],
                    graph_profile_registry=self.graph_profile_registry,
                    finding_id=finding_id,
                )
                case_context = context
            else:
                if not isinstance(case_id, str) or not case_id:
                    raise StoreConflictError("case:case-id")
                head_row = self._case_head_row(connection, case_id)
                prior_case_raw = bytes(head_row["payload"])
                prior_value = case_independent._parse(prior_case_raw)
                retry_stage = str(head_row["stage_kind"])
                if retry_stage == action or (action == "ADVANCE_RETEST" and retry_stage in {case_independent.STAGE_PARITY, case_independent.STAGE_PERSISTS}):
                    receipt_row = connection.execute(
                        "SELECT r.receipt FROM operations o JOIN receipts r ON r.operation_id=o.operation_id WHERE o.artifact_kind=? AND o.artifact_id=?",
                        (ARTIFACT_CASE, head_row["artifact_id"]),
                    ).fetchone()
                    if receipt_row is None:
                        raise StoreSchemaError("case:retry-receipt-missing")
                    connection.commit()
                    return AdmissionReceipt(bytes(receipt_row["receipt"]))
                upstream = prior_value["upstream"]
                context = self._case_upstream_context(
                    connection,
                    upstream["graph"]["artifact_id"],
                    upstream["reconciliation"]["artifact_id"],
                    upstream["finding"]["finding_id"],
                )
                actual_action = action
                if action == "ADVANCE_RETEST":
                    parity = prior_value["retest"].get("parity") if isinstance(prior_value.get("retest"), dict) else None
                    if not isinstance(parity, dict):
                        raise StoreConflictError("case:retest-result-missing")
                    actual_action = case_independent.STAGE_PARITY if parity["status"] == case_independent.PARITY_FULL else case_independent.STAGE_PERSISTS
                if actual_action in {case_independent.STAGE_RETEST, case_independent.STAGE_SUPERSEDED}:
                    retest_raw, retest_context = self._case_latest_reconciliation(connection, context["reconciliation_raw"])
                candidate = case_independent.build_artifact(
                    actual_action,
                    graph_raw=context["graph_raw"],
                    reconciliation_raw=context["reconciliation_raw"],
                    reconciliation_context=context["reconciliation_context"],
                    governance_raw=context["governance_raw"],
                    graph_profile_registry=self.graph_profile_registry,
                    prior_case_raw=prior_case_raw,
                    retest_reconciliation_raw=retest_raw,
                    retest_context=retest_context,
                )
                action = actual_action
                case_context = {
                    **context,
                    "prior_case_raw": prior_case_raw,
                    "retest_reconciliation_raw": retest_raw,
                    "retest_context": retest_context,
                }
            artifact = verify_artifact(
                ARTIFACT_CASE,
                candidate,
                graph_profile_registry=self.graph_profile_registry,
                reconciliation_context=case_context,
            )
            receipt = self._admit_in_transaction(
                connection,
                artifact,
                _payload_hash(candidate),
                enforce_governance=False,
            )
            self._validate_transaction_snapshot(connection)
            self._fault("after_event_receipt_before_commit")
            connection.commit()
            try:
                self._fault("after_commit_before_response")
            except InjectedFault as exc:
                raise IndeterminateCommitError(receipt.operation_id) from exc
            return receipt
        except IndeterminateCommitError:
            raise
        except (InjectedFault, StoreConflictError, StoreSchemaError, StoreBusyError):
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise
        except sqlite3.IntegrityError as exc:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise StoreConflictError("transaction:integrity") from exc
        except sqlite3.OperationalError as exc:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise StoreBusyError("transaction:operational") from exc
        finally:
            connection.close()

    def admit_source_evidence(
        self,
        custody_raw: bytes,
        graph_raw: bytes | None = None,
        graph_profile_registry: Mapping[str, object] | None = None,
    ) -> SourceCustodyAdmission:
        """Atomically custody source evidence and, when present, its graph artifact."""

        return self._admit_source_evidence(
            custody_raw,
            graph_raw,
            graph_profile_registry,
            observation_raw=None,
        )

    def admit_source_evidence_with_governance_observation(
        self,
        custody_raw: bytes,
        graph_raw: bytes,
        observation_raw: bytes,
        graph_profile_registry: Mapping[str, object] | None = None,
    ) -> SourceCustodyAdmission:
        """Atomically retain observation evidence only for a typed governance outcome."""

        return self._admit_source_evidence(
            custody_raw,
            graph_raw,
            graph_profile_registry,
            observation_raw=observation_raw,
        )

    def _admit_source_evidence(
        self,
        custody_raw: bytes,
        graph_raw: bytes | None,
        graph_profile_registry: Mapping[str, object] | None,
        *,
        observation_raw: bytes | None,
    ) -> SourceCustodyAdmission:
        """Run source/graph admission with any observation fallback inside one transaction."""

        if graph_profile_registry is not None and dict(graph_profile_registry) != dict(self.graph_profile_registry):
            raise StoreConflictError("profile:registry-mismatch")
        registry = self.graph_profile_registry
        if observation_raw is not None and graph_raw is None:
            raise StoreConflictError("custody:observation-without-graph")
        try:
            source_preview = source_independent.verify_artifact(custody_raw, graph_raw=graph_raw, graph_profile_registry=registry)
        except Exception as exc:
            raise StoreConflictError("custody:independent-reject") from exc
        linked = source_preview.get("linked_graph_artifact_id") is not None
        if linked != (graph_raw is not None):
            raise StoreConflictError("custody:graph-link-carrier")
        graph_artifact: VerifiedArtifact | None = None
        if graph_raw is not None:
            try:
                source_independent.verify_artifact(custody_raw, graph_raw=graph_raw, graph_profile_registry=registry)
                graph_artifact = verify_artifact(ARTIFACT_GRAPH, graph_raw, graph_profile_registry=registry)
            except Exception as exc:
                raise StoreConflictError("custody:graph-independent-reject") from exc
            if (
                source_preview.get("linked_graph_artifact_id") != graph_artifact.artifact_id
                or source_preview.get("linked_graph_payload_hash") != graph_artifact.payload_hash
                or source_preview.get("linked_graph_report_id") != graph_artifact.report_id
            ):
                raise StoreConflictError("custody:graph-link-mismatch")
        source_artifact = verify_artifact(ARTIFACT_SOURCE_EVIDENCE, custody_raw, graph_profile_registry=registry)
        observation_artifact: VerifiedArtifact | None = None
        if observation_raw is not None:
            try:
                observation_preview = source_independent.verify_artifact(
                    observation_raw,
                    graph_profile_registry=registry,
                )
                observation_artifact = verify_artifact(
                    ARTIFACT_SOURCE_EVIDENCE,
                    observation_raw,
                    graph_profile_registry=registry,
                )
            except Exception as exc:
                raise StoreConflictError("custody:observation-independent-reject") from exc
            if observation_preview.get("linked_graph_artifact_id") is not None:
                raise StoreConflictError("custody:observation-graph-link")
            if (
                observation_preview.get("envelope_digest") != source_preview.get("envelope_digest")
                or observation_artifact.subject != source_artifact.subject
                or observation_artifact.scope != source_artifact.scope
                or observation_artifact.profile_id != source_artifact.profile_id
                or observation_artifact.prior_artifact_id != source_artifact.prior_artifact_id
                or observation_artifact.prior_stage_id != source_artifact.prior_stage_id
            ):
                raise StoreConflictError("custody:observation-binding")
        request_hash = _payload_hash(custody_raw)
        self._fault("before_transaction")
        connection = self._connect()
        try:
            try:
                connection.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as exc:
                raise StoreBusyError("transaction:busy") from exc
            self._fault("after_begin")
            self._validate_transaction_snapshot(connection)
            expected_envelope_digest = source_preview["envelope_digest"]
            for row in connection.execute(
                "SELECT artifact_id,payload_hash,payload FROM artifacts WHERE kind=? ORDER BY artifact_id",
                (ARTIFACT_SOURCE_EVIDENCE,),
            ):
                existing_digest = source_independent.envelope_digest_from_artifact(bytes(row["payload"]))
                if existing_digest == expected_envelope_digest:
                    if row["artifact_id"] != source_artifact.artifact_id or row["payload_hash"] != source_artifact.payload_hash or bytes(row["payload"]) != custody_raw:
                        raise StoreConflictError("custody:envelope-collision")
                    existing = verify_artifact(ARTIFACT_SOURCE_EVIDENCE, custody_raw, graph_profile_registry=registry)
                    source_receipt = self._receipt_for_artifact(connection, existing)
                    graph_receipt = None
                    if graph_artifact is not None:
                        graph_receipt = self._receipt_for_artifact(connection, graph_artifact)
                    connection.commit()
                    return SourceCustodyAdmission(source_receipt, graph_receipt, graph_receipt is not None)
            admitted_source_artifact = source_artifact
            admitted_source_request_hash = request_hash
            if graph_artifact is not None:
                try:
                    self._require_active_v2_governance(connection, graph_artifact)
                except GovernanceObservationOnly:
                    if observation_artifact is None or observation_raw is None:
                        raise
                    admitted_source_artifact = observation_artifact
                    admitted_source_request_hash = _payload_hash(observation_raw)
                    graph_artifact = None
            if graph_artifact is not None:
                existing_graph_row = connection.execute(
                    "SELECT * FROM artifacts WHERE kind=? AND artifact_id=?",
                    (ARTIFACT_GRAPH, graph_artifact.artifact_id),
                ).fetchone()
                if existing_graph_row is not None and not self._artifact_matches(existing_graph_row, graph_artifact):
                    raise StoreConflictError("custody:graph-identity-conflict")
            source_receipt = self._admit_in_transaction(
                connection,
                admitted_source_artifact,
                admitted_source_request_hash,
                enforce_governance=False,
            )
            if graph_artifact is None:
                graph_receipt = None
            elif existing_graph_row is not None:
                graph_receipt = self._receipt_for_artifact(connection, graph_artifact)
            else:
                graph_receipt = self._admit_in_transaction(connection, graph_artifact, _payload_hash(graph_raw), enforce_governance=True)
            self._validate_transaction_snapshot(connection)
            self._fault("after_event_receipt_before_commit")
            connection.commit()
            try:
                self._fault("after_commit_before_response")
            except InjectedFault as exc:
                operation = graph_receipt or source_receipt
                raise IndeterminateCommitError(operation.operation_id) from exc
            return SourceCustodyAdmission(source_receipt, graph_receipt, graph_receipt is not None)
        except IndeterminateCommitError:
            raise
        except (InjectedFault, StoreConflictError, StoreSchemaError, StoreBusyError):
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise
        except sqlite3.IntegrityError as exc:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise StoreConflictError("transaction:integrity") from exc
        except sqlite3.OperationalError as exc:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise StoreBusyError("transaction:operational") from exc
        finally:
            connection.close()

    def _snapshot_rows(self) -> dict[str, list[dict[str, object]]]:
        connection = self._connect()
        try:
            return {
                "meta": [dict(row) for row in connection.execute("SELECT key,value FROM store_meta ORDER BY key")],
                "artifacts": [dict(row) for row in connection.execute("SELECT * FROM artifacts ORDER BY kind,artifact_id")],
                "operations": [dict(row) for row in connection.execute("SELECT * FROM operations ORDER BY event_sequence")],
                "receipts": [dict(row) for row in connection.execute("SELECT * FROM receipts ORDER BY operation_id")],
                "events": [dict(row) for row in connection.execute("SELECT * FROM events ORDER BY sequence")],
                "heads": [dict(row) for row in connection.execute("SELECT * FROM heads ORDER BY chain_id")],
            }
        finally:
            connection.close()

    def _restore_snapshot(self, snapshot: Mapping[str, list[Mapping[str, object]]]) -> None:
        """Restore one independently verified complete snapshot into this fresh DB."""

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            if any(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in ("artifacts", "operations", "receipts", "events", "heads")):
                raise StoreConflictError("restore:nonempty")
            connection.execute("DELETE FROM store_meta")
            for row in snapshot["meta"]:
                connection.execute("INSERT INTO store_meta(key,value) VALUES(?,?)", (row["key"], row["value"]))
            for row in snapshot["artifacts"]:
                connection.execute(
                    "INSERT INTO artifacts(kind,artifact_id,payload_hash,payload,artifact_schema,report_id,current_stage_id,transition_id,prior_artifact_id,prior_stage_id,subject,scope,stage_kind,authority_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    tuple(sqlite3.Binary(row["payload"]) if key == "payload" else row[key] for key in (
                        "kind", "artifact_id", "payload_hash", "payload", "artifact_schema", "report_id",
                        "current_stage_id", "transition_id", "prior_artifact_id", "prior_stage_id", "subject",
                        "scope", "stage_kind", "authority_json",
                    )),
                )
            for row in snapshot["operations"]:
                connection.execute(
                    "INSERT INTO operations(operation_id,chain_id,artifact_kind,artifact_id,payload_hash,request_hash,prior_artifact_id,prior_stage_id,expected_head_artifact_id,expected_head_stage_id,event_sequence,receipt_hash,commit_state_root) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    tuple(row[key] for key in (
                        "operation_id", "chain_id", "artifact_kind", "artifact_id", "payload_hash", "request_hash",
                        "prior_artifact_id", "prior_stage_id", "expected_head_artifact_id", "expected_head_stage_id",
                        "event_sequence", "receipt_hash", "commit_state_root",
                    )),
                )
            for row in snapshot["receipts"]:
                connection.execute(
                    "INSERT INTO receipts(operation_id,receipt_hash,receipt) VALUES(?,?,?)",
                    (row["operation_id"], row["receipt_hash"], sqlite3.Binary(row["receipt"])),
                )
            for row in snapshot["events"]:
                connection.execute(
                    "INSERT INTO events(sequence,chain_id,previous_event_root,event_root,operation_id,artifact_kind,artifact_id,payload_hash,prior_artifact_id,prior_stage_id,receipt_hash,commit_state_root) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    tuple(row[key] for key in (
                        "sequence", "chain_id", "previous_event_root", "event_root", "operation_id", "artifact_kind",
                        "artifact_id", "payload_hash", "prior_artifact_id", "prior_stage_id", "receipt_hash",
                        "commit_state_root",
                    )),
                )
            for row in snapshot["heads"]:
                connection.execute(
                    "INSERT INTO heads(chain_id,artifact_kind,artifact_id,current_stage_id,stage_kind,transition_id,event_sequence,head_root,state_root) VALUES(?,?,?,?,?,?,?,?,?)",
                    tuple(row[key] for key in (
                        "chain_id", "artifact_kind", "artifact_id", "current_stage_id", "stage_kind", "transition_id",
                        "event_sequence", "head_root", "state_root",
                    )),
                )
            connection.commit()
        except Exception:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()
