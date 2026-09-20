"""Synthetic, state-local financial responsibility owner for RightRail.

This is a separate application generation from the retained direct-clearance
Queue/Composition path.  It records descriptive financial history and
authorized local actions only.  It never calls a payment processor, emits a
live directive, stores raw evidence, or claims production authority.
"""

from __future__ import annotations

from contextlib import closing, contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import time
from typing import Any, Final, Iterable, Iterator, Mapping, Protocol


class FinancialError(RuntimeError):
    """Base error with a stable, redacted code in ``str(error)``."""


class FinancialInputError(FinancialError):
    pass


class FinancialIntegrityError(FinancialError):
    pass


class FinancialAuthorityError(FinancialError):
    pass


class FinancialConflictError(FinancialError):
    pass


class FinancialRevisionError(FinancialError):
    pass


class FinancialContinuityError(FinancialError):
    pass


class FinancialDispatchError(FinancialError):
    pass


def _fail(error_type: type[FinancialError], code: str) -> None:
    error = error_type(code)
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    raise error


_SCHEMA_VERSION: Final[int] = 5
_SCHEMA: Final[str] = "RR/FINANCIAL/OWNER/v5"
_CONTINUITY_SCHEMA: Final[str] = "RR/FINANCIAL/CONTINUITY/v5"
_CURRENCY: Final[str] = "USD"
_MAX_CENTS: Final[int] = (1 << 63) - 1
_MAX_ROWS: Final[int] = 10_000
_MAX_DUPLICATE_INPUTS: Final[int] = 256
_MAX_PACKAGE_BYTES: Final[int] = 8 * 1024 * 1024
_MODES: Final[frozenset[str]] = frozenset({"LIVE", "SHADOW", "TEST"})
_TEST_OWNER_ID: Final[str] = "continuity-test-owner-v1"
_SHADOW_OWNER_ID: Final[str] = "continuity-shadow-owner-v1"
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_ROLE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_KIND = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_WILDCARD_PERIODS: Final[frozenset[str]] = frozenset({"PROGRAM", "ALL"})
_CONTROL_PACK_ALLOWED_ROLES: Final[frozenset[str]] = frozenset(
    {"FINANCE_DECISION", "CASE_OWNER", "REPORTING_EDITOR", "RECEIVER"}
)
_CONTROL_PACK_REQUIRED_ROLES: Final[frozenset[str]] = frozenset(
    {"FINANCE_DECISION", "REPORTING_EDITOR", "RECEIVER"}
)
_CONTROL_PACK_POLICIES: Final[dict[tuple[str, str], tuple[tuple[str, ...], str, str]]] = {
    (
        "calculation:per-recipient:v1",
        "adjustment:offset:v1",
    ): (
        (
            "program-total=100000000",
            "H-owed=10000000",
            "other-total=90000000",
            "timeliness-separate",
        ),
        "PER_RECIPIENT",
        "AUTHORIZED_OFFSET",
    ),
    (
        "calculation:per-recipient:v2",
        "adjustment:offset:v2",
    ): (
        (
            "period-02-uses-rule-v2",
            "period-01-evaluation-preserved",
            "retrospective-authority-required",
        ),
        "PER_RECIPIENT",
        "AUTHORIZED_OFFSET",
    ),
}
_EVENT_DOMAIN = b"RR/FINANCIAL/EVENT/v2\x00"
_HEAD_DOMAIN = b"RR/FINANCIAL/HEAD/v2\x00"
_GENESIS_DOMAIN = b"RR/FINANCIAL/GENESIS/v5\x00"
_EVIDENCE_DOMAIN = b"RR/FINANCIAL/EVIDENCE/v1\x00"
_ACTION_DOMAIN = b"RR/FINANCIAL/ACTION/v1\x00"
_IDEMPOTENCY_DOMAIN = b"RR/FINANCIAL/IDEMPOTENCY/v1\x00"
_EVALUATION_RESULT_DOMAIN = b"RR/FINANCIAL/EVALUATION/v5\x00"
_EVALUATION_INPUT_DOMAIN = b"RR/FINANCIAL/EVALUATION-INPUT/v1\x00"
_EVALUATION_EVENT_DOMAIN = b"RR/FINANCIAL/EVALUATION-EVENT/v1\x00"
_EVALUATION_RECEIPT_DOMAIN = b"RR/FINANCIAL/EVALUATION-RECEIPT/v1\x00"
_CONTINUITY_DOMAIN = b"RR/FINANCIAL/CONTINUITY/v5\x00"
_IDENTITY_DOMAIN = b"RR/FINANCIAL/IDENTITY/v1\x00"
_EVALUATION_RECEIPT_CONTRACT: Final[str] = "RR/FINANCIAL/EVALUATION-RECEIPT/v1"
_ZERO_DIGEST: Final[bytes] = b"\x00" * 64

_TABLES: Final[frozenset[str]] = frozenset(
    {
        "financial_identity",
        "financial_meta",
        "control_packs",
        "population_imports",
        "population_items",
        "obligations",
        "evidence",
        "payments",
        "claimed_adjustments",
        "cases",
        "determinations",
        "actions",
        "action_outbox",
        "financial_events",
        "financial_conflicts",
        "evaluations",
    }
)

_TABLE_COLUMNS: Final[dict[str, tuple[str, ...]]] = {
    "financial_identity": (
        "id", "schema_version", "provenance", "bound_mode", "bound_owner_id",
        "anchor_sequence", "anchor_head", "genesis_head", "source_package_digest", "identity_digest",
    ),
    "financial_meta": (
        "id", "schema_version", "schema", "state_id", "deployment_id", "program_id",
        "period_id", "currency", "sequence", "history_head", "continuity_epoch",
        "dispatch_enabled", "egress_enabled", "trusted_authority_id",
        "trusted_authority_epoch", "trusted_authority_digest", "mode", "owner_id",
    ),
    "control_packs": (
        "pack_id", "state_id", "deployment_id", "program_id", "period_id", "version",
        "source_refs_json", "effective_start_ms", "effective_end_ms", "recorded_at_ms",
        "approved_at_ms", "calculation_rule_id", "adjustment_rule_id", "authorized_roles_json",
        "expected_tests_json", "pack_digest", "status",
    ),
    "population_imports": (
        "population_id", "pack_id", "cutoff_ms", "inclusion_rules_json", "expected_count",
        "source_complete", "imported_count", "validated_count", "validation_digest", "status",
        "created_at_ms", "updated_at_ms",
    ),
    "population_items": (
        "population_id", "item_id", "display_label", "owed_cents", "due_at_ms", "currency",
    ),
    "obligations": (
        "obligation_id", "population_id", "item_id", "period_id", "currency", "owed_cents",
        "due_at_ms", "rule_version", "revision", "claimed_adjustment_cents",
        "lawful_adjustment_cents", "received_cash_cents", "shortfall_cents", "overage_cents",
        "cash_satisfied", "amount_satisfied", "timely", "reporting_complete",
        "verification_status", "case_status", "delivery_status", "current_evaluation_id",
        "updated_at_ms",
    ),
    "evidence": (
        "evidence_id", "item_id", "kind", "common_origin_id", "source_id", "source_version",
        "local_ref", "applicable_at_ms", "event_at_ms", "received_at_ms", "content_digest",
        "record_digest", "amount_cents", "reversal_of", "supersedes",
    ),
    "payments": (
        "payment_id", "obligation_id", "item_id", "evidence_id", "common_origin_id",
        "amount_cents", "event_at_ms", "active", "reversed_by_evidence_id",
    ),
    "claimed_adjustments": (
        "claim_id", "obligation_id", "evidence_id", "amount_cents", "owner_role", "deadline_ms",
        "status", "created_at_ms", "updated_at_ms",
    ),
    "cases": (
        "case_id", "obligation_id", "reason", "contractual_accountability", "next_action_owner",
        "due_at_ms", "completion_conditions_json", "status", "updated_at_ms",
    ),
    "determinations": (
        "determination_id", "obligation_id", "claim_id", "actor_id", "actor_role", "authority_id",
        "authority_epoch", "authority_digest", "decision", "amount_cents",
        "supporting_evidence_json", "expected_revision", "resulting_revision", "decided_at_ms",
        "determination_digest", "input_evaluation_id", "input_evaluation_result_digest",
    ),
    "actions": (
        "action_id", "obligation_id", "determination_id", "kind", "status", "revision",
        "payload_json", "payload_digest", "idempotency_key", "created_at_ms",
    ),
    "action_outbox": (
        "action_id", "status", "attempt", "payload_digest", "acknowledgment_ref", "updated_at_ms",
    ),
    "financial_events": (
        "event_sequence", "event_id", "aggregate_type", "aggregate_id", "kind", "before_revision",
        "after_revision", "payload_json", "payload_digest", "previous_head", "head",
        "committed_at_ms",
    ),
    "financial_conflicts": (
        "conflict_id", "obligation_id", "common_origin_id", "existing_payment_id",
        "candidate_evidence_id", "existing_amount_cents", "candidate_amount_cents", "reason",
        "visible_at_ms",
    ),
    "evaluations": (
        "evaluation_id", "obligation_id", "revision", "rule_version", "evidence_ids_json",
        "authority_id", "evaluated_at_ms", "owed_cents", "claimed_adjustment_cents",
        "lawful_adjustment_cents", "received_cash_cents", "shortfall_cents", "overage_cents",
        "cash_satisfied", "amount_satisfied", "timely", "reporting_complete", "verification_status",
        "case_status", "delivery_status", "result_digest", "contract_version", "scope_json",
        "control_pack_id", "control_pack_version", "control_pack_digest", "authority_epoch",
        "authority_digest", "evidence_bindings_json", "input_snapshot_json",
        "input_snapshot_digest", "receipt_digest",
    ),
}


def _canonical(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        _fail(FinancialIntegrityError, "canonical_json")


def _digest(domain: bytes, *parts: bytes) -> bytes:
    digest = hashlib.sha3_512(domain)
    for part in parts:
        if type(part) is not bytes:
            _fail(FinancialIntegrityError, "digest_part")
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return digest.digest()


def _id(value: object, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        _fail(FinancialInputError, label)
    return value


def _role(value: object, label: str) -> str:
    if type(value) is not str or _ROLE.fullmatch(value) is None:
        _fail(FinancialInputError, label)
    return value


def _kind(value: object, label: str) -> str:
    if type(value) is not str or _KIND.fullmatch(value) is None:
        _fail(FinancialInputError, label)
    return value


def _text(value: object, label: str, *, max_bytes: int = 512) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > max_bytes or "\x00" in value:
        _fail(FinancialInputError, label)
    return value


def _cents(value: object, label: str, *, nonnegative: bool = False) -> int:
    if type(value) is not int or abs(value) > _MAX_CENTS or (nonnegative and value < 0):
        _fail(FinancialInputError, label)
    return value


def _add(left: int, right: int) -> int:
    value = left + right
    if value < -_MAX_CENTS or value > _MAX_CENTS:
        _fail(FinancialIntegrityError, "cents_overflow")
    return value


def _sum_cents(values: Iterable[int]) -> int:
    total = 0
    for value in values:
        total = _add(total, value)
    return total


def _hex(value: bytes) -> str:
    if type(value) is not bytes:
        _fail(FinancialIntegrityError, "bytes_required")
    return value.hex().upper()


def _identity_digest(
    *,
    provenance: str,
    bound_mode: str,
    bound_owner_id: str,
    anchor_sequence: int,
    source_package_digest: bytes,
) -> bytes:
    if provenance not in {"ROOT", "CONTINUITY_RESTORE"}:
        _fail(FinancialIntegrityError, "identity_provenance")
    if bound_mode not in _MODES:
        _fail(FinancialIntegrityError, "identity_mode")
    _id(bound_owner_id, "identity_owner_id")
    if type(anchor_sequence) is not int or not 0 <= anchor_sequence <= _MAX_ROWS:
        _fail(FinancialIntegrityError, "identity_anchor_sequence")
    source_package_digest = _blob(source_package_digest, 64, "identity_source_package_digest")
    return _digest(
        _IDENTITY_DOMAIN,
        _canonical(
            {
                "anchor_sequence": anchor_sequence,
                "bound_mode": bound_mode,
                "bound_owner_id": bound_owner_id,
                "provenance": provenance,
                "source_package_digest": _hex(source_package_digest),
            }
        ),
    )


def _blob(value: object, size: int, label: str) -> bytes:
    if type(value) is not bytes or len(value) != size:
        _fail(FinancialInputError, label)
    return bytes(value)


def _time(value: object, label: str) -> int:
    if type(value) is not int or value < 0 or value >= 2**63:
        _fail(FinancialInputError, label)
    return value


def _identity_record(
    value: Mapping[str, Any],
    *,
    error_type: type[FinancialError] = FinancialIntegrityError,
    code_prefix: str = "identity",
) -> dict[str, Any]:
    fields = set(_TABLE_COLUMNS["financial_identity"])
    if not isinstance(value, Mapping) or set(value) != fields:
        _fail(error_type, f"{code_prefix}:shape")
    if value["id"] != 1:
        _fail(error_type, f"{code_prefix}:id")
    schema_version = value["schema_version"]
    if type(schema_version) is not int or schema_version != _SCHEMA_VERSION:
        _fail(error_type, f"{code_prefix}:schema")
    provenance = value["provenance"]
    bound_mode = value["bound_mode"]
    bound_owner_id = value["bound_owner_id"]
    if provenance not in {"ROOT", "CONTINUITY_RESTORE"}:
        _fail(error_type, f"{code_prefix}:provenance")
    if bound_mode not in _MODES:
        _fail(error_type, f"{code_prefix}:mode")
    if type(bound_owner_id) is not str or _ID.fullmatch(bound_owner_id) is None:
        _fail(error_type, f"{code_prefix}:owner")
    if provenance == "CONTINUITY_RESTORE":
        if bound_mode == "LIVE":
            _fail(error_type, f"{code_prefix}:restore-live")
        expected_owner_id = _SHADOW_OWNER_ID if bound_mode == "SHADOW" else _TEST_OWNER_ID
        if bound_owner_id != expected_owner_id:
            _fail(error_type, f"{code_prefix}:restore-owner")
    anchor_sequence = value["anchor_sequence"]
    if type(anchor_sequence) is not int or not 0 <= anchor_sequence <= _MAX_ROWS:
        _fail(error_type, f"{code_prefix}:anchor-sequence")
    byte_values: dict[str, bytes] = {}
    for field in ("anchor_head", "genesis_head", "source_package_digest", "identity_digest"):
        raw = value[field]
        if type(raw) is not bytes or len(raw) != 64:
            _fail(error_type, f"{code_prefix}:{field}")
        byte_values[field] = bytes(raw)
    expected_digest = _identity_digest(
        provenance=provenance,
        bound_mode=bound_mode,
        bound_owner_id=bound_owner_id,
        anchor_sequence=anchor_sequence,
        source_package_digest=byte_values["source_package_digest"],
    )
    if byte_values["identity_digest"] != expected_digest:
        _fail(error_type, f"{code_prefix}:digest")
    return {
        "id": value["id"],
        "schema_version": schema_version,
        "provenance": provenance,
        "bound_mode": bound_mode,
        "bound_owner_id": bound_owner_id,
        "anchor_sequence": anchor_sequence,
        "anchor_head": byte_values["anchor_head"],
        "genesis_head": byte_values["genesis_head"],
        "source_package_digest": byte_values["source_package_digest"],
        "identity_digest": byte_values["identity_digest"],
    }


class FinancialClock(Protocol):
    def now_ms(self) -> int: ...


class _SystemClock:
    def now_ms(self) -> int:
        return time.time_ns() // 1_000_000


@dataclass(frozen=True, slots=True)
class AuthorityActor:
    actor_id: str
    roles: tuple[str, ...]

    def __post_init__(self) -> None:
        _id(self.actor_id, "actor_id")
        if type(self.roles) is not tuple or not self.roles or len(set(self.roles)) != len(self.roles):
            _fail(FinancialAuthorityError, "actor_roles")
        for role in self.roles:
            _role(role, "actor_role")


@dataclass(frozen=True, slots=True)
class SyntheticTrustedAuthority:
    authority_id: str = "synthetic-authority-v1"
    epoch: int = 1
    actors: tuple[AuthorityActor, ...] = (
        AuthorityActor("synthetic-official", ("FINANCE_DECISION", "CASE_OWNER")),
        AuthorityActor("synthetic-reporter", ("REPORTING_EDITOR",)),
        AuthorityActor("synthetic-receiver", ("RECEIVER",)),
    )
    synthetic_only: bool = True

    def __post_init__(self) -> None:
        _id(self.authority_id, "authority_id")
        if type(self.epoch) is not int or self.epoch < 1 or type(self.synthetic_only) is not bool or not self.synthetic_only:
            _fail(FinancialAuthorityError, "synthetic_authority_required")
        if type(self.actors) is not tuple or not self.actors:
            _fail(FinancialAuthorityError, "authority_actors")
        actor_ids: set[str] = set()
        for actor in self.actors:
            if type(actor) is not AuthorityActor or actor.actor_id in actor_ids:
                _fail(FinancialAuthorityError, "authority_actor_duplicate")
            actor_ids.add(actor.actor_id)

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical(
            {
                "authority_id": self.authority_id,
                "epoch": self.epoch,
                "actors": [{"actor_id": actor.actor_id, "roles": list(actor.roles)} for actor in self.actors],
                "synthetic_only": True,
            }
        )

    @property
    def digest(self) -> bytes:
        return _digest(_EVIDENCE_DOMAIN, self.canonical_bytes)

    def require(self, actor_id: str, role: str) -> None:
        _id(actor_id, "actor_id")
        _role(role, "actor_role")
        for actor in self.actors:
            if actor.actor_id == actor_id and role in actor.roles:
                return
        _fail(FinancialAuthorityError, "authority_actor_not_authorized")


@dataclass(frozen=True, slots=True)
class ControlPack:
    pack_id: str
    state_id: str
    deployment_id: str
    program_id: str
    period_id: str
    version: int
    source_refs: tuple[str, ...]
    effective_start_ms: int
    effective_end_ms: int
    recorded_at_ms: int
    approved_at_ms: int
    calculation_rule_id: str
    adjustment_rule_id: str
    authorized_roles: tuple[str, ...]
    expected_tests: tuple[str, ...]

    def __post_init__(self) -> None:
        for value, label in (
            (self.pack_id, "pack_id"),
            (self.state_id, "state_id"),
            (self.deployment_id, "deployment_id"),
            (self.program_id, "program_id"),
            (self.period_id, "period_id"),
            (self.calculation_rule_id, "calculation_rule_id"),
            (self.adjustment_rule_id, "adjustment_rule_id"),
        ):
            _id(value, label)
        if self.period_id in _WILDCARD_PERIODS:
            _fail(FinancialInputError, "period_scope_required")
        if type(self.version) is not int or self.version < 1:
            _fail(FinancialInputError, "pack_version")
        if type(self.source_refs) is not tuple or not self.source_refs:
            _fail(FinancialInputError, "pack_source_refs")
        for value in self.source_refs:
            _text(value, "pack_source_ref")
        if self.effective_start_ms >= self.effective_end_ms:
            _fail(FinancialInputError, "pack_effective_period")
        for value, label in ((self.effective_start_ms, "pack_effective_start"), (self.effective_end_ms, "pack_effective_end"), (self.recorded_at_ms, "pack_recorded"), (self.approved_at_ms, "pack_approved")):
            _time(value, label)
        if self.approved_at_ms < self.recorded_at_ms:
            _fail(FinancialInputError, "pack_approval_chronology")
        if type(self.authorized_roles) is not tuple or not self.authorized_roles or len(set(self.authorized_roles)) != len(self.authorized_roles):
            _fail(FinancialInputError, "pack_authorized_roles")
        for role in self.authorized_roles:
            _role(role, "pack_authorized_role")
        if type(self.expected_tests) is not tuple or not self.expected_tests:
            _fail(FinancialInputError, "pack_expected_tests")
        for test in self.expected_tests:
            _text(test, "pack_expected_test")

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical(
            {
                "pack_id": self.pack_id,
                "state_id": self.state_id,
                "deployment_id": self.deployment_id,
                "program_id": self.program_id,
                "period_id": self.period_id,
                "version": self.version,
                "source_refs": list(self.source_refs),
                "effective_start_ms": self.effective_start_ms,
                "effective_end_ms": self.effective_end_ms,
                "recorded_at_ms": self.recorded_at_ms,
                "approved_at_ms": self.approved_at_ms,
                "calculation_rule_id": self.calculation_rule_id,
                "adjustment_rule_id": self.adjustment_rule_id,
                "authorized_roles": list(self.authorized_roles),
                "expected_tests": list(self.expected_tests),
            }
        )

    @property
    def digest(self) -> bytes:
        return _digest(_EVIDENCE_DOMAIN, self.canonical_bytes)


def _control_pack_policy(
    *,
    calculation_rule_id: object,
    adjustment_rule_id: object,
    authorized_roles: object,
    expected_tests: object,
) -> tuple[str, str]:
    if type(calculation_rule_id) is not str or type(adjustment_rule_id) is not str:
        _fail(FinancialIntegrityError, "control_pack_policy_unsupported")
    if type(authorized_roles) not in (tuple, list) or type(expected_tests) not in (tuple, list):
        _fail(FinancialIntegrityError, "control_pack_policy_unsupported")
    roles = tuple(authorized_roles)
    tests = tuple(expected_tests)
    policy = _CONTROL_PACK_POLICIES.get((calculation_rule_id, adjustment_rule_id))
    if policy is None or tests != policy[0]:
        _fail(FinancialIntegrityError, "control_pack_policy_unsupported")
    if not roles or len(set(roles)) != len(roles):
        _fail(FinancialIntegrityError, "control_pack_roles_unsupported")
    for role in roles:
        _role(role, "control_pack_role")
    if not set(roles) <= _CONTROL_PACK_ALLOWED_ROLES or not _CONTROL_PACK_REQUIRED_ROLES <= set(roles):
        _fail(FinancialIntegrityError, "control_pack_roles_unsupported")
    return policy[1], policy[2]


_EVALUATION_RESULT_FIELDS: Final[tuple[str, ...]] = (
    "evaluation_id", "obligation_id", "revision", "rule_version", "evidence_ids",
    "authority_id", "evaluated_at_ms", "owed_cents", "claimed_adjustment_cents",
    "lawful_adjustment_cents", "received_cash_cents", "shortfall_cents", "overage_cents",
    "cash_satisfied", "amount_satisfied", "timely", "reporting_complete",
    "verification_status", "case_status", "delivery_status",
)


def _digest_input(value: object, label: str) -> bytes:
    if type(value) is bytes:
        if len(value) != 64:
            _fail(FinancialInputError, label)
        return value
    if type(value) is not str or re.fullmatch(r"[0-9A-Fa-f]{128}", value) is None:
        _fail(FinancialInputError, label)
    try:
        result = bytes.fromhex(value)
    except ValueError:
        _fail(FinancialInputError, label)
    if len(result) != 64:
        _fail(FinancialInputError, label)
    return result


def _evaluation_result_body(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value[key] for key in _EVALUATION_RESULT_FIELDS}


def _evaluation_receipt_body(
    *,
    result: Mapping[str, Any],
    scope: Mapping[str, str],
    control_pack_id: str,
    control_pack_version: int,
    control_pack_digest: bytes,
    evidence_bindings: list[dict[str, str]],
    authority_id: str,
    authority_epoch: int,
    authority_digest: bytes,
    input_snapshot_digest: bytes,
    result_digest: bytes,
) -> dict[str, Any]:
    return {
        "contract_version": _EVALUATION_RECEIPT_CONTRACT,
        "scope": dict(scope),
        "evaluation_id": str(result["evaluation_id"]),
        "obligation_id": str(result["obligation_id"]),
        "revision": int(result["revision"]),
        "control_pack": {
            "pack_id": control_pack_id,
            "version": control_pack_version,
            "digest": _hex(control_pack_digest),
        },
        "evidence_bindings": evidence_bindings,
        "input_snapshot_digest": _hex(input_snapshot_digest),
        "authority": {
            "authority_id": authority_id,
            "epoch": authority_epoch,
            "digest": _hex(authority_digest),
        },
        **_evaluation_result_body(result),
        "result_digest": _hex(result_digest),
    }


def _evaluation_binding_digest(bindings: Iterable[Mapping[str, Any]]) -> bytes:
    ordered = sorted(
        (
            {
                "evaluation_id": str(binding["evaluation_id"]),
                "input_snapshot_digest": str(binding["input_snapshot_digest"]),
                "result_digest": str(binding["result_digest"]),
                "receipt_digest": str(binding["receipt_digest"]),
            }
            for binding in bindings
        ),
        key=lambda binding: binding["evaluation_id"],
    )
    return _digest(_EVALUATION_EVENT_DOMAIN, _canonical({"evaluations": ordered}))


def _determination_digest_payload(
    *,
    action_id: str,
    determination_id: str,
    obligation_id: str,
    kind: str,
    claim_id: str,
    decision: str,
    amount_cents: int,
    input_evaluation_id: str,
    input_evaluation_result_digest: bytes,
    actor_id: str,
    actor_role: str,
    authority_id: str,
    authority_epoch: int,
    authority_digest: bytes,
    supporting_evidence: list[dict[str, str]],
    expected_revision: int,
    resulting_revision: int,
    decided_at_ms: int,
) -> dict[str, Any]:
    return {
        "action_id": action_id,
        "determination_id": determination_id,
        "obligation_id": obligation_id,
        "kind": kind,
        "claim_id": claim_id,
        "decision": decision,
        "amount_cents": amount_cents,
        "input_evaluation_id": input_evaluation_id,
        "input_evaluation_result_digest": _hex(input_evaluation_result_digest),
        "actor_id": actor_id,
        "actor_role": actor_role,
        "authority_id": authority_id,
        "authority_epoch": authority_epoch,
        "authority_digest": _hex(authority_digest),
        "supporting_evidence": supporting_evidence,
        "expected_revision": expected_revision,
        "resulting_revision": resulting_revision,
        "decided_at_ms": decided_at_ms,
    }


@dataclass(frozen=True, slots=True)
class PopulationItem:
    population_id: str
    item_id: str
    display_label: str
    owed_cents: int
    due_at_ms: int
    currency: str = _CURRENCY
    included: bool = True

    def __post_init__(self) -> None:
        _id(self.population_id, "population_id")
        _id(self.item_id, "item_id")
        _text(self.display_label, "display_label", max_bytes=128)
        _cents(self.owed_cents, "owed_cents", nonnegative=True)
        if self.owed_cents == 0:
            _fail(FinancialInputError, "owed_cents_zero")
        _time(self.due_at_ms, "due_at_ms")
        if self.currency != _CURRENCY or type(self.included) is not bool or not self.included:
            _fail(FinancialInputError, "population_item_scope")

    @property
    def digest(self) -> bytes:
        return _digest(_EVIDENCE_DOMAIN, _canonical({"population_id": self.population_id, "item_id": self.item_id, "display_label": self.display_label, "owed_cents": self.owed_cents, "due_at_ms": self.due_at_ms, "currency": self.currency}))


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    evidence_id: str
    item_id: str
    kind: str
    common_origin_id: str
    source_id: str
    source_version: str
    local_ref: str
    applicable_at_ms: int
    event_at_ms: int
    received_at_ms: int
    content_digest: bytes
    amount_cents: int | None = None
    reversal_of: str | None = None
    supersedes: str | None = None

    def __post_init__(self) -> None:
        for value, label in ((self.evidence_id, "evidence_id"), (self.item_id, "item_id"), (self.common_origin_id, "common_origin_id"), (self.source_id, "source_id"), (self.source_version, "source_version"), (self.local_ref, "local_ref")):
            _id(value, label)
        _kind(self.kind, "evidence_kind")
        for value, label in ((self.applicable_at_ms, "evidence_applicable"), (self.event_at_ms, "evidence_event"), (self.received_at_ms, "evidence_received")):
            _time(value, label)
        if self.event_at_ms > self.received_at_ms:
            _fail(FinancialInputError, "evidence_chronology")
        _blob(self.content_digest, 64, "evidence_content_digest")
        if self.amount_cents is not None:
            _cents(self.amount_cents, "evidence_amount", nonnegative=True)
        if self.reversal_of is not None:
            _id(self.reversal_of, "evidence_reversal_of")
        if self.supersedes is not None:
            _id(self.supersedes, "evidence_supersedes")

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical(
            {
                "evidence_id": self.evidence_id,
                "item_id": self.item_id,
                "kind": self.kind,
                "common_origin_id": self.common_origin_id,
                "source_id": self.source_id,
                "source_version": self.source_version,
                "local_ref": self.local_ref,
                "applicable_at_ms": self.applicable_at_ms,
                "event_at_ms": self.event_at_ms,
                "received_at_ms": self.received_at_ms,
                "content_digest": _hex(self.content_digest),
                "amount_cents": self.amount_cents,
                "reversal_of": self.reversal_of,
                "supersedes": self.supersedes,
            }
        )

    @property
    def record_digest(self) -> bytes:
        return _digest(_EVIDENCE_DOMAIN, self.canonical_bytes)


class _WriteClock(Protocol):
    def now_ms(self) -> int: ...


@dataclass(frozen=True, slots=True)
class FinancialOwnerConfig:
    state_id: str
    deployment_id: str
    program_id: str
    period_id: str = "PROGRAM"
    currency: str = _CURRENCY

    def __post_init__(self) -> None:
        for value, label in ((self.state_id, "state_id"), (self.deployment_id, "deployment_id"), (self.program_id, "program_id"), (self.period_id, "period_id")):
            _id(value, label)
        if self.period_id in _WILDCARD_PERIODS:
            _fail(FinancialInputError, "period_scope_required")
        if self.currency != _CURRENCY:
            _fail(FinancialInputError, "currency")

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical({"state_id": self.state_id, "deployment_id": self.deployment_id, "program_id": self.program_id, "period_id": self.period_id, "currency": self.currency})


def _sql_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE financial_identity (
            id INTEGER PRIMARY KEY CHECK (id=1),
            schema_version INTEGER NOT NULL,
            provenance TEXT NOT NULL CHECK (provenance IN ('ROOT','CONTINUITY_RESTORE')),
            bound_mode TEXT NOT NULL CHECK (bound_mode IN ('LIVE','SHADOW','TEST')),
            bound_owner_id TEXT NOT NULL,
            anchor_sequence INTEGER NOT NULL CHECK (anchor_sequence>=0),
            anchor_head BLOB NOT NULL CHECK (length(anchor_head)=64),
            genesis_head BLOB NOT NULL CHECK (length(genesis_head)=64),
            source_package_digest BLOB NOT NULL CHECK (length(source_package_digest)=64),
            identity_digest BLOB NOT NULL CHECK (length(identity_digest)=64)
        );
        CREATE TABLE financial_meta (
            id INTEGER PRIMARY KEY CHECK (id=1),
            schema_version INTEGER NOT NULL,
            schema TEXT NOT NULL,
            state_id TEXT NOT NULL,
            deployment_id TEXT NOT NULL,
            program_id TEXT NOT NULL,
            period_id TEXT NOT NULL,
            currency TEXT NOT NULL,
            sequence INTEGER NOT NULL CHECK (sequence>=0),
            history_head BLOB NOT NULL CHECK (length(history_head)=64),
            continuity_epoch INTEGER NOT NULL CHECK (continuity_epoch>=1),
            dispatch_enabled INTEGER NOT NULL CHECK (dispatch_enabled=0),
            egress_enabled INTEGER NOT NULL CHECK (egress_enabled=0),
            trusted_authority_id TEXT NOT NULL,
            trusted_authority_epoch INTEGER NOT NULL CHECK (trusted_authority_epoch>=1),
            trusted_authority_digest BLOB NOT NULL CHECK (length(trusted_authority_digest)=64),
            mode TEXT NOT NULL CHECK (mode IN ('LIVE','SHADOW','TEST')),
            owner_id TEXT NOT NULL
        );
        CREATE TABLE control_packs (
            pack_id TEXT PRIMARY KEY,
            state_id TEXT NOT NULL,
            deployment_id TEXT NOT NULL,
            program_id TEXT NOT NULL,
            period_id TEXT NOT NULL,
            version INTEGER NOT NULL,
            source_refs_json TEXT NOT NULL,
            effective_start_ms INTEGER NOT NULL,
            effective_end_ms INTEGER NOT NULL,
            recorded_at_ms INTEGER NOT NULL,
            approved_at_ms INTEGER NOT NULL,
            calculation_rule_id TEXT NOT NULL,
            adjustment_rule_id TEXT NOT NULL,
            authorized_roles_json TEXT NOT NULL,
            expected_tests_json TEXT NOT NULL,
            pack_digest BLOB NOT NULL CHECK (length(pack_digest)=64),
            status TEXT NOT NULL CHECK (status IN ('APPROVED','WITHDRAWN'))
        );
        CREATE TABLE population_imports (
            population_id TEXT PRIMARY KEY,
            pack_id TEXT NOT NULL,
            cutoff_ms INTEGER NOT NULL,
            inclusion_rules_json TEXT NOT NULL,
            expected_count INTEGER NOT NULL CHECK (expected_count>0),
            source_complete INTEGER NOT NULL CHECK (source_complete IN (0,1)),
            imported_count INTEGER NOT NULL CHECK (imported_count>=0),
            validated_count INTEGER NOT NULL CHECK (validated_count>=0),
            validation_digest BLOB,
            status TEXT NOT NULL CHECK (status IN ('STAGED','VALIDATED','PUBLISHED')),
            created_at_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL
        );
        CREATE TABLE population_items (
            population_id TEXT NOT NULL,
            item_id TEXT NOT NULL,
            display_label TEXT NOT NULL,
            owed_cents INTEGER NOT NULL CHECK (owed_cents>0),
            due_at_ms INTEGER NOT NULL,
            currency TEXT NOT NULL,
            PRIMARY KEY (population_id,item_id)
        );
        CREATE TABLE obligations (
            obligation_id TEXT PRIMARY KEY,
            population_id TEXT NOT NULL,
            item_id TEXT NOT NULL,
            period_id TEXT NOT NULL,
            currency TEXT NOT NULL,
            owed_cents INTEGER NOT NULL CHECK (owed_cents>0),
            due_at_ms INTEGER NOT NULL,
            rule_version INTEGER NOT NULL CHECK (rule_version>0),
            revision INTEGER NOT NULL CHECK (revision>=0),
            claimed_adjustment_cents INTEGER NOT NULL CHECK (claimed_adjustment_cents>=0),
            lawful_adjustment_cents INTEGER NOT NULL CHECK (lawful_adjustment_cents>=0),
            received_cash_cents INTEGER NOT NULL CHECK (received_cash_cents>=0),
            shortfall_cents INTEGER NOT NULL CHECK (shortfall_cents>=0),
            overage_cents INTEGER NOT NULL CHECK (overage_cents>=0),
            cash_satisfied INTEGER NOT NULL CHECK (cash_satisfied IN (0,1)),
            amount_satisfied INTEGER NOT NULL CHECK (amount_satisfied IN (0,1)),
            timely INTEGER NOT NULL CHECK (timely IN (0,1)),
            reporting_complete INTEGER NOT NULL CHECK (reporting_complete IN (0,1)),
            verification_status TEXT NOT NULL,
            case_status TEXT NOT NULL,
            delivery_status TEXT NOT NULL,
            current_evaluation_id TEXT,
            updated_at_ms INTEGER NOT NULL,
            UNIQUE (population_id,item_id)
        );
        CREATE TABLE evidence (
            evidence_id TEXT PRIMARY KEY,
            item_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            common_origin_id TEXT NOT NULL,
            source_id TEXT NOT NULL,
            source_version TEXT NOT NULL,
            local_ref TEXT NOT NULL,
            applicable_at_ms INTEGER NOT NULL,
            event_at_ms INTEGER NOT NULL,
            received_at_ms INTEGER NOT NULL,
            content_digest BLOB NOT NULL CHECK (length(content_digest)=64),
            record_digest BLOB NOT NULL CHECK (length(record_digest)=64),
            amount_cents INTEGER,
            reversal_of TEXT,
            supersedes TEXT
        );
        CREATE TABLE payments (
            payment_id TEXT PRIMARY KEY,
            obligation_id TEXT NOT NULL,
            item_id TEXT NOT NULL,
            evidence_id TEXT NOT NULL,
            common_origin_id TEXT NOT NULL,
            amount_cents INTEGER NOT NULL CHECK (amount_cents>0),
            event_at_ms INTEGER NOT NULL,
            active INTEGER NOT NULL CHECK (active IN (0,1)),
            reversed_by_evidence_id TEXT,
            UNIQUE (obligation_id,common_origin_id)
        );
        CREATE TABLE claimed_adjustments (
            claim_id TEXT PRIMARY KEY,
            obligation_id TEXT NOT NULL,
            evidence_id TEXT NOT NULL,
            amount_cents INTEGER NOT NULL CHECK (amount_cents>0),
            owner_role TEXT NOT NULL,
            deadline_ms INTEGER NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('CLAIMED','AUTHORIZED','REJECTED')),
            created_at_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL
        );
        CREATE TABLE cases (
            case_id TEXT PRIMARY KEY,
            obligation_id TEXT NOT NULL,
            reason TEXT NOT NULL,
            contractual_accountability TEXT NOT NULL,
            next_action_owner TEXT NOT NULL,
            due_at_ms INTEGER NOT NULL,
            completion_conditions_json TEXT NOT NULL,
            status TEXT NOT NULL,
            updated_at_ms INTEGER NOT NULL
        );
        CREATE TABLE determinations (
            determination_id TEXT PRIMARY KEY,
            obligation_id TEXT NOT NULL,
            claim_id TEXT,
            actor_id TEXT NOT NULL,
            actor_role TEXT NOT NULL,
            authority_id TEXT NOT NULL,
            authority_epoch INTEGER NOT NULL,
            authority_digest BLOB NOT NULL CHECK (length(authority_digest)=64),
            decision TEXT NOT NULL,
            amount_cents INTEGER NOT NULL CHECK (amount_cents>=0),
            supporting_evidence_json TEXT NOT NULL,
            expected_revision INTEGER NOT NULL,
            resulting_revision INTEGER NOT NULL,
            decided_at_ms INTEGER NOT NULL,
            determination_digest BLOB NOT NULL CHECK (length(determination_digest)=64),
            input_evaluation_id TEXT NOT NULL,
            input_evaluation_result_digest BLOB NOT NULL CHECK (length(input_evaluation_result_digest)=64),
            UNIQUE (input_evaluation_id)
        );
        CREATE TABLE actions (
            action_id TEXT PRIMARY KEY,
            obligation_id TEXT NOT NULL,
            determination_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('READY','ACKNOWLEDGED','CANCELLED')),
            revision INTEGER NOT NULL,
            payload_json TEXT NOT NULL,
            payload_digest BLOB NOT NULL CHECK (length(payload_digest)=64),
            idempotency_key BLOB NOT NULL CHECK (length(idempotency_key)=64),
            created_at_ms INTEGER NOT NULL
        );
        CREATE TABLE action_outbox (
            action_id TEXT PRIMARY KEY,
            status TEXT NOT NULL CHECK (status IN ('READY','ACKNOWLEDGED','CANCELLED')),
            attempt INTEGER NOT NULL CHECK (attempt>=0),
            payload_digest BLOB NOT NULL CHECK (length(payload_digest)=64),
            acknowledgment_ref TEXT,
            updated_at_ms INTEGER NOT NULL
        );
        CREATE TABLE financial_events (
            event_sequence INTEGER PRIMARY KEY,
            event_id BLOB NOT NULL UNIQUE CHECK (length(event_id)=64),
            aggregate_type TEXT NOT NULL,
            aggregate_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            before_revision INTEGER NOT NULL,
            after_revision INTEGER NOT NULL,
            payload_json TEXT NOT NULL,
            payload_digest BLOB NOT NULL CHECK (length(payload_digest)=64),
            previous_head BLOB NOT NULL CHECK (length(previous_head)=64),
            head BLOB NOT NULL CHECK (length(head)=64),
            committed_at_ms INTEGER NOT NULL
        );
        CREATE TABLE financial_conflicts (
            conflict_id TEXT PRIMARY KEY,
            obligation_id TEXT NOT NULL,
            common_origin_id TEXT NOT NULL,
            existing_payment_id TEXT,
            candidate_evidence_id TEXT NOT NULL,
            existing_amount_cents INTEGER,
            candidate_amount_cents INTEGER,
            reason TEXT NOT NULL,
            visible_at_ms INTEGER NOT NULL
        );
        CREATE TABLE evaluations (
            evaluation_id TEXT PRIMARY KEY,
            obligation_id TEXT NOT NULL,
            revision INTEGER NOT NULL,
            rule_version INTEGER NOT NULL,
            evidence_ids_json TEXT NOT NULL,
            authority_id TEXT NOT NULL,
            evaluated_at_ms INTEGER NOT NULL,
            owed_cents INTEGER NOT NULL,
            claimed_adjustment_cents INTEGER NOT NULL,
            lawful_adjustment_cents INTEGER NOT NULL,
            received_cash_cents INTEGER NOT NULL,
            shortfall_cents INTEGER NOT NULL,
            overage_cents INTEGER NOT NULL,
            cash_satisfied INTEGER NOT NULL,
            amount_satisfied INTEGER NOT NULL,
            timely INTEGER NOT NULL,
            reporting_complete INTEGER NOT NULL,
            verification_status TEXT NOT NULL,
            case_status TEXT NOT NULL,
            delivery_status TEXT NOT NULL,
            result_digest BLOB NOT NULL CHECK (length(result_digest)=64),
            contract_version TEXT NOT NULL,
            scope_json TEXT NOT NULL,
            control_pack_id TEXT NOT NULL,
            control_pack_version INTEGER NOT NULL,
            control_pack_digest BLOB NOT NULL CHECK (length(control_pack_digest)=64),
            authority_epoch INTEGER NOT NULL,
            authority_digest BLOB NOT NULL CHECK (length(authority_digest)=64),
            evidence_bindings_json TEXT NOT NULL,
            input_snapshot_json TEXT NOT NULL,
            input_snapshot_digest BLOB NOT NULL CHECK (length(input_snapshot_digest)=64),
            receipt_digest BLOB NOT NULL CHECK (length(receipt_digest)=64)
        );
        CREATE TRIGGER action_payload_immutable
        BEFORE UPDATE OF action_id,obligation_id,determination_id,kind,revision,payload_json,payload_digest,idempotency_key,created_at_ms ON actions
        BEGIN SELECT RAISE(ABORT,'action_payload_immutable'); END;
        CREATE TRIGGER action_outbox_payload_immutable
        BEFORE UPDATE OF action_id,payload_digest ON action_outbox
        BEGIN SELECT RAISE(ABORT,'action_outbox_payload_immutable'); END;
        CREATE TRIGGER evidence_record_immutable
        BEFORE UPDATE OF evidence_id,item_id,kind,common_origin_id,source_id,source_version,local_ref,applicable_at_ms,event_at_ms,received_at_ms,content_digest,record_digest,amount_cents,reversal_of,supersedes ON evidence
        BEGIN SELECT RAISE(ABORT,'evidence_record_immutable'); END;
        CREATE TRIGGER financial_identity_insert_immutable
        BEFORE INSERT ON financial_identity
        WHEN EXISTS (SELECT 1 FROM financial_identity)
        BEGIN SELECT RAISE(ABORT,'financial_identity_immutable'); END;
        CREATE TRIGGER financial_identity_update_immutable
        BEFORE UPDATE OF schema_version,provenance,bound_mode,bound_owner_id,anchor_sequence,anchor_head,genesis_head,source_package_digest,identity_digest ON financial_identity
        BEGIN SELECT RAISE(ABORT,'financial_identity_immutable'); END;
        CREATE TRIGGER financial_identity_delete_immutable
        BEFORE DELETE ON financial_identity
        BEGIN SELECT RAISE(ABORT,'financial_identity_immutable'); END;
        """
    )


class FinancialOwner:
    """The sole writer for the synthetic financial responsibility."""

    def __init__(
        self,
        *,
        path: Path,
        config: FinancialOwnerConfig,
        trusted_authority: SyntheticTrustedAuthority | None,
        clock: FinancialClock | None = None,
        mode: str = "LIVE",
        owner_id: str = "financial-owner-v1",
        _identity_contract: Mapping[str, Any] | None = None,
    ) -> None:
        if not isinstance(path, Path) or not path.parent.is_dir() or path.is_symlink():
            _fail(FinancialIntegrityError, "owner_path")
        if mode not in _MODES:
            _fail(FinancialInputError, "owner_mode")
        if trusted_authority is None or type(trusted_authority) is not SyntheticTrustedAuthority:
            _fail(FinancialAuthorityError, "trusted_authority_required")
        if type(clock) is not type(None) and not hasattr(clock, "now_ms"):
            _fail(FinancialInputError, "clock")
        self.path = path
        self.config = config
        self.trusted_authority = trusted_authority
        self.clock: FinancialClock = clock if clock is not None else _SystemClock()
        self.mode = mode
        self.owner_id = _id(owner_id, "owner_id")
        if self.mode == "TEST" and self.owner_id != _TEST_OWNER_ID:
            _fail(FinancialInputError, "test_owner_identity")
        existed = path.exists()
        if existed and path.stat().st_size == 0:
            _fail(FinancialIntegrityError, "empty_database")
        if existed and _identity_contract is not None:
            _fail(FinancialIntegrityError, "identity_contract_destination")
        if not existed:
            if _identity_contract is None:
                identity_digest = _identity_digest(
                    provenance="ROOT",
                    bound_mode=mode,
                    bound_owner_id=self.owner_id,
                    anchor_sequence=0,
                    source_package_digest=_ZERO_DIGEST,
                )
                genesis = _digest(_GENESIS_DOMAIN, config.canonical_bytes, trusted_authority.digest, identity_digest)
                identity = {
                    "id": 1,
                    "schema_version": _SCHEMA_VERSION,
                    "provenance": "ROOT",
                    "bound_mode": mode,
                    "bound_owner_id": self.owner_id,
                    "anchor_sequence": 0,
                    "anchor_head": genesis,
                    "genesis_head": genesis,
                    "source_package_digest": _ZERO_DIGEST,
                    "identity_digest": identity_digest,
                }
                initial_sequence = 0
                initial_history_head = genesis
            else:
                identity = _identity_record(_identity_contract, code_prefix="identity_contract")
                if identity["provenance"] != "CONTINUITY_RESTORE" or identity["bound_mode"] != mode or identity["bound_owner_id"] != self.owner_id:
                    _fail(FinancialIntegrityError, "identity_contract_binding")
                if identity["source_package_digest"] == _ZERO_DIGEST:
                    _fail(FinancialIntegrityError, "identity_contract_source")
                initial_sequence = int(identity["anchor_sequence"])
                initial_history_head = bytes(identity["anchor_head"])
            with closing(self._connect()) as connection:
                _sql_schema(connection)
                connection.execute(
                    "INSERT INTO financial_meta VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (1, _SCHEMA_VERSION, _SCHEMA, config.state_id, config.deployment_id, config.program_id, config.period_id, config.currency, initial_sequence, initial_history_head, 1, 0, 0, trusted_authority.authority_id, trusted_authority.epoch, trusted_authority.digest, mode, self.owner_id),
                )
                identity_columns = _TABLE_COLUMNS["financial_identity"]
                connection.execute(
                    f"INSERT INTO financial_identity ({','.join(identity_columns)}) VALUES ({','.join('?' for _ in identity_columns)})",
                    tuple(identity[column] for column in identity_columns),
                )
                connection.commit()
        if _identity_contract is None:
            self._verify_open_identity()

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(str(self.path), timeout=5.0, isolation_level=None)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=5000")
            return connection
        except sqlite3.Error:
            _fail(FinancialIntegrityError, "database_open")

    def _verify_open_identity(self) -> None:
        try:
            with closing(self._connect()) as connection:
                tables = {str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
                if tables != _TABLES:
                    _fail(FinancialIntegrityError, "schema_tables")
                row = connection.execute("SELECT * FROM financial_meta WHERE id=1").fetchone()
                if row is None:
                    _fail(FinancialIntegrityError, "schema_meta")
                expected = (self.config.state_id, self.config.deployment_id, self.config.program_id, self.config.period_id, self.config.currency)
                if tuple(row[key] for key in ("schema_version", "schema", "state_id", "deployment_id", "program_id", "period_id", "currency")) != (_SCHEMA_VERSION, _SCHEMA, *expected):
                    _fail(FinancialIntegrityError, "schema_identity")
                if int(row["dispatch_enabled"]) != 0 or int(row["egress_enabled"]) != 0 or str(row["mode"]) != self.mode:
                    _fail(FinancialIntegrityError, "nonactivating_boundary")
                if str(row["owner_id"]) != self.owner_id:
                    _fail(FinancialIntegrityError, "owner_identity")
                if (str(row["trusted_authority_id"]), int(row["trusted_authority_epoch"]), bytes(row["trusted_authority_digest"])) != (self.trusted_authority.authority_id, self.trusted_authority.epoch, self.trusted_authority.digest):
                    _fail(FinancialAuthorityError, "trusted_authority_stale")
                identity_rows = connection.execute("SELECT * FROM financial_identity WHERE id=1").fetchall()
                if len(identity_rows) != 1:
                    _fail(FinancialIntegrityError, "identity_cardinality")
                identity_row = identity_rows[0]
                identity = _identity_record({column: identity_row[column] for column in _TABLE_COLUMNS["financial_identity"]})
                if identity["bound_mode"] != str(row["mode"]) or identity["bound_owner_id"] != str(row["owner_id"]):
                    _fail(FinancialIntegrityError, "identity_binding")
                if identity["provenance"] == "ROOT":
                    expected_genesis = _digest(_GENESIS_DOMAIN, self.config.canonical_bytes, self.trusted_authority.digest, identity["identity_digest"])
                    if identity["source_package_digest"] != _ZERO_DIGEST or identity["anchor_sequence"] != 0 or identity["anchor_head"] != expected_genesis or identity["genesis_head"] != expected_genesis:
                        _fail(FinancialIntegrityError, "identity_genesis")
                else:
                    if identity["source_package_digest"] == _ZERO_DIGEST or identity["anchor_sequence"] > int(row["sequence"]):
                        _fail(FinancialIntegrityError, "identity_anchor")
                    if identity["anchor_sequence"] == 0:
                        if identity["anchor_head"] != identity["genesis_head"]:
                            _fail(FinancialIntegrityError, "identity_anchor")
                    else:
                        anchor = connection.execute(
                            "SELECT head FROM financial_events WHERE event_sequence=?",
                            (identity["anchor_sequence"],),
                        ).fetchone()
                        if anchor is None or bytes(anchor["head"]) != identity["anchor_head"]:
                            _fail(FinancialIntegrityError, "identity_history_anchor")
                if int(row["sequence"]) == 0:
                    if bytes(row["history_head"]) != identity["genesis_head"]:
                        _fail(FinancialIntegrityError, "identity_history_head")
                else:
                    first_event = connection.execute(
                        "SELECT previous_head FROM financial_events WHERE event_sequence=1",
                    ).fetchone()
                    if first_event is None or bytes(first_event["previous_head"]) != identity["genesis_head"]:
                        _fail(FinancialIntegrityError, "identity_history_genesis")
        except sqlite3.DatabaseError:
            _fail(FinancialIntegrityError, "schema_read")

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                yield connection
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    @contextmanager
    def _read(self) -> Iterator[sqlite3.Connection]:
        with closing(self._connect()) as connection:
            yield connection

    def _now(self) -> int:
        value = self.clock.now_ms()
        return _time(value, "clock")

    def _scope_period(self, period_id: str) -> None:
        _id(period_id, "period_id")
        if period_id in _WILDCARD_PERIODS or self.config.period_id in _WILDCARD_PERIODS or period_id != self.config.period_id:
            _fail(FinancialIntegrityError, "period_scope")

    def _meta(self, connection: sqlite3.Connection) -> sqlite3.Row:
        row = connection.execute("SELECT * FROM financial_meta WHERE id=1").fetchone()
        if row is None:
            _fail(FinancialIntegrityError, "meta_missing")
        return row

    def _append_event(
        self,
        connection: sqlite3.Connection,
        *,
        aggregate_type: str,
        aggregate_id: str,
        kind: str,
        before_revision: int,
        after_revision: int,
        payload: Mapping[str, Any],
        committed_at_ms: int,
    ) -> bytes:
        _kind(aggregate_type, "aggregate_type")
        _id(aggregate_id, "aggregate_id")
        _kind(kind, "event_kind")
        for value, label in (
            (before_revision, "event_before_revision"),
            (after_revision, "event_after_revision"),
            (committed_at_ms, "event_committed_at"),
        ):
            if type(value) is not int or value < 0 or value >= 2**63:
                _fail(FinancialIntegrityError, label)
        event_payload = dict(payload)
        if aggregate_type == "OBLIGATION" and "evaluation_id" in event_payload:
            evaluation_id = _id(event_payload["evaluation_id"], "event_evaluation_id")
            evaluation = connection.execute(
                "SELECT input_snapshot_digest,result_digest,receipt_digest FROM evaluations WHERE evaluation_id=? AND obligation_id=?",
                (evaluation_id, aggregate_id),
            ).fetchone()
            if evaluation is None:
                _fail(FinancialIntegrityError, "event_evaluation_missing")
            event_payload.update(
                {
                    "evaluation_input_digest": _hex(bytes(evaluation["input_snapshot_digest"])),
                    "evaluation_result_digest": _hex(bytes(evaluation["result_digest"])),
                    "evaluation_receipt_digest": _hex(bytes(evaluation["receipt_digest"])),
                }
            )
        payload_bytes = _canonical(event_payload)
        payload_digest = _digest(_EVENT_DOMAIN, payload_bytes)
        meta = self._meta(connection)
        if int(meta["sequence"]) >= _MAX_ROWS:
            _fail(FinancialIntegrityError, "history_capacity")
        sequence = int(meta["sequence"]) + 1
        previous_head = bytes(meta["history_head"])
        header = b"".join(
            value.to_bytes(8, "big")
            for value in (before_revision, after_revision, committed_at_ms)
        )
        event_id = _digest(
            _EVENT_DOMAIN,
            sequence.to_bytes(8, "big"),
            aggregate_type.encode("ascii"),
            aggregate_id.encode("ascii"),
            kind.encode("ascii"),
            header,
            payload_digest,
        )
        head = _digest(_HEAD_DOMAIN, previous_head, event_id, header, payload_digest)
        connection.execute(
            "INSERT INTO financial_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (sequence, event_id, aggregate_type, aggregate_id, kind, before_revision, after_revision, payload_bytes.decode("ascii"), payload_digest, previous_head, head, committed_at_ms),
        )
        connection.execute("UPDATE financial_meta SET sequence=?,history_head=? WHERE id=1", (sequence, head))
        return event_id

    def _assert_actionable(self) -> None:
        if self.mode == "SHADOW":
            _fail(FinancialDispatchError, "shadow_owner_read_only")

    def _get_obligation_row(self, connection: sqlite3.Connection, item_id: str) -> sqlite3.Row:
        _id(item_id, "item_id")
        row = connection.execute("SELECT * FROM obligations WHERE item_id=? AND period_id=?", (item_id, self.config.period_id)).fetchone()
        if row is None:
            _fail(FinancialIntegrityError, "obligation_missing")
        return row

    def _control_pack_for_obligation(
        self,
        connection: sqlite3.Connection,
        obligation_id: str,
    ) -> tuple[ControlPack, str, str]:
        row = connection.execute(
            """
            SELECT cp.*
            FROM obligations o
            JOIN population_imports pi ON pi.population_id=o.population_id
            JOIN control_packs cp ON cp.pack_id=pi.pack_id
            WHERE o.obligation_id=?
            """,
            (obligation_id,),
        ).fetchone()
        if row is None or str(row["status"]) != "APPROVED":
            _fail(FinancialIntegrityError, "control_pack_missing")
        try:
            source_refs = json.loads(str(row["source_refs_json"]))
            authorized_roles = json.loads(str(row["authorized_roles_json"]))
            expected_tests = json.loads(str(row["expected_tests_json"]))
            if not isinstance(source_refs, dict) or set(source_refs) != {"values"}:
                _fail(FinancialIntegrityError, "control_pack_binding")
            if not isinstance(authorized_roles, dict) or set(authorized_roles) != {"values"}:
                _fail(FinancialIntegrityError, "control_pack_binding")
            if not isinstance(expected_tests, dict) or set(expected_tests) != {"values"}:
                _fail(FinancialIntegrityError, "control_pack_binding")
            pack = ControlPack(
                pack_id=str(row["pack_id"]),
                state_id=str(row["state_id"]),
                deployment_id=str(row["deployment_id"]),
                program_id=str(row["program_id"]),
                period_id=str(row["period_id"]),
                version=int(row["version"]),
                source_refs=tuple(source_refs["values"]),
                effective_start_ms=int(row["effective_start_ms"]),
                effective_end_ms=int(row["effective_end_ms"]),
                recorded_at_ms=int(row["recorded_at_ms"]),
                approved_at_ms=int(row["approved_at_ms"]),
                calculation_rule_id=str(row["calculation_rule_id"]),
                adjustment_rule_id=str(row["adjustment_rule_id"]),
                authorized_roles=tuple(authorized_roles["values"]),
                expected_tests=tuple(expected_tests["values"]),
            )
        except (TypeError, ValueError, json.JSONDecodeError):
            _fail(FinancialIntegrityError, "control_pack_binding")
        if bytes(row["pack_digest"]) != pack.digest:
            _fail(FinancialIntegrityError, "control_pack_digest")
        calculation, adjustment = _control_pack_policy(
            calculation_rule_id=pack.calculation_rule_id,
            adjustment_rule_id=pack.adjustment_rule_id,
            authorized_roles=pack.authorized_roles,
            expected_tests=pack.expected_tests,
        )
        self._scope_pack(pack)
        return pack, calculation, adjustment

    def _insert_evidence(self, connection: sqlite3.Connection, evidence: EvidenceRecord) -> str:
        existing = connection.execute("SELECT record_digest FROM evidence WHERE evidence_id=?", (evidence.evidence_id,)).fetchone()
        if existing is not None:
            if bytes(existing[0]) == evidence.record_digest:
                return "DUPLICATE"
            _fail(FinancialConflictError, "evidence_identity_conflict")
        connection.execute(
            "INSERT INTO evidence VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (evidence.evidence_id, evidence.item_id, evidence.kind, evidence.common_origin_id, evidence.source_id, evidence.source_version, evidence.local_ref, evidence.applicable_at_ms, evidence.event_at_ms, evidence.received_at_ms, evidence.content_digest, evidence.record_digest, evidence.amount_cents, evidence.reversal_of, evidence.supersedes),
        )
        return "INSERTED"

    def _evidence_for(self, connection: sqlite3.Connection, item_id: str) -> tuple[str, ...]:
        return tuple(str(row[0]) for row in connection.execute("SELECT evidence_id FROM evidence WHERE item_id=? ORDER BY evidence_id", (item_id,)))

    def _case_status(self, connection: sqlite3.Connection, obligation_id: str) -> str:
        row = connection.execute("SELECT status FROM cases WHERE obligation_id=? ORDER BY case_id DESC LIMIT 1", (obligation_id,)).fetchone()
        return "OPEN" if row is None else str(row[0])

    def _delivery_status(self, connection: sqlite3.Connection, obligation_id: str) -> str:
        row = connection.execute("SELECT a.status FROM actions a WHERE a.obligation_id=? ORDER BY a.created_at_ms DESC,a.action_id DESC LIMIT 1", (obligation_id,)).fetchone()
        return "NONE" if row is None else str(row[0])

    def _completion_time(self, connection: sqlite3.Connection, obligation_id: str, owed_cents: int, lawful_cents: int) -> int | None:
        entries: list[tuple[int, int]] = [(int(row[0]), int(row[1])) for row in connection.execute("SELECT decided_at_ms,amount_cents FROM determinations WHERE obligation_id=? AND decision='OFFSET_AUTHORIZED' ORDER BY decided_at_ms,determination_id", (obligation_id,))]
        entries.extend((int(row[0]), int(row[1])) for row in connection.execute("SELECT event_at_ms,amount_cents FROM payments WHERE obligation_id=? AND active=1 ORDER BY event_at_ms,payment_id", (obligation_id,)))
        total = 0
        for at_ms, amount in sorted(entries, key=lambda value: (value[0], value[1])):
            total = _add(total, amount)
            if total >= owed_cents:
                return at_ms
        if lawful_cents + _sum_cents(int(row[0]) for row in connection.execute("SELECT amount_cents FROM payments WHERE obligation_id=? AND active=1", (obligation_id,))) >= owed_cents and entries:
            return max(value[0] for value in entries)
        return None

    def _recompute_obligation(self, connection: sqlite3.Connection, obligation_id: str, *, now_ms: int, authority_id: str) -> tuple[int, int, dict[str, Any]]:
        old = connection.execute("SELECT * FROM obligations WHERE obligation_id=?", (obligation_id,)).fetchone()
        if old is None:
            _fail(FinancialIntegrityError, "obligation_missing")
        pack, calculation, adjustment = self._control_pack_for_obligation(connection, obligation_id)
        if int(old["rule_version"]) != pack.version:
            _fail(FinancialIntegrityError, "control_pack_rule_version")
        if calculation != "PER_RECIPIENT":
            _fail(FinancialIntegrityError, "control_pack_calculation")
        cash = _sum_cents(int(row[0]) for row in connection.execute("SELECT amount_cents FROM payments WHERE obligation_id=? AND active=1", (obligation_id,)))
        if adjustment != "AUTHORIZED_OFFSET":
            _fail(FinancialIntegrityError, "control_pack_adjustment")
        claimed = _sum_cents(int(row[0]) for row in connection.execute("SELECT amount_cents FROM claimed_adjustments WHERE obligation_id=? AND status IN ('CLAIMED','AUTHORIZED')", (obligation_id,)))
        lawful = _sum_cents(int(row[0]) for row in connection.execute("SELECT amount_cents FROM claimed_adjustments WHERE obligation_id=? AND status='AUTHORIZED'", (obligation_id,)))
        total = _add(cash, lawful)
        owed = int(old["owed_cents"])
        shortfall = max(owed - total, 0)
        overage = max(total - owed, 0)
        evidence_ids = self._evidence_for(connection, str(old["item_id"]))
        future_evidence = connection.execute(
            "SELECT 1 FROM evidence WHERE item_id=? AND received_at_ms>? LIMIT 1",
            (old["item_id"], now_ms),
        ).fetchone()
        if future_evidence is not None:
            _fail(FinancialIntegrityError, "evaluation_evidence_chronology")
        conflict_count = int(connection.execute("SELECT COUNT(*) FROM financial_conflicts WHERE obligation_id=?", (obligation_id,)).fetchone()[0])
        evidence_count = int(connection.execute("SELECT COUNT(*) FROM evidence WHERE item_id=?", (old["item_id"],)).fetchone()[0])
        verification = "CONFLICT_VISIBLE" if conflict_count else ("SUPPORTED" if evidence_count else "MISSING_EVIDENCE")
        completion = self._completion_time(connection, obligation_id, owed, lawful)
        timely = int(completion is not None and completion <= int(old["due_at_ms"]))
        amount_satisfied = int(total >= owed)
        cash_satisfied = int(cash >= owed)
        reporting_complete = int(old["reporting_complete"])
        delivery = self._delivery_status(connection, obligation_id)
        prior_case = self._case_status(connection, obligation_id)
        if amount_satisfied and reporting_complete:
            case_status = "RESOLVED"
        elif amount_satisfied:
            case_status = "ACTIONED"
        elif prior_case in {"CORRECTION_REQUIRED", "AUTHORIZED"}:
            case_status = prior_case
        else:
            case_status = "OPEN"
        before_revision = int(old["revision"])
        after_revision = before_revision + 1
        evaluation_id = f"evaluation:{obligation_id}:r{after_revision}"
        result = {
            "evaluation_id": evaluation_id,
            "obligation_id": obligation_id,
            "revision": after_revision,
            "rule_version": int(old["rule_version"]),
            "evidence_ids": list(evidence_ids),
            "authority_id": authority_id,
            "evaluated_at_ms": now_ms,
            "owed_cents": owed,
            "claimed_adjustment_cents": claimed,
            "lawful_adjustment_cents": lawful,
            "received_cash_cents": cash,
            "shortfall_cents": shortfall,
            "overage_cents": overage,
            "cash_satisfied": cash_satisfied,
            "amount_satisfied": amount_satisfied,
            "timely": timely,
            "reporting_complete": reporting_complete,
            "verification_status": verification,
            "case_status": case_status,
            "delivery_status": delivery,
        }
        connection.execute("UPDATE cases SET status=?,updated_at_ms=? WHERE obligation_id=?", (case_status, now_ms, obligation_id))
        stored_evaluation = self._insert_evaluation(
            connection,
            result=result,
            pack=pack,
            evidence_bindings=self._evidence_bindings(connection, evidence_ids),
            authority_epoch=self.trusted_authority.epoch,
            authority_digest=self.trusted_authority.digest,
        )
        updated = connection.execute(
            "UPDATE obligations SET revision=?,claimed_adjustment_cents=?,lawful_adjustment_cents=?,received_cash_cents=?,shortfall_cents=?,overage_cents=?,cash_satisfied=?,amount_satisfied=?,timely=?,verification_status=?,case_status=?,delivery_status=?,current_evaluation_id=?,updated_at_ms=? WHERE obligation_id=? AND revision=?",
            (after_revision, claimed, lawful, cash, shortfall, overage, cash_satisfied, amount_satisfied, timely, verification, case_status, delivery, evaluation_id, now_ms, obligation_id, before_revision),
        )
        if updated.rowcount != 1:
            _fail(FinancialRevisionError, "obligation_revision_conflict")
        return before_revision, after_revision, stored_evaluation

    def _scope_pack(self, pack: ControlPack) -> None:
        if type(pack) is not ControlPack:
            _fail(FinancialInputError, "control_pack_type")
        if (pack.state_id, pack.deployment_id, pack.program_id) != (self.config.state_id, self.config.deployment_id, self.config.program_id):
            _fail(FinancialIntegrityError, "control_pack_scope")
        self._scope_period(pack.period_id)

    def publish_control_pack(self, pack: ControlPack) -> dict[str, Any]:
        """Publish one approved, versioned rule pack in the owner database."""
        self._assert_actionable()
        self._scope_pack(pack)
        _control_pack_policy(
            calculation_rule_id=pack.calculation_rule_id,
            adjustment_rule_id=pack.adjustment_rule_id,
            authorized_roles=pack.authorized_roles,
            expected_tests=pack.expected_tests,
        )
        with self._write() as connection:
            existing = connection.execute("SELECT pack_digest FROM control_packs WHERE pack_id=?", (pack.pack_id,)).fetchone()
            if existing is not None:
                if bytes(existing[0]) == pack.digest:
                    return {"status": "DUPLICATE", "pack_id": pack.pack_id, "digest": _hex(pack.digest)}
                _fail(FinancialConflictError, "control_pack_identity_conflict")
            for row in connection.execute("SELECT version,effective_start_ms,effective_end_ms FROM control_packs WHERE program_id=? AND period_id=? AND status='APPROVED'", (pack.program_id, pack.period_id)):
                if int(row[0]) == pack.version or max(pack.effective_start_ms, int(row[1])) < min(pack.effective_end_ms, int(row[2])):
                    _fail(FinancialConflictError, "control_pack_effective_overlap")
            connection.execute(
                "INSERT INTO control_packs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (pack.pack_id, pack.state_id, pack.deployment_id, pack.program_id, pack.period_id, pack.version, _canonical({"values": list(pack.source_refs)}).decode("ascii"), pack.effective_start_ms, pack.effective_end_ms, pack.recorded_at_ms, pack.approved_at_ms, pack.calculation_rule_id, pack.adjustment_rule_id, _canonical({"values": list(pack.authorized_roles)}).decode("ascii"), _canonical({"values": list(pack.expected_tests)}).decode("ascii"), pack.digest, "APPROVED"),
            )
            at_ms = self._now()
            self._append_event(connection, aggregate_type="CONTROL_PACK", aggregate_id=pack.pack_id, kind="CONTROL_PACK_PUBLISHED", before_revision=0, after_revision=1, payload={"pack_id": pack.pack_id, "version": pack.version, "period_id": pack.period_id, "digest": _hex(pack.digest)}, committed_at_ms=at_ms)
            return {"status": "PUBLISHED", "pack_id": pack.pack_id, "version": pack.version, "digest": _hex(pack.digest)}

    def _ensure_population_import(self, connection: sqlite3.Connection, *, population_id: str, pack_id: str, cutoff_ms: int, inclusion_rules: tuple[str, ...], expected_count: int, now_ms: int) -> sqlite3.Row:
        pack = connection.execute("SELECT * FROM control_packs WHERE pack_id=? AND status='APPROVED'", (pack_id,)).fetchone()
        if pack is None:
            _fail(FinancialIntegrityError, "control_pack_missing")
        existing = connection.execute("SELECT * FROM population_imports WHERE population_id=?", (population_id,)).fetchone()
        encoded_rules = _canonical({"values": list(inclusion_rules)}).decode("ascii")
        if existing is not None:
            if (str(existing["pack_id"]), int(existing["cutoff_ms"]), str(existing["inclusion_rules_json"]), int(existing["expected_count"])) != (pack_id, cutoff_ms, encoded_rules, expected_count):
                _fail(FinancialConflictError, "population_import_identity_conflict")
            if str(existing["status"]) == "PUBLISHED":
                _fail(FinancialConflictError, "population_already_published")
            return existing
        connection.execute(
            "INSERT INTO population_imports VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (population_id, pack_id, cutoff_ms, encoded_rules, expected_count, 0, 0, 0, None, "STAGED", now_ms, now_ms),
        )
        return connection.execute("SELECT * FROM population_imports WHERE population_id=?", (population_id,)).fetchone()

    def _stage_population_chunk(self, *, population_id: str, pack_id: str, cutoff_ms: int, inclusion_rules: tuple[str, ...], expected_count: int, chunk: tuple[PopulationItem, ...]) -> None:
        if not chunk:
            return
        with self._write() as connection:
            now_ms = self._now()
            population = self._ensure_population_import(connection, population_id=population_id, pack_id=pack_id, cutoff_ms=cutoff_ms, inclusion_rules=inclusion_rules, expected_count=expected_count, now_ms=now_ms)
            current_count = int(connection.execute("SELECT COUNT(*) FROM population_items WHERE population_id=?", (population_id,)).fetchone()[0])
            seen: dict[str, tuple[str, int, int, str]] = {}
            new_items: list[PopulationItem] = []
            for item in chunk:
                if item.population_id != population_id:
                    _fail(FinancialInputError, "population_item_id")
                expected = (item.display_label, item.owed_cents, item.due_at_ms, item.currency)
                prior = seen.get(item.item_id)
                if prior is not None:
                    if prior != expected:
                        _fail(FinancialConflictError, "population_item_conflict")
                    continue
                seen[item.item_id] = expected
                existing = connection.execute("SELECT display_label,owed_cents,due_at_ms,currency FROM population_items WHERE population_id=? AND item_id=?", (population_id, item.item_id)).fetchone()
                if existing is not None:
                    if tuple(existing) != expected:
                        _fail(FinancialConflictError, "population_item_conflict")
                    continue
                new_items.append(item)
            if new_items and str(population["status"]) != "STAGED":
                _fail(FinancialConflictError, "population_not_staged")
            if current_count + len(new_items) > expected_count:
                _fail(FinancialIntegrityError, "population_count_exceeded")
            if not new_items:
                return
            for item in new_items:
                connection.execute("INSERT INTO population_items VALUES (?,?,?,?,?,?)", (population_id, item.item_id, item.display_label, item.owed_cents, item.due_at_ms, item.currency))
            count = int(connection.execute("SELECT COUNT(*) FROM population_items WHERE population_id=?", (population_id,)).fetchone()[0])
            connection.execute("UPDATE population_imports SET imported_count=?,updated_at_ms=? WHERE population_id=?", (count, now_ms, population_id))
            self._append_event(connection, aggregate_type="POPULATION", aggregate_id=population_id, kind="POPULATION_STAGED", before_revision=current_count, after_revision=count, payload={"population_id": population_id, "imported_count": count, "chunk_count": len(new_items)}, committed_at_ms=now_ms)

    def stage_population(
        self,
        *,
        population_id: str,
        pack_id: str,
        cutoff_ms: int,
        inclusion_rules: tuple[str, ...],
        expected_count: int,
        items: Iterable[PopulationItem],
        chunk_size: int = 256,
    ) -> dict[str, Any]:
        """Stream a population into a staged import; publish is a separate gate."""
        self._assert_actionable()
        _id(population_id, "population_id")
        _id(pack_id, "pack_id")
        _time(cutoff_ms, "population_cutoff")
        if type(inclusion_rules) is not tuple or not inclusion_rules:
            _fail(FinancialInputError, "population_inclusion_rules")
        for rule in inclusion_rules:
            _text(rule, "population_inclusion_rule")
        if type(expected_count) is not int or not 1 <= expected_count <= _MAX_ROWS:
            _fail(FinancialInputError, "population_expected_count")
        if type(chunk_size) is not int or not 1 <= chunk_size <= 1000:
            _fail(FinancialInputError, "population_chunk_size")
        with self._write() as connection:
            self._ensure_population_import(connection, population_id=population_id, pack_id=pack_id, cutoff_ms=cutoff_ms, inclusion_rules=inclusion_rules, expected_count=expected_count, now_ms=self._now())
        iterator = iter(items)
        chunk: list[PopulationItem] = []
        input_limit = min(_MAX_ROWS, expected_count + _MAX_DUPLICATE_INPUTS)
        consumed = 0
        for item in iterator:
            consumed += 1
            if consumed > input_limit:
                _fail(FinancialIntegrityError, "population_input_limit")
            if type(item) is not PopulationItem:
                _fail(FinancialInputError, "population_item_type")
            chunk.append(item)
            if len(chunk) >= chunk_size:
                self._stage_population_chunk(population_id=population_id, pack_id=pack_id, cutoff_ms=cutoff_ms, inclusion_rules=inclusion_rules, expected_count=expected_count, chunk=tuple(chunk))
                chunk.clear()
        if chunk:
            self._stage_population_chunk(population_id=population_id, pack_id=pack_id, cutoff_ms=cutoff_ms, inclusion_rules=inclusion_rules, expected_count=expected_count, chunk=tuple(chunk))
        with self._write() as connection:
            row = connection.execute("SELECT expected_count,imported_count,source_complete FROM population_imports WHERE population_id=?", (population_id,)).fetchone()
            assert row is not None
            if int(row["imported_count"]) == int(row["expected_count"]) and int(row["source_complete"]) == 0:
                now_ms = self._now()
                connection.execute("UPDATE population_imports SET source_complete=1,updated_at_ms=? WHERE population_id=?", (now_ms, population_id))
                self._append_event(
                    connection,
                    aggregate_type="POPULATION",
                    aggregate_id=population_id,
                    kind="POPULATION_SOURCE_COMPLETED",
                    before_revision=0,
                    after_revision=int(row["imported_count"]),
                    payload={"population_id": population_id, "imported_count": int(row["imported_count"]), "expected_count": int(row["expected_count"])},
                    committed_at_ms=now_ms,
                )
        with self._read() as connection:
            row = connection.execute("SELECT imported_count,source_complete,status FROM population_imports WHERE population_id=?", (population_id,)).fetchone()
            assert row is not None
            return {"status": str(row[2]), "population_id": population_id, "imported_count": int(row[0]), "expected_count": expected_count, "source_complete": bool(row[1])}

    def validate_population(self, population_id: str) -> dict[str, Any]:
        self._assert_actionable()
        _id(population_id, "population_id")
        with self._write() as connection:
            row = connection.execute("SELECT * FROM population_imports WHERE population_id=?", (population_id,)).fetchone()
            if row is None:
                _fail(FinancialIntegrityError, "population_missing")
            if int(row["source_complete"]) != 1:
                _fail(FinancialIntegrityError, "population_source_incomplete")
            count = int(connection.execute("SELECT COUNT(*) FROM population_items WHERE population_id=?", (population_id,)).fetchone()[0])
            if count != int(row["imported_count"]) or count != int(row["expected_count"]):
                _fail(FinancialIntegrityError, "population_incomplete")
            material = b"".join(_digest(_EVIDENCE_DOMAIN, _canonical({"item_id": str(item[0]), "display_label": str(item[1]), "owed_cents": int(item[2]), "due_at_ms": int(item[3]), "currency": str(item[4])})) for item in connection.execute("SELECT item_id,display_label,owed_cents,due_at_ms,currency FROM population_items WHERE population_id=? ORDER BY item_id", (population_id,)))
            digest = _digest(_EVIDENCE_DOMAIN, material)
            now_ms = self._now()
            connection.execute("UPDATE population_imports SET imported_count=?,validated_count=?,validation_digest=?,status='VALIDATED',updated_at_ms=? WHERE population_id=?", (count, count, digest, now_ms, population_id))
            self._append_event(connection, aggregate_type="POPULATION", aggregate_id=population_id, kind="POPULATION_VALIDATED", before_revision=0, after_revision=count, payload={"population_id": population_id, "validated_count": count, "validation_digest": _hex(digest)}, committed_at_ms=now_ms)
            return {"status": "VALIDATED", "population_id": population_id, "validated_count": count, "validation_digest": _hex(digest)}

    def _scope_value(self) -> dict[str, str]:
        return {
            "state_id": self.config.state_id,
            "deployment_id": self.config.deployment_id,
            "program_id": self.config.program_id,
            "period_id": self.config.period_id,
            "currency": self.config.currency,
        }

    def _evidence_bindings(self, connection: sqlite3.Connection, evidence_ids: Iterable[str]) -> list[dict[str, str]]:
        ordered = list(evidence_ids)
        if ordered != sorted(ordered) or len(set(ordered)) != len(ordered):
            _fail(FinancialIntegrityError, "evaluation_evidence_order")
        bindings: list[dict[str, str]] = []
        for evidence_id in ordered:
            row = connection.execute("SELECT record_digest FROM evidence WHERE evidence_id=?", (evidence_id,)).fetchone()
            if row is None:
                _fail(FinancialIntegrityError, "evaluation_evidence_missing")
            bindings.append({"evidence_id": evidence_id, "record_digest": _hex(bytes(row[0]))})
        return bindings

    def _evaluation_input_snapshot(
        self,
        connection: sqlite3.Connection,
        *,
        obligation_id: str,
        pre_revision: int,
    ) -> dict[str, Any]:
        obligation = connection.execute(
            "SELECT obligation_id,item_id,revision,rule_version,owed_cents,due_at_ms,reporting_complete FROM obligations WHERE obligation_id=?",
            (obligation_id,),
        ).fetchone()
        if obligation is None:
            _fail(FinancialIntegrityError, "evaluation_input_obligation_missing")
        item_id = str(obligation["item_id"])
        if int(obligation["revision"]) != pre_revision:
            _fail(FinancialRevisionError, "evaluation_input_revision")
        return {
            "pre_revision": pre_revision,
            "obligation": {
                "obligation_id": str(obligation["obligation_id"]),
                "item_id": item_id,
                "revision": int(obligation["revision"]),
                "rule_version": int(obligation["rule_version"]),
                "owed_cents": int(obligation["owed_cents"]),
                "due_at_ms": int(obligation["due_at_ms"]),
                "reporting_complete": int(obligation["reporting_complete"]),
            },
            "evidence": [
                {
                    "evidence_id": str(row["evidence_id"]),
                    "record_digest": _hex(bytes(row["record_digest"])),
                    "event_at_ms": int(row["event_at_ms"]),
                    "received_at_ms": int(row["received_at_ms"]),
                }
                for row in connection.execute(
                    "SELECT evidence_id,record_digest,event_at_ms,received_at_ms FROM evidence WHERE item_id=? ORDER BY evidence_id",
                    (item_id,),
                )
            ],
            "payments": [
                {
                    "payment_id": str(row["payment_id"]),
                    "amount_cents": int(row["amount_cents"]),
                    "event_at_ms": int(row["event_at_ms"]),
                    "active": int(row["active"]),
                }
                for row in connection.execute(
                    "SELECT payment_id,amount_cents,event_at_ms,active FROM payments WHERE obligation_id=? ORDER BY payment_id",
                    (obligation_id,),
                )
            ],
            "claims": [
                {
                    "claim_id": str(row["claim_id"]),
                    "amount_cents": int(row["amount_cents"]),
                    "status": str(row["status"]),
                }
                for row in connection.execute(
                    "SELECT claim_id,amount_cents,status FROM claimed_adjustments WHERE obligation_id=? ORDER BY claim_id",
                    (obligation_id,),
                )
            ],
            "determinations": [
                {
                    "determination_id": str(row["determination_id"]),
                    "decision": str(row["decision"]),
                    "amount_cents": int(row["amount_cents"]),
                    "decided_at_ms": int(row["decided_at_ms"]),
                }
                for row in connection.execute(
                    "SELECT determination_id,decision,amount_cents,decided_at_ms FROM determinations WHERE obligation_id=? ORDER BY determination_id",
                    (obligation_id,),
                )
            ],
            "cases": [
                {"case_id": str(row["case_id"]), "status": str(row["status"])}
                for row in connection.execute(
                    "SELECT case_id,status FROM cases WHERE obligation_id=? ORDER BY case_id",
                    (obligation_id,),
                )
            ],
            "actions": [
                {
                    "action_id": str(row["action_id"]),
                    "status": str(row["status"]),
                    "created_at_ms": int(row["created_at_ms"]),
                }
                for row in connection.execute(
                    "SELECT action_id,status,created_at_ms FROM actions WHERE obligation_id=? ORDER BY action_id",
                    (obligation_id,),
                )
            ],
            "conflicts": [
                str(row["conflict_id"])
                for row in connection.execute(
                    "SELECT conflict_id FROM financial_conflicts WHERE obligation_id=? ORDER BY conflict_id",
                    (obligation_id,),
                )
            ],
        }

    def _insert_evaluation(
        self,
        connection: sqlite3.Connection,
        *,
        result: Mapping[str, Any],
        pack: ControlPack,
        evidence_bindings: list[dict[str, str]],
        authority_epoch: int,
        authority_digest: bytes,
    ) -> dict[str, Any]:
        result_body = _evaluation_result_body(result)
        result_digest = _digest(_EVALUATION_RESULT_DOMAIN, _canonical(result_body))
        stored_result = {**result_body, "result_digest": _hex(result_digest)}
        result_revision = int(result["revision"])
        pre_revision = result_revision if result_revision == 0 else result_revision - 1
        input_snapshot = self._evaluation_input_snapshot(
            connection,
            obligation_id=str(result["obligation_id"]),
            pre_revision=pre_revision,
        )
        input_snapshot_bytes = _canonical(input_snapshot)
        input_snapshot_digest = _digest(_EVALUATION_INPUT_DOMAIN, input_snapshot_bytes)
        receipt_body = _evaluation_receipt_body(
            result=stored_result,
            scope=self._scope_value(),
            control_pack_id=pack.pack_id,
            control_pack_version=pack.version,
            control_pack_digest=pack.digest,
            evidence_bindings=evidence_bindings,
            authority_id=str(result["authority_id"]),
            authority_epoch=authority_epoch,
            authority_digest=authority_digest,
            input_snapshot_digest=input_snapshot_digest,
            result_digest=result_digest,
        )
        receipt_digest = _digest(_EVALUATION_RECEIPT_DOMAIN, _canonical(receipt_body))
        values: dict[str, Any] = {
            **stored_result,
            "evidence_ids_json": _canonical({"evidence_ids": list(result["evidence_ids"])}).decode("ascii"),
            "contract_version": _EVALUATION_RECEIPT_CONTRACT,
            "scope_json": _canonical(self._scope_value()).decode("ascii"),
            "control_pack_id": pack.pack_id,
            "control_pack_version": pack.version,
            "control_pack_digest": pack.digest,
            "authority_epoch": authority_epoch,
            "authority_digest": authority_digest,
            "evidence_bindings_json": _canonical({"bindings": evidence_bindings}).decode("ascii"),
            "input_snapshot_json": input_snapshot_bytes.decode("ascii"),
            "input_snapshot_digest": input_snapshot_digest,
            "receipt_digest": receipt_digest,
        }
        values["result_digest"] = result_digest
        columns = _TABLE_COLUMNS["evaluations"]
        connection.execute(
            f"INSERT INTO evaluations ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})",
            tuple(values[column] for column in columns),
        )
        return {
            **stored_result,
            "receipt_digest": _hex(receipt_digest),
            "evaluation_result_digest": _hex(result_digest),
            "input_snapshot_digest": _hex(input_snapshot_digest),
        }

    def _insert_initial_evaluation(self, connection: sqlite3.Connection, *, obligation_id: str, owed_cents: int, rule_version: int, pack: ControlPack, now_ms: int) -> dict[str, Any]:
        result = {"evaluation_id": f"evaluation:{obligation_id}:r0", "obligation_id": obligation_id, "revision": 0, "rule_version": rule_version, "evidence_ids": [], "authority_id": self.trusted_authority.authority_id, "evaluated_at_ms": now_ms, "owed_cents": owed_cents, "claimed_adjustment_cents": 0, "lawful_adjustment_cents": 0, "received_cash_cents": 0, "shortfall_cents": owed_cents, "overage_cents": 0, "cash_satisfied": 0, "amount_satisfied": 0, "timely": 0, "reporting_complete": 0, "verification_status": "MISSING_EVIDENCE", "case_status": "OPEN", "delivery_status": "NONE"}
        return self._insert_evaluation(
            connection,
            result=result,
            pack=pack,
            evidence_bindings=[],
            authority_epoch=self.trusted_authority.epoch,
            authority_digest=self.trusted_authority.digest,
        )

    @staticmethod
    def _obligation_id(item_id: str, period_id: str) -> str:
        suffix = period_id
        marker = "period-"
        if marker in period_id:
            suffix = marker + period_id.rsplit(marker, 1)[1]
        return f"obligation:{item_id}:{suffix}"

    def _ensure_case(self, connection: sqlite3.Connection, *, obligation_id: str, reason: str, owner: str, due_at_ms: int, status: str, now_ms: int) -> None:
        case_id = f"case:{obligation_id}"
        existing = connection.execute("SELECT case_id FROM cases WHERE case_id=?", (case_id,)).fetchone()
        conditions = _canonical({"amount_satisfied": True, "reporting_complete": True, "delivery_acknowledged_or_not_required": True}).decode("ascii")
        if existing is None:
            connection.execute("INSERT INTO cases VALUES (?,?,?,?,?,?,?, ?,?)", (case_id, obligation_id, reason, "PROGRAM_ACCOUNTABILITY", owner, due_at_ms, conditions, status, now_ms))
        else:
            connection.execute("UPDATE cases SET reason=?,next_action_owner=?,due_at_ms=?,status=?,updated_at_ms=? WHERE case_id=?", (reason, owner, due_at_ms, status, now_ms, case_id))

    def publish_population(self, population_id: str) -> dict[str, Any]:
        """Publish only a fully validated population and create obligations atomically."""
        self._assert_actionable()
        _id(population_id, "population_id")
        with self._write() as connection:
            import_row = connection.execute("SELECT * FROM population_imports WHERE population_id=?", (population_id,)).fetchone()
            if import_row is None or str(import_row["status"]) != "VALIDATED" or int(import_row["source_complete"]) != 1:
                _fail(FinancialIntegrityError, "population_not_validated")
            if connection.execute("SELECT 1 FROM obligations WHERE population_id=? LIMIT 1", (population_id,)).fetchone() is not None:
                _fail(FinancialConflictError, "population_already_published")
            pack = connection.execute("SELECT * FROM control_packs WHERE pack_id=?", (import_row["pack_id"],)).fetchone()
            assert pack is not None
            now_ms = self._now()
            items = connection.execute("SELECT item_id,display_label,owed_cents,due_at_ms,currency FROM population_items WHERE population_id=? ORDER BY item_id", (population_id,)).fetchall()
            initial_evaluation_bindings: list[dict[str, str]] = []
            for item_id, _label, owed_cents, due_at_ms, currency in items:
                obligation_id = self._obligation_id(str(item_id), str(pack["period_id"]))
                connection.execute("INSERT INTO obligations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (obligation_id, population_id, str(item_id), str(pack["period_id"]), str(currency), int(owed_cents), int(due_at_ms), int(pack["version"]), 0, 0, 0, 0, int(owed_cents), 0, 0, 0, 0, 0, "MISSING_EVIDENCE", "OPEN", "NONE", f"evaluation:{obligation_id}:r0", now_ms))
                initial_evaluation = self._insert_initial_evaluation(
                    connection,
                    obligation_id=obligation_id,
                    owed_cents=int(owed_cents),
                    rule_version=int(pack["version"]),
                    pack=ControlPack(
                        pack_id=str(pack["pack_id"]),
                        state_id=str(pack["state_id"]),
                        deployment_id=str(pack["deployment_id"]),
                        program_id=str(pack["program_id"]),
                        period_id=str(pack["period_id"]),
                        version=int(pack["version"]),
                        source_refs=tuple(json.loads(str(pack["source_refs_json"]))["values"]),
                        effective_start_ms=int(pack["effective_start_ms"]),
                        effective_end_ms=int(pack["effective_end_ms"]),
                        recorded_at_ms=int(pack["recorded_at_ms"]),
                        approved_at_ms=int(pack["approved_at_ms"]),
                        calculation_rule_id=str(pack["calculation_rule_id"]),
                        adjustment_rule_id=str(pack["adjustment_rule_id"]),
                        authorized_roles=tuple(json.loads(str(pack["authorized_roles_json"]))["values"]),
                        expected_tests=tuple(json.loads(str(pack["expected_tests_json"]))["values"]),
                    ),
                    now_ms=now_ms,
                )
                initial_evaluation_bindings.append(
                    {
                        "evaluation_id": str(initial_evaluation["evaluation_id"]),
                        "input_snapshot_digest": str(initial_evaluation["input_snapshot_digest"]),
                        "result_digest": str(initial_evaluation["evaluation_result_digest"]),
                        "receipt_digest": str(initial_evaluation["receipt_digest"]),
                    }
                )
                self._ensure_case(connection, obligation_id=obligation_id, reason="INITIAL_ACCOUNTABILITY", owner="CASE_OWNER", due_at_ms=int(due_at_ms), status="OPEN", now_ms=now_ms)
            connection.execute("UPDATE population_imports SET status='PUBLISHED',updated_at_ms=? WHERE population_id=?", (now_ms, population_id))
            self._append_event(
                connection,
                aggregate_type="POPULATION",
                aggregate_id=population_id,
                kind="POPULATION_PUBLISHED",
                before_revision=0,
                after_revision=len(items),
                payload={
                    "population_id": population_id,
                    "item_count": len(items),
                    "pack_id": str(import_row["pack_id"]),
                    "pack_version": int(pack["version"]),
                    "evaluation_count": len(initial_evaluation_bindings),
                    "evaluation_binding_digest": _hex(_evaluation_binding_digest(initial_evaluation_bindings)),
                },
                committed_at_ms=now_ms,
            )
            return {"status": "PUBLISHED", "population_id": population_id, "item_count": len(items), "pack_id": str(import_row["pack_id"]), "pack_version": int(pack["version"])}

    def _new_evidence(
        self,
        *,
        evidence_id: str,
        item_id: str,
        kind: str,
        common_origin_id: str,
        source_id: str,
        source_version: str,
        local_ref: str,
        applicable_at_ms: int,
        event_at_ms: int,
        received_at_ms: int,
        amount_cents: int | None = None,
        reversal_of: str | None = None,
        supersedes: str | None = None,
    ) -> EvidenceRecord:
        content_digest = _digest(_EVIDENCE_DOMAIN, _canonical({"source_id": source_id, "source_version": source_version, "local_ref": local_ref, "common_origin_id": common_origin_id, "kind": kind}))
        return EvidenceRecord(evidence_id, item_id, kind, common_origin_id, source_id, source_version, local_ref, applicable_at_ms, event_at_ms, received_at_ms, content_digest, amount_cents, reversal_of, supersedes)

    def _check_revision(self, row: sqlite3.Row, expected_revision: int | None) -> None:
        if expected_revision is not None and (type(expected_revision) is not int or expected_revision != int(row["revision"])):
            _fail(FinancialRevisionError, "obligation_revision_conflict")

    def _projection_for_row(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "obligation_id": str(row["obligation_id"]),
            "item_id": str(row["item_id"]),
            "population_id": str(row["population_id"]),
            "period_id": str(row["period_id"]),
            "currency": str(row["currency"]),
            "revision": int(row["revision"]),
            "owed_cents": int(row["owed_cents"]),
            "claimed_adjustment_cents": int(row["claimed_adjustment_cents"]),
            "lawful_adjustment_cents": int(row["lawful_adjustment_cents"]),
            "received_cash_cents": int(row["received_cash_cents"]),
            "shortfall_cents": int(row["shortfall_cents"]),
            "overage_cents": int(row["overage_cents"]),
            "cash_satisfied": bool(row["cash_satisfied"]),
            "amount_satisfied": bool(row["amount_satisfied"]),
            "timely": bool(row["timely"]),
            "reporting_complete": bool(row["reporting_complete"]),
            "verification_status": str(row["verification_status"]),
            "case_status": str(row["case_status"]),
            "delivery_status": str(row["delivery_status"]),
            "current_evaluation_id": None if row["current_evaluation_id"] is None else str(row["current_evaluation_id"]),
            "due_at_ms": int(row["due_at_ms"]),
        }

    def _current_projection(self, connection: sqlite3.Connection, obligation_id: str) -> dict[str, Any]:
        row = connection.execute("SELECT * FROM obligations WHERE obligation_id=?", (obligation_id,)).fetchone()
        if row is None:
            _fail(FinancialIntegrityError, "obligation_missing")
        return self._projection_for_row(row)

    def record_support_evidence(
        self,
        *,
        item_id: str,
        evidence_id: str,
        common_origin_id: str,
        source_id: str = "synthetic-source",
        source_version: str = "fixture-v1",
        local_ref: str | None = None,
        applicable_at_ms: int = 1,
        event_at_ms: int = 1,
        received_at_ms: int | None = None,
        expected_revision: int | None = None,
    ) -> dict[str, Any]:
        self._assert_actionable()
        received = self._now() if received_at_ms is None else received_at_ms
        evidence = self._new_evidence(evidence_id=evidence_id, item_id=item_id, kind="SUPPORT", common_origin_id=common_origin_id, source_id=source_id, source_version=source_version, local_ref=local_ref or f"support:{evidence_id}", applicable_at_ms=applicable_at_ms, event_at_ms=event_at_ms, received_at_ms=received)
        with self._write() as connection:
            obligation = self._get_obligation_row(connection, item_id)
            self._check_revision(obligation, expected_revision)
            status = self._insert_evidence(connection, evidence)
            if status == "DUPLICATE":
                return {"status": "DUPLICATE", **self._projection_for_row(obligation)}
            now_ms = self._now()
            before, after, evaluation = self._recompute_obligation(connection, str(obligation["obligation_id"]), now_ms=now_ms, authority_id=self.trusted_authority.authority_id)
            self._append_event(connection, aggregate_type="OBLIGATION", aggregate_id=str(obligation["obligation_id"]), kind="SUPPORT_EVIDENCE_RECORDED", before_revision=before, after_revision=after, payload={"evidence_id": evidence_id, "record_digest": _hex(evidence.record_digest), "evaluation_id": evaluation["evaluation_id"]}, committed_at_ms=now_ms)
            return {"status": "RECORDED", **self._current_projection(connection, str(obligation["obligation_id"]))}

    def record_payment_evidence(
        self,
        *,
        item_id: str,
        payment_id: str,
        common_origin_id: str,
        amount_cents: int,
        evidence_id: str,
        event_at_ms: int,
        source_id: str = "synthetic-payment-source",
        source_version: str = "fixture-v1",
        local_ref: str | None = None,
        expected_revision: int | None = None,
    ) -> dict[str, Any]:
        """Record one payment once by common origin; conflicts never mutate cash."""
        self._assert_actionable()
        _id(payment_id, "payment_id")
        _cents(amount_cents, "payment_amount", nonnegative=True)
        if amount_cents == 0:
            _fail(FinancialInputError, "payment_amount_zero")
        evidence = self._new_evidence(evidence_id=evidence_id, item_id=item_id, kind="PAYMENT_CONFIRMATION", common_origin_id=common_origin_id, source_id=source_id, source_version=source_version, local_ref=local_ref or f"payment:{payment_id}", applicable_at_ms=event_at_ms, event_at_ms=event_at_ms, received_at_ms=self._now(), amount_cents=amount_cents)
        with self._write() as connection:
            obligation = self._get_obligation_row(connection, item_id)
            self._check_revision(obligation, expected_revision)
            evidence_status = self._insert_evidence(connection, evidence)
            existing = connection.execute("SELECT * FROM payments WHERE obligation_id=? AND common_origin_id=?", (obligation["obligation_id"], common_origin_id)).fetchone()
            existing_id = connection.execute("SELECT * FROM payments WHERE payment_id=?", (payment_id,)).fetchone()
            if existing is not None or existing_id is not None:
                candidate_existing = existing if existing is not None else existing_id
                assert candidate_existing is not None
                if int(candidate_existing["amount_cents"]) == amount_cents and str(candidate_existing["common_origin_id"]) == common_origin_id:
                    now_ms = self._now()
                    if evidence_status == "INSERTED":
                        self._append_event(connection, aggregate_type="OBLIGATION", aggregate_id=str(obligation["obligation_id"]), kind="PAYMENT_DUPLICATE_EVIDENCE", before_revision=int(obligation["revision"]), after_revision=int(obligation["revision"]), payload={"candidate_evidence_id": evidence_id, "existing_payment_id": str(candidate_existing["payment_id"]), "common_origin_id": common_origin_id}, committed_at_ms=now_ms)
                    return {"status": "DUPLICATE", "payment_id": str(candidate_existing["payment_id"]), **self._current_projection(connection, str(obligation["obligation_id"]))}
                conflict_id = f"conflict:{item_id}:{common_origin_id}:{evidence_id}"
                if connection.execute("SELECT 1 FROM financial_conflicts WHERE conflict_id=?", (conflict_id,)).fetchone() is None:
                    connection.execute("INSERT INTO financial_conflicts VALUES (?,?,?,?,?,?,?,?,?)", (conflict_id, obligation["obligation_id"], common_origin_id, str(candidate_existing["payment_id"]), evidence_id, int(candidate_existing["amount_cents"]), amount_cents, "CONFLICTING_COMMON_ORIGIN_AMOUNT", self._now()))
                    before, after, evaluation = self._recompute_obligation(connection, str(obligation["obligation_id"]), now_ms=self._now(), authority_id=self.trusted_authority.authority_id)
                    self._append_event(connection, aggregate_type="OBLIGATION", aggregate_id=str(obligation["obligation_id"]), kind="PAYMENT_CONFLICT_VISIBLE", before_revision=before, after_revision=after, payload={"conflict_id": conflict_id, "candidate_evidence_id": evidence_id, "existing_payment_id": str(candidate_existing["payment_id"]), "common_origin_id": common_origin_id, "evaluation_id": evaluation["evaluation_id"]}, committed_at_ms=self._now())
                return {"status": "CONFLICT", "conflict_id": conflict_id, **self._current_projection(connection, str(obligation["obligation_id"]))}
            connection.execute("INSERT INTO payments VALUES (?,?,?,?,?,?,?,?,?)", (payment_id, obligation["obligation_id"], item_id, evidence_id, common_origin_id, amount_cents, event_at_ms, 1, None))
            now_ms = self._now()
            before, after, evaluation = self._recompute_obligation(connection, str(obligation["obligation_id"]), now_ms=now_ms, authority_id=self.trusted_authority.authority_id)
            self._append_event(connection, aggregate_type="OBLIGATION", aggregate_id=str(obligation["obligation_id"]), kind="PAYMENT_RECEIVED", before_revision=before, after_revision=after, payload={"payment_id": payment_id, "evidence_id": evidence_id, "amount_cents": amount_cents, "common_origin_id": common_origin_id, "evaluation_id": evaluation["evaluation_id"]}, committed_at_ms=now_ms)
            return {"status": "RECORDED", "payment_id": payment_id, **self._current_projection(connection, str(obligation["obligation_id"]))}

    receive_payment_evidence = record_payment_evidence

    def reverse_payment(
        self,
        *,
        item_id: str,
        payment_id: str,
        evidence_id: str,
        common_origin_id: str | None = None,
        event_at_ms: int | None = None,
        expected_revision: int | None = None,
    ) -> dict[str, Any]:
        self._assert_actionable()
        _id(payment_id, "payment_id")
        with self._write() as connection:
            obligation = self._get_obligation_row(connection, item_id)
            self._check_revision(obligation, expected_revision)
            payment = connection.execute("SELECT * FROM payments WHERE payment_id=? AND obligation_id=?", (payment_id, obligation["obligation_id"])).fetchone()
            if payment is None:
                _fail(FinancialIntegrityError, "payment_missing")
            reversal_time = self._now() if event_at_ms is None else event_at_ms
            evidence = self._new_evidence(evidence_id=evidence_id, item_id=item_id, kind="PAYMENT_REVERSAL", common_origin_id=common_origin_id or f"reversal:{payment_id}", source_id="synthetic-payment-source", source_version="fixture-v1", local_ref=f"reversal:{payment_id}", applicable_at_ms=reversal_time, event_at_ms=reversal_time, received_at_ms=self._now(), amount_cents=int(payment["amount_cents"]), reversal_of=payment_id)
            status = self._insert_evidence(connection, evidence)
            if status == "DUPLICATE":
                return {"status": "DUPLICATE", **self._projection_for_row(obligation)}
            if int(payment["active"]) == 0:
                return {"status": "DUPLICATE", **self._projection_for_row(obligation)}
            connection.execute("UPDATE payments SET active=0,reversed_by_evidence_id=? WHERE payment_id=? AND active=1", (evidence_id, payment_id))
            now_ms = self._now()
            before, after, evaluation = self._recompute_obligation(connection, str(obligation["obligation_id"]), now_ms=now_ms, authority_id=self.trusted_authority.authority_id)
            self._append_event(connection, aggregate_type="OBLIGATION", aggregate_id=str(obligation["obligation_id"]), kind="PAYMENT_REVERSED", before_revision=before, after_revision=after, payload={"payment_id": payment_id, "evidence_id": evidence_id, "evaluation_id": evaluation["evaluation_id"]}, committed_at_ms=now_ms)
            return {"status": "REVERSED", "payment_id": payment_id, **self._current_projection(connection, str(obligation["obligation_id"]))}

    reverse_payment_evidence = reverse_payment

    def record_offset_claim(
        self,
        *,
        item_id: str,
        claim_id: str,
        amount_cents: int,
        evidence_id: str,
        owner_role: str = "CASE_OWNER",
        deadline_ms: int,
        expected_revision: int | None = None,
    ) -> dict[str, Any]:
        self._assert_actionable()
        _id(claim_id, "claim_id")
        _cents(amount_cents, "offset_amount", nonnegative=True)
        if amount_cents == 0:
            _fail(FinancialInputError, "offset_amount_zero")
        _role(owner_role, "offset_owner_role")
        _time(deadline_ms, "offset_deadline")
        evidence = self._new_evidence(evidence_id=evidence_id, item_id=item_id, kind="OFFSET_CLAIM", common_origin_id=claim_id, source_id="synthetic-offset-source", source_version="fixture-v1", local_ref=f"offset:{claim_id}", applicable_at_ms=self._now(), event_at_ms=self._now(), received_at_ms=self._now(), amount_cents=amount_cents)
        with self._write() as connection:
            obligation = self._get_obligation_row(connection, item_id)
            pack, _calculation, _adjustment = self._control_pack_for_obligation(connection, str(obligation["obligation_id"]))
            if owner_role not in pack.authorized_roles:
                _fail(FinancialAuthorityError, "control_pack_owner_role_not_authorized")
            self._check_revision(obligation, expected_revision)
            existing = connection.execute("SELECT * FROM claimed_adjustments WHERE claim_id=?", (claim_id,)).fetchone()
            if existing is not None:
                if int(existing["amount_cents"]) == amount_cents and str(existing["obligation_id"]) == str(obligation["obligation_id"]):
                    return {"status": "DUPLICATE", "claim_id": claim_id, **self._projection_for_row(obligation)}
                _fail(FinancialConflictError, "offset_claim_identity_conflict")
            evidence_status = self._insert_evidence(connection, evidence)
            if evidence_status == "DUPLICATE":
                _fail(FinancialConflictError, "offset_evidence_reused")
            now_ms = self._now()
            connection.execute("INSERT INTO claimed_adjustments VALUES (?,?,?,?,?,?,?,?,?)", (claim_id, obligation["obligation_id"], evidence_id, amount_cents, owner_role, deadline_ms, "CLAIMED", now_ms, now_ms))
            self._ensure_case(connection, obligation_id=str(obligation["obligation_id"]), reason="UNSUPPORTED_OFFSET", owner=owner_role, due_at_ms=deadline_ms, status="OPEN", now_ms=now_ms)
            before, after, evaluation = self._recompute_obligation(connection, str(obligation["obligation_id"]), now_ms=now_ms, authority_id=self.trusted_authority.authority_id)
            self._append_event(connection, aggregate_type="OBLIGATION", aggregate_id=str(obligation["obligation_id"]), kind="OFFSET_CLAIMED", before_revision=before, after_revision=after, payload={"claim_id": claim_id, "evidence_id": evidence_id, "amount_cents": amount_cents, "evaluation_id": evaluation["evaluation_id"]}, committed_at_ms=now_ms)
            return {"status": "CLAIMED", "claim_id": claim_id, **self._current_projection(connection, str(obligation["obligation_id"]))}

    claim_offset = record_offset_claim

    def _create_action(self, connection: sqlite3.Connection, *, action_id: str, obligation_id: str, determination_id: str, kind: str, revision: int, payload: Mapping[str, Any], now_ms: int) -> str:
        payload_json = _canonical(payload).decode("ascii")
        payload_digest = _digest(_ACTION_DOMAIN, payload_json.encode("ascii"))
        existing = connection.execute("SELECT payload_digest FROM actions WHERE action_id=?", (action_id,)).fetchone()
        if existing is not None:
            if bytes(existing[0]) != payload_digest:
                _fail(FinancialConflictError, "action_payload_immutable")
            return "DUPLICATE"
        idempotency_key = _digest(_IDEMPOTENCY_DOMAIN, action_id.encode("ascii"))
        connection.execute("INSERT INTO actions VALUES (?,?,?,?,?,?,?,?,?,?)", (action_id, obligation_id, determination_id, kind, "READY", revision, payload_json, payload_digest, idempotency_key, now_ms))
        connection.execute("INSERT INTO action_outbox VALUES (?,?,?,?,?,?)", (action_id, "READY", 0, payload_digest, None, now_ms))
        return "CREATED"

    def retry_action(self, action_id: str, payload: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Retry a state-owned action without permitting payload replacement."""
        self._assert_actionable()
        _id(action_id, "action_id")
        if payload is not None and not isinstance(payload, Mapping):
            _fail(FinancialInputError, "action_payload")
        with self._write() as connection:
            action = connection.execute("SELECT * FROM actions WHERE action_id=?", (action_id,)).fetchone()
            if action is None:
                _fail(FinancialIntegrityError, "action_missing")
            stored_payload = json.loads(str(action["payload_json"]))
            if payload is not None and _canonical(dict(payload)) != _canonical(stored_payload):
                _fail(FinancialConflictError, "action_payload_immutable")
            obligation = connection.execute("SELECT * FROM obligations WHERE obligation_id=?", (action["obligation_id"],)).fetchone()
            if obligation is None:
                _fail(FinancialIntegrityError, "obligation_missing")
            return {"status": "DUPLICATE", "action_id": action_id, **self._projection_for_row(obligation)}

    def _authority_action(self, connection: sqlite3.Connection, obligation_id: str, actor_id: str, actor_role: str) -> None:
        self.trusted_authority.require(actor_id, actor_role)
        pack, _calculation, _adjustment = self._control_pack_for_obligation(connection, obligation_id)
        if actor_role not in pack.authorized_roles:
            _fail(FinancialAuthorityError, "control_pack_actor_role_not_authorized")

    def _validate_evaluation_reference(
        self,
        connection: sqlite3.Connection,
        obligation: sqlite3.Row,
        *,
        claim_evidence_id: str,
        evaluation_id: str | None,
        evaluation_result_digest: str | bytes | None,
        expected_revision: int | None,
        decision_time: int,
    ) -> tuple[sqlite3.Row, dict[str, Any], bytes]:
        if evaluation_id is None or evaluation_result_digest is None:
            _fail(FinancialInputError, "evaluation_reference_required")
        if type(expected_revision) is not int:
            _fail(FinancialInputError, "expected_revision_required")
        _id(evaluation_id, "evaluation_id")
        provided_digest = _digest_input(evaluation_result_digest, "evaluation_result_digest")
        if expected_revision != int(obligation["revision"]):
            _fail(FinancialRevisionError, "obligation_revision_conflict")
        if str(obligation["current_evaluation_id"]) != evaluation_id:
            _fail(FinancialRevisionError, "evaluation_revision_conflict")
        row = connection.execute("SELECT * FROM evaluations WHERE evaluation_id=? AND obligation_id=?", (evaluation_id, obligation["obligation_id"])).fetchone()
        if row is None:
            _fail(FinancialIntegrityError, "evaluation_reference_missing")
        if int(row["revision"]) != expected_revision or bytes(row["result_digest"]) != provided_digest:
            _fail(FinancialRevisionError, "evaluation_reference_conflict")
        receipt = self._evaluation_receipt_for_row(connection, row)
        if receipt["result_digest"] != _hex(provided_digest) or int(receipt["revision"]) != expected_revision:
            _fail(FinancialRevisionError, "evaluation_reference_conflict")
        if claim_evidence_id not in receipt["evidence_ids"]:
            _fail(FinancialIntegrityError, "evaluation_evidence_coverage")
        if int(receipt["evaluated_at_ms"]) > decision_time:
            _fail(FinancialIntegrityError, "evaluation_chronology")
        for key in (
            "owed_cents", "claimed_adjustment_cents", "lawful_adjustment_cents", "received_cash_cents",
            "shortfall_cents", "overage_cents", "cash_satisfied", "amount_satisfied", "timely",
            "reporting_complete", "verification_status", "case_status", "delivery_status",
        ):
            if receipt[key] != obligation[key]:
                _fail(FinancialRevisionError, "evaluation_projection_conflict")
        consumed = connection.execute("SELECT determination_id FROM determinations WHERE input_evaluation_id=?", (evaluation_id,)).fetchone()
        if consumed is not None:
            _fail(FinancialConflictError, "evaluation_already_consumed")
        return row, receipt, provided_digest

    def _duplicate_action_or_conflict(
        self,
        connection: sqlite3.Connection,
        *,
        action: sqlite3.Row,
        obligation: sqlite3.Row,
        claim_id: str,
        actor_id: str,
        actor_role: str,
        decision: str,
        kind: str,
        evaluation_id: str | None,
        evaluation_result_digest: str | bytes | None,
        expected_revision: int | None,
        decision_at_ms: int | None,
    ) -> dict[str, Any]:
        determination = connection.execute("SELECT * FROM determinations WHERE determination_id=?", (action["determination_id"],)).fetchone()
        if determination is None:
            _fail(FinancialIntegrityError, "determination_missing")
        if str(action["obligation_id"]) != str(obligation["obligation_id"]) or str(determination["obligation_id"]) != str(obligation["obligation_id"]):
            _fail(FinancialConflictError, "determination_request_conflict")
        if str(action["kind"]) != kind or str(determination["decision"]) != decision or str(determination["claim_id"]) != claim_id:
            _fail(FinancialConflictError, "determination_request_conflict")
        if str(determination["actor_id"]) != actor_id or str(determination["actor_role"]) != actor_role:
            _fail(FinancialConflictError, "determination_request_conflict")
        if evaluation_id is not None and str(determination["input_evaluation_id"]) != evaluation_id:
            _fail(FinancialConflictError, "determination_request_conflict")
        if evaluation_result_digest is not None and bytes(determination["input_evaluation_result_digest"]) != _digest_input(evaluation_result_digest, "evaluation_result_digest"):
            _fail(FinancialConflictError, "determination_request_conflict")
        if expected_revision is not None and type(expected_revision) is not int:
            _fail(FinancialInputError, "expected_revision")
        if expected_revision is not None and int(determination["expected_revision"]) != expected_revision:
            _fail(FinancialConflictError, "determination_request_conflict")
        if decision_at_ms is not None:
            _time(decision_at_ms, "decision_time")
            if int(determination["decided_at_ms"]) != decision_at_ms:
                _fail(FinancialConflictError, "determination_request_conflict")
        if (str(determination["authority_id"]), int(determination["authority_epoch"]), bytes(determination["authority_digest"])) != (self.trusted_authority.authority_id, self.trusted_authority.epoch, self.trusted_authority.digest):
            _fail(FinancialAuthorityError, "determination_authority_stale")
        return {"status": "DUPLICATE", "action_id": str(action["action_id"]), "determination_id": str(action["determination_id"]), **self._projection_for_row(obligation)}

    def authorize_offset(
        self,
        *,
        item_id: str,
        claim_id: str,
        actor_id: str = "synthetic-official",
        actor_role: str = "FINANCE_DECISION",
        expected_revision: int | None = None,
        action_id: str | None = None,
        decision_at_ms: int | None = None,
        evaluation_id: str | None = None,
        evaluation_result_digest: str | bytes | None = None,
    ) -> dict[str, Any]:
        self._assert_actionable()
        action_ref = action_id or f"action:offset:{claim_id}"
        _id(action_ref, "action_id")
        with self._write() as connection:
            obligation = self._get_obligation_row(connection, item_id)
            existing_action = connection.execute("SELECT * FROM actions WHERE action_id=?", (action_ref,)).fetchone()
            if existing_action is not None:
                return self._duplicate_action_or_conflict(
                    connection,
                    action=existing_action,
                    obligation=obligation,
                    claim_id=claim_id,
                    actor_id=actor_id,
                    actor_role=actor_role,
                    decision="OFFSET_AUTHORIZED",
                    kind="OFFSET_AUTHORIZATION",
                    evaluation_id=evaluation_id,
                    evaluation_result_digest=evaluation_result_digest,
                    expected_revision=expected_revision,
                    decision_at_ms=decision_at_ms,
                )
            self._authority_action(connection, str(obligation["obligation_id"]), actor_id, actor_role)
            claim = connection.execute("SELECT * FROM claimed_adjustments WHERE claim_id=? AND obligation_id=?", (claim_id, obligation["obligation_id"])).fetchone()
            if claim is None:
                _fail(FinancialIntegrityError, "offset_claim_missing")
            decision_time = self._now() if decision_at_ms is None else decision_at_ms
            _time(decision_time, "decision_time")
            _evaluation_row, evaluation_receipt, input_result_digest = self._validate_evaluation_reference(
                connection,
                obligation,
                claim_evidence_id=str(claim["evidence_id"]),
                evaluation_id=evaluation_id,
                evaluation_result_digest=evaluation_result_digest,
                expected_revision=expected_revision,
                decision_time=decision_time,
            )
            if str(claim["status"]) != "CLAIMED":
                _fail(FinancialConflictError, "offset_claim_not_claimed")
            mutation_time = max(decision_time, self._now())
            before_revision = int(obligation["revision"])
            resulting_revision = before_revision + 1
            determination_id = f"determination:{action_ref}"
            evidence_bindings = list(evaluation_receipt["evidence_bindings"])
            determination_payload = _determination_digest_payload(
                action_id=action_ref,
                determination_id=determination_id,
                obligation_id=str(obligation["obligation_id"]),
                kind="OFFSET_AUTHORIZATION",
                claim_id=claim_id,
                decision="OFFSET_AUTHORIZED",
                amount_cents=int(claim["amount_cents"]),
                input_evaluation_id=str(evaluation_receipt["evaluation_id"]),
                input_evaluation_result_digest=input_result_digest,
                actor_id=actor_id,
                actor_role=actor_role,
                authority_id=self.trusted_authority.authority_id,
                authority_epoch=self.trusted_authority.epoch,
                authority_digest=self.trusted_authority.digest,
                supporting_evidence=evidence_bindings,
                expected_revision=before_revision,
                resulting_revision=resulting_revision,
                decided_at_ms=decision_time,
            )
            determination_digest = _digest(_ACTION_DOMAIN, _canonical(determination_payload))
            connection.execute(
                "INSERT INTO determinations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    determination_id, obligation["obligation_id"], claim_id, actor_id, actor_role,
                    self.trusted_authority.authority_id, self.trusted_authority.epoch, self.trusted_authority.digest,
                    "OFFSET_AUTHORIZED", int(claim["amount_cents"]),
                    _canonical({"bindings": evidence_bindings}).decode("ascii"), before_revision,
                    resulting_revision, decision_time, determination_digest,
                    str(evaluation_receipt["evaluation_id"]), input_result_digest,
                ),
            )
            connection.execute("UPDATE claimed_adjustments SET status='AUTHORIZED',updated_at_ms=? WHERE claim_id=? AND status='CLAIMED'", (mutation_time, claim_id))
            self._ensure_case(connection, obligation_id=str(obligation["obligation_id"]), reason="OFFSET_AUTHORIZED", owner="CASE_OWNER", due_at_ms=int(claim["deadline_ms"]), status="AUTHORIZED", now_ms=mutation_time)
            action_payload = {"action_id": action_ref, "obligation_id": str(obligation["obligation_id"]), "determination_id": determination_id, "kind": "OFFSET_AUTHORIZATION", "claim_id": claim_id, "amount_cents": int(claim["amount_cents"]), "currency": self.config.currency, "revision": resulting_revision, "input_evaluation_id": str(evaluation_receipt["evaluation_id"]), "input_evaluation_result_digest": _hex(input_result_digest), "dispatch": "SYNTHETIC_RECORD_ONLY"}
            self._create_action(connection, action_id=action_ref, obligation_id=str(obligation["obligation_id"]), determination_id=determination_id, kind="OFFSET_AUTHORIZATION", revision=resulting_revision, payload=action_payload, now_ms=mutation_time)
            before, after, evaluation = self._recompute_obligation(connection, str(obligation["obligation_id"]), now_ms=mutation_time, authority_id=self.trusted_authority.authority_id)
            if (before, after) != (before_revision, resulting_revision):
                _fail(FinancialRevisionError, "determination_revision_binding")
            self._append_event(connection, aggregate_type="OBLIGATION", aggregate_id=str(obligation["obligation_id"]), kind="OFFSET_AUTHORIZED", before_revision=before, after_revision=after, payload={"determination_id": determination_id, "action_id": action_ref, "amount_cents": int(claim["amount_cents"]), "evaluation_id": evaluation["evaluation_id"]}, committed_at_ms=mutation_time)
            return {"status": "AUTHORIZED", "action_id": action_ref, "determination_id": determination_id, **self._current_projection(connection, str(obligation["obligation_id"]))}

    authorize_adjustment = authorize_offset

    def reject_offset_and_authorize_correction(
        self,
        *,
        item_id: str,
        claim_id: str,
        actor_id: str = "synthetic-official",
        actor_role: str = "FINANCE_DECISION",
        expected_revision: int | None = None,
        action_id: str | None = None,
        decision_at_ms: int | None = None,
        evaluation_id: str | None = None,
        evaluation_result_digest: str | bytes | None = None,
    ) -> dict[str, Any]:
        self._assert_actionable()
        action_ref = action_id or f"action:correction:{claim_id}"
        _id(action_ref, "action_id")
        with self._write() as connection:
            obligation = self._get_obligation_row(connection, item_id)
            existing_action = connection.execute("SELECT * FROM actions WHERE action_id=?", (action_ref,)).fetchone()
            if existing_action is not None:
                return self._duplicate_action_or_conflict(
                    connection,
                    action=existing_action,
                    obligation=obligation,
                    claim_id=claim_id,
                    actor_id=actor_id,
                    actor_role=actor_role,
                    decision="OFFSET_REJECTED_CORRECTION_AUTHORIZED",
                    kind="CORRECTION_PAYMENT_REQUEST",
                    evaluation_id=evaluation_id,
                    evaluation_result_digest=evaluation_result_digest,
                    expected_revision=expected_revision,
                    decision_at_ms=decision_at_ms,
                )
            self._authority_action(connection, str(obligation["obligation_id"]), actor_id, actor_role)
            claim = connection.execute("SELECT * FROM claimed_adjustments WHERE claim_id=? AND obligation_id=?", (claim_id, obligation["obligation_id"])).fetchone()
            if claim is None:
                _fail(FinancialIntegrityError, "offset_claim_missing")
            decision_time = self._now() if decision_at_ms is None else decision_at_ms
            _time(decision_time, "decision_time")
            _evaluation_row, evaluation_receipt, input_result_digest = self._validate_evaluation_reference(
                connection,
                obligation,
                claim_evidence_id=str(claim["evidence_id"]),
                evaluation_id=evaluation_id,
                evaluation_result_digest=evaluation_result_digest,
                expected_revision=expected_revision,
                decision_time=decision_time,
            )
            if str(claim["status"]) != "CLAIMED":
                _fail(FinancialConflictError, "offset_claim_not_claimed")
            mutation_time = max(decision_time, self._now())
            before_revision = int(obligation["revision"])
            resulting_revision = before_revision + 1
            determination_id = f"determination:{action_ref}"
            evidence_bindings = list(evaluation_receipt["evidence_bindings"])
            determination_payload = _determination_digest_payload(
                action_id=action_ref,
                determination_id=determination_id,
                obligation_id=str(obligation["obligation_id"]),
                kind="CORRECTION_PAYMENT_REQUEST",
                claim_id=claim_id,
                decision="OFFSET_REJECTED_CORRECTION_AUTHORIZED",
                amount_cents=int(claim["amount_cents"]),
                input_evaluation_id=str(evaluation_receipt["evaluation_id"]),
                input_evaluation_result_digest=input_result_digest,
                actor_id=actor_id,
                actor_role=actor_role,
                authority_id=self.trusted_authority.authority_id,
                authority_epoch=self.trusted_authority.epoch,
                authority_digest=self.trusted_authority.digest,
                supporting_evidence=evidence_bindings,
                expected_revision=before_revision,
                resulting_revision=resulting_revision,
                decided_at_ms=decision_time,
            )
            determination_digest = _digest(_ACTION_DOMAIN, _canonical(determination_payload))
            connection.execute(
                "INSERT INTO determinations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    determination_id, obligation["obligation_id"], claim_id, actor_id, actor_role,
                    self.trusted_authority.authority_id, self.trusted_authority.epoch, self.trusted_authority.digest,
                    "OFFSET_REJECTED_CORRECTION_AUTHORIZED", int(claim["amount_cents"]),
                    _canonical({"bindings": evidence_bindings}).decode("ascii"), before_revision,
                    resulting_revision, decision_time, determination_digest,
                    str(evaluation_receipt["evaluation_id"]), input_result_digest,
                ),
            )
            connection.execute("UPDATE claimed_adjustments SET status='REJECTED',updated_at_ms=? WHERE claim_id=? AND status='CLAIMED'", (mutation_time, claim_id))
            self._ensure_case(connection, obligation_id=str(obligation["obligation_id"]), reason="CORRECTION_REQUIRED", owner="CASE_OWNER", due_at_ms=int(claim["deadline_ms"]), status="CORRECTION_REQUIRED", now_ms=mutation_time)
            action_payload = {"action_id": action_ref, "obligation_id": str(obligation["obligation_id"]), "determination_id": determination_id, "kind": "CORRECTION_PAYMENT_REQUEST", "claim_id": claim_id, "amount_cents": int(claim["amount_cents"]), "currency": self.config.currency, "revision": resulting_revision, "input_evaluation_id": str(evaluation_receipt["evaluation_id"]), "input_evaluation_result_digest": _hex(input_result_digest), "dispatch": "SYNTHETIC_RECORD_ONLY"}
            self._create_action(connection, action_id=action_ref, obligation_id=str(obligation["obligation_id"]), determination_id=determination_id, kind="CORRECTION_PAYMENT_REQUEST", revision=resulting_revision, payload=action_payload, now_ms=mutation_time)
            before, after, evaluation = self._recompute_obligation(connection, str(obligation["obligation_id"]), now_ms=mutation_time, authority_id=self.trusted_authority.authority_id)
            if (before, after) != (before_revision, resulting_revision):
                _fail(FinancialRevisionError, "determination_revision_binding")
            self._append_event(connection, aggregate_type="OBLIGATION", aggregate_id=str(obligation["obligation_id"]), kind="OFFSET_REJECTED_CORRECTION_AUTHORIZED", before_revision=before, after_revision=after, payload={"determination_id": determination_id, "action_id": action_ref, "amount_cents": int(claim["amount_cents"]), "evaluation_id": evaluation["evaluation_id"]}, committed_at_ms=mutation_time)
            return {"status": "CORRECTION_AUTHORIZED", "action_id": action_ref, "determination_id": determination_id, **self._current_projection(connection, str(obligation["obligation_id"]))}

    reject_offset = reject_offset_and_authorize_correction

    def acknowledge_action(
        self,
        action_id: str,
        acknowledgment_ref: str,
        *,
        actor_id: str = "synthetic-receiver",
        actor_role: str = "RECEIVER",
    ) -> dict[str, Any]:
        """Record a local acknowledgment; it never creates cash evidence."""
        self._assert_actionable()
        _id(action_id, "action_id")
        _id(acknowledgment_ref, "acknowledgment_ref")
        with self._write() as connection:
            action = connection.execute("SELECT * FROM actions WHERE action_id=?", (action_id,)).fetchone()
            if action is None:
                _fail(FinancialIntegrityError, "action_missing")
            obligation = connection.execute("SELECT * FROM obligations WHERE obligation_id=?", (action["obligation_id"],)).fetchone()
            if obligation is None:
                _fail(FinancialIntegrityError, "obligation_missing")
            self._authority_action(connection, str(obligation["obligation_id"]), actor_id, actor_role)
            outbox = connection.execute("SELECT * FROM action_outbox WHERE action_id=?", (action_id,)).fetchone()
            assert outbox is not None
            if str(action["status"]) == "ACKNOWLEDGED":
                if str(outbox["acknowledgment_ref"]) == acknowledgment_ref:
                    return {"status": "DUPLICATE", "action_id": action_id, **self._projection_for_row(obligation)}
                _fail(FinancialConflictError, "acknowledgment_conflict")
            if str(action["status"]) != "READY":
                _fail(FinancialConflictError, "action_not_acknowledgeable")
            connection.execute("UPDATE actions SET status='ACKNOWLEDGED' WHERE action_id=? AND status='READY'", (action_id,))
            connection.execute("UPDATE action_outbox SET status='ACKNOWLEDGED',attempt=attempt+1,acknowledgment_ref=?,updated_at_ms=? WHERE action_id=? AND status='READY'", (acknowledgment_ref, self._now(), action_id))
            now_ms = self._now()
            before, after, evaluation = self._recompute_obligation(connection, str(action["obligation_id"]), now_ms=now_ms, authority_id=self.trusted_authority.authority_id)
            self._append_event(connection, aggregate_type="OBLIGATION", aggregate_id=str(action["obligation_id"]), kind="ACTION_ACKNOWLEDGED", before_revision=before, after_revision=after, payload={"action_id": action_id, "acknowledgment_ref": acknowledgment_ref, "evaluation_id": evaluation["evaluation_id"], "cash_mutation": False}, committed_at_ms=now_ms)
            return {"status": "ACKNOWLEDGED", "action_id": action_id, **self._current_projection(connection, str(action["obligation_id"]))}

    acknowledge = acknowledge_action

    def record_reporting_evidence(
        self,
        *,
        item_id: str,
        report_id: str,
        evidence_id: str | None = None,
        actor_id: str = "synthetic-reporter",
        actor_role: str = "REPORTING_EDITOR",
        expected_revision: int | None = None,
        event_at_ms: int | None = None,
    ) -> dict[str, Any]:
        """Record the report that a later reporting correction may supersede."""
        self._assert_actionable()
        _id(report_id, "report_id")
        evidence_ref = evidence_id or f"evidence:report:{report_id}"
        _id(evidence_ref, "evidence_id")
        requested_event_time = None if event_at_ms is None else _time(event_at_ms, "reporting_event")
        received_at_ms = self._now()
        evidence_fields = {
            "evidence_id": evidence_ref,
            "item_id": item_id,
            "kind": "REPORT",
            "common_origin_id": report_id,
            "source_id": "synthetic-report-source",
            "source_version": "fixture-v1",
            "local_ref": f"report:{report_id}",
        }
        with self._write() as connection:
            obligation = self._get_obligation_row(connection, item_id)
            self._authority_action(connection, str(obligation["obligation_id"]), actor_id, actor_role)
            existing = connection.execute("SELECT * FROM evidence WHERE evidence_id=?", (evidence_ref,)).fetchone()
            if existing is not None:
                duplicate_event_time = int(existing["event_at_ms"]) if requested_event_time is None else requested_event_time
                try:
                    duplicate_candidate = self._new_evidence(
                        **evidence_fields,
                        applicable_at_ms=duplicate_event_time,
                        event_at_ms=duplicate_event_time,
                        received_at_ms=int(existing["received_at_ms"]),
                    )
                except FinancialError:
                    _fail(FinancialConflictError, "evidence_identity_conflict")
                if duplicate_candidate.record_digest != bytes(existing["record_digest"]):
                    _fail(FinancialConflictError, "evidence_identity_conflict")
                return {"status": "DUPLICATE", "report_id": report_id, **self._projection_for_row(obligation)}
            self._check_revision(obligation, expected_revision)
            event_time = received_at_ms if requested_event_time is None else requested_event_time
            evidence = self._new_evidence(
                **evidence_fields,
                applicable_at_ms=event_time,
                event_at_ms=event_time,
                received_at_ms=received_at_ms,
            )
            status = self._insert_evidence(connection, evidence)
            assert status == "INSERTED"
            connection.execute("UPDATE obligations SET reporting_complete=1 WHERE obligation_id=?", (obligation["obligation_id"],))
            now_ms = self._now()
            before, after, evaluation = self._recompute_obligation(connection, str(obligation["obligation_id"]), now_ms=now_ms, authority_id=self.trusted_authority.authority_id)
            self._append_event(connection, aggregate_type="OBLIGATION", aggregate_id=str(obligation["obligation_id"]), kind="REPORTING_EVIDENCE_RECORDED", before_revision=before, after_revision=after, payload={"report_id": report_id, "evidence_id": evidence.evidence_id, "evaluation_id": evaluation["evaluation_id"], "cash_mutation": False}, committed_at_ms=now_ms)
            return {"status": "RECORDED", "report_id": report_id, **self._current_projection(connection, str(obligation["obligation_id"]))}

    def record_reporting_correction(
        self,
        *,
        item_id: str,
        report_id: str,
        evidence_id: str | None = None,
        actor_id: str = "synthetic-reporter",
        actor_role: str = "REPORTING_EDITOR",
        expected_revision: int | None = None,
        event_at_ms: int | None = None,
        supersedes: str | None = None,
    ) -> dict[str, Any]:
        self._assert_actionable()
        _id(report_id, "report_id")
        evidence_ref = evidence_id or f"evidence:report:{report_id}"
        _id(evidence_ref, "evidence_id")
        if supersedes is None:
            _fail(FinancialIntegrityError, "report_supersedes_required")
        _id(supersedes, "supersedes")
        requested_event_time = None if event_at_ms is None else _time(event_at_ms, "reporting_event")
        received_at_ms = self._now()
        evidence_fields = {
            "evidence_id": evidence_ref,
            "item_id": item_id,
            "kind": "REPORT_CORRECTION",
            "common_origin_id": report_id,
            "source_id": "synthetic-report-source",
            "source_version": "fixture-v1",
            "local_ref": f"report:{report_id}",
            "supersedes": supersedes,
        }
        with self._write() as connection:
            obligation = self._get_obligation_row(connection, item_id)
            self._authority_action(connection, str(obligation["obligation_id"]), actor_id, actor_role)
            existing = connection.execute("SELECT * FROM evidence WHERE evidence_id=?", (evidence_ref,)).fetchone()
            if existing is not None:
                duplicate_event_time = int(existing["event_at_ms"]) if requested_event_time is None else requested_event_time
                try:
                    duplicate_candidate = self._new_evidence(
                        **evidence_fields,
                        applicable_at_ms=duplicate_event_time,
                        event_at_ms=duplicate_event_time,
                        received_at_ms=int(existing["received_at_ms"]),
                    )
                except FinancialError:
                    _fail(FinancialConflictError, "evidence_identity_conflict")
                if duplicate_candidate.record_digest != bytes(existing["record_digest"]):
                    _fail(FinancialConflictError, "evidence_identity_conflict")
                return {"status": "DUPLICATE", "report_id": report_id, **self._projection_for_row(obligation)}
            self._check_revision(obligation, expected_revision)
            event_time = received_at_ms if requested_event_time is None else requested_event_time
            evidence = self._new_evidence(
                **evidence_fields,
                applicable_at_ms=event_time,
                event_at_ms=event_time,
                received_at_ms=received_at_ms,
            )
            prior = connection.execute("SELECT * FROM evidence WHERE evidence_id=?", (supersedes,)).fetchone()
            if prior is None:
                _fail(FinancialIntegrityError, "report_supersedes_missing")
            if str(prior["item_id"]) != item_id:
                _fail(FinancialIntegrityError, "report_supersedes_item")
            if str(prior["kind"]) not in {"REPORT", "REPORT_CORRECTION"}:
                _fail(FinancialIntegrityError, "report_supersedes_kind")
            if int(prior["event_at_ms"]) >= event_time:
                _fail(FinancialIntegrityError, "report_supersedes_chronology")
            if connection.execute("SELECT 1 FROM evidence WHERE supersedes=? LIMIT 1", (supersedes,)).fetchone() is not None:
                _fail(FinancialConflictError, "report_supersedes_already_superseded")
            self._insert_evidence(connection, evidence)
            connection.execute("UPDATE obligations SET reporting_complete=1 WHERE obligation_id=?", (obligation["obligation_id"],))
            now_ms = self._now()
            before, after, evaluation = self._recompute_obligation(connection, str(obligation["obligation_id"]), now_ms=now_ms, authority_id=self.trusted_authority.authority_id)
            self._append_event(connection, aggregate_type="OBLIGATION", aggregate_id=str(obligation["obligation_id"]), kind="REPORTING_CORRECTION_RECORDED", before_revision=before, after_revision=after, payload={"report_id": report_id, "evidence_id": evidence.evidence_id, "evaluation_id": evaluation["evaluation_id"], "cash_mutation": False}, committed_at_ms=now_ms)
            return {"status": "RECORDED", "report_id": report_id, **self._current_projection(connection, str(obligation["obligation_id"]))}

    correct_reporting = record_reporting_correction

    def evaluate_obligation(self, item_id: str, *, expected_revision: int | None = None) -> dict[str, Any]:
        self._assert_actionable()
        with self._write() as connection:
            obligation = self._get_obligation_row(connection, item_id)
            self._check_revision(obligation, expected_revision)
            now_ms = self._now()
            before, after, evaluation = self._recompute_obligation(connection, str(obligation["obligation_id"]), now_ms=now_ms, authority_id=self.trusted_authority.authority_id)
            self._append_event(connection, aggregate_type="OBLIGATION", aggregate_id=str(obligation["obligation_id"]), kind="EVALUATION_RECORDED", before_revision=before, after_revision=after, payload={"evaluation_id": evaluation["evaluation_id"], "evidence_ids": evaluation["evidence_ids"]}, committed_at_ms=now_ms)
            return {"status": "EVALUATED", "evaluation_receipt": self._evaluation_receipt_for_row(connection, connection.execute("SELECT * FROM evaluations WHERE evaluation_id=?", (evaluation["evaluation_id"],)).fetchone()), **self._current_projection(connection, str(obligation["obligation_id"]))}

    evaluate = evaluate_obligation

    def _evaluation_receipt_for_row(self, connection: sqlite3.Connection, row: sqlite3.Row | None) -> dict[str, Any]:
        if row is None:
            _fail(FinancialIntegrityError, "evaluation_missing")
        try:
            evidence_ids_value = json.loads(str(row["evidence_ids_json"]))
            bindings_value = json.loads(str(row["evidence_bindings_json"]))
            scope = json.loads(str(row["scope_json"]))
            input_snapshot = json.loads(str(row["input_snapshot_json"]))
        except (TypeError, ValueError, json.JSONDecodeError):
            _fail(FinancialIntegrityError, "evaluation_reference_malformed")
        if not isinstance(evidence_ids_value, dict) or set(evidence_ids_value) != {"evidence_ids"} or not isinstance(evidence_ids_value["evidence_ids"], list):
            _fail(FinancialIntegrityError, "evaluation_evidence_binding")
        evidence_ids = evidence_ids_value["evidence_ids"]
        if any(type(value) is not str for value in evidence_ids) or evidence_ids != sorted(evidence_ids) or len(set(evidence_ids)) != len(evidence_ids):
            _fail(FinancialIntegrityError, "evaluation_evidence_binding")
        if not isinstance(bindings_value, dict) or set(bindings_value) != {"bindings"} or not isinstance(bindings_value["bindings"], list):
            _fail(FinancialIntegrityError, "evaluation_evidence_binding")
        bindings = bindings_value["bindings"]
        if any(type(value) is not dict or set(value) != {"evidence_id", "record_digest"} for value in bindings):
            _fail(FinancialIntegrityError, "evaluation_evidence_binding")
        if [value["evidence_id"] for value in bindings] != evidence_ids:
            _fail(FinancialIntegrityError, "evaluation_evidence_binding")
        for binding in bindings:
            if type(binding["evidence_id"]) is not str or type(binding["record_digest"]) is not str:
                _fail(FinancialIntegrityError, "evaluation_evidence_binding")
            record = connection.execute("SELECT record_digest FROM evidence WHERE evidence_id=?", (binding["evidence_id"],)).fetchone()
            if record is None or _hex(bytes(record[0])) != binding["record_digest"]:
                _fail(FinancialIntegrityError, "evaluation_evidence_binding")
            _digest_input(binding["record_digest"], "evaluation_evidence_binding")
        if not isinstance(scope, dict) or set(scope) != set(self._scope_value()) or scope != self._scope_value():
            _fail(FinancialIntegrityError, "evaluation_scope_binding")
        if not isinstance(input_snapshot, dict) or type(input_snapshot.get("pre_revision")) is not int:
            _fail(FinancialIntegrityError, "evaluation_input_snapshot")
        expected_pre_revision = int(row["revision"]) if int(row["revision"]) == 0 else int(row["revision"]) - 1
        if input_snapshot["pre_revision"] != expected_pre_revision:
            _fail(FinancialIntegrityError, "evaluation_input_revision")
        input_snapshot_digest = bytes(row["input_snapshot_digest"])
        if input_snapshot_digest != _digest(_EVALUATION_INPUT_DOMAIN, _canonical(input_snapshot)):
            _fail(FinancialIntegrityError, "evaluation_input_digest")
        obligation = connection.execute("SELECT * FROM obligations WHERE obligation_id=?", (row["obligation_id"],)).fetchone()
        if obligation is None:
            _fail(FinancialIntegrityError, "evaluation_obligation_missing")
        pack, _calculation, _adjustment = self._control_pack_for_obligation(connection, str(obligation["obligation_id"]))
        if str(row["control_pack_id"]) != pack.pack_id or int(row["control_pack_version"]) != pack.version or bytes(row["control_pack_digest"]) != pack.digest:
            _fail(FinancialIntegrityError, "evaluation_control_pack_binding")
        authority_digest = bytes(row["authority_digest"])
        if (str(row["authority_id"]), int(row["authority_epoch"]), authority_digest) != (self.trusted_authority.authority_id, self.trusted_authority.epoch, self.trusted_authority.digest):
            _fail(FinancialAuthorityError, "evaluation_authority_stale")
        result = {
            "evaluation_id": str(row["evaluation_id"]),
            "obligation_id": str(row["obligation_id"]),
            "revision": int(row["revision"]),
            "rule_version": int(row["rule_version"]),
            "evidence_ids": evidence_ids,
            "authority_id": str(row["authority_id"]),
            "evaluated_at_ms": int(row["evaluated_at_ms"]),
            "owed_cents": int(row["owed_cents"]),
            "claimed_adjustment_cents": int(row["claimed_adjustment_cents"]),
            "lawful_adjustment_cents": int(row["lawful_adjustment_cents"]),
            "received_cash_cents": int(row["received_cash_cents"]),
            "shortfall_cents": int(row["shortfall_cents"]),
            "overage_cents": int(row["overage_cents"]),
            "cash_satisfied": int(row["cash_satisfied"]),
            "amount_satisfied": int(row["amount_satisfied"]),
            "timely": int(row["timely"]),
            "reporting_complete": int(row["reporting_complete"]),
            "verification_status": str(row["verification_status"]),
            "case_status": str(row["case_status"]),
            "delivery_status": str(row["delivery_status"]),
        }
        result_digest = bytes(row["result_digest"])
        if result_digest != _digest(_EVALUATION_RESULT_DOMAIN, _canonical(_evaluation_result_body(result))):
            _fail(FinancialIntegrityError, "evaluation_result_digest")
        receipt_body = _evaluation_receipt_body(
            result={**result, "result_digest": _hex(result_digest)},
            scope=scope,
            control_pack_id=pack.pack_id,
            control_pack_version=pack.version,
            control_pack_digest=pack.digest,
            evidence_bindings=bindings,
            authority_id=str(row["authority_id"]),
            authority_epoch=int(row["authority_epoch"]),
            authority_digest=authority_digest,
            input_snapshot_digest=input_snapshot_digest,
            result_digest=result_digest,
        )
        receipt_digest = _digest(_EVALUATION_RECEIPT_DOMAIN, _canonical(receipt_body))
        if bytes(row["receipt_digest"]) != receipt_digest or str(row["contract_version"]) != _EVALUATION_RECEIPT_CONTRACT:
            _fail(FinancialIntegrityError, "evaluation_receipt_digest")
        return {**receipt_body, "receipt_digest": _hex(receipt_digest), "evaluation_result_digest": _hex(result_digest)}

    def current_evaluation_receipt(self, item_id: str) -> dict[str, Any]:
        """Read the current persisted evaluation reference without advancing state."""

        with self._read() as connection:
            obligation = self._get_obligation_row(connection, item_id)
            evaluation_id = obligation["current_evaluation_id"]
            if evaluation_id is None:
                _fail(FinancialIntegrityError, "evaluation_missing")
            row = connection.execute("SELECT * FROM evaluations WHERE evaluation_id=? AND obligation_id=?", (evaluation_id, obligation["obligation_id"])).fetchone()
            receipt = self._evaluation_receipt_for_row(connection, row)
            if int(receipt["revision"]) != int(obligation["revision"]):
                _fail(FinancialRevisionError, "evaluation_revision_binding")
            return receipt

    def _dict_rows(self, connection: sqlite3.Connection, query: str, args: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        return [dict(row) for row in connection.execute(query, args).fetchall()]

    def summary(self) -> dict[str, Any]:
        with self._read() as connection:
            meta = self._meta(connection)
            totals = connection.execute("SELECT COUNT(*),COALESCE(SUM(owed_cents),0),COALESCE(SUM(received_cash_cents),0),COALESCE(SUM(lawful_adjustment_cents),0),COALESCE(SUM(shortfall_cents),0) FROM obligations").fetchone()
            return {
                "schema": _SCHEMA,
                "state_id": str(meta["state_id"]),
                "deployment_id": str(meta["deployment_id"]),
                "program_id": str(meta["program_id"]),
                "period_id": str(meta["period_id"]),
                "currency": str(meta["currency"]),
                "sequence": int(meta["sequence"]),
                "population_count": int(connection.execute("SELECT COUNT(*) FROM population_imports WHERE status='PUBLISHED'").fetchone()[0]),
                "obligation_count": int(totals[0]),
                "owed_cents": int(totals[1]),
                "received_cash_cents": int(totals[2]),
                "lawful_adjustment_cents": int(totals[3]),
                "shortfall_cents": int(totals[4]),
                "open_count": int(connection.execute("SELECT COUNT(*) FROM obligations WHERE amount_satisfied=0").fetchone()[0]),
                "cash_satisfied_count": int(connection.execute("SELECT COUNT(*) FROM obligations WHERE cash_satisfied=1").fetchone()[0]),
                "amount_satisfied_count": int(connection.execute("SELECT COUNT(*) FROM obligations WHERE amount_satisfied=1").fetchone()[0]),
                "dispatch_enabled": False,
                "egress_enabled": False,
                "production_usable": False,
                "activation": False,
                "proof_suite_id": None,
            }

    def list_obligations(self, *, status: str = "OPEN", limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        if status not in {"OPEN", "ALL", "SATISFIED", "CASH_UNSATISFIED"}:
            _fail(FinancialInputError, "obligation_status")
        if type(limit) is not int or not 1 <= limit <= 100 or type(offset) is not int or not 0 <= offset <= _MAX_ROWS:
            _fail(FinancialInputError, "obligation_page")
        with self._read() as connection:
            clause = "1=1" if status == "ALL" else ("amount_satisfied=0" if status == "OPEN" else ("amount_satisfied=1" if status == "SATISFIED" else "cash_satisfied=0"))
            return [self._projection_for_row(row) for row in connection.execute(f"SELECT * FROM obligations WHERE {clause} ORDER BY obligation_id LIMIT ? OFFSET ?", (limit, offset)).fetchall()]

    def obligation_detail(self, item_id: str, *, limit: int = 100) -> dict[str, Any]:
        if type(limit) is not int or not 1 <= limit <= 200:
            _fail(FinancialInputError, "detail_limit")
        with self._read() as connection:
            obligation = self._get_obligation_row(connection, item_id)
            obligation_id = str(obligation["obligation_id"])
            result = self._projection_for_row(obligation)
            result["evidence"] = self._dict_rows(connection, "SELECT evidence_id,kind,common_origin_id,source_id,source_version,local_ref,applicable_at_ms,event_at_ms,received_at_ms,amount_cents,reversal_of,supersedes,record_digest FROM evidence WHERE item_id=? ORDER BY evidence_id LIMIT ?", (item_id, limit))
            result["payments"] = self._dict_rows(connection, "SELECT payment_id,evidence_id,common_origin_id,amount_cents,event_at_ms,active,reversed_by_evidence_id FROM payments WHERE obligation_id=? ORDER BY payment_id LIMIT ?", (obligation_id, limit))
            result["cases"] = self._dict_rows(connection, "SELECT case_id,reason,contractual_accountability,next_action_owner,due_at_ms,completion_conditions_json,status,updated_at_ms FROM cases WHERE obligation_id=? ORDER BY case_id LIMIT ?", (obligation_id, limit))
            result["determinations"] = self._dict_rows(connection, "SELECT determination_id,claim_id,actor_id,actor_role,authority_id,authority_epoch,authority_digest,decision,amount_cents,supporting_evidence_json,expected_revision,resulting_revision,decided_at_ms,determination_digest,input_evaluation_id,input_evaluation_result_digest FROM determinations WHERE obligation_id=? ORDER BY determination_id LIMIT ?", (obligation_id, limit))
            result["actions"] = self._dict_rows(connection, "SELECT action_id,determination_id,kind,status,revision,payload_digest,idempotency_key,created_at_ms FROM actions WHERE obligation_id=? ORDER BY action_id LIMIT ?", (obligation_id, limit))
            result["conflicts"] = self._dict_rows(connection, "SELECT conflict_id,common_origin_id,existing_payment_id,candidate_evidence_id,existing_amount_cents,candidate_amount_cents,reason,visible_at_ms FROM financial_conflicts WHERE obligation_id=? ORDER BY conflict_id LIMIT ?", (obligation_id, limit))
            result["evaluations"] = self._dict_rows(connection, "SELECT evaluation_id,revision,rule_version,evidence_ids_json,authority_id,authority_epoch,authority_digest,evaluated_at_ms,owed_cents,claimed_adjustment_cents,lawful_adjustment_cents,received_cash_cents,shortfall_cents,overage_cents,cash_satisfied,amount_satisfied,timely,reporting_complete,verification_status,case_status,delivery_status,result_digest,contract_version,scope_json,control_pack_id,control_pack_version,control_pack_digest,evidence_bindings_json,input_snapshot_json,input_snapshot_digest,receipt_digest FROM evaluations WHERE obligation_id=? ORDER BY revision LIMIT ?", (obligation_id, limit))
            return result

    def history(self, *, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        if type(limit) is not int or not 1 <= limit <= 200 or type(offset) is not int or not 0 <= offset <= _MAX_ROWS:
            _fail(FinancialInputError, "history_page")
        with self._read() as connection:
            return self._dict_rows(connection, "SELECT event_sequence,event_id,aggregate_type,aggregate_id,kind,before_revision,after_revision,payload_json,payload_digest,previous_head,head,committed_at_ms FROM financial_events ORDER BY event_sequence LIMIT ? OFFSET ?", (limit, offset))

    def action_payload(self, action_id: str) -> dict[str, Any]:
        _id(action_id, "action_id")
        with self._read() as connection:
            row = connection.execute("SELECT payload_json,payload_digest FROM actions WHERE action_id=?", (action_id,)).fetchone()
            if row is None:
                _fail(FinancialIntegrityError, "action_missing")
            return {"action_id": action_id, "payload": json.loads(str(row[0])), "payload_digest": _hex(bytes(row[1]))}

    def read_model(self) -> dict[str, Any]:
        return {"summary": self.summary(), "open": self.list_obligations(status="OPEN", limit=100), "dispatch_enabled": False}

    @staticmethod
    def _export_value(value: Any) -> Any:
        if type(value) is bytes:
            return {"hex": _hex(value)}
        if value is None or type(value) in {str, int, float, bool}:
            return value
        _fail(FinancialContinuityError, "continuity_value")

    @staticmethod
    def _import_value(value: Any) -> Any:
        if type(value) is dict and set(value) == {"hex"} and type(value["hex"]) is str:
            try:
                raw = bytes.fromhex(value["hex"])
            except ValueError:
                _fail(FinancialContinuityError, "continuity_hex")
            return raw
        if value is None or type(value) in {str, int, float, bool}:
            return value
        _fail(FinancialContinuityError, "continuity_value")

    @classmethod
    def validate_continuity_package(cls, package_bytes: bytes) -> dict[str, Any]:
        if type(package_bytes) is not bytes or not package_bytes or len(package_bytes) > _MAX_PACKAGE_BYTES:
            _fail(FinancialContinuityError, "continuity_package_size")
        try:
            package = json.loads(package_bytes.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            _fail(FinancialContinuityError, "continuity_package_json")
        if type(package) is not dict or _canonical(package) != package_bytes:
            _fail(FinancialContinuityError, "continuity_package_canonical")
        required = {
            "schema", "version", "scope", "authority", "continuity_epoch", "sequence",
            "history_head", "dispatch_enabled", "egress_enabled", "mode", "tables",
            "package_digest",
        }
        if set(package) != required:
            _fail(FinancialContinuityError, "continuity_package_shape")
        if package["schema"] != _CONTINUITY_SCHEMA or package["version"] != 5:
            _fail(FinancialContinuityError, "continuity_package_schema")
        scope = package["scope"]
        if type(scope) is not dict or set(scope) != {"state_id", "deployment_id", "program_id", "period_id", "currency"}:
            _fail(FinancialContinuityError, "continuity_package_scope")
        for key in ("state_id", "deployment_id", "program_id", "period_id"):
            _id(scope[key], f"continuity_scope_{key}")
        if scope["currency"] != _CURRENCY:
            _fail(FinancialContinuityError, "continuity_scope_currency")
        authority = package["authority"]
        if type(authority) is not dict or set(authority) != {"authority_id", "epoch", "digest"}:
            _fail(FinancialContinuityError, "continuity_package_authority")
        _id(authority["authority_id"], "continuity_authority_id")
        if type(authority["epoch"]) is not int or authority["epoch"] < 1:
            _fail(FinancialContinuityError, "continuity_authority_epoch")
        try:
            authority_digest = bytes.fromhex(str(authority["digest"]))
        except (TypeError, ValueError):
            _fail(FinancialContinuityError, "continuity_authority_digest")
        if type(authority["digest"]) is not str or len(authority_digest) != 64:
            _fail(FinancialContinuityError, "continuity_authority_digest")
        if type(package["continuity_epoch"]) is not int or package["continuity_epoch"] < 1:
            _fail(FinancialContinuityError, "continuity_package_epoch")
        if type(package["sequence"]) is not int or not 0 <= package["sequence"] <= _MAX_ROWS:
            _fail(FinancialContinuityError, "continuity_package_sequence")
        for field in ("history_head", "package_digest"):
            value = package[field]
            if type(value) is not str or re.fullmatch(r"[0-9A-Fa-f]{128}", value) is None:
                _fail(FinancialContinuityError, f"continuity_{field}")
            try:
                if len(bytes.fromhex(value)) != 64:
                    _fail(FinancialContinuityError, f"continuity_{field}")
            except ValueError:
                _fail(FinancialContinuityError, f"continuity_{field}")
        if package["dispatch_enabled"] is not False or package["egress_enabled"] is not False or package["mode"] not in _MODES:
            _fail(FinancialContinuityError, "continuity_package_binding")
        tables = package["tables"]
        if type(tables) is not dict or set(tables) != _TABLES:
            _fail(FinancialContinuityError, "continuity_package_tables")
        for table in sorted(_TABLES):
            rows = tables[table]
            if type(rows) is not list or len(rows) > _MAX_ROWS:
                _fail(FinancialContinuityError, "continuity_package_rows")
            expected_columns = set(_TABLE_COLUMNS[table])
            for row in rows:
                if type(row) is not dict or set(row) != expected_columns:
                    _fail(FinancialContinuityError, "continuity_package_row")
                for value in row.values():
                    cls._import_value(value)
        identity_rows = tables["financial_identity"]
        if len(identity_rows) != 1:
            _fail(FinancialContinuityError, "continuity_identity_cardinality")
        identity_raw = {column: cls._import_value(identity_rows[0][column]) for column in _TABLE_COLUMNS["financial_identity"]}
        identity = _identity_record(identity_raw, error_type=FinancialContinuityError, code_prefix="continuity_identity")
        if identity["id"] != 1:
            _fail(FinancialContinuityError, "continuity_identity_id")
        meta_rows = tables["financial_meta"]
        if len(meta_rows) != 1:
            _fail(FinancialContinuityError, "continuity_meta_rows")
        meta_row = {column: cls._import_value(meta_rows[0][column]) for column in _TABLE_COLUMNS["financial_meta"]}
        expected_meta = {
            "schema_version": _SCHEMA_VERSION,
            "schema": _SCHEMA,
            "state_id": scope["state_id"],
            "deployment_id": scope["deployment_id"],
            "program_id": scope["program_id"],
            "period_id": scope["period_id"],
            "currency": scope["currency"],
            "sequence": package["sequence"],
            "history_head": bytes.fromhex(str(package["history_head"])),
            "continuity_epoch": package["continuity_epoch"],
            "dispatch_enabled": 0,
            "egress_enabled": 0,
            "trusted_authority_id": authority["authority_id"],
            "trusted_authority_epoch": authority["epoch"],
            "trusted_authority_digest": authority_digest,
            "mode": package["mode"],
        }
        for key, expected_value in expected_meta.items():
            if meta_row.get(key) != expected_value:
                _fail(FinancialContinuityError, "continuity_meta_binding")
        if identity["bound_mode"] != package["mode"] or identity["bound_mode"] != meta_row["mode"] or identity["bound_owner_id"] != meta_row["owner_id"]:
            _fail(FinancialContinuityError, "continuity_identity_binding")
        if identity["provenance"] == "ROOT":
            expected_genesis = _digest(_GENESIS_DOMAIN, _canonical(scope), authority_digest, identity["identity_digest"])
            if identity["source_package_digest"] != _ZERO_DIGEST or identity["anchor_sequence"] != 0 or identity["anchor_head"] != expected_genesis or identity["genesis_head"] != expected_genesis:
                _fail(FinancialContinuityError, "continuity_identity_genesis")
        else:
            if identity["source_package_digest"] == _ZERO_DIGEST or identity["anchor_sequence"] > package["sequence"]:
                _fail(FinancialContinuityError, "continuity_identity_anchor")
            if identity["anchor_sequence"] == 0:
                if identity["anchor_head"] != identity["genesis_head"]:
                    _fail(FinancialContinuityError, "continuity_identity_anchor")
            else:
                anchor_row = next((row for row in tables["financial_events"] if row["event_sequence"] == identity["anchor_sequence"]), None)
                if anchor_row is None or cls._import_value(anchor_row["head"]) != identity["anchor_head"]:
                    _fail(FinancialContinuityError, "continuity_identity_history_anchor")
        digest = package["package_digest"]
        body = dict(package)
        del body["package_digest"]
        expected = _hex(_digest(_CONTINUITY_DOMAIN, _canonical(body)))
        if digest != expected:
            _fail(FinancialContinuityError, "continuity_package_digest")
        return package

    def export_continuity(self) -> bytes:
        """Export only bounded, allowlisted responsibility state."""
        with self._read() as connection:
            meta = self._meta(connection)
            if int(meta["dispatch_enabled"]) != 0 or int(meta["egress_enabled"]) != 0:
                _fail(FinancialContinuityError, "continuity_dispatch_boundary")
            exported_rows: dict[str, list[dict[str, Any]]] = {}
            for table in sorted(_TABLES):
                columns = tuple(str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})") )
                if columns != _TABLE_COLUMNS[table]:
                    _fail(FinancialContinuityError, "continuity_schema_columns")
                rows: list[dict[str, Any]] = []
                for row in connection.execute(f"SELECT * FROM {table}"):
                    rows.append({column: self._export_value(row[column]) for column in columns})
                if len(rows) > _MAX_ROWS:
                    _fail(FinancialContinuityError, "continuity_row_cap")
                exported_rows[table] = rows
            scope = {
                "state_id": self.config.state_id,
                "deployment_id": self.config.deployment_id,
                "program_id": self.config.program_id,
                "period_id": self.config.period_id,
                "currency": self.config.currency,
            }
            body: dict[str, Any] = {
                "schema": _CONTINUITY_SCHEMA,
                "version": 5,
                "scope": scope,
                "authority": {"authority_id": self.trusted_authority.authority_id, "epoch": self.trusted_authority.epoch, "digest": _hex(self.trusted_authority.digest)},
                "continuity_epoch": int(meta["continuity_epoch"]),
                "sequence": int(meta["sequence"]),
                "history_head": _hex(bytes(meta["history_head"])),
                "dispatch_enabled": False,
                "egress_enabled": False,
                "mode": str(meta["mode"]),
                "tables": exported_rows,
            }
            package = {**body, "package_digest": _hex(_digest(_CONTINUITY_DOMAIN, _canonical(body)))}
            encoded = _canonical(package)
            if len(encoded) > _MAX_PACKAGE_BYTES:
                _fail(FinancialContinuityError, "continuity_package_size")
            return encoded

    continuity_export = export_continuity

    @classmethod
    def restore_continuity(
        cls,
        *,
        package_bytes: bytes,
        recovered_path: Path,
        trusted_authority: SyntheticTrustedAuthority | None,
        clock: FinancialClock | None = None,
        restore_mode: str = "SHADOW",
    ) -> "FinancialOwner":
        """Restore into a new SHADOW or explicitly approved TEST owner."""
        sidecar_paths = (Path(f"{recovered_path}-wal"), Path(f"{recovered_path}-shm")) if isinstance(recovered_path, Path) else ()
        occupied = lambda path: path.exists() or path.is_symlink()
        if not isinstance(recovered_path, Path) or any(occupied(path) for path in (recovered_path, *sidecar_paths)) or not recovered_path.parent.is_dir():
            _fail(FinancialContinuityError, "continuity_destination")
        if restore_mode not in {"SHADOW", "TEST"}:
            _fail(FinancialContinuityError, "continuity_restore_mode")
        package = cls.validate_continuity_package(package_bytes)
        if trusted_authority is None or type(trusted_authority) is not SyntheticTrustedAuthority:
            _fail(FinancialAuthorityError, "trusted_authority_required")
        authority = package["authority"]
        if (str(authority.get("authority_id")), int(authority.get("epoch", 0)), str(authority.get("digest"))) != (trusted_authority.authority_id, trusted_authority.epoch, _hex(trusted_authority.digest)):
            _fail(FinancialAuthorityError, "continuity_authority_mismatch")
        config_map = package["scope"]
        config = FinancialOwnerConfig(state_id=str(config_map["state_id"]), deployment_id=str(config_map["deployment_id"]), program_id=str(config_map["program_id"]), period_id=str(config_map["period_id"]), currency=str(config_map["currency"]))
        restored_owner_id = _SHADOW_OWNER_ID if restore_mode == "SHADOW" else _TEST_OWNER_ID
        source_identity_rows = package["tables"]["financial_identity"]
        if len(source_identity_rows) != 1:
            _fail(FinancialContinuityError, "continuity_identity_rows")
        source_identity = _identity_record(
            {column: cls._import_value(source_identity_rows[0][column]) for column in _TABLE_COLUMNS["financial_identity"]},
            error_type=FinancialContinuityError,
            code_prefix="continuity_identity",
        )
        identity_contract = {
            "id": 1,
            "schema_version": _SCHEMA_VERSION,
            "provenance": "CONTINUITY_RESTORE",
            "bound_mode": restore_mode,
            "bound_owner_id": restored_owner_id,
            "anchor_sequence": int(package["sequence"]),
            "anchor_head": bytes.fromhex(str(package["history_head"])),
            "genesis_head": bytes(source_identity["genesis_head"]),
            "source_package_digest": bytes.fromhex(str(package["package_digest"])),
            "identity_digest": _identity_digest(
                provenance="CONTINUITY_RESTORE",
                bound_mode=restore_mode,
                bound_owner_id=restored_owner_id,
                anchor_sequence=int(package["sequence"]),
                source_package_digest=bytes.fromhex(str(package["package_digest"])),
            ),
        }
        owner: FinancialOwner | None = None
        attempt_directory: Path | None = None
        attempt_path: Path | None = None
        published = False
        published_identity: tuple[int, int] | None = None
        cleanup_failures: list[str] = []

        def cleanup_path(path: Path) -> None:
            try:
                if occupied(path):
                    path.unlink()
            except OSError as cleanup_error:
                cleanup_failures.append(f"{path}:{cleanup_error.__class__.__name__}")

        def cleanup_attempt() -> None:
            if attempt_path is not None:
                cleanup_path(attempt_path)
                cleanup_path(Path(f"{attempt_path}-wal"))
                cleanup_path(Path(f"{attempt_path}-shm"))
            if attempt_directory is not None:
                try:
                    attempt_directory.rmdir()
                except FileNotFoundError:
                    pass
                except OSError as cleanup_error:
                    cleanup_failures.append(f"{attempt_directory}:{cleanup_error.__class__.__name__}")

        def cleanup_published_destination() -> None:
            if not published or published_identity is None:
                return
            try:
                current = recovered_path.stat()
                if (int(current.st_dev), int(current.st_ino)) == published_identity:
                    recovered_path.unlink()
            except FileNotFoundError:
                pass
            except OSError as cleanup_error:
                cleanup_failures.append(f"{recovered_path}:{cleanup_error.__class__.__name__}")

        try:
            try:
                attempt_directory = Path(tempfile.mkdtemp(prefix=f".{recovered_path.name}.restore-", dir=str(recovered_path.parent)))
            except OSError:
                _fail(FinancialContinuityError, "continuity_destination")
            attempt_path = attempt_directory / "owner.sqlite"
            owner = cls(
                path=attempt_path,
                config=config,
                trusted_authority=trusted_authority,
                clock=clock,
                mode=restore_mode,
                owner_id=restored_owner_id,
                _identity_contract=identity_contract,
            )
            insertion_order = ["control_packs", "population_imports", "population_items", "obligations", "evidence", "payments", "claimed_adjustments", "cases", "determinations", "actions", "action_outbox", "financial_events", "financial_conflicts", "evaluations"]
            with owner._write() as connection:
                for table in insertion_order:
                    connection.execute(f"DELETE FROM {table}")
                meta_rows = package["tables"]["financial_meta"]
                if len(meta_rows) != 1:
                    _fail(FinancialContinuityError, "continuity_meta_rows")
                meta_columns = _TABLE_COLUMNS["financial_meta"]
                meta_values = [owner._import_value(meta_rows[0][column]) for column in meta_columns]
                if len(meta_values) != len(meta_columns):
                    _fail(FinancialContinuityError, "continuity_meta_columns")
                overrides = {"mode": restore_mode, "dispatch_enabled": 0, "egress_enabled": 0, "owner_id": restored_owner_id}
                meta_values = [overrides.get(column, value) for column, value in zip(meta_columns, meta_values)]
                assignments = ",".join(f"{column}=?" for column in meta_columns)
                connection.execute(f"UPDATE financial_meta SET {assignments} WHERE id=1", tuple(meta_values))
                for table in insertion_order:
                    columns = _TABLE_COLUMNS[table]
                    rows = package["tables"][table]
                    placeholders = ",".join("?" for _ in columns)
                    for raw_row in rows:
                        values = [owner._import_value(raw_row[column]) for column in columns]
                        if len(values) != len(columns):
                            _fail(FinancialContinuityError, "continuity_columns")
                        connection.execute(f"INSERT INTO {table} ({','.join(columns)}) VALUES ({placeholders})", tuple(values))
            owner._verify_open_identity()
            from app.right_rail_financial_owner_independent import verify_database

            verify_database(
                owner.path,
                expected_config=config,
                expected_authority={"authority_id": trusted_authority.authority_id, "epoch": trusted_authority.epoch, "digest": _hex(trusted_authority.digest)},
                expected_mode=restore_mode,
                expected_owner_id=restored_owner_id,
                expected_continuity_epoch=int(package["continuity_epoch"]),
                restore_source_package=package_bytes,
            )
            owner.close()
            if any(occupied(path) for path in sidecar_paths):
                _fail(FinancialContinuityError, "continuity_destination")
            try:
                os.link(attempt_path, recovered_path)
            except FileExistsError:
                _fail(FinancialContinuityError, "continuity_destination")
            except OSError:
                _fail(FinancialContinuityError, "continuity_destination_claim")
            published = True
            published_stat = recovered_path.stat()
            published_identity = (int(published_stat.st_dev), int(published_stat.st_ino))
            if any(occupied(path) for path in sidecar_paths):
                _fail(FinancialContinuityError, "continuity_destination")
            cleanup_attempt()
            if cleanup_failures:
                cleanup_published_destination()
                _fail(FinancialContinuityError, "continuity_restore_cleanup")
            owner.path = recovered_path
        except Exception as error:
            if owner is not None:
                owner.close()
            cleanup_published_destination()
            cleanup_attempt()
            if cleanup_failures:
                _fail(FinancialContinuityError, "continuity_restore_cleanup")
            if error.__class__.__module__ == "app.right_rail_financial_owner_independent":
                _fail(FinancialContinuityError, "continuity_restore_integrity")
            raise
        assert owner is not None
        return owner

    @classmethod
    def restore_test_continuity(
        cls,
        *,
        package_bytes: bytes,
        recovered_path: Path,
        trusted_authority: SyntheticTrustedAuthority | None,
        clock: FinancialClock | None = None,
    ) -> "FinancialOwner":
        """Restore into a separate non-live TEST owner for synthetic continuation."""

        return cls.restore_continuity(
            package_bytes=package_bytes,
            recovered_path=recovered_path,
            trusted_authority=trusted_authority,
            clock=clock,
            restore_mode="TEST",
        )

    continuity_restore = restore_continuity
    continuity_test_restore = restore_test_continuity

    def verify_integrity(self) -> dict[str, Any]:
        from app.right_rail_financial_owner_independent import verify_database

        return verify_database(
            self.path,
            expected_config={"state_id": self.config.state_id, "deployment_id": self.config.deployment_id, "program_id": self.config.program_id, "period_id": self.config.period_id, "currency": self.config.currency},
            expected_authority={"authority_id": self.trusted_authority.authority_id, "epoch": self.trusted_authority.epoch, "digest": _hex(self.trusted_authority.digest)},
            expected_mode=self.mode,
            expected_owner_id=self.owner_id,
        )

    def dispatch_outbox(self, *_args: Any, **_kwargs: Any) -> None:
        _fail(FinancialDispatchError, "dispatch_disabled")

    def close(self) -> None:
        return None


__all__ = (
    "AuthorityActor",
    "ControlPack",
    "EvidenceRecord",
    "FinancialAuthorityError",
    "FinancialConflictError",
    "FinancialContinuityError",
    "FinancialDispatchError",
    "FinancialError",
    "FinancialInputError",
    "FinancialIntegrityError",
    "FinancialOwner",
    "FinancialOwnerConfig",
    "FinancialRevisionError",
    "PopulationItem",
    "SyntheticTrustedAuthority",
)
