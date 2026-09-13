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
from pathlib import Path
import re
import sqlite3
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


_SCHEMA_VERSION: Final[int] = 1
_SCHEMA: Final[str] = "RR/FINANCIAL/OWNER/v1"
_CONTINUITY_SCHEMA: Final[str] = "RR/FINANCIAL/CONTINUITY/v1"
_CURRENCY: Final[str] = "USD"
_MAX_CENTS: Final[int] = (1 << 63) - 1
_MAX_ROWS: Final[int] = 10_000
_MAX_PACKAGE_BYTES: Final[int] = 8 * 1024 * 1024
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_ROLE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_KIND = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_EVENT_DOMAIN = b"RR/FINANCIAL/EVENT/v1\x00"
_HEAD_DOMAIN = b"RR/FINANCIAL/HEAD/v1\x00"
_GENESIS_DOMAIN = b"RR/FINANCIAL/GENESIS/v1\x00"
_EVIDENCE_DOMAIN = b"RR/FINANCIAL/EVIDENCE/v1\x00"
_ACTION_DOMAIN = b"RR/FINANCIAL/ACTION/v1\x00"
_IDEMPOTENCY_DOMAIN = b"RR/FINANCIAL/IDEMPOTENCY/v1\x00"

_TABLES: Final[frozenset[str]] = frozenset(
    {
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


def _blob(value: object, size: int, label: str) -> bytes:
    if type(value) is not bytes or len(value) != size:
        _fail(FinancialInputError, label)
    return bytes(value)


def _time(value: object, label: str) -> int:
    if type(value) is not int or value < 0 or value >= 2**63:
        _fail(FinancialInputError, label)
    return value


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
        if self.currency != _CURRENCY:
            _fail(FinancialInputError, "currency")

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical({"state_id": self.state_id, "deployment_id": self.deployment_id, "program_id": self.program_id, "period_id": self.period_id, "currency": self.currency})


def _sql_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
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
            mode TEXT NOT NULL CHECK (mode IN ('LIVE','SHADOW')),
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
            determination_digest BLOB NOT NULL CHECK (length(determination_digest)=64)
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
            result_digest BLOB NOT NULL CHECK (length(result_digest)=64)
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
    ) -> None:
        if not isinstance(path, Path) or not path.parent.is_dir() or path.is_symlink():
            _fail(FinancialIntegrityError, "owner_path")
        if mode not in {"LIVE", "SHADOW"}:
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
        existed = path.exists()
        if existed and path.stat().st_size == 0:
            _fail(FinancialIntegrityError, "empty_database")
        if not existed:
            with closing(self._connect()) as connection:
                _sql_schema(connection)
                genesis = _digest(_GENESIS_DOMAIN, config.canonical_bytes, trusted_authority.digest)
                connection.execute(
                    "INSERT INTO financial_meta VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (1, _SCHEMA_VERSION, _SCHEMA, config.state_id, config.deployment_id, config.program_id, config.period_id, config.currency, 0, genesis, 1, 0, 0, trusted_authority.authority_id, trusted_authority.epoch, trusted_authority.digest, mode, self.owner_id),
                )
                connection.commit()
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
                if (str(row["trusted_authority_id"]), int(row["trusted_authority_epoch"]), bytes(row["trusted_authority_digest"])) != (self.trusted_authority.authority_id, self.trusted_authority.epoch, self.trusted_authority.digest):
                    _fail(FinancialAuthorityError, "trusted_authority_stale")
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
        if self.config.period_id not in {"PROGRAM", "ALL"} and period_id != self.config.period_id:
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
        payload_bytes = _canonical(payload)
        payload_digest = _digest(_EVENT_DOMAIN, payload_bytes)
        meta = self._meta(connection)
        sequence = int(meta["sequence"]) + 1
        previous_head = bytes(meta["history_head"])
        event_id = _digest(_EVENT_DOMAIN, sequence.to_bytes(8, "big"), aggregate_type.encode("ascii"), aggregate_id.encode("ascii"), kind.encode("ascii"), payload_digest)
        head = _digest(_HEAD_DOMAIN, previous_head, event_id, payload_digest)
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
        row = connection.execute("SELECT * FROM obligations WHERE item_id=?", (item_id,)).fetchone()
        if row is None:
            _fail(FinancialIntegrityError, "obligation_missing")
        return row

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
        if lawful_cents + _sum_cents(int(row[1]) for row in connection.execute("SELECT amount_cents FROM payments WHERE obligation_id=? AND active=1", (obligation_id,))) >= owed_cents and entries:
            return max(value[0] for value in entries)
        return None

    def _recompute_obligation(self, connection: sqlite3.Connection, obligation_id: str, *, now_ms: int, authority_id: str) -> tuple[int, int, dict[str, Any]]:
        old = connection.execute("SELECT * FROM obligations WHERE obligation_id=?", (obligation_id,)).fetchone()
        if old is None:
            _fail(FinancialIntegrityError, "obligation_missing")
        cash = _sum_cents(int(row[0]) for row in connection.execute("SELECT amount_cents FROM payments WHERE obligation_id=? AND active=1", (obligation_id,)))
        claimed = _sum_cents(int(row[0]) for row in connection.execute("SELECT amount_cents FROM claimed_adjustments WHERE obligation_id=? AND status IN ('CLAIMED','AUTHORIZED')", (obligation_id,)))
        lawful = _sum_cents(int(row[0]) for row in connection.execute("SELECT amount_cents FROM claimed_adjustments WHERE obligation_id=? AND status='AUTHORIZED'", (obligation_id,)))
        total = _add(cash, lawful)
        owed = int(old["owed_cents"])
        shortfall = max(owed - total, 0)
        overage = max(total - owed, 0)
        evidence_ids = self._evidence_for(connection, str(old["item_id"]))
        conflict_count = int(connection.execute("SELECT COUNT(*) FROM financial_conflicts WHERE obligation_id=?", (obligation_id,)).fetchone()[0])
        support_count = int(connection.execute("SELECT COUNT(*) FROM evidence WHERE item_id=? AND kind='SUPPORT'", (old["item_id"],)).fetchone()[0])
        verification = "CONFLICT_VISIBLE" if conflict_count else ("SUPPORTED" if support_count else "MISSING_EVIDENCE")
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
        result_digest = _digest(_EVIDENCE_DOMAIN, _canonical(result))
        connection.execute(
            "INSERT INTO evaluations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (evaluation_id, obligation_id, after_revision, int(old["rule_version"]), _canonical({"evidence_ids": list(evidence_ids)}).decode("ascii"), authority_id, now_ms, owed, claimed, lawful, cash, shortfall, overage, cash_satisfied, amount_satisfied, timely, reporting_complete, verification, case_status, delivery, result_digest),
        )
        updated = connection.execute(
            "UPDATE obligations SET revision=?,claimed_adjustment_cents=?,lawful_adjustment_cents=?,received_cash_cents=?,shortfall_cents=?,overage_cents=?,cash_satisfied=?,amount_satisfied=?,timely=?,verification_status=?,case_status=?,delivery_status=?,current_evaluation_id=?,updated_at_ms=? WHERE obligation_id=? AND revision=?",
            (after_revision, claimed, lawful, cash, shortfall, overage, cash_satisfied, amount_satisfied, timely, verification, case_status, delivery, evaluation_id, now_ms, obligation_id, before_revision),
        )
        if updated.rowcount != 1:
            _fail(FinancialRevisionError, "obligation_revision_conflict")
        return before_revision, after_revision, {**result, "result_digest": _hex(result_digest)}

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
            "INSERT INTO population_imports VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (population_id, pack_id, cutoff_ms, encoded_rules, expected_count, 0, 0, None, "STAGED", now_ms, now_ms),
        )
        return connection.execute("SELECT * FROM population_imports WHERE population_id=?", (population_id,)).fetchone()

    def _stage_population_chunk(self, *, population_id: str, pack_id: str, cutoff_ms: int, inclusion_rules: tuple[str, ...], expected_count: int, chunk: tuple[PopulationItem, ...]) -> None:
        if not chunk:
            return
        with self._write() as connection:
            now_ms = self._now()
            self._ensure_population_import(connection, population_id=population_id, pack_id=pack_id, cutoff_ms=cutoff_ms, inclusion_rules=inclusion_rules, expected_count=expected_count, now_ms=now_ms)
            for item in chunk:
                if item.population_id != population_id:
                    _fail(FinancialInputError, "population_item_id")
                existing = connection.execute("SELECT display_label,owed_cents,due_at_ms,currency FROM population_items WHERE population_id=? AND item_id=?", (population_id, item.item_id)).fetchone()
                expected = (item.display_label, item.owed_cents, item.due_at_ms, item.currency)
                if existing is not None:
                    if tuple(existing) != expected:
                        _fail(FinancialConflictError, "population_item_conflict")
                    continue
                connection.execute("INSERT INTO population_items VALUES (?,?,?,?,?,?)", (population_id, item.item_id, item.display_label, item.owed_cents, item.due_at_ms, item.currency))
            count = int(connection.execute("SELECT COUNT(*) FROM population_items WHERE population_id=?", (population_id,)).fetchone()[0])
            connection.execute("UPDATE population_imports SET imported_count=?,updated_at_ms=? WHERE population_id=?", (count, now_ms, population_id))
            self._append_event(connection, aggregate_type="POPULATION", aggregate_id=population_id, kind="POPULATION_STAGED", before_revision=count - len(chunk), after_revision=count, payload={"population_id": population_id, "imported_count": count, "chunk_count": len(chunk)}, committed_at_ms=now_ms)

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
        for item in iterator:
            if type(item) is not PopulationItem:
                _fail(FinancialInputError, "population_item_type")
            chunk.append(item)
            if len(chunk) >= chunk_size:
                self._stage_population_chunk(population_id=population_id, pack_id=pack_id, cutoff_ms=cutoff_ms, inclusion_rules=inclusion_rules, expected_count=expected_count, chunk=tuple(chunk))
                chunk.clear()
        if chunk:
            self._stage_population_chunk(population_id=population_id, pack_id=pack_id, cutoff_ms=cutoff_ms, inclusion_rules=inclusion_rules, expected_count=expected_count, chunk=tuple(chunk))
        with self._read() as connection:
            row = connection.execute("SELECT imported_count,status FROM population_imports WHERE population_id=?", (population_id,)).fetchone()
            assert row is not None
            return {"status": str(row[1]), "population_id": population_id, "imported_count": int(row[0]), "expected_count": expected_count}

    def validate_population(self, population_id: str) -> dict[str, Any]:
        self._assert_actionable()
        _id(population_id, "population_id")
        with self._write() as connection:
            row = connection.execute("SELECT * FROM population_imports WHERE population_id=?", (population_id,)).fetchone()
            if row is None:
                _fail(FinancialIntegrityError, "population_missing")
            count = int(connection.execute("SELECT COUNT(*) FROM population_items WHERE population_id=?", (population_id,)).fetchone()[0])
            if count != int(row["expected_count"]):
                _fail(FinancialIntegrityError, "population_incomplete")
            material = b"".join(_digest(_EVIDENCE_DOMAIN, _canonical({"item_id": str(item[0]), "display_label": str(item[1]), "owed_cents": int(item[2]), "due_at_ms": int(item[3]), "currency": str(item[4])})) for item in connection.execute("SELECT item_id,display_label,owed_cents,due_at_ms,currency FROM population_items WHERE population_id=? ORDER BY item_id", (population_id,)))
            digest = _digest(_EVIDENCE_DOMAIN, material)
            now_ms = self._now()
            connection.execute("UPDATE population_imports SET imported_count=?,validated_count=?,validation_digest=?,status='VALIDATED',updated_at_ms=? WHERE population_id=?", (count, count, digest, now_ms, population_id))
            self._append_event(connection, aggregate_type="POPULATION", aggregate_id=population_id, kind="POPULATION_VALIDATED", before_revision=0, after_revision=count, payload={"population_id": population_id, "validated_count": count, "validation_digest": _hex(digest)}, committed_at_ms=now_ms)
            return {"status": "VALIDATED", "population_id": population_id, "validated_count": count, "validation_digest": _hex(digest)}

    def _insert_initial_evaluation(self, connection: sqlite3.Connection, *, obligation_id: str, owed_cents: int, rule_version: int, authority_id: str, now_ms: int) -> None:
        result = {"evaluation_id": f"evaluation:{obligation_id}:r0", "obligation_id": obligation_id, "revision": 0, "rule_version": rule_version, "evidence_ids": [], "authority_id": authority_id, "evaluated_at_ms": now_ms, "owed_cents": owed_cents, "claimed_adjustment_cents": 0, "lawful_adjustment_cents": 0, "received_cash_cents": 0, "shortfall_cents": owed_cents, "overage_cents": 0, "cash_satisfied": 0, "amount_satisfied": 0, "timely": 0, "reporting_complete": 0, "verification_status": "MISSING_EVIDENCE", "case_status": "OPEN", "delivery_status": "NONE"}
        result_digest = _digest(_EVIDENCE_DOMAIN, _canonical(result))
        connection.execute("INSERT INTO evaluations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (result["evaluation_id"], obligation_id, 0, rule_version, _canonical({"evidence_ids": []}).decode("ascii"), authority_id, now_ms, owed_cents, 0, 0, 0, owed_cents, 0, 0, 0, 0, 0, "MISSING_EVIDENCE", "OPEN", "NONE", result_digest))

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
            if import_row is None or str(import_row["status"]) != "VALIDATED":
                _fail(FinancialIntegrityError, "population_not_validated")
            if connection.execute("SELECT 1 FROM obligations WHERE population_id=? LIMIT 1", (population_id,)).fetchone() is not None:
                _fail(FinancialConflictError, "population_already_published")
            pack = connection.execute("SELECT * FROM control_packs WHERE pack_id=?", (import_row["pack_id"],)).fetchone()
            assert pack is not None
            now_ms = self._now()
            items = connection.execute("SELECT item_id,display_label,owed_cents,due_at_ms,currency FROM population_items WHERE population_id=? ORDER BY item_id", (population_id,)).fetchall()
            for item_id, _label, owed_cents, due_at_ms, currency in items:
                obligation_id = f"obligation:{population_id}:{item_id}"
                connection.execute("INSERT INTO obligations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (obligation_id, population_id, str(item_id), str(pack["period_id"]), str(currency), int(owed_cents), int(due_at_ms), int(pack["version"]), 0, 0, 0, 0, int(owed_cents), 0, 0, 0, 0, 0, "MISSING_EVIDENCE", "OPEN", "NONE", f"evaluation:{obligation_id}:r0", now_ms))
                self._insert_initial_evaluation(connection, obligation_id=obligation_id, owed_cents=int(owed_cents), rule_version=int(pack["version"]), authority_id=self.trusted_authority.authority_id, now_ms=now_ms)
                self._ensure_case(connection, obligation_id=obligation_id, reason="INITIAL_ACCOUNTABILITY", owner="CASE_OWNER", due_at_ms=int(due_at_ms), status="OPEN", now_ms=now_ms)
            connection.execute("UPDATE population_imports SET status='PUBLISHED',updated_at_ms=? WHERE population_id=?", (now_ms, population_id))
            self._append_event(connection, aggregate_type="POPULATION", aggregate_id=population_id, kind="POPULATION_PUBLISHED", before_revision=0, after_revision=len(items), payload={"population_id": population_id, "item_count": len(items), "pack_id": str(import_row["pack_id"]), "pack_version": int(pack["version"])}, committed_at_ms=now_ms)
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
            _fail(FinancialRevisionError, "revision_fence")

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
                    self._append_event(connection, aggregate_type="OBLIGATION", aggregate_id=str(obligation["obligation_id"]), kind="PAYMENT_CONFLICT_VISIBLE", before_revision=int(obligation["revision"]), after_revision=int(obligation["revision"]), payload={"conflict_id": conflict_id, "candidate_evidence_id": evidence_id, "existing_payment_id": str(candidate_existing["payment_id"]), "common_origin_id": common_origin_id}, committed_at_ms=self._now())
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

    def _authority_action(self, actor_id: str, actor_role: str) -> None:
        self.trusted_authority.require(actor_id, actor_role)

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
    ) -> dict[str, Any]:
        self._assert_actionable()
        self._authority_action(actor_id, actor_role)
        action_ref = action_id or f"action:offset:{claim_id}"
        _id(action_ref, "action_id")
        with self._write() as connection:
            obligation = self._get_obligation_row(connection, item_id)
            existing_action = connection.execute("SELECT * FROM actions WHERE action_id=?", (action_ref,)).fetchone()
            if existing_action is not None:
                return {"status": "DUPLICATE", "action_id": action_ref, **self._projection_for_row(obligation)}
            self._check_revision(obligation, expected_revision)
            claim = connection.execute("SELECT * FROM claimed_adjustments WHERE claim_id=? AND obligation_id=?", (claim_id, obligation["obligation_id"])).fetchone()
            if claim is None:
                _fail(FinancialIntegrityError, "offset_claim_missing")
            if str(claim["status"]) != "CLAIMED":
                _fail(FinancialConflictError, "offset_claim_not_claimed")
            decision_time = self._now() if decision_at_ms is None else decision_at_ms
            _time(decision_time, "decision_time")
            before_revision = int(obligation["revision"])
            resulting_revision = before_revision + 1
            determination_id = f"determination:{action_ref}"
            evidence_ids = [str(claim["evidence_id"])]
            determination_payload = {"determination_id": determination_id, "claim_id": claim_id, "decision": "OFFSET_AUTHORIZED", "amount_cents": int(claim["amount_cents"]), "actor_id": actor_id, "actor_role": actor_role, "authority_id": self.trusted_authority.authority_id, "authority_epoch": self.trusted_authority.epoch, "supporting_evidence_ids": evidence_ids, "expected_revision": before_revision, "resulting_revision": resulting_revision}
            determination_digest = _digest(_ACTION_DOMAIN, _canonical(determination_payload))
            connection.execute("INSERT INTO determinations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (determination_id, obligation["obligation_id"], claim_id, actor_id, actor_role, self.trusted_authority.authority_id, self.trusted_authority.epoch, self.trusted_authority.digest, "OFFSET_AUTHORIZED", int(claim["amount_cents"]), _canonical({"values": evidence_ids}).decode("ascii"), before_revision, resulting_revision, decision_time, determination_digest))
            connection.execute("UPDATE claimed_adjustments SET status='AUTHORIZED',updated_at_ms=? WHERE claim_id=? AND status='CLAIMED'", (decision_time, claim_id))
            self._ensure_case(connection, obligation_id=str(obligation["obligation_id"]), reason="OFFSET_AUTHORIZED", owner="CASE_OWNER", due_at_ms=int(claim["deadline_ms"]), status="AUTHORIZED", now_ms=decision_time)
            action_payload = {"action_id": action_ref, "obligation_id": str(obligation["obligation_id"]), "determination_id": determination_id, "kind": "OFFSET_AUTHORIZATION", "claim_id": claim_id, "amount_cents": int(claim["amount_cents"]), "currency": self.config.currency, "revision": resulting_revision, "dispatch": "SYNTHETIC_RECORD_ONLY"}
            self._create_action(connection, action_id=action_ref, obligation_id=str(obligation["obligation_id"]), determination_id=determination_id, kind="OFFSET_AUTHORIZATION", revision=resulting_revision, payload=action_payload, now_ms=decision_time)
            before, after, evaluation = self._recompute_obligation(connection, str(obligation["obligation_id"]), now_ms=decision_time, authority_id=self.trusted_authority.authority_id)
            if (before, after) != (before_revision, resulting_revision):
                _fail(FinancialRevisionError, "determination_revision_binding")
            self._append_event(connection, aggregate_type="OBLIGATION", aggregate_id=str(obligation["obligation_id"]), kind="OFFSET_AUTHORIZED", before_revision=before, after_revision=after, payload={"determination_id": determination_id, "action_id": action_ref, "amount_cents": int(claim["amount_cents"]), "evaluation_id": evaluation["evaluation_id"]}, committed_at_ms=decision_time)
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
    ) -> dict[str, Any]:
        self._assert_actionable()
        self._authority_action(actor_id, actor_role)
        action_ref = action_id or f"action:correction:{claim_id}"
        _id(action_ref, "action_id")
        with self._write() as connection:
            obligation = self._get_obligation_row(connection, item_id)
            existing_action = connection.execute("SELECT * FROM actions WHERE action_id=?", (action_ref,)).fetchone()
            if existing_action is not None:
                return {"status": "DUPLICATE", "action_id": action_ref, **self._projection_for_row(obligation)}
            self._check_revision(obligation, expected_revision)
            claim = connection.execute("SELECT * FROM claimed_adjustments WHERE claim_id=? AND obligation_id=?", (claim_id, obligation["obligation_id"])).fetchone()
            if claim is None:
                _fail(FinancialIntegrityError, "offset_claim_missing")
            if str(claim["status"]) != "CLAIMED":
                _fail(FinancialConflictError, "offset_claim_not_claimed")
            decision_time = self._now() if decision_at_ms is None else decision_at_ms
            _time(decision_time, "decision_time")
            before_revision = int(obligation["revision"])
            resulting_revision = before_revision + 1
            determination_id = f"determination:{action_ref}"
            evidence_ids = [str(claim["evidence_id"])]
            determination_payload = {"determination_id": determination_id, "claim_id": claim_id, "decision": "OFFSET_REJECTED_CORRECTION_AUTHORIZED", "amount_cents": int(claim["amount_cents"]), "actor_id": actor_id, "actor_role": actor_role, "authority_id": self.trusted_authority.authority_id, "authority_epoch": self.trusted_authority.epoch, "supporting_evidence_ids": evidence_ids, "expected_revision": before_revision, "resulting_revision": resulting_revision}
            determination_digest = _digest(_ACTION_DOMAIN, _canonical(determination_payload))
            connection.execute("INSERT INTO determinations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (determination_id, obligation["obligation_id"], claim_id, actor_id, actor_role, self.trusted_authority.authority_id, self.trusted_authority.epoch, self.trusted_authority.digest, "OFFSET_REJECTED_CORRECTION_AUTHORIZED", int(claim["amount_cents"]), _canonical({"values": evidence_ids}).decode("ascii"), before_revision, resulting_revision, decision_time, determination_digest))
            connection.execute("UPDATE claimed_adjustments SET status='REJECTED',updated_at_ms=? WHERE claim_id=? AND status='CLAIMED'", (decision_time, claim_id))
            self._ensure_case(connection, obligation_id=str(obligation["obligation_id"]), reason="CORRECTION_REQUIRED", owner="CASE_OWNER", due_at_ms=int(claim["deadline_ms"]), status="CORRECTION_REQUIRED", now_ms=decision_time)
            action_payload = {"action_id": action_ref, "obligation_id": str(obligation["obligation_id"]), "determination_id": determination_id, "kind": "CORRECTION_PAYMENT_REQUEST", "claim_id": claim_id, "amount_cents": int(claim["amount_cents"]), "currency": self.config.currency, "revision": resulting_revision, "dispatch": "SYNTHETIC_RECORD_ONLY"}
            self._create_action(connection, action_id=action_ref, obligation_id=str(obligation["obligation_id"]), determination_id=determination_id, kind="CORRECTION_PAYMENT_REQUEST", revision=resulting_revision, payload=action_payload, now_ms=decision_time)
            before, after, evaluation = self._recompute_obligation(connection, str(obligation["obligation_id"]), now_ms=decision_time, authority_id=self.trusted_authority.authority_id)
            if (before, after) != (before_revision, resulting_revision):
                _fail(FinancialRevisionError, "determination_revision_binding")
            self._append_event(connection, aggregate_type="OBLIGATION", aggregate_id=str(obligation["obligation_id"]), kind="OFFSET_REJECTED_CORRECTION_AUTHORIZED", before_revision=before, after_revision=after, payload={"determination_id": determination_id, "action_id": action_ref, "amount_cents": int(claim["amount_cents"]), "evaluation_id": evaluation["evaluation_id"]}, committed_at_ms=decision_time)
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
        self._authority_action(actor_id, actor_role)
        _id(action_id, "action_id")
        _id(acknowledgment_ref, "acknowledgment_ref")
        with self._write() as connection:
            action = connection.execute("SELECT * FROM actions WHERE action_id=?", (action_id,)).fetchone()
            if action is None:
                _fail(FinancialIntegrityError, "action_missing")
            outbox = connection.execute("SELECT * FROM action_outbox WHERE action_id=?", (action_id,)).fetchone()
            assert outbox is not None
            if str(action["status"]) == "ACKNOWLEDGED":
                if str(outbox["acknowledgment_ref"]) == acknowledgment_ref:
                    row = connection.execute("SELECT * FROM obligations WHERE obligation_id=?", (action["obligation_id"],)).fetchone()
                    assert row is not None
                    return {"status": "DUPLICATE", "action_id": action_id, **self._projection_for_row(row)}
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

    def record_reporting_correction(
        self,
        *,
        item_id: str,
        report_id: str,
        actor_id: str = "synthetic-reporter",
        actor_role: str = "REPORTING_EDITOR",
        expected_revision: int | None = None,
        event_at_ms: int | None = None,
    ) -> dict[str, Any]:
        self._assert_actionable()
        self._authority_action(actor_id, actor_role)
        _id(report_id, "report_id")
        event_time = self._now() if event_at_ms is None else event_at_ms
        _time(event_time, "reporting_event")
        evidence = self._new_evidence(evidence_id=f"evidence:report:{report_id}", item_id=item_id, kind="REPORTING_CORRECTION", common_origin_id=report_id, source_id="synthetic-report-source", source_version="fixture-v1", local_ref=f"report:{report_id}", applicable_at_ms=event_time, event_at_ms=event_time, received_at_ms=self._now())
        with self._write() as connection:
            obligation = self._get_obligation_row(connection, item_id)
            self._check_revision(obligation, expected_revision)
            status = self._insert_evidence(connection, evidence)
            if status == "DUPLICATE":
                return {"status": "DUPLICATE", "report_id": report_id, **self._projection_for_row(obligation)}
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
            return {"status": "EVALUATED", **self._current_projection(connection, str(obligation["obligation_id"]))}

    evaluate = evaluate_obligation

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
            result["determinations"] = self._dict_rows(connection, "SELECT determination_id,claim_id,actor_id,actor_role,authority_id,authority_epoch,decision,amount_cents,supporting_evidence_json,expected_revision,resulting_revision,decided_at_ms,determination_digest FROM determinations WHERE obligation_id=? ORDER BY determination_id LIMIT ?", (obligation_id, limit))
            result["actions"] = self._dict_rows(connection, "SELECT action_id,determination_id,kind,status,revision,payload_digest,idempotency_key,created_at_ms FROM actions WHERE obligation_id=? ORDER BY action_id LIMIT ?", (obligation_id, limit))
            result["conflicts"] = self._dict_rows(connection, "SELECT conflict_id,common_origin_id,existing_payment_id,candidate_evidence_id,existing_amount_cents,candidate_amount_cents,reason,visible_at_ms FROM financial_conflicts WHERE obligation_id=? ORDER BY conflict_id LIMIT ?", (obligation_id, limit))
            result["evaluations"] = self._dict_rows(connection, "SELECT evaluation_id,revision,rule_version,evidence_ids_json,authority_id,evaluated_at_ms,owed_cents,claimed_adjustment_cents,lawful_adjustment_cents,received_cash_cents,shortfall_cents,overage_cents,cash_satisfied,amount_satisfied,timely,reporting_complete,verification_status,case_status,delivery_status,result_digest FROM evaluations WHERE obligation_id=? ORDER BY revision LIMIT ?", (obligation_id, limit))
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
        if type(package_bytes) is not bytes or len(package_bytes) > _MAX_PACKAGE_BYTES:
            _fail(FinancialContinuityError, "continuity_package_size")
        try:
            package = json.loads(package_bytes.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            _fail(FinancialContinuityError, "continuity_package_json")
        if type(package) is not dict or set(package) != {"package_schema", "source_schema", "config", "authority", "mode", "dispatch_enabled", "egress_enabled", "exported_at_ms", "rows", "export_digest"}:
            _fail(FinancialContinuityError, "continuity_package_shape")
        digest = package.pop("export_digest")
        if type(digest) is not str:
            _fail(FinancialContinuityError, "continuity_package_digest")
        expected = _hex(_digest(_EVIDENCE_DOMAIN, _canonical(package)))
        package["export_digest"] = digest
        if digest != expected or package["package_schema"] != _CONTINUITY_SCHEMA or package["source_schema"] != _SCHEMA or package["dispatch_enabled"] is not False or package["egress_enabled"] is not False or package["mode"] not in {"LIVE", "SHADOW"}:
            _fail(FinancialContinuityError, "continuity_package_binding")
        if type(package["rows"]) is not dict or set(package["rows"]) != _TABLES:
            _fail(FinancialContinuityError, "continuity_package_tables")
        if type(package["config"]) is not dict or type(package["authority"]) is not dict:
            _fail(FinancialContinuityError, "continuity_package_config")
        for table, rows in package["rows"].items():
            if type(rows) is not list or len(rows) > _MAX_ROWS:
                _fail(FinancialContinuityError, "continuity_package_rows")
            for row in rows:
                if type(row) is not list or len(row) > 64:
                    _fail(FinancialContinuityError, "continuity_package_row")
                for value in row:
                    cls._import_value(value)
        return package

    def export_continuity(self) -> bytes:
        """Export only bounded, allowlisted responsibility state."""
        with self._read() as connection:
            meta = self._meta(connection)
            if int(meta["dispatch_enabled"]) != 0 or int(meta["egress_enabled"]) != 0:
                _fail(FinancialContinuityError, "continuity_dispatch_boundary")
            exported_rows: dict[str, list[list[Any]]] = {}
            for table in sorted(_TABLES):
                columns = [str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})")]
                rows: list[list[Any]] = []
                for row in connection.execute(f"SELECT * FROM {table}"):
                    rows.append([self._export_value(value) for value in tuple(row)])
                if len(rows) > _MAX_ROWS:
                    _fail(FinancialContinuityError, "continuity_row_cap")
                exported_rows[table] = rows
            body: dict[str, Any] = {
                "package_schema": _CONTINUITY_SCHEMA,
                "source_schema": _SCHEMA,
                "config": {"state_id": self.config.state_id, "deployment_id": self.config.deployment_id, "program_id": self.config.program_id, "period_id": self.config.period_id, "currency": self.config.currency},
                "authority": {"authority_id": self.trusted_authority.authority_id, "epoch": self.trusted_authority.epoch, "digest": _hex(self.trusted_authority.digest)},
                "mode": str(meta["mode"]),
                "dispatch_enabled": False,
                "egress_enabled": False,
                "exported_at_ms": self._now(),
                "rows": exported_rows,
            }
            package = {**body, "export_digest": _hex(_digest(_EVIDENCE_DOMAIN, _canonical(body)))}
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
    ) -> "FinancialOwner":
        """Restore into a new SHADOW owner; no source file is overwritten."""
        if not isinstance(recovered_path, Path) or recovered_path.exists() or recovered_path.is_symlink() or not recovered_path.parent.is_dir():
            _fail(FinancialContinuityError, "continuity_destination")
        package = cls.validate_continuity_package(package_bytes)
        if trusted_authority is None or type(trusted_authority) is not SyntheticTrustedAuthority:
            _fail(FinancialAuthorityError, "trusted_authority_required")
        authority = package["authority"]
        if (str(authority.get("authority_id")), int(authority.get("epoch", 0)), str(authority.get("digest"))) != (trusted_authority.authority_id, trusted_authority.epoch, _hex(trusted_authority.digest)):
            _fail(FinancialAuthorityError, "continuity_authority_mismatch")
        config_map = package["config"]
        config = FinancialOwnerConfig(state_id=str(config_map["state_id"]), deployment_id=str(config_map["deployment_id"]), program_id=str(config_map["program_id"]), period_id=str(config_map["period_id"]), currency=str(config_map["currency"]))
        owner = cls(path=recovered_path, config=config, trusted_authority=trusted_authority, clock=clock, mode="SHADOW", owner_id="continuity-shadow-owner-v1")
        insertion_order = ["control_packs", "population_imports", "population_items", "obligations", "evidence", "payments", "claimed_adjustments", "cases", "determinations", "actions", "action_outbox", "financial_events", "financial_conflicts", "evaluations"]
        with owner._write() as connection:
            for table in insertion_order:
                connection.execute(f"DELETE FROM {table}")
            meta_rows = package["rows"]["financial_meta"]
            if len(meta_rows) != 1:
                _fail(FinancialContinuityError, "continuity_meta_rows")
            meta_columns = [str(row[1]) for row in connection.execute("PRAGMA table_info(financial_meta)")]
            meta_values = [owner._import_value(value) for value in meta_rows[0]]
            if len(meta_values) != len(meta_columns):
                _fail(FinancialContinuityError, "continuity_meta_columns")
            overrides = {"mode": "SHADOW", "dispatch_enabled": 0, "egress_enabled": 0, "owner_id": "continuity-shadow-owner-v1"}
            meta_values = [overrides.get(column, value) for column, value in zip(meta_columns, meta_values)]
            placeholders = ",".join("?" for _ in meta_columns)
            connection.execute(f"INSERT INTO financial_meta ({','.join(meta_columns)}) VALUES ({placeholders})", tuple(meta_values))
            for table in insertion_order:
                columns = [str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})")]
                rows = package["rows"][table]
                placeholders = ",".join("?" for _ in columns)
                for raw_row in rows:
                    values = [owner._import_value(value) for value in raw_row]
                    if len(values) != len(columns):
                        _fail(FinancialContinuityError, "continuity_columns")
                    connection.execute(f"INSERT INTO {table} ({','.join(columns)}) VALUES ({placeholders})", tuple(values))
        owner._verify_open_identity()
        owner.verify_integrity()
        return owner

    continuity_restore = restore_continuity

    def verify_integrity(self) -> dict[str, Any]:
        from app.right_rail_financial_owner_independent import verify_database

        return verify_database(self.path, expected_config={"state_id": self.config.state_id, "deployment_id": self.config.deployment_id, "program_id": self.config.program_id, "period_id": self.config.period_id, "currency": self.config.currency}, expected_authority={"authority_id": self.trusted_authority.authority_id, "epoch": self.trusted_authority.epoch, "digest": _hex(self.trusted_authority.digest)})

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
