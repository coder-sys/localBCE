"""Loopback-only browser workspace for the synthetic RightRail staff workflow.

Run with ``python -m app.right_rail_financial_staff_server``. The service creates
an ephemeral synthetic Owner, serves a small local UI, and sends every operator
command through FinancialMirror to FinancialOwner. It has no authentication
integration, external source connector, payment movement, or dispatch path.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import secrets
import socket
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from app import right_rail_financial_engine as financial_engine
from app.right_rail_financial_canonical_json import decode, encode
from app.right_rail_financial_mirror import (
    FinancialMirror,
    FinancialMirrorError,
    MAX_PACKAGE_BYTES,
)
from app.right_rail_financial_owner import (
    ControlPack,
    FinancialAuthorityError,
    FinancialBusyError,
    FinancialError,
    FinancialOwner,
    FinancialOwnerConfig,
    FinancialRevisionError,
    PopulationItem,
    PopulationManifest,
    SYNTHETIC_STAFF,
    staff_authority,
)


STATE_ID = "fixture-state"
DEPLOYMENT_ID = "fixture-rightrail"
PROGRAM_ID = "fixture-provider-payment"
PERIOD_ID = "fixture-2026-period-01"
POPULATION_ID = "population:fixture-2026-01"
PACK_ID = "control-pack:fixture-2026-01:v1"
MANIFEST_ID = "population-manifest:fixture-2026-01:v1"
H_ITEM_ID = "item-h"
H_CLAIM_ID = "claim:obligation-item-h:offset-v1"
H_ACTION_ID = "action:obligation-item-h:correction-v1"
_ITEM_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}")


def _names(item_id: str) -> dict[str, str]:
    """Every record name a command writes for one item. For item H these are exactly the fixture's names."""
    short = item_id.removeprefix("item-")
    action, offset = f"action:obligation-{item_id}:correction-v1", f"action:obligation-{item_id}:offset-v1"
    return {"claim": f"claim:obligation-{item_id}:offset-v1", "action": action, "offset_action": offset,
            "ack": {action: f"ack:correction:{short}:v1", offset: f"ack:offset:{short}:v1"}, "report": f"report:{short}:v1", "report_evidence": f"evidence:report:{short}:original"}


def _cash_command(item_id: str) -> dict[str, Any]:
    short = item_id.removeprefix("item-")
    return {**CASH_CORRECTION_COMMAND, "item_id": item_id, "pays_action_id": _names(item_id)["action"], "payment_id": f"payment:{short}:p2",
            "common_origin_id": f"origin:payment:{short}:p2", "evidence_id": f"evidence:payment-{short}:p2", "local_ref": f"ref:payment:{short}:p2"}
H_OBLIGATION_ID = "obligation:item-h:period-01"
MAX_RESTORE_DESTINATIONS = 1000
MAX_STAFF_COMMAND_BYTES = 8192
HTTP_REQUEST_TIMEOUT_SECONDS = 60.0
HTTP_BODY_TIMEOUT_SECONDS = 5.0
HTTP_REFUSAL_DRAIN_SECONDS = 0.1

PROGRAM_TOTAL_CENTS = 100_000_000
H_OWED_CENTS = 10_000_000
H_CASH_CENTS = 9_700_000
H_SHORTFALL_CENTS = 300_000
CORRECTION_CENTS = 300_000
OTHER_ITEM_CENTS = 4_700_000
FINAL_OTHER_ITEM_CENTS = 5_400_000

PERIOD_START_MS = 1_767_225_600_000
PERIOD_END_MS = 1_775_001_600_000
H_DUE_AT_MS = 1_774_915_200_000
PACK_RECORDED_AT_MS = 1_767_139_200_000
PACK_APPROVED_AT_MS = 1_767_182_400_000
SUPPORT_EVENT_MS = 1_767_312_000_000
OTHER_ITEM_PAYMENT_MS = 1_767_312_000_001
CASH_EVENT_MS = 1_774_828_800_000
DECISION_AT_MS = 1_774_922_400_000
CORRECTION_EVENT_MS = 1_775_001_600_000
REPORT_EVENT_MS = 1_775_001_600_000

CASH_CORRECTION_COMMAND = {
    "item_id": H_ITEM_ID,
    "pays_action_id": H_ACTION_ID,
    "payment_id": "payment:h:p2",
    "common_origin_id": "origin:payment:h:p2",
    "amount_cents": CORRECTION_CENTS,
    "evidence_id": "evidence:payment-h:p2",
    "event_at_ms": CORRECTION_EVENT_MS,
    "source_id": "fixture-payment-file",
    "source_version": "payment-v2",
    "local_ref": "ref:payment:h:p2",
}

ITEM_IDS = (H_ITEM_ID,) + tuple(f"item-{index:02d}" for index in range(1, 20))
ITEM_AMOUNTS = {
    H_ITEM_ID: H_OWED_CENTS,
    **{f"item-{index:02d}": OTHER_ITEM_CENTS for index in range(1, 19)},
    "item-19": FINAL_OTHER_ITEM_CENTS,
}
ITEM_LABELS = {
    item_id: "Synthetic recipient H" if item_id == H_ITEM_ID else f"Synthetic recipient {item_id[-2:]}"
    for item_id in ITEM_IDS
}

_ROOT = Path(__file__).resolve().parent


class StaffServerError(RuntimeError):
    """A file this server ships is missing or malformed; the message names it."""


def _shipped(name: str) -> bytes:
    try:
        return (_ROOT / name).read_bytes()
    except OSError:
        raise StaffServerError(f"shipped_file_unreadable:{name}") from None


def _interaction_model(raw: bytes) -> tuple[tuple, dict]:
    """(roles, route -> roles) from the interaction model: do_POST enforces it, the page reads the same file.
    A role is selected by path, never by query string, and a fixed set of real roles keeps every disallowed control absent from the page (Art. XII.7)."""
    try:
        model = json.loads(raw)
        return tuple(model["roles"]), {c["route"][5:]: frozenset(c["roles"]) for c in model["controls"].values() if c["route"].startswith("POST ")}
    except (ValueError, KeyError, TypeError, AttributeError):
        raise StaffServerError("interaction_model_malformed") from None


FOLLOWTHROUGH_RULES_BYTES = _shipped("fixtures/h_followthrough_rules_v1.json")  # listed by the fixture Control Pack
STAFF_ROLES, COMMAND_ROLES = _interaction_model(_shipped("staff_workspace/interaction-model.json"))
_STATIC_FILES: dict[str, tuple[str, str]] = {
    "/": ("staff_workspace/index.html", "text/html; charset=utf-8"),
    "/staff.css": ("staff_workspace/staff.css", "text/css; charset=utf-8"),
    "/staff.js": ("staff_workspace/staff.js", "text/javascript; charset=utf-8"),
    "/interaction-model.json": ("staff_workspace/interaction-model.json", "application/json; charset=utf-8"),
    **{f"/role/{role}": ("staff_workspace/index.html", "text/html; charset=utf-8") for role in STAFF_ROLES},
}
# Routes match the raw request target exactly, so a query, fragment, authority
# form or encoded variant matches nothing. Commands are exactly the interaction
# model's declared POST controls (tested): no undeclared command is served.
_READ_ROUTES = {
    "/api/workspace": "workspace",
    "/api/decision-package": "decision_view",
    "/api/correction-followup": "correction_followup",
    "/api/item-timeline": "item_timeline",
}
# The owner role each actor-bearing command needs. X-Staff-Person names the acting person; with no header nobody is named and the command records its role's synthetic actor.
_ACTOR_ROLE = {
    "authorize_offset": "FINANCE_DECISION", "reject_offset_and_authorize_correction": "FINANCE_DECISION",
    "acknowledge_correction_action": "RECEIVER", "record_reporting_evidence": "REPORTING_EDITOR",
}
_PEOPLE = {person[0]: person for person in SYNTHETIC_STAFF}
_DECISION_EVENTS = ("OFFSET_AUTHORIZED", "OFFSET_REJECTED_CORRECTION_AUTHORIZED")


def _person_fits(staff_role: str, owner_role: str, named: list[str]) -> bool:
    """Exactly one named roster person of this staff role who holds the owner role."""
    return len(named) == 1 and any(i == named[0] and role == staff_role and owner_role in owner_roles for i, _n, role, owner_roles in SYNTHETIC_STAFF)
# The record only that command writes: its appearance after a busy error proves the command committed.
def _own_record(name: str, item_id: str) -> tuple[Any, ...]:
    n = _names(item_id)
    return {
        "authorize_offset": ("SELECT COUNT(*) FROM actions WHERE action_id=?", n["offset_action"]),
        "reject_offset_and_authorize_correction": ("SELECT COUNT(*) FROM actions WHERE action_id=?", n["action"]),
        "acknowledge_correction_action": ("SELECT COUNT(*) FROM action_outbox WHERE acknowledgment_ref IN (?,?)", *n["ack"].values()),
        "record_cash_correction": ("SELECT COUNT(*) FROM evidence WHERE evidence_id=?", _cash_command(item_id)["evidence_id"]),
        "record_reporting_evidence": ("SELECT COUNT(*) FROM evidence WHERE evidence_id=?", n["report_evidence"]),
    }.get(name, ("SELECT 0",))
_COMMAND_ROUTES = {
    "/api/decision/authorize-offset": "authorize_offset",
    "/api/decision/reject-offset": "reject_offset_and_authorize_correction",
    "/api/action/acknowledge": "acknowledge_correction_action",
    "/api/correction/record-cash": "record_cash_correction",
    "/api/reporting/record": "record_reporting_evidence",
    "/api/continuity/restore-test": "restore_test",
}
# These three act on one click and cannot be retried blind, so each carries the one-time token its item's read returned.
_TOKEN_COMMANDS = frozenset({"acknowledge_correction_action", "record_reporting_evidence", "restore_test"})
MAX_ACTION_TOKENS = 256
_HEX_DIGEST = re.compile(r"^[0-9A-F]{128}$")
_EVALUATION_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


# One reparse-point check, shared with the Engine release loader.
_is_reparse_path = financial_engine._is_reparse_path


class _DemoClock:
    """Deterministic clock for the fixed synthetic fixture."""

    def __init__(self, initial_ms: int = CASH_EVENT_MS) -> None:
        self._value = initial_ms
        self._lock = threading.Lock()

    def now_ms(self) -> int:
        with self._lock:
            self._value += 1
            return self._value

    def advance_to(self, event_at_ms: int) -> None:
        with self._lock:
            self._value = max(self._value, event_at_ms)

    def as_of(self) -> str:
        """The fixture's own present, read without ticking it: the screen shows a year only when an instant is from another one."""
        with self._lock:
            return datetime.fromtimestamp(self._value / 1000, timezone.utc).isoformat()


class StaffWorkflow:
    """Synthetic workspace backed by one current Owner/Mirror pair."""

    def __init__(
        self,
        workspace_dir: Path | None = None,
        *,
        resume_existing: bool = False,
    ) -> None:
        if type(resume_existing) is not bool or (resume_existing and workspace_dir is None):
            raise ValueError("workspace_resume_configuration")
        self._temporary_directory: tempfile.TemporaryDirectory[str] | None = None
        if workspace_dir is None:
            self._temporary_directory = tempfile.TemporaryDirectory(prefix="rightrail-staff-demo-")
            self.workspace_dir = Path(self._temporary_directory.name)
        else:
            self.workspace_dir = workspace_dir
        if _is_reparse_path(self.workspace_dir) or not self.workspace_dir.is_dir():
            self.close()
            raise ValueError("workspace_directory")
        if resume_existing:
            _validate_workspace_directory(self.workspace_dir, resume_existing=True)

        self._lock = threading.RLock()
        self._clock = _DemoClock()
        self._authority = staff_authority()
        self._restore_number = 0
        self._tokens: dict[str, tuple[str, tuple[object, ...]]] = {}  # token -> (item, store position at the read); oldest dropped first
        owner_path = self.workspace_dir / "financial-owner.sqlite"
        owner_exists = owner_path.exists() or owner_path.is_symlink()
        if resume_existing and (_is_reparse_path(owner_path) or not owner_path.is_file()):
            self.close()
            raise ValueError("workspace_database")
        if owner_exists and not resume_existing:
            self.close()
            raise ValueError("workspace_must_be_empty")

        config = FinancialOwnerConfig(
            state_id=STATE_ID,
            deployment_id=DEPLOYMENT_ID,
            program_id=PROGRAM_ID,
            period_id=PERIOD_ID,
            currency="USD",
            schema_version=8,
        )
        self._mirror = FinancialMirror(
            FinancialOwner(
                path=owner_path,
                config=config,
                trusted_authority=self._authority,
                clock=self._clock,
                mode="TEST",
                owner_id="continuity-test-owner-v1",
            )
        )
        self._continuity = {
            "restored": False,
            "mode": "SYNTHETIC_LOCAL",
            "package_digest": None,
            "package_bytes": None,
            "decision_package_equal": None,
        }
        try:
            if resume_existing:
                self._verify_resumable_workspace()
            else:
                self._seed_synthetic_population()
        except BaseException:
            self.close()  # the owner holds the store open
            raise

    def __enter__(self) -> "StaffWorkflow":
        return self

    def __exit__(self, _exc_type: object, _exc_value: object, _traceback: object) -> None:
        self.close()

    @property
    def mirror(self) -> FinancialMirror:
        return self._mirror

    @property
    def continuity(self) -> dict[str, Any]:
        return dict(self._continuity)

    def close(self) -> None:
        mirror = getattr(self, "_mirror", None)
        if mirror is not None:
            mirror.owner.close()
        if self._temporary_directory is not None:
            self._temporary_directory.cleanup()
            self._temporary_directory = None

    def _verify_resumable_workspace(self) -> None:
        owner = self._mirror.owner
        integrity = owner.verify_integrity()
        summary = self._mirror.summary()
        population = owner.population_status(POPULATION_ID)
        package = self._mirror.decision_package(H_ITEM_ID, limit=100, offset=0)
        obligations = owner.list_obligations(status="ALL", limit=100)
        obligation_amounts: dict[str, int] = {}
        exact_obligation_rows = len(obligations) == len(ITEM_AMOUNTS)
        for row in obligations:
            item_id = row.get("item_id") if type(row) is dict else None
            owed_cents = row.get("owed_cents") if type(row) is dict else None
            if type(item_id) is not str or type(owed_cents) is not int or item_id in obligation_amounts:
                exact_obligation_rows = False
                continue
            obligation_amounts[item_id] = owed_cents
        control_pack = package.get("control_pack")
        expected_pack = self._fixture_control_pack()
        # ``verify_integrity`` raises on any checker failure; on success its
        # result carries the checked identity fields, not a status label.
        history_head = integrity.get("history_head")
        if (
            integrity.get("mode") != "TEST"
            or integrity.get("owner_id") != owner.owner_id
            or integrity.get("schema_version") != 8
            or integrity.get("scope") != {
                "state_id": STATE_ID,
                "deployment_id": DEPLOYMENT_ID,
                "program_id": PROGRAM_ID,
                "period_id": PERIOD_ID,
                "currency": "USD",
            }
            or integrity.get("authority") != {
                "authority_id": self._authority.authority_id,
                "epoch": self._authority.epoch,
                "digest": self._authority.digest.hex().upper(),
            }
            or type(history_head) is not str
            or not _HEX_DIGEST.fullmatch(history_head)
            or owner.mode != "TEST"
            # The owner summary has no ``mode`` key (mode is bound above by
            # the checker result and the open owner); a ``summary["mode"]``
            # test could never pass. It binds the nonactivation flags instead.
            or summary.get("production_usable") is not False
            or summary.get("activation") is not False
            or summary.get("proof_suite_id") is not None
            or summary.get("dispatch_enabled") is not False
            or summary.get("egress_enabled") is not False
            or summary.get("obligation_count") != len(ITEM_IDS)
            or summary.get("owed_cents") != PROGRAM_TOTAL_CENTS
            or not exact_obligation_rows
            or obligation_amounts != ITEM_AMOUNTS
            or population.get("population_id") != POPULATION_ID
            or population.get("status") != "PUBLISHED"
            or population.get("completeness") != "EXACT"
            or population.get("expected_count") != len(ITEM_IDS)
            or population.get("imported_count") != len(ITEM_IDS)
            or population.get("validated_count") != len(ITEM_IDS)
            or population.get("manifest_status") != "CURRENT"
            or population.get("source_complete") is not True
            or type(control_pack) is not dict
            or control_pack.get("pack_id") != expected_pack.pack_id
            or control_pack.get("version") != expected_pack.version
            or control_pack.get("digest") != expected_pack.digest.hex().upper()
        ):
            self.close()
            raise ValueError("workspace_resume_integrity")
        sequence = integrity.get("sequence")
        if type(sequence) is not int or sequence < 1:
            self.close()
            raise ValueError("workspace_resume_history")
        latest = owner.history(limit=1, offset=sequence - 1)
        if len(latest) != 1 or type(latest[0].get("committed_at_ms")) is not int:
            self.close()
            raise ValueError("workspace_resume_history")
        self._clock.advance_to(int(latest[0]["committed_at_ms"]))

    @staticmethod
    def _fixture_control_pack() -> ControlPack:
        return ControlPack(
            pack_id=PACK_ID,
            state_id=STATE_ID,
            deployment_id=DEPLOYMENT_ID,
            program_id=PROGRAM_ID,
            period_id=PERIOD_ID,
            version=1,
            source_refs=("fixture-source:approved-schedule:v1", "followthrough-rules:sha256:" + hashlib.sha256(FOLLOWTHROUGH_RULES_BYTES).hexdigest().upper()),
            effective_start_ms=PERIOD_START_MS,
            effective_end_ms=PERIOD_END_MS,
            recorded_at_ms=PACK_RECORDED_AT_MS,
            approved_at_ms=PACK_APPROVED_AT_MS,
            calculation_rule_id="calculation:per-recipient:v1",
            adjustment_rule_id="adjustment:offset:v1",
            authorized_roles=("FINANCE_DECISION", "CASE_OWNER", "REPORTING_EDITOR", "RECEIVER"),
            expected_tests=(
                "program-total=100000000",
                "H-owed=10000000",
                "other-total=90000000",
                "timeliness-separate",
            ),
        )

    def _seed_synthetic_population(self) -> None:
        if sum(ITEM_AMOUNTS.values()) != PROGRAM_TOTAL_CENTS or len(ITEM_IDS) != 20:
            raise RuntimeError("synthetic_fixture_arithmetic")

        pack = self._fixture_control_pack()
        manifest = PopulationManifest(
            manifest_id=MANIFEST_ID,
            manifest_version=1,
            state_id=STATE_ID,
            deployment_id=DEPLOYMENT_ID,
            program_id=PROGRAM_ID,
            period_id=PERIOD_ID,
            currency="USD",
            pack_id=PACK_ID,
            cutoff_ms=PERIOD_START_MS,
            inclusion_rules=("included:synthetic",),
            source_owner_id="source-owner:fixture-state-finance-v1",
            authority_id=self._authority.authority_id,
            authority_epoch=self._authority.epoch,
            authority_digest=self._authority.digest,
            approved_by="synthetic-official",
            approval_ref="synthetic-approval:population-roster:2026-01:v1",
            source_id="fixture-source:population-roster",
            source_version="roster-v1",
            source_digest=bytes.fromhex("0123456789ABCDEF" * 8),
            member_ids=tuple(sorted(ITEM_IDS)),
        )

        owner = self._mirror.owner
        owner.publish_control_pack(pack)
        owner.register_population_manifest(manifest)
        owner.stage_population(
            population_id=POPULATION_ID,
            manifest_id=MANIFEST_ID,
            pack_id=PACK_ID,
            cutoff_ms=PERIOD_START_MS,
            inclusion_rules=("included:synthetic",),
            expected_count=20,
            items=tuple(
                PopulationItem(
                    population_id=POPULATION_ID,
                    item_id=item_id,
                    display_label=ITEM_LABELS[item_id],
                    owed_cents=ITEM_AMOUNTS[item_id],
                    due_at_ms=H_DUE_AT_MS,
                    currency="USD",
                )
                for item_id in ITEM_IDS
            ),
            chunk_size=5,
        )
        owner.validate_population(POPULATION_ID)
        owner.publish_population(POPULATION_ID)

        # Synthetic SUPPORT references and full payment exist for the 19 other
        # recipients: they are paid in full and are not open items. H's offset
        # claim intentionally has no supporting source evidence and is the
        # one item this fixture leaves for staff to work.
        for index in range(1, 20):
            item_id = f"item-{index:02d}"
            owner.record_support_evidence(
                item_id=item_id,
                evidence_id=f"evidence:support:{item_id}",
                common_origin_id=f"origin:support:{index:02d}",
                source_id="fixture-source",
                source_version="support-v1",
                local_ref=f"ref:support:{index:02d}",
                applicable_at_ms=SUPPORT_EVENT_MS,
                event_at_ms=SUPPORT_EVENT_MS,
            )
            owner.record_payment_evidence(
                item_id=item_id,
                payment_id=f"payment:{item_id}:full",
                common_origin_id=f"origin:payment:{index:02d}",
                amount_cents=ITEM_AMOUNTS[item_id],
                evidence_id=f"evidence:payment:{item_id}",
                event_at_ms=OTHER_ITEM_PAYMENT_MS,
                source_id="fixture-payment-file",
                source_version="payment-v1",
                local_ref=f"ref:payment:{index:02d}",
            )

        owner.record_payment_evidence(
            item_id=H_ITEM_ID,
            payment_id="payment:h:cash",
            common_origin_id="origin:cash:h:v1",
            amount_cents=H_CASH_CENTS,
            evidence_id="evidence:cash-h:9700000",
            event_at_ms=CASH_EVENT_MS,
            source_id="fixture-payment-file",
            source_version="cash-v1",
            local_ref="ref:cash:h:v1",
        )
        owner.record_offset_claim(
            item_id=H_ITEM_ID,
            claim_id=H_CLAIM_ID,
            amount_cents=H_SHORTFALL_CENTS,
            evidence_id="evidence:offset-h:claim",
            owner_role="CASE_OWNER",
            deadline_ms=H_DUE_AT_MS,
            expected_revision=int(self._mirror.obligation_detail(H_ITEM_ID)["revision"]),
        )

    @staticmethod
    def _require_object(value: object, expected_keys: set[str]) -> dict[str, Any]:
        if type(value) is not dict or set(value) != expected_keys:
            raise ValueError("request_shape")
        return value

    @staticmethod
    def _review_values(body: object, *, with_receipt: bool = True) -> tuple[int, str | None, str | None]:
        required = {"revision"}
        if with_receipt:
            required |= {"evaluation_id", "evaluation_result_digest"}
        body = StaffWorkflow._require_object(body, required)
        revision = body["revision"]
        if type(revision) is not int or revision < 0:
            raise ValueError("review_binding")
        evaluation_id = body.get("evaluation_id")
        result_digest = body.get("evaluation_result_digest")
        if with_receipt and (
            type(evaluation_id) is not str
            or not _EVALUATION_ID.fullmatch(evaluation_id)
            or type(result_digest) is not str
            or not _HEX_DIGEST.fullmatch(result_digest)
        ):
            raise ValueError("review_binding")
        return revision, evaluation_id, result_digest

    def _review_dependencies(self, body: object) -> tuple[int, str, str, dict[str, Any]]:
        """The one shape check for a reviewed command: exact keys, typed values, binding object."""
        payload = self._require_object(
            body,
            {"revision", "evaluation_id", "evaluation_result_digest", "read_binding"},
        )
        if type(payload["read_binding"]) is not dict:
            raise ValueError("review_binding")
        revision, evaluation_id, result_digest = self._review_values(
            {key: payload[key] for key in ("revision", "evaluation_id", "evaluation_result_digest")}
        )
        if evaluation_id is None or result_digest is None:
            raise ValueError("review_binding")
        return revision, evaluation_id, result_digest, payload["read_binding"]

    def _received_cash_cents(self, item_id: str) -> int:
        """Measure one item's recorded cash from the Owner projection."""
        value = self._mirror.obligation_detail(item_id, limit=1).get("received_cash_cents")
        if type(value) is not int:
            raise RuntimeError("owner_cash_unavailable")
        return value

    def command(self, name: str, body: object, actor: str | None = None, item_id: str = H_ITEM_ID) -> dict[str, Any]:
        """Run one staff command. On a busy store, changed is true only when this command's own record appeared,
        false only when the store did not move at all, and otherwise None: another process may have written."""
        with self._lock:
            mirror = self._mirror
            try:
                before = self._store_position(name, item_id)
            except FinancialBusyError as error:
                error.changed = False  # nothing has run yet
                raise
            try:
                return getattr(self, name)(body, *(() if actor is None else (actor,)), item_id=item_id)
            except FinancialBusyError as error:  # the command's own write, or its read-back after a commit
                try:
                    position, own = self._store_position(name, item_id)
                except FinancialBusyError:
                    position, own = None, False
                if (own and not before[1]) or self._mirror is not mirror:  # its own record appeared, or restore swapped in its store
                    error.changed = True
                else:
                    error.changed = False if position == before[0] else None
                raise

    def _store_position(self, name: str, item_id: str = H_ITEM_ID) -> tuple[tuple[object, ...], bool]:
        """(owner path, sequence, head) and whether this command's own record exists."""
        owner, (query, *arguments) = self._mirror.owner, _own_record(name, item_id)
        with owner._read_snapshot() as connection:
            position = (str(owner.path), *connection.execute("SELECT sequence,history_head FROM financial_meta WHERE id=1").fetchone())
            return position, connection.execute(query, arguments).fetchone()[0] > 0

    def reject_offset_and_authorize_correction(self, body: object, actor: str = "synthetic-official", *, item_id: str = H_ITEM_ID) -> dict[str, Any]:
        n = _names(item_id)
        with self._lock:
            revision, evaluation_id, result_digest, read_binding = self._review_dependencies(body)
            self._clock.advance_to(DECISION_AT_MS)
            result = self._mirror.reject_offset_and_authorize_correction(
                item_id=item_id,
                claim_id=n["claim"],
                actor_id=actor,
                actor_role="FINANCE_DECISION",
                expected_revision=revision,
                action_id=n["action"],
                decision_at_ms=DECISION_AT_MS,
                evaluation_id=evaluation_id,
                evaluation_result_digest=result_digest,
                staff_read_binding=read_binding,
            )
            return {"command": result, "workspace": self.item(item_id)}

    def authorize_offset(self, body: object, actor: str = "synthetic-official", *, item_id: str = H_ITEM_ID) -> dict[str, Any]:
        """Accept Plan A's offset. Bound to the read the approver saw, like restore-test; a resend returns the first result."""
        revision, evaluation_id, result_digest, read_binding = self._review_dependencies(body)
        n = _names(item_id)
        with self._lock:
            view = self.decision_view(item_id)
            # Once decided, the read has moved on by design: a resend goes to the Owner, which answers DUPLICATE or refuses.
            if view["decision_package"].get("current_determination") is None and read_binding != self._staff_command_binding(view, item_id):
                raise FinancialRevisionError("obligation_revision_conflict")
            self._clock.advance_to(DECISION_AT_MS)
            result = self._mirror.authorize_offset(
                item_id=item_id,
                claim_id=n["claim"],
                actor_id=actor,
                actor_role="FINANCE_DECISION",
                expected_revision=revision,
                action_id=n["offset_action"],
                decision_at_ms=DECISION_AT_MS,
                evaluation_id=evaluation_id,
                evaluation_result_digest=result_digest,
            )
            return {"command": result, "workspace": self.item(item_id)}

    def acknowledge_correction_action(self, body: object, actor: str = "synthetic-receiver", *, item_id: str = H_ITEM_ID) -> dict[str, Any]:
        revision, _evaluation_id, _result_digest = self._review_values(body, with_receipt=False)
        with self._lock:
            n = _names(item_id)
            current = self._mirror.decision_package(item_id, limit=100, offset=0).get("current_action")
            action_id = current.get("action_id") if type(current) is dict and current.get("action_id") in n["ack"] else n["action"]
            cash_before = self._received_cash_cents(item_id)
            result = self._mirror.acknowledge_action(
                action_id,
                n["ack"][action_id],
                actor_id=actor,
                actor_role="RECEIVER",
                expected_revision=revision,
            )
            cash_after = self._received_cash_cents(item_id)
            return {
                "command": result,
                "cash_before_cents": cash_before,
                "cash_after_cents": cash_after,
                "cash_effect_cents": cash_after - cash_before,
                "workspace": self.item(item_id),
            }

    def record_cash_correction(self, body: object, *, item_id: str = H_ITEM_ID) -> dict[str, Any]:
        payload = self._require_object(body, {"revision", "cash_command"})
        revision, _evaluation_id, _result_digest = self._review_values({"revision": payload["revision"]}, with_receipt=False)
        cash_command = self._require_object(payload["cash_command"], set(CASH_CORRECTION_COMMAND))
        if cash_command != _cash_command(item_id):
            raise ValueError("cash_command_binding")
        with self._lock:
            self._clock.advance_to(CORRECTION_EVENT_MS)
            result = self._mirror.record_payment_evidence(
                **cash_command,
                expected_revision=revision,
            )
            return {"command": result, "money_movement": False, "workspace": self.item(item_id)}

    def record_reporting_evidence(self, body: object, actor: str = "synthetic-reporter", *, item_id: str = H_ITEM_ID) -> dict[str, Any]:
        revision, _evaluation_id, _result_digest = self._review_values(body, with_receipt=False)
        with self._lock:
            self._clock.advance_to(REPORT_EVENT_MS)
            result = self._mirror.record_reporting_evidence(
                item_id=item_id,
                report_id=_names(item_id)["report"],
                evidence_id=_names(item_id)["report_evidence"],
                actor_id=actor,
                actor_role="REPORTING_EDITOR",
                expected_revision=revision,
                event_at_ms=REPORT_EVENT_MS,
            )
            return {"command": result, "reporting_source": "SYNTHETIC_UNVERIFIED", "workspace": self.item(item_id)}

    def _workspace_locked(self, item_id: str = H_ITEM_ID) -> dict[str, Any]:
        return self._mirror.staff_read_snapshot(
            {
                "resource": "workspace",
                "item_id": item_id,
                "population_id": POPULATION_ID,
                "status": "ALL",
                "limit": 100,
                "offset": 0,
                "detail_limit": 100,
                "history_limit": 200,
            },
            read_at=self._clock.as_of(),
            labels=ITEM_LABELS,
            continuity=self._continuity,
        )

    def workspace(self) -> dict[str, Any]:
        return self.item(H_ITEM_ID)

    def item(self, item_id: str) -> dict[str, Any]:
        """The verified, safely rendered read with this one stored item in the detail slot, plus the one-time token its three
        one-click commands need. The token is bound to this item and the store position read just before it."""
        with self._lock:
            try:
                value = self._workspace_locked(item_id)
                if value["h"]["obligation"]["item_id"] != item_id:
                    raise KeyError("item_not_held")
            except Exception:
                if item_id not in {row["item_id"] for row in self._mirror.list_obligations(status="ALL", limit=100, offset=0)["items"]}:
                    raise KeyError("item_not_held") from None
                raise
            seen = value["read_envelope"]  # the token is bound to the store position of this very read
            token = secrets.token_urlsafe(24)
            self._tokens[token] = (item_id, (str(self._mirror.owner.path), seen["sequence"], bytes.fromhex(seen["history_head"])))
            while len(self._tokens) > MAX_ACTION_TOKENS:
                del self._tokens[next(iter(self._tokens))]
            return {**value, "action_token": token}

    def check_token(self, name: str, item_id: str, tokens: list[str]) -> str | None:
        """None only for the single token a read of this item issued, never used, with the store unmoved since. It is spent here."""
        with self._lock:
            if not tokens:
                return "action_token_missing"
            held = self._tokens.pop(tokens[0], None) if len(tokens) == 1 else None
            if held is None or held[0] != item_id:
                return "action_token_invalid"  # never issued, already used, or for another item
            try:
                position = self._store_position(name, item_id)[0]
            except FinancialBusyError as error:
                error.changed = False  # nothing has run
                raise
            return None if held[1] == position else "obligation_revision_conflict"  # the item changed since the read: the same answer a stale revision gets

    def decision_view(self, item_id: str = H_ITEM_ID) -> dict[str, Any]:
        with self._lock:
            return self._mirror.staff_read_snapshot(
                {"resource": "decision_package", "item_id": item_id, "limit": 100, "offset": 0},
                read_at=self._clock.as_of(),
            )

    @staticmethod
    def _staff_command_binding(view: dict[str, Any], item_id: str = H_ITEM_ID) -> dict[str, Any]:
        envelope = view.get("read_envelope")
        package = view.get("decision_package")
        if type(envelope) is not dict or type(package) is not dict:
            raise ValueError("staff_command_binding")
        bindings = envelope.get("item_bindings")
        receipt = package.get("evaluation_receipt")
        if type(bindings) is not list or type(receipt) is not dict:
            raise ValueError("staff_command_binding")
        item_binding = next(
            (row for row in bindings if type(row) is dict and row.get("item_id") == item_id),
            None,
        )
        authority = receipt.get("authority")
        if type(item_binding) is not dict or type(authority) is not dict:
            raise ValueError("staff_command_binding")
        snapshot_fields = (
            "schema", "schema_version", "scope", "mode", "owner_id",
            "continuity_epoch", "sequence", "history_head", "snapshot_id",
        )
        snapshot = {key: envelope[key] for key in snapshot_fields}
        input_binding = {
            "evaluation_id": receipt.get("evaluation_id"),
            "evaluation_result_digest": receipt.get("evaluation_result_digest"),
            "receipt_digest": receipt.get("receipt_digest"),
        }
        return {
            "contract": "RR/FINANCIAL/STAFF-COMMAND-BINDING/v2",
            "snapshot": snapshot,
            "item_binding": dict(item_binding),
            "authority": dict(authority),
            "input": input_binding,
        }

    def correction_followup(self) -> dict[str, Any]:
        with self._lock:
            package = self._mirror.decision_package(H_ITEM_ID, limit=100, offset=0)
            action = package.get("current_action")
            if type(action) is not dict or action.get("action_id") != H_ACTION_ID:
                return {
                    "contract": "RR/FINANCIAL/STAFF-CORRECTION-FOLLOWUP/v1",
                    "status": "NOT_STARTED",
                    "followup": None,
                }
            return {
                "contract": "RR/FINANCIAL/STAFF-CORRECTION-FOLLOWUP/v1",
                "status": "AVAILABLE",
                "followup": self._mirror.correction_followup_outputs(H_ITEM_ID, H_ACTION_ID),
            }

    def item_timeline(self) -> dict[str, Any]:
        """Item H's record chain, read-only, from the verified staff snapshot. A step with no record is named in ``absent``, never filled in.
        Every person is ``claimed``: the session named them and nobody signed. ``incomplete`` is true when older events are not shown."""
        with self._lock:
            h = self._workspace_locked()["h"]
        events = h["timeline"]

        def by(actor_id: str) -> dict[str, str]:
            return {"by": actor_id, "by_name": _PEOPLE.get(actor_id, (None, actor_id))[1], "attribution": "claimed"}

        # A decision is placed by its own owner event (the one that reached its resulting revision); older than the window sorts first.
        decided = {e["after_revision"]: e["event_sequence"] for e in events if e["kind"] in _DECISION_EVENTS}
        steps = [{"step": "decision", "seq": decided.get(d["resulting_revision"], 0), "at_ms": d["decided_at_ms"], "what": d["decision"], "amount_cents": d["amount_cents"], **by(d["actor_id"])} for d in h["detail"]["determinations"]]
        steps += [{"step": "assign", "seq": e["event_sequence"], "at_ms": e["committed_at_ms"], "owner_id": e["followthrough"]["owner_id"], **by(e["followthrough"]["actor_id"])}
                  for e in events if e["kind"] == "FOLLOWTHROUGH_DECIDED" and e["followthrough"]["act"] == "ASSIGN"]
        steps.sort(key=lambda step: step["seq"])
        # No release or payment-system confirmation record exists in the stack, so those steps are always absent: cash recorded
        # from the payer (the payments table) is a different fact and never reads as "Paid" here.
        chain = ("hold", "assign", "ask", "reply", "decision", "release", "payment_confirmation")
        return {"contract": "RR/FINANCIAL/STAFF-ITEM-TIMELINE/v1", "item_id": H_ITEM_ID, "steps": steps, "incomplete": h["timeline_truncated"], "absent": [n for n in chain if n not in {x["step"] for x in steps}]}

    def restore_test(self, body: object, *, item_id: str = H_ITEM_ID) -> dict[str, Any]:
        revision, evaluation_id, result_digest, read_binding = self._review_dependencies(body)
        with self._lock:
            if read_binding != self._staff_command_binding(self.decision_view(item_id), item_id):
                raise FinancialRevisionError("obligation_revision_conflict")
            before_package = self._mirror.decision_package(item_id, limit=100, offset=0)
            receipt = before_package.get("evaluation_receipt", {})
            if (
                before_package.get("obligation", {}).get("revision") != revision
                or receipt.get("evaluation_id") != evaluation_id
                or receipt.get("result_digest") != result_digest
            ):
                raise FinancialRevisionError("obligation_revision_conflict")
            package_bytes = self._mirror.export_continuity()
            if len(package_bytes) > MAX_PACKAGE_BYTES:
                raise FinancialMirrorError("continuity_package_size")
            number, destination = self._next_restore_destination()
            restored = self._mirror.restore_test_continuity(package_bytes, destination)
            try:
                restored_package = restored.decision_package(item_id, limit=100, offset=0)
                if restored_package != before_package:
                    raise FinancialMirrorError("continuity_decision_package_mismatch")
                integrity = restored.verify_integrity()
                restored_summary = restored.summary()
                if (
                    integrity.get("mode") != "TEST"
                    or restored_summary.get("dispatch_enabled") is not False
                    or restored_summary.get("egress_enabled") is not False
                    or restored_summary.get("production_usable") is not False
                    or restored_summary.get("activation") is not False
                    or restored_summary.get("proof_suite_id") is not None
                ):
                    raise FinancialMirrorError("continuity_test_boundary")
                package_digest = str(restored.validate_owner_continuity_package(package_bytes)["package_digest"])  # before the swap: a failure leaves the old owner serving
            except BaseException:  # a restore that fails leaves no open handle and no file behind, even if the close itself fails
                try:
                    restored.owner.close()
                finally:
                    for suffix in ("", "-wal", "-shm", "-journal"):
                        Path(f"{destination}{suffix}").unlink(missing_ok=True)
                raise
            previous, self._mirror, self._restore_number = self._mirror, restored, number  # only a restore that took effect uses up its number
            try:
                self._continuity = {
                    "restored": True,
                    "mode": "TEST",
                    "package_digest": package_digest,
                    "package_bytes": len(package_bytes),
                    "decision_package_equal": True,
                }
            finally:
                previous.owner.close()
            return {"continuity": self.continuity, "workspace": self.item(item_id)}

    def _next_restore_destination(self) -> tuple[int, Path]:
        for number in range(self._restore_number + 1, MAX_RESTORE_DESTINATIONS + 1):
            destination = self.workspace_dir / f"continuity-test-{number:04d}.sqlite"
            if not _is_reparse_path(destination) and not destination.exists():
                return number, destination
        raise FinancialMirrorError("continuity_destination_capacity")


def _refuse_request_json(code: str):
    def refuse(_value: str) -> None:
        raise ValueError(code)  # a repeated key would give one command two meanings (Art. III.3)
    return refuse


def _request_allowed(peer: str, host: str, origin: str | None, port: int, *, mutation: bool) -> bool:
    # Exact Host blocks DNS rebinding; a command also needs the exact same-origin Origin (CSRF).
    expected_origin = f"http://127.0.0.1:{port}"
    allowed_origins = (expected_origin,) if mutation else (None, expected_origin)
    return peer == "127.0.0.1" and host == f"127.0.0.1:{port}" and origin in allowed_origins


def _validate_workspace_directory(
    path: Path | None,
    *,
    resume_existing: bool = False,
) -> Path | None:
    if path is None:
        if resume_existing:
            raise ValueError("workspace_resume_configuration")
        return None
    if not isinstance(path, Path) or _is_reparse_path(path) or not path.is_dir():
        raise ValueError("workspace_directory")
    if resume_existing:
        owner_path = path / "financial-owner.sqlite"
        if _is_reparse_path(owner_path) or not owner_path.is_file():
            raise ValueError("workspace_database")
        for suffix in ("-journal", "-wal", "-shm"):
            sidecar = Path(f"{owner_path}{suffix}")
            if _is_reparse_path(sidecar) or (sidecar.exists() and not sidecar.is_file()):
                raise ValueError("workspace_database_sidecar")
        return path
    try:
        if next(path.iterdir(), None) is not None:
            raise ValueError("workspace_must_be_empty")
    except OSError as error:
        raise ValueError("workspace_directory") from error
    return path


def _handler_for(workflow: StaffWorkflow) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def setup(self) -> None:
            super().setup()
            self.connection.settimeout(HTTP_REQUEST_TIMEOUT_SECONDS)
            self._body_read = False

        def log_message(self, _format: str, *args: Any) -> None:
            # Avoid request paths or user activity in console logs.
            return

        def version_string(self) -> str:
            return "RightRail"  # no Python or runtime version banner

        def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
            # Framework refusals (bad request line, oversized header, unsupported
            # method) carry the same JSON body and security headers as any other.
            self._respond(code, {"error": {"code": "invalid_request"}})

        def _headers(self, content_type: str) -> None:
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(self._response_length))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.send_header("Connection", "close")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
            )

        def _respond(self, status: int, value: Any, content_type: str = "application/json; charset=utf-8", *, retry_after: bool = False) -> None:
            content = value if type(value) is bytes else encode(value)
            self.close_connection = True
            self._response_length = len(content)
            self.send_response(status)
            self._headers(content_type)
            if retry_after:
                self.send_header("Retry-After", "1")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(content)
            self.wfile.flush()
            if status >= 400 and not self._body_read:
                # Closing with unread bytes can reset away the refusal on Windows.
                # Send first, then discard a bounded amount without trusting framing.
                deadline = time.monotonic() + HTTP_REFUSAL_DRAIN_SECONDS
                remaining = MAX_STAFF_COMMAND_BYTES + 1
                try:
                    self.connection.shutdown(socket.SHUT_WR)
                    while remaining and (wait := deadline - time.monotonic()) > 0:
                        self.connection.settimeout(wait)
                        chunk = self.rfile.read1(remaining)
                        if not chunk:
                            break
                        remaining -= len(chunk)
                except OSError:
                    pass  # peer gone or drain bound reached; never dispatch these bytes

        def _allowed(self, *, mutation: bool) -> bool:
            return _request_allowed(
                self.client_address[0],
                ",".join(self.headers.get_all("Host", [])),  # a repeated Host never matches
                self.headers.get("Origin"),
                int(self.server.server_address[1]),
                mutation=mutation,
            )

        def _json_request(self) -> dict[str, Any]:
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1 or self.headers.get_all("Transfer-Encoding"):
                raise ValueError("request_framing")
            length = lengths[0]
            if len(self.headers.get_all("Content-Type", [])) != 1 or self.headers.get_content_type() != "application/json" or not re.fullmatch(r"[0-9]{1,5}", length):
                raise ValueError("request_header")
            if int(length) > MAX_STAFF_COMMAND_BYTES:
                raise ValueError("request_size")
            deadline, data = time.monotonic() + HTTP_BODY_TIMEOUT_SECONDS, bytearray()
            try:
                while len(data) < int(length):
                    wait = deadline - time.monotonic()
                    if wait <= 0:
                        raise ValueError("request_timeout")
                    self.connection.settimeout(wait)
                    chunk = self.rfile.read1(int(length) - len(data))
                    if not chunk:
                        raise ValueError("request_short_body")
                    data.extend(chunk)
            finally:
                self.connection.settimeout(HTTP_REQUEST_TIMEOUT_SECONDS)
            self._body_read = True
            value = decode(data, "utf-8", _refuse_request_json("request_duplicate_key"), _refuse_request_json("request_nonstandard_number"))
            if type(value) is not dict:
                raise ValueError("request_shape")
            return value

        def do_GET(self) -> None:
            read, static = _READ_ROUTES.get(self.path), _STATIC_FILES.get(self.path)
            one = re.fullmatch(r"/api/items/([A-Za-z0-9._:-]{1,128})", self.path)
            if not self._allowed(mutation=False):
                self._respond(403, {"error": {"code": "loopback_origin_required"}})
            elif read is not None or one is not None:
                try:
                    value = workflow.item(one[1]) if one else getattr(workflow, read)()
                except KeyError:
                    self._respond(404, {"error": {"code": "not_found"}})
                    return
                except Exception:  # one detail-free refusal; no internal error reaches the client
                    self._respond(503, {"error": {"code": "owner_read_unavailable"}})
                else:
                    self._respond(200, value)
            elif static is None:
                self._respond(404, {"error": {"code": "not_found"}})
            else:
                try:
                    content = (_ROOT / static[0]).read_bytes()
                except OSError:
                    self._respond(503, {"error": {"code": "staff_ui_unavailable"}})
                else:
                    self._respond(200, content, static[1])

        def do_POST(self) -> None:
            command = _COMMAND_ROUTES.get(self.path)
            if not self._allowed(mutation=True):
                self._respond(403, {"error": {"code": "loopback_origin_required"}})
                return
            if command is None:
                self._respond(404, {"error": {"code": "not_found"}})
                return
            claimed = self.headers.get_all("X-Staff-Role", [])  # a caller claim, not a login: it can only narrow access to this command's row, never grant it; refused before the body is read
            if len(claimed) != 1 or claimed[0] not in COMMAND_ROLES.get(self.path, ()):
                self._respond(403, {"error": {"code": "staff_role_refused"}, "changed": False})
                return
            named = self.headers.get_all("X-Staff-Person", []) if command in _ACTOR_ROLE else []
            if named and not _person_fits(claimed[0], _ACTOR_ROLE[command], named):
                self._respond(403, {"error": {"code": "staff_person_refused"}, "changed": False})
                return
            actor = named[0] if named else None
            wanted = self.headers.get_all("X-Staff-Item", [])  # the item this command is for; none means item H
            item_id = wanted[0] if len(wanted) == 1 else H_ITEM_ID if not wanted else ""
            if not _ITEM_ID.fullmatch(item_id):
                self._respond(400, {"error": {"code": "invalid_request"}, "changed": False})
                return
            try:
                body = self._json_request()
            except (ValueError, RecursionError, OSError):  # malformed, truncated or timed-out body
                self._respond(400, {"error": {"code": "invalid_request"}})
                return
            try:
                if command in _TOKEN_COMMANDS and (code := workflow.check_token(command, item_id, self.headers.get_all("X-Action-Token", []))):
                    self._respond(409, {"error": {"code": code}, "changed": False})
                    return
                result = workflow.command(command, body, actor, item_id)
            except FinancialBusyError as exc:  # a transient lock: retry only a command that provably did not commit
                changed = getattr(exc, "changed", None)
                code = "store_busy_outcome_unknown" if changed is None else str(exc)
                self._respond(503, {"error": {"code": code}, "changed": changed}, retry_after=changed is False)
            except FinancialRevisionError as exc:
                self._respond(409, {"error": {"code": str(exc)}, "changed": False})
            except FinancialAuthorityError as exc:
                self._respond(403, {"error": {"code": str(exc)}, "changed": False})
            except FinancialError as exc:  # a failed restore also carries its safe support package
                self._respond(409, {"error": {"code": str(exc), **({"corporate_support": s} if (s := getattr(exc, "corporate_support", None)) else {})}})
            except ValueError:
                self._respond(400, {"error": {"code": "invalid_request"}})
            except Exception:
                self._respond(503, {"error": {"code": "owner_command_unavailable"}})
            else:
                self._respond(200, result)

    return Handler


class _LoopbackServer(ThreadingHTTPServer):
    daemon_threads = False
    block_on_close = True
    allow_reuse_address = False


def serve(
    port: int = 8765,
    *,
    workspace_dir: Path | None = None,
    resume_existing: bool = False,
) -> None:
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("port")
    workspace_dir = _validate_workspace_directory(
        workspace_dir,
        resume_existing=resume_existing,
    )
    with StaffWorkflow(
        workspace_dir,
        resume_existing=resume_existing,
    ) as workflow:
        server = _LoopbackServer(("127.0.0.1", port), _handler_for(workflow))
        actual_port = int(server.server_address[1])
        print("Synthetic RightRail staff workspace; local demo only.")
        print(f"Open http://127.0.0.1:{actual_port}/")
        print("No State credentials, authenticated source, production role map, payment movement, or dispatch.")
        if resume_existing:
            print("Reopened the caller-owned synthetic TEST Owner workspace after integrity verification.")
        try:
            server.serve_forever(poll_interval=0.25)
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765, help="loopback port; use 0 to select an available port")
    parser.add_argument("--workspace", type=Path, help="caller-owned directory for the synthetic Owner database")
    parser.add_argument(
        "--resume-existing-workspace",
        action="store_true",
        help="reopen and independently verify an existing TEST Owner database without reseeding it",
    )
    args = parser.parse_args(argv)
    if not 0 <= args.port <= 65535:
        parser.error("--port must be between 0 and 65535")
    if args.resume_existing_workspace and not args.workspace:
        parser.error("--resume-existing-workspace requires --workspace")
    try:
        serve(
            args.port,
            workspace_dir=args.workspace,
            resume_existing=args.resume_existing_workspace,
        )
    except (OSError, ValueError, FinancialError, financial_engine.FinancialEngineError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
