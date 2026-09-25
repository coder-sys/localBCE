"""Loopback-only browser workspace for the synthetic RightRail staff workflow.

Run with ``python -m app.right_rail_financial_staff_server``. The service creates
an ephemeral synthetic Owner, serves a small local UI, and sends every operator
command through FinancialMirror to FinancialOwner. It has no authentication
integration, external source connector, payment movement, or dispatch path.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import urlsplit

from app import right_rail_financial_engine as financial_engine
from app.right_rail_financial_mirror import (
    FinancialMirror,
    FinancialMirrorError,
    MAX_PACKAGE_BYTES,
)
from app.right_rail_financial_owner import (
    ControlPack,
    FinancialAuthorityError,
    FinancialError,
    FinancialOwner,
    FinancialOwnerConfig,
    FinancialRevisionError,
    PopulationItem,
    PopulationManifest,
    SyntheticTrustedAuthority,
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
H_OBLIGATION_ID = "obligation:item-h:period-01"
MAX_RESTORE_DESTINATIONS = 1000
MAX_STAFF_COMMAND_BYTES = 8192
HTTP_REQUEST_TIMEOUT_SECONDS = 60.0

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
# Role is selected by path, never by query string: do_GET rejects any query
# or fragment outright, and a fixed set of real roles keeps every disallowed
# control absent from the page rather than merely disabled (Art. XIII.4).
STAFF_ROLES = ("analyst", "approver", "director", "auditor", "operator")
_STATIC_FILES: dict[str, tuple[str, str]] = {
    "/": ("staff_workspace/index.html", "text/html; charset=utf-8"),
    "/staff.css": ("staff_workspace/staff.css", "text/css; charset=utf-8"),
    "/staff.js": ("staff_workspace/staff.js", "text/javascript; charset=utf-8"),
    "/interaction-model.json": ("staff_workspace/interaction-model.json", "application/json; charset=utf-8"),
    **{f"/role/{role}": ("staff_workspace/index.html", "text/html; charset=utf-8") for role in STAFF_ROLES},
}
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


class StaffWorkflow:
    """Synthetic workspace backed by one current Owner/Mirror pair."""

    def __init__(
        self,
        workspace_dir: Path | None = None,
        *,
        correction_transition_release: object | None = None,
        resume_existing: bool = False,
    ) -> None:
        if type(resume_existing) is not bool or (resume_existing and workspace_dir is None):
            raise ValueError("workspace_resume_configuration")
        if resume_existing and correction_transition_release is None:
            raise ValueError("workspace_resume_requires_correction_release")
        if correction_transition_release is not None:
            correction_transition_release = financial_engine.require_correction_transition_v1(
                correction_transition_release
            )
            if type(correction_transition_release) is not financial_engine.FinancialCorrectionTransitionRelease:
                raise ValueError("correction_transition_release")
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
        self._authority = SyntheticTrustedAuthority()
        self._restore_number = 0
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
                correction_transition_release=correction_transition_release,
            )
        )
        self._gate_checks: list[dict[str, Any]] = []
        self._continuity = {
            "restored": False,
            "mode": "SYNTHETIC_LOCAL",
            "package_digest": None,
            "package_bytes": None,
            "decision_package_equal": None,
        }
        if resume_existing:
            self._verify_resumable_workspace()
        else:
            self._seed_synthetic_population()

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

    @property
    def gate_checks(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self._gate_checks]

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
            source_refs=("fixture-source:approved-schedule:v1",),
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
                received_at_ms=SUPPORT_EVENT_MS,
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
    def _review_values(body: dict[str, Any], *, with_receipt: bool = True) -> tuple[int, str | None, str | None]:
        required = {"revision"}
        if with_receipt:
            required |= {"evaluation_id", "evaluation_result_digest"}
        StaffWorkflow._require_object(body, required)
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

    def _review_dependencies(self, body: dict[str, Any]) -> tuple[int, str, str]:
        self._require_object(
            body,
            {"revision", "evaluation_id", "evaluation_result_digest", "read_binding"},
        )
        if type(body["read_binding"]) is not dict:
            raise ValueError("review_binding")
        revision, evaluation_id, result_digest = self._review_values(
            {
                "revision": body["revision"],
                "evaluation_id": body["evaluation_id"],
                "evaluation_result_digest": body["evaluation_result_digest"],
            }
        )
        if evaluation_id is None or result_digest is None:
            raise ValueError("review_binding")
        return revision, evaluation_id, result_digest

    def _owner_position(self) -> tuple[int, object]:
        """Measure the Owner's committed history position (sequence and head)."""
        owner = self._mirror.owner
        sequence = owner.summary().get("sequence")
        if type(sequence) is not int or sequence < 0:
            raise RuntimeError("owner_position_unavailable")
        if sequence == 0:
            return sequence, None
        latest = owner.history(limit=1, offset=sequence - 1)
        if len(latest) != 1 or latest[0].get("event_sequence") != sequence or latest[0].get("head") is None:
            raise RuntimeError("owner_position_unavailable")
        return sequence, latest[0]["head"]

    def _h_received_cash_cents(self) -> int:
        """Measure H's recorded cash from the Owner projection."""
        value = self._mirror.obligation_detail(H_ITEM_ID, limit=1).get("received_cash_cents")
        if type(value) is not int:
            raise RuntimeError("owner_cash_unavailable")
        return value

    def _gate_attempt(self, body: object, *, stale: bool) -> dict[str, Any]:
        payload = self._require_object(
            body,
            {"revision", "evaluation_id", "evaluation_result_digest", "read_binding"},
        )
        revision, evaluation_id, result_digest = self._review_dependencies(payload)
        if self._mirror.decision_package(H_ITEM_ID).get("current_determination") is not None:
            raise ValueError("gate_check_not_available_after_determination")
        if stale:
            actor_id = "synthetic-official"
            expected_revision = revision - 1
            expected_code = "obligation_revision_conflict"
            label = "Stale revision"
        else:
            actor_id = "synthetic-reporter"
            expected_revision = revision
            expected_code = "authority_actor_not_authorized"
            label = "Wrong role"
        position_before = self._owner_position()
        try:
            self._mirror.reject_offset_and_authorize_correction(
                item_id=H_ITEM_ID,
                claim_id=H_CLAIM_ID,
                actor_id=actor_id,
                actor_role="FINANCE_DECISION",
                expected_revision=expected_revision,
                action_id=H_ACTION_ID,
                decision_at_ms=DECISION_AT_MS,
                evaluation_id=evaluation_id,
                evaluation_result_digest=result_digest,
                staff_read_binding=payload["read_binding"],
            )
        except (FinancialError, FinancialMirrorError) as exc:
            code = str(exc)
        else:
            raise RuntimeError(f"demo_gate_unexpected_success:{label}")
        if code != expected_code:
            raise RuntimeError(f"demo_gate_verification:{label}")
        result = {
            "name": label,
            "status": "REJECTED",
            "code": code,
            "state_unchanged": self._owner_position() == position_before,
        }
        self._gate_checks = [row for row in self._gate_checks if row["name"] != label]
        self._gate_checks.append(result)
        return result

    def attempt_wrong_role(self, body: object) -> dict[str, Any]:
        with self._lock:
            result = self._gate_attempt(body, stale=False)
            return {"gate": result, "workspace": self._workspace_locked()}

    def attempt_stale_revision(self, body: object) -> dict[str, Any]:
        with self._lock:
            result = self._gate_attempt(body, stale=True)
            return {"gate": result, "workspace": self._workspace_locked()}

    def reject_offset_and_authorize_correction(self, body: object) -> dict[str, Any]:
        payload = self._require_object(
            body,
            {"revision", "evaluation_id", "evaluation_result_digest", "read_binding"},
        )
        with self._lock:
            revision, evaluation_id, result_digest = self._review_dependencies(payload)
            result = self._mirror.reject_offset_and_authorize_correction(
                item_id=H_ITEM_ID,
                claim_id=H_CLAIM_ID,
                actor_id="synthetic-official",
                actor_role="FINANCE_DECISION",
                expected_revision=revision,
                action_id=H_ACTION_ID,
                decision_at_ms=DECISION_AT_MS,
                evaluation_id=evaluation_id,
                evaluation_result_digest=result_digest,
                staff_read_binding=payload["read_binding"],
            )
            return {"command": result, "workspace": self._workspace_locked()}

    def acknowledge_correction_action(self, body: object) -> dict[str, Any]:
        payload = self._require_object(body, {"revision"})
        revision, _evaluation_id, _result_digest = self._review_values(payload, with_receipt=False)
        with self._lock:
            cash_before = self._h_received_cash_cents()
            result = self._mirror.acknowledge_action(
                H_ACTION_ID,
                "ack:correction:h:v1",
                actor_id="synthetic-receiver",
                actor_role="RECEIVER",
                expected_revision=revision,
            )
            cash_after = self._h_received_cash_cents()
            return {
                "command": result,
                "cash_before_cents": cash_before,
                "cash_after_cents": cash_after,
                "cash_effect_cents": cash_after - cash_before,
                "workspace": self._workspace_locked(),
            }

    def record_cash_correction(self, body: object) -> dict[str, Any]:
        payload = self._require_object(body, {"revision", "cash_command"})
        revision, _evaluation_id, _result_digest = self._review_values(
            {"revision": payload["revision"]},
            with_receipt=False,
        )
        cash_command = self._require_object(payload["cash_command"], set(CASH_CORRECTION_COMMAND))
        if cash_command != CASH_CORRECTION_COMMAND:
            raise ValueError("cash_command_binding")
        with self._lock:
            self._clock.advance_to(CORRECTION_EVENT_MS)
            result = self._mirror.record_payment_evidence(
                **cash_command,
                expected_revision=revision,
            )
            return {"command": result, "money_movement": False, "workspace": self._workspace_locked()}

    def record_reporting_evidence(self, body: object) -> dict[str, Any]:
        payload = self._require_object(body, {"revision"})
        revision, _evaluation_id, _result_digest = self._review_values(payload, with_receipt=False)
        with self._lock:
            self._clock.advance_to(REPORT_EVENT_MS)
            result = self._mirror.record_reporting_evidence(
                item_id=H_ITEM_ID,
                report_id="report:h:v1",
                evidence_id="evidence:report:h:original",
                actor_id="synthetic-reporter",
                actor_role="REPORTING_EDITOR",
                expected_revision=revision,
                event_at_ms=REPORT_EVENT_MS,
            )
            return {"command": result, "reporting_source": "SYNTHETIC_UNVERIFIED", "workspace": self._workspace_locked()}

    def _workspace_locked(self) -> dict[str, Any]:
        return self._mirror.staff_read_snapshot(
            {
                "resource": "workspace",
                "item_id": H_ITEM_ID,
                "population_id": POPULATION_ID,
                "status": "ALL",
                "limit": 100,
                "offset": 0,
                "detail_limit": 100,
                "history_limit": 200,
            },
            read_at=datetime.now(timezone.utc).isoformat(),
            labels=ITEM_LABELS,
            gate_checks=self.gate_checks,
            continuity=self._continuity,
        )

    def workspace(self) -> dict[str, Any]:
        with self._lock:
            return self._workspace_locked()

    def decision_view(self) -> dict[str, Any]:
        with self._lock:
            return self._mirror.staff_read_snapshot(
                {"resource": "decision_package", "item_id": H_ITEM_ID, "limit": 100, "offset": 0},
                read_at=datetime.now(timezone.utc).isoformat(),
            )

    @staticmethod
    def _staff_command_binding(view: dict[str, Any]) -> dict[str, Any]:
        envelope = view.get("read_envelope")
        package = view.get("decision_package")
        if type(envelope) is not dict or type(package) is not dict:
            raise ValueError("staff_command_binding")
        bindings = envelope.get("item_bindings")
        receipt = package.get("evaluation_receipt")
        if type(bindings) is not list or type(receipt) is not dict:
            raise ValueError("staff_command_binding")
        item_binding = next(
            (row for row in bindings if type(row) is dict and row.get("item_id") == H_ITEM_ID),
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

    def restore_test(self, body: object) -> dict[str, Any]:
        payload = self._require_object(
            body,
            {"revision", "evaluation_id", "evaluation_result_digest", "read_binding"},
        )
        revision, evaluation_id, result_digest = self._review_dependencies(payload)
        if evaluation_id is None or result_digest is None:
            raise ValueError("review_binding")
        with self._lock:
            if payload["read_binding"] != self._staff_command_binding(self.decision_view()):
                raise FinancialRevisionError("obligation_revision_conflict")
            before_package = self._mirror.decision_package(H_ITEM_ID, limit=100, offset=0)
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
            destination = self._next_restore_destination()
            restored = self._mirror.restore_test_continuity(package_bytes, destination)
            restored_package = restored.decision_package(H_ITEM_ID, limit=100, offset=0)
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
            self._mirror = restored
            self._continuity = {
                "restored": True,
                "mode": "TEST",
                "package_digest": str(restored.validate_owner_continuity_package(package_bytes)["package_digest"]),
                "package_bytes": len(package_bytes),
                "decision_package_equal": True,
            }
            return {"continuity": self.continuity, "workspace": self._workspace_locked()}

    def _next_restore_destination(self) -> Path:
        while self._restore_number < MAX_RESTORE_DESTINATIONS:
            self._restore_number += 1
            destination = self.workspace_dir / f"continuity-test-{self._restore_number:04d}.sqlite"
            if not _is_reparse_path(destination) and not destination.exists():
                return destination
        raise FinancialMirrorError("continuity_destination_capacity")


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _request_allowed(peer: str, host: str, origin: str | None, port: int, *, mutation: bool) -> bool:
    expected_host = f"127.0.0.1:{port}"
    expected_origin = f"http://{expected_host}"
    if peer != "127.0.0.1" or host != expected_host:
        return False
    if origin is not None and origin != expected_origin:
        return False
    if mutation and origin != expected_origin:
        return False
    return True


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

        def log_message(self, _format: str, *args: Any) -> None:
            # Avoid request paths or user activity in console logs.
            return

        def _headers(self, content_type: str) -> None:
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(self._response_length))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Connection", "close")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
            )

        def _respond(self, status: int, value: Any, content_type: str = "application/json; charset=utf-8") -> None:
            content = value if type(value) is bytes else _json_bytes(value)
            self._response_length = len(content)
            self.send_response(status)
            self._headers(content_type)
            self.end_headers()
            self.wfile.write(content)

        def _allowed(self, *, mutation: bool) -> bool:
            return _request_allowed(
                self.client_address[0],
                self.headers.get("Host", ""),
                self.headers.get("Origin"),
                int(self.server.server_address[1]),
                mutation=mutation,
            )

        def _json_request(self) -> dict[str, Any]:
            if self.headers.get_content_type() != "application/json":
                raise ValueError("content_type")
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError as exc:
                raise ValueError("content_length") from exc
            if length < 0 or length > MAX_STAFF_COMMAND_BYTES:
                raise ValueError("request_size")
            if length == 0:
                return {}
            value = json.loads(self.rfile.read(length).decode("utf-8"))
            if type(value) is not dict:
                raise ValueError("request_shape")
            return value

        def do_GET(self) -> None:
            if not self._allowed(mutation=False):
                self._respond(403, {"error": {"code": "loopback_origin_required"}})
                return
            path = urlsplit(self.path)
            if path.query or path.fragment:
                self._respond(404, {"error": {"code": "not_found"}})
                return
            if path.path == "/api/workspace":
                try:
                    self._respond(200, workflow.workspace())
                except (FinancialError, FinancialMirrorError, OSError, ValueError):
                    self._respond(503, {"error": {"code": "owner_read_unavailable"}})
                return
            if path.path == "/api/decision-package":
                try:
                    self._respond(200, workflow.decision_view())
                except (FinancialError, FinancialMirrorError, OSError, ValueError):
                    self._respond(503, {"error": {"code": "owner_read_unavailable"}})
                return
            if path.path == "/api/correction-followup":
                try:
                    self._respond(200, workflow.correction_followup())
                except (FinancialError, FinancialMirrorError, OSError, ValueError):
                    self._respond(503, {"error": {"code": "owner_read_unavailable"}})
                return
            static = _STATIC_FILES.get(path.path)
            if static is None:
                self._respond(404, {"error": {"code": "not_found"}})
                return
            relative_path, content_type = static
            try:
                content = (_ROOT / relative_path).read_bytes()
            except OSError:
                self._respond(503, {"error": {"code": "staff_ui_unavailable"}})
                return
            self._respond(200, content, content_type)

        def do_POST(self) -> None:
            if not self._allowed(mutation=True):
                self._respond(403, {"error": {"code": "loopback_origin_required"}})
                return
            try:
                body = self._json_request()
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                self._respond(400, {"error": {"code": "invalid_request"}})
                return
            routes: dict[str, Callable[[object], dict[str, Any]]] = {
                "/api/attempt/wrong-role": workflow.attempt_wrong_role,
                "/api/attempt/stale-revision": workflow.attempt_stale_revision,
                "/api/decision/reject-offset": workflow.reject_offset_and_authorize_correction,
                "/api/action/acknowledge": workflow.acknowledge_correction_action,
                "/api/correction/record-cash": workflow.record_cash_correction,
                "/api/reporting/record": workflow.record_reporting_evidence,
                "/api/continuity/restore-test": workflow.restore_test,
            }
            action = routes.get(urlsplit(self.path).path)
            if action is None or urlsplit(self.path).query or urlsplit(self.path).fragment:
                self._respond(404, {"error": {"code": "not_found"}})
                return
            try:
                result = action(body)
            except FinancialRevisionError as exc:
                self._respond(409, {"error": {"code": str(exc)}, "changed": False})
            except FinancialAuthorityError as exc:
                self._respond(403, {"error": {"code": str(exc)}, "changed": False})
            except FinancialError as exc:
                self._respond(409, {"error": {"code": str(exc)}})
            except FinancialMirrorError as exc:
                self._respond(409, {"error": {"code": str(exc)}})
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
    correction_transition_release: object | None = None,
    resume_existing: bool = False,
) -> None:
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("port")
    if resume_existing and correction_transition_release is None:
        raise ValueError("workspace_resume_requires_correction_release")
    workspace_dir = _validate_workspace_directory(
        workspace_dir,
        resume_existing=resume_existing,
    )
    with StaffWorkflow(
        workspace_dir,
        correction_transition_release=correction_transition_release,
        resume_existing=resume_existing,
    ) as workflow:
        server = _LoopbackServer(("127.0.0.1", port), _handler_for(workflow))
        actual_port = int(server.server_address[1])
        print("Synthetic RightRail staff workspace; local demo only.")
        print(f"Open http://127.0.0.1:{actual_port}/")
        print("No State credentials, authenticated source, production role map, payment movement, or dispatch.")
        if resume_existing:
            print("Reopened the caller-owned synthetic TEST Owner workspace after integrity verification.")
        if correction_transition_release is None:
            print("Correction transition is unavailable; correction commands fail closed.")
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
    parser.add_argument("--correction-transition-executable", type=Path)
    parser.add_argument("--correction-transition-workspace", type=Path)
    args = parser.parse_args(argv)
    if not 0 <= args.port <= 65535:
        parser.error("--port must be between 0 and 65535")
    has_executable = args.correction_transition_executable is not None
    has_engine_workspace = args.correction_transition_workspace is not None
    if has_executable != has_engine_workspace:
        parser.error("--correction-transition-executable and --correction-transition-workspace must be supplied together")
    if args.resume_existing_workspace and not args.workspace:
        parser.error("--resume-existing-workspace requires --workspace")
    if args.resume_existing_workspace and not has_executable:
        parser.error("--resume-existing-workspace requires the explicit correction Engine release")
    try:
        release = None
        if has_executable and has_engine_workspace:
            release = financial_engine.load_correction_transition_release(
                args.correction_transition_executable,
                args.correction_transition_workspace,
            )
        serve(
            args.port,
            workspace_dir=args.workspace,
            correction_transition_release=release,
            resume_existing=args.resume_existing_workspace,
        )
    except (OSError, ValueError, financial_engine.FinancialEngineError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
