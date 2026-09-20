"""Focused real-persistence tests for the same-owner financial Mirror boundary."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

from app import right_rail_financial_owner as owner
from app.right_rail_financial_mirror import (
    FinancialMirror,
    FinancialMirrorContinuityError,
    FinancialMirrorDispatchError,
    MAX_PACKAGE_BYTES,
)
from tests.rightrail_financial_expected_cases import (
    CONTROL_PACK_V1,
    H_CASH_CENTS,
    H_ITEM_ID,
    H_OWED_CENTS,
    PERIOD_ONE_SCOPE,
    PROGRAM_ITEMS,
    UNAPPROVED_OFFSET_CENTS,
)


class _Clock:
    def __init__(self, value: int = 1_774_828_801_000) -> None:
        self.value = value

    def now_ms(self) -> int:
        self.value += 1
        return self.value


class FinancialMirrorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="right-rail-financial-mirror-")
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.db = self.root / "owner.sqlite"
        self.clock = _Clock()
        self.config = owner.FinancialOwnerConfig(
            state_id=PERIOD_ONE_SCOPE.state_id,
            deployment_id=PERIOD_ONE_SCOPE.deployment_id,
            program_id=PERIOD_ONE_SCOPE.program_id,
            period_id=PERIOD_ONE_SCOPE.period_id,
            currency=PERIOD_ONE_SCOPE.currency,
        )
        self.authority = owner.SyntheticTrustedAuthority()
        self.store = owner.FinancialOwner(
            path=self.db,
            config=self.config,
            trusted_authority=self.authority,
            clock=self.clock,
        )
        self._populate_owner()
        self.mirror = FinancialMirror(self.store)

    def _populate_owner(self) -> None:
        scope = CONTROL_PACK_V1.scope
        pack = owner.ControlPack(
            pack_id=CONTROL_PACK_V1.pack_id,
            state_id=scope.state_id,
            deployment_id=scope.deployment_id,
            program_id=scope.program_id,
            period_id=scope.period_id,
            version=CONTROL_PACK_V1.version,
            source_refs=CONTROL_PACK_V1.source_refs,
            effective_start_ms=CONTROL_PACK_V1.effective_start_ms,
            effective_end_ms=CONTROL_PACK_V1.effective_end_ms,
            recorded_at_ms=CONTROL_PACK_V1.recorded_at_ms,
            approved_at_ms=CONTROL_PACK_V1.approved_at_ms,
            calculation_rule_id=CONTROL_PACK_V1.calculation_rule_id,
            adjustment_rule_id=CONTROL_PACK_V1.adjustment_rule_id,
            authorized_roles=CONTROL_PACK_V1.authorized_roles,
            expected_tests=CONTROL_PACK_V1.expected_tests,
        )
        self.store.publish_control_pack(pack)
        items = tuple(
            owner.PopulationItem(
                population_id=item.population_id,
                item_id=item.item_id,
                display_label=item.display_label,
                owed_cents=item.owed_cents,
                due_at_ms=item.due_at_ms,
                currency=item.currency,
            )
            for item in PROGRAM_ITEMS
        )
        self.store.stage_population(
            population_id=items[0].population_id,
            pack_id=pack.pack_id,
            cutoff_ms=CONTROL_PACK_V1.effective_start_ms,
            inclusion_rules=("fixture-inclusion-v1",),
            expected_count=len(items),
            items=items,
        )
        self.store.validate_population(items[0].population_id)
        self.store.publish_population(items[0].population_id)

    def _prepare_claim(self) -> None:
        self.mirror.record_payment_evidence(
            item_id=H_ITEM_ID,
            payment_id="payment:p1",
            common_origin_id="origin:payment:p1",
            amount_cents=H_CASH_CENTS,
            evidence_id="evidence:payment:p1",
            event_at_ms=1_774_828_800_000,
        )
        self.store.record_offset_claim(
            item_id=H_ITEM_ID,
            claim_id="claim:offset:h",
            amount_cents=UNAPPROVED_OFFSET_CENTS,
            evidence_id="evidence:offset:claim:h",
            deadline_ms=1_774_915_200_000,
            expected_revision=1,
        )

    def _prepare_action(self) -> dict[str, object]:
        self._prepare_claim()
        receipt = self.mirror.current_evaluation_receipt(H_ITEM_ID)
        return self.mirror.reject_offset_and_authorize_correction(
            item_id=H_ITEM_ID,
            claim_id="claim:offset:h",
            action_id="action:correction:h",
            expected_revision=receipt["revision"],
            decision_at_ms=1_774_922_400_000,
            evaluation_id=receipt["evaluation_id"],
            evaluation_result_digest=receipt["result_digest"],
        )

    def test_queries_are_bounded_and_return_references_without_raw_payloads(self) -> None:
        first = self.mirror.list_obligations(status="ALL", limit=5, offset=0)
        second = self.mirror.list_obligations(status="ALL", limit=5, offset=5)
        self.assertEqual(first["count"], 5)
        self.assertEqual(first["next_offset"], 5)
        self.assertEqual(second["offset"], 5)
        self.assertTrue(set(row["item_id"] for row in first["items"]).isdisjoint(row["item_id"] for row in second["items"]))

        self._prepare_action()
        detail = self.mirror.obligation_detail(H_ITEM_ID, limit=50)
        self.assertEqual(detail["owed_cents"], H_OWED_CENTS)
        self.assertEqual(detail["shortfall_cents"], UNAPPROVED_OFFSET_CENTS)
        self.assertTrue(detail["evidence_references"])
        self.assertTrue(detail["action_references"])
        self.assertTrue(all("payload" not in row and "payload_json" not in row for row in detail["action_references"]))

        history = self.mirror.history(limit=20, offset=0)
        self.assertTrue(history["items"])
        self.assertTrue(all("payload" not in row and "payload_json" not in row for row in history["items"]))
        self.assertTrue(all(type(row["payload_digest"]) is str for row in history["items"]))

        action = self.mirror.action_payload("action:correction:h")
        self.assertNotIn("payload", action)
        self.assertNotIn("payload_json", action)
        self.assertEqual(action["payload_fields"]["amount_cents"], UNAPPROVED_OFFSET_CENTS)

    def test_commands_delegate_revision_and_authority_fences(self) -> None:
        self._prepare_claim()
        receipt = self.mirror.current_evaluation_receipt(H_ITEM_ID)
        with self.assertRaisesRegex(owner.FinancialRevisionError, "obligation_revision_conflict"):
            self.mirror.authorize_offset(
                item_id=H_ITEM_ID,
                claim_id="claim:offset:h",
                action_id="action:stale:h",
                expected_revision=1,
                evaluation_id=receipt["evaluation_id"],
                evaluation_result_digest=receipt["result_digest"],
            )
        with self.assertRaisesRegex(owner.FinancialAuthorityError, "authority_actor_not_authorized"):
            self.mirror.authorize_offset(
                item_id=H_ITEM_ID,
                claim_id="claim:offset:h",
                action_id="action:unauthorized:h",
                expected_revision=2,
                actor_id="synthetic-reporter",
                actor_role="FINANCE_DECISION",
                evaluation_id=receipt["evaluation_id"],
                evaluation_result_digest=receipt["result_digest"],
            )
        result = self.mirror.authorize_offset(
            item_id=H_ITEM_ID,
            claim_id="claim:offset:h",
            action_id="action:offset:h",
            expected_revision=2,
            decision_at_ms=1_774_864_800_000,
            evaluation_id=receipt["evaluation_id"],
            evaluation_result_digest=receipt["result_digest"],
        )
        self.assertEqual(result["status"], "AUTHORIZED")
        self.assertEqual(result["lawful_adjustment_cents"], UNAPPROVED_OFFSET_CENTS)
        self.assertEqual(result["received_cash_cents"], H_CASH_CENTS)

    def test_mirror_offset_authorization_retry_keeps_stored_time_and_rejects_conflicts(self) -> None:
        self._prepare_claim()
        receipt = self.mirror.current_evaluation_receipt(H_ITEM_ID)
        request = {
            "item_id": H_ITEM_ID,
            "claim_id": "claim:offset:h",
            "action_id": "action:retry-offset:h",
            "expected_revision": receipt["revision"],
            "decision_at_ms": 1_774_922_400_000,
            "evaluation_id": receipt["evaluation_id"],
            "evaluation_result_digest": receipt["result_digest"],
        }
        first = self.mirror.authorize_offset(**request)
        self.assertEqual(first["status"], "AUTHORIZED")
        after_first = self.mirror.summary()

        duplicate = self.mirror.authorize_offset(**request)
        self.assertEqual(duplicate["status"], "DUPLICATE")
        self.assertEqual(self.mirror.summary()["sequence"], after_first["sequence"])

        with self.assertRaisesRegex(owner.FinancialConflictError, "determination_request_conflict"):
            self.mirror.authorize_offset(**{**request, "decision_at_ms": request["decision_at_ms"] + 1})
        with self.assertRaisesRegex(owner.FinancialConflictError, "determination_request_conflict"):
            self.mirror.authorize_offset(**{**request, "evaluation_result_digest": "0" * 128})
        self.assertEqual(self.mirror.summary()["sequence"], after_first["sequence"])

    def test_mirror_correction_retry_keeps_stored_time_and_rejects_conflicts(self) -> None:
        self._prepare_claim()
        receipt = self.mirror.current_evaluation_receipt(H_ITEM_ID)
        request = {
            "item_id": H_ITEM_ID,
            "claim_id": "claim:offset:h",
            "action_id": "action:retry-correction:h",
            "expected_revision": receipt["revision"],
            "decision_at_ms": 1_774_922_400_000,
            "evaluation_id": receipt["evaluation_id"],
            "evaluation_result_digest": receipt["result_digest"],
        }
        first = self.mirror.reject_offset_and_authorize_correction(**request)
        self.assertEqual(first["status"], "CORRECTION_AUTHORIZED")
        after_first = self.mirror.summary()

        duplicate = self.mirror.reject_offset_and_authorize_correction(**request)
        self.assertEqual(duplicate["status"], "DUPLICATE")
        self.assertEqual(self.mirror.summary()["sequence"], after_first["sequence"])

        with self.assertRaisesRegex(owner.FinancialConflictError, "determination_request_conflict"):
            self.mirror.reject_offset_and_authorize_correction(**{**request, "decision_at_ms": request["decision_at_ms"] + 1})
        with self.assertRaisesRegex(owner.FinancialConflictError, "determination_request_conflict"):
            self.mirror.reject_offset_and_authorize_correction(**{**request, "claim_id": "claim:changed:h"})
        self.assertEqual(self.mirror.summary()["sequence"], after_first["sequence"])

    def test_reporting_correction_accepts_explicit_evidence_lineage(self) -> None:
        original = self.mirror.record_reporting_evidence(
            item_id=H_ITEM_ID,
            report_id="report:prior:h",
            evidence_id="evidence:report:prior:h",
            event_at_ms=1_774_828_800_000,
        )
        self.assertEqual(original["status"], "RECORDED")
        result = self.mirror.record_reporting_correction(
            item_id=H_ITEM_ID,
            report_id="report:correction:h",
            evidence_id="evidence:report:correction:h",
            supersedes="evidence:report:prior:h",
            expected_revision=1,
            event_at_ms=1_774_828_800_100,
        )
        self.assertEqual(result["status"], "RECORDED")
        detail = self.mirror.obligation_detail(H_ITEM_ID, limit=20)
        evidence = next(
            row for row in detail["evidence_references"]
            if row["evidence_id"] == "evidence:report:correction:h"
        )
        self.assertEqual(evidence["supersedes"], "evidence:report:prior:h")

    def test_reporting_default_timestamp_retries_are_stable_through_mirror(self) -> None:
        original = self.mirror.record_reporting_evidence(
            item_id=H_ITEM_ID,
            report_id="report:default:prior:h",
            evidence_id="evidence:report:default:prior:h",
        )
        self.assertEqual(original["status"], "RECORDED")
        original_revision = self.mirror.obligation_detail(H_ITEM_ID)["revision"]
        original_retry = self.mirror.record_reporting_evidence(
            item_id=H_ITEM_ID,
            report_id="report:default:prior:h",
            evidence_id="evidence:report:default:prior:h",
            expected_revision=0,
        )
        self.assertEqual(original_retry["status"], "DUPLICATE")
        first = self.mirror.record_reporting_correction(
            item_id=H_ITEM_ID,
            report_id="report:default:correction:h",
            evidence_id="evidence:report:default:correction:h",
            supersedes="evidence:report:default:prior:h",
            expected_revision=original_revision,
        )
        self.assertEqual(first["status"], "RECORDED")
        before = self.mirror.obligation_detail(H_ITEM_ID, limit=20)
        before_summary = self.mirror.summary()
        before_row = next(row for row in before["evidence_references"] if row["evidence_id"] == "evidence:report:default:correction:h")
        self.clock.value += 1_000_000
        retry = self.mirror.record_reporting_correction(
            item_id=H_ITEM_ID,
            report_id="report:default:correction:h",
            evidence_id="evidence:report:default:correction:h",
            supersedes="evidence:report:default:prior:h",
            expected_revision=original_revision,
        )
        self.assertEqual(retry["status"], "DUPLICATE")
        after = self.mirror.obligation_detail(H_ITEM_ID, limit=20)
        after_summary = self.mirror.summary()
        after_row = next(row for row in after["evidence_references"] if row["evidence_id"] == "evidence:report:default:correction:h")
        self.assertEqual(after_row["record_digest"], before_row["record_digest"])
        self.assertEqual(after_row["event_at_ms"], before_row["event_at_ms"])
        self.assertEqual(after_row["received_at_ms"], before_row["received_at_ms"])
        self.assertEqual(after["revision"], before["revision"])
        self.assertEqual(len(after["evaluation_references"]), len(before["evaluation_references"]))
        self.assertEqual(after_summary["sequence"], before_summary["sequence"])
        with self.assertRaisesRegex(owner.FinancialConflictError, "evidence_identity_conflict"):
            self.mirror.record_reporting_correction(
                item_id=H_ITEM_ID,
                report_id="report:default:correction:h",
                evidence_id="evidence:report:default:correction:h",
                supersedes="evidence:report:default:prior:h",
                expected_revision=original_revision,
                event_at_ms=int(before_row["event_at_ms"]) + 1,
            )
        self.assertEqual(self.mirror.summary()["sequence"], before_summary["sequence"])
        self.mirror.verify_integrity()

    def test_cli_reporting_correction_default_retry_and_identity_conflicts(self) -> None:
        from tools import right_rail_financial_cli as cli

        self.mirror.record_reporting_evidence(
            item_id=H_ITEM_ID,
            report_id="report:cli:prior:h",
            evidence_id="evidence:report:cli:prior:h",
            event_at_ms=1_700_000_000_000,
        )
        common = [
            "--database", str(self.db),
            "--state-id", self.config.state_id,
            "--deployment-id", self.config.deployment_id,
            "--program-id", self.config.program_id,
            "--period-id", self.config.period_id,
            "record-reporting-correction",
            "--item-id", H_ITEM_ID,
            "--report-id", "report:cli:correction:h",
            "--evidence-id", "evidence:report:cli:correction:h",
            "--supersedes", "evidence:report:cli:prior:h",
            "--expected-revision", "1",
        ]

        def invoke(args: list[str]) -> tuple[int, dict[str, object], str]:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = cli.main(args)
            output = json.loads(stdout.getvalue()) if stdout.getvalue() else {}
            return status, output, stderr.getvalue()

        status, first, stderr = invoke(common)
        self.assertEqual(status, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(first["status"], "RECORDED")
        before = self.mirror.obligation_detail(H_ITEM_ID, limit=20)
        before_summary = self.mirror.summary()
        before_row = next(row for row in before["evidence_references"] if row["evidence_id"] == "evidence:report:cli:correction:h")

        status, duplicate, stderr = invoke(common)
        self.assertEqual(status, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(duplicate["status"], "DUPLICATE")
        after = self.mirror.obligation_detail(H_ITEM_ID, limit=20)
        self.assertEqual(next(row for row in after["evidence_references"] if row["evidence_id"] == "evidence:report:cli:correction:h")["record_digest"], before_row["record_digest"])
        self.assertEqual(self.mirror.summary()["sequence"], before_summary["sequence"])

        status, _changed_time, stderr = invoke(common + ["--event-at-ms", str(int(before_row["event_at_ms"]) + 1)])
        self.assertEqual(status, 2)
        self.assertEqual(stderr, "ERROR:evidence_identity_conflict\n")
        status, _changed_payload, stderr = invoke(
            [value if value != "report:cli:correction:h" else "report:cli:changed:h" for value in common]
        )
        self.assertEqual(status, 2)
        self.assertEqual(stderr, "ERROR:evidence_identity_conflict\n")
        self.assertEqual(self.mirror.summary()["sequence"], before_summary["sequence"])
        self.mirror.verify_integrity()

    def test_v5_evaluation_receipt_is_mirror_and_cli_reference(self) -> None:
        from tools import right_rail_financial_cli as cli

        self._prepare_claim()
        receipt = self.mirror.current_evaluation_receipt(H_ITEM_ID)
        self.assertEqual(receipt["schema"], "RR/FINANCIAL/MIRROR/v1")
        self.assertEqual(receipt["resource"], "evaluation_receipt")
        self.assertEqual(receipt["evaluation_result_digest"], receipt["result_digest"])
        self.assertNotIn("raw_evidence", receipt)
        self.assertNotIn("payload", receipt)
        common = [
            "--database", str(self.db),
            "--state-id", self.config.state_id,
            "--deployment-id", self.config.deployment_id,
            "--program-id", self.config.program_id,
            "--period-id", self.config.period_id,
        ]

        def invoke(args: list[str]) -> tuple[int, dict[str, object], str]:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = cli.main(args)
            output = json.loads(stdout.getvalue()) if stdout.getvalue() else {}
            return status, output, stderr.getvalue()

        status, cli_receipt, stderr = invoke(common + ["current-evaluation-receipt", "--item-id", H_ITEM_ID])
        self.assertEqual(status, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(cli_receipt["evaluation_id"], receipt["evaluation_id"])
        self.assertEqual(cli_receipt["result_digest"], receipt["result_digest"])

        status, command, stderr = invoke(
            common
            + [
                "reject-offset-and-authorize-correction",
                "--item-id", H_ITEM_ID,
                "--claim-id", "claim:offset:h",
                "--action-id", "action:cli:correction:h",
                "--expected-revision", str(receipt["revision"]),
                "--decision-at-ms", "1774922400000",
                "--evaluation-id", str(receipt["evaluation_id"]),
                "--evaluation-result-digest", str(receipt["result_digest"]),
            ]
        )
        self.assertEqual(status, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(command["status"], "CORRECTION_AUTHORIZED")
        self.mirror.verify_integrity()

    def test_cli_authorize_offset_success_retry_and_binding_conflict(self) -> None:
        from tools import right_rail_financial_cli as cli

        self._prepare_claim()
        receipt = self.mirror.current_evaluation_receipt(H_ITEM_ID)
        common = [
            "--database", str(self.db),
            "--state-id", self.config.state_id,
            "--deployment-id", self.config.deployment_id,
            "--program-id", self.config.program_id,
            "--period-id", self.config.period_id,
            "authorize-offset",
            "--item-id", H_ITEM_ID,
            "--claim-id", "claim:offset:h",
            "--action-id", "action:cli:offset:h",
            "--expected-revision", str(receipt["revision"]),
            "--decision-at-ms", "1774864800000",
            "--evaluation-id", str(receipt["evaluation_id"]),
            "--evaluation-result-digest", str(receipt["result_digest"]),
        ]

        def invoke(args: list[str]) -> tuple[int, dict[str, object], str]:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = cli.main(args)
            return status, json.loads(stdout.getvalue()) if stdout.getvalue() else {}, stderr.getvalue()

        status, first, stderr = invoke(common)
        self.assertEqual(status, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(first["status"], "AUTHORIZED")
        after_first = self.mirror.summary()

        status, duplicate, stderr = invoke(common)
        self.assertEqual(status, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(duplicate["status"], "DUPLICATE")
        self.assertEqual(self.mirror.summary()["sequence"], after_first["sequence"])

        changed = list(common)
        changed[changed.index("--decision-at-ms") + 1] = "1774864800001"
        status, _changed, stderr = invoke(changed)
        self.assertEqual(status, 2)
        self.assertEqual(stderr, "ERROR:determination_request_conflict\n")
        self.assertEqual(self.mirror.summary()["sequence"], after_first["sequence"])
        self.mirror.verify_integrity()

    def test_continuity_export_validate_restore_restart_and_readback(self) -> None:
        self._prepare_action()
        package = self.mirror.export_continuity()
        metadata = self.mirror.validate_continuity_package(package)
        self.assertEqual(metadata["schema"], "RR/FINANCIAL/CONTINUITY/v5")
        self.assertEqual(metadata["version"], 5)
        self.assertEqual(metadata["scope"]["state_id"], self.config.state_id)
        self.assertIn("financial_meta", metadata["table_counts"])
        self.assertFalse(metadata["dispatch_enabled"])
        self.assertFalse(metadata["egress_enabled"])
        self.assertNotIn("rows", metadata)
        self.assertNotIn("tables", metadata)

        destination = self.root / "shadow.sqlite"
        shadow = self.mirror.restore_continuity(package, destination)
        self.assertTrue(destination.is_file())
        self.assertEqual(shadow.owner.mode, "SHADOW")
        self.assertEqual(shadow.owner.owner_id, "continuity-shadow-owner-v1")
        self.assertFalse(shadow.summary()["dispatch_enabled"])
        self.assertFalse(shadow.summary()["egress_enabled"])
        self.assertEqual(shadow.verify_integrity()["mode"], "SHADOW")
        self.assertEqual(shadow.obligation_detail(H_ITEM_ID)["shortfall_cents"], UNAPPROVED_OFFSET_CENTS)

        shadow.owner.close()
        reopened_owner = owner.FinancialOwner(
            path=destination,
            config=self.config,
            trusted_authority=self.authority,
            clock=_Clock(),
            mode="SHADOW",
            owner_id="continuity-shadow-owner-v1",
        )
        reopened = FinancialMirror(reopened_owner)
        self.assertEqual(reopened.obligation_detail(H_ITEM_ID)["case_status"], "CORRECTION_REQUIRED")
        self.assertEqual(reopened.verify_integrity()["mode"], "SHADOW")

    def test_continuity_tamper_oversize_source_overwrite_and_existing_destination_reject(self) -> None:
        package = self.mirror.export_continuity()
        tampered = json.loads(package.decode("ascii"))
        tampered["package_digest"] = "0" * 128
        tampered_bytes = json.dumps(tampered, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
        destination = self.root / "tampered-shadow.sqlite"
        with self.assertRaisesRegex(owner.FinancialContinuityError, "continuity_package_digest"):
            self.mirror.restore_continuity(tampered_bytes, destination)
        self.assertFalse(destination.exists())

        with self.assertRaisesRegex(FinancialMirrorContinuityError, "continuity_package_size"):
            self.mirror.restore_continuity(b"x" * (MAX_PACKAGE_BYTES + 1), self.root / "oversized.sqlite")
        self.assertFalse((self.root / "oversized.sqlite").exists())

        with self.assertRaisesRegex(FinancialMirrorContinuityError, "continuity_source_overwrite"):
            self.mirror.restore_continuity(package, self.db)
        self.assertTrue(self.db.is_file())

        existing = self.root / "existing.sqlite"
        existing.write_bytes(b"existing-destination")
        with self.assertRaisesRegex(FinancialMirrorContinuityError, "continuity_destination"):
            self.mirror.restore_continuity(package, existing)
        self.assertEqual(existing.read_bytes(), b"existing-destination")

    def test_dispatch_remains_rejected(self) -> None:
        with self.assertRaisesRegex(FinancialMirrorDispatchError, "dispatch_disabled"):
            self.mirror.dispatch_outbox()

    def test_cli_summary_is_local_and_redacted(self) -> None:
        from tools import right_rail_financial_cli as cli

        stdout = io.StringIO()
        stderr = io.StringIO()
        argv = [
            "--database", str(self.db),
            "--state-id", self.config.state_id,
            "--deployment-id", self.config.deployment_id,
            "--program-id", self.config.program_id,
            "--period-id", self.config.period_id,
            "summary",
        ]
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = cli.main(argv)
        self.assertEqual(status, 0)
        self.assertEqual(stderr.getvalue(), "")
        summary = json.loads(stdout.getvalue())
        self.assertEqual(summary["schema"], "RR/FINANCIAL/MIRROR/v1")
        self.assertFalse(summary["dispatch_enabled"])
        self.assertFalse(summary["egress_enabled"])


if __name__ == "__main__":
    unittest.main()
