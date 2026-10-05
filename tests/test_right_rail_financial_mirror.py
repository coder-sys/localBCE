"""Focused real-persistence tests for the same-owner financial Mirror boundary."""

from __future__ import annotations

from contextlib import ExitStack, closing, redirect_stderr, redirect_stdout
import dataclasses
import hashlib
import io
import json
from pathlib import Path
import re
import sqlite3
import tempfile
import unittest
from unittest import mock

from app import right_rail_financial_engine as financial_engine
from app import right_rail_financial_owner as owner
from app.right_rail_financial_mirror import (
    FinancialMirror,
    FinancialMirrorContinuityError,
    FinancialMirrorInputError,
    MAX_PACKAGE_BYTES,
)
from tests.rightrail_financial_expected_cases import (
    CONTINUITY,
    CONTROL_PACK_V1,
    CONTROL_PACK_V2,
    H_CASH_CENTS,
    H_ITEM_ID,
    H_OWED_CENTS,
    PERIOD_ONE_SCOPE,
    POPULATION_MANIFEST_V1,
    PROGRAM_ITEMS,
    UNAPPROVED_OFFSET_CENTS,
)
from tests.instruments.privacy_artifact_scan import scan_artifacts
from tests.test_right_rail_financial_acceptance import (
    _control_pack_from_fixture,
    _items_from_fixture,
    _population_manifest_from_fixture,
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
        self.config = owner.FinancialOwnerConfig(**dataclasses.asdict(PERIOD_ONE_SCOPE))
        self.authority = owner.SyntheticTrustedAuthority()
        self.store = owner.FinancialOwner(
            path=self.db,
            config=self.config,
            trusted_authority=self.authority,
            clock=self.clock,
        )
        self.addCleanup(self.store.close)  # R1a: the owner's writer holds the file open until closed
        self._populate_owner()
        self.mirror = FinancialMirror(self.store)

    def _authority_file(self) -> Path:
        from tools import right_rail_financial_cli as cli

        path = self.root / "trusted-authority.json"
        if not path.exists():
            path.write_text(json.dumps(cli.authority_file_record(self.authority)), encoding="ascii")
        return path

    def _cli_prefix(self, *, include_authority: bool = True) -> list[str]:
        prefix = ["--database", str(self.db)]
        if include_authority:
            prefix += ["--authority-file", str(self._authority_file())]
        return prefix + [
            "--state-id", self.config.state_id,
            "--deployment-id", self.config.deployment_id,
            "--program-id", self.config.program_id,
            "--period-id", self.config.period_id,
        ]

    @staticmethod
    def _invoke_cli(args: list[str]) -> tuple[int, str, str]:
        from tools import right_rail_financial_cli as cli

        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = cli.main(args)
        return status, stdout.getvalue(), stderr.getvalue()

    def _invoke_cli_json(self, args: list[str]) -> tuple[int, dict[str, object], str]:
        status, stdout, stderr = self._invoke_cli(args)
        return status, json.loads(stdout) if stdout else {}, stderr

    def _populate_owner(self) -> None:
        pack = _control_pack_from_fixture(CONTROL_PACK_V1)
        self.store.publish_control_pack(pack)
        manifest_fixture = POPULATION_MANIFEST_V1
        manifest = _population_manifest_from_fixture(manifest_fixture, self.authority)
        self.store.register_population_manifest(manifest)
        items = _items_from_fixture(PROGRAM_ITEMS, None)
        self.store.stage_population(
            population_id=items[0].population_id,
            manifest_id=manifest.manifest_id,
            pack_id=pack.pack_id,
            cutoff_ms=CONTROL_PACK_V1.effective_start_ms,
            inclusion_rules=manifest_fixture.inclusion_rules,
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

    @staticmethod
    def _reject_correction(target: FinancialMirror) -> dict[str, object]:
        receipt = target.current_evaluation_receipt(H_ITEM_ID)
        return target.reject_offset_and_authorize_correction(
            item_id=H_ITEM_ID,
            claim_id="claim:offset:h",
            action_id="action:correction:h",
            expected_revision=receipt["revision"],
            decision_at_ms=1_774_922_400_000,
            evaluation_id=receipt["evaluation_id"],
            evaluation_result_digest=receipt["result_digest"],
        )

    def _prepare_action(self) -> dict[str, object]:
        self._prepare_claim()
        self.clock.value = 1_774_922_399_999  # recorded when decided: a later event never commits before this one
        return self._reject_correction(self.mirror)

    def _followup(self) -> tuple[str, list[str]]:
        outputs = self.mirror.correction_followup_outputs(H_ITEM_ID, "action:correction:h")
        return outputs["followup_status"], outputs["state_report"]["changed_dependencies"]

    def _assert_privacy_clean(self, package: dict) -> None:  # the scanner reports the file itself, and nothing inside it
        directory = Path(tempfile.mkdtemp(dir=self.root))
        (directory / "support.json").write_text(json.dumps(package, sort_keys=True), encoding="utf-8")
        self.assertEqual(scan_artifacts(directory), ["item[000001]:unapproved_json_artifact_schema"])

    def _cancel_correction(self) -> None:  # no command cancels a correction; only a raw store edit can
        with closing(sqlite3.connect(self.db)) as connection, connection:
            for table in ("actions", "action_outbox"):
                connection.execute(f"UPDATE {table} SET status='CANCELLED' WHERE action_id='action:correction:h'")

    def test_correction_followup_outputs_resume_and_reopen_through_mirror(self) -> None:
        self._prepare_action()

        current = self.mirror.correction_followup_outputs(H_ITEM_ID, "action:correction:h")
        self.assertEqual(current["followup_status"], "CURRENT")
        self.assertEqual(current["resource"], "correction_followup")
        explanation = current["mirror_explanation"]
        report = current["state_report"]
        self.assertEqual(
            explanation["decision_package"],
            report["decision_package"],
        )
        self.assertEqual(explanation["decision_package"]["current_action"]["status"], "READY")
        support = current["corporate_support"]
        self.assertEqual(support, {
            "contract": "RR/FINANCIAL/CORPORATE-SUPPORT/v2", "status": "CURRENT", "component": "FINANCIAL_CORRECTION",
            "software_version": "NONE",
            "rule_version": {key: explanation["accepted_basis"]["control_pack"][key] for key in ("pack_id", "version", "digest")},
            "adapter_versions": {"population": "RR/FINANCIAL/POPULATION-MANIFEST/v1", "trust_graph_source_profile": "NONE"},
            "artifact": {
                "contract": financial_engine.CORRECTION_TRANSITION_OPERATION, "version": 1,
                "sha256": financial_engine.EVALUATOR_ARTIFACT_SHA256.hex().upper(),
            },
            "failure_stage": "NONE", "error_class": "NONE", "work_ref_count": 0,
            "reproduction": financial_engine.CORRECTION_TRANSITION_REPRODUCTION,
        })
        self._assert_privacy_clean(support)
        # the fictional reproduction is the published vector's case (fixture ids), never this record
        support_json = json.dumps({**support, "reproduction": None}, sort_keys=True)
        for private_value in (
            H_ITEM_ID,
            "action:correction:h",
            "obligation:",
            "evidence:",
        ):
            self.assertNotIn(private_value, support_json)

        self.assertEqual(report["changed_dependencies"], [])
        # A plain acknowledgment moves the head but no dependency value: the work stays closed.
        self.mirror.acknowledge_action("action:correction:h", "ack:correction:h:followup")
        self.assertEqual(self._followup(), ("CURRENT", []))
        # No command or event records a delivery rejection yet: a status no event explains needs review.
        self._cancel_correction()
        self.assertEqual(self._followup(), ("REVIEW_REQUIRED", []))
        drained = self.mirror.drain_correction_followups(limit=1)
        self.assertEqual(drained["count"], 1)
        review = drained["items"][0]["corporate_support"]
        self.assertEqual((review["error_class"], review["work_ref_count"]), ("UNSUPPORTED_DEPENDENCY", 1))
        # no store counter leaves the owner: no leaf value is the sequence (a substring test hit "10" inside the pin hex)
        sequence, leaves, stack = drained["items"][0]["source_event_sequence"], [], [review]
        while stack:
            node = stack.pop()
            stack.extend(node.values() if isinstance(node, dict) else node if isinstance(node, list) else ())
            leaves += [] if isinstance(node, (dict, list)) else [node]
        self.assertNotIn(sequence, leaves)
        self.assertNotIn(str(sequence), leaves)
        self._assert_privacy_clean(review)
        self.assertFalse(drained["has_more"])
        self.assertEqual(drained["skipped"], {"count": 0, "reasons": {}})

    def test_hospital_h_correction_reopens_only_when_its_offset_evidence_changes(self) -> None:
        self._prepare_action()
        other_item_id = next(item.item_id for item in PROGRAM_ITEMS if item.item_id != H_ITEM_ID)

        self.store.record_support_evidence(item_id=other_item_id, evidence_id="evidence:support:other", common_origin_id="origin:support:other")
        self.assertEqual(self._followup(), ("CURRENT", []))
        # This owner is scoped to period 01: the period-02 pack cannot reach H at all ...
        with self.assertRaisesRegex(owner.FinancialIntegrityError, "period_scope"):
            self.store.publish_control_pack(_control_pack_from_fixture(CONTROL_PACK_V2))
        # ... and a later period-01 pack touches RULE, but H stays bound to the pack it was decided under.
        later_pack = dataclasses.replace(
            _control_pack_from_fixture(CONTROL_PACK_V2), pack_id="control-pack:fixture-2026-01:v2", period_id=CONTROL_PACK_V1.scope.period_id,
        )
        self.assertEqual(self.store.publish_control_pack(later_pack)["status"], "PUBLISHED")
        self.assertEqual(self._followup(), ("CURRENT", []))
        support = self.mirror.correction_followup_outputs(H_ITEM_ID, "action:correction:h")
        accepted = support["mirror_explanation"]["accepted_basis"]["control_pack"]
        self.assertNotEqual(accepted["pack_id"], later_pack.pack_id)  # H is decided under the older pack, so the rule version is that pack, not the current one
        self.assertEqual(support["corporate_support"]["rule_version"], {key: accepted[key] for key in ("pack_id", "version", "digest")})
        self.store.record_offset_claim(
            item_id=H_ITEM_ID, claim_id="claim:offset:h2", amount_cents=1, evidence_id="evidence:offset:claim:h2", deadline_ms=1_774_915_200_000,
        )
        self.assertEqual(self._followup(), ("REOPENED", [f"COLLECTION(OFFSET_EVIDENCE, {H_ITEM_ID})"]))
        support = self.mirror.correction_followup_outputs(H_ITEM_ID, "action:correction:h")["corporate_support"]
        self.assertEqual((support["error_class"], support["work_ref_count"]), ("STALE_DEPENDENCY", 1))
        self._assert_privacy_clean(support)

    def test_mirror_refuses_a_support_package_that_is_not_the_approved_v2_shape(self) -> None:
        self._prepare_action()
        good = json.loads(json.dumps(self.store.correction_followup_outputs(H_ITEM_ID, "action:correction:h")))
        for name, edit in {
            "software version": lambda s: s.update(software_version="abc123"),
            "missing rule version": lambda s: s.pop("rule_version"),
            "old contract": lambda s: s.update(contract="RR/FINANCIAL/CORPORATE-SUPPORT/v1"),
            "another case": lambda s: s["reproduction"].update(case_id="case:other"),
            "no reproduction for the pinned engine": lambda s: s.update(reproduction="NONE"),
            "false is not a count of zero": lambda s: s.update(work_ref_count=False),
            "an old affected_work with ids": lambda s: s.update(affected_work={"count": 0, "ids": [1]}),
            "an extra top-level key": lambda s: s.update(note="member-private"),
            "an extra reproduction key": lambda s: s["reproduction"].update(extra="x"),
            "an extra artifact key": lambda s: s["artifact"].update(extra="x"),
            "an extra rule version key": lambda s: s["rule_version"].update(extra="x"),
            "an extra adapter key": lambda s: s["adapter_versions"].update(extra="x"),
        }.items():
            with self.subTest(name):
                bad = json.loads(json.dumps(good))
                edit(bad["corporate_support"])
                with mock.patch.object(self.store, "correction_followup_outputs", return_value=bad):
                    with self.assertRaisesRegex(FinancialMirrorContinuityError, "corporate_support_allowlist"):
                        self.mirror.correction_followup_outputs(H_ITEM_ID, "action:correction:h")

    def test_the_pack_named_in_a_support_package_has_fixed_shapes_or_none(self) -> None:
        self._prepare_action()
        good = json.loads(json.dumps(self.store.correction_followup_outputs(H_ITEM_ID, "action:correction:h")))

        def output(edit: object, *, no_basis: bool = False, rule_version: object = None) -> dict:
            bad = json.loads(json.dumps(good))
            for part in ("mirror_explanation", "state_report"):  # the two views must agree, so both carry the edit
                if no_basis:
                    bad[part]["accepted_basis"] = None
                else:
                    edit(bad[part]["accepted_basis"]["control_pack"])
            if rule_version is not None:
                bad["corporate_support"]["rule_version"] = rule_version
            else:
                edit(bad["corporate_support"]["rule_version"])
            return bad

        for name, edit in {
            "a free-text pack id": lambda p: p.update(pack_id="member Jane Doe"),
            "a bool version": lambda p: p.update(version=True),
            "a zero version": lambda p: p.update(version=0),
            "a short digest": lambda p: p.update(digest="AB"),
            "a lower-case digest": lambda p: p.update(digest=p["digest"].lower()),
        }.items():
            with self.subTest(name), mock.patch.object(self.store, "correction_followup_outputs", return_value=output(edit)):
                with self.assertRaisesRegex(FinancialMirrorContinuityError, "corporate_support_allowlist"):
                    self.mirror.correction_followup_outputs(H_ITEM_ID, "action:correction:h")
        with self.subTest("no accepted basis names no rule version"):
            with mock.patch.object(self.store, "correction_followup_outputs", return_value=output(None, no_basis=True, rule_version="NONE")):
                self.assertEqual(self.mirror.correction_followup_outputs(H_ITEM_ID, "action:correction:h")["corporate_support"]["rule_version"], "NONE")
            with mock.patch.object(self.store, "correction_followup_outputs", return_value=output(None, no_basis=True, rule_version=good["corporate_support"]["rule_version"])):
                with self.assertRaisesRegex(FinancialMirrorContinuityError, "corporate_support_allowlist"):
                    self.mirror.correction_followup_outputs(H_ITEM_ID, "action:correction:h")

    def test_a_failed_restore_gives_a_support_package_holding_only_its_fixed_failure_code(self) -> None:
        with self.assertRaises(FinancialMirrorContinuityError) as mirror_failure:
            self.mirror.restore_continuity(self.mirror.export_continuity(), self.db)
        with self.assertRaises(owner.FinancialContinuityError) as owner_failure:
            self.mirror.restore_continuity(b"{}", self.root / "not-a-package.sqlite")
        for error, code in (
            (mirror_failure.exception, "continuity_source_overwrite"), (owner_failure.exception, "continuity_package_shape"),
            (ValueError("continuity_x member-name-private"), "UNCLASSIFIED"), (RuntimeError("continuity_Bad"), "UNCLASSIFIED"),
            (RuntimeError("continuity_history_head"), "UNCLASSIFIED"),  # a known code from a class that is not ours
            (owner.FinancialContinuityError("continuity_new_unlisted_code"), "UNCLASSIFIED"),  # ours, but not in the closed tuple
            (owner.FinancialContinuityError("continuity_identity:member-name"), "UNCLASSIFIED"),
        ):
            support = FinancialMirror.continuity_restore_support(error)
            self.assertEqual((support["rule_version"], support["adapter_versions"]["population"]), ("NONE", "NONE"))  # nothing was read
            self.assertEqual(support["work_ref_count"], 0)
            self.assertEqual((support["status"], support["component"], support["failure_stage"], support["error_class"]), ("FAILED", "CONTINUITY", "RESTORE", code))
            self.assertNotIn("private", json.dumps(support))
            self._assert_privacy_clean(support)

    def test_a_failed_restore_carries_its_support_package_on_the_raised_error(self) -> None:
        with self.assertRaises(FinancialMirrorContinuityError) as failure:
            self.mirror.restore_continuity(self.mirror.export_continuity(), self.db)
        self.assertEqual(failure.exception.corporate_support, FinancialMirror.continuity_restore_support(failure.exception))
        self.assertEqual(failure.exception.corporate_support["error_class"], "continuity_source_overwrite")

    def test_the_restore_code_list_holds_every_code_the_restore_path_can_raise(self) -> None:
        root = Path(financial_engine.__file__).parent
        found = set()
        for name in ("right_rail_financial_owner.py", "right_rail_financial_mirror.py"):
            text = (root / name).read_text(encoding="utf-8")
            found |= set(re.findall(r'_fail\([^,]+,\s*f?"(continuity_[a-z0-9_:-]+)"', text))
            found |= {"continuity_identity:" + sub for sub in re.findall(r'f"\{code_prefix\}:([a-z_-]+)"', text)}
        named = {"continuity_history_head", "continuity_package_digest", "continuity_shadow_boundary", "continuity_test_boundary"}
        self.assertTrue(found)
        self.assertEqual({code for code in found | named if "{" not in code} - set(owner.CONTINUITY_ERROR_CODES), set())
        self.assertEqual(len(set(owner.CONTINUITY_ERROR_CODES)), len(owner.CONTINUITY_ERROR_CODES))

    def test_the_reproduction_names_a_case_in_the_pinned_vector_result(self) -> None:
        vectors = Path(__file__).resolve().parents[1] / "artifacts" / "engine-correction" / "vectors"
        reproduction = financial_engine.CORRECTION_TRANSITION_REPRODUCTION
        self.assertEqual(hashlib.sha256((vectors / "request.bin").read_bytes()).hexdigest().upper(), reproduction["vector_file_digest"])
        self.assertIn(reproduction["case_id"].encode(), (vectors / "result.expected.bin").read_bytes())

    def test_a_resent_payment_confirmation_keeps_the_correction_closed(self) -> None:
        self._prepare_action()

        payment = {"item_id": H_ITEM_ID, "event_at_ms": 1_774_828_800_000}
        resent = self.mirror.record_payment_evidence(
            **payment, payment_id="payment:p1:resent", common_origin_id="origin:payment:p1",
            amount_cents=H_CASH_CENTS, evidence_id="evidence:payment:p1:resent",
        )
        self.assertEqual(resent["status"], "DUPLICATE")
        self.assertEqual(self._followup(), ("CURRENT", []))
        self.mirror.record_payment_evidence(
            **payment, payment_id="payment:p2", common_origin_id="origin:payment:p2", amount_cents=1, evidence_id="evidence:payment:p2",
        )
        self.assertEqual(self._followup(), ("REOPENED", [f"COLLECTION(PAYMENT_EVIDENCE, {H_ITEM_ID})"]))

    def test_correction_followup_fails_closed_on_an_unknown_event_kind(self) -> None:
        self._prepare_action()
        other_item_id = next(item.item_id for item in PROGRAM_ITEMS if item.item_id != H_ITEM_ID)
        with mock.patch.dict(owner._FOLLOWUP_TOUCHES):
            del owner._FOLLOWUP_TOUCHES["EVALUATION_RECORDED"]
            self.store.evaluate_obligation(other_item_id)
            outputs = self.mirror.correction_followup_outputs(H_ITEM_ID, "action:correction:h")
        self.assertEqual((outputs["followup_status"], outputs["state_report"]["changed_dependencies"]), ("REVIEW_REQUIRED", []))
        self.assertEqual(outputs["corporate_support"]["error_class"], "UNSUPPORTED_DEPENDENCY")
        self.assertEqual(self.mirror.correction_followup_outputs(H_ITEM_ID, "action:correction:h")["followup_status"], "CURRENT")

    def test_each_later_fact_about_h_reopens_its_correction_and_nothing_else_does(self) -> None:
        payment = {"item_id": H_ITEM_ID, "event_at_ms": 1_774_828_800_000}
        cases = {
            "the payment the correction requested": (lambda: self.store.record_payment_evidence(
                **payment, payment_id="payment:own", common_origin_id="origin:payment:own", amount_cents=1,
                evidence_id="evidence:payment:own", pays_action_id="action:correction:h"), "CURRENT", None),
            "a same-inputs re-evaluation": (lambda: self.store.evaluate_obligation(H_ITEM_ID), "CURRENT", None),
            "a reversal of the bound payment": (lambda: self.store.reverse_payment(
                item_id=H_ITEM_ID, payment_id="payment:p1", evidence_id="evidence:reversal:p1"), "REOPENED", "PAYMENT_EVIDENCE"),
            "a conflicting amount for the bound origin": (lambda: self.store.record_payment_evidence(
                **payment, payment_id="payment:p1:conflict", common_origin_id="origin:payment:p1", amount_cents=H_CASH_CENTS - 1,
                evidence_id="evidence:payment:p1:conflict"), "REOPENED", "PAYMENT_EVIDENCE"),
            "new support evidence on H": (lambda: self.store.record_support_evidence(
                item_id=H_ITEM_ID, evidence_id="evidence:support:h", common_origin_id="origin:support:h"), "REOPENED", "SUPPORT_EVIDENCE"),
            "a cancellation no event explains": (self._cancel_correction, "REVIEW_REQUIRED", None),
        }
        for name, (act, status, family) in cases.items():
            with self.subTest(name):
                self.setUp()
                self._prepare_action()
                act()
                self.assertEqual(self._followup(), (status, [f"COLLECTION({family}, {H_ITEM_ID})"] if family else []))

    def test_mirror_refuses_an_inconsistent_changed_dependencies_list(self) -> None:
        self._prepare_action()
        current = self.store.correction_followup_outputs(H_ITEM_ID, "action:correction:h")
        self.mirror._validated_correction_followup_output(current)
        key = f"COLLECTION(PAYMENT_EVIDENCE, {H_ITEM_ID})"
        for status, changed, report_changed in (
            ("REOPENED", [key, "A"], None),  # unsorted
            ("REOPENED", [key, key], None),  # repeated
            ("REOPENED", key, None),  # not a list
            ("REOPENED", [1], None),  # not strings
            ("REOPENED", [], None),  # REOPENED names what moved
            ("CURRENT", [key], None),  # CURRENT names nothing
            ("REOPENED", [key], []),  # the explanation and the report disagree
        ):
            with self.subTest(status=status, changed=changed, report_changed=report_changed):
                raw = json.loads(json.dumps(current))
                raw["followup_status"] = raw["mirror_explanation"]["followup_status"] = raw["state_report"]["followup_status"] = status
                raw["mirror_explanation"]["changed_dependencies"] = changed
                raw["state_report"]["changed_dependencies"] = changed if report_changed is None else report_changed
                with self.assertRaisesRegex(FinancialMirrorContinuityError, "^correction_followup_projection$"):
                    self.mirror._validated_correction_followup_output(raw)

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

    def test_c05_decision_package_is_sanitized_bounded_and_ack_is_not_cash(self) -> None:
        self._prepare_action()
        self.mirror.acknowledge_action("action:correction:h", "ack:correction:h:v1")
        sequence_after_ack = self.mirror.summary()["sequence"]
        durable_snapshot_before = self.store.export_continuity()

        owner_receipt = self.store.current_evaluation_receipt(H_ITEM_ID)
        self.assertIn("input_snapshot_digest", owner_receipt)
        mirror_receipt = self.mirror.current_evaluation_receipt(H_ITEM_ID)
        self.assertEqual(mirror_receipt["input_snapshot_digest"], owner_receipt["input_snapshot_digest"])
        owner_package = self.store.decision_package(H_ITEM_ID, limit=1, offset=0)
        self.assertIn("input_snapshot_digest", owner_package["evaluation_receipt"])

        first = self.mirror.decision_package(H_ITEM_ID, limit=1, offset=0)
        second = self.mirror.decision_package(H_ITEM_ID, limit=1, offset=1)
        self.assertEqual(first["schema"], "RR/FINANCIAL/MIRROR/v1")
        self.assertEqual(first["resource"], "decision_package")
        self.assertEqual(first["contract"], "RR/FINANCIAL/DECISION-PACKAGE/v3")
        self.assertEqual(first["cash"]["recorded_received_cash_cents"], H_CASH_CENTS)
        self.assertEqual(first["cash"]["shortfall_cents"], UNAPPROVED_OFFSET_CENTS)
        self.assertEqual(first["current_action"]["status"], "ACKNOWLEDGED")
        self.assertEqual(first["current_action"]["acknowledgment"]["cash_effect_cents"], 0)
        self.assertEqual(first["conclusions"]["action_acknowledgment"]["cash_effect_cents"], 0)
        self.assertNotIn("input_snapshot_digest", first["evaluation_receipt"])
        self.assertEqual(
            first["population_binding"],
            {
                "status": "PUBLISHED",
                "completeness": "EXACT",
                "source_complete": True,
                "manifest_version": 1,
                "member_count": len(PROGRAM_ITEMS),
            },
        )
        self.assertNotIn("population_id", first["obligation"])
        self.assertNotIn("population_id", self.mirror.list_obligations()["items"][0])
        self.assertNotIn("population_id", self.mirror.obligation_detail(H_ITEM_ID))
        first_ids = {row["evidence_id"] for row in first["references"]["evidence"]["items"]}
        second_ids = {row["evidence_id"] for row in second["references"]["evidence"]["items"]}
        self.assertEqual(first["references"]["evidence"]["next_offset"], 1)
        self.assertEqual(second["references"]["evidence"]["offset"], 1)
        self.assertTrue(first_ids.isdisjoint(second_ids))
        self.assertEqual(self.mirror.summary()["sequence"], sequence_after_ack)
        self.assertEqual(self.store.export_continuity(), durable_snapshot_before)

        def collect_keys(value: object) -> set[str]:
            if type(value) is dict:
                return {str(key) for key in value} | set().union(*(collect_keys(item) for item in value.values()))
            if type(value) is list:
                return set().union(*(collect_keys(item) for item in value)) if value else set()
            return set()

        forbidden = {
            "payload",
            "payload_json",
            "input_snapshot",
            "input_snapshot_json",
            "input_snapshot_digest",
            "content_digest",
            "display_label",
            "population_id",
            "manifest_id",
            "manifest_digest",
            "member_id",
            "member_ids",
            "member_digest",
            "source_digest",
            "source_owner_id",
            "approval_ref",
        }
        self.assertFalse(forbidden.intersection(collect_keys(first)))
        population_history = [
            row
            for row in self.mirror.history(limit=200)["items"]
            if row.get("aggregate_type") in {"POPULATION", "POPULATION_MANIFEST"}
        ]
        self.assertTrue(population_history)
        self.assertTrue(all("aggregate_id" not in row for row in population_history))
        with self.assertRaisesRegex(FinancialMirrorInputError, "decision_package_page"):
            self.mirror.decision_package(H_ITEM_ID, limit=201)

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
        self.clock.value = 1_774_864_800_000  # recorded when decided
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

    def _assert_decision_retry_keeps_stored_time(self, method: str, action_id: str, status: str, conflicting: dict[str, object]) -> None:
        self._prepare_claim()
        receipt = self.mirror.current_evaluation_receipt(H_ITEM_ID)
        request = {
            "item_id": H_ITEM_ID,
            "claim_id": "claim:offset:h",
            "action_id": action_id,
            "expected_revision": receipt["revision"],
            "decision_at_ms": 1_774_922_400_000,
            "evaluation_id": receipt["evaluation_id"],
            "evaluation_result_digest": receipt["result_digest"],
        }
        decide = getattr(self.mirror, method)
        self.clock.value = 1_774_922_400_000  # recorded when decided
        first = decide(**request)
        self.assertEqual(first["status"], status)
        after_first = self.mirror.summary()

        duplicate = decide(**request)
        self.assertEqual(duplicate["status"], "DUPLICATE")
        self.assertEqual(self.mirror.summary()["sequence"], after_first["sequence"])

        for change in ({"decision_at_ms": request["decision_at_ms"] - 1}, conflicting):
            with self.assertRaisesRegex(owner.FinancialConflictError, "determination_request_conflict"):
                decide(**{**request, **change})
        self.assertEqual(self.mirror.summary()["sequence"], after_first["sequence"])

    def test_mirror_offset_authorization_retry_keeps_stored_time_and_rejects_conflicts(self) -> None:
        self._assert_decision_retry_keeps_stored_time(
            "authorize_offset", "action:retry-offset:h", "AUTHORIZED", {"evaluation_result_digest": "0" * 128},
        )

    def test_mirror_correction_retry_keeps_stored_time_and_rejects_conflicts(self) -> None:
        self._assert_decision_retry_keeps_stored_time(
            "reject_offset_and_authorize_correction", "action:retry-correction:h", "CORRECTION_AUTHORIZED",
            {"claim_id": "claim:changed:h"},
        )

    def test_correction_refuses_a_known_actor_without_the_decision_role_and_changes_nothing(self) -> None:
        self._prepare_claim()
        receipt = self.mirror.current_evaluation_receipt(H_ITEM_ID)
        before = self.store.export_continuity()
        with self.assertRaisesRegex(owner.FinancialAuthorityError, "authority_actor_not_authorized"):
            self.mirror.reject_offset_and_authorize_correction(
                item_id=H_ITEM_ID,
                claim_id="claim:offset:h",
                actor_id="synthetic-reporter",
                actor_role="FINANCE_DECISION",
                action_id="action:wrong-role:h",
                expected_revision=receipt["revision"],
                decision_at_ms=1_774_922_400_000,
                evaluation_id=receipt["evaluation_id"],
                evaluation_result_digest=receipt["result_digest"],
            )
        self.assertEqual(self.store.export_continuity(), before)

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
        def correct() -> dict[str, object]:
            return self.mirror.record_reporting_correction(
                item_id=H_ITEM_ID, report_id="report:default:correction:h", evidence_id="evidence:report:default:correction:h",
                supersedes="evidence:report:default:prior:h", expected_revision=original_revision,
            )

        first = correct()
        self.assertEqual(first["status"], "RECORDED")
        before = self.mirror.obligation_detail(H_ITEM_ID, limit=20)
        before_summary = self.mirror.summary()
        before_row = next(row for row in before["evidence_references"] if row["evidence_id"] == "evidence:report:default:correction:h")
        self.clock.value += 1_000_000
        retry = correct()
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
        self.mirror.record_reporting_evidence(
            item_id=H_ITEM_ID,
            report_id="report:cli:prior:h",
            evidence_id="evidence:report:cli:prior:h",
            event_at_ms=1_700_000_000_000,
        )
        common = self._cli_prefix() + [
            "record-reporting-correction",
            "--item-id", H_ITEM_ID,
            "--report-id", "report:cli:correction:h",
            "--evidence-id", "evidence:report:cli:correction:h",
            "--supersedes", "evidence:report:cli:prior:h",
            "--actor-id", "synthetic-reporter",
            "--actor-role", "REPORTING_EDITOR",
            "--expected-revision", "1",
        ]

        status, first, stderr = self._invoke_cli_json(common)
        self.assertEqual(status, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(first["status"], "RECORDED")
        before = self.mirror.obligation_detail(H_ITEM_ID, limit=20)
        before_summary = self.mirror.summary()
        before_row = next(row for row in before["evidence_references"] if row["evidence_id"] == "evidence:report:cli:correction:h")

        status, duplicate, stderr = self._invoke_cli_json(common)
        self.assertEqual(status, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(duplicate["status"], "DUPLICATE")
        after = self.mirror.obligation_detail(H_ITEM_ID, limit=20)
        self.assertEqual(next(row for row in after["evidence_references"] if row["evidence_id"] == "evidence:report:cli:correction:h")["record_digest"], before_row["record_digest"])
        self.assertEqual(self.mirror.summary()["sequence"], before_summary["sequence"])

        status, _changed_time, stderr = self._invoke_cli_json(common + ["--event-at-ms", str(int(before_row["event_at_ms"]) + 1)])
        self.assertEqual(status, 2)
        self.assertEqual(stderr, "ERROR:evidence_identity_conflict\n")
        status, _changed_payload, stderr = self._invoke_cli_json(
            [value if value != "report:cli:correction:h" else "report:cli:changed:h" for value in common]
        )
        self.assertEqual(status, 2)
        self.assertEqual(stderr, "ERROR:evidence_identity_conflict\n")
        self.assertEqual(self.mirror.summary()["sequence"], before_summary["sequence"])
        self.mirror.verify_integrity()

    def test_v5_evaluation_receipt_is_mirror_and_cli_reference(self) -> None:
        self._prepare_claim()
        receipt = self.mirror.current_evaluation_receipt(H_ITEM_ID)
        self.assertEqual(receipt["schema"], "RR/FINANCIAL/MIRROR/v1")
        self.assertEqual(receipt["resource"], "evaluation_receipt")
        self.assertEqual(receipt["evaluation_result_digest"], receipt["result_digest"])
        self.assertNotIn("raw_evidence", receipt)
        self.assertNotIn("payload", receipt)
        common = self._cli_prefix()

        status, cli_receipt, stderr = self._invoke_cli_json(common + ["current-evaluation-receipt", "--item-id", H_ITEM_ID])
        self.assertEqual(status, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(cli_receipt["evaluation_id"], receipt["evaluation_id"])
        self.assertEqual(cli_receipt["result_digest"], receipt["result_digest"])

        status, command, stderr = self._invoke_cli_json(
            common
            + [
                "reject-offset-and-authorize-correction",
                "--item-id", H_ITEM_ID,
                "--claim-id", "claim:offset:h",
                "--action-id", "action:cli:correction:h",
                "--actor-id", "synthetic-official",
                "--actor-role", "FINANCE_DECISION",
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
        self._prepare_claim()
        self.clock.value = 1_774_864_800_000  # recorded when decided, not at today's wall time (S2: no backdating past due)
        self.enterContext(mock.patch.object(owner._SystemClock, "now_ms", lambda _clock: self.clock.now_ms()))
        receipt = self.mirror.current_evaluation_receipt(H_ITEM_ID)
        common = self._cli_prefix() + [
            "authorize-offset",
            "--item-id", H_ITEM_ID,
            "--claim-id", "claim:offset:h",
            "--action-id", "action:cli:offset:h",
            "--actor-id", "synthetic-official",
            "--actor-role", "FINANCE_DECISION",
            "--expected-revision", str(receipt["revision"]),
            "--decision-at-ms", "1774864800000",
            "--evaluation-id", str(receipt["evaluation_id"]),
            "--evaluation-result-digest", str(receipt["result_digest"]),
        ]

        status, first, stderr = self._invoke_cli_json(common)
        self.assertEqual(status, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(first["status"], "AUTHORIZED")
        after_first = self.mirror.summary()

        status, duplicate, stderr = self._invoke_cli_json(common)
        self.assertEqual(status, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(duplicate["status"], "DUPLICATE")
        self.assertEqual(self.mirror.summary()["sequence"], after_first["sequence"])

        changed = list(common)
        changed[changed.index("--decision-at-ms") + 1] = "1774864800001"
        status, _changed, stderr = self._invoke_cli_json(changed)
        self.assertEqual(status, 2)
        self.assertEqual(stderr, "ERROR:determination_request_conflict\n")
        self.assertEqual(self.mirror.summary()["sequence"], after_first["sequence"])
        self.mirror.verify_integrity()

    def test_cli_payment_link_reaches_the_owner(self) -> None:
        sequence = self.mirror.summary()["sequence"]
        status, _output, stderr = self._invoke_cli(self._cli_prefix() + [
            "record-payment-evidence", "--item-id", H_ITEM_ID, "--payment-id", "payment:cli:h", "--common-origin-id", "origin:cli:h",
            "--amount-cents", "1", "--evidence-id", "evidence:cli:h", "--event-at-ms", "1",
            "--expected-revision", str(self.mirror.obligation_detail(H_ITEM_ID)["revision"]), "--pays-action-id", "action:cli:none",
        ])
        self.assertEqual((status, stderr), (2, "ERROR:payment_request_unknown\n"))
        self.assertEqual(self.mirror.summary()["sequence"], sequence)

    def test_cli_mutations_require_explicit_actor_and_expected_revision(self) -> None:
        from tools import right_rail_financial_cli as cli

        common = self._cli_prefix()
        actor = ["--actor-id", "synthetic-official", "--actor-role", "FINANCE_DECISION", "--expected-revision", "1"]
        offset = ["--item-id", H_ITEM_ID, "--claim-id", "claim:offset:h", "--evaluation-id", "evaluation:h", "--evaluation-result-digest", "0" * 64]
        commands = {
            "authorize-offset": offset + actor,
            "reject-offset-and-authorize-correction": offset + actor,
            "acknowledge-action": ["--action-id", "action:h", "--acknowledgment-ref", "ack:h"] + actor,
            "record-reporting-correction": ["--item-id", H_ITEM_ID, "--report-id", "report:h"] + actor,
            "record-payment-evidence": [
                "--item-id", H_ITEM_ID, "--payment-id", "payment:h", "--common-origin-id", "origin:h",
                "--amount-cents", "1", "--evidence-id", "evidence:h", "--event-at-ms", "1",
                "--expected-revision", "1",
            ],
        }

        def without(args: list[str], flag: str) -> list[str]:
            index = args.index(flag)
            return args[:index] + args[index + 2:]

        before_bytes = self.db.read_bytes()
        refusals = 0
        for command, args in commands.items():
            for flag in ("--actor-id", "--actor-role", "--expected-revision"):
                if flag not in args:
                    continue
                stderr = io.StringIO()
                with redirect_stdout(io.StringIO()), redirect_stderr(stderr), self.assertRaises(SystemExit) as refused:
                    cli.main(common + [command] + without(args, flag))
                self.assertEqual(refused.exception.code, 2, (command, flag))
                self.assertIn(f"the following arguments are required: {flag}", stderr.getvalue(), (command, flag))
                refusals += 1
        self.assertEqual(refusals, 13)
        # Refused before the Owner is opened: nothing was read or written.
        self.assertEqual(self.db.read_bytes(), before_bytes)

        # The supplied actor and revision reach the Mirror exactly, for acknowledge too.
        with mock.patch.object(FinancialMirror, "acknowledge_action", return_value={"status": "STUB"}) as acknowledge:
            self.assertEqual(self._invoke_cli(common + ["acknowledge-action", "--action-id", "action:h", "--acknowledgment-ref", "ack:h",
                                                       "--actor-id", "synthetic-receiver", "--actor-role", "RECEIVER", "--expected-revision", "7"])[0], 0)
        acknowledge.assert_called_once_with(
            "action:h", "ack:h", actor_id="synthetic-receiver", actor_role="RECEIVER", expected_revision=7
        )
        # A stale revision is refused by the Owner, not silently applied.
        revision = int(self.mirror.obligation_detail(H_ITEM_ID)["revision"])
        stale = list(commands["record-payment-evidence"])
        stale[stale.index("--expected-revision") + 1] = str(revision - 1)
        sequence = self.mirror.summary()["sequence"]
        status, _output, stderr = self._invoke_cli(common + ["record-payment-evidence"] + stale)
        self.assertEqual(status, 2)
        self.assertEqual(stderr, "ERROR:obligation_revision_conflict\n")
        self.assertEqual(self.mirror.summary()["sequence"], sequence)

    def test_population_status_reports_manifest_completeness_without_roster(self) -> None:
        status = self.mirror.population_status(PROGRAM_ITEMS[0].population_id)
        self.assertEqual(status["schema"], "RR/FINANCIAL/MIRROR/v1")
        self.assertEqual(status["resource"], "population_status")
        self.assertEqual(status["status"], "PUBLISHED")
        self.assertEqual(status["imported_count"], len(PROGRAM_ITEMS))
        self.assertEqual(status["expected_count"], len(PROGRAM_ITEMS))
        self.assertEqual(status["validated_count"], len(PROGRAM_ITEMS))
        self.assertEqual(status["manifest_status"], "CURRENT")
        self.assertEqual(status["completeness"], "EXACT")
        self.assertTrue(status["source_complete"])
        self.assertEqual(status["manifest_version"], 1)
        self.assertEqual(
            set(status),
            {
                "schema",
                "resource",
                "status",
                "imported_count",
                "expected_count",
                "validated_count",
                "manifest_status",
                "completeness",
                "source_complete",
                "manifest_version",
            },
        )
        self.assertFalse(
            {
                "population_id",
                "manifest_id",
                "manifest_digest",
                "member_id",
                "member_ids",
                "member_digest",
                "members",
                "source_digest",
                "source_owner_id",
                "approval_ref",
            }
            & set(status)
        )

    def test_continuity_export_validate_restore_restart_and_readback(self) -> None:
        self._prepare_action()
        package = self.mirror.export_continuity()
        metadata = self.mirror.validate_owner_continuity_package(package)
        self.assertEqual(metadata["schema"], "RR/FINANCIAL/CONTINUITY/v8")
        self.assertEqual(metadata["schema"], CONTINUITY.export_version)  # CASE_11
        self.assertEqual(metadata["version"], 8)
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
        self.addCleanup(reopened_owner.close)
        reopened = FinancialMirror(reopened_owner)
        self.assertEqual(reopened.obligation_detail(H_ITEM_ID)["case_status"], "CORRECTION_REQUIRED")
        self.assertEqual(reopened.verify_integrity()["mode"], "SHADOW")

    def test_restore_test_continuity_keeps_the_correction_engine_binding(self) -> None:
        """A TEST restore must not disable reject-offset: a correction attempted
        on the restored Owner still succeeds."""
        self._prepare_claim()
        package = self.mirror.export_continuity()
        destination = self.root / "test-restore-then-reject.sqlite"
        restored = self.mirror.restore_test_continuity(package, destination)
        self.addCleanup(restored.owner.close)
        decision = self._reject_correction(restored)
        self.assertEqual(decision["status"], "CORRECTION_AUTHORIZED")

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

    def test_continuity_validation_requires_caller_trusted_authority(self) -> None:
        package = self.mirror.export_continuity()
        scope = dataclasses.asdict(PERIOD_ONE_SCOPE)
        with self.assertRaisesRegex(FinancialMirrorContinuityError, "continuity_trusted_authority_required"):
            FinancialMirror.validate_continuity_package(package, trusted_authority=None, expected_scope=scope)
        other_authority = owner.SyntheticTrustedAuthority(authority_id="synthetic-authority-other")
        with self.assertRaisesRegex(FinancialMirrorContinuityError, "continuity_authority_mismatch"):
            FinancialMirror.validate_continuity_package(package, trusted_authority=other_authority, expected_scope=scope)
        verified = FinancialMirror.validate_continuity_package(
            package,
            trusted_authority=self.authority,
            expected_scope=scope,
        )
        self.assertEqual(verified["package_digest"], json.loads(package.decode("ascii"))["package_digest"])

    def test_cli_requires_explicit_trusted_authority_file(self) -> None:
        status, stdout, stderr = self._invoke_cli(self._cli_prefix(include_authority=False) + ["summary"])
        self.assertEqual(status, 2)
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "ERROR:trusted_authority_missing\n")

    def test_cli_summary_is_local_and_redacted(self) -> None:
        status, stdout, stderr = self._invoke_cli(self._cli_prefix() + ["summary"])
        self.assertEqual(status, 0)
        self.assertEqual(stderr, "")
        summary = json.loads(stdout)
        self.assertEqual(summary["schema"], "RR/FINANCIAL/MIRROR/v1")
        self.assertFalse(summary["dispatch_enabled"])
        self.assertFalse(summary["egress_enabled"])

    def test_unapproved_owner_field_never_reaches_mirror_or_cli_output(self) -> None:
        """Article IV.2: outputs copy approved fields only, so a new owner column cannot leak."""
        from tools import right_rail_financial_cli as cli

        self._prepare_action()
        marker = "unapproved_owner_column"

        def tag(value: object) -> object:
            if type(value) is dict:
                # the support package is refused, not projected, when it carries an extra key: its own test covers that
                return {**{key: item if key == "corporate_support" else tag(item) for key, item in value.items()}, marker: marker}
            return [tag(item) for item in value] if type(value) is list else value

        def tagging(name: str) -> object:
            original = getattr(owner.FinancialOwner, name)
            return mock.patch.object(owner.FinancialOwner, name, lambda store, *a, **k: tag(original(store, *a, **k)))

        mirror = self.mirror
        reads = {
            "summary": mirror.summary,
            "list": lambda: mirror.list_obligations(status="ALL"),
            "detail": lambda: mirror.obligation_detail(H_ITEM_ID),
            "receipt": lambda: mirror.current_evaluation_receipt(H_ITEM_ID),
            "decision_package": lambda: mirror.decision_package(H_ITEM_ID),
            "history": lambda: mirror.history(limit=200),
            "followup": lambda: mirror.correction_followup_outputs(H_ITEM_ID, "action:correction:h"),
            "drain": mirror.drain_correction_followups,
            "program_funding": mirror.program_funding_summary,
            "integrity": mirror.verify_integrity,
            "command": lambda: mirror.acknowledge_action("action:correction:h", "ack:correction:h:tagged"),
        }
        scope = [text for key in ("state_id", "deployment_id", "program_id", "period_id") for text in (f"--{key.replace('_', '-')}", getattr(self.config, key))]
        base = ["--database", str(self.db), "--authority-file", str(self._authority_file()), *scope]
        cli_reads = (["summary"], ["list-obligations", "--status", "ALL"], ["obligation-detail", "--item-id", H_ITEM_ID],
                     ["current-evaluation-receipt", "--item-id", H_ITEM_ID], ["history", "--limit", "200"], ["verify-integrity"])
        with ExitStack() as patches:
            for name in ("summary", "list_obligations", "obligation_detail", "current_evaluation_receipt", "decision_package", "history",
                         "correction_followup_outputs", "program_funding_summary", "verify_integrity", "acknowledge_action"):
                patches.enter_context(tagging(name))
            for label, read in reads.items():
                with self.subTest(label):
                    self.assertNotIn(marker, json.dumps(read()))
            for argv in cli_reads:
                with self.subTest(argv[0]), redirect_stdout(io.StringIO()) as stdout, redirect_stderr(io.StringIO()) as stderr:
                    self.assertEqual((cli.main(base + argv), stderr.getvalue()), (0, ""))
                    self.assertNotIn(marker, stdout.getvalue())

if __name__ == "__main__":
    unittest.main()
