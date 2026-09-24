"""Focused synthetic tests for the read-only Switch comparison boundary."""

from __future__ import annotations

import json
from dataclasses import replace
import unittest

from app.right_rail_financial_owner import FinancialOwner
from app.right_rail_financial_switch import (
    CandidateSpec,
    CohortApproval,
    DifferencePolicy,
    ReferenceSpec,
    decode_replay_input,
    inspect_shadow_snapshot,
    run_shadow_replay,
)
from tests import rightrail_financial_expected_cases as expected


class FinancialSwitchTests(unittest.TestCase):
    def setUp(self) -> None:
        from tests.test_right_rail_financial_acceptance import RightRailFinancialAcceptanceTests

        self.fixture = RightRailFinancialAcceptanceTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.incumbent = self.fixture._build_base()
        incumbent_package = self.incumbent.export_continuity()
        self.shadow = FinancialOwner.restore_continuity(
            package_bytes=incumbent_package,
            recovered_path=self.fixture._path("switch-shadow.sqlite"),
            trusted_authority=self.fixture.authority,
            restore_mode="SHADOW",
        )
        self.snapshot = self.shadow.export_continuity()
        self.incumbent_before = self.incumbent.export_continuity()
        self.shadow_before = self.shadow.export_continuity()
        self.facts = inspect_shadow_snapshot(self.snapshot)
        self.approval = self._approval()
        self.reference = self._reference()
        self.candidate = self._candidate()

    def _approval(self) -> CohortApproval:
        fields = {
            "cohort_id": "cohort:synthetic-period-one",
            "test_identity": "switch-fixture:population-summary-v1",
            "source_class": "SYNTHETIC",
            "receiver_boundary_ref": "fixture-receiver-boundary:nonlive",
            "custody_ref": "fixture-custody:local-test-only",
            "permissions_ref": "fixture-permission:local-test-only",
            "pending_boundary_ref": "fixture-pending-boundary:whole-population",
        }
        binding = self.facts.cohort_binding_bytes(**fields)
        import hashlib

        return CohortApproval(
            approval_id="fixture-approval:local-test-only",
            cohort_id=fields["cohort_id"],
            test_identity=fields["test_identity"],
            approved_by="fixture-reviewer",
            approval_ref="fixture-approval-ref:local-test-only",
            source_class=fields["source_class"],
            receiver_boundary_ref=fields["receiver_boundary_ref"],
            custody_ref=fields["custody_ref"],
            permissions_ref=fields["permissions_ref"],
            pending_boundary_ref=fields["pending_boundary_ref"],
            binding_sha256=hashlib.sha256(binding).hexdigest().upper(),
        )

    def _reference(self, *, expected_differences: tuple[DifferencePolicy, ...] = (), forbidden_differences: tuple[DifferencePolicy, ...] = ()) -> ReferenceSpec:
        expected_by_id = {item.item_id: item.owed_cents for item in expected.PROGRAM_ITEMS}

        def evaluate(input_bytes: bytes) -> dict[str, object]:
            replay = decode_replay_input(input_bytes)
            member_results = [
                {"member_id": item_id, "currency": replay.currency, "owed_cents": expected_by_id[item_id]}
                for item_id in replay.member_ids
            ]
            return {
                **replay.reference_output_binding(),
                "member_results": member_results,
                "aggregate": {
                    "member_count": len(member_results),
                    "total_owed_cents": sum(row["owed_cents"] for row in member_results),
                    "currency": replay.currency,
                },
            }

        return ReferenceSpec(
            reference_id="independent-reference:fixture",
            version="hand-derived-v1",
            authority_id="fixture-reference-authority",
            reviewer_id="fixture-reference-reviewer",
            source_ref="tests/rightrail_financial_expected_cases.py",
            source_sha256="A" * 64,
            tool_version="test-reference-runtime-v1",
            evaluate=evaluate,
            expected_differences=expected_differences,
            forbidden_differences=forbidden_differences,
        )

    def _candidate(self, *, h_delta: int = 0, unknown_field: bool = False) -> CandidateSpec:
        def evaluate(input_bytes: bytes) -> dict[str, object]:
            replay = decode_replay_input(input_bytes)
            package = json.loads(replay.snapshot_package_bytes.decode("ascii"))
            population_items = {
                row["item_id"]: row
                for row in package["tables"]["population_items"]
                if row["population_id"] == replay.population_id
            }
            member_results = []
            for item_id in replay.member_ids:
                item = population_items[item_id]
                amount = item["owed_cents"] + (h_delta if item_id == expected.H_ITEM_ID else 0)
                member_results.append({"member_id": item_id, "currency": item["currency"], "owed_cents": amount})
            result: dict[str, object] = {
                **replay.output_binding(
                    producer_kind="CANDIDATE",
                    producer_id=replay.candidate_id,
                    version=replay.candidate_version,
                    tool_version=replay.candidate_tool_version,
                    artifact_sha256=replay.candidate_release_sha256,
                ),
                "member_results": member_results,
                "aggregate": {
                    "member_count": len(member_results),
                    "total_owed_cents": sum(row["owed_cents"] for row in member_results),
                    "currency": replay.currency,
                },
            }
            if unknown_field:
                result["invented_field"] = "unknown schema fields fail closed"
            return result

        return CandidateSpec(
            operator_id="candidate:fixture",
            version="candidate-v1",
            tool_version="test-candidate-runtime-v1",
            release_sha256="B" * 64,
            evaluate=evaluate,
        )

    def _assert_source_bytes_unchanged(self) -> None:
        self.assertEqual(self.incumbent.export_continuity(), self.incumbent_before)
        self.assertEqual(self.shadow.export_continuity(), self.shadow_before)

    def test_synthetic_shadow_replay_reports_typed_difference_and_preserves_owner_bytes(self) -> None:
        received_inputs: list[bytes] = []
        reference = self._reference(
            expected_differences=(
                DifferencePolicy(
                    path=f"members.{expected.H_ITEM_ID}.owed_cents",
                    classification="EXPECTED",
                    rationale="test-only comparison fixture",
                    approval_ref="fixture-difference-approval:local-test-only",
                ),
            )
        )
        candidate = self._candidate(h_delta=1)
        reference_runner = replace(reference, evaluate=lambda raw: (received_inputs.append(raw), reference.evaluate(raw))[1])
        candidate_runner = replace(candidate, evaluate=lambda raw: (received_inputs.append(raw), candidate.evaluate(raw))[1])

        report = run_shadow_replay(
            self.snapshot,
            cohort_approval=self.approval,
            reference=reference_runner,
            candidate=candidate_runner,
        )

        self.assertEqual(report["status"], "BLOCKED")
        self.assertEqual(report["comparison_status"], "UNEXPLAINED_DIFFERENCES")
        differences = {row["path"]: row for row in report["differences"]}
        self.assertEqual(differences[f"members.{expected.H_ITEM_ID}.owed_cents"]["classification"], "EXPECTED")
        self.assertEqual(differences["aggregate.total_owed_cents"]["classification"], "UNEXPLAINED")
        self.assertEqual(report["expected_member_count"], len(expected.PROGRAM_ITEMS))
        self.assertEqual(report["reference_received_member_count"], len(expected.PROGRAM_ITEMS))
        self.assertEqual(report["candidate_received_member_count"], len(expected.PROGRAM_ITEMS))
        self.assertEqual(len(received_inputs), 2)
        self.assertEqual(received_inputs[0], received_inputs[1])
        self.assertIs(received_inputs[0], received_inputs[1])
        self.assertEqual(report["isolation"]["evaluator_input"], "CANONICAL_REPLAY_BYTES_ONLY")
        self.assertEqual(report["isolation"]["evaluator_closure_isolation"], "UNVERIFIED")
        self.assertFalse(report["resources"]["evaluation_timeout_enforced_by_module"])
        self.assertEqual(report["source_class_verification"], "CALLER_ASSERTED")
        self.assertEqual(report["difference_policy_approval"], "CALLER_ASSERTED")
        self.assertFalse(report["transfer_authorized"])
        self.assertEqual(report["candidate_authority"], "NONE")
        self._assert_source_bytes_unchanged()

    def test_missing_approval_or_reference_never_calls_evaluators(self) -> None:
        calls: list[str] = []
        reference = replace(self.reference, evaluate=lambda _raw: calls.append("reference"))
        candidate = replace(self.candidate, evaluate=lambda _raw: calls.append("candidate"))

        missing_approval = run_shadow_replay(
            self.snapshot,
            cohort_approval=None,
            reference=reference,
            candidate=candidate,
        )
        missing_reference = run_shadow_replay(
            self.snapshot,
            cohort_approval=self.approval,
            reference=None,
            candidate=candidate,
        )

        self.assertEqual(missing_approval["status"], "INCOMPLETE")
        self.assertIn("cohort_approval_missing", missing_approval["reasons"])
        self.assertEqual(missing_reference["status"], "INCOMPLETE")
        self.assertIn("independent_reference_missing", missing_reference["reasons"])
        self.assertEqual(calls, [])
        self._assert_source_bytes_unchanged()

    def test_tampered_snapshot_and_mismatched_approval_fail_before_evaluation(self) -> None:
        calls: list[str] = []
        reference = replace(self.reference, evaluate=lambda _raw: calls.append("reference"))
        candidate = replace(self.candidate, evaluate=lambda _raw: calls.append("candidate"))
        tampered = self.snapshot.replace(b'"mode":"SHADOW"', b'"mode":"LIVE"', 1)
        bad_approval = replace(self.approval, binding_sha256="F" * 64)

        invalid_snapshot = run_shadow_replay(
            tampered,
            cohort_approval=self.approval,
            reference=reference,
            candidate=candidate,
        )
        invalid_approval = run_shadow_replay(
            self.snapshot,
            cohort_approval=bad_approval,
            reference=reference,
            candidate=candidate,
        )

        self.assertEqual(invalid_snapshot["status"], "INVALID_SNAPSHOT")
        self.assertEqual(invalid_approval["status"], "INCOMPLETE")
        self.assertIn("cohort_approval_binding_mismatch", invalid_approval["reasons"])
        self.assertEqual(calls, [])
        self._assert_source_bytes_unchanged()

    def test_unknown_candidate_fields_return_incomplete_unknown(self) -> None:
        report = run_shadow_replay(
            self.snapshot,
            cohort_approval=self.approval,
            reference=self.reference,
            candidate=self._candidate(unknown_field=True),
        )

        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertEqual(report["reasons"], ["candidate_result_invalid"])
        self.assertTrue(any("unknown-result-fields:invented_field" in row["reason"] for row in report["unknowns"]))
        self._assert_source_bytes_unchanged()

    def test_forbidden_difference_is_reported_as_blocking(self) -> None:
        reference = self._reference(
            forbidden_differences=(
                DifferencePolicy(
                    path=f"members.{expected.H_ITEM_ID}.owed_cents",
                    classification="FORBIDDEN",
                    rationale="synthetic negative-path assertion",
                    approval_ref="fixture-forbidden-difference:local-test-only",
                ),
            )
        )
        report = run_shadow_replay(
            self.snapshot,
            cohort_approval=self.approval,
            reference=reference,
            candidate=self._candidate(h_delta=1),
        )

        differences = {row["path"]: row for row in report["differences"]}
        self.assertEqual(report["status"], "BLOCKED")
        self.assertEqual(report["comparison_status"], "FORBIDDEN_DIFFERENCES")
        self.assertEqual(differences[f"members.{expected.H_ITEM_ID}.owed_cents"]["classification"], "FORBIDDEN")
        self._assert_source_bytes_unchanged()


if __name__ == "__main__":
    unittest.main()
