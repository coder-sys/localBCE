"""End-to-end local CLI coverage for read-only Switch result comparison."""

from __future__ import annotations

from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import unittest

from app.right_rail_financial_owner import FinancialOwner
from app.right_rail_financial_switch import decode_replay_input, inspect_shadow_snapshot
from tests import rightrail_financial_expected_cases as expected
from tools import right_rail_financial_cli as financial_cli


def _json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


class FinancialSwitchCliTests(unittest.TestCase):
    def setUp(self) -> None:
        from tests.test_right_rail_financial_acceptance import RightRailFinancialAcceptanceTests

        self.fixture = RightRailFinancialAcceptanceTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.incumbent = self.fixture._build_base()
        incumbent_package = self.incumbent.export_continuity()
        self.shadow = FinancialOwner.restore_continuity(
            package_bytes=incumbent_package,
            recovered_path=self.fixture._path("switch-cli-shadow.sqlite"),
            trusted_authority=self.fixture.authority,
            restore_mode="SHADOW",
        )
        self.package = self.shadow.export_continuity()
        self.incumbent_before = self.incumbent.export_continuity()
        self.shadow_before = self.shadow.export_continuity()
        self.facts = inspect_shadow_snapshot(self.package)

        self.package_path = self.fixture._path("switch-cli-package.json")
        self.package_path.write_bytes(self.package)
        self.approval_path = self.fixture._path("switch-cli-approval.json")
        self.reference_path = self.fixture._path("switch-cli-reference.json")
        self.candidate_path = self.fixture._path("switch-cli-candidate.json")
        self.approval = self._approval_document()
        self.reference_identity = {
            "reference_id": "independent-reference:cli-fixture",
            "version": "hand-derived-v1",
            "authority_id": "fixture-reference-authority",
            "reviewer_id": "fixture-reference-reviewer",
            "source_ref": "tests/rightrail_financial_expected_cases.py",
            "source_sha256": "A" * 64,
            "tool_version": "fixture-reference-tool-v1",
        }
        self.candidate_identity = {
            "operator_id": "candidate:cli-fixture",
            "version": "candidate-v1",
            "tool_version": "candidate-tool-v1",
            "release_sha256": "B" * 64,
        }
        self.reference_document = {
            "contract": financial_cli.CLI_REFERENCE_SPEC_CONTRACT,
            "identity": self.reference_identity,
            "expected_differences": [],
            "forbidden_differences": [],
        }
        self.candidate_document = {
            "contract": financial_cli.CLI_CANDIDATE_SPEC_CONTRACT,
            "identity": self.candidate_identity,
        }
        self._write_identity_documents()

    def _approval_document(self) -> dict[str, object]:
        fields = {
            "cohort_id": "cohort:synthetic-period-one",
            "test_identity": "switch-cli-fixture:population-summary-v1",
            "source_class": "SYNTHETIC",
            "receiver_boundary_ref": "fixture-receiver-boundary:nonlive",
            "custody_ref": "fixture-custody:local-test-only",
            "permissions_ref": "fixture-permission:local-test-only",
            "pending_boundary_ref": "fixture-pending-boundary:whole-population",
        }
        binding = self.facts.cohort_binding_bytes(**fields)
        return {
            "contract": "RR/SWITCH/COHORT-APPROVAL/v1",
            "approval_id": "fixture-approval:cli-test-only",
            "cohort_id": fields["cohort_id"],
            "test_identity": fields["test_identity"],
            "approved_by": "fixture-reviewer",
            "approval_ref": "fixture-approval-ref:cli-test-only",
            "source_class": fields["source_class"],
            "receiver_boundary_ref": fields["receiver_boundary_ref"],
            "custody_ref": fields["custody_ref"],
            "permissions_ref": fields["permissions_ref"],
            "pending_boundary_ref": fields["pending_boundary_ref"],
            "binding_sha256": hashlib.sha256(binding).hexdigest().upper(),
        }

    def _write_identity_documents(self) -> None:
        self.approval_path.write_bytes(_json_bytes(self.approval))
        self.reference_path.write_bytes(_json_bytes(self.reference_document))
        self.candidate_path.write_bytes(_json_bytes(self.candidate_document))

    def _invoke(self, args: list[str]) -> tuple[int, str]:
        output = io.StringIO()
        with redirect_stdout(output):
            exit_code = financial_cli.main(args)
        return exit_code, output.getvalue()

    def _prepare_input(self) -> tuple[bytes, object]:
        replay_path = self.fixture._path("switch-cli-replay-input.json")
        exit_code, output = self._invoke([
            "switch-prepare",
            "--package", str(self.package_path),
            "--cohort-approval", str(self.approval_path),
            "--reference-spec", str(self.reference_path),
            "--candidate-spec", str(self.candidate_path),
            "--output", str(replay_path),
        ])
        self.assertEqual(exit_code, 0)
        prepare_report = json.loads(output)
        self.assertEqual(prepare_report["status"], "READY_FOR_EXTERNAL_COMPARISON")
        return replay_path.read_bytes(), prepare_report

    def _result_records(
        self,
        replay_bytes: bytes,
        *,
        wrong_candidate_input: bool = False,
    ) -> tuple[dict[str, object], dict[str, object]]:
        replay = decode_replay_input(replay_bytes)
        expected_by_id = {item.item_id: item.owed_cents for item in expected.PROGRAM_ITEMS}
        reference_rows = [
            {"member_id": item_id, "currency": replay.currency, "owed_cents": expected_by_id[item_id]}
            for item_id in replay.member_ids
        ]
        package = json.loads(replay.snapshot_package_bytes.decode("ascii"))
        candidate_items = {
            row["item_id"]: row
            for row in package["tables"]["population_items"]
            if row["population_id"] == replay.population_id
        }
        changed_ids = (
            expected.H_ITEM_ID,
            next(item_id for item_id in replay.member_ids if item_id != expected.H_ITEM_ID),
        )
        deltas = {changed_ids[0]: 257, changed_ids[1]: 101}
        candidate_rows = [
            {
                "member_id": item_id,
                "currency": replay.currency,
                "owed_cents": candidate_items[item_id]["owed_cents"] + deltas.get(item_id, 0),
            }
            for item_id in replay.member_ids
        ]
        reference = {
            **replay.reference_output_binding(),
            "member_results": reference_rows,
            "aggregate": {
                "member_count": len(reference_rows),
                "total_owed_cents": sum(row["owed_cents"] for row in reference_rows),
                "currency": replay.currency,
            },
        }
        candidate = {
            **replay.output_binding(
                producer_kind="CANDIDATE",
                producer_id=replay.candidate_id,
                version=replay.candidate_version,
                tool_version=replay.candidate_tool_version,
                artifact_sha256=replay.candidate_release_sha256,
            ),
            "member_results": candidate_rows,
            "aggregate": {
                "member_count": len(candidate_rows),
                "total_owed_cents": sum(row["owed_cents"] for row in candidate_rows),
                "currency": replay.currency,
            },
        }
        if wrong_candidate_input:
            candidate["input_sha256"] = "F" * 64
        return reference, candidate

    def _write_result_documents(self, reference: dict[str, object], candidate: dict[str, object]) -> None:
        reference_document = dict(self.reference_document)
        reference_document["result"] = reference
        candidate_document = dict(self.candidate_document)
        candidate_document["result"] = candidate
        self.reference_path.write_bytes(_json_bytes(reference_document))
        self.candidate_path.write_bytes(_json_bytes(candidate_document))

    def _compare(self, *, report_path: Path | None = None) -> tuple[int, dict[str, object]]:
        args = [
            "switch-compare",
            "--package", str(self.package_path),
            "--cohort-approval", str(self.approval_path),
            "--reference-spec", str(self.reference_path),
            "--candidate-spec", str(self.candidate_path),
        ]
        if report_path is not None:
            args.extend(("--report-output", str(report_path)))
        exit_code, output = self._invoke(args)
        return exit_code, json.loads(output)

    def _assert_owner_packages_unchanged(self) -> None:
        self.assertEqual(self.incumbent.export_continuity(), self.incumbent_before)
        self.assertEqual(self.shadow.export_continuity(), self.shadow_before)

    def test_cli_prepares_and_compares_external_results_without_opening_owner_database(self) -> None:
        replay_bytes, prepare_report = self._prepare_input()
        reference, candidate = self._result_records(replay_bytes)
        self._write_result_documents(reference, candidate)
        report_path = self.fixture._path("switch-cli-report.json")

        exit_code, report = self._compare(report_path=report_path)

        replay = decode_replay_input(replay_bytes)
        comparison = report["comparison"]
        differences = {row["path"]: row for row in comparison["differences"]}
        self.assertEqual(exit_code, 0)
        self.assertEqual(report["contract"], financial_cli.SWITCH_COMPARE_CLI_REPORT_CONTRACT)
        self.assertEqual(report["completion"], "COMPLETED")
        self.assertEqual(report["exit_code"], 0)
        self.assertFalse(report["owner_state_writes"])
        self.assertEqual(prepare_report["replay_input_sha256"], replay.input_sha256)
        self.assertEqual(comparison["replay_input_sha256"], replay.input_sha256)
        self.assertEqual(comparison["status"], "BLOCKED")
        self.assertEqual(comparison["comparison_status"], "UNEXPLAINED_DIFFERENCES")
        self.assertEqual(len(differences), 3)
        h_owed = next(item.owed_cents for item in expected.PROGRAM_ITEMS if item.item_id == expected.H_ITEM_ID)
        self.assertEqual(
            differences[f"members.{expected.H_ITEM_ID}.owed_cents"]["candidate_value"],
            h_owed + 257,
        )
        self.assertEqual(
            differences["aggregate.total_owed_cents"]["candidate_value"],
            differences["aggregate.total_owed_cents"]["reference_value"] + 358,
        )
        self.assertFalse(comparison["transfer_authorized"])
        self.assertEqual(comparison["candidate_authority"], "NONE")
        self.assertEqual(comparison["evaluation_mode"], "PRECOMPUTED_RESULT_FILES")
        self.assertIsNone(comparison["resources"]["reference_elapsed_ns"])
        self.assertIsNone(comparison["resources"]["candidate_elapsed_ns"])
        self.assertEqual(report_path.read_bytes(), _json_bytes(report))
        self._assert_owner_packages_unchanged()

    def test_cli_missing_approval_and_reference_facts_returns_incomplete_unknown(self) -> None:
        exit_code, report = self._invoke([
            "switch-compare",
            "--package", str(self.package_path),
        ])

        self.assertEqual(exit_code, financial_cli.SWITCH_COMPARE_INCOMPLETE_EXIT)
        self.assertEqual(report["completion"], "INCOMPLETE")
        self.assertEqual(report["exit_code"], financial_cli.SWITCH_COMPARE_INCOMPLETE_EXIT)
        self.assertEqual(report["comparison"]["status"], "INCOMPLETE")
        self.assertEqual(
            report["comparison"]["reasons"],
            ["cohort_approval_missing", "independent_reference_missing", "candidate_missing"],
        )
        self.assertFalse(report["comparison"]["transfer_authorized"])
        self.assertEqual(report["comparison"]["candidate_authority"], "NONE")
        self._assert_owner_packages_unchanged()

    def test_cli_missing_permission_provenance_stops_as_incomplete(self) -> None:
        incomplete_approval = dict(self.approval)
        del incomplete_approval["permissions_ref"]
        self.approval_path.write_bytes(_json_bytes(incomplete_approval))

        exit_code, report = self._compare()

        self.assertEqual(exit_code, financial_cli.SWITCH_COMPARE_INCOMPLETE_EXIT)
        self.assertEqual(report["comparison"]["status"], "INCOMPLETE")
        self.assertIn("cohort_approval_missing", report["comparison"]["reasons"])
        self.assertIn("cohort_approval_invalid:switch_approval_fields", report["comparison"]["reasons"])
        self.assertTrue(any(row["class"] == "UNKNOWN" for row in report["comparison"]["unknowns"]))
        self._assert_owner_packages_unchanged()

    def test_cli_candidate_cannot_be_the_claimed_cohort_approver(self) -> None:
        candidate_document = dict(self.candidate_document)
        candidate_identity = dict(self.candidate_identity)
        candidate_identity["operator_id"] = self.approval["approved_by"]
        candidate_document["identity"] = candidate_identity
        self.candidate_path.write_bytes(_json_bytes(candidate_document))

        exit_code, report = self._compare()

        self.assertEqual(exit_code, financial_cli.SWITCH_COMPARE_INCOMPLETE_EXIT)
        self.assertEqual(report["comparison"]["status"], "INCOMPLETE")
        self.assertIn("switch:candidate-self-approval", report["comparison"]["reasons"])
        self.assertFalse(report["comparison"]["transfer_authorized"])
        self._assert_owner_packages_unchanged()

    def test_cli_rejects_result_bound_to_different_replay_input(self) -> None:
        replay_bytes, _prepare_report = self._prepare_input()
        reference, candidate = self._result_records(replay_bytes, wrong_candidate_input=True)
        self._write_result_documents(reference, candidate)

        exit_code, report = self._compare()

        self.assertEqual(exit_code, financial_cli.SWITCH_COMPARE_INCOMPLETE_EXIT)
        self.assertEqual(report["comparison"]["status"], "INCOMPLETE")
        self.assertEqual(report["comparison"]["reasons"], ["candidate_result_invalid"])
        self.assertTrue(any(row["reason"] == "candidate:input-binding" for row in report["comparison"]["unknowns"]))
        self.assertFalse(report["comparison"]["transfer_authorized"])
        self._assert_owner_packages_unchanged()

    def test_cli_switch_error_returns_structured_nonzero_without_owner_writes(self) -> None:
        original_package = self.package_path.read_bytes()
        self.package_path.write_bytes(b"not-a-continuity-package")

        exit_code, output = self._invoke([
            "switch-compare",
            "--package", str(self.package_path),
        ])
        report = json.loads(output)

        self.assertEqual(exit_code, 2)
        self.assertEqual(report["contract"], financial_cli.SWITCH_COMPARE_CLI_REPORT_CONTRACT)
        self.assertEqual(report["completion"], "ERROR")
        self.assertEqual(report["exit_code"], 2)
        self.assertIsNone(report["comparison"])
        self.assertFalse(report["owner_state_writes"])
        self.assertEqual(self.package_path.read_bytes(), b"not-a-continuity-package")
        self.package_path.write_bytes(original_package)
        self._assert_owner_packages_unchanged()


if __name__ == "__main__":
    unittest.main()
