"""Focused synthetic tests for the read-only Switch comparison boundary."""

from __future__ import annotations

import json
from dataclasses import replace
import unittest

from app.right_rail_financial_owner import FinancialOwner
from app.right_rail_financial_switch import (
    _RECORDS,
    CandidateSpec,
    CohortApproval,
    DifferencePolicy,
    FinancialSwitchError,
    ReferenceSpec,
    decode_replay_input,
    inspect_shadow_snapshot,
    prepare_shadow_replay_input,
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
        self.addCleanup(self.shadow.close)  # R1a: its export opens the writer
        self.snapshot = self.shadow.export_continuity()
        self.incumbent_before = self.incumbent.export_continuity()
        self.shadow_before = self.shadow.export_continuity()
        config = self.shadow.config
        # Trusted inputs come from the test's own authority and Owner config,
        # never from the snapshot being inspected.
        self.trust = {
            "trusted_authority": self.fixture.authority,
            "expected_scope": {
                "state_id": config.state_id,
                "deployment_id": config.deployment_id,
                "program_id": config.program_id,
                "period_id": config.period_id,
                "currency": config.currency,
            },
        }
        self.facts = inspect_shadow_snapshot(self.snapshot, **self.trust)
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
            replay = decode_replay_input(input_bytes, **self.trust)
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

    def _candidate(self, *, h_delta: int = 0) -> CandidateSpec:
        def evaluate(input_bytes: bytes) -> dict[str, object]:
            replay = decode_replay_input(input_bytes, **self.trust)
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
            return {
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

    def _run(self, **changes: object) -> dict[str, object]:
        return run_shadow_replay(**{"snapshot_bytes": self.snapshot, **self.trust, "cohort_approval": self.approval, "reference": self.reference, "candidate": self.candidate, **changes})

    def _h_policy(self, classification: str) -> DifferencePolicy:
        return DifferencePolicy(path=f"members.{expected.H_ITEM_ID}.owed_cents", classification=classification, rationale="test-only comparison fixture", approval_ref="fixture-difference-approval:local-test-only")

    def test_synthetic_shadow_replay_reports_typed_difference_and_preserves_owner_bytes(self) -> None:
        received_inputs: list[bytes] = []
        reference, candidate = self._reference(expected_differences=(self._h_policy("EXPECTED"),)), self._candidate(h_delta=1)
        report = self._run(reference=replace(reference, evaluate=lambda raw: (received_inputs.append(raw), reference.evaluate(raw))[1]),
                           candidate=replace(candidate, evaluate=lambda raw: (received_inputs.append(raw), candidate.evaluate(raw))[1]))
        self.assertEqual((report["status"], report["comparison_status"]), ("BLOCKED", "UNEXPLAINED_DIFFERENCES"))
        differences = {row["path"]: row["classification"] for row in report["differences"]}
        self.assertEqual((differences[f"members.{expected.H_ITEM_ID}.owed_cents"], differences["aggregate.total_owed_cents"]), ("EXPECTED", "UNEXPLAINED"))
        self.assertEqual((report["expected_member_count"], report["reference_received_member_count"], report["candidate_received_member_count"]), (len(expected.PROGRAM_ITEMS),) * 3)
        self.assertEqual([id(raw) for raw in received_inputs], [id(received_inputs[0])] * 2)  # both evaluators got the same bytes object
        self.assertEqual(report["isolation"], {**report["isolation"], "evaluator_input": "CANONICAL_REPLAY_BYTES_ONLY", "evaluator_closure_isolation": "UNVERIFIED"})
        self.assertFalse(report["resources"]["evaluation_timeout_enforced_by_module"])
        self.assertEqual((report["source_class_verification"], report["difference_policy_approval"]), ("CALLER_ASSERTED",) * 2)
        self.assertEqual((report["transfer_authorized"], report["candidate_authority"]), (False, "NONE"))
        self._assert_source_bytes_unchanged()

    def test_missing_or_bad_inputs_never_call_evaluators(self) -> None:
        calls: list[str] = []
        stubs = {"reference": replace(self.reference, evaluate=lambda _raw: calls.append("reference")),
                 "candidate": replace(self.candidate, evaluate=lambda _raw: calls.append("candidate"))}
        for changes, status, reasons in (  # a str must be among the reasons; a list is all of them
            ({"cohort_approval": None}, "INCOMPLETE", "cohort_approval_missing"),
            ({"reference": None}, "INCOMPLETE", "independent_reference_missing"),
            ({"snapshot_bytes": self.snapshot.replace(b'"mode":"SHADOW"', b'"mode":"LIVE"', 1)}, "INVALID_SNAPSHOT", None),
            ({"cohort_approval": replace(self.approval, binding_sha256="F" * 64)}, "INCOMPLETE", "cohort_approval_binding_mismatch"),
            ({"trusted_authority": None}, "INVALID_SNAPSHOT", ["switch:trusted-authority-required"]),
        ):
            with self.subTest(changes=sorted(changes)):
                report = self._run(**{**stubs, **changes})
                self.assertEqual(report["status"], status)
                if type(reasons) is str:
                    self.assertIn(reasons, report["reasons"])
                elif reasons is not None:
                    self.assertEqual(report["reasons"], reasons)
                self.assertEqual(calls, [])
                self._assert_source_bytes_unchanged()

    def test_candidate_unknown_field_or_float_or_bool_binding_is_incomplete(self) -> None:
        records = self.facts.binding_records()  # 7.0 / True / False pass == for 7 / 1 / 0 but hash differently
        cases = [(name, key, bad) for name in _RECORDS for key, held in records[name].items() if type(held) is int
                 for bad in (float(held), *((bool(held),) if held in (0, 1) else ()))]
        named = {repr(("owner", "sequence", float(self.facts.sequence))), repr(("authority", "epoch", True)), repr(("control_pack", "effective_start_ms", float(self.facts.control_pack_start_ms)))}
        self.assertLessEqual(named, {repr(case) for case in cases})  # repr: a set's == would take 1.0 for True
        for name, key, bad in [*cases, ("invented_field", None, "unknown schema fields fail closed")]:
            with self.subTest(record=name, key=key, value=bad):
                forge = {name: {**records[name], key: bad} if key else bad}
                candidate = replace(self.candidate, evaluate=lambda raw, forge=forge: {**self.candidate.evaluate(raw), **forge})
                self._assert_incomplete(self._run(candidate=candidate), [f"{name}-binding" if key else "unknown-result-fields:invented_field"])
                self._assert_source_bytes_unchanged()

    def _assert_incomplete(self, report: dict[str, object], reasons: list[str]) -> None:
        audit = ("OUTPUT_NOT_ENCODABLE", None) if reasons == ["result-byte-cap-or-type"] else ("OUTPUT_RETURNED", len(self.facts.member_ids))
        self.assertEqual((report["status"], report["reasons"], report["unknowns"], report["member_audit"]["candidate"]["status"], report["candidate_received_member_count"]),
                         ("INCOMPLETE", ["candidate_result_invalid"], [{"class": "UNKNOWN", "reason": f"candidate:{reason}"} for reason in reasons], *audit))

    def test_output_is_checked_stored_and_hashed_as_one_plain_json_copy(self) -> None:
        class Flip(dict):  # json.dumps reads a non-empty dict subclass through items(); this one answers each call differently
            def __init__(self, *answers: object) -> None:
                super().__init__(pairs)
                self.answers = list(answers)

            def items(self):  # type: ignore[override]
                return self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]

        class Liar(str):  # != calls a str subclass's own __ne__ first: "XXX" claims equality, any other text raises
            def __ne__(self, other: object) -> bool:
                return False if self == "XXX" else bool(1 // 0)

        pairs = list(self.facts.record("authority").items())
        forged = [(key, value + 1 if key == "epoch" else value) for key, value in pairs]
        first_id, honest = self.facts.member_ids[0], self._run()
        self.assertEqual(honest["comparison_status"], "MATCHED")
        for name, forge, reasons in (  # reasons None: the run matches and hashes exactly the honest output
            ("forged-first-encoding", lambda out: out.update(authority=Flip(forged, pairs)), ["authority-binding"]),
            ("non-json-second-encoding", lambda out: out.update(authority=Flip(pairs, [("epoch", object())])), None),
            ("encoding-raises-index-error", lambda out: out.update(authority=Flip((pairs[len(pairs)] for _ in "x"), pairs)), ["result-byte-cap-or-type"]),
            ("duplicate-keys-last-forged", lambda out: out.update(authority=Flip(pairs + forged)), ["result-byte-cap-or-type"]),
            ("over-8-mib-cap", lambda out: out.update(contract="x" * 8 * 1024 * 1024), ["result-byte-cap-or-type"]),
            ("currency-ne-raises", lambda out: out["aggregate"].update(currency=Liar(out["aggregate"]["currency"])), None),
            ("member-currency-ne-lies", lambda out: out["member_results"][0].update(currency=Liar("XXX")), [f"member-result-type:{first_id}", "aggregate-reconciliation"]),
            ("aggregate-currency-ne-lies", lambda out: out["aggregate"].update(currency=Liar("XXX")), ["aggregate-reconciliation"]),
        ):
            with self.subTest(name):
                report = self._run(candidate=replace(self.candidate, evaluate=lambda raw, forge=forge: (out := self.candidate.evaluate(raw), forge(out))[0]))
                if reasons is None:
                    self.assertEqual((report["status"], report["candidate_result_sha256"]), (honest["status"], honest["candidate_result_sha256"]))
                else:
                    self._assert_incomplete(report, reasons)

    def test_forbidden_difference_is_reported_as_blocking(self) -> None:
        report = self._run(reference=self._reference(forbidden_differences=(self._h_policy("FORBIDDEN"),)), candidate=self._candidate(h_delta=1))
        differences = {row["path"]: row for row in report["differences"]}
        self.assertEqual((report["status"], report["comparison_status"]), ("BLOCKED", "FORBIDDEN_DIFFERENCES"))
        self.assertEqual(differences[f"members.{expected.H_ITEM_ID}.owed_cents"]["classification"], "FORBIDDEN")
        self._assert_source_bytes_unchanged()

    def test_replay_input_refuses_a_float_or_bool_for_an_integer_field(self) -> None:
        raw = prepare_shadow_replay_input(self.snapshot, **self.trust, cohort_approval=self.approval, reference=self.reference, candidate=self.candidate)
        self.assertEqual(decode_replay_input(raw, **self.trust).sequence, self.facts.sequence)
        value = json.loads(raw)  # 7 -> 7.0 everywhere; 0/1 -> False/True too (Python's == takes both as the int)
        cases = [(name, key, bad) for name in _RECORDS for key, held in value[name].items() if type(held) is int
                 for bad in (float(held), *((bool(held),) if held in (0, 1) else ()))]
        self.assertIn(("owner", "sequence", float(self.facts.sequence)), cases)
        self.assertTrue(any(type(bad) is bool for *_, bad in cases))
        for name, key, bad in cases:
            with self.subTest(record=name, key=key, value=bad):
                forged = {**value, name: {**value[name], key: bad}}
                with self.assertRaisesRegex(FinancialSwitchError, "^switch:replay-binding$"):
                    decode_replay_input(json.dumps(forged, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii"), **self.trust)


if __name__ == "__main__":
    unittest.main()
