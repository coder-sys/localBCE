"""Focused V1 contract, semantic, mutation, and cross-process tests."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import traceback
import unittest

from app.mirror import provider_trust_graph as graph
from app.mirror import provider_trust_graph_independent as independent


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _artifact_object(raw: bytes) -> dict[str, object]:
    value = json.loads(raw.decode("utf-8"))
    assert isinstance(value, dict)
    return value


def _mutated_artifact(raw: bytes, callback) -> bytes:
    value = _artifact_object(raw)
    callback(value)
    return _canonical(value)


def _rebind_report_and_transition(value: dict[str, object]) -> None:
    """Test attacker helper: recompute outer identities after evidence edits."""

    report = value["report"]
    transition = value["transition"]
    assert isinstance(report, dict) and isinstance(transition, dict)
    report["report_id"] = graph._digest("report-id", report["identity_material"])
    snapshot = value["observation_snapshot"]
    assert isinstance(snapshot, dict)
    transition["current_report_id"] = report["report_id"]
    transition["current_snapshot_id"] = snapshot["snapshot_id"]
    transition["current_snapshot_root"] = snapshot["snapshot_root"]
    transition_core = {key: transition[key] for key in graph.TRANSITION_KEYS if key != "transition_id"}
    transition["transition_id"] = graph._digest("transition-id", transition_core)


def _rebind_retest_outer(value: dict[str, object]) -> None:
    remediation = value["remediation"]
    assert isinstance(remediation, dict)
    prior = remediation["prior_artifact"]
    assert isinstance(prior, dict)
    prior_report = prior["report"]
    prior_snapshot = prior["observation_snapshot"]
    report = value["report"]
    assert isinstance(prior_report, dict) and isinstance(prior_snapshot, dict) and isinstance(report, dict)
    identity = report["identity_material"]
    assert isinstance(identity, dict)
    identity["remediation_root"] = graph._digest("remediation-root", {"remediation": remediation})
    identity["prior_report_id"] = prior_report["report_id"]
    identity["prior_snapshot_id"] = prior_snapshot["snapshot_id"]
    identity["prior_snapshot_root"] = prior_snapshot["snapshot_root"]
    _rebind_report_and_transition(value)


class ProviderTrustGraphV1Tests(unittest.TestCase):
    def build_case(self, case: str = "confirmed") -> tuple[bytes, dict[str, object]]:
        return graph.build_demo_report(case)

    @staticmethod
    def verify(raw: bytes) -> dict[str, object]:
        return independent.verify_bytes(raw)

    def retest_input(self, result_case: str, *, result: str = "PASSED") -> dict[str, object]:
        prior_raw, _ = self.build_case("expired")
        prior = graph.prior_link_from_artifact(prior_raw)
        current = graph.demo_input(result_case)
        current["observation_time"] = 8_000
        for source in current["sources"]:
            source["coverage_observation_time"] = 8_000
            source["coverage_effective_start"] = 7_000
            source["coverage_effective_end"] = 9_000
            for record in source["records"]:
                record["observed_at"] = 8_000
        current["prior_artifact"] = prior
        current["remediation"] = {
            "action_artifact_id": "SYNTH_ACTION_001",
            "submitted_at": 7_500,
            "retest_result": result,
            "prior_finding_ids": [prior["findings"][0]["finding_id"]],
        }
        return graph.refresh_input_digests(current)

    def test_seven_base_vectors_and_independent_acceptance(self) -> None:
        expected = {
            "confirmed": graph.FINDING_CONTINUITY,
            "expired": graph.FINDING_EXPIRED,
            "terminated": graph.FINDING_TERMINATED,
            "incomplete": graph.FINDING_INCOMPLETE,
            "absent": graph.FINDING_ABSENT,
            "conflict": graph.FINDING_CONFLICT,
            "stale": graph.FINDING_STALE,
        }
        for case, kind in expected.items():
            with self.subTest(case=case):
                raw, telemetry = self.build_case(case)
                result = self.verify(raw)
                self.assertEqual([kind], result["finding_kinds"])
                self.assertTrue(result["accepted"])
                self.assertLess(len(raw), graph.MAX_ARTIFACT_BYTES)
                self.assertFalse(telemetry["proof_performance_claim"])
                self.assertEqual(len(raw), telemetry["artifact_bytes"])
                peak = telemetry["process_tree_peak_bytes"]
                if peak is not None:
                    self.assertLess(peak, 5_000_000_000)

    def test_external_payload_is_separate_and_nonactivating(self) -> None:
        raw, _ = self.build_case()
        payload = _artifact_object(raw)
        self.assertEqual(graph.SCHEMA, payload["schema"])
        self.assertEqual(
            {
                "clearance_authority": False,
                "payment_authority": False,
                "economic_mutation": False,
                "production_usable": False,
                "synthetic_only": True,
            },
            payload["authority"],
        )
        encoded = raw.decode("utf-8")
        for token in (
            "policyResult",
            "policy_result",
            "effectiveDirective",
            "ClearanceDecisionRow",
            "StateAccessRow",
            "proofSuiteId",
            "directive",
            "payment_directive",
        ):
            self.assertNotIn(token, encoded)
        self.assertNotIn("native_v3_plaintext_continuity", Path(graph.__file__).read_text(encoding="utf-8"))
        self.assertNotIn("from app.mirror.provider_trust_graph", Path(independent.__file__).read_text(encoding="utf-8"))

    def test_profile_getter_failure_is_context_free_in_both_verifiers(self) -> None:
        class MaliciousProfile:
            @property
            def profile_id(self) -> str:
                raise RuntimeError("PTG-PROFILE-CANARY")

        for verifier, error_type in (
            (graph, graph.ProviderTrustGraphError),
            (independent, independent.IndependentProviderTrustGraphError),
        ):
            with self.subTest(verifier=verifier.__name__):
                with self.assertRaises(error_type) as caught:
                    verifier._profile_view(MaliciousProfile())
                self.assertEqual("profile:configuration", str(caught.exception))
                self.assertIsNone(caught.exception.__cause__)
                self.assertIsNone(caught.exception.__context__)
                self.assertNotIn("PTG-PROFILE-CANARY", "".join(traceback.format_exception(caught.exception)))

    def test_descriptor_bound_file_reads_reject_same_size_swap_and_accept_exact_bytes(self) -> None:
        raw, _ = self.build_case()
        with tempfile.TemporaryDirectory(prefix="mirror-file-bound-") as directory:
            path = Path(directory) / "artifact.json"
            replacement = Path(directory) / "replacement.json"
            path.write_bytes(raw)
            self.assertEqual(raw, graph._read_bounded(path, graph.MAX_INPUT_BYTES))
            self.assertTrue(independent.verify_file(path)["accepted"])

            canary = b"X" * len(raw)
            replacement.write_bytes(canary)
            original_lstat = graph.os.lstat
            calls = {"count": 0}

            def swap_after_lstat(value: object):
                result = original_lstat(value)
                if calls["count"] == 0:
                    calls["count"] += 1
                    replacement.replace(path)
                return result

            graph.os.lstat = swap_after_lstat  # type: ignore[assignment]
            try:
                with self.assertRaises(graph.ProviderTrustGraphError) as caught:
                    graph._read_bounded(path, graph.MAX_INPUT_BYTES)
            finally:
                graph.os.lstat = original_lstat  # type: ignore[assignment]
            self.assertNotIn("X", str(caught.exception))
            self.assertIsNone(caught.exception.__context__)
            path.write_bytes(raw)

            replacement.write_bytes(canary)
            original_lstat = independent.os.lstat
            calls = {"count": 0}

            def swap_after_independent_lstat(value: object):
                result = original_lstat(value)
                if calls["count"] == 0:
                    calls["count"] += 1
                    replacement.replace(path)
                return result

            independent.os.lstat = swap_after_independent_lstat  # type: ignore[assignment]
            try:
                with self.assertRaises(independent.IndependentProviderTrustGraphError) as caught_independent:
                    independent.verify_file(path)
            finally:
                independent.os.lstat = original_lstat  # type: ignore[assignment]
            self.assertNotIn("X", str(caught_independent.exception))
            self.assertIsNone(caught_independent.exception.__context__)

    def test_descriptor_bound_file_reads_reject_missing_symlink_directory_and_oversize(self) -> None:
        raw, _ = self.build_case()
        with tempfile.TemporaryDirectory(prefix="mirror-file-shapes-") as directory:
            root = Path(directory)
            missing = root / "missing.json"
            for reader in (
                lambda path: graph._read_bounded(path, graph.MAX_INPUT_BYTES),
                independent.verify_file,
            ):
                with self.subTest(shape="missing", reader=reader):
                    with self.assertRaises(Exception) as caught:
                        reader(missing)
                    self.assertNotIn("mirror-file-shapes", str(caught.exception))
                    self.assertIsNone(caught.exception.__context__)
            directory_path = root / "directory"
            directory_path.mkdir()
            with self.assertRaises(Exception):
                graph._read_bounded(directory_path, graph.MAX_INPUT_BYTES)
            with self.assertRaises(Exception):
                independent.verify_file(directory_path)
            symlink = root / "symlink.json"
            try:
                symlink.symlink_to(root / "valid.json")
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation unavailable")
            (root / "valid.json").write_bytes(raw)
            with self.assertRaises(Exception):
                graph._read_bounded(symlink, graph.MAX_INPUT_BYTES)
            with self.assertRaises(Exception):
                independent.verify_file(symlink)
            oversized = root / "oversized.json"
            oversized.write_bytes(b"x" * (graph.MAX_INPUT_BYTES + 1))
            with self.assertRaisesRegex(graph.ProviderTrustGraphError, "file:byte-cap"):
                graph._read_bounded(oversized, graph.MAX_INPUT_BYTES)
            oversized.write_bytes(b"x" * (independent.MAX_ARTIFACT_BYTES + 1))
            with self.assertRaisesRegex(independent.IndependentProviderTrustGraphError, "file:byte-cap"):
                independent.verify_file(oversized)

    def test_source_provenance_snapshot_report_and_transition_bindings(self) -> None:
        raw, _ = self.build_case()
        payload = _artifact_object(raw)
        self.assertEqual(2, len(payload["source_coverage"]))
        self.assertEqual(payload["observation_snapshot"]["snapshot_id"], payload["findings"][0]["observation_snapshot_id"])
        transition = payload["transition"]
        report = payload["report"]
        self.assertEqual("INITIAL", transition["transition_kind"])
        self.assertIsNone(transition["prior_report_id"])
        self.assertEqual(report["report_id"], transition["current_report_id"])
        self.assertEqual(payload["observation_snapshot"]["snapshot_id"], transition["current_snapshot_id"])
        self.assertEqual(payload["observation_snapshot"]["snapshot_root"], transition["current_snapshot_root"])

    def test_retest_pass_is_append_only_and_independently_accepted(self) -> None:
        raw, _ = graph.build_report(graph.canonical_input(self.retest_input("confirmed", result="PASSED")))
        result = self.verify(raw)
        self.assertLess(len(raw), graph.MAX_ARTIFACT_BYTES)
        self.assertEqual(graph.LIFECYCLE_REMEDIATED, result["lifecycle"])
        payload = _artifact_object(raw)
        self.assertEqual("RETEST", payload["transition"]["transition_kind"])
        self.assertEqual(payload["remediation"]["prior_artifact"]["findings"], graph.prior_link_from_artifact(self.build_case("expired")[0])["findings"])
        self.assertEqual(graph.FINDING_CONTINUITY, payload["findings"][0]["kind"])

    def test_retest_fail_preserves_original_finding(self) -> None:
        raw, _ = graph.build_report(graph.canonical_input(self.retest_input("expired", result="FAILED")))
        result = self.verify(raw)
        self.assertLess(len(raw), graph.MAX_ARTIFACT_BYTES)
        self.assertEqual(graph.LIFECYCLE_RETEST_FAILED, result["lifecycle"])
        payload = _artifact_object(raw)
        self.assertEqual(graph.FINDING_EXPIRED, payload["findings"][0]["kind"])
        self.assertEqual(graph.FINDING_EXPIRED, payload["remediation"]["prior_artifact"]["findings"][0]["kind"])

    def test_parity_pass_and_mismatch_are_explicit(self) -> None:
        passing = graph.demo_input("confirmed")
        passing["parity_cases"] = [{"case_id": "CASE_001", "expected_kind": graph.FINDING_CONTINUITY, "expected_present": True}]
        raw, _ = graph.build_report(graph.canonical_input(passing))
        self.assertTrue(self.verify(raw)["accepted"])
        self.assertTrue(_artifact_object(raw)["parity_cases"][0]["passed"])

        mismatch = graph.demo_input("confirmed")
        mismatch["parity_cases"] = [{"case_id": "CASE_001", "expected_kind": graph.FINDING_EXPIRED, "expected_present": True}]
        raw, _ = graph.build_report(graph.canonical_input(mismatch))
        payload = _artifact_object(raw)
        self.assertFalse(payload["parity_cases"][0]["passed"])
        self.assertEqual("PARITY_MISMATCH", payload["discrepancies"][0]["kind"])
        self.assertTrue(self.verify(raw)["accepted"])

    def test_fact_nonmembership_contradiction_fails_producer_before_digest(self) -> None:
        value = graph.demo_input("confirmed")
        value["sources"][0]["nonmembership_keys"] = [graph.SUBJECT_KEY]
        value = graph.refresh_input_digests(value)
        with self.assertRaisesRegex(graph.ProviderTrustGraphError, "completeness:fact-nonmembership-conflict"):
            graph.build_report(graph.canonical_input(value))

    def test_fact_nonmembership_contradiction_fails_independent_before_root(self) -> None:
        raw, _ = self.build_case("confirmed")
        mutated = _mutated_artifact(raw, lambda value: value["source_coverage"][0]["nonmembership_keys"].append(graph.SUBJECT_KEY))
        with self.assertRaisesRegex(independent.IndependentProviderTrustGraphError, "completeness:fact-nonmembership-conflict"):
            self.verify(mutated)

    def test_incomplete_feed_never_becomes_absence(self) -> None:
        value = graph.demo_input("absent")
        value["sources"][1]["coverage_complete"] = False
        value = graph.refresh_input_digests(value)
        raw, _ = graph.build_report(graph.canonical_input(value))
        self.assertEqual([graph.FINDING_INCOMPLETE], self.verify(raw)["finding_kinds"])

    def test_observation_status_and_interval_contradictions_fail_closed(self) -> None:
        value = graph.demo_input("confirmed")
        value["sources"][0]["records"][0]["observed_at"] = 7_001
        value = graph.refresh_input_digests(value)
        with self.assertRaisesRegex(graph.ProviderTrustGraphError, "record:observation-mismatch"):
            graph.build_report(graph.canonical_input(value))

        value = graph.demo_input("terminated")
        value["sources"][1]["records"][0]["terminated_at"] = 8_000
        value = graph.refresh_input_digests(value)
        with self.assertRaisesRegex(graph.ProviderTrustGraphError, "record:termination-time"):
            graph.build_report(graph.canonical_input(value))

        value = graph.demo_input("confirmed")
        value["sources"][0]["records"][0]["status"] = graph.STATUS_EXPIRED
        value = graph.refresh_input_digests(value)
        with self.assertRaisesRegex(graph.ProviderTrustGraphError, "record:status-time-mismatch"):
            graph.build_report(graph.canonical_input(value))

    def test_provider_credential_enrollment_source_time_interval_and_enum_mutations_fail(self) -> None:
        mutations = (
            ("provider", lambda value: value["sources"][0]["records"][0].__setitem__("provider_id", "SYNTH_PROVIDER_002")),
            ("credential", lambda value: value["sources"][0]["records"][0].__setitem__("credential_id", "SYNTH_CREDENTIAL_002")),
            ("enrollment", lambda value: value["sources"][1]["records"][0].__setitem__("enrollment_id", "SYNTH_ENROLLMENT_002")),
            ("source", lambda value: value["sources"][0].__setitem__("source_id", graph.SOURCE_ENROLLMENT_ID)),
            ("coverage-time", lambda value: value["sources"][0].__setitem__("coverage_observation_time", 7_001)),
            ("interval", lambda value: value["sources"][0]["records"][0].__setitem__("valid_until", 6_000)),
            ("enum", lambda value: value["sources"][0]["records"][0].__setitem__("status", "UNKNOWN")),
        )
        for name, mutation in mutations:
            with self.subTest(name=name):
                value = graph.demo_input()
                mutation(value)
                value = graph.refresh_input_digests(value)
                with self.assertRaises(graph.ProviderTrustGraphError):
                    graph.build_report(graph.canonical_input(value))

    def test_caller_modes_unknown_fields_and_forbidden_external_fields_fail(self) -> None:
        value = graph.demo_input()
        value["caller_fields"] = {}
        with self.assertRaisesRegex(graph.ProviderTrustGraphError, "input:schema"):
            graph.build_report(graph.canonical_input(value))

        raw, _ = self.build_case()
        forbidden = _mutated_artifact(raw, lambda value: value.__setitem__("payment_directive", "UNSAFE"))
        # Exact artifact keys own the external-boundary exclusion; no keyword blacklist is authority.
        with self.assertRaisesRegex(independent.IndependentProviderTrustGraphError, "artifact:schema"):
            self.verify(forbidden)

        unknown_enum = _mutated_artifact(raw, lambda value: value["findings"][0].__setitem__("kind", "UNKNOWN"))
        with self.assertRaises(independent.IndependentProviderTrustGraphError):
            self.verify(unknown_enum)

    def test_canonical_duplicate_trailing_float_and_count_abuse_fail(self) -> None:
        raw, _ = self.build_case()
        duplicate = raw.replace(b'"schema":"mirror-provider-trust-graph-v1"', b'"schema":"mirror-provider-trust-graph-v1","schema":"mirror-provider-trust-graph-v1"', 1)
        with self.assertRaisesRegex(independent.IndependentProviderTrustGraphError, "json:duplicate-key"):
            self.verify(duplicate)
        with self.assertRaisesRegex(independent.IndependentProviderTrustGraphError, "json:not-canonical"):
            self.verify(raw + b"\n")
        with self.assertRaisesRegex(independent.IndependentProviderTrustGraphError, "json:not-canonical"):
            self.verify(b" " + raw)
        with self.assertRaisesRegex(independent.IndependentProviderTrustGraphError, "json:byte-cap"):
            self.verify(raw + b" " * independent.MAX_ARTIFACT_BYTES)
        with tempfile.TemporaryDirectory(prefix="mirror-cap-") as directory:
            path = Path(directory) / "oversized.json"
            path.write_bytes(b"x" * (independent.MAX_ARTIFACT_BYTES + 1))
            with self.assertRaisesRegex(independent.IndependentProviderTrustGraphError, "file:byte-cap"):
                independent.verify_file(path)

    def test_source_record_order_duplicate_root_provenance_and_subject_mutations_fail(self) -> None:
        raw, _ = self.build_case("conflict")
        reordered = _mutated_artifact(raw, lambda value: value["source_coverage"][0]["records"].reverse())
        with self.assertRaisesRegex(independent.IndependentProviderTrustGraphError, "record-order-or-duplicate"):
            self.verify(reordered)
        duplicated = _mutated_artifact(raw, lambda value: value["source_coverage"][0]["records"].__setitem__(1, deepcopy(value["source_coverage"][0]["records"][0])))
        with self.assertRaisesRegex(independent.IndependentProviderTrustGraphError, "record-order-or-duplicate"):
            self.verify(duplicated)

        raw, _ = self.build_case()
        root_bad = _mutated_artifact(raw, lambda value: value["source_coverage"][0].__setitem__("source_root", "0" * 128))
        with self.assertRaisesRegex(independent.IndependentProviderTrustGraphError, "source:root-mismatch"):
            self.verify(root_bad)
        provenance_bad = _mutated_artifact(raw, lambda value: value["source_coverage"][0]["records"][0].__setitem__("credential_id", "SYNTH_CREDENTIAL_002"))
        with self.assertRaises(independent.IndependentProviderTrustGraphError):
            self.verify(provenance_bad)

    def test_source_finding_parity_transition_and_report_omission_or_reorder_fail(self) -> None:
        raw, _ = self.build_case()
        for name, callback in (
            ("source-omit", lambda value: value["source_coverage"].pop()),
            ("source-reorder", lambda value: value["source_coverage"].reverse()),
            ("finding-omit", lambda value: value["findings"].clear()),
            ("transition-omit", lambda value: value.__setitem__("transition", None)),
            ("report-id", lambda value: value["report"].__setitem__("report_id", "0" * 128)),
            ("snapshot-root", lambda value: value["observation_snapshot"].__setitem__("snapshot_root", "0" * 128)),
        ):
            with self.subTest(name=name):
                mutated = _mutated_artifact(raw, callback)
                with self.assertRaises(independent.IndependentProviderTrustGraphError):
                    self.verify(mutated)

        value = graph.demo_input()
        value["parity_cases"] = [{"case_id": "CASE_001", "expected_kind": graph.FINDING_CONTINUITY, "expected_present": True}]
        raw, _ = graph.build_report(graph.canonical_input(value))
        parity_bad = _mutated_artifact(raw, lambda value: value["parity_cases"].append(deepcopy(value["parity_cases"][0])))
        with self.assertRaises(independent.IndependentProviderTrustGraphError):
            self.verify(parity_bad)

    def test_independent_provenance_snapshot_flag_transition_and_count_mutations_fail(self) -> None:
        raw, _ = self.build_case()
        mutations = (
            ("provenance", lambda value: value["source_coverage"][0]["provenance"].__setitem__("integrity_digest", "0" * 128)),
            ("snapshot-id", lambda value: value["observation_snapshot"].__setitem__("snapshot_id", "0" * 128)),
            ("authority-flag", lambda value: value["authority"].__setitem__("economic_mutation", True)),
            ("transition-id", lambda value: value["transition"].__setitem__("transition_id", "0" * 128)),
            ("transition-report", lambda value: value["transition"].__setitem__("current_report_id", "0" * 128)),
            ("source-count", lambda value: value["source_coverage"].append(deepcopy(value["source_coverage"][0]))),
        )
        for name, mutation in mutations:
            with self.subTest(name=name):
                with self.assertRaises(independent.IndependentProviderTrustGraphError):
                    self.verify(_mutated_artifact(raw, mutation))

    def test_remediation_omission_duplicate_and_prior_snapshot_mutations_fail(self) -> None:
        raw, _ = graph.build_report(graph.canonical_input(self.retest_input("confirmed", result="PASSED")))
        mutations = (
            ("remediation-field", lambda value: value["remediation"].pop("prior_finding_ids")),
            ("remediation-duplicate", lambda value: value["remediation"]["prior_finding_ids"].append(value["remediation"]["prior_finding_ids"][0])),
            ("prior-snapshot-root", lambda value: value["remediation"]["prior_artifact"]["observation_snapshot"].__setitem__("snapshot_root", "0" * 128)),
        )
        for name, mutation in mutations:
            with self.subTest(name=name):
                with self.assertRaises(independent.IndependentProviderTrustGraphError):
                    self.verify(_mutated_artifact(raw, mutation))

    def test_retest_link_and_result_mutations_fail(self) -> None:
        raw, _ = graph.build_report(graph.canonical_input(self.retest_input("confirmed", result="PASSED")))
        stale_prior = _mutated_artifact(raw, lambda value: value["remediation"]["prior_artifact"]["report"].__setitem__("report_id", "0" * 128))
        with self.assertRaises(independent.IndependentProviderTrustGraphError):
            self.verify(stale_prior)
        missing_prior = _mutated_artifact(raw, lambda value: value["remediation"].__setitem__("prior_artifact", None))
        with self.assertRaises(independent.IndependentProviderTrustGraphError):
            self.verify(missing_prior)
        wrong_result = _mutated_artifact(raw, lambda value: value["remediation"].__setitem__("retest_result", "FAILED"))
        with self.assertRaises(independent.IndependentProviderTrustGraphError):
            self.verify(wrong_result)
        wrong_transition = _mutated_artifact(raw, lambda value: value["transition"].__setitem__("current_snapshot_root", "0" * 128))
        with self.assertRaises(independent.IndependentProviderTrustGraphError):
            self.verify(wrong_transition)

    def test_reconstructed_retest_forgery_attacks_fail_closed(self) -> None:
        valid_raw, _ = graph.build_report(graph.canonical_input(self.retest_input("confirmed", result="PASSED")))

        empty_ids = _artifact_object(valid_raw)
        empty_ids["remediation"]["prior_finding_ids"] = []
        _rebind_retest_outer(empty_ids)
        with self.assertRaisesRegex(independent.IndependentProviderTrustGraphError, "remediation:prior-findings-empty"):
            self.verify(_canonical(empty_ids))

        fabricated_prior = _artifact_object(valid_raw)
        prior = fabricated_prior["remediation"]["prior_artifact"]
        prior["report"]["identity_material"]["source_coverage_root"] = "f" * 128
        _rebind_report_and_transition(prior)
        _rebind_retest_outer(fabricated_prior)
        with self.assertRaises(independent.IndependentProviderTrustGraphError):
            self.verify(_canonical(fabricated_prior))

        partial_prior = _artifact_object(valid_raw)
        full_prior = partial_prior["remediation"]["prior_artifact"]
        partial_prior["remediation"]["prior_artifact"] = {
            "report_id": full_prior["report"]["report_id"],
            "snapshot_id": full_prior["observation_snapshot"]["snapshot_id"],
            "snapshot_root": full_prior["observation_snapshot"]["snapshot_root"],
            "observation_time": full_prior["observation_snapshot"]["observation_time"],
            "identity_material": full_prior["report"]["identity_material"],
            "findings": full_prior["findings"],
        }
        partial_link = partial_prior["remediation"]["prior_artifact"]
        partial_identity = partial_prior["report"]["identity_material"]
        partial_identity["remediation_root"] = graph._digest("remediation-root", {"remediation": partial_prior["remediation"]})
        partial_identity["prior_report_id"] = partial_link["report_id"]
        partial_identity["prior_snapshot_id"] = partial_link["snapshot_id"]
        partial_identity["prior_snapshot_root"] = partial_link["snapshot_root"]
        _rebind_report_and_transition(partial_prior)
        with self.assertRaises(independent.IndependentProviderTrustGraphError):
            self.verify(_canonical(partial_prior))

    def test_every_partial_prior_link_combination_rejects_after_rebinding(self) -> None:
        initial_raw, _ = self.build_case("confirmed")
        fields = ("prior_report_id", "prior_snapshot_id", "prior_snapshot_root")
        for selected_count in (1, 2):
            for selected in __import__("itertools").combinations(fields, selected_count):
                with self.subTest(selected=selected):
                    forged = _artifact_object(initial_raw)
                    identity = forged["report"]["identity_material"]
                    transition = forged["transition"]
                    for field in selected:
                        identity[field] = "0" * 128
                        transition[field] = "0" * 128
                    _rebind_report_and_transition(forged)
                    with self.assertRaisesRegex(independent.IndependentProviderTrustGraphError, "identity:prior-link"):
                        self.verify(_canonical(forged))

    def test_nested_retest_prior_is_rejected_by_producer_and_independent_verifier(self) -> None:
        nested_raw, _ = graph.build_report(graph.canonical_input(self.retest_input("confirmed", result="PASSED")))
        outer = self.retest_input("confirmed", result="PASSED")
        outer["prior_artifact"] = _artifact_object(nested_raw)
        with self.assertRaisesRegex(graph.ProviderTrustGraphError, "prior-artifact:nested-retest-forbidden"):
            graph.build_report(graph.canonical_input(outer))

        valid_raw, _ = graph.build_report(graph.canonical_input(self.retest_input("confirmed", result="PASSED")))
        forged = _artifact_object(valid_raw)
        forged["remediation"]["prior_artifact"] = _artifact_object(nested_raw)
        _rebind_retest_outer(forged)
        with self.assertRaisesRegex(independent.IndependentProviderTrustGraphError, "prior-artifact:nested-retest-forbidden"):
            self.verify(_canonical(forged))

        producer_empty = self.retest_input("confirmed", result="PASSED")
        producer_empty["remediation"]["prior_finding_ids"] = []
        with self.assertRaisesRegex(graph.ProviderTrustGraphError, "remediation:prior-findings-empty"):
            graph.build_report(graph.canonical_input(producer_empty))

        producer_partial = self.retest_input("confirmed", result="PASSED")
        producer_full = producer_partial["prior_artifact"]
        producer_partial["prior_artifact"] = {
            "report_id": producer_full["report"]["report_id"],
            "snapshot_id": producer_full["observation_snapshot"]["snapshot_id"],
            "snapshot_root": producer_full["observation_snapshot"]["snapshot_root"],
            "observation_time": producer_full["observation_snapshot"]["observation_time"],
            "identity_material": producer_full["report"]["identity_material"],
            "findings": producer_full["findings"],
        }
        with self.assertRaises(graph.ProviderTrustGraphError):
            graph.build_report(graph.canonical_input(producer_partial))

    def test_independent_cross_process_accepts_and_rejects(self) -> None:
        raw, _ = self.build_case()
        with tempfile.TemporaryDirectory(prefix="mirror-v1-") as directory:
            path = Path(directory) / "artifact.json"
            path.write_bytes(raw)
            accepted = subprocess.run(
                [sys.executable, "-m", "app.mirror.provider_trust_graph_independent", str(path)],
                cwd=Path(__file__).parents[1],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(0, accepted.returncode, accepted.stderr)
            self.assertIn('"accepted":true', accepted.stdout)
            retest_raw, _ = graph.build_report(graph.canonical_input(self.retest_input("confirmed", result="PASSED")))
            path.write_bytes(retest_raw)
            retest_accepted = subprocess.run(
                [sys.executable, "-m", "app.mirror.provider_trust_graph_independent", str(path)],
                cwd=Path(__file__).parents[1],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(0, retest_accepted.returncode, retest_accepted.stderr)
            self.assertIn('"accepted":true', retest_accepted.stdout)
            path.write_bytes(raw[:-1])
            rejected = subprocess.run(
                [sys.executable, "-m", "app.mirror.provider_trust_graph_independent", str(path)],
                cwd=Path(__file__).parents[1],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(0, rejected.returncode)
            self.assertIn("REJECT", rejected.stderr)

    def test_cli_input_failures_redact_host_path_and_exception_details(self) -> None:
        canary = Path(tempfile.gettempdir()) / "PRIVATE-CREDENTIAL-CANARY-provider-trust.json"
        missing = str(canary)
        for module in ("app.mirror.provider_trust_graph", "app.mirror.provider_trust_graph_independent"):
            with self.subTest(module=module):
                result = subprocess.run(
                    [sys.executable, "-m", module, missing],
                    cwd=Path(__file__).parents[1],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertNotEqual(0, result.returncode)
                self.assertEqual("REJECT input\n", result.stderr)
                self.assertNotIn(missing, result.stderr)
                self.assertNotIn("CREDENTIAL", result.stderr)


if __name__ == "__main__":
    unittest.main()
