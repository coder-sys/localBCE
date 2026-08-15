"""Focused V1 governance contract, promotion, and independent-verifier tests."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from app.governance import provider_continuity_control_pack as pack
from app.governance import provider_continuity_control_pack_independent as independent
from app.mirror import provider_trust_graph as graph


APPROVAL_FIXTURE_BYTES = b'{"approval_authority_id":"SYNTH_STATE_APPROVAL_AUTHORITY_001","approval_id":"37f9fe84b5e19eea0083f5184a6df1cecf2fead57b0ef770bc86e2bffb6a828264818bd78882461a93d150af999408e017183ed40bf1fd4501a4cb2109da4688","approval_reason":"SYNTHETIC_OBSERVATION_ONLY_KAT_APPROVAL_V1","approval_time":7300,"approver_id":"SYNTH_STATE_APPROVER_001","approver_role":"OBSERVATION_CONTROL_PACK_APPROVER","effective_end":9000,"effective_start":6000,"provider_graph_subject":"SYNTH_PROVIDER_001","schema":"provider-continuity-state-approval-v1","scope":"provider-credential-enrollment-continuity-v1","source_contract_root":"490ff2b0a518fec07f0f74ecafb3246af546ea23394a0c21234160843227d72172c5d4a160683a00ec161dff4285ba87db7e94fcc424f028582fd5e9c22f522f","suite_root":"fbb5c8bd13045ca08cb3395a08775a5a839410468307b8af08c8b79a1b3974f0f3e69e73843b71474204f6ecbfe30840234d8905d11eaf90e7733d59cea89127","supersession":{"prior_approval_id":null,"supersession_sentinel":"NO_SUPERSESSION_V1"},"synthetic_kat_seal":"f4b50a5f133302bacc082acbb3e3103448131dcfa60323718690ade0bbb43d8a078d434ad66c22268965d4a727f5d70070c1fdc4a76f71df569263ba9402f4fc","tested_stage_id":"3e84f148db1b77aae7eb54931ae1d3c1fa1f1fa729184b67fe74e17bea2fb5dc43e70f889f4a5f387d4160132accb15be02d34ecb28a168e0e51fe12d9fea840","tested_stage_root":"2df88c520ae90b45afafa6a40568a0c349f8f2755d81b701fbf85b9fe46afd012565664ba07be8e0905ea4143b474f9a8483c7609d63b3515c4d837e6727a667"}'


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")


def _object(raw: bytes) -> dict[str, object]:
    value = json.loads(raw.decode("ascii"))
    assert isinstance(value, dict)
    return value


def _mutate(raw: bytes, callback) -> bytes:
    value = _object(raw)
    callback(value)
    return _canonical(value)


def _rebind_stage(stage: dict[str, object]) -> None:
    body = {key: value for key, value in stage.items() if key not in {"stage_id", "stage_root"}}
    stage["stage_root"] = independent._digest("stage-root", body)
    stage["stage_id"] = independent._digest("stage-id", {"stage_kind": body["stage_kind"], "stage_root": stage["stage_root"]})


def _rebind_artifact(value: dict[str, object], *, update_prior_links: bool = True) -> None:
    stages = value["stages"]
    assert isinstance(stages, list)
    for index, stage_value in enumerate(stages):
        assert isinstance(stage_value, dict)
        if index == 0:
            material = stage_value["material"]
            assert isinstance(material, dict)
            stage_value["candidate_root"] = independent._digest(
                "candidate-root",
                {
                    "source_contract_root": independent.SOURCE_CONTRACT_ROOT,
                    "subject": independent.SUBJECT,
                    "origin": stage_value["origin"],
                    "material": material,
                },
            )
        elif update_prior_links:
            previous = stages[index - 1]
            assert isinstance(previous, dict)
            stage_value["prior_stage_id"] = previous["stage_id"]
            stage_value["prior_stage_root"] = previous["stage_root"]
            stage_value["candidate_root"] = stages[0]["candidate_root"]
        _rebind_stage(stage_value)
    value["chain_root"] = independent._digest("chain-root", {"stages": stages})
    value["current_stage_kind"] = stages[-1]["stage_kind"]
    value["current_stage_id"] = stages[-1]["stage_id"]
    body = {key: item for key, item in value.items() if key != "artifact_id"}
    value["artifact_id"] = independent._digest("artifact-id", body)


def _rebind_current_stage(raw: bytes, callback) -> bytes:
    value = _object(raw)
    stages = value["stages"]
    assert isinstance(stages, list) and stages
    current = stages[-1]
    assert isinstance(current, dict)
    callback(current)
    _rebind_stage(current)
    value["chain_root"] = independent._digest("chain-root", {"stages": stages})
    value["current_stage_id"] = current["stage_id"]
    body = {key: item for key, item in value.items() if key != "artifact_id"}
    value["artifact_id"] = independent._digest("artifact-id", body)
    return _canonical(value)


def _approval_fixture_bytes() -> bytes:
    return APPROVAL_FIXTURE_BYTES


def _recompute_suite_root(conformance: dict[str, object]) -> None:
    conformance["suite_root"] = independent._digest(
        "suite-root",
        {
            "schema": conformance["schema"],
            "suite_id": conformance["suite_id"],
            "suite_version": conformance["suite_version"],
            "producer_module_identity": conformance["producer_module_identity"],
            "independent_verifier_module_identity": conformance["independent_verifier_module_identity"],
            "source_contract_root": conformance["source_contract_root"],
            "candidate_root": conformance["candidate_root"],
            "authority_profile": conformance["authority_profile"],
            "authority_profile_root": conformance["authority_profile_root"],
            "definitions": conformance["definitions"],
        },
    )


class ProviderContinuityControlPackV1Tests(unittest.TestCase):
    def candidate(self, case: str = "confirmed", *, origin: str = pack.ORIGIN_MIRROR) -> tuple[bytes, dict[str, object]]:
        return pack.build_demo_candidate(case, origin=origin)

    def chain(self, case: str = "confirmed") -> tuple[bytes, bytes, bytes]:
        candidate, _ = self.candidate(case)
        tested, _ = pack.build_tested(candidate)
        approved, _ = pack.build_approved(tested, _approval_fixture_bytes())
        return candidate, tested, approved

    def verify(self, raw: bytes) -> dict[str, object]:
        return independent.verify_bytes(raw)

    def test_base_evidence_labels_and_both_typed_sources(self) -> None:
        expected = {
            "confirmed": pack.EVIDENCE_CONTINUITY,
            "expired": pack.EVIDENCE_EXPIRED,
            "terminated": pack.EVIDENCE_TERMINATED,
            "incomplete": pack.EVIDENCE_INCOMPLETE,
            "absent": pack.EVIDENCE_ABSENT,
            "conflict": pack.EVIDENCE_CONFLICT,
        }
        for case, label in expected.items():
            with self.subTest(case=case):
                raw, telemetry = self.candidate(case)
                result = self.verify(raw)
                self.assertEqual(label, result["evidence_qualification"])
                payload = _object(raw)
                self.assertEqual(2, len(payload["source_contracts"]))
                coverage = payload["stages"][0]["material"]["graph_artifact"]["source_coverage"]
                if case != "absent":
                    self.assertEqual(["CREDENTIAL", "ENROLLMENT"], [source["records"][0]["record_kind"] for source in coverage if source["records"]])
                self.assertEqual(len(raw), telemetry["artifact_bytes"])
                self.assertLess(len(raw), pack.MAX_ARTIFACT_BYTES)

    def test_absence_requires_complete_nonmembership_and_incomplete_stays_incomplete(self) -> None:
        absent, _ = self.candidate("absent")
        absent_value = _object(absent)
        for source in absent_value["stages"][0]["material"]["graph_artifact"]["source_coverage"]:
            self.assertTrue(source["coverage_complete"])
            self.assertEqual([pack.SUBJECT_KEY], source["nonmembership_keys"])
        self.assertEqual(pack.EVIDENCE_ABSENT, self.verify(absent)["evidence_qualification"])
        incomplete, _ = self.candidate("incomplete")
        self.assertEqual(pack.EVIDENCE_INCOMPLETE, self.verify(incomplete)["evidence_qualification"])

    def test_fixed_contract_and_nonactivating_flags(self) -> None:
        raw, _ = self.candidate()
        value = _object(raw)
        self.assertEqual([dict(item) for item in pack.SOURCE_CONTRACTS], value["source_contracts"])
        self.assertEqual(pack.SOURCE_CONTRACT_ROOT, self.verify(raw)["source_contract_root"])
        for key, expected in pack.AUTHORITY_FLAGS.items():
            self.assertEqual(expected, value[key])
        encoded = raw.decode("ascii")
        for token in pack.FORBIDDEN_EXTERNAL_TOKENS:
            self.assertNotIn(token, encoded)
        self.assertNotIn("from app.governance.provider_continuity_control_pack", Path(independent.__file__).read_text(encoding="utf-8"))
        self.assertIn("provider_trust_graph_independent", Path(independent.__file__).read_text(encoding="utf-8"))

    def test_candidate_tested_approved_chain_and_telemetry(self) -> None:
        candidate, tested, approved = self.chain()
        for raw in (candidate, tested, approved):
            result = self.verify(raw)
            self.assertTrue(result["accepted"])
            self.assertLess(result["artifact_bytes"], pack.MAX_ARTIFACT_BYTES)
        value = _object(approved)
        self.assertEqual([pack.STAGE_CANDIDATE, pack.STAGE_TESTED, pack.STAGE_APPROVED], [stage["stage_kind"] for stage in value["stages"]])
        self.assertEqual(value["stages"][-1]["stage_id"], value["current_stage_id"])
        self.assertEqual(pack.STAGE_APPROVED, value["current_stage_kind"])
        self.assertEqual(pack.SUPERSESSION_SENTINEL, value["stages"][-1]["material"]["approval_record"]["supersession"]["supersession_sentinel"])
        conformance = value["stages"][1]["material"]["conformance"]
        self.assertEqual(pack.SCHEMA, conformance["schema"])
        self.assertEqual(pack.SOURCE_CONTRACT_ROOT, conformance["source_contract_root"])
        self.assertEqual(pack.AUTHORITY_PROFILE_ROOT, conformance["authority_profile_root"])
        self.assertEqual(pack.PRODUCER_MODULE_IDENTITY, conformance["producer_module_identity"])
        self.assertEqual(pack.INDEPENDENT_VERIFIER_MODULE_IDENTITY, conformance["independent_verifier_module_identity"])
        self.assertTrue(all(result["passed"] and result["observed_outcome"] == "PASS" for result in conformance["results"]))

    def test_cross_process_accepts_complete_artifact(self) -> None:
        _, _, raw = self.chain()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "control-pack.json"
            path.write_bytes(raw)
            accepted = subprocess.run(
                [sys.executable, "-m", "app.governance.provider_continuity_control_pack_independent", str(path)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(0, accepted.returncode, accepted.stderr)
            self.assertIn('"accepted":true', accepted.stdout)
            path.write_bytes(raw[:-1])
            rejected = subprocess.run(
                [sys.executable, "-m", "app.governance.provider_continuity_control_pack_independent", str(path)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(0, rejected.returncode)
            self.assertIn("REJECT", rejected.stderr)

    def test_behavioral_twin_is_candidate_only_even_after_rebinding(self) -> None:
        candidate, _ = self.candidate(origin=pack.ORIGIN_BEHAVIORAL_TWIN)
        self.assertEqual(pack.STAGE_CANDIDATE, self.verify(candidate)["current_stage_kind"])
        with self.assertRaisesRegex(pack.ControlPackError, "behavioral-twin-candidate-only"):
            pack.build_tested(candidate)
        normal_candidate, normal_tested, _ = self.chain()
        forged = _object(normal_tested)
        forged["stages"][0]["origin"] = pack.ORIGIN_BEHAVIORAL_TWIN
        candidate_stage = forged["stages"][0]
        candidate_stage["candidate_root"] = independent._digest(
            "candidate-root",
            {
                "source_contract_root": independent.SOURCE_CONTRACT_ROOT,
                "subject": independent.SUBJECT,
                "origin": pack.ORIGIN_BEHAVIORAL_TWIN,
                "material": candidate_stage["material"],
            },
        )
        tested_stage = forged["stages"][1]
        tested_stage["origin"] = pack.ORIGIN_BEHAVIORAL_TWIN
        tested_stage["candidate_root"] = candidate_stage["candidate_root"]
        _rebind_stage(candidate_stage)
        tested_stage["prior_stage_id"] = candidate_stage["stage_id"]
        tested_stage["prior_stage_root"] = candidate_stage["stage_root"]
        _rebind_stage(tested_stage)
        _rebind_artifact(forged, update_prior_links=False)
        with self.assertRaisesRegex(independent.IndependentControlPackError, "behavioral-twin-candidate-only"):
            self.verify(_canonical(forged))
        self.assertTrue(normal_candidate)

    def test_fact_nonmembership_contradiction_rejects_before_governance_digest(self) -> None:
        raw, _ = self.candidate()
        mutated = _mutate(
            raw,
            lambda value: value["stages"][0]["material"]["graph_artifact"]["source_coverage"][0]["nonmembership_keys"].append(pack.SUBJECT_KEY),
        )
        value = _object(mutated)
        _rebind_artifact(value)
        with self.assertRaisesRegex(independent.IndependentControlPackError, "graph:.*fact-nonmembership-conflict"):
            self.verify(_canonical(value))

    def test_graph_report_root_finding_and_source_rebound_attacks_fail(self) -> None:
        mutations = (
            ("report", lambda graph_value: graph_value["report"].__setitem__("report_id", "0" * 128)),
            ("finding", lambda graph_value: graph_value["findings"][0].__setitem__("kind", pack.EVIDENCE_EXPIRED)),
            ("source", lambda graph_value: graph_value["source_coverage"][0]["records"][0].__setitem__("provider_id", "SYNTH_PROVIDER_002")),
            ("record-kind", lambda graph_value: graph_value["source_coverage"][0]["records"][0].__setitem__("record_kind", "ENROLLMENT")),
        )
        for name, callback in mutations:
            with self.subTest(name=name):
                value = _object(self.candidate()[0])
                callback(value["stages"][0]["material"]["graph_artifact"])
                _rebind_artifact(value)
                with self.assertRaises(independent.IndependentControlPackError):
                    self.verify(_canonical(value))

    def test_wrong_source_contract_authority_source_record_schema_version_provenance_and_interval_fail(self) -> None:
        fields = (
            ("source_authority_id", "SYNTH_AUTHORITY_OTHER_001"),
            ("source_id", "SYNTH_SOURCE_OTHER_001"),
            ("authority_role", "OTHER_ROLE"),
            ("record_kind", "OTHER"),
            ("schema_id", "SYNTH_OTHER_SCHEMA_V1"),
            ("schema_version", 2),
            ("provenance_method", "OTHER"),
            ("integrity_method", "OTHER"),
            ("effective_start", 6_001),
            ("effective_end", 9_001),
        )
        for field, replacement in fields:
            with self.subTest(field=field):
                value = _object(self.candidate()[0])
                value["source_contracts"][0][field] = replacement
                _rebind_artifact(value)
                with self.assertRaises(independent.IndependentControlPackError):
                    self.verify(_canonical(value))

    def test_wrong_provider_scope_time_and_effective_interval_fail(self) -> None:
        mutations = (
            ("provider", lambda graph_value: graph_value["subject"].__setitem__("provider_graph_subject", "SYNTH_PROVIDER_002")),
            ("scope", lambda graph_value: graph_value["subject"].__setitem__("scope", "OTHER_SCOPE")),
            ("time", lambda graph_value: graph_value["observation_snapshot"].__setitem__("observation_time", 7_001)),
            ("interval", lambda graph_value: graph_value["source_coverage"][0].__setitem__("coverage_effective_end", 8_999)),
        )
        for name, callback in mutations:
            with self.subTest(name=name):
                value = _object(self.candidate()[0])
                callback(value["stages"][0]["material"]["graph_artifact"])
                _rebind_artifact(value)
                with self.assertRaises(independent.IndependentControlPackError):
                    self.verify(_canonical(value))
        with self.assertRaises(pack.ControlPackError):
            pack.build_demo_candidate("stale")

    def test_canonical_unknown_duplicate_float_nonascii_truncated_and_count_inputs_fail(self) -> None:
        _, _, raw = self.chain()
        self.assertRaises(independent.IndependentControlPackError, self.verify, raw + b" ")
        self.assertRaises(independent.IndependentControlPackError, self.verify, raw[:-1])
        self.assertRaises(independent.IndependentControlPackError, independent.verify_bytes, b'{"x":1.0}')
        self.assertRaises(independent.IndependentControlPackError, independent.verify_bytes, b'{"x":"\xc3\xa9"}')
        self.assertRaises(independent.IndependentControlPackError, independent.verify_bytes, b'{"x":1,"x":1}')
        unknown = _mutate(raw, lambda value: value.__setitem__("unknown", 1))
        self.assertRaises(independent.IndependentControlPackError, self.verify, unknown)
        omitted = _mutate(raw, lambda value: value["source_contracts"].pop())
        self.assertRaises(independent.IndependentControlPackError, self.verify, omitted)
        reordered = _mutate(raw, lambda value: value["source_contracts"].reverse())
        self.assertRaises(independent.IndependentControlPackError, self.verify, reordered)
        duplicated = _mutate(raw, lambda value: value["source_contracts"].append(deepcopy(value["source_contracts"][0])))
        self.assertRaises(independent.IndependentControlPackError, self.verify, duplicated)
        huge = b"{" + b'"x":[' + b"0," * (independent.MAX_NODES + 2) + b"0]}"
        self.assertRaises(independent.IndependentControlPackError, self.verify, huge)

    def test_forbidden_external_field_and_caller_selected_status_fail(self) -> None:
        _, tested, approved = self.chain()
        forbidden = _mutate(tested, lambda value: value.__setitem__("payment_directive", "UNSAFE"))
        self.assertRaisesRegex(independent.IndependentControlPackError, "forbidden-token", self.verify, forbidden)
        status = _rebind_current_stage(tested, lambda stage: stage.__setitem__("status", "APPROVED_OBSERVATION_ONLY"))
        with self.assertRaises(independent.IndependentControlPackError):
            self.verify(status)
        top_status = _mutate(approved, lambda value: value.__setitem__("current_stage_kind", pack.STAGE_TESTED))
        self.assertRaises(independent.IndependentControlPackError, self.verify, top_status)

    def test_conformance_failed_missing_reordered_duplicate_and_rebound_results_fail(self) -> None:
        _, tested, _ = self.chain()
        callbacks = (
            ("failed", lambda value: value["stages"][1]["material"]["conformance"]["results"][0].__setitem__("passed", False)),
            ("fake-pass-output", lambda value: value["stages"][1]["material"]["conformance"]["results"][0]["decisive_output"].__setitem__("contract_count", 99)),
            ("wrong-observed-output", lambda value: value["stages"][1]["material"]["conformance"]["results"][2]["decisive_output"].__setitem__("evidence_qualification", pack.EVIDENCE_EXPIRED)),
            ("missing", lambda value: value["stages"][1]["material"]["conformance"]["results"].pop()),
            ("reordered", lambda value: value["stages"][1]["material"]["conformance"]["results"].reverse()),
            ("duplicate", lambda value: value["stages"][1]["material"]["conformance"]["results"].append(deepcopy(value["stages"][1]["material"]["conformance"]["results"][0]))),
            ("caller-suite", lambda value: value["stages"][1]["material"]["conformance"].__setitem__("suite_id", "WEAKER_SUITE")),
        )
        for name, callback in callbacks:
            with self.subTest(name=name):
                value = _object(tested)
                callback(value)
                _rebind_artifact(value, update_prior_links=False)
                with self.assertRaises(independent.IndependentControlPackError):
                    self.verify(_canonical(value))

    def test_conformance_module_identity_mutations_fail_after_rebound(self) -> None:
        _, tested, _ = self.chain()
        for field in ("producer_module_identity", "independent_verifier_module_identity"):
            with self.subTest(field=field):
                value = _object(tested)
                conformance = value["stages"][1]["material"]["conformance"]
                conformance[field] = "0" * 128
                _recompute_suite_root(conformance)
                _rebind_artifact(value, update_prior_links=False)
                with self.assertRaises(independent.IndependentControlPackError):
                    self.verify(_canonical(value))

    def test_wrong_prior_id_root_time_and_skipped_stage_fail(self) -> None:
        _, tested, approved = self.chain()
        mutations = (
            ("prior-id", lambda stage: stage.__setitem__("prior_stage_id", "0" * 128)),
            ("prior-root", lambda stage: stage.__setitem__("prior_stage_root", "0" * 128)),
            ("time", lambda stage: stage.__setitem__("stage_time", pack.TESTED_TIME + 1)),
        )
        for name, callback in mutations:
            with self.subTest(name=name):
                forged = _rebind_current_stage(tested, callback)
                with self.assertRaises(independent.IndependentControlPackError):
                    self.verify(forged)
        skipped = _mutate(approved, lambda value: value["stages"].pop(1))
        self.assertRaises(independent.IndependentControlPackError, self.verify, skipped)
        duplicate = _mutate(approved, lambda value: value["stages"].append(deepcopy(value["stages"][0])))
        self.assertRaises(independent.IndependentControlPackError, self.verify, duplicate)

    def test_approval_authority_role_scope_interval_reason_seal_and_supersession_fail(self) -> None:
        _, _, approved = self.chain()
        fields = (
            ("approval_authority_id", "SYNTH_OTHER_AUTHORITY"),
            ("approver_id", "SYNTH_OTHER_APPROVER"),
            ("approver_role", "OTHER_ROLE"),
            ("scope", "OTHER_SCOPE"),
            ("effective_start", pack.EFFECTIVE_START + 1),
            ("effective_end", pack.EFFECTIVE_END - 1),
            ("approval_reason", "OTHER_REASON"),
            ("approval_time", pack.APPROVAL_TIME + 1),
            ("tested_stage_id", "0" * 128),
            ("tested_stage_root", "0" * 128),
            ("source_contract_root", "0" * 128),
            ("suite_root", "0" * 128),
            ("schema", "other-approval-v1"),
            ("approval_id", "0" * 128),
            ("synthetic_kat_seal", "0" * 128),
        )
        for field, replacement in fields:
            with self.subTest(field=field):
                forged = _rebind_current_stage(
                    approved,
                    lambda stage, field=field, replacement=replacement: stage["material"]["approval_record"].__setitem__(field, replacement),
                )
                with self.assertRaises(independent.IndependentControlPackError):
                    self.verify(forged)
        forged = _rebind_current_stage(
            approved,
            lambda stage: stage["material"]["approval_record"]["supersession"].__setitem__("supersession_sentinel", "OTHER"),
        )
        self.assertRaises(independent.IndependentControlPackError, self.verify, forged)

    def test_external_approval_record_is_mandatory_strict_and_exactly_bound(self) -> None:
        candidate, tested, _ = self.chain()
        fixture = _approval_fixture_bytes()
        self.assertEqual(fixture, pack._canonical(_object(fixture)))
        direct_approved, _ = pack.build_approved(tested, fixture)
        direct_approval = _object(direct_approved)["stages"][-1]["material"]["approval_record"]
        fixture_record = _object(fixture)
        for field in ("approval_id", "synthetic_kat_seal", "tested_stage_id", "tested_stage_root"):
            self.assertEqual(direct_approval[field], fixture_record[field])
        self.assertTrue(direct_approved)
        with self.assertRaisesRegex(pack.ControlPackError, "json:not-canonical"):
            pack.build_approved(tested, fixture + b"\n")
        with self.assertRaises(TypeError):
            pack.build_approved(tested)  # type: ignore[call-arg]
        for name, raw in (
            ("empty", b""),
            ("unknown", _canonical({"schema": pack.APPROVAL_SCHEMA, "unknown": 1})),
            ("duplicate", _approval_fixture_bytes().replace(b'"approval_id":"', b'"approval_id":"0","approval_id":"', 1)),
            ("trailing", _approval_fixture_bytes() + b" "),
            ("truncated", _approval_fixture_bytes()[:-1]),
            ("float", _approval_fixture_bytes().replace(b"7300", b"7300.0", 1)),
        ):
            with self.subTest(name=name):
                with self.assertRaises(pack.ControlPackError):
                    pack.build_approved(tested, raw)
        expired_candidate, _ = self.candidate("expired")
        expired_tested, _ = pack.build_tested(expired_candidate)
        with self.assertRaisesRegex(pack.ControlPackError, "approval:binding"):
            pack.build_approved(expired_tested, _approval_fixture_bytes())
        self.assertTrue(candidate)

    def test_independent_embedded_approval_schema_and_size_fail_closed(self) -> None:
        _, _, approved = self.chain()
        mutations = (
            ("unknown", lambda record: record.__setitem__("unexpected", 1)),
            ("oversize", lambda record: record.__setitem__("approval_reason", "X" * (pack.MAX_APPROVAL_BYTES + 1))),
        )
        for name, callback in mutations:
            with self.subTest(name=name):
                value = _object(approved)
                record = value["stages"][2]["material"]["approval_record"]
                callback(record)
                value["stages"][2]["approval_root"] = independent._digest("approval-root", {"approval_record": record})
                _rebind_artifact(value)
                with self.assertRaises(independent.IndependentControlPackError):
                    self.verify(_canonical(value))

    def test_rebound_approval_for_different_tested_stage_is_rejected(self) -> None:
        _, tested, approved = self.chain()
        record = _object(_approval_fixture_bytes())
        record["tested_stage_id"] = "0" * 128
        record["tested_stage_root"] = "1" * 128
        core = {key: record[key] for key in pack.APPROVAL_CORE_KEYS}
        record["approval_id"] = pack._digest("approval-id", core)
        record["synthetic_kat_seal"] = pack._digest("synthetic-kat-seal", {"approval_id": record["approval_id"], **core})
        with self.assertRaisesRegex(pack.ControlPackError, "approval:binding"):
            pack.build_approved(tested, _canonical(record))
        forged = _object(approved)
        forged_record = forged["stages"][2]["material"]["approval_record"]
        forged_record["tested_stage_id"] = record["tested_stage_id"]
        forged_record["tested_stage_root"] = record["tested_stage_root"]
        forged_record["approval_id"] = record["approval_id"]
        forged_record["synthetic_kat_seal"] = record["synthetic_kat_seal"]
        forged["stages"][2]["approval_root"] = independent._digest("approval-root", {"approval_record": forged_record})
        _rebind_artifact(forged)
        with self.assertRaises(independent.IndependentControlPackError):
            self.verify(_canonical(forged))

    def test_replay_and_duplicate_approval_are_not_accepted(self) -> None:
        _, _, approved = self.chain()
        value = _object(approved)
        duplicate = deepcopy(value["stages"][2])
        value["stages"].append(duplicate)
        self.assertRaises(independent.IndependentControlPackError, self.verify, _canonical(value))
        self.assertEqual(pack.STAGE_APPROVED, self.verify(approved)["current_stage_kind"])

    def test_producer_does_not_accept_caller_test_or_approval_boolean(self) -> None:
        candidate, _ = self.candidate()
        tested, _ = pack.build_tested(candidate)
        value = _object(tested)
        value["stages"][1]["material"]["conformance"]["results"][0]["passed"] = False
        forged = _canonical(value)
        with self.assertRaises(pack.ControlPackError):
            pack.build_approved(forged, _approval_fixture_bytes())
        with self.assertRaises(TypeError):
            pack.build_approved(forged)  # type: ignore[call-arg]

    def test_wrong_graph_provenance_integrity_and_record_time_fail(self) -> None:
        mutations = (
            ("provenance", lambda graph_value: graph_value["source_coverage"][0]["provenance"].__setitem__("provenance_id", "OTHER")),
            ("integrity", lambda graph_value: graph_value["source_coverage"][0]["provenance"].__setitem__("integrity_digest", "0" * 128)),
            ("record-time", lambda graph_value: graph_value["source_coverage"][0]["records"][0].__setitem__("observed_at", 7_001)),
        )
        for name, callback in mutations:
            with self.subTest(name=name):
                value = _object(self.candidate()[0])
                callback(value["stages"][0]["material"]["graph_artifact"])
                _rebind_artifact(value)
                with self.assertRaises(independent.IndependentControlPackError):
                    self.verify(_canonical(value))


if __name__ == "__main__":
    unittest.main()
