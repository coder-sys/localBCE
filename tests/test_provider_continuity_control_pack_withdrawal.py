"""Focused terminal withdrawal contract and independent-verifier tests."""

from __future__ import annotations

from copy import deepcopy
import json
import subprocess
import sys
import unittest

from app.governance import provider_continuity_control_pack as pack
from app.governance import provider_continuity_control_pack_independent as pack_independent
from app.governance import provider_continuity_control_pack_withdrawal as withdrawal
from app.governance import provider_continuity_control_pack_withdrawal_independent as independent
from tests.test_provider_continuity_control_pack import APPROVAL_FIXTURE_BYTES


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")


def _object(raw: bytes) -> dict[str, object]:
    value = json.loads(raw.decode("ascii"))
    if not isinstance(value, dict):
        raise AssertionError("expected object")
    return value


def _approved() -> bytes:
    candidate, _ = pack.build_demo_candidate()
    tested, _ = pack.build_tested(candidate)
    approved, _ = pack.build_approved(tested, APPROVAL_FIXTURE_BYTES)
    return approved


def _authorization(approved_raw: bytes) -> bytes:
    approved = _object(approved_raw)
    stages = approved["stages"]
    assert isinstance(stages, list) and len(stages) == 3
    stage = stages[-1]
    assert isinstance(stage, dict)
    material = stage["material"]
    assert isinstance(material, dict)
    approval = material["approval_record"]
    assert isinstance(approval, dict)
    core = {
        "schema": withdrawal.AUTHORIZATION_SCHEMA,
        "authority_id": withdrawal.WITHDRAWAL_AUTHORITY_ID,
        "withdrawer_id": withdrawal.WITHDRAWER_ID,
        "authorized_role": withdrawal.WITHDRAWER_ROLE,
        "reason_code": withdrawal.WITHDRAWAL_REASON,
        "withdrawal_time": withdrawal.WITHDRAWAL_TIME,
        "effective_time": withdrawal.EFFECTIVE_TIME,
        "provider_graph_subject": withdrawal.PROVIDER_GRAPH_SUBJECT,
        "scope": withdrawal.SCOPE,
        "effective_start": withdrawal.EFFECTIVE_START,
        "effective_end": withdrawal.EFFECTIVE_END,
        "prior_approved_artifact_id": approved["artifact_id"],
        "prior_approved_stage_id": stage["stage_id"],
        "prior_approved_stage_root": stage["stage_root"],
        "prior_approval_id": approval["approval_id"],
        "prior_approval_root": stage["approval_root"],
        "source_contract_root": stage["source_contract_root"],
        "suite_root": stage["suite_root"],
        "terminal_sentinel": withdrawal.TERMINAL_SENTINEL,
    }
    authorization_id = withdrawal._digest("withdrawal-authorization-id", core)
    return _canonical({
        **core,
        "withdrawal_authorization_id": authorization_id,
        "synthetic_kat_seal": withdrawal._digest(
            "synthetic-kat-seal", {"withdrawal_authorization_id": authorization_id, **core}
        ),
    })


def _artifact_with_rebound_outer(raw: bytes, callback) -> bytes:
    value = _object(raw)
    callback(value)
    value["withdrawal_root"] = withdrawal._digest("withdrawal-root", withdrawal._withdrawal_body(value))
    value["withdrawal_id"] = withdrawal._digest("withdrawal-id", {"action": withdrawal.ACTION, "withdrawal_root": value["withdrawal_root"]})
    value["artifact_id"] = withdrawal._digest("artifact-id", {key: item for key, item in value.items() if key != "artifact_id"})
    return _canonical(value)


def _artifact_with_rebound_auth(raw: bytes, callback) -> bytes:
    value = _object(raw)
    authorization = value["withdrawal_authorization"]
    assert isinstance(authorization, dict)
    callback(authorization)
    core = {key: authorization[key] for key in independent.AUTHORIZATION_CORE_KEYS}
    authorization["withdrawal_authorization_id"] = independent._digest("withdrawal-authorization-id", core)
    authorization["synthetic_kat_seal"] = independent._digest(
        "synthetic-kat-seal", {"withdrawal_authorization_id": authorization["withdrawal_authorization_id"], **core}
    )
    value["withdrawal_authorization_id"] = authorization["withdrawal_authorization_id"]
    value["withdrawal_authorization_root"] = independent._digest("withdrawal-authorization-root", {"authorization": authorization})
    return _artifact_with_rebound_outer(_canonical(value), lambda _value: None)


class ProviderContinuityWithdrawalV1Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.approved = _approved()
        cls.authorization = _authorization(cls.approved)
        cls.raw, cls.telemetry = withdrawal.build_withdrawal(cls.approved, cls.authorization)

    def test_valid_deterministic_and_exact_flags(self) -> None:
        raw_again, telemetry = withdrawal.build_withdrawal(self.approved, self.authorization)
        self.assertEqual(raw_again, self.raw)
        self.assertEqual(independent.verify_bytes(self.raw)["accepted"], True)
        self.assertLess(len(self.raw), withdrawal.MAX_ARTIFACT_BYTES)
        self.assertEqual(telemetry["children_launched"], 0)
        value = _object(self.raw)
        self.assertEqual(value["action"], withdrawal.ACTION)
        self.assertEqual(value["status"], withdrawal.STATUS)
        self.assertTrue(value["terminal"])
        for key, expected in withdrawal.AUTHORITY_FLAGS.items():
            self.assertEqual(value[key], expected)

    def test_external_authorization_is_required_and_candidate_or_tested_reject(self) -> None:
        with self.assertRaises(TypeError):
            withdrawal.build_withdrawal(self.approved)  # type: ignore[call-arg]
        candidate, _ = pack.build_demo_candidate()
        tested, _ = pack.build_tested(candidate)
        with self.assertRaises(withdrawal.WithdrawalError):
            withdrawal.build_withdrawal(candidate, self.authorization)
        with self.assertRaises(withdrawal.WithdrawalError):
            withdrawal.build_withdrawal(tested, self.authorization)

    def test_cross_process_independent_accept_and_truncation_reject(self) -> None:
        from tempfile import TemporaryDirectory
        from pathlib import Path

        with TemporaryDirectory() as directory:
            path = Path(directory) / "withdrawal.json"
            path.write_bytes(self.raw)
            accepted = subprocess.run(
                [sys.executable, "-m", "app.governance.provider_continuity_control_pack_withdrawal_independent", str(path)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            path.write_bytes(self.raw[:-1])
            rejected = subprocess.run(
                [sys.executable, "-m", "app.governance.provider_continuity_control_pack_withdrawal_independent", str(path)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(rejected.returncode, 0)

    def test_input_encoding_and_shape_fail_closed(self) -> None:
        for bad in (b"", self.raw + b"\n", self.raw[:-1], b"\xef\xbb\xbf" + self.raw, b"{}"):
            with self.subTest(length=len(bad)), self.assertRaises(independent.IndependentWithdrawalError):
                independent.verify_bytes(bad)
        value = _object(self.raw)
        value["unknown"] = 1
        with self.assertRaises(independent.IndependentWithdrawalError):
            independent.verify_bytes(_canonical(value))

    def test_authorization_bytes_are_strict_and_bounded(self) -> None:
        authorization = _object(self.authorization)
        authorization.pop("reason_code")
        with self.assertRaises(withdrawal.WithdrawalError):
            withdrawal.build_withdrawal(self.approved, _canonical(authorization))
        bad_binding = _object(self.authorization)
        bad_binding["authority_id"] = "OTHER_AUTHORITY"
        with self.assertRaises(withdrawal.WithdrawalError):
            withdrawal.build_withdrawal(self.approved, _canonical(bad_binding))
        duplicate = self.authorization[:-1] + b',"schema":"duplicate"}'
        with self.assertRaises(withdrawal.WithdrawalError):
            withdrawal.build_withdrawal(self.approved, duplicate)
        with self.assertRaises(withdrawal.WithdrawalError):
            withdrawal.build_withdrawal(self.approved, self.authorization + b"\n")
        with self.assertRaises(withdrawal.WithdrawalError):
            withdrawal.build_withdrawal(self.approved, b"x" * (withdrawal.MAX_AUTHORIZATION_BYTES + 1))

    def test_top_level_omission_and_duplicate_fields_reject(self) -> None:
        omitted = _object(self.raw)
        omitted.pop("status")
        with self.assertRaises(independent.IndependentWithdrawalError):
            independent.verify_bytes(_canonical(omitted))
        duplicate = self.raw[:-1] + b',"action":"WITHDRAWN_OBSERVATION_ONLY"}'
        with self.assertRaises(independent.IndependentWithdrawalError):
            independent.verify_bytes(duplicate)

    def test_prior_stage_and_all_outer_digest_bindings_reject(self) -> None:
        fields = (
            "approved_artifact_id",
            "approved_artifact_sha3_512",
            "approved_stage_id",
            "approved_stage_root",
            "approval_id",
            "approval_root",
            "source_contract_root",
            "suite_root",
            "withdrawal_authorization_id",
            "withdrawal_authorization_root",
        )
        for field in fields:
            def mutate(value: dict[str, object], field: str = field) -> None:
                value[field] = "0" * 128

            with self.subTest(field=field), self.assertRaises(independent.IndependentWithdrawalError):
                independent.verify_bytes(_artifact_with_rebound_outer(self.raw, mutate))

    def test_forbidden_clearance_payment_and_activation_material_rejects(self) -> None:
        for key, injected in (
            ("effectiveDirective", "CLEAR"),
            ("ClearanceDecisionRow", "x"),
            ("payment_authorization", "x"),
            ("activation", False),
        ):
            value = _object(self.raw)
            value[key] = injected
            with self.subTest(key=key), self.assertRaises(independent.IndependentWithdrawalError):
                independent.verify_bytes(_canonical(value))

    def test_withdrawal_identity_and_prior_origin_mutations_reject(self) -> None:
        for field in ("withdrawal_id", "withdrawal_root"):
            value = _object(self.raw)
            value[field] = "0" * 128
            with self.subTest(field=field), self.assertRaises(independent.IndependentWithdrawalError):
                independent.verify_bytes(_canonical(value))
        value = _object(self.raw)
        prior = value["approved_artifact"]
        assert isinstance(prior, dict)
        stages = prior["stages"]
        assert isinstance(stages, list)
        approved_stage = stages[-1]
        assert isinstance(approved_stage, dict)
        approved_stage["origin"] = "OTHER_ORIGIN"
        with self.assertRaises(independent.IndependentWithdrawalError):
            independent.verify_bytes(_canonical(value))

    def test_noncanonical_reordered_top_level_is_rejected(self) -> None:
        value = _object(self.raw)
        reordered = dict(reversed(list(value.items())))
        reordered_raw = json.dumps(reordered, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        self.assertNotEqual(reordered_raw, self.raw)
        with self.assertRaises(independent.IndependentWithdrawalError):
            independent.verify_bytes(reordered_raw)
        value = _object(self.raw)
        value["withdrawal_time"] = 7400.0
        with self.assertRaises(independent.IndependentWithdrawalError):
            independent.verify_bytes(_canonical(value))

    def test_top_level_bindings_reject_after_outer_rebind(self) -> None:
        mutations = {
            "action": lambda value: value.__setitem__("action", "OTHER_ACTION"),
            "status": lambda value: value.__setitem__("status", "OTHER_STATUS"),
            "authority": lambda value: value.__setitem__("authority_profile_root", "0" * 128),
            "subject": lambda value: value.__setitem__("provider_graph_subject", "OTHER_PROVIDER"),
            "scope": lambda value: value.__setitem__("scope", "OTHER_SCOPE"),
            "origin": lambda value: value.__setitem__("origin", "OTHER_ORIGIN"),
            "effective-time": lambda value: value.__setitem__("effective_time", 7401),
            "withdrawal-time": lambda value: value.__setitem__("withdrawal_time", 7401),
            "interval": lambda value: value.__setitem__("effective_end", 9001),
            "terminal": lambda value: value.__setitem__("terminal", False),
            "sentinel": lambda value: value.__setitem__("terminal_sentinel", "OTHER"),
        }
        for name, callback in mutations.items():
            with self.subTest(name=name), self.assertRaises(independent.IndependentWithdrawalError):
                independent.verify_bytes(_artifact_with_rebound_outer(self.raw, callback))

    def test_authorization_bindings_and_seal_reject(self) -> None:
        mutations = {
            "authority": lambda value: value.__setitem__("authority_id", "OTHER"),
            "withdrawer": lambda value: value.__setitem__("withdrawer_id", "OTHER"),
            "role": lambda value: value.__setitem__("authorized_role", "OTHER"),
            "reason": lambda value: value.__setitem__("reason_code", "OTHER"),
            "time": lambda value: value.__setitem__("withdrawal_time", 7401),
            "effective": lambda value: value.__setitem__("effective_time", 7401),
            "prior-stage": lambda value: value.__setitem__("prior_approved_stage_id", "0" * 128),
            "prior-root": lambda value: value.__setitem__("prior_approved_stage_root", "0" * 128),
        }
        for name, callback in mutations.items():
            with self.subTest(name=name), self.assertRaises(independent.IndependentWithdrawalError):
                independent.verify_bytes(_artifact_with_rebound_auth(self.raw, callback))
        bad_seal = _object(self.raw)
        authorization = bad_seal["withdrawal_authorization"]
        assert isinstance(authorization, dict)
        authorization["synthetic_kat_seal"] = "0" * 128
        with self.assertRaises(independent.IndependentWithdrawalError):
            independent.verify_bytes(_canonical(bad_seal))

    def test_prior_artifact_is_complete_and_not_rebound_summary(self) -> None:
        def mutate_prior(value: dict[str, object]) -> None:
            prior = value["approved_artifact"]
            assert isinstance(prior, dict)
            prior["current_stage_id"] = "0" * 128
            value["approved_artifact_sha3_512"] = withdrawal._bytes_digest("approved-artifact", _canonical(prior))
            value["approved_artifact_id"] = prior["artifact_id"]

        with self.assertRaises(independent.IndependentWithdrawalError):
            independent.verify_bytes(_artifact_with_rebound_outer(self.raw, mutate_prior))

    def test_approval_and_prior_identity_mutations_reject(self) -> None:
        def mutate_prior(value: dict[str, object]) -> None:
            prior = value["approved_artifact"]
            assert isinstance(prior, dict)
            stages = prior["stages"]
            assert isinstance(stages, list)
            approved = stages[-1]
            assert isinstance(approved, dict)
            approved["approval_root"] = "0" * 128

        with self.assertRaises(independent.IndependentWithdrawalError):
            independent.verify_bytes(_artifact_with_rebound_outer(self.raw, mutate_prior))

    def test_no_reactivation_or_replacement_api_and_no_producer_import(self) -> None:
        self.assertFalse(hasattr(withdrawal, "reactivate"))
        self.assertFalse(hasattr(withdrawal, "replace_approval"))
        self.assertNotIn("provider_continuity_control_pack as", __import__("pathlib").Path(independent.__file__).read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
