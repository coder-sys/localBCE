import copy
import csv
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path

from app.batch.batch_orchestrator import BatchConfig, _claim_source_commitment_for_oracle
from app.batch.leaf import current_duplicate_pepper
from app.ingestion import parse_837
from app.models import Patient, Provider, ServiceLine, SharedContext
from app.oracle_attestation import make_test_attestation
from app.rules_engine_adapter import canonical_rules_engine_context_payload
from app.rules_engine_fallback import adjudicate as python_adjudicate
from app.shared_context import build_shared_context, tar_authorization_commitment_for_context


ROOT = Path(__file__).resolve().parents[1]
RUST_CRATE = ROOT / "rules-engine-rust"
RUST_BUILD_INPUTS = (
    RUST_CRATE / "Cargo.toml",
    RUST_CRATE / "Cargo.lock",
    RUST_CRATE / "src" / "lib.rs",
    RUST_CRATE / "src" / "main.rs",
    ROOT / "rarc_mapping.tsv",
    ROOT / "app" / "policy" / "tar_required_procedures_v1.json",
)


def _default_rust_target_dir() -> Path:
    identity = hashlib.sha256(str(ROOT).encode("utf-8"))
    for path in RUST_BUILD_INPUTS:
        identity.update(path.relative_to(ROOT).as_posix().encode("utf-8"))
        identity.update(path.read_bytes())
    return Path(tempfile.gettempdir()) / f"blind-ledger-rules-{identity.hexdigest()[:16]}"


RUST_TARGET_DIR = Path(
    os.environ.get("BL_RULES_ENGINE_TARGET_DIR")
    or os.environ.get("CARGO_TARGET_DIR")
    or _default_rust_target_dir()
)
RUST_BIN = RUST_TARGET_DIR / "debug" / "rules-engine.exe"
CARGO = Path(os.environ.get("BL_CARGO") or shutil.which("cargo") or "cargo")
TOOLCHAIN = "1.96.0-x86_64-pc-windows-msvc"
VSDEV = Path(r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat")
DECISION_FACTS = (
    "eligibility_active",
    "provider_enrolled",
    "provider_not_suspended",
    "not_deceased",
    "duplicate_claim",
    "program_integrity_hold",
)


def base_context() -> SharedContext:
    return SharedContext(
        claim_id="TEST-CLAIM",
        transaction_set="837",
        payer_id="PAYER",
        member_id="M1",
        patient=Patient(name="Jane Doe", id="M1"),
        provider=Provider(npi="1999999987", name="Alice Adams"),
        service_date="20260601",
        diagnoses=["F840"],
        service_lines=[
            ServiceLine(
                line_id="1",
                procedure_code="99213",
                charge_amount=125.0,
                units=1.0,
                prior_authorization="PA-OK",
            )
        ],
        total_charge=125.0,
        flags={
            "eligibility_active": True,
            "provider_enrolled": True,
            "provider_not_suspended": True,
            "not_deceased": True,
            "duplicate_claim": False,
            "program_integrity_hold": False,
        },
    )


def load_mapping() -> dict[str, tuple[str, str]]:
    with (ROOT / "rarc_mapping.tsv").open(encoding="utf-8", newline="") as handle:
        return {
            row["reason"]: (row["carc"], row["rarc"])
            for row in csv.DictReader(handle, delimiter="\t")
        }


def ensure_rust_binary() -> None:
    if RUST_BIN.exists() and all(path.stat().st_mtime <= RUST_BIN.stat().st_mtime for path in RUST_BUILD_INPUTS):
        return
    if not CARGO.exists():
        raise AssertionError(f"cargo not found at {CARGO}")
    build_env = os.environ.copy()
    build_env["CARGO_TARGET_DIR"] = str(RUST_TARGET_DIR)
    proc = subprocess.run([str(CARGO), f"+{TOOLCHAIN}", "build"], cwd=RUST_CRATE, text=True, capture_output=True, env=build_env)
    if proc.returncode != 0 and VSDEV.exists():
        command = f'call "{VSDEV}" -arch=x64 -host_arch=x64 && "{CARGO}" +{TOOLCHAIN} build'
        proc = subprocess.run(["cmd.exe", "/c", command], cwd=RUST_CRATE, text=True, capture_output=True, env=build_env)
    if proc.returncode != 0:
        raise AssertionError(f"rust build failed\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")
    if not RUST_BIN.exists():
        raise AssertionError(f"rust rules-engine binary not found at {RUST_BIN}")


def rust_adjudicate(ctx: SharedContext) -> dict:
    context_payload = canonical_rules_engine_context_payload(ctx)
    proc = subprocess.run(
        [str(RUST_BIN), json.dumps(context_payload)],
        cwd=RUST_CRATE,
        text=True,
        capture_output=True,
        check=True,
    )
    return json.loads(proc.stdout)


def python_result_dict(ctx: SharedContext) -> dict:
    result = python_adjudicate(ctx)
    return asdict(result)


def gate(result: dict, gate_name: str) -> dict:
    for item in result["gates"]:
        if item["gate"] == gate_name:
            return item
    raise AssertionError(f"missing gate {gate_name}")


def no_change(ctx: SharedContext) -> None:
    return None


def g1_fail(ctx: SharedContext) -> None:
    ctx.member_id = ""
    ctx.patient.id = ""


def g2_fail(ctx: SharedContext) -> None:
    ctx.flags["eligibility_active"] = False


def g3_fail(ctx: SharedContext) -> None:
    ctx.provider.npi = ""


def g4_fail(ctx: SharedContext) -> None:
    ctx.flags["provider_enrolled"] = False


def g2b_fail(ctx: SharedContext) -> None:
    ctx.flags["not_deceased"] = False


def g4b_fail(ctx: SharedContext) -> None:
    ctx.flags["provider_not_suspended"] = False


def g5_fail(ctx: SharedContext) -> None:
    ctx.service_lines = []
    ctx.total_charge = 0.0


def g6_fail(ctx: SharedContext) -> None:
    ctx.diagnoses = []


def g7_pass_required_pa(ctx: SharedContext) -> SharedContext:
    return signed_tar_context("TEST-G7-PA-PASS")


def g7_fail(ctx: SharedContext) -> None:
    ctx.service_lines[0].procedure_code = "T1019"
    ctx.service_lines[0].prior_authorization = None


def g8_fail_zero_total(ctx: SharedContext) -> None:
    ctx.total_charge = 0.0
    ctx.service_lines[0].charge_amount = 0.0


def g9_fail(ctx: SharedContext) -> None:
    ctx.flags["duplicate_claim"] = True


def g10_fail(ctx: SharedContext) -> None:
    ctx.flags["program_integrity_hold"] = True


def multi_gate_fail(ctx: SharedContext) -> None:
    g1_fail(ctx)
    g2_fail(ctx)
    g3_fail(ctx)


def signed_tar_context(claim_id: str) -> SharedContext:
    payload = json.loads((ROOT / "sample_claim_input.json").read_text(encoding="utf-8"))
    payload["edi"] = payload["edi"].replace("BL-CLAIM-0001", claim_id)
    payload["edi"] = payload["edi"].replace("SV1*HC:99213*125.00", "SV1*HC:T1019*125.00")
    parsed = parse_837(payload["edi"])
    if not parsed.accepted:
        raise AssertionError(parsed.errors)
    config = BatchConfig()
    unsigned_ctx = build_shared_context(
        parsed,
        payload["flags"],
        strict_oracle=False,
        tar_required_procedure_codes=config.tar_required_procedure_codes,
    )
    claim_source_commitment = _claim_source_commitment_for_oracle(
        unsigned_ctx,
        config=config,
        frequency_type="original",
        duplicate_pepper=current_duplicate_pepper(),
    )
    tar_authorization_commitment = tar_authorization_commitment_for_context(
        unsigned_ctx,
        config.tar_required_procedure_codes,
    )
    attestations = [
        make_test_attestation(
            fact,
            bool(payload["flags"][fact]),
            source_id=f"TEST-{fact}",
            claim_id=claim_id,
            claim_source_commitment=claim_source_commitment,
            tar_authorization_commitment=tar_authorization_commitment,
        )
        for fact in DECISION_FACTS
    ]
    return build_shared_context(
        parsed,
        payload["flags"],
        oracle_attestations=attestations,
        strict_oracle=True,
        claim_source_commitment=claim_source_commitment,
        tar_required_procedure_codes=config.tar_required_procedure_codes,
    )


CASES = [
    ("g1_pass", no_change, "G1_MEMBER_ID_PRESENT", True, ""),
    ("g1_fail_missing_member", g1_fail, "G1_MEMBER_ID_PRESENT", False, "member_id_missing"),
    ("g2_pass", no_change, "G2_ELIGIBILITY_ACTIVE", True, ""),
    ("g2_fail_inactive", g2_fail, "G2_ELIGIBILITY_ACTIVE", False, "eligibility_inactive"),
    ("g3_pass", no_change, "G3_PROVIDER_NPI_PRESENT", True, ""),
    ("g3_fail_missing_npi", g3_fail, "G3_PROVIDER_NPI_PRESENT", False, "provider_npi_missing"),
    ("g4_pass", no_change, "G4_PROVIDER_ENROLLED", True, ""),
    ("g4_fail_not_enrolled", g4_fail, "G4_PROVIDER_ENROLLED", False, "provider_not_enrolled"),
    ("g2b_fail_patient_deceased", g2b_fail, "G2B_PATIENT_NOT_DECEASED", False, "patient_deceased"),
    ("g4b_fail_provider_suspended", g4b_fail, "G4B_PROVIDER_NOT_SUSPENDED", False, "provider_suspended"),
    ("g5_pass", no_change, "G5_SERVICE_LINES_PRESENT", True, ""),
    ("g5_fail_missing_line", g5_fail, "G5_SERVICE_LINES_PRESENT", False, "service_line_missing"),
    ("g6_pass", no_change, "G6_DIAGNOSIS_PRESENT", True, ""),
    ("g6_fail_missing_diagnosis", g6_fail, "G6_DIAGNOSIS_PRESENT", False, "diagnosis_missing"),
    ("g7_pass_required_pa_present", g7_pass_required_pa, "G7_PRIOR_AUTH_WHEN_REQUIRED", True, ""),
    ("g7_fail_missing_pa", g7_fail, "G7_PRIOR_AUTH_WHEN_REQUIRED", False, "prior_authorization_required"),
    ("g8_fail_zero_total", g8_fail_zero_total, "G8A_CHARGE_VALID", False, "invalid_charge"),
    ("g9_pass", no_change, "G9_NOT_DUPLICATE", True, ""),
    ("g9_fail_duplicate", g9_fail, "G9_NOT_DUPLICATE", False, "duplicate_claim"),
    ("g10_pass", no_change, "G10_NO_PROGRAM_INTEGRITY_HOLD", True, ""),
    ("g10_fail_hold", g10_fail, "G10_NO_PROGRAM_INTEGRITY_HOLD", False, "program_integrity_hold"),
    ("multi_gate_failure_first_reason_wins", multi_gate_fail, "G1_MEMBER_ID_PRESENT", False, "member_id_missing"),
]


class RulesEngineAgreementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ensure_rust_binary()
        cls.mapping = load_mapping()

    def run_case(self, name, mutator, expected_gate, expected_passed, expected_reason):
        ctx = copy.deepcopy(base_context())
        ctx.claim_id = f"TEST-{name.upper()}"
        replacement_ctx = mutator(ctx)
        if replacement_ctx is not None:
            ctx = replacement_ctx

        py_result = python_result_dict(ctx)
        rust_result = rust_adjudicate(ctx)

        comparable_keys = ["approved", "denial_reason", "gates", "carc", "rarc", "total_charge", "payable_amount"]
        self.assertEqual({key: py_result[key] for key in comparable_keys}, {key: rust_result[key] for key in comparable_keys})

        selected_gate = gate(py_result, expected_gate)
        self.assertEqual(selected_gate["passed"], expected_passed)
        self.assertEqual(selected_gate["reason"], expected_reason)

        if expected_reason:
            self.assertFalse(py_result["approved"])
            self.assertEqual(py_result["denial_reason"], expected_reason)
            self.assertEqual((py_result["carc"], py_result["rarc"]), self.mapping[expected_reason])
        else:
            self.assertEqual(selected_gate["reason"], "")

    def test_unknown_procedure_denies_instead_of_approving_zero_payable(self):
        ctx = copy.deepcopy(base_context())
        ctx.claim_id = "TEST-UNKNOWN-PROCEDURE"
        ctx.service_lines[0].procedure_code = "ZZZ999"

        py_result = python_result_dict(ctx)
        rust_result = rust_adjudicate(ctx)

        for result in (py_result, rust_result):
            self.assertFalse(result["approved"])
            self.assertEqual(result["denial_reason"], "fee_schedule_missing")
            self.assertEqual(result["payable_amount"], 0.0)
            self.assertEqual(gate(result, "G8B_FEE_SCHEDULE_PRESENT")["passed"], False)

    def test_known_procedure_still_approves_and_pays(self):
        ctx = copy.deepcopy(base_context())

        py_result = python_result_dict(ctx)
        rust_result = rust_adjudicate(ctx)

        for result in (py_result, rust_result):
            self.assertTrue(result["approved"])
            self.assertEqual(result["denial_reason"], "")
            self.assertEqual(result["payable_amount"], 125.0)


def make_test(case):
    def test(self):
        self.run_case(*case)

    test.__name__ = f"test_{case[0]}"
    return test


for test_case in CASES:
    setattr(RulesEngineAgreementTests, f"test_{test_case[0]}", make_test(test_case))


if __name__ == "__main__":
    unittest.main()
