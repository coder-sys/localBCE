import copy
import csv
import json
import os
import subprocess
import unittest
from dataclasses import asdict
from pathlib import Path

from app.models import Patient, Provider, ServiceLine, SharedContext
from app.rules_engine_fallback import adjudicate as python_adjudicate


ROOT = Path(__file__).resolve().parents[1]
RUST_CRATE = ROOT / "rules-engine-rust"
RUST_BIN = RUST_CRATE / "target" / "debug" / "rules-engine.exe"
CARGO = Path(os.environ.get("BL_CARGO", r"C:\Users\neers\.cargo\bin\cargo.exe"))
TOOLCHAIN = "1.96.0-x86_64-pc-windows-msvc"
VSDEV = Path(r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat")


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
    if RUST_BIN.exists():
        return
    if not CARGO.exists():
        raise AssertionError(f"cargo not found at {CARGO}")
    if VSDEV.exists():
        command = f'call "{VSDEV}" -arch=x64 -host_arch=x64 && "{CARGO}" +{TOOLCHAIN} build'
        proc = subprocess.run(["cmd.exe", "/c", command], cwd=RUST_CRATE, text=True, capture_output=True)
    else:
        proc = subprocess.run([str(CARGO), f"+{TOOLCHAIN}", "build"], cwd=RUST_CRATE, text=True, capture_output=True)
    if proc.returncode != 0:
        raise AssertionError(f"rust build failed\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")
    if not RUST_BIN.exists():
        raise AssertionError(f"rust rules-engine binary not found at {RUST_BIN}")


def rust_adjudicate(ctx: SharedContext) -> dict:
    proc = subprocess.run(
        [str(RUST_BIN), json.dumps(ctx.to_dict())],
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


def g5_fail(ctx: SharedContext) -> None:
    ctx.service_lines = []


def g6_fail(ctx: SharedContext) -> None:
    ctx.diagnoses = []


def g7_pass_required_pa(ctx: SharedContext) -> None:
    ctx.service_lines[0].procedure_code = "T1019"
    ctx.service_lines[0].prior_authorization = "PA-OK"


def g7_fail(ctx: SharedContext) -> None:
    ctx.service_lines[0].procedure_code = "T1019"
    ctx.service_lines[0].prior_authorization = None


def g8_pass_threshold(ctx: SharedContext) -> None:
    ctx.service_lines[0].charge_amount = 5000.0
    ctx.total_charge = 5000.0


def g8_fail_above_threshold(ctx: SharedContext) -> None:
    ctx.service_lines[0].charge_amount = 5000.01
    ctx.total_charge = 5000.01


def g8_fail_zero_total(ctx: SharedContext) -> None:
    ctx.total_charge = 0.0


def g9_fail(ctx: SharedContext) -> None:
    ctx.flags["duplicate_claim"] = True


def g10_fail(ctx: SharedContext) -> None:
    ctx.flags["program_integrity_hold"] = True


def multi_gate_fail(ctx: SharedContext) -> None:
    g1_fail(ctx)
    g2_fail(ctx)
    g3_fail(ctx)


CASES = [
    ("g1_pass", no_change, "G1_MEMBER_ID_PRESENT", True, ""),
    ("g1_fail_missing_member", g1_fail, "G1_MEMBER_ID_PRESENT", False, "member_id_missing"),
    ("g2_pass", no_change, "G2_ELIGIBILITY_ACTIVE", True, ""),
    ("g2_fail_inactive", g2_fail, "G2_ELIGIBILITY_ACTIVE", False, "eligibility_inactive"),
    ("g3_pass", no_change, "G3_PROVIDER_NPI_PRESENT", True, ""),
    ("g3_fail_missing_npi", g3_fail, "G3_PROVIDER_NPI_PRESENT", False, "provider_npi_missing"),
    ("g4_pass", no_change, "G4_PROVIDER_ENROLLED", True, ""),
    ("g4_fail_not_enrolled", g4_fail, "G4_PROVIDER_ENROLLED", False, "provider_not_enrolled"),
    ("g5_pass", no_change, "G5_SERVICE_LINES_PRESENT", True, ""),
    ("g5_fail_missing_line", g5_fail, "G5_SERVICE_LINES_PRESENT", False, "service_line_missing"),
    ("g6_pass", no_change, "G6_DIAGNOSIS_PRESENT", True, ""),
    ("g6_fail_missing_diagnosis", g6_fail, "G6_DIAGNOSIS_PRESENT", False, "diagnosis_missing"),
    ("g7_pass_required_pa_present", g7_pass_required_pa, "G7_PRIOR_AUTH_WHEN_REQUIRED", True, ""),
    ("g7_fail_missing_pa", g7_fail, "G7_PRIOR_AUTH_WHEN_REQUIRED", False, "prior_authorization_required"),
    ("g8_pass_exact_threshold", g8_pass_threshold, "G8B_CHARGE_WITHIN_ALLOWABLE", True, ""),
    ("g8_fail_above_threshold", g8_fail_above_threshold, "G8B_CHARGE_WITHIN_ALLOWABLE", False, "excessive_charge"),
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
        mutator(ctx)

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


def make_test(case):
    def test(self):
        self.run_case(*case)

    test.__name__ = f"test_{case[0]}"
    return test


for test_case in CASES:
    setattr(RulesEngineAgreementTests, f"test_{test_case[0]}", make_test(test_case))


if __name__ == "__main__":
    unittest.main()
