"""The independent checker written from conformance/GATE_RULES_V2.md reproduces the gate_rules vector output byte for byte."""

import hashlib
import os
import subprocess
import sys
import unittest

from conformance import gate_rules_v2_ref as ref
from tests.test_gate_rules_vectors import runner_source_line

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = os.path.join(ROOT, "lean", ".lake", "build", "bin", "gate_rules.exe" if os.name == "nt" else "gate_rules")
VECTORS = os.path.join(ROOT, "tests", "gate_rules")


def mine(name):
    with open(os.path.join(VECTORS, name), encoding="utf-8", newline="") as f:
        return ref.run(f.read())


def exe_out(name):
    run = subprocess.run([EXE, os.path.join(VECTORS, name)], capture_output=True, text=True, encoding="utf-8", timeout=600)
    return run.stdout.splitlines()[1:], run.returncode  # line 1 is RULES_SOURCE, a build hash


class GateRulesV2Spec(unittest.TestCase):
    def test_published_vectors_pass_in_the_checker(self):
        for name in ("rules_v2.vectors", "demo_zz_v2.vectors"):
            with self.subTest(name):
                self.assertRegex(mine(name)[-1], r"^RULES_VECTORS=PASS checked=(\d+) expected=\1 failed=0$")

    def test_negative_vectors_are_rejected_in_the_checker(self):
        out = mine("rules_v2_negative.vectors")
        self.assertTrue(out[-1].startswith("RULES_VECTORS=FAIL"))
        for tag in ("RULES_VECTOR_MALFORMED", "RULES_VECTOR_MISMATCH", "RULES_GOT", "RULES_PAY"):
            self.assertTrue(any(line.startswith(tag) for line in out), tag)

    def test_negative_output_is_the_frozen_file_in_checker_and_exe(self):
        with open(os.path.join(VECTORS, "rules_v2_negative.expected"), encoding="ascii", newline="") as f:
            frozen = f.read().splitlines()
        self.assertEqual(mine("rules_v2_negative.vectors"), frozen)
        self.assertEqual(exe_out("rules_v2_negative.vectors")[0], frozen)

    def test_checker_output_equals_exe_output(self):
        self.assertTrue(os.path.isfile(EXE), f"gate_rules exe missing: {EXE}")
        self.assertEqual(*runner_source_line(), "gate_rules was not built from these sources; run `lake build gate_rules` in lean/")
        for name in ("rules_v2.vectors", "demo_zz_v2.vectors", "rules_v2_negative.vectors"):
            with self.subTest(name):
                out, code = exe_out(name)
                self.assertEqual(mine(name), out)
                self.assertEqual(code, 0 if out[-1].startswith("RULES_VECTORS=PASS") else 1)

    def test_g2_cases_are_covered(self):
        """Every G2 reason is decided somewhere in the published or negative vectors, so the checker's G2 arms are compared."""
        seen = "\n".join(mine("rules_v2.vectors") + mine("rules_v2_negative.vectors"))
        with open(os.path.join(VECTORS, "rules_v2.vectors"), encoding="utf-8") as f:
            seen += f.read()
        for reason in ("BENEFIT_LEVEL_MISSING", "BENEFIT_LEVEL_MISSING_UNVERIFIED", "PROGRAM_NOT_ELIGIBLE",
                       "PROGRAM_NOT_ELIGIBLE_UNVERIFIED", "STALE_ELIGIBILITY"):
            with self.subTest(reason):
                self.assertIn(" " + reason, seen.replace(",", " "))

    def test_aid_codes_are_the_page_numbers(self):
        self.assertEqual(ref.aid_id("13"), 78131)
        self.assertEqual(sorted(ref.ALLOWED_AID), [78131, 78387, 79155, 20000819, 20000820])
        self.assertNotIn(ref.aid_id("105"), ref.ALLOWED_AID)
        self.assertNotIn(ref.aid_id("D3"), ref.ALLOWED_AID)

    def test_checker_parses_any_length_and_leaves_the_process_digit_limit_alone(self):
        # t18f1: a global set_int_max_str_digits(0) here let later tests' hostile huge integers through.
        self.assertNotEqual(sys.get_int_max_str_digits(), 0)
        self.assertEqual(ref.num("7" * 9000), (10 ** 9000 - 1) // 9 * 7)
        self.assertIsNone(ref.num("1_000"))

    def test_manifest_hashes_still_match(self):
        with open(os.path.join(ROOT, "conformance", "MANIFEST.sha256"), encoding="utf-8") as f:
            for line in f.read().splitlines():
                want, path = line.split("  ", 1)
                with open(os.path.join(ROOT, path), "rb") as g:
                    self.assertEqual(hashlib.sha256(g.read()).hexdigest(), want, f"{path} changed after it was published")


if __name__ == "__main__":
    unittest.main()
