"""The G2 rule-set pack through RightRail's Lean tool `ruleset_admit`, and a test-key admission.  Local only.

**A test-key admission checks mechanics only. It is not a real signed rule set.**  The keys are RightRail's fixed
test-only keys, derived in memory from public constants by the signer's known-answer mode (`kat-keygen`); no key or
seed file is made and `keygen` is never run.  The admitted copies carry the test fixture's state, tenant and signing
window, so their digests are not the pinned ones, and nobody with authority over a rule set has signed anything.
An `ADMIT` line here says only that the record is well formed, names no unbacked reason, and passes the Lean
admission code under a test key set.  It does not say any gate runs the pack: none does until the engine carries the
eligibility read.

What is checked (scripts/g2_ruleset_pack_lean.py does the run, in its own process):
- Lean's own evaluation (`dataFires`, EVAL lines) of all 43 cases, on the eligibility-only and the full record as
  built, equals RightRail's Python reference and the pinned expected reasons.
- A copy of each record signed by the two test policy keys is admitted with its body digest; signed under the
  version 1 tag, or by one key only, it is refused UNSIGNED; with a benefit level rule (24) it is refused NOSOURCE.

Skipped, with the reason named, unless all of these hold (the owner accepted the skip in CI on 2026-11-28):
- G2_LEAN_CHECK=1 is set.  The run starts the Lean executable and the signer, so it belongs under the memory guard
  (scripts/rr_guarded_interim.ps1), not in the ordinary check set.
- `ruleset_admit.exe` is built (`lake build` in rightrail/lean; CI does not build Lean).
- The pinned signer `rr_gate_mldsa87.exe` is found (CI does not have it).
Synthetic, not legally verified, nonpayment.
"""

import json
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import build_g2_ruleset_pack as gp  # noqa: E402
import g2_ruleset_pack_lean as gl  # noqa: E402

ref = gp.load_module("rr_ruleset_v2_ref", "rightrail/conformance/ruleset_v2_ref.py")
EXPECTED = json.loads(gp.EXPECTED.read_text("utf-8"))
STALE_ENROLLMENT = 19


def skip_reason():
    if os.environ.get("G2_LEAN_CHECK") != "1":
        return "local only: set G2_LEAN_CHECK=1 and run under the memory guard (scripts/rr_guarded_interim.ps1)"
    missing = gl.absent()
    return "absent: " + "; ".join(missing) if missing else None


class LeanAndTestKeyAdmission(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        reason = skip_reason()
        if reason:
            raise unittest.SkipTest(reason)
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        done = subprocess.run([sys.executable, "-B", str(gp.ROOT / "scripts" / "g2_ruleset_pack_lean.py")],
                              capture_output=True, timeout=1800, env=env)
        if done.returncode != 0:
            raise AssertionError(f"g2_ruleset_pack_lean.py exit {done.returncode}: {done.stderr.decode(errors='replace')}")
        cls.got = json.loads(done.stdout)
        cls.records = gp.records(gp.load_source())

    def test_lean_evaluates_every_case_as_the_reference_does(self):
        ev = self.got["eval"]
        cases = EXPECTED["cases"]
        self.assertEqual(ev["records"], ["elig_only", "full"])
        self.assertEqual(ev["cases"], [c["name"] for c in cases])
        self.assertEqual(len(ev["answers"]), 2 * len(cases))
        for i, name in enumerate(ev["records"]):
            for j, case in enumerate(cases):
                want = ref.fired(self.records[name], gl.to_read(case["read"]), case["service"], ev["flow"], case["batch"])
                self.assertEqual(ev["answers"][i * len(cases) + j], f"EVAL {i} {want}", (name, case["name"]))
                if name == "elig_only":
                    self.assertEqual(want, 1 << STALE_ENROLLMENT | sum(1 << b for b in case["expect"]), case["name"])

    def test_the_records_as_built_are_not_admitted(self):
        """They carry placeholder bytes, not signatures, and the source's own state and tenant."""
        self.assertEqual(len(self.got["eval"]["admission"]), 2)
        for line in self.got["eval"]["admission"]:
            self.assertTrue(line.startswith("REFUSED "), line)

    def test_test_key_admission_mechanics(self):
        for name in ("elig_only", "full"):
            a = self.got["admit"][name]
            self.assertEqual(a["signed"], [f"ADMIT 1 4 {a['digest']}"], name)
            self.assertNotEqual(a["digest"], EXPECTED["records"][name]["digest"], name)  # a re-headed copy, not the pin
            self.assertEqual(a["signed_under_v1_tag"], ["REFUSED UNSIGNED"], name)
            self.assertEqual(a["one_signer"], ["REFUSED UNSIGNED"], name)
            self.assertEqual(a["benefit_level_rule"], ["REFUSED NOSOURCE"], name)


if __name__ == "__main__":
    unittest.main()
