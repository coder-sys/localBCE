import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SP1_ROOT = ROOT / "zk-sp1"
EXECUTE_RE = re.compile(
    r"case=(?P<case>\S+) decision=(?P<decision>\d+) failure_code=(?P<failure>\d+) "
    r"execute_ms=(?P<ms>\d+) cycles=(?P<cycles>\d+)"
)


def run_sp1_execute():
    linux_root = "/mnt/c/Users/neers/Documents/Codex/blind-ledger-app-layer/zk-sp1"
    command = (
        f"cd {linux_root} && "
        'env PATH="$HOME/.sp1/bin:$HOME/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" '
        "timeout 180s ./target/release/fibonacci --execute"
    )
    proc = subprocess.run(
        ["wsl", "-d", "Ubuntu", "--", "bash", "-lc", command],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=240,
        check=True,
    )
    cases = {}
    for match in EXECUTE_RE.finditer(proc.stdout):
        cases[match.group("case")] = {
            "decision": int(match.group("decision")),
            "failure_code": int(match.group("failure")),
            "cycles": int(match.group("cycles")),
        }
    return cases, proc.stdout, proc.stderr


class SP1ExecuteModeAttackTests(unittest.TestCase):
    def test_sp1_execute_public_outputs_match_expected_decisions(self):
        observed, stdout, _ = run_sp1_execute()
        expected = {
            "approved": {"decision": 1, "failure_code": 0},
            "ineligible_denied": {"decision": 0, "failure_code": 2},
            "duplicate_denied": {"decision": 0, "failure_code": 9},
            "excessive_charge_denied": {"decision": 0, "failure_code": 8},
        }
        stripped = {
            name: {"decision": row["decision"], "failure_code": row["failure_code"]}
            for name, row in observed.items()
        }
        self.assertEqual(stripped, expected, stdout)
        for row in observed.values():
            self.assertGreater(row["cycles"], 0)
            self.assertLess(row["cycles"], 250_000, stdout)


if __name__ == "__main__":
    unittest.main()
