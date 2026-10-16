from __future__ import annotations

import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
STARK_VALIDATORS = (
    ROOT / "scripts" / "validate_stark_runtime_settlement.sh",
    ROOT / "scripts" / "validate_stark_v2_anvil.sh",
)


class StarkValidationConfigGateTests(unittest.TestCase):
    def test_checked_in_default_remains_adjudication_only(self) -> None:
        config = json.loads(
            (ROOT / "rust-engine" / "config.json").read_text(encoding="utf-8")
        )

        self.assertIs(config.get("proof_execution_enabled"), False)
        self.assertEqual(config.get("proof_backend"), "none")

    def test_stark_settlement_validators_explicitly_enable_proof_execution(self) -> None:
        setting = re.compile(r'"proof_execution_enabled"\s*:\s*True')

        for path in STARK_VALIDATORS:
            with self.subTest(path=path.name):
                source = path.read_text(encoding="utf-8")
                self.assertRegex(
                    source,
                    setting,
                    msg=(
                        f"{path.name} selects stark_attested but does not explicitly "
                        "enable the proof execution gate"
                    ),
                )


if __name__ == "__main__":
    unittest.main()
