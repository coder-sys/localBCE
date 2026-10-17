from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
STARK_VALIDATORS = (
    ROOT / "scripts" / "validate_stark_runtime_settlement.sh",
    ROOT / "scripts" / "validate_stark_v2_anvil.sh",
)
HEREDOC = re.compile(r"python3 -[^<]*?<<'PY'\n(.*?)\nPY\n", re.DOTALL)


def stark_config_snippets(source: str) -> list[str]:
    """Return the python heredocs in a validator that build the stark_attested config."""
    return [m.group(1) for m in HEREDOC.finditer(source) if '"stark_attested"' in m.group(1)]


class StarkValidationConfigGateTests(unittest.TestCase):
    def test_checked_in_default_remains_adjudication_only(self) -> None:
        config = json.loads((ROOT / "rust-engine" / "config.json").read_text(encoding="utf-8"))

        self.assertIs(config.get("proof_execution_enabled"), False)
        self.assertEqual(config.get("proof_backend"), "none")

    def test_stark_settlement_validators_generate_proof_execution_enabled_config(self) -> None:
        for path in STARK_VALIDATORS:
            with self.subTest(validator=path.name):
                snippets = stark_config_snippets(path.read_text(encoding="utf-8"))
                self.assertEqual(len(snippets), 1, "expected exactly one stark_attested config builder")
                with tempfile.TemporaryDirectory() as tmp:
                    out = Path(tmp) / "config.json"
                    # Run the generator with its own argv contract: argv[1] is the output path.
                    argv = [str(out)] + [f"arg{i}" for i in range(2, 12)] + [str(ROOT)]
                    result = subprocess.run(
                        [sys.executable, "-", *argv],
                        input=snippets[0],
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    generated = json.loads(out.read_text(encoding="utf-8"))
                self.assertEqual(generated.get("proof_backend"), "stark_attested")
                self.assertIs(
                    generated.get("proof_execution_enabled"),
                    True,
                    f"{path.name} generates a stark_attested config with proof execution disabled",
                )


if __name__ == "__main__":
    unittest.main()
