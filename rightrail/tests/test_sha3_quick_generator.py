"""The unrolled Keccak in lean/BlindLedger/Sha3Quick.lean is exactly what tools/sha3_bench/gen_keccak_rounds.py writes
(two rounds per loop step); the generator runs on a temporary copy, never on the repository file."""

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
QUICK = ROOT / "lean" / "BlindLedger" / "Sha3Quick.lean"
GEN = ROOT / "tools" / "sha3_bench" / "gen_keccak_rounds.py"


class Sha3QuickGenerator(unittest.TestCase):
    def test_the_committed_file_is_the_generators_output(self):
        spec = importlib.util.spec_from_file_location("gen_keccak_rounds", GEN)
        gen = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gen)
        with tempfile.TemporaryDirectory() as d:
            copy = Path(d) / "Sha3Quick.lean"
            copy.write_bytes(QUICK.read_bytes())
            gen.patch(str(copy), 2)
            self.assertEqual(copy.read_bytes(), QUICK.read_bytes())


if __name__ == "__main__":
    unittest.main()
