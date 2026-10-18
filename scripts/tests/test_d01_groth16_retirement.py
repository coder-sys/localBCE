import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUST_MAIN = ROOT / "rust-engine" / "src" / "main.rs"


class D01Groth16RetirementTests(unittest.TestCase):
    def test_d_01_n_08_groth16_backend_is_unreachable(self) -> None:
        source = RUST_MAIN.read_text(encoding="utf-8")

        self.assertNotIn('"none" | "groth16" | "stark_attested"', source)
        self.assertNotIn("snarkjs groth16 prove", source)
        self.assertNotIn("submitVerifiedClaim(bytes32", source)

    def test_d_01_groth16_sources_are_outside_active_build_roots(self) -> None:
        active_paths = (
            ROOT / "zk" / "claim.circom",
            ROOT / "blind-ledger" / "src" / "ClaimsRegistry.sol",
            ROOT / "blind-ledger" / "src" / "Verifier.sol",
            ROOT / "blind-ledger" / "script" / "Counter.s.sol",
            ROOT / "blind-ledger" / "test" / "ClaimsRegistry.t.sol",
            ROOT / "blind-ledger" / "test" / "DeploymentJson.t.sol",
        )
        deprecated_paths = (
            ROOT / "deprecated" / "groth16" / "zk" / "claim.circom",
            ROOT / "deprecated" / "groth16" / "blind-ledger" / "src" / "ClaimsRegistry.sol",
            ROOT / "deprecated" / "groth16" / "blind-ledger" / "src" / "Verifier.sol",
            ROOT / "deprecated" / "groth16" / "blind-ledger" / "script" / "Counter.s.sol",
            ROOT / "deprecated" / "groth16" / "blind-ledger" / "test" / "ClaimsRegistry.t.sol",
            ROOT / "deprecated" / "groth16" / "blind-ledger" / "test" / "DeploymentJson.t.sol",
        )

        for path in active_paths:
            self.assertFalse(path.exists(), f"active Groth16 source remains: {path}")
        for path in deprecated_paths:
            self.assertTrue(path.is_file(), f"missing deprecated Groth16 source: {path}")

        self.assertTrue((ROOT / "deprecated" / "groth16" / "README.md").is_file())


if __name__ == "__main__":
    unittest.main()
