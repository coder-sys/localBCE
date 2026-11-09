import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUST_MAIN = ROOT / "rust-engine" / "src" / "main.rs"
PARKED = ROOT / "parked" / "localbce"


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
        deprecated = PARKED / "deprecated" / "groth16"
        deprecated_paths = (
            deprecated / "zk" / "claim.circom",
            deprecated / "blind-ledger" / "src" / "ClaimsRegistry.sol",
            deprecated / "blind-ledger" / "src" / "Verifier.sol",
            deprecated / "blind-ledger" / "script" / "Counter.s.sol",
            deprecated / "blind-ledger" / "test" / "ClaimsRegistry.t.sol",
            deprecated / "blind-ledger" / "test" / "DeploymentJson.t.sol",
        )

        for path in active_paths:
            self.assertFalse(path.exists(), f"active Groth16 source remains: {path}")
        for path in deprecated_paths:
            self.assertTrue(path.is_file(), f"missing deprecated Groth16 source: {path}")

        self.assertTrue((deprecated / "README.md").is_file())


class ProofAndChainParkingTests(unittest.TestCase):
    """RightRail is the base system; proof and chain code is parked, not deleted."""

    PARKED_ROOTS = (
        "zk",
        "zk-prover",
        "stark-engine",
        "blind-ledger",
        "deprecated",
        "blind-ledger-app-layer/contracts",
        "blind-ledger-app-layer/l2",
        "blind-ledger-app-layer/zk",
        "blind-ledger-app-layer/zk-stark",
        "blind-ledger-app-layer/zk-sp1",
        "blind-ledger-app-layer/zk-cairo-sharp",
        "blind-ledger-app-layer/zk-production-binding",
    )

    def test_proof_and_chain_roots_are_parked(self) -> None:
        for relative in self.PARKED_ROOTS:
            self.assertFalse((ROOT / relative).exists(), f"active proof/chain root remains: {relative}")
            self.assertTrue((PARKED / relative).is_dir(), f"parked copy missing: {relative}")

    def test_parked_readme_explains_the_boundary(self) -> None:
        readme = (PARKED / "README.md").read_text(encoding="utf-8")

        self.assertIn("RightRail", readme)
        self.assertIn("not deleted", readme)

    def test_adjudicator_has_no_stark_or_chain_runtime(self) -> None:
        source = RUST_MAIN.read_text(encoding="utf-8")

        for token in ("stark_activation", "run_stark_attested_app", "Command::new", "private_key"):
            self.assertNotIn(token, source)
        self.assertFalse((ROOT / "rust-engine" / "src" / "stark_activation.rs").exists())

    def test_default_config_carries_no_chain_settings(self) -> None:
        config = (ROOT / "rust-engine" / "config.json").read_text(encoding="utf-8")

        for key in ("private_key", "rpc_url", "claims_registry_address", "stark_"):
            self.assertNotIn(key, config)


if __name__ == "__main__":
    unittest.main()
