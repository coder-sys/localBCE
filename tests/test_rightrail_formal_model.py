import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FORMAL = ROOT / "right-rail-integration" / "formal"


class RightRailFormalModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = json.loads((FORMAL / "settlement_model_v1.json").read_text(encoding="ascii"))

    def test_only_listed_state_transitions_are_legal(self):
        states = self.model["states"]
        legal = {tuple(item) for item in self.model["legal_transitions"]}
        self.assertEqual(
            legal,
            {
                ("prepared", "submitted"),
                ("submitted", "mined"),
                ("mined", "finalized"),
                ("finalized", "local_state_committed"),
            },
        )
        for source in states:
            for target in states:
                if target == "local_state_committed" and (source, target) in legal:
                    self.assertEqual(source, "finalized")

    def test_denied_preserves_roots_and_approved_is_finality_bound(self):
        self.assertEqual(self.model["decisions"]["denied"], "root_must_be_preserved")
        self.assertIn("after_finality", self.model["decisions"]["approved"])

    def test_stale_and_conflicting_retries_fail_closed(self):
        retry = self.model["retry_policy"]
        self.assertEqual(retry["exact_retry"], "duplicate")
        self.assertEqual(retry["changed_input"], "conflict")
        self.assertEqual(retry["stale_generation"], "reject")

    def test_authorization_is_separated(self):
        auth = self.model["authorization"]
        self.assertEqual(auth["treasury_transfer"], ["treasury"])
        self.assertEqual(auth["configuration"], ["governance"])
        self.assertEqual(auth["emergency_pause"], ["pauser"])

    def test_recovery_preserves_backend(self):
        self.assertEqual(self.model["backend_recovery"], "preserve_selected_backend")

    def test_formal_sources_name_required_properties(self):
        lean = (FORMAL / "LocalBCE" / "Settlement.lean").read_text(encoding="ascii")
        tla = (FORMAL / "Settlement.tla").read_text(encoding="ascii")
        for name in (
            "noLocalCommitBeforeFinality",
            "deniedPreservesRoots",
            "staleGenerationFailsClosed",
            "conflictingRetryFailsClosed",
            "governanceCannotTransferTreasury",
            "recoveryNeverFallsBack",
        ):
            self.assertIn(name, lean)
        for name in (
            "DeniedPreservesRoots",
            "RetryFailsClosed",
            "AuthorizationSeparation",
            "NoAutomaticBackendFallback",
        ):
            self.assertIn(name, tla)


if __name__ == "__main__":
    unittest.main()
