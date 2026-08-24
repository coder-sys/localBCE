import json
import unittest
from pathlib import Path

from app.public_inputs import PUBLIC_INPUT_FIELD_NAMES_V2


REPO_ROOT = Path(__file__).resolve().parents[1]


class EvidenceAndPublicInputTests(unittest.TestCase):
    def test_v2_manifest_matches_direct_state_boundary(self):
        manifest = json.loads(
            (REPO_ROOT / "ops" / "native_stark_public_inputs_v2.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            tuple(field["name"] for field in manifest["fields"]),
            PUBLIC_INPUT_FIELD_NAMES_V2,
        )
        self.assertIn("atomic database transition", manifest["statement"])


if __name__ == "__main__":
    unittest.main()
