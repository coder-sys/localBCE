import os
import unittest
from unittest.mock import patch

from app.batch.leaf import current_duplicate_pepper, stable_private_hash
from app.oracle_attestation import make_test_attestation, verify_oracle_attestation


class ConsolidatedHardeningTests(unittest.TestCase):
    def test_typed_length_prefixed_encoding_blocks_demonstrated_collisions(self):
        self.assertNotEqual(stable_private_hash(["A|B", "C"]), stable_private_hash(["A", "B|C"]))
        self.assertNotEqual(stable_private_hash(1), stable_private_hash(True))
        self.assertNotEqual(stable_private_hash(1), stable_private_hash("1"))
        self.assertNotEqual(stable_private_hash(True), stable_private_hash("1"))

    def test_duplicate_pepper_missing_without_dev_fails_closed(self):
        env = {key: value for key, value in os.environ.items() if key not in {"BL_DEV", "BL_DUPLICATE_CHECK_PEPPER", "BL_ENV"}}
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaisesRegex(RuntimeError, "missing required duplicate pepper"):
                current_duplicate_pepper()

    def test_oracle_expired_forged_and_replayed_attestations_reject(self):
        good = make_test_attestation("eligibility_active", True, claim_id="BL-HARDEN-ORACLE", claim_source_commitment=17)
        self.assertTrue(verify_oracle_attestation(good, claim_id="BL-HARDEN-ORACLE", claim_source_commitment=17))
        self.assertFalse(verify_oracle_attestation(good, claim_id="OTHER-CLAIM", claim_source_commitment=17))

        expired = make_test_attestation(
            "eligibility_active",
            True,
            claim_id="BL-HARDEN-ORACLE",
            valid_from="2020-01-01",
            valid_until="2020-12-31",
            claim_source_commitment=17,
        )
        self.assertFalse(verify_oracle_attestation(expired, claim_id="BL-HARDEN-ORACLE", claim_source_commitment=17))

        replay_cache = set()
        self.assertTrue(verify_oracle_attestation(good, claim_id="BL-HARDEN-ORACLE", claim_source_commitment=17, replay_cache=replay_cache))
        self.assertFalse(verify_oracle_attestation(good, claim_id="BL-HARDEN-ORACLE", claim_source_commitment=17, replay_cache=replay_cache))

if __name__ == "__main__":
    unittest.main()
