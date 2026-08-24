import json
import os
import subprocess
import unittest
from unittest.mock import patch

from app.batch import poseidon as poseidon_module
from app.batch.poseidon import FIELD_MODULUS, domain_tag, ensure_helper_built, poseidon_hash, poseidon_many
from app.batch.stark_encoding import (
    canonical_cents,
    canonical_day_count,
    canonical_npi,
    pack_felt_text,
)


class StarkFieldFoundationTests(unittest.TestCase):
    def test_poseidon_domain_vectors_match_helper_and_do_not_collide(self):
        rows = [
            [domain_tag("claim_source"), 3, 1, 2, 3],
            [domain_tag("oracle"), 3, 1, 2, 3],
            [domain_tag("fee"), 3, 1, 2, 3],
            [domain_tag("address"), 3, 1, 2, 3],
            [domain_tag("nullifier"), 3, 1, 2, 3],
            [domain_tag("payment"), 3, 1, 2, 3],
        ]
        python_values = poseidon_many(rows)
        helper = ensure_helper_built()
        direct = subprocess.run(
            [str(helper)],
            input=json.dumps([[str(value) for value in row] for row in rows]),
            text=True,
            capture_output=True,
            check=True,
        )
        helper_values = [int(value) for value in json.loads(direct.stdout)]
        self.assertEqual(python_values, helper_values)
        self.assertEqual(len(set(python_values)), len(rows))
        self.assertGreater(domain_tag("claim_source"), 2**200)
        with self.assertRaisesRegex(ValueError, "arity mismatch"):
            poseidon_hash([domain_tag("claim_source"), 2, 1, 2, 3])

    def test_poseidon_worker_restarts_and_retries_the_failed_request(self):
        class RestartProbeWorker:
            starts = 0

            def __init__(self):
                type(self).starts += 1
                self.instance = type(self).starts

            def close(self):
                return None

            def request(self, normalized):
                if self.instance == 1:
                    raise RuntimeError("simulated worker exit")
                return [int(row[-1]) for row in normalized]

        poseidon_module._close_worker()
        try:
            with patch.object(poseidon_module, "_PoseidonWorker", RestartProbeWorker):
                result = poseidon_module.poseidon_many([[domain_tag("claim_source"), 1, 7]])
                self.assertEqual(result, [7])
                self.assertEqual(RestartProbeWorker.starts, 2)
        finally:
            poseidon_module._close_worker()

    def test_canonical_felt_encoding_rejects_out_of_range_values(self):
        self.assertEqual(canonical_cents("125.00"), 12500)
        self.assertGreater(canonical_day_count("2026-06-01"), 0)
        self.assertEqual(canonical_npi("1999999984"), 1999999984)
        self.assertGreater(pack_felt_text("99213"), 0)
        with self.assertRaisesRegex(ValueError, "amount_cents_out_of_range"):
            canonical_cents(2**59)
        with self.assertRaises(ValueError):
            canonical_day_count(2**32)
        with self.assertRaisesRegex(ValueError, "npi_must_be_10_decimal_digits"):
            canonical_npi("123")
        with self.assertRaisesRegex(ValueError, "npi_must_be_10_decimal_digits"):
            canonical_npi("10000000000")
        with self.assertRaisesRegex(ValueError, "packed_text_length_out_of_range"):
            pack_felt_text("x" * 32)
        with self.assertRaisesRegex(ValueError, "canonical field"):
            poseidon_hash([domain_tag("claim_source"), 1, FIELD_MODULUS])
        with self.assertRaisesRegex(ValueError, "domain tag"):
            poseidon_hash([123456, 0])

if __name__ == "__main__":
    unittest.main()
