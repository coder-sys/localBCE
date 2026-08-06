from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import unittest

from app.public_inputs import PUBLIC_INPUT_FIELD_NAMES_V2
from experiments.fixed_shape_claim_air.whole_product_vector_corpus import (
    WholeProductVectorError,
    canonical_manifest_bytes,
    expected_case,
    manifest_sha3_512,
    parse_manifest,
)


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "test_data" / "bl_pq512_whole_product_vectors.json"
EXPECTED_DIGEST = (
    "f69ffb9e3c07c052977fe4c92cf4344b1b7ecbe51d88d832eb3969c81a73079e"
    "bde44ecbf4b12ec1b11fdebdb7a4f5340f4aca171a0fa7c73637456606bcb8b2"
)


class WholeProductVectorCorpusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.raw = MANIFEST.read_bytes()
        self.value = parse_manifest(self.raw)

    def test_manifest_is_canonical_and_has_all_profiles_and_outcomes(self) -> None:
        self.assertEqual(canonical_manifest_bytes(self.value), self.raw)
        self.assertEqual(manifest_sha3_512(self.raw), EXPECTED_DIGEST)
        self.assertEqual(
            {(case["profile"], case["outcome"]) for case in self.value["cases"]},
            {
                (profile, outcome)
                for profile in ("K128", "K512")
                for outcome in ("APPROVAL", "DENIAL", "COVER")
            },
        )

    def test_public_boundary_is_exactly_ordered_and_commitment_only(self) -> None:
        self.assertEqual(tuple(self.value["fieldNames"]), PUBLIC_INPUT_FIELD_NAMES_V2)
        encoded = self.raw.lower()
        for forbidden in (b"phi", b"patient", b"amount", b"witness", b"claimdocument"):
            self.assertNotIn(forbidden, encoded)
        for case in self.value["cases"]:
            self.assertEqual(
                case,
                expected_case(case["caseId"], case["profile"], case["outcome"]),
            )

    def test_mutated_commitment_and_identity_are_rejected(self) -> None:
        mutated = deepcopy(self.value)
        mutated["cases"][0]["publicFields"][0] = "01" * 32
        with self.assertRaisesRegex(WholeProductVectorError, "expected_value_mismatch"):
            parse_manifest(canonical_manifest_bytes(mutated))

        activation = deepcopy(self.value)
        activation["activationAllowed"] = True
        with self.assertRaisesRegex(WholeProductVectorError, "identity_invalid"):
            parse_manifest(canonical_manifest_bytes(activation))

    def test_duplicate_key_and_private_shape_are_rejected(self) -> None:
        duplicate = self.raw.replace(
            b'"schema":"blind-ledger-whole-product-kat-v1"',
            b'"schema":"bad","schema":"blind-ledger-whole-product-kat-v1"',
            1,
        )
        with self.assertRaisesRegex(WholeProductVectorError, "duplicate_key"):
            parse_manifest(duplicate)

        private = json.loads(self.raw)
        private["cases"][0]["privateWitness"] = "forbidden"
        with self.assertRaisesRegex(WholeProductVectorError, "case_keys_invalid"):
            parse_manifest(canonical_manifest_bytes(private))


if __name__ == "__main__":
    unittest.main()
