from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import unittest
from unittest import mock

from app.batch.pq_tree_reference import (
    MAX_FOUNDATION_VECTOR_RECORDS,
    MAX_REFERENCE_TREE_HEIGHT,
    PUBLIC_OUTPUT_NAMES,
    parse_foundation_vector_json,
)


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "bl_pq512_vector_v1.schema.json"
VECTOR_PATH = ROOT / "test_data" / "bl_pq512_foundation_vectors.json"
FLAGS = {
    "BL_ENV": "test",
    "BL_DEV": "1",
    "BL_ALLOW_SYNTHETIC_PQ_TREE_REFERENCE": "1",
}


class FoundationVectorSchemaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.environment = mock.patch.dict(os.environ, FLAGS, clear=False)
        self.environment.start()
        self.raw = VECTOR_PATH.read_bytes()
        self.vector = json.loads(self.raw)
        self.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    def tearDown(self) -> None:
        self.environment.stop()

    def test_committed_t01_scaffold_recomputes_only_p01_p02_tree_values(self) -> None:
        parsed = parse_foundation_vector_json(self.raw)
        self.assertEqual(parsed, self.vector)
        self.assertEqual(len(parsed["compatibilityOutputs"]), 12)
        self.assertEqual(
            tuple(item["name"] for item in parsed["compatibilityOutputs"]),
            PUBLIC_OUTPUT_NAMES,
        )
        self.assertEqual(
            parsed["wideSidecar"]["encodingStatus"],
            "LOGICAL_PLACEHOLDERS_S04_P06_OPEN_NOT_AUTHENTICATED",
        )
        self.assertEqual(
            parsed["referenceStatus"],
            "SYNTHETIC_T01_STRUCTURE_AND_P01_P02_TREE_KAT_NOT_T02",
        )
        self.assertIn("structural placeholders until T02-T06", self.schema["description"])

    def test_schema_machine_enforces_exact_ordered_twelve_field_abi(self) -> None:
        outputs = self.schema["properties"]["compatibilityOutputs"]
        self.assertEqual(outputs["minItems"], 12)
        self.assertEqual(outputs["maxItems"], 12)
        self.assertFalse(outputs["items"])
        prefix = outputs["prefixItems"]
        self.assertEqual(len(prefix), 12)
        names = tuple(
            item["allOf"][1]["properties"]["name"]["const"] for item in prefix
        )
        indices = tuple(
            item["allOf"][1]["properties"]["index"]["const"] for item in prefix
        )
        self.assertEqual(names, PUBLIC_OUTPUT_NAMES)
        self.assertEqual(indices, tuple(range(12)))
        private = self.schema["properties"]["privateSemantics"]["properties"]
        self.assertEqual(
            private["canonicalRecordsHex"]["maxItems"], MAX_FOUNDATION_VECTOR_RECORDS
        )
        self.assertEqual(
            private["legacyTree"]["$ref"], "#/$defs/legacyTree"
        )
        self.assertEqual(
            self.schema["$defs"]["legacyTree"]["properties"]["leafFeltHex"]["maxItems"],
            MAX_FOUNDATION_VECTOR_RECORDS,
        )
        self.assertEqual(
            self.schema["$defs"]["wideTree"]["properties"]["leafSha3_512"]["maxItems"],
            MAX_FOUNDATION_VECTOR_RECORDS,
        )
        self.assertEqual(
            self.schema["$defs"]["legacyTree"]["properties"]["treeHeight"]["maximum"],
            MAX_REFERENCE_TREE_HEIGHT,
        )
        self.assertEqual(
            self.schema["$defs"]["wideTree"]["properties"]["treeHeight"]["maximum"],
            MAX_REFERENCE_TREE_HEIGHT,
        )

    def test_sidecar_matches_s04_minimum_inventory_and_marks_open_choices(self) -> None:
        sidecar_schema = self.schema["properties"]["wideSidecar"]
        required = set(sidecar_schema["required"])
        self.assertTrue(
            {
                "profileId",
                "proofSuiteId",
                "schemaId",
                "verifierArtifactIdentity",
                "epoch",
                "sequenceBefore",
                "sequenceAfter",
                "strongNullifierRootBefore",
                "strongNullifierRootAfter",
                "strongGovernanceCommitment",
                "strongPaymentStateBinding",
                "strongBatchCommitment",
            }.issubset(required)
        )
        sidecar = self.vector["wideSidecar"]
        self.assertEqual(sidecar["proofSuiteId"], "TBD-S07-S08-S09-NOT-SELECTED")
        self.assertEqual(
            sidecar["schemaId"], "TBD-S12-P06-NOT-FROZEN"
        )
        self.assertEqual(
            sidecar["strongPaymentStateBinding"],
            {"status": "UNRESOLVED-A11-P05", "bindingKind": "TBD", "bindingValue": None},
        )
        self.assertNotIn("verifierIdentity", sidecar)

    def test_schema_and_parser_reject_unknown_properties_at_every_boundary(self) -> None:
        self.assertFalse(self.schema["additionalProperties"])
        self.assertFalse(
            self.schema["properties"]["privateSemantics"]["additionalProperties"]
        )
        self.assertFalse(
            self.schema["properties"]["wideSidecar"]["additionalProperties"]
        )
        for definition in ("compatibilityField", "legacyTree", "wideTree"):
            self.assertFalse(self.schema["$defs"][definition]["additionalProperties"])

        top_extra = deepcopy(self.vector)
        top_extra["alternateEncoding"] = "forbidden"
        with self.assertRaisesRegex(ValueError, "foundation_vector_keys_invalid"):
            parse_foundation_vector_json(json.dumps(top_extra).encode("utf-8"))
        nested_extra = deepcopy(self.vector)
        nested_extra["wideSidecar"]["trailing"] = "forbidden"
        with self.assertRaisesRegex(ValueError, "wide_sidecar_keys_invalid"):
            parse_foundation_vector_json(json.dumps(nested_extra).encode("utf-8"))

    def test_duplicate_json_keys_wrong_abi_order_and_root_tampering_fail_closed(self) -> None:
        text = self.raw.decode("utf-8")
        duplicated = text.replace(
            '"caseId": "synthetic-foundation-approved-0001"',
            '"caseId": "synthetic-duplicate",\n  "caseId": "synthetic-foundation-approved-0001"',
            1,
        )
        with self.assertRaisesRegex(ValueError, "foundation_vector_duplicate_key:caseId"):
            parse_foundation_vector_json(duplicated.encode("utf-8"))

        wrong_order = deepcopy(self.vector)
        wrong_order["compatibilityOutputs"][0], wrong_order["compatibilityOutputs"][1] = (
            wrong_order["compatibilityOutputs"][1],
            wrong_order["compatibilityOutputs"][0],
        )
        with self.assertRaisesRegex(ValueError, "public_output_order_mismatch"):
            parse_foundation_vector_json(json.dumps(wrong_order).encode("utf-8"))

        changed_root = deepcopy(self.vector)
        changed_root["privateSemantics"]["wideTree"]["rootSha3_512"] = "00" * 64
        with self.assertRaisesRegex(ValueError, "wide_root_mismatch"):
            parse_foundation_vector_json(json.dumps(changed_root).encode("utf-8"))

    def test_parser_rejects_boolean_indices_bad_taxonomy_and_schema_boundaries(self) -> None:
        bool_version = deepcopy(self.vector)
        bool_version["privateSemantics"]["snapshotVersion"] = False
        with self.assertRaisesRegex(TypeError, "snapshot_version_must_be_integer"):
            parse_foundation_vector_json(json.dumps(bool_version).encode("utf-8"))

        bool_index = deepcopy(self.vector)
        bool_index["compatibilityOutputs"][0]["index"] = False
        with self.assertRaisesRegex(TypeError, "public_output_index_must_be_integer"):
            parse_foundation_vector_json(json.dumps(bool_index).encode("utf-8"))

        bad_code = deepcopy(self.vector)
        bad_code["privateSemantics"]["decision"] = "denied"
        bad_code["privateSemantics"]["failureCode"] = 14
        bad_code["privateSemantics"]["payableCents"] = "0000000000000000"
        with self.assertRaisesRegex(ValueError, "failure_code_out_of_taxonomy"):
            parse_foundation_vector_json(json.dumps(bad_code).encode("utf-8"))

        too_many_operations = deepcopy(self.vector)
        too_many_operations["privateSemantics"]["orderedOperations"] = [
            f"operation-{index:03d}" for index in range(129)
        ]
        with self.assertRaisesRegex(ValueError, "ordered_operations_invalid"):
            parse_foundation_vector_json(json.dumps(too_many_operations).encode("utf-8"))

        too_many_records = deepcopy(self.vector)
        too_many_records["privateSemantics"]["canonicalRecordsHex"] = [
            self.vector["privateSemantics"]["canonicalRecordsHex"][0]
        ] * 257
        with self.assertRaisesRegex(ValueError, "canonical_records_invalid"):
            parse_foundation_vector_json(json.dumps(too_many_records).encode("utf-8"))

        bare_case = deepcopy(self.vector)
        bare_case["caseId"] = "synthetic-"
        with self.assertRaisesRegex(ValueError, "case_id_not_synthetic"):
            parse_foundation_vector_json(json.dumps(bare_case).encode("utf-8"))

        bare_snapshot = deepcopy(self.vector)
        bare_snapshot["privateSemantics"]["snapshotId"] = "SYNTHETIC-"
        with self.assertRaisesRegex(ValueError, "snapshot_id_not_synthetic"):
            parse_foundation_vector_json(json.dumps(bare_snapshot).encode("utf-8"))

        overflow_epoch = deepcopy(self.vector)
        overflow_epoch["wideSidecar"]["epoch"] = "1" + "0" * 16
        with self.assertRaisesRegex(ValueError, "epoch_not_canonical_hex"):
            parse_foundation_vector_json(json.dumps(overflow_epoch).encode("utf-8"))

        wide_float_height = deepcopy(self.vector)
        wide_float_height["privateSemantics"]["wideTree"]["treeHeight"] = 2.0
        with self.assertRaisesRegex(TypeError, "wide_tree_height_must_be_integer"):
            parse_foundation_vector_json(json.dumps(wide_float_height).encode("utf-8"))

        denied_branch = self.schema["properties"]["privateSemantics"]["allOf"][1]["then"]
        self.assertEqual(
            denied_branch["properties"]["payableCents"]["const"],
            "0000000000000000",
        )
        padding_branch = self.schema["properties"]["privateSemantics"]["allOf"][2]["then"]
        self.assertEqual(
            padding_branch["properties"]["allowedCents"]["const"],
            "0000000000000000",
        )
        self.assertEqual(
            padding_branch["properties"]["payableCents"]["const"],
            "0000000000000000",
        )

    def test_vector_domains_are_reference_v0_and_do_not_claim_p06_encoding(self) -> None:
        self.assertEqual(self.vector["domainSuite"], "BL-PQ512-REFERENCE/v0")
        self.assertEqual(
            self.vector["referenceSchemaId"], "BL-PQ512-TREE-REFERENCE-v0"
        )
        self.assertNotIn("encodedSidecarHex", self.vector["wideSidecar"])
        self.assertIn("P06_OPEN", self.vector["wideSidecar"]["encodingStatus"])


if __name__ == "__main__":
    unittest.main()
