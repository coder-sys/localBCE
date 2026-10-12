from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from gov_rules_kg.canonical_rules import canonical_sha256
from gov_rules_kg.rules_checkpoint import (
    EXPECTED_CHECKPOINT_SHA256,
    EXPECTED_RULES_SHA256,
    RulesCheckpointError,
    validate_rules_corpus_checkpoint,
)


WORKDIR = Path(__file__).resolve().parents[1]
REPO_ROOT = WORKDIR.parent
CHECKPOINT_PATH = WORKDIR / "reports" / "rules_corpus_checkpoint_v1.json"


class RulesCorpusCheckpointTests(unittest.TestCase):
    def checkpoint(self) -> dict:
        return json.loads(CHECKPOINT_PATH.read_text(encoding="utf-8"))

    def write_checkpoint(self, payload: dict, *, rehash: bool = True) -> Path:
        if rehash:
            payload["canonical_checkpoint_sha256"] = canonical_sha256(
                {
                    key: value
                    for key, value in payload.items()
                    if key != "canonical_checkpoint_sha256"
                }
            )
        temporary = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", encoding="utf-8", delete=False
        )
        with temporary:
            json.dump(payload, temporary)
        self.addCleanup(Path(temporary.name).unlink, missing_ok=True)
        return Path(temporary.name)

    def validate_mutation(self, payload: dict) -> dict:
        return validate_rules_corpus_checkpoint(
            REPO_ROOT,
            self.write_checkpoint(payload),
            expected_checkpoint_sha256=None,
        )

    def test_committed_checkpoint_is_pinned_and_nonbinding(self) -> None:
        summary = validate_rules_corpus_checkpoint(REPO_ROOT)
        self.assertEqual(summary["status"], "ok")
        self.assertEqual(
            summary["canonical_checkpoint_sha256"], EXPECTED_CHECKPOINT_SHA256
        )
        self.assertEqual(summary["rules_active_v1_sha256"], EXPECTED_RULES_SHA256)
        self.assertEqual(summary["programs"], 51)
        self.assertEqual(summary["medicaid_source_records"], 15)
        self.assertEqual(summary["validation_scope"], "committed_snapshot_only")
        self.assertFalse(summary["live_postgres_recount_performed"])
        self.assertFalse(summary["runtime_activation"])
        self.assertFalse(summary["proof_binding"])

    def test_rejects_tampering_without_a_matching_hash(self) -> None:
        payload = self.checkpoint()
        payload["corpus"]["raw_grounded_candidate_count"] += 1
        path = self.write_checkpoint(payload, rehash=False)
        with self.assertRaisesRegex(RulesCheckpointError, "canonical SHA-256 mismatch"):
            validate_rules_corpus_checkpoint(
                REPO_ROOT, path, expected_checkpoint_sha256=None
            )

    def test_rejects_internally_inconsistent_counts(self) -> None:
        payload = self.checkpoint()
        payload["corpus"]["raw_grounded_candidate_count"] += 1
        with self.assertRaisesRegex(RulesCheckpointError, "raw candidate total mismatch"):
            self.validate_mutation(payload)

    def test_rejects_expired_inference_lease(self) -> None:
        payload = self.checkpoint()
        payload["jobs"]["inference_job_states"][0]["expired_leases"] = 1
        with self.assertRaisesRegex(RulesCheckpointError, "expired_leases mismatch"):
            self.validate_mutation(payload)

    def test_rejects_rule_activation_claim(self) -> None:
        payload = self.checkpoint()
        payload["safety_boundaries"]["runtime_activation"] = True
        with self.assertRaisesRegex(
            RulesCheckpointError, "safety_boundaries.runtime_activation mismatch"
        ):
            self.validate_mutation(payload)

    def test_rejects_medicaid_registry_hash_mismatch(self) -> None:
        payload = copy.deepcopy(self.checkpoint())
        payload["source_registries"]["medicaid_registry_canonical_sha256"] = "0" * 64
        with self.assertRaisesRegex(
            RulesCheckpointError, "medicaid_registry_canonical_sha256 mismatch"
        ):
            self.validate_mutation(payload)

    def test_rejects_invalid_blocker_count(self) -> None:
        payload = self.checkpoint()
        payload["blockers"]["draft_blocker_counts"]["conflicting_duplicate"] = -1
        with self.assertRaisesRegex(
            RulesCheckpointError,
            "blockers.draft_blocker_counts.conflicting_duplicate must be a nonnegative integer",
        ):
            self.validate_mutation(payload)


if __name__ == "__main__":
    unittest.main()
