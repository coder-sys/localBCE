from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from gov_rules_kg.rules_baseline import RulesBaselineError, validate_rules_baseline


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SOURCE_WORKDIR = REPOSITORY_ROOT / "gov-rules-kg-prototype"
BASELINE_FILES = (
    "data/rules_baseline_manifest_v1.json",
    "reports/claude_web_candidate_corpus.json",
    "reports/claude_web_mapping_qa.json",
    "reports/claude_web_promotion_ready.json",
)


class RulesBaselineTests(unittest.TestCase):
    def _copy_baseline(self, destination: Path) -> Path:
        workdir = destination / "gov-rules-kg-prototype"
        for relative_name in BASELINE_FILES:
            source = SOURCE_WORKDIR / relative_name
            target = workdir / relative_name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        return workdir

    def _rewrite_manifest_hash(self, workdir: Path, role: str, sha256: str) -> None:
        manifest_path = workdir / "data" / "rules_baseline_manifest_v1.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for artifact in manifest["artifacts"]:
            if artifact["role"] == role:
                artifact["sha256"] = sha256
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    def test_tracked_baseline_passes_integrity_and_safety_checks(self) -> None:
        summary = validate_rules_baseline(SOURCE_WORKDIR)

        self.assertEqual(summary["source_candidates"], 226)
        self.assertEqual(summary["mapping_records"], 221)
        self.assertEqual(summary["qa_pass_records"], 191)
        self.assertEqual(summary["programs"], 51)
        self.assertEqual(summary["missing_lineage"], 5)
        self.assertFalse(summary["runtime_activation"])
        self.assertFalse(summary["proof_binding"])

    def test_tampered_artifact_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workdir = self._copy_baseline(Path(temp))
            path = workdir / "reports" / "claude_web_candidate_corpus.json"
            path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")

            with self.assertRaisesRegex(RulesBaselineError, "hash mismatch"):
                validate_rules_baseline(workdir)

    def test_runtime_activation_claim_is_rejected_even_when_hash_is_updated(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workdir = self._copy_baseline(Path(temp))
            path = workdir / "reports" / "claude_web_candidate_corpus.json"
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["runtime_activation"] = True
            path.write_text(json.dumps(payload), encoding="utf-8")

            updated_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            self._rewrite_manifest_hash(workdir, "source_candidates", updated_hash)
            with self.assertRaisesRegex(RulesBaselineError, "runtime_activation must be false"):
                validate_rules_baseline(workdir)

    def test_duplicate_candidate_id_is_rejected_even_when_hash_is_updated(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workdir = self._copy_baseline(Path(temp))
            path = workdir / "reports" / "claude_web_candidate_corpus.json"
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["candidate_rules"][1]["candidate_id"] = payload["candidate_rules"][0][
                "candidate_id"
            ]
            path.write_text(json.dumps(payload), encoding="utf-8")

            updated_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            self._rewrite_manifest_hash(workdir, "source_candidates", updated_hash)
            with self.assertRaisesRegex(RulesBaselineError, "duplicate source candidates"):
                validate_rules_baseline(workdir)

    def test_mapping_provenance_must_match_its_source_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workdir = self._copy_baseline(Path(temp))
            path = workdir / "reports" / "claude_web_mapping_qa.json"
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["candidates"][0]["source_url"] = "https://example.gov/mismatch"
            path.write_text(json.dumps(payload), encoding="utf-8")

            updated_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            self._rewrite_manifest_hash(workdir, "mapping_qa", updated_hash)
            with self.assertRaisesRegex(RulesBaselineError, "source URL mismatch"):
                validate_rules_baseline(workdir)

    def test_manifest_cannot_relax_pinned_counts(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workdir = self._copy_baseline(Path(temp))
            path = workdir / "data" / "rules_baseline_manifest_v1.json"
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["expected_counts"]["source_candidates"] = 225
            path.write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaisesRegex(RulesBaselineError, "expected_counts"):
                validate_rules_baseline(workdir)


if __name__ == "__main__":
    unittest.main()
