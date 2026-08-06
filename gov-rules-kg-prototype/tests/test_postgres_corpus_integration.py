from __future__ import annotations

import os
import unittest
from pathlib import Path

from gov_rules_kg.postgres_corpus import PostgresCorpusStore
from gov_rules_kg.scaled_corpus import load_source_registry


WORKDIR = Path(__file__).resolve().parents[1]


@unittest.skipUnless(
    os.environ.get("RULES_TEST_DATABASE_URL"),
    "RULES_TEST_DATABASE_URL is required for destructive PostgreSQL integration tests",
)
class PostgresCorpusIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = PostgresCorpusStore(os.environ["RULES_TEST_DATABASE_URL"])
        self.store.migrate(WORKDIR / "migrations")

    def test_registry_sync_and_baseline_import_are_idempotent(self) -> None:
        registry = load_source_registry(WORKDIR)
        self.assertEqual(self.store.sync_registry(registry), 104)
        self.assertEqual(self.store.sync_registry(registry), 104)
        self.assertEqual(self.store.import_blocked_baseline(WORKDIR), 226)
        self.assertEqual(self.store.import_blocked_baseline(WORKDIR), 226)
        metrics = self.store.rules_metrics()
        self.assertEqual(metrics["table_counts"]["official_sources"], 104)
        self.assertEqual(metrics["table_counts"]["legacy_baseline_candidates"], 226)
        self.assertFalse(metrics["runtime_activation"])
        self.assertFalse(metrics["proof_binding"])

    def test_concurrent_claim_queries_use_skip_locked(self) -> None:
        source = (WORKDIR / "src" / "gov_rules_kg" / "postgres_corpus.py").read_text(encoding="utf-8")
        self.assertGreaterEqual(source.count("FOR UPDATE SKIP LOCKED"), 2)


if __name__ == "__main__":
    unittest.main()
