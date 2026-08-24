from __future__ import annotations

import copy
import json
import os
import tempfile
import threading
import unittest
import uuid
import zlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path
from typing import Any

from gov_rules_kg.canonical_rules import canonical_sha256
from gov_rules_kg.claude_inference import build_inference_request
from gov_rules_kg.postgres_corpus import (
    CURRENT_CRITIQUE_CONTRACT_KEY,
    CURRENT_EXTRACTION_CONTRACT_KEY,
    CorpusDatabaseError,
    PostgresCorpusStore,
)
from gov_rules_kg.scale_commands import rules_checkpoint
from gov_rules_kg.scaled_corpus import (
    RELEVANCE_CLASSIFIER_VERSION,
    all_programs,
    assess_section_relevance,
    build_evidence_span,
    build_ocr_artifact,
    build_source_snapshot,
    candidate_id,
    load_source_registry,
    restore_snapshot_bytes,
    segment_structured_blocks,
    segment_text,
)
from gov_rules_kg.source_adapters import (
    SOURCE_DISCOVERY_PARSER_VERSION,
    discover_official_links,
    extract_source_text,
)
from gov_rules_kg.state_medicaid_core import (
    build_postgres_supplemental_registry,
    load_state_medicaid_preflight,
    load_state_medicaid_registry,
)


WORKDIR = Path(__file__).resolve().parents[1]


@unittest.skipUnless(
    os.environ.get("RULES_TEST_DATABASE_URL"),
    "RULES_TEST_DATABASE_URL is required for destructive PostgreSQL integration tests",
)
class PostgresCorpusIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = PostgresCorpusStore(os.environ["RULES_TEST_DATABASE_URL"])
        with self.store.connection() as conn:
            conn.execute("DROP SCHEMA public CASCADE")
            conn.execute("CREATE SCHEMA public")
            conn.commit()
        self.store.migrate(WORKDIR / "migrations")

    def test_pending_critique_scheduler_indexes_are_installed(self) -> None:
        with self.store.connection() as conn:
            rows = conn.execute(
                """
                SELECT indexname
                FROM pg_indexes
                WHERE schemaname = current_schema()
                  AND indexname IN (
                      'inference_jobs_section_contract_idx',
                      'grounded_candidates_pending_critique_idx'
                  )
                ORDER BY indexname
                """
            ).fetchall()

        self.assertEqual(
            [row["indexname"] for row in rows],
            [
                "grounded_candidates_pending_critique_idx",
                "inference_jobs_section_contract_idx",
            ],
        )

    def test_quality_metrics_distinguish_open_and_silent_conflicts(self) -> None:
        from psycopg.types.json import Jsonb

        _, left_draft_id, _ = self._insert_review_candidate()
        _, right_draft_id, _ = self._insert_review_candidate()
        with self.store.connection() as conn:
            left = conn.execute(
                """
                SELECT scope_fingerprint FROM typed_rule_drafts
                WHERE draft_id = %s
                """,
                (left_draft_id,),
            ).fetchone()
            conn.execute(
                """
                UPDATE typed_rule_drafts
                SET scope_fingerprint = %s, outcome_hash = %s
                WHERE draft_id = %s
                """,
                (left["scope_fingerprint"], "f" * 64, right_draft_id),
            )
            conn.commit()

        silent = self.store.quality_measurements()
        self.assertEqual(silent["open_conflicts"], 0)
        self.assertEqual(silent["silently_merged_conflicts"], 1)

        cluster_id = f"cluster_{uuid.uuid4().hex}"
        with self.store.connection() as conn:
            conn.execute(
                """
                INSERT INTO duplicate_conflict_clusters (
                    cluster_id, cluster_kind, status, fingerprint
                ) VALUES (%s, 'conflicting_outcome', 'open', %s)
                """,
                (cluster_id, left["scope_fingerprint"]),
            )
            for draft_id in (left_draft_id, right_draft_id):
                conn.execute(
                    """
                    INSERT INTO duplicate_conflict_members (cluster_id, draft_id)
                    VALUES (%s, %s)
                    """,
                    (cluster_id, draft_id),
                )
                conn.execute(
                    """
                    UPDATE typed_rule_drafts
                    SET blocker_codes = %s
                    WHERE draft_id = %s
                    """,
                    (Jsonb(["conflicting_duplicate"]), draft_id),
                )
            conn.commit()

        detected = self.store.quality_measurements()
        self.assertEqual(detected["open_conflicts"], 1)
        self.assertEqual(detected["silently_merged_conflicts"], 0)

    def _insert_review_candidate(self) -> tuple[str, str, str]:
        from psycopg.types.json import Jsonb

        suffix = uuid.uuid4().hex
        digest = canonical_sha256({"fixture": suffix})
        source_id = f"source_{suffix}"
        retrieval_id = f"retrieval_{suffix}"
        section_id = f"section_{suffix}"
        inference_job_id = f"inference_{suffix}"
        candidate_id = f"candidate_{suffix}"
        draft_id = f"draft_{suffix}"
        canonical_rule = {"candidate_id": candidate_id, "version": 1}
        draft_hash = canonical_sha256(canonical_rule)
        with self.store.connection() as conn:
            conn.execute(
                """
                INSERT INTO official_sources (
                    source_id, registry_version, canonical_url, program,
                    jurisdiction, issuer, source_type, required, official
                ) VALUES (%s, 'lease-fixture-v1', %s, 'medicaid', %s,
                          'CMS', 'html', true, true)
                """,
                (
                    source_id,
                    f"https://example.gov/{suffix}",
                    Jsonb({"country": "US"}),
                ),
            )
            conn.execute(
                """
                INSERT INTO source_snapshots (
                    snapshot_hash, mime_type, compression, compressed_bytes,
                    uncompressed_size, text_layer_kind
                ) VALUES (%s, 'text/plain', 'zlib', %s, 1, 'native')
                """,
                (digest, zlib.compress(b"x")),
            )
            conn.execute(
                """
                INSERT INTO source_snapshot_retrievals (
                    retrieval_id, snapshot_hash, source_id, canonical_url,
                    retrieved_at, http_status, issuer
                ) VALUES (%s, %s, %s, %s, now(), 200, 'CMS')
                """,
                (retrieval_id, digest, source_id, f"https://example.gov/{suffix}"),
            )
            conn.execute(
                """
                INSERT INTO source_sections (
                    section_id, snapshot_hash, retrieval_id, ordinal,
                    hierarchy_path, normalized_text, normalized_text_hash,
                    parser_name, parser_version
                ) VALUES (%s, %s, %s, 0, '[]'::jsonb, 'x', %s, 'fixture', '1')
                """,
                (section_id, digest, retrieval_id, digest),
            )
            conn.execute(
                """
                INSERT INTO inference_jobs (
                    inference_job_id, section_id, pass, prompt_version,
                    model_version, schema_version, idempotency_key, status,
                    request_payload
                ) VALUES (%s, %s, 1, 'fixture', 'fixture', 'fixture', %s,
                          'completed', '{}'::jsonb)
                """,
                (inference_job_id, section_id, digest),
            )
            conn.execute(
                """
                INSERT INTO grounded_candidates (
                    candidate_id, primary_program, section_id, snapshot_hash,
                    evidence_char_start, evidence_char_end, evidence_byte_start,
                    evidence_byte_end, evidence_quote, evidence_hash,
                    extraction_job_id, extraction_contract_key,
                    critique_contract_key, candidate_payload, grounding_status
                ) VALUES (%s, 'medicaid', %s, %s, 0, 1, 0, 1, 'x', %s,
                          %s, %s, %s, %s, 'accepted')
                """,
                (
                    candidate_id,
                    section_id,
                    digest,
                    digest,
                    inference_job_id,
                    CURRENT_EXTRACTION_CONTRACT_KEY,
                    CURRENT_CRITIQUE_CONTRACT_KEY,
                    Jsonb({"candidate_id": candidate_id}),
                ),
            )
            conn.execute(
                """
                INSERT INTO typed_rule_drafts (
                    draft_id, candidate_id, draft_version, canonical_rule,
                    canonical_hash, semantic_fingerprint, scope_fingerprint,
                    outcome_hash, runtime_eligibility_status
                ) VALUES (%s, %s, 1, %s, %s, %s, %s, %s, 'shadow_only')
                """,
                (
                    draft_id,
                    candidate_id,
                    Jsonb(canonical_rule),
                    draft_hash,
                    digest,
                    digest,
                    digest,
                ),
            )
            conn.commit()
        return candidate_id, draft_id, draft_hash

    def _insert_release_cohort_for_candidate(
        self,
        *,
        release_id: str,
        candidate_id: str,
        draft_id: str,
        draft_hash: str,
    ) -> None:
        with self.store.connection() as conn:
            lineage = conn.execute(
                """
                SELECT candidates.snapshot_hash, candidates.section_id,
                       candidates.extraction_contract_key,
                       candidates.critique_contract_key,
                       sources.registry_version,
                       sections.extraction_pipeline_version
                FROM grounded_candidates candidates
                JOIN source_sections sections USING (section_id)
                JOIN source_snapshot_retrievals retrievals USING (retrieval_id)
                JOIN official_sources sources USING (source_id)
                WHERE candidates.candidate_id = %s
                """,
                (candidate_id,),
            ).fetchone()
            conn.execute(
                """
                INSERT INTO corpus_release_cohorts (
                    release_id, corpus_target_count, candidate_id, selection_hash,
                    draft_id, draft_hash, snapshot_hash, section_id,
                    source_registry_version, extraction_pipeline_version,
                    extraction_contract_key, critique_contract_key
                ) VALUES (
                    %s, 5100, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    release_id,
                    candidate_id,
                    canonical_sha256([candidate_id]),
                    draft_id,
                    draft_hash,
                    lineage["snapshot_hash"],
                    lineage["section_id"],
                    lineage["registry_version"],
                    lineage["extraction_pipeline_version"],
                    lineage["extraction_contract_key"],
                    lineage["critique_contract_key"],
                ),
            )
            conn.commit()

    def test_review_task_leases_are_owned_recoverable_and_audited(self) -> None:
        _, draft_id, _ = self._insert_review_candidate()
        task_id = f"task_{uuid.uuid4().hex}"
        with self.store.connection() as conn:
            conn.execute(
                """
                INSERT INTO reviewer_tasks (task_id, draft_id, task_type, status)
                VALUES (%s, %s, 'policy_review', 'pending')
                """,
                (task_id, draft_id),
            )
            conn.commit()

        claimed = self.store.claim_review_task(
            "policy-a", "policy_reviewer", lease_seconds=60
        )
        self.assertEqual(claimed["task_id"], task_id)
        self.assertEqual(claimed["claim_attempts"], 1)
        with self.assertRaisesRegex(CorpusDatabaseError, "owned by another"):
            self.store.renew_review_task_claim(
                task_id,
                reviewer_id="policy-b",
                reviewer_role="policy_reviewer",
                lease_seconds=60,
            )
        self.store.renew_review_task_claim(
            task_id,
            reviewer_id="policy-a",
            reviewer_role="policy_reviewer",
            lease_seconds=120,
        )
        released = self.store.release_review_task_claim(
            task_id,
            reviewer_id="policy-a",
            reviewer_role="policy_reviewer",
        )
        self.assertEqual(released["status"], "pending")
        reclaimed = self.store.claim_review_task(
            "policy-b", "policy_reviewer", lease_seconds=60
        )
        self.assertEqual(reclaimed["claim_attempts"], 2)
        with self.store.connection() as conn:
            conn.execute(
                "UPDATE reviewer_tasks SET claim_expires_at = NULL WHERE task_id = %s",
                (task_id,),
            )
            conn.commit()
        reclaimed = self.store.claim_review_task(
            "policy-c", "policy_reviewer", lease_seconds=60
        )
        self.assertEqual(reclaimed["claim_attempts"], 3)
        with self.assertRaisesRegex(CorpusDatabaseError, "not claimed"):
            self.store.record_review_decision(
                task_id=task_id,
                reviewer_id="policy-b",
                reviewer_role="policy_reviewer",
                decision="approve",
                rationale="stale owner must fail",
            )
        self.store.record_review_decision(
            task_id=task_id,
            reviewer_id="policy-c",
            reviewer_role="policy_reviewer",
            decision="approve",
            rationale="exact source and mapping reviewed",
        )
        with self.store.connection() as conn:
            task = conn.execute(
                """
                SELECT status, assigned_reviewer_id, claimed_at, claim_expires_at
                FROM reviewer_tasks WHERE task_id = %s
                """,
                (task_id,),
            ).fetchone()
            actions = {
                row["action"]
                for row in conn.execute(
                    "SELECT action FROM review_audit_events WHERE entity_id = %s",
                    (task_id,),
                ).fetchall()
            }
        self.assertEqual(task["status"], "completed")
        self.assertIsNone(task["assigned_reviewer_id"])
        self.assertIsNone(task["claimed_at"])
        self.assertIsNone(task["claim_expires_at"])
        self.assertTrue(
            {
                "task_claimed",
                "task_claim_renew",
                "task_claim_release",
                "task_claim_expired",
                "review_decision",
            }.issubset(actions)
        )

    def test_review_tasks_cancel_when_source_or_section_is_superseded(self) -> None:
        for superseded_entity in ("source", "section"):
            with self.subTest(superseded_entity=superseded_entity):
                _, draft_id, _ = self._insert_review_candidate()
                task_id = f"task_{uuid.uuid4().hex}"
                with self.store.connection() as conn:
                    lineage = conn.execute(
                        """
                        SELECT sections.section_id, sources.source_id
                        FROM typed_rule_drafts drafts
                        JOIN grounded_candidates candidates USING (candidate_id)
                        JOIN source_sections sections USING (section_id)
                        JOIN source_snapshot_retrievals retrievals USING (retrieval_id)
                        JOIN official_sources sources USING (source_id)
                        WHERE drafts.draft_id = %s
                        """,
                        (draft_id,),
                    ).fetchone()
                    conn.execute(
                        """
                        INSERT INTO reviewer_tasks (task_id, draft_id, task_type, status)
                        VALUES (%s, %s, 'policy_review', 'pending')
                        """,
                        (task_id, draft_id),
                    )
                    conn.commit()
                claimed = self.store.claim_review_task(
                    f"policy-{superseded_entity}",
                    "policy_reviewer",
                    lease_seconds=60,
                )
                self.assertEqual(claimed["task_id"], task_id)
                with self.store.connection() as conn:
                    if superseded_entity == "source":
                        conn.execute(
                            "UPDATE official_sources SET active = false WHERE source_id = %s",
                            (lineage["source_id"],),
                        )
                    else:
                        conn.execute(
                            "UPDATE source_sections SET active = false WHERE section_id = %s",
                            (lineage["section_id"],),
                        )
                    conn.commit()
                with self.assertRaisesRegex(CorpusDatabaseError, "superseded"):
                    self.store.record_review_decision(
                        task_id=task_id,
                        reviewer_id=f"policy-{superseded_entity}",
                        reviewer_role="policy_reviewer",
                        decision="approve",
                        rationale="stale lineage must never be approved",
                    )
                with self.store.connection() as conn:
                    status = conn.execute(
                        "SELECT status FROM reviewer_tasks WHERE task_id = %s",
                        (task_id,),
                    ).fetchone()["status"]
                    actions = {
                        row["action"]
                        for row in conn.execute(
                            "SELECT action FROM review_audit_events WHERE entity_id = %s",
                            (task_id,),
                        ).fetchall()
                    }
                self.assertEqual(status, "cancelled")
                self.assertIn("task_cancelled_superseded_lineage", actions)

    def test_review_tasks_cancel_when_draft_is_superseded(self) -> None:
        from psycopg.types.json import Jsonb

        candidate_id, draft_id, _ = self._insert_review_candidate()
        task_id = f"task_{uuid.uuid4().hex}"
        replacement_rule = {"candidate_id": candidate_id, "version": 2}
        with self.store.connection() as conn:
            original = conn.execute(
                """
                SELECT semantic_fingerprint, scope_fingerprint, outcome_hash
                FROM typed_rule_drafts WHERE draft_id = %s
                """,
                (draft_id,),
            ).fetchone()
            conn.execute(
                """
                INSERT INTO reviewer_tasks (task_id, draft_id, task_type, status)
                VALUES (%s, %s, 'policy_review', 'pending')
                """,
                (task_id, draft_id),
            )
            conn.execute(
                """
                INSERT INTO typed_rule_drafts (
                    draft_id, candidate_id, draft_version, canonical_rule,
                    canonical_hash, semantic_fingerprint, scope_fingerprint,
                    outcome_hash, runtime_eligibility_status
                ) VALUES (%s, %s, 2, %s, %s, %s, %s, %s, 'shadow_only')
                """,
                (
                    f"draft_v2_{uuid.uuid4().hex}",
                    candidate_id,
                    Jsonb(replacement_rule),
                    canonical_sha256(replacement_rule),
                    original["semantic_fingerprint"],
                    original["scope_fingerprint"],
                    original["outcome_hash"],
                ),
            )
            conn.commit()

        self.assertIsNone(
            self.store.claim_review_task(
                "policy-current-only", "policy_reviewer", lease_seconds=60
            )
        )
        self.assertEqual(
            self.store.list_review_tasks("policy_reviewer"),
            [],
        )
        with self.store.connection() as conn:
            self.assertEqual(
                conn.execute(
                    "SELECT status FROM reviewer_tasks WHERE task_id = %s",
                    (task_id,),
                ).fetchone()["status"],
                "cancelled",
            )

    def test_quality_sample_leases_recover_and_preserve_role_separation(self) -> None:
        candidate_id, draft_id, draft_hash = self._insert_review_candidate()
        sample_id = f"sample_{uuid.uuid4().hex}"
        release_id = "lease-fixture-release"
        self._insert_release_cohort_for_candidate(
            release_id=release_id,
            candidate_id=candidate_id,
            draft_id=draft_id,
            draft_hash=draft_hash,
        )
        with self.store.connection() as conn:
            conn.execute(
                """
                INSERT INTO quality_sample_plans (
                    sample_id, release_id, corpus_target_count, candidate_id,
                    draft_id, draft_hash, stratum, status
                ) VALUES (%s, %s, 5100, %s, %s, %s,
                          'balanced_program', 'pending_policy')
                """,
                (sample_id, release_id, candidate_id, draft_id, draft_hash),
            )
            conn.commit()

        first = self.store.claim_quality_sample(
            reviewer_id="policy-a",
            reviewer_role="policy_reviewer",
            lease_seconds=60,
        )
        self.assertEqual(first["claim_attempts"], 1)
        with self.assertRaisesRegex(CorpusDatabaseError, "owned by another"):
            self.store.release_quality_sample_claim(
                sample_id,
                reviewer_id="policy-b",
                reviewer_role="policy_reviewer",
            )
        self.store.renew_quality_sample_claim(
            sample_id,
            reviewer_id="policy-a",
            reviewer_role="policy_reviewer",
            lease_seconds=120,
        )
        self.store.release_quality_sample_claim(
            sample_id,
            reviewer_id="policy-a",
            reviewer_role="policy_reviewer",
        )
        self.store.claim_quality_sample(
            reviewer_id="policy-b",
            reviewer_role="policy_reviewer",
            lease_seconds=60,
        )
        with self.store.connection() as conn:
            conn.execute(
                """
                UPDATE quality_sample_plans SET claim_expires_at = NULL
                WHERE sample_id = %s
                """,
                (sample_id,),
            )
            conn.commit()
        recovered = self.store.claim_quality_sample(
            reviewer_id="policy-c",
            reviewer_role="policy_reviewer",
            lease_seconds=60,
        )
        self.assertEqual(recovered["claim_attempts"], 3)
        measurements = {
            "evidence_span_precise": True,
            "typed_mapping_correct": True,
            "program_classification_correct": True,
            "deterministic_rerun_match": True,
        }
        policy_result = self.store.record_quality_review(
            {
                "schema_version": "localbce-rules-quality-review-v1",
                "sample_id": sample_id,
                "candidate_id": candidate_id,
                "draft_hash": draft_hash,
                "reviewer_id": "policy-c",
                "reviewer_role": "policy_reviewer",
                "measurements": measurements,
                "rationale": "policy mapping checked",
                "runtime_activation": False,
                "proof_binding": False,
            }
        )
        self.assertFalse(policy_result["completed"])
        self.assertIsNone(
            self.store.claim_quality_sample(
                reviewer_id="policy-c",
                reviewer_role="legal_verifier",
                lease_seconds=60,
            )
        )
        legal = self.store.claim_quality_sample(
            reviewer_id="legal-a",
            reviewer_role="legal_verifier",
            lease_seconds=60,
        )
        self.assertIsNotNone(legal)
        with self.store.connection() as conn:
            conn.execute(
                """
                UPDATE quality_sample_plans
                SET claim_expires_at = now() - interval '1 second'
                WHERE sample_id = %s
                """,
                (sample_id,),
            )
            conn.commit()
        legal = self.store.claim_quality_sample(
            reviewer_id="legal-b",
            reviewer_role="legal_verifier",
            lease_seconds=60,
        )
        self.assertEqual(legal["claim_attempts"], 5)
        legal_result = self.store.record_quality_review(
            {
                "schema_version": "localbce-rules-quality-review-v1",
                "sample_id": sample_id,
                "candidate_id": candidate_id,
                "draft_hash": draft_hash,
                "reviewer_id": "legal-b",
                "reviewer_role": "legal_verifier",
                "measurements": measurements,
                "rationale": "legal evidence checked independently",
                "runtime_activation": False,
                "proof_binding": False,
            }
        )
        self.assertTrue(legal_result["completed"])

    def test_quality_sample_and_release_cohort_fail_closed_on_stale_draft(self) -> None:
        from psycopg.types.json import Jsonb

        candidate_id, draft_id, draft_hash = self._insert_review_candidate()
        release_id = f"stale-quality-{uuid.uuid4().hex}"
        sample_id = f"sample_{uuid.uuid4().hex}"
        self._insert_release_cohort_for_candidate(
            release_id=release_id,
            candidate_id=candidate_id,
            draft_id=draft_id,
            draft_hash=draft_hash,
        )
        with self.store.connection() as conn:
            original = conn.execute(
                """
                SELECT semantic_fingerprint, scope_fingerprint, outcome_hash
                FROM typed_rule_drafts WHERE draft_id = %s
                """,
                (draft_id,),
            ).fetchone()
            conn.execute(
                """
                INSERT INTO quality_sample_plans (
                    sample_id, release_id, corpus_target_count, candidate_id,
                    draft_id, draft_hash, stratum, status
                ) VALUES (%s, %s, 5100, %s, %s, %s,
                          'program_stratified', 'pending_policy')
                """,
                (sample_id, release_id, candidate_id, draft_id, draft_hash),
            )
            conn.commit()
        claimed = self.store.claim_quality_sample(
            reviewer_id="policy-stale",
            reviewer_role="policy_reviewer",
            release_id=release_id,
            lease_seconds=60,
        )
        self.assertEqual(claimed["sample_id"], sample_id)

        replacement_rule = {"candidate_id": candidate_id, "version": 2}
        with self.store.connection() as conn:
            conn.execute(
                """
                INSERT INTO typed_rule_drafts (
                    draft_id, candidate_id, draft_version, canonical_rule,
                    canonical_hash, semantic_fingerprint, scope_fingerprint,
                    outcome_hash, runtime_eligibility_status
                ) VALUES (%s, %s, 2, %s, %s, %s, %s, %s, 'shadow_only')
                """,
                (
                    f"draft_v2_{uuid.uuid4().hex}",
                    candidate_id,
                    Jsonb(replacement_rule),
                    canonical_sha256(replacement_rule),
                    original["semantic_fingerprint"],
                    original["scope_fingerprint"],
                    original["outcome_hash"],
                ),
            )
            conn.commit()

        with self.assertRaisesRegex(CorpusDatabaseError, "stale"):
            self.store.record_quality_review(
                {
                    "schema_version": "localbce-rules-quality-review-v1",
                    "sample_id": sample_id,
                    "candidate_id": candidate_id,
                    "draft_hash": draft_hash,
                    "reviewer_id": "policy-stale",
                    "reviewer_role": "policy_reviewer",
                    "measurements": {
                        "evidence_span_precise": True,
                        "typed_mapping_correct": True,
                        "program_classification_correct": True,
                        "deterministic_rerun_match": True,
                    },
                    "rationale": "must not accept a superseded mapping",
                    "runtime_activation": False,
                    "proof_binding": False,
                }
            )
        with self.store.connection() as conn:
            plan = conn.execute(
                """
                SELECT status, invalidated_at, invalidation_reason
                FROM quality_sample_plans WHERE sample_id = %s
                """,
                (sample_id,),
            ).fetchone()
            actions = {
                row["action"]
                for row in conn.execute(
                    "SELECT action FROM review_audit_events WHERE entity_id = %s",
                    (sample_id,),
                ).fetchall()
            }
        self.assertEqual(plan["status"], "invalidated")
        self.assertIsNotNone(plan["invalidated_at"])
        self.assertIn("stale", plan["invalidation_reason"])
        self.assertIn("quality_sample_invalidated_stale_lineage", actions)
        with self.assertRaisesRegex(CorpusDatabaseError, "lineage is stale"):
            self.store.release_cohort_summary(release_id)
        with self.assertRaisesRegex(CorpusDatabaseError, "lineage is stale"):
            self.store.quality_measurements(release_id=release_id)

    def test_release_cohort_fails_closed_on_inference_contract_drift(self) -> None:
        candidate_id, draft_id, draft_hash = self._insert_review_candidate()
        release_id = f"stale-contract-{uuid.uuid4().hex}"
        self._insert_release_cohort_for_candidate(
            release_id=release_id,
            candidate_id=candidate_id,
            draft_id=draft_id,
            draft_hash=draft_hash,
        )
        self.assertEqual(
            self.store.release_cohort_summary(release_id)["candidate_count"],
            1,
        )
        with self.store.connection() as conn:
            conn.execute(
                """
                UPDATE grounded_candidates
                SET extraction_contract_key = %s
                WHERE candidate_id = %s
                """,
                ("0" * 64, candidate_id),
            )
            conn.commit()
        with self.assertRaisesRegex(CorpusDatabaseError, "lineage is stale"):
            self.store.release_cohort_summary(release_id)

    def test_registry_sync_and_baseline_import_are_idempotent(self) -> None:
        registry = load_source_registry(WORKDIR)
        self.assertEqual(self.store.sync_registry(registry), 128)
        self.assertEqual(self.store.sync_registry(registry), 128)
        self.assertEqual(self.store.import_blocked_baseline(WORKDIR), 226)
        self.assertEqual(self.store.import_blocked_baseline(WORKDIR), 226)
        metrics = self.store.rules_metrics()
        self.assertEqual(metrics["table_counts"]["official_sources"], 128)
        self.assertEqual(metrics["table_counts"]["legacy_baseline_candidates"], 226)
        self.assertFalse(metrics["runtime_activation"])
        self.assertFalse(metrics["proof_binding"])
        progress = self.store.corpus_scale_progress(5_100)
        self.assertEqual(progress["program_count"], 51)
        self.assertEqual(
            sum(item["active_source_count"] for item in progress["programs"]),
            128,
        )
        self.assertEqual(progress["accepted_grounded_candidates"], 0)
        self.assertEqual(progress["accepted_candidates_with_effective_from"], 0)
        self.assertEqual(progress["accepted_candidates_missing_effective_from"], 0)
        self.assertEqual(progress["current_draft_candidates"], 0)
        self.assertEqual(progress["blocked_draft_candidates"], 0)
        self.assertEqual(progress["draft_blocker_counts"], {})
        self.assertEqual(progress["deterministic_candidates"], 0)
        self.assertEqual(progress["programs_at_accepted_candidate_quota"], 0)
        self.assertEqual(progress["programs_at_deterministic_candidate_quota"], 0)
        self.assertEqual(progress["programs_at_candidate_quota"], 0)
        self.assertEqual(progress["max_candidates_per_program_section"], 25)
        self.assertEqual(progress["active_physical_sections"], 0)
        self.assertEqual(progress["physical_section_candidate_capacity"], 0)
        self.assertEqual(progress["active_program_section_contexts"], 0)
        self.assertEqual(progress["program_context_quota_upper_bound"], 0)
        self.assertEqual(
            progress["minimum_additional_physical_sections_lower_bound"], 204
        )
        self.assertEqual(
            progress["minimum_additional_program_contexts_lower_bound"], 204
        )
        self.assertEqual(
            progress["minimum_additional_source_sections_lower_bound"], 204
        )
        self.assertEqual(
            len(progress["programs_without_program_context_quota_capacity"]),
            51,
        )
        self.assertEqual(len(progress["programs_with_candidate_deficit"]), 51)
        self.assertEqual(
            len(progress["programs_with_accepted_candidate_deficit"]), 51
        )
        self.assertEqual(
            len(progress["programs_with_deterministic_candidate_deficit"]), 51
        )
        self.assertFalse(progress["milestone_grounded_candidate_ready"])
        self.assertFalse(progress["milestone_deterministic_candidate_ready"])
        self.assertFalse(progress["milestone_candidate_ready"])
        self.assertFalse(progress["milestone_source_capacity_ready"])
        self.assertTrue(
            progress["source_capacity_evidence_is_necessary_not_sufficient"]
        )
        self.assertFalse(progress["runtime_activation"])
        self.assertFalse(progress["proof_binding"])

    def test_medicaid_supplemental_sync_is_additive_idempotent_and_source_only(self) -> None:
        base_registry = load_source_registry(WORKDIR)
        self.store.sync_registry(base_registry)
        registry, _ = load_state_medicaid_registry(
            WORKDIR / "data" / "source_manifests" / "state_medicaid_core_v1.json"
        )
        preflight, _ = load_state_medicaid_preflight(
            WORKDIR / "reports" / "state_medicaid_core_preflight_v1.json",
            registry,
        )
        supplemental = build_postgres_supplemental_registry(registry, preflight)
        protected_before = self.store.rules_metrics()["table_counts"]

        first = self.store.sync_supplemental_registry(supplemental)
        second = self.store.sync_supplemental_registry(supplemental)
        summary = self.store.supplemental_registry_summary(registry["registry_id"])
        protected_after = self.store.rules_metrics()["table_counts"]

        self.assertEqual(first["inserted"], 15)
        self.assertEqual(first["active_sources_before"], 128)
        self.assertEqual(first["active_sources_after"], 143)
        self.assertEqual(second["inserted"], 0)
        self.assertEqual(second["active_sources_before"], 143)
        self.assertEqual(second["active_sources_after"], 143)
        self.assertEqual(summary["source_count"], 15)
        self.assertEqual(summary["state_counts"], {"CA": 5, "GA": 5, "NC": 5})
        self.assertEqual(summary["snapshot_count"], 0)
        self.assertEqual(summary["fetch_job_count"], 0)
        self.assertEqual(summary["human_approved_source_count"], 0)
        self.assertEqual(summary["legally_verified_source_count"], 0)
        self.assertEqual(len(summary["adapter_required_source_ids"]), 5)
        self.assertEqual(
            protected_after["official_sources"],
            protected_before["official_sources"] + 15,
        )
        for table in (
            "source_snapshots",
            "source_sections",
            "section_extraction_jobs",
            "source_fetch_jobs",
            "inference_jobs",
            "grounded_candidates",
            "typed_rule_drafts",
            "reviewer_tasks",
            "reviewer_decisions",
            "quality_samples",
            "corpus_releases",
        ):
            with self.subTest(table=table):
                self.assertEqual(protected_after[table], protected_before[table])
        with self.store.connection() as conn:
            active_federal = int(
                conn.execute(
                    """
                    SELECT count(*) AS count FROM official_sources
                    WHERE registry_version = %s AND active
                    """,
                    (base_registry["registry_id"],),
                ).fetchone()["count"]
            )
        self.assertEqual(active_federal, 128)
        with tempfile.TemporaryDirectory() as directory:
            checkpoint_path = Path(directory) / "checkpoint.json"
            first_checkpoint = rules_checkpoint(
                WORKDIR,
                self.store,
                registry_path=(
                    WORKDIR
                    / "data"
                    / "source_manifests"
                    / "state_medicaid_core_v1.json"
                ),
                preflight_path=(
                    WORKDIR
                    / "reports"
                    / "state_medicaid_core_preflight_v1.json"
                ),
                output_path=checkpoint_path,
            )
            first_bytes = checkpoint_path.read_bytes()
            second_checkpoint = rules_checkpoint(
                WORKDIR,
                self.store,
                registry_path=(
                    WORKDIR
                    / "data"
                    / "source_manifests"
                    / "state_medicaid_core_v1.json"
                ),
                preflight_path=(
                    WORKDIR
                    / "reports"
                    / "state_medicaid_core_preflight_v1.json"
                ),
                output_path=checkpoint_path,
            )
            self.assertEqual(checkpoint_path.read_bytes(), first_bytes)
            self.assertEqual(
                first_checkpoint["canonical_checkpoint_sha256"],
                second_checkpoint["canonical_checkpoint_sha256"],
            )
            persisted = json.loads(first_bytes)
            expected_hash = canonical_sha256(
                {
                    key: value
                    for key, value in persisted.items()
                    if key != "canonical_checkpoint_sha256"
                }
            )
            self.assertEqual(
                persisted["canonical_checkpoint_sha256"], expected_hash
            )
            self.assertEqual(persisted["corpus"]["program_count"], 51)
            self.assertFalse(
                persisted["safety_boundaries"]["candidate_rule_activation"]
            )
            self.assertFalse(persisted["safety_boundaries"]["proof_binding"])

    def test_corpus_progress_reports_current_draft_quality_gaps(self) -> None:
        from psycopg.types.json import Jsonb

        candidate_id, draft_id, _ = self._insert_review_candidate()
        progress = self.store.corpus_scale_progress(5_100)
        self.assertEqual(progress["accepted_grounded_candidates"], 1)
        self.assertEqual(progress["accepted_candidates_with_effective_from"], 0)
        self.assertEqual(progress["accepted_candidates_missing_effective_from"], 1)
        self.assertEqual(progress["current_draft_candidates"], 1)
        self.assertEqual(progress["blocked_draft_candidates"], 0)
        self.assertEqual(progress["draft_blocker_counts"], {})
        program = next(
            item
            for item in progress["programs"]
            if item["accepted_grounded_candidates"] == 1
        )
        self.assertFalse(program["accepted_candidate_quota_met"])
        self.assertFalse(program["deterministic_candidate_quota_met"])
        self.assertFalse(program["candidate_quota_met"])
        self.assertEqual(program["active_program_section_count"], 1)
        self.assertEqual(program["program_context_candidate_upper_bound"], 25)
        self.assertEqual(
            program["program_context_capacity_deficit_lower_bound"], 75
        )
        self.assertEqual(
            program["minimum_additional_program_contexts_lower_bound"], 3
        )
        self.assertFalse(program["program_context_quota_possible"])
        self.assertEqual(progress["active_physical_sections"], 1)
        self.assertEqual(progress["physical_section_candidate_capacity"], 25)

        with self.store.connection() as conn:
            conn.execute(
                """
                UPDATE typed_rule_drafts
                SET validation_errors = %s, blocker_codes = %s
                WHERE draft_id = %s AND candidate_id = %s
                """,
                (
                    Jsonb(["effective_from is required"]),
                    Jsonb(["missing_effective_date"]),
                    draft_id,
                    candidate_id,
                ),
            )
            conn.commit()

        blocked = self.store.corpus_scale_progress(5_100)
        self.assertEqual(blocked["current_draft_candidates"], 1)
        self.assertEqual(blocked["blocked_draft_candidates"], 1)
        self.assertEqual(
            blocked["draft_blocker_counts"], {"missing_effective_date": 1}
        )

    def test_source_fetch_batch_is_idempotent_recoverable_and_atomic(self) -> None:
        registry = load_source_registry(WORKDIR)
        self.store.sync_registry(registry)
        batch = self.store.enqueue_source_fetch_batch(
            registry_version=registry["registry_id"],
            registry_manifest_sha256=registry["registry_manifest_sha256"],
            capture_id="integration-capture-v1",
            limit=2,
        )
        repeated = self.store.enqueue_source_fetch_batch(
            registry_version=registry["registry_id"],
            registry_manifest_sha256=registry["registry_manifest_sha256"],
            capture_id="integration-capture-v1",
            limit=2,
        )
        self.assertEqual(batch["batch_id"], repeated["batch_id"])
        self.assertEqual(batch["job_count"], 2)
        first = self.store.claim_source_fetch_jobs(
            batch["batch_id"],
            worker_id="fetch-worker-a",
            limit=1,
            lease_seconds=60,
        )
        second = self.store.claim_source_fetch_jobs(
            batch["batch_id"],
            worker_id="fetch-worker-b",
            limit=1,
            lease_seconds=60,
        )
        self.assertEqual(len(first), 1)
        self.assertEqual(len(second), 1)
        self.assertNotEqual(first[0]["fetch_job_id"], second[0]["fetch_job_id"])
        self.store.renew_source_fetch_lease(
            first[0]["fetch_job_id"],
            worker_id="fetch-worker-a",
            lease_seconds=120,
        )
        first_snapshot = build_source_snapshot(
            first[0],
            b"first official source",
            retrieved_at="2026-08-07T12:00:00Z",
            mime_type="text/plain",
        )
        with self.assertRaisesRegex(CorpusDatabaseError, "source ID mismatch"):
            self.store.complete_source_fetch_job(
                first[0]["fetch_job_id"],
                worker_id="fetch-worker-a",
                snapshot={**first_snapshot, "source_id": "wrong-source"},
                response_headers={},
            )
        self.store.complete_source_fetch_job(
            first[0]["fetch_job_id"],
            worker_id="fetch-worker-a",
            snapshot=first_snapshot,
            response_headers={"content-type": "text/plain"},
        )
        with self.store.connection() as conn:
            conn.execute(
                """
                UPDATE source_fetch_jobs
                SET attempts = attempt_limit,
                    lease_expires_at = now() - interval '1 second'
                WHERE fetch_job_id = %s
                """,
                (second[0]["fetch_job_id"],),
            )
            conn.commit()
        self.assertEqual(
            self.store.claim_source_fetch_jobs(
                batch["batch_id"],
                worker_id="fetch-worker-c",
                limit=1,
                lease_seconds=60,
            ),
            [],
        )
        failed = self.store.source_fetch_batch_summary(batch["batch_id"])
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["job_counts"]["completed"], 1)
        self.assertEqual(failed["job_counts"]["failed"], 1)
        self.assertEqual(
            self.store.retry_failed_source_fetch_jobs(
                batch["batch_id"], limit=1, additional_attempts=2
            ),
            1,
        )
        recovered = self.store.claim_source_fetch_jobs(
            batch["batch_id"],
            worker_id="fetch-worker-c",
            limit=1,
            lease_seconds=60,
        )
        self.assertEqual(len(recovered), 1)
        self.assertEqual(recovered[0]["retry_rounds"], 1)
        second_snapshot = build_source_snapshot(
            recovered[0],
            b"second official source",
            retrieved_at="2026-08-07T12:01:00Z",
            mime_type="text/plain",
        )
        self.store.complete_source_fetch_job(
            recovered[0]["fetch_job_id"],
            worker_id="fetch-worker-c",
            snapshot=second_snapshot,
            response_headers={"content-type": "text/plain"},
        )
        completed = self.store.source_fetch_batch_summary(batch["batch_id"])
        self.assertEqual(completed["status"], "completed")
        self.assertEqual(completed["job_counts"]["completed"], 2)
        self.assertFalse(completed["runtime_activation"])
        self.assertFalse(completed["proof_binding"])

    def test_section_extraction_jobs_are_idempotent_recoverable_and_atomic(self) -> None:
        registry = load_source_registry(WORKDIR)
        self.store.sync_registry(registry)
        retrievals: list[tuple[str, dict, bytes]] = []
        for index, source in enumerate(registry["sources"][:2]):
            raw = f"Official rule {index}: applicants must file.".encode("utf-8")
            snapshot = build_source_snapshot(
                source,
                raw,
                retrieved_at=f"2026-08-07T12:0{index}:00Z",
                mime_type="text/plain",
            )
            retrieval_id = self.store.save_snapshot(snapshot)
            legacy = segment_text(
                snapshot["snapshot_hash"],
                raw.decode("utf-8"),
                parser_name="legacy-fixture",
                parser_version="1",
            )
            self.store.save_sections(retrieval_id, legacy)
            retrievals.append((retrieval_id, snapshot, raw))

        queued = self.store.enqueue_section_extraction_jobs(
            pipeline_version="section-integration-v1",
            limit=2,
        )
        repeated = self.store.enqueue_section_extraction_jobs(
            pipeline_version="section-integration-v1",
            limit=2,
        )
        self.assertEqual(queued["jobs_inserted"], 2)
        self.assertEqual(repeated["jobs_inserted"], 0)
        first = self.store.claim_section_extraction_jobs(
            pipeline_version="section-integration-v1",
            worker_id="section-worker-a",
            limit=1,
            lease_seconds=60,
        )
        second = self.store.claim_section_extraction_jobs(
            pipeline_version="section-integration-v1",
            worker_id="section-worker-b",
            limit=1,
            lease_seconds=60,
        )
        self.assertEqual(len(first), 1)
        self.assertEqual(len(second), 1)
        self.assertNotEqual(
            first[0]["extraction_job_id"], second[0]["extraction_job_id"]
        )
        self.store.renew_section_extraction_lease(
            first[0]["extraction_job_id"],
            worker_id="section-worker-a",
            lease_seconds=120,
        )
        first_sections = segment_text(
            first[0]["snapshot_hash"],
            restore_snapshot_bytes(first[0]).decode("utf-8"),
            parser_name="plain_text",
            parser_version="1",
            extraction_pipeline_version="section-integration-v1",
        )
        with self.assertRaisesRegex(CorpusDatabaseError, "lineage"):
            self.store.complete_section_extraction_job(
                first[0]["extraction_job_id"],
                worker_id="section-worker-a",
                sections=[
                    {
                        **first_sections[0],
                        "extraction_pipeline_version": "wrong-pipeline",
                    }
                ],
                warnings=[],
            )
        self.store.complete_section_extraction_job(
            first[0]["extraction_job_id"],
            worker_id="section-worker-a",
            sections=first_sections,
            warnings=[],
        )

        with self.store.connection() as conn:
            conn.execute(
                """
                UPDATE section_extraction_jobs
                SET attempts = attempt_limit,
                    lease_expires_at = now() - interval '1 second'
                WHERE extraction_job_id = %s
                """,
                (second[0]["extraction_job_id"],),
            )
            conn.commit()
        self.assertEqual(
            self.store.claim_section_extraction_jobs(
                pipeline_version="section-integration-v1",
                worker_id="section-worker-c",
                limit=1,
                lease_seconds=60,
            ),
            [],
        )
        failed = self.store.section_extraction_summary("section-integration-v1")
        self.assertEqual(failed["job_counts"]["completed"], 1)
        self.assertEqual(failed["job_counts"]["failed"], 1)
        self.assertEqual(
            self.store.retry_failed_section_extraction_jobs(
                pipeline_version="section-integration-v1",
                limit=1,
                additional_attempts=2,
            ),
            1,
        )
        recovered = self.store.claim_section_extraction_jobs(
            pipeline_version="section-integration-v1",
            worker_id="section-worker-c",
            limit=1,
            lease_seconds=60,
        )
        self.assertEqual(len(recovered), 1)
        self.assertEqual(recovered[0]["retry_rounds"], 1)
        recovered_sections = segment_text(
            recovered[0]["snapshot_hash"],
            restore_snapshot_bytes(recovered[0]).decode("utf-8"),
            parser_name="plain_text",
            parser_version="1",
            extraction_pipeline_version="section-integration-v1",
        )
        self.store.complete_section_extraction_job(
            recovered[0]["extraction_job_id"],
            worker_id="section-worker-c",
            sections=recovered_sections,
            warnings=[],
        )
        completed = self.store.section_extraction_summary("section-integration-v1")
        self.assertEqual(completed["job_counts"]["completed"], 2)
        self.assertEqual(completed["sections_created"], 2)
        self.assertFalse(completed["runtime_activation"])
        self.assertFalse(completed["proof_binding"])
        with self.store.connection() as conn:
            states = conn.execute(
                """
                SELECT extraction_pipeline_version, active, count(*) AS count
                FROM source_sections
                GROUP BY extraction_pipeline_version, active
                ORDER BY extraction_pipeline_version, active
                """
            ).fetchall()
        state_counts = {
            (row["extraction_pipeline_version"], row["active"]): row["count"]
            for row in states
        }
        self.assertEqual(state_counts[("legacy-v1", False)], 2)
        self.assertEqual(state_counts[("section-integration-v1", True)], 2)
        self.assertEqual(
            {
                section["extraction_pipeline_version"]
                for section in self.store.uninferred_sections()
            },
            {"section-integration-v1"},
        )

    def test_concurrent_claim_queries_use_skip_locked(self) -> None:
        source = (WORKDIR / "src" / "gov_rules_kg" / "postgres_corpus.py").read_text(encoding="utf-8")
        self.assertGreaterEqual(source.count("FOR UPDATE SKIP LOCKED"), 2)
        self.assertIn("FOR UPDATE OF jobs SKIP LOCKED", source)

    def test_concurrent_inference_workers_claim_distinct_jobs(self) -> None:
        registry = load_source_registry(WORKDIR)
        self.store.sync_registry(registry)
        source = registry["sources"][0]
        job_ids: list[str] = []
        for ordinal in range(2):
            raw = (
                f"Applicants must satisfy requirement {ordinal} "
                f"{uuid.uuid4().hex}."
            ).encode("utf-8")
            snapshot = build_source_snapshot(
                source,
                raw,
                retrieved_at="2026-08-06T12:00:00Z",
                mime_type="text/plain",
            )
            retrieval_id = self.store.save_snapshot(snapshot)
            extracted = extract_source_text(
                raw,
                mime_type="text/plain",
                source_url=source["canonical_url"],
            )
            sections = segment_structured_blocks(
                snapshot["snapshot_hash"],
                [asdict(block) for block in extracted.blocks],
                parser_name=extracted.parser_name,
                parser_version=extracted.parser_version,
            )
            self.store.save_sections(retrieval_id, sections)
            section = self.store.section(sections[0]["section_id"])
            job_ids.append(
                self.store.enqueue_inference(
                    build_inference_request(
                        section,
                        source["program"],
                        pass_number=1,
                    )
                )
            )

        barrier = threading.Barrier(2)

        def claim(worker_id: str) -> tuple[str, str]:
            contender = PostgresCorpusStore(
                os.environ["RULES_TEST_DATABASE_URL"]
            )
            barrier.wait(timeout=5)
            rows = contender.claim_inference_jobs(worker_id, limit=1)
            self.assertEqual(len(rows), 1)
            return rows[0]["inference_job_id"], rows[0]["lease_owner"]

        with ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(claim, "concurrent-worker-1")
            second = executor.submit(claim, "concurrent-worker-2")
            claims = [first.result(timeout=10), second.result(timeout=10)]

        claimed_ids = {item[0] for item in claims}
        lease_owners = {item[1] for item in claims}
        self.assertEqual(claimed_ids, set(job_ids))
        self.assertEqual(
            lease_owners,
            {"concurrent-worker-1", "concurrent-worker-2"},
        )

    def test_shared_snapshot_sections_retain_all_program_lineage_without_duplication(
        self,
    ) -> None:
        from psycopg.types.json import Jsonb

        raw = b"State tax authorities must publish applicable filing rules."
        sources = [
            {
                "source_id": "source_shared_property_tax",
                "canonical_url": "https://www.usa.gov/property-tax",
                "program": "property_tax",
                "issuer": "USAGov",
            },
            {
                "source_id": "source_shared_sales_tax",
                "canonical_url": "https://www.usa.gov/sales-tax",
                "program": "sales_tax",
                "issuer": "USAGov",
            },
        ]
        with self.store.connection() as conn:
            for source_record in sources:
                conn.execute(
                    """
                    INSERT INTO official_sources (
                        source_id, registry_version, canonical_url, program,
                        jurisdiction, issuer, source_type, required, official
                    ) VALUES (%s, 'shared-source-v1', %s, %s, %s, %s,
                              'html', true, true)
                    """,
                    (
                        source_record["source_id"],
                        source_record["canonical_url"],
                        source_record["program"],
                        Jsonb({"country": "US"}),
                        source_record["issuer"],
                    ),
                )
            conn.commit()

        retrieval_ids: list[str] = []
        sections = None
        for index, source_record in enumerate(sources):
            snapshot = build_source_snapshot(
                source_record,
                raw,
                retrieved_at=f"2026-08-07T13:0{index}:00Z",
                mime_type="text/plain",
            )
            retrieval_id = self.store.save_snapshot(snapshot)
            if sections is None:
                sections = segment_text(
                    snapshot["snapshot_hash"],
                    raw.decode("utf-8"),
                    parser_name="shared-source-fixture",
                    parser_version="1",
                    extraction_pipeline_version="shared-source-v1",
                )
            self.store.save_sections(retrieval_id, sections)
            retrieval_ids.append(retrieval_id)

        with self.store.connection() as conn:
            physical_sections = int(
                conn.execute(
                    "SELECT count(*) AS count FROM source_sections"
                ).fetchone()["count"]
            )
            links = conn.execute(
                """
                SELECT section_id, retrieval_id
                FROM source_section_retrieval_links
                ORDER BY retrieval_id
                """
            ).fetchall()
        self.assertEqual(physical_sections, 1)
        self.assertEqual(
            [row["retrieval_id"] for row in links], sorted(retrieval_ids)
        )

        uninferred = self.store.uninferred_sections()
        self.assertEqual(len(uninferred), 1)
        self.assertEqual(
            uninferred[0]["programs"], ["property_tax", "sales_tax"]
        )
        self.assertEqual(uninferred[0]["program_candidate_count"], 0)
        request = build_inference_request(
            uninferred[0], uninferred[0]["program"], pass_number=1
        )
        self.assertEqual(
            request["source_programs"], ["property_tax", "sales_tax"]
        )

        progress = self.store.corpus_scale_progress(5_100)
        program_progress = {
            item["program"]: item for item in progress["programs"]
        }
        self.assertEqual(
            program_progress["property_tax"]["active_section_count"], 1
        )
        self.assertEqual(
            program_progress["sales_tax"]["active_section_count"], 1
        )

    def test_uninferred_sections_uses_only_current_relevance_classifier(self) -> None:
        registry = load_source_registry(WORKDIR)
        self.store.sync_registry(registry)
        source = registry["sources"][0]
        raw = b"""Guidance documents
January 1, 2020 Filing Guidance (PDF)
February 2, 2021 Rate Review Bulletin (PDF)
March 3, 2022 Submission Timeline (PDF)
April 4, 2023 Final Guidance (PDF)
May 5, 2024 Reporting Guidance (PDF)"""
        snapshot = build_source_snapshot(
            source,
            raw,
            retrieved_at="2026-08-08T12:00:00Z",
            mime_type="text/plain",
        )
        retrieval_id = self.store.save_snapshot(snapshot)
        extracted = extract_source_text(
            raw,
            mime_type="text/plain",
            source_url=source["canonical_url"],
        )
        sections = segment_structured_blocks(
            snapshot["snapshot_hash"],
            [asdict(block) for block in extracted.blocks],
            parser_name=extracted.parser_name,
            parser_version=extracted.parser_version,
        )
        self.store.save_sections(retrieval_id, sections)
        section = self.store.section(sections[0]["section_id"])

        stale_decision = assess_section_relevance(section)
        stale_decision["classifier_version"] = "federal-rule-section-relevance-v1"
        stale_decision.pop("decision_hash")
        stale_decision["decision_hash"] = canonical_sha256(stale_decision)
        self.store.save_relevance_decision(stale_decision)
        available = self.store.uninferred_sections(limit=10)
        current_row = next(
            item for item in available if item["section_id"] == section["section_id"]
        )
        self.assertIsNone(current_row["relevance_decision_id"])

        current_decision = assess_section_relevance(section)
        self.assertEqual(
            current_decision["classifier_version"], RELEVANCE_CLASSIFIER_VERSION
        )
        self.assertFalse(current_decision["relevant"])
        self.store.save_relevance_decision(current_decision)
        self.assertNotIn(
            section["section_id"],
            {
                item["section_id"]
                for item in self.store.uninferred_sections(limit=10)
            },
        )

    def test_inference_run_lock_is_database_wide_and_released(self) -> None:
        contender = PostgresCorpusStore(os.environ["RULES_TEST_DATABASE_URL"])
        with self.store.inference_run_lock():
            with self.assertRaisesRegex(
                CorpusDatabaseError, "already holds the PostgreSQL worker lock"
            ):
                with contender.inference_run_lock():
                    self.fail("a second PostgreSQL session acquired the inference lock")

        with contender.inference_run_lock():
            pass

    def test_ready_critiques_are_claimed_before_new_extractions(self) -> None:
        registry = load_source_registry(WORKDIR)
        self.store.sync_registry(registry)
        source = registry["sources"][0]
        raw = b"Applicants must meet the official eligibility requirement."
        snapshot = build_source_snapshot(
            source,
            raw,
            retrieved_at="2026-08-06T12:00:00Z",
            mime_type="text/plain",
        )
        retrieval_id = self.store.save_snapshot(snapshot)
        extracted = extract_source_text(
            raw,
            mime_type="text/plain",
            source_url=source["canonical_url"],
        )
        sections = segment_structured_blocks(
            snapshot["snapshot_hash"],
            [asdict(block) for block in extracted.blocks],
            parser_name=extracted.parser_name,
            parser_version=extracted.parser_version,
        )
        self.store.save_sections(retrieval_id, sections)
        section = self.store.section(sections[0]["section_id"])
        extraction_job_id = self.store.enqueue_inference(
            build_inference_request(section, source["program"], pass_number=1)
        )
        critique_job_id = self.store.enqueue_inference(
            build_inference_request(
                section,
                source["program"],
                pass_number=2,
                proposed_candidates=[{"candidate_id": "candidate-fixture"}],
            )
        )

        claimed = self.store.claim_inference_jobs("quality-first-worker", limit=1)

        self.assertEqual(claimed[0]["inference_job_id"], critique_job_id)
        self.assertEqual(claimed[0]["pass"], 2)
        self.assertNotEqual(claimed[0]["inference_job_id"], extraction_job_id)

    def test_extraction_claims_prioritize_lower_coverage_programs(self) -> None:
        registry = load_source_registry(WORKDIR)
        self.store.sync_registry(registry)
        self._insert_review_candidate()
        medicaid_source = next(
            source
            for source in registry["sources"]
            if source["program"] == "medicaid"
        )
        lower_coverage_source = next(
            source
            for source in registry["sources"]
            if source["program"] != "medicaid"
        )

        def captured_section(
            source: dict[str, Any],
            label: str,
        ) -> dict[str, Any]:
            raw = (
                f"{label} applicants must satisfy an official requirement "
                f"{uuid.uuid4().hex}."
            ).encode("utf-8")
            snapshot = build_source_snapshot(
                source,
                raw,
                retrieved_at="2026-08-06T12:00:00Z",
                mime_type="text/plain",
            )
            retrieval_id = self.store.save_snapshot(snapshot)
            extracted = extract_source_text(
                raw,
                mime_type="text/plain",
                source_url=source["canonical_url"],
            )
            sections = segment_structured_blocks(
                snapshot["snapshot_hash"],
                [asdict(block) for block in extracted.blocks],
                parser_name=extracted.parser_name,
                parser_version=extracted.parser_version,
            )
            self.store.save_sections(retrieval_id, sections)
            return self.store.section(sections[0]["section_id"])

        higher_section = captured_section(medicaid_source, "Medicaid")
        lower_section = captured_section(lower_coverage_source, "Lower coverage")
        higher_job_id = self.store.enqueue_inference(
            build_inference_request(higher_section, "medicaid", pass_number=1)
        )
        lower_job_id = self.store.enqueue_inference(
            build_inference_request(
                lower_section,
                lower_coverage_source["program"],
                pass_number=1,
            )
        )

        claimed = self.store.claim_inference_jobs("balanced-worker", limit=1)

        self.assertEqual(claimed[0]["inference_job_id"], lower_job_id)
        self.assertNotEqual(claimed[0]["inference_job_id"], higher_job_id)
        self.assertEqual(
            claimed[0]["request_payload"]["program"],
            lower_coverage_source["program"],
        )

        higher_critique_job_id = self.store.enqueue_inference(
            build_inference_request(
                higher_section,
                "medicaid",
                pass_number=2,
                proposed_candidates=[{"candidate_id": "medicaid-fixture"}],
            )
        )
        lower_critique_job_id = self.store.enqueue_inference(
            build_inference_request(
                lower_section,
                lower_coverage_source["program"],
                pass_number=2,
                proposed_candidates=[{"candidate_id": "lower-coverage-fixture"}],
            )
        )

        critique_claimed = self.store.claim_inference_jobs(
            "balanced-critique-worker", limit=1
        )

        self.assertEqual(
            critique_claimed[0]["inference_job_id"], lower_critique_job_id
        )
        self.assertNotEqual(
            critique_claimed[0]["inference_job_id"], higher_critique_job_id
        )
        self.assertEqual(critique_claimed[0]["pass"], 2)
        self.assertEqual(
            critique_claimed[0]["request_payload"]["program"],
            lower_coverage_source["program"],
        )

    def test_expired_final_lease_fails_closed_and_can_be_resumed(self) -> None:
        registry = load_source_registry(WORKDIR)
        self.store.sync_registry(registry)
        source = registry["sources"][0]
        raw = b"Applicants must meet the official eligibility requirement."
        snapshot = build_source_snapshot(
            source,
            raw,
            retrieved_at="2026-08-06T12:00:00Z",
            mime_type="text/plain",
        )
        retrieval_id = self.store.save_snapshot(snapshot)
        extracted = extract_source_text(
            raw,
            mime_type="text/plain",
            source_url=source["canonical_url"],
        )
        sections = segment_structured_blocks(
            snapshot["snapshot_hash"],
            [asdict(block) for block in extracted.blocks],
            parser_name=extracted.parser_name,
            parser_version=extracted.parser_version,
        )
        self.store.save_sections(retrieval_id, sections)
        section = self.store.section(sections[0]["section_id"])
        job_id = self.store.enqueue_inference(
            build_inference_request(section, source["program"], pass_number=1)
        )

        claimed = self.store.claim_inference_jobs(
            "crashing-worker", limit=1, lease_seconds=1
        )
        self.assertEqual([job["inference_job_id"] for job in claimed], [job_id])
        self.store.renew_inference_lease(
            job_id, worker_id="crashing-worker", lease_seconds=60
        )
        with self.store.connection() as conn:
            conn.execute(
                """
                UPDATE inference_jobs
                SET lease_expires_at = now() - interval '1 second'
                WHERE inference_job_id = %s
                """,
                (job_id,),
            )
            conn.commit()
        recovered = self.store.recover_expired_inference_leases()
        self.assertEqual(recovered["requeued"], 1)
        self.assertEqual(recovered["failed_at_attempt_limit"], 0)
        self.assertEqual(recovered["remaining_expired_leases"], 0)
        claimed = self.store.claim_inference_jobs(
            "crashing-worker", limit=1, lease_seconds=60
        )
        self.assertEqual([job["inference_job_id"] for job in claimed], [job_id])
        with self.store.connection() as conn:
            conn.execute(
                """
                UPDATE inference_jobs
                SET attempts = attempt_limit,
                    lease_expires_at = now() - interval '1 second'
                WHERE inference_job_id = %s
                """,
                (job_id,),
            )
            conn.commit()

        recovered = self.store.recover_expired_inference_leases()
        self.assertEqual(recovered["requeued"], 0)
        self.assertEqual(recovered["failed_at_attempt_limit"], 1)
        self.assertEqual(recovered["remaining_expired_leases"], 0)
        with self.store.connection() as conn:
            exhausted = conn.execute(
                """
                SELECT status, attempts, attempt_limit, retry_rounds, lease_renewals
                FROM inference_jobs WHERE inference_job_id = %s
                """,
                (job_id,),
            ).fetchone()
        self.assertEqual(exhausted["status"], "failed")
        self.assertEqual(exhausted["attempts"], exhausted["attempt_limit"])
        self.assertEqual(exhausted["lease_renewals"], 1)

        self.assertEqual(
            self.store.retry_failed_inference_jobs(
                limit=1, additional_attempts=5
            ),
            1,
        )
        resumed = self.store.claim_inference_jobs("replacement-worker", limit=1)
        self.assertEqual([job["inference_job_id"] for job in resumed], [job_id])
        self.assertEqual(resumed[0]["attempts"], exhausted["attempts"] + 1)
        self.assertEqual(resumed[0]["attempt_limit"], exhausted["attempt_limit"] + 5)
        self.assertEqual(resumed[0]["retry_rounds"], 1)
        with self.assertRaisesRegex(CorpusDatabaseError, "lost before renewal"):
            self.store.renew_inference_lease(
                job_id,
                worker_id="crashing-worker",
                lease_seconds=60,
            )
        self.store.fail_inference_job(
            job_id,
            worker_id="replacement-worker",
            error="fixture retryable transport failure",
            retry=True,
            input_tokens=3,
            output_tokens=4,
            usage_metadata={"model": "fixture", "request_id": "failed-request"},
        )
        resumed = self.store.claim_inference_jobs("replacement-worker", limit=1)
        self.assertEqual([job["inference_job_id"] for job in resumed], [job_id])

        with self.store.connection() as conn:
            conn.execute(
                """
                UPDATE inference_jobs
                SET lease_expires_at = now() - interval '1 second'
                WHERE inference_job_id = %s
                """,
                (job_id,),
            )
            conn.commit()
        self.store.renew_inference_lease(
            job_id, worker_id="replacement-worker", lease_seconds=60
        )
        with self.store.connection() as conn:
            conn.execute(
                """
                UPDATE inference_jobs
                SET lease_expires_at = now() - interval '1 second'
                WHERE inference_job_id = %s
                """,
                (job_id,),
            )
            conn.commit()

        evidence = build_evidence_span(
            section, 0, len(section["normalized_text"])
        )
        response = {
            "candidates": [
                {
                    "program": source["program"],
                    "authority": {"issuer": source["issuer"], "citation": "fixture"},
                    "rule_type": "eligibility_rule",
                    "conditions": {
                        "op": "compare",
                        "fact": "application_filed",
                        "fact_type": "boolean",
                        "operator": "eq",
                        "value": {"type": "boolean", "value": True},
                    },
                    "outcome": {"kind": "decision", "code": "eligible"},
                    "effective_from": "2026-01-01",
                    "effective_through": None,
                    "exceptions": [],
                    "evidence": evidence,
                }
            ]
        }
        with self.store.connection() as conn:
            conn.execute(
                "UPDATE source_sections SET active = false WHERE section_id = %s",
                (section["section_id"],),
            )
            conn.commit()
        with self.assertRaisesRegex(CorpusDatabaseError, "superseded"):
            self.store.commit_inference_result(
                job_id,
                worker_id="replacement-worker",
                response_payload=response,
                input_tokens=10,
                output_tokens=20,
                usage_metadata={"model": "fixture", "request_id": "fixture"},
            )
        with self.store.connection() as conn:
            candidate_count = conn.execute(
                "SELECT count(*) AS count FROM grounded_candidates"
            ).fetchone()["count"]
            job_status = conn.execute(
                "SELECT status FROM inference_jobs WHERE inference_job_id = %s",
                (job_id,),
            ).fetchone()["status"]
            conn.execute(
                "UPDATE source_sections SET active = true WHERE section_id = %s",
                (section["section_id"],),
            )
            conn.commit()
        self.assertEqual(candidate_count, 0)
        self.assertEqual(job_status, "leased")
        with self.store.connection() as conn:
            conn.execute(
                "UPDATE official_sources SET active = false WHERE source_id = %s",
                (source["source_id"],),
            )
            conn.commit()
        with self.assertRaisesRegex(CorpusDatabaseError, "superseded"):
            self.store.commit_inference_result(
                job_id,
                worker_id="replacement-worker",
                response_payload=response,
                input_tokens=10,
                output_tokens=20,
                usage_metadata={"model": "fixture", "request_id": "fixture"},
            )
        with self.store.connection() as conn:
            self.assertEqual(
                conn.execute(
                    "SELECT count(*) AS count FROM grounded_candidates"
                ).fetchone()["count"],
                0,
            )
            conn.execute(
                "UPDATE official_sources SET active = true WHERE source_id = %s",
                (source["source_id"],),
            )
            conn.commit()
        self.assertEqual(
            self.store.commit_inference_result(
                job_id,
                worker_id="replacement-worker",
                response_payload=response,
                input_tokens=10,
                output_tokens=20,
                usage_metadata={"model": "fixture", "request_id": "fixture"},
            ),
            1,
        )
        with self.store.connection() as conn:
            committed = conn.execute(
                """
                SELECT jobs.status, jobs.input_tokens, jobs.output_tokens,
                       jobs.usage_metadata,
                       count(candidates.candidate_id) AS candidate_count
                FROM inference_jobs jobs
                LEFT JOIN grounded_candidates candidates
                  ON candidates.extraction_job_id = jobs.inference_job_id
                WHERE jobs.inference_job_id = %s
                GROUP BY jobs.status, jobs.input_tokens, jobs.output_tokens,
                         jobs.usage_metadata
                """,
                (job_id,),
            ).fetchone()
        self.assertEqual(committed["status"], "completed")
        self.assertEqual(committed["candidate_count"], 1)
        self.assertEqual(committed["input_tokens"], 13)
        self.assertEqual(committed["output_tokens"], 24)
        self.assertEqual(len(committed["usage_metadata"]["attempts"]), 2)
        self.assertEqual(
            [item["status"] for item in committed["usage_metadata"]["attempts"]],
            ["retry_scheduled", "completed"],
        )
        usage_report = self.store.inference_usage_report()
        self.assertEqual(json.loads(json.dumps(usage_report)), usage_report)
        self.assertEqual(usage_report["input_tokens"], 13)
        self.assertEqual(usage_report["output_tokens"], 24)
        self.assertEqual(len(self.store.pending_critique_sections()), 1)
        with self.store.connection() as conn:
            conn.execute(
                """
                UPDATE inference_jobs
                SET prompt_version = 'superseded-extraction-prompt-v0'
                WHERE inference_job_id = %s
                """,
                (job_id,),
            )
            conn.commit()
        self.assertEqual(self.store.pending_critique_sections(), [])

    def test_launch_failures_ignore_superseded_inference_contracts(self) -> None:
        registry = load_source_registry(WORKDIR)
        self.store.sync_registry(registry)
        source = registry["sources"][0]
        raw = b"Applicants must meet the official eligibility requirement."
        snapshot = build_source_snapshot(
            source,
            raw,
            retrieved_at="2026-08-09T12:00:00Z",
            mime_type="text/plain",
        )
        retrieval_id = self.store.save_snapshot(snapshot)
        sections = segment_text(
            snapshot["snapshot_hash"],
            raw.decode("utf-8"),
            parser_name="launch-failure-fixture",
            parser_version="1",
        )
        self.store.save_sections(retrieval_id, sections)
        section = self.store.section(sections[0]["section_id"])
        request = build_inference_request(
            section, section["program"], pass_number=1
        )
        job_id = self.store.enqueue_inference(request)
        with self.store.connection() as conn:
            conn.execute(
                """
                UPDATE inference_jobs
                SET status = 'failed', prompt_version = 'superseded-prompt-v0'
                WHERE inference_job_id = %s
                """,
                (job_id,),
            )
            conn.commit()

        historical = self.store.corpus_scale_progress(5_100)
        self.assertEqual(historical["queue_failures"]["inference_jobs"], 1)
        self.assertEqual(
            historical["blocking_queue_failures"]["inference_jobs"], 0
        )
        self.assertEqual(
            self.store.retry_failed_inference_jobs(limit=1),
            0,
        )

        with self.store.connection() as conn:
            conn.execute(
                """
                UPDATE inference_jobs
                SET prompt_version = %s
                WHERE inference_job_id = %s
                """,
                (request["prompt_version"], job_id),
            )
            conn.commit()
        current = self.store.corpus_scale_progress(5_100)
        self.assertEqual(current["queue_failures"]["inference_jobs"], 1)
        self.assertEqual(
            current["blocking_queue_failures"]["inference_jobs"], 1
        )
        failure_report = self.store.inference_failure_report(limit=10)
        self.assertEqual(failure_report["failed"], 1)
        self.assertEqual(failure_report["rejected"], 0)
        self.assertEqual(failure_report["current_retryable_failed"], 1)
        self.assertTrue(failure_report["details"][0]["current_contract"])
        self.assertTrue(failure_report["details"][0]["operator_retryable"])
        self.assertEqual(
            failure_report["details"][0]["error_class"],
            "transport_or_worker_failure",
        )
        self.assertFalse(failure_report["contains_source_text"])

        with self.store.connection() as conn:
            conn.execute(
                """
                UPDATE inference_jobs
                SET status = 'pending', lease_owner = NULL, lease_expires_at = NULL
                WHERE inference_job_id = %s
                """,
                (job_id,),
            )
            conn.commit()
        claimed = self.store.claim_inference_jobs("rejection-worker", limit=1)
        self.assertEqual([item["inference_job_id"] for item in claimed], [job_id])
        self.store.fail_inference_job(
            job_id,
            worker_id="rejection-worker",
            error="fixture deterministic response rejection",
            retry=False,
            rejected=True,
            input_tokens=5,
            output_tokens=7,
            usage_metadata={"request_id": "rejected-request"},
        )
        rejected = self.store.corpus_scale_progress(5_100)
        self.assertEqual(rejected["queues"]["inference_jobs"]["rejected"], 1)
        self.assertEqual(rejected["queue_failures"]["inference_jobs"], 0)
        self.assertEqual(
            rejected["blocking_queue_failures"]["inference_jobs"], 0
        )
        rejection_report = self.store.inference_failure_report(limit=10)
        self.assertEqual(rejection_report["failed"], 0)
        self.assertEqual(rejection_report["rejected"], 1)
        self.assertFalse(rejection_report["details"][0]["operator_retryable"])
        self.assertEqual(
            rejection_report["details"][0]["error_class"], "response_rejected"
        )

    def test_inactive_source_failures_are_historical_not_blocking(self) -> None:
        registry = load_source_registry(WORKDIR)
        self.store.sync_registry(registry)
        source = registry["sources"][0]
        raw = b"Applicants must meet the official eligibility requirement."
        snapshot = build_source_snapshot(
            source,
            raw,
            retrieved_at="2026-08-09T12:00:00Z",
            mime_type="text/plain",
        )
        retrieval_id = self.store.save_snapshot(snapshot)
        sections = segment_text(
            snapshot["snapshot_hash"],
            raw.decode("utf-8"),
            parser_name="inactive-failure-fixture",
            parser_version="1",
        )
        self.store.save_sections(retrieval_id, sections)
        section_id = sections[0]["section_id"]
        request = build_inference_request(
            self.store.section(section_id),
            source["program"],
            pass_number=1,
        )
        job_id = self.store.enqueue_inference(request)
        with self.store.connection() as conn:
            conn.execute(
                """
                UPDATE inference_jobs
                SET status = 'failed', last_error = 'fixture transport failure'
                WHERE inference_job_id = %s
                """,
                (job_id,),
            )
            conn.execute(
                """
                UPDATE official_sources
                SET active = false
                WHERE source_id = %s
                """,
                (source["source_id"],),
            )
            conn.commit()

        progress = self.store.corpus_scale_progress(5_100)
        self.assertEqual(progress["queue_failures"]["inference_jobs"], 1)
        self.assertEqual(
            progress["blocking_queue_failures"]["inference_jobs"], 0
        )
        failure_report = self.store.inference_failure_report(limit=10)
        self.assertEqual(failure_report["current_retryable_failed"], 0)
        self.assertFalse(failure_report["details"][0]["source_active"])
        self.assertFalse(failure_report["details"][0]["operator_retryable"])

    def test_repeat_candidate_refreshes_current_contract_projection(self) -> None:
        from psycopg.types.json import Jsonb

        registry = load_source_registry(WORKDIR)
        self.store.sync_registry(registry)
        source = registry["sources"][0]
        raw = b"Applicants must file an application to qualify."
        snapshot = build_source_snapshot(
            source,
            raw,
            retrieved_at="2026-08-09T12:00:00Z",
            mime_type="text/plain",
        )
        retrieval_id = self.store.save_snapshot(snapshot)
        sections = segment_text(
            snapshot["snapshot_hash"],
            raw.decode("utf-8"),
            parser_name="contract-projection-fixture",
            parser_version="1",
        )
        self.store.save_sections(retrieval_id, sections)
        section = self.store.section(sections[0]["section_id"])
        evidence = build_evidence_span(section, 0, len(section["normalized_text"]))
        candidate = {
            "program": source["program"],
            "authority": {"issuer": source["issuer"], "citation": "fixture"},
            "rule_type": "eligibility_rule",
            "conditions": {
                "op": "compare",
                "fact": "application_filed",
                "fact_type": "boolean",
                "operator": "eq",
                "value": {"type": "boolean", "value": True},
            },
            "outcome": {"kind": "decision", "code": "eligible"},
            "effective_from": "2026-01-01",
            "effective_through": None,
            "exceptions": [],
            "evidence": evidence,
        }
        identifier = candidate_id(section, candidate)
        old_job_id = f"old_contract_{uuid.uuid4().hex}"
        with self.store.connection() as conn:
            conn.execute(
                """
                INSERT INTO inference_jobs (
                    inference_job_id, section_id, pass, prompt_version,
                    model_version, schema_version, idempotency_key, status,
                    request_payload
                ) VALUES (
                    %s, %s, 1, 'superseded-extraction-v0', 'superseded-model',
                    'localbce-grounded-inference-v1', %s, 'completed', %s
                )
                """,
                (
                    old_job_id,
                    section["section_id"],
                    canonical_sha256({"old_job": old_job_id}),
                    Jsonb({"response_contract_version": "superseded-contract-v0"}),
                ),
            )
            conn.execute(
                """
                INSERT INTO grounded_candidates (
                    candidate_id, primary_program, section_id, snapshot_hash,
                    evidence_char_start, evidence_char_end, evidence_byte_start,
                    evidence_byte_end, evidence_quote, evidence_hash,
                    extraction_job_id, extraction_contract_key,
                    critique_contract_key, candidate_payload, grounding_status
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, 'accepted'
                )
                """,
                (
                    identifier,
                    candidate["program"],
                    section["section_id"],
                    section["snapshot_hash"],
                    evidence["char_start"],
                    evidence["char_end"],
                    evidence["byte_start"],
                    evidence["byte_end"],
                    evidence["quote"],
                    evidence["evidence_hash"],
                    old_job_id,
                    "0" * 64,
                    "1" * 64,
                    Jsonb({**candidate, "candidate_id": identifier}),
                ),
            )
            conn.commit()

        self.assertEqual(
            self.store.corpus_scale_progress(5_100)["accepted_grounded_candidates"],
            0,
        )
        request = build_inference_request(
            section, source["program"], pass_number=1
        )
        extraction_job_id = self.store.enqueue_inference(request)
        claimed = self.store.claim_inference_jobs(
            "current-extraction-worker", limit=1
        )
        self.assertEqual(
            [item["inference_job_id"] for item in claimed],
            [extraction_job_id],
        )
        self.store.commit_inference_result(
            extraction_job_id,
            worker_id="current-extraction-worker",
            response_payload={"candidates": [candidate]},
            input_tokens=1,
            output_tokens=1,
            usage_metadata={"request_id": "current-extraction"},
        )
        with self.store.connection() as conn:
            projected = conn.execute(
                """
                SELECT extraction_job_id, extraction_contract_key,
                       critique_contract_key, grounding_status
                FROM grounded_candidates WHERE candidate_id = %s
                """,
                (identifier,),
            ).fetchone()
        self.assertEqual(projected["extraction_job_id"], extraction_job_id)
        self.assertEqual(
            projected["extraction_contract_key"],
            CURRENT_EXTRACTION_CONTRACT_KEY,
        )
        self.assertIsNone(projected["critique_contract_key"])
        self.assertEqual(projected["grounding_status"], "pending")

        repaired = copy.deepcopy(candidate)
        repaired["outcome"]["code"] = "conditionally_eligible"
        repaired_identifier = candidate_id(section, repaired)
        with self.store.connection() as conn:
            conn.execute(
                """
                INSERT INTO grounded_candidates (
                    candidate_id, primary_program, section_id, snapshot_hash,
                    evidence_char_start, evidence_char_end, evidence_byte_start,
                    evidence_byte_end, evidence_quote, evidence_hash,
                    extraction_job_id, extraction_contract_key,
                    critique_contract_key, candidate_payload, grounding_status
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, 'accepted'
                )
                """,
                (
                    repaired_identifier,
                    repaired["program"],
                    section["section_id"],
                    section["snapshot_hash"],
                    evidence["char_start"],
                    evidence["char_end"],
                    evidence["byte_start"],
                    evidence["byte_end"],
                    evidence["quote"],
                    evidence["evidence_hash"],
                    old_job_id,
                    "0" * 64,
                    "1" * 64,
                    Jsonb({**repaired, "candidate_id": repaired_identifier}),
                ),
            )
            conn.execute(
                """
                INSERT INTO candidate_lineage (
                    lineage_id, candidate_id, predecessor_candidate_id,
                    relation, details
                ) VALUES (%s, %s, %s, 'repaired_from', '{}'::jsonb)
                """,
                (
                    f"lineage_{uuid.uuid4().hex}",
                    repaired_identifier,
                    identifier,
                ),
            )
            conn.commit()

        critique_section = self.store.pending_critique_sections()[0]
        critique_request = build_inference_request(
            critique_section,
            critique_section["program"],
            pass_number=2,
            proposed_candidates=critique_section["proposed_candidates"],
        )
        critique_job_id = self.store.enqueue_inference(critique_request)
        claimed = self.store.claim_inference_jobs(
            "current-critique-worker", limit=1
        )
        self.assertEqual(
            [item["inference_job_id"] for item in claimed],
            [critique_job_id],
        )
        self.store.commit_inference_result(
            critique_job_id,
            worker_id="current-critique-worker",
            response_payload={
                "candidates": [
                    {
                        "candidate_id": identifier,
                        "critique": {
                            "result": "repair",
                            "findings": ["fixture correction"],
                            "repaired_candidate": repaired,
                        },
                    }
                ]
            },
            input_tokens=1,
            output_tokens=1,
            usage_metadata={"request_id": "current-critique"},
        )
        with self.store.connection() as conn:
            projected = conn.execute(
                """
                SELECT extraction_contract_key, critique_contract_key,
                       grounding_status
                FROM grounded_candidates WHERE candidate_id = %s
                """,
                (repaired_identifier,),
            ).fetchone()
            original = conn.execute(
                """
                SELECT grounding_status
                FROM grounded_candidates WHERE candidate_id = %s
                """,
                (identifier,),
            ).fetchone()
            lineage_count = conn.execute(
                """
                SELECT count(*) AS count FROM candidate_lineage
                WHERE candidate_id = %s
                  AND relation = 'repaired_from'
                  AND predecessor_candidate_id = %s
                """,
                (repaired_identifier, identifier),
            ).fetchone()["count"]
        self.assertEqual(
            projected["extraction_contract_key"],
            CURRENT_EXTRACTION_CONTRACT_KEY,
        )
        self.assertEqual(
            projected["critique_contract_key"],
            CURRENT_CRITIQUE_CONTRACT_KEY,
        )
        self.assertEqual(projected["grounding_status"], "accepted")
        self.assertEqual(
            self.store.corpus_scale_progress(5_100)["accepted_grounded_candidates"],
            1,
        )
        self.assertEqual(original["grounding_status"], "repair")
        self.assertEqual(lineage_count, 1)

    def test_ocr_artifact_is_immutable_linked_and_mandatory_for_quality(self) -> None:
        from psycopg.types.json import Jsonb

        registry = load_source_registry(WORKDIR)
        self.store.sync_registry(registry)
        source = registry["sources"][0]
        snapshot = build_source_snapshot(
            source,
            b"%PDF-1.7\nscanned fixture",
            retrieved_at="2026-08-11T12:00:00Z",
            mime_type="application/pdf",
            text_layer_kind="none",
        )
        retrieval_id = self.store.save_snapshot(snapshot)
        extraction_job_id = f"ocr-failed-{uuid.uuid4().hex}"
        with self.store.connection() as conn:
            conn.execute(
                """
                INSERT INTO section_extraction_jobs (
                    extraction_job_id, retrieval_id, snapshot_hash,
                    pipeline_version, status, attempts, attempt_limit, last_error
                ) VALUES (%s, %s, %s, 'section-extraction-v1', 'failed', 5, 5,
                          'source has no usable text layer; OCR review is required')
                """,
                (extraction_job_id, retrieval_id, snapshot["snapshot_hash"]),
            )
            conn.commit()

        artifact = build_ocr_artifact(
            retrieval_id=retrieval_id,
            snapshot_hash=snapshot["snapshot_hash"],
            artifact_bytes=b"Applicants must file an application to qualify.\n",
            engine_name="tesseract",
            engine_version="5.4.1",
            operator_id="reviewer-17",
            generated_at="2026-08-11T17:30:00Z",
            metadata={"artifact_relative_path": "fixture/source.txt"},
        )
        sections = segment_text(
            snapshot["snapshot_hash"],
            artifact["normalized_text"],
            parser_name="ocr:tesseract",
            parser_version="5.4.1",
            extraction_pipeline_version=(
                f"ocr-artifact-v1:{artifact['artifact_hash']}"
            ),
            ocr_used=True,
            source_locator={
                "kind": "ocr_artifact_text",
                "ocr_artifact_id": artifact["ocr_artifact_id"],
                "ocr_artifact_hash": artifact["artifact_hash"],
            },
        )
        first = self.store.save_ocr_artifact(artifact, sections)
        repeated = self.store.save_ocr_artifact(artifact, sections)
        self.assertEqual(first, repeated)
        self.assertTrue(first["mandatory_quality_review"])

        section = sections[0]
        digest = canonical_sha256({"ocr_fixture": artifact["artifact_hash"]})
        inference_job_id = f"ocr-inference-{uuid.uuid4().hex}"
        candidate_id_value = f"ocr-candidate-{uuid.uuid4().hex}"
        draft_id = f"ocr-draft-{uuid.uuid4().hex}"
        canonical_rule = {"candidate_id": candidate_id_value, "version": 1}
        draft_hash = canonical_sha256(canonical_rule)
        with self.store.connection() as conn:
            evidence_rows = conn.execute(
                """
                SELECT snapshots.text_layer_kind,
                       count(DISTINCT artifacts.ocr_artifact_id) AS artifact_count,
                       count(DISTINCT links.section_id) AS linked_section_count
                FROM source_snapshots snapshots
                JOIN source_ocr_artifacts artifacts
                  ON artifacts.retrieval_id = %s
                JOIN source_ocr_artifact_sections links
                  ON links.ocr_artifact_id = artifacts.ocr_artifact_id
                WHERE snapshots.snapshot_hash = %s
                GROUP BY snapshots.text_layer_kind
                """,
                (retrieval_id, snapshot["snapshot_hash"]),
            ).fetchone()
            self.assertEqual(evidence_rows["text_layer_kind"], "none")
            self.assertEqual(evidence_rows["artifact_count"], 1)
            self.assertEqual(evidence_rows["linked_section_count"], len(sections))
            conn.execute(
                """
                INSERT INTO inference_jobs (
                    inference_job_id, section_id, pass, prompt_version,
                    model_version, schema_version, idempotency_key, status,
                    request_payload
                ) VALUES (%s, %s, 1, 'fixture', 'fixture', 'fixture', %s,
                          'completed', '{}'::jsonb)
                """,
                (inference_job_id, section["section_id"], digest),
            )
            conn.execute(
                """
                INSERT INTO grounded_candidates (
                    candidate_id, primary_program, section_id, snapshot_hash,
                    evidence_char_start, evidence_char_end, evidence_byte_start,
                    evidence_byte_end, evidence_quote, evidence_hash,
                    extraction_job_id, extraction_contract_key,
                    critique_contract_key, candidate_payload, grounding_status
                ) VALUES (%s, %s, %s, %s, 0, %s, 0, %s, %s, %s,
                          %s, %s, %s, %s, 'accepted')
                """,
                (
                    candidate_id_value,
                    source["program"],
                    section["section_id"],
                    snapshot["snapshot_hash"],
                    len(section["normalized_text"]),
                    len(section["normalized_text"].encode("utf-8")),
                    section["normalized_text"],
                    section["normalized_text_hash"],
                    inference_job_id,
                    CURRENT_EXTRACTION_CONTRACT_KEY,
                    CURRENT_CRITIQUE_CONTRACT_KEY,
                    Jsonb({"candidate_id": candidate_id_value}),
                ),
            )
            conn.execute(
                """
                INSERT INTO typed_rule_drafts (
                    draft_id, candidate_id, draft_version, canonical_rule,
                    canonical_hash, semantic_fingerprint, scope_fingerprint,
                    outcome_hash, runtime_eligibility_status
                ) VALUES (%s, %s, 1, %s, %s, %s, %s, %s, 'shadow_only')
                """,
                (
                    draft_id,
                    candidate_id_value,
                    Jsonb(canonical_rule),
                    draft_hash,
                    digest,
                    digest,
                    digest,
                ),
            )
            conn.commit()

        candidates = self.store.quality_sample_candidates()
        candidate = next(
            item for item in candidates if item["candidate_id"] == candidate_id_value
        )
        self.assertIn("ocr_evidence", candidate["mandatory_reasons"])

    def test_structured_sections_and_reviewed_source_discovery_round_trip(self) -> None:
        registry = load_source_registry(WORKDIR)
        self.store.sync_registry(registry)
        source = registry["sources"][0]
        second_source = next(
            item
            for item in registry["sources"]
            if item["program"] == source["program"]
            and item["source_id"] != source["source_id"]
        )
        nonce = uuid.uuid4().hex
        candidate_url = f"https://www.cms.gov/rules/{nonce}"
        raw = (
            "<html><body><h1>Eligibility</h1>"
            f"<p>Applicants must file form {nonce}.</p>"
            f"<a href='{candidate_url}'>{source['program']} official rule</a>"
            "</body></html>"
        ).encode("utf-8")
        snapshot = build_source_snapshot(
            source,
            raw,
            retrieved_at="2026-08-06T12:00:00Z",
            mime_type="text/html",
        )
        retrieval_id = self.store.save_snapshot(snapshot)
        extracted = extract_source_text(
            raw,
            mime_type="text/html",
            source_url=source["canonical_url"],
        )
        sections = segment_structured_blocks(
            snapshot["snapshot_hash"],
            [asdict(block) for block in extracted.blocks],
            parser_name=extracted.parser_name,
            parser_version=extracted.parser_version,
        )
        self.assertEqual(
            self.store.save_sections(retrieval_id, sections), len(sections)
        )
        stored_section = self.store.section(sections[0]["section_id"])
        self.assertEqual(stored_section["hierarchy_path"], ["Eligibility"])
        self.assertTrue(stored_section["source_locator"]["blocks"])

        links = [
            asdict(link)
            for link in discover_official_links(
                raw,
                mime_type="text/html",
                source_url=source["canonical_url"],
            )
        ]
        run = self.store.save_source_discovery(
            retrieval={
                "retrieval_id": retrieval_id,
                "snapshot_hash": snapshot["snapshot_hash"],
                "parent_source_id": source["source_id"],
                "program": source["program"],
            },
            parser_version=SOURCE_DISCOVERY_PARSER_VERSION,
            links=links,
        )
        self.assertEqual(run["candidate_count"], 1)
        second_raw = (
            "<html><body><h1>Updated landing page</h1>"
            f"<p>Second capture {uuid.uuid4().hex}.</p>"
            f"<a href='{candidate_url}'>Read more</a>"
            "</body></html>"
        ).encode("utf-8")
        second_snapshot = build_source_snapshot(
            second_source,
            second_raw,
            retrieved_at="2026-08-07T12:00:00Z",
            mime_type="text/html",
        )
        second_retrieval_id = self.store.save_snapshot(second_snapshot)
        second_links = [
            asdict(link)
            for link in discover_official_links(
                second_raw,
                mime_type="text/html",
                source_url=second_source["canonical_url"],
            )
        ]
        second_run = self.store.save_source_discovery(
            retrieval={
                "retrieval_id": second_retrieval_id,
                "snapshot_hash": second_snapshot["snapshot_hash"],
                "parent_source_id": second_source["source_id"],
                "program": second_source["program"],
            },
            parser_version=SOURCE_DISCOVERY_PARSER_VERSION,
            links=second_links,
        )
        self.assertEqual(second_run["candidate_count"], 1)
        preflight = self.store.preflight_source_registry_candidates(
            target_count=600_000
        )
        self.assertEqual(preflight["candidates_assessed_this_run"], 2)
        self.assertEqual(preflight["unique_program_url_count"], 1)
        self.assertEqual(preflight["duplicate_source_candidate_count"], 1)
        self.assertEqual(preflight["duplicate_source_candidate_group_count"], 1)
        self.assertEqual(preflight["eligible_for_human_review_count"], 1)
        self.assertEqual(
            preflight["blocker_counts"]["duplicate_source_candidate_url"], 1
        )
        self.assertEqual(
            preflight["eligible_priority_counts"], {"general_official_source": 1}
        )
        self.assertEqual(
            preflight["eligible_scope_mode_counts"],
            {"direct_candidate_evidence": 1},
        )
        self.assertEqual(preflight["temporal_authority_eligible_count"], 0)
        self.assertEqual(preflight["temporal_authority_program_counts"], {})
        self.assertTrue(preflight["human_review_required"])
        self.assertEqual(preflight["source_review_milestone_target"], 600_000)
        self.assertEqual(len(preflight["accepted_candidate_counts"]), 51)
        self.assertEqual(
            preflight["accepted_candidate_counts"][source["program"]], 0
        )
        source_priority = next(
            item
            for item in preflight["source_review_priority_programs"]
            if item["program"] == source["program"]
        )
        self.assertEqual(source_priority["eligible_source_candidates"], 1)
        self.assertEqual(source_priority["accepted_grounded_candidates"], 0)
        self.assertEqual(
            source_priority["active_program_section_count"], len(sections)
        )
        self.assertEqual(
            source_priority["program_context_candidate_upper_bound"],
            len(sections) * 25,
        )
        self.assertFalse(source_priority["program_context_quota_possible"])
        self.assertGreater(
            source_priority["minimum_additional_program_contexts_lower_bound"],
            0,
        )
        self.assertIn(
            source["program"],
            preflight["programs_without_program_context_quota_capacity"],
        )
        self.assertTrue(
            preflight["source_capacity_evidence_is_necessary_not_sufficient"]
        )
        capacity_review_candidates = preflight[
            "capacity_blocker_review_candidates"
        ]
        self.assertEqual(
            preflight["capacity_blocker_review_candidate_count"],
            len(capacity_review_candidates),
        )
        self.assertEqual(
            preflight["capacity_blocker_review_candidates_sha256"],
            canonical_sha256(capacity_review_candidates),
        )
        reviewed_candidate = next(
            item
            for item in capacity_review_candidates
            if item["program"] == source["program"]
        )
        self.assertEqual(
            reviewed_candidate["scope_mode"], "direct_candidate_evidence"
        )
        self.assertEqual(
            reviewed_candidate["approval_effect"],
            "inactive_registry_candidate_only",
        )
        self.assertFalse(reviewed_candidate["legal_verification"])
        self.assertFalse(reviewed_candidate["runtime_activation"])
        self.assertFalse(reviewed_candidate["proof_binding"])
        with self.assertRaisesRegex(ValueError, "5100, 51000, or 600000"):
            self.store.source_registry_preflight_summary(target_count=600_001)
        other_program = next(
            program for program in all_programs() if program != source["program"]
        )
        self.assertNotIn(
            source["program"],
            preflight["zero_candidate_programs_without_eligible_source_candidates"],
        )
        self.assertIn(
            other_program,
            preflight["zero_candidate_programs_without_eligible_source_candidates"],
        )
        self.assertNotIn(
            source["program"],
            preflight["deficit_programs_without_eligible_source_candidates"],
        )
        self.assertIn(
            other_program,
            preflight["deficit_programs_without_eligible_source_candidates"],
        )
        self.assertIsNone(
            self.store.claim_source_registry_candidate(
                reviewer_id="admin-other", program=other_program, lease_seconds=60
            )
        )
        with self.assertRaisesRegex(ValueError, "recognized program"):
            self.store.claim_source_registry_candidate(
                reviewer_id="admin-invalid", program="not_a_program"
            )
        self.assertFalse(preflight["automatic_registry_activation"])
        claimed = self.store.claim_source_registry_candidate(
            reviewer_id="admin-fixture",
            program=source["program"],
            lease_seconds=60,
        )
        self.assertIsNotNone(claimed)
        self.assertFalse(claimed["registry_activation"])
        self.assertEqual(claimed["claim_attempts"], 1)
        with self.assertRaisesRegex(CorpusDatabaseError, "owned by another"):
            self.store.renew_source_registry_candidate_claim(
                claimed["source_candidate_id"],
                reviewer_id="different-admin",
                lease_seconds=60,
            )
        renewed = self.store.renew_source_registry_candidate_claim(
            claimed["source_candidate_id"],
            reviewer_id="admin-fixture",
            lease_seconds=120,
        )
        self.assertEqual(renewed["action"], "renew")
        released = self.store.release_source_registry_candidate_claim(
            claimed["source_candidate_id"], reviewer_id="admin-fixture"
        )
        self.assertEqual(released["review_status"], "pending_review")
        reclaimed = self.store.claim_source_registry_candidate(
            reviewer_id="admin-replacement", lease_seconds=60
        )
        self.assertEqual(reclaimed["source_candidate_id"], claimed["source_candidate_id"])
        self.assertEqual(reclaimed["claim_attempts"], 2)
        with self.store.connection() as conn:
            conn.execute(
                """
                UPDATE source_registry_candidates
                SET claim_expires_at = now() - interval '1 second'
                WHERE source_candidate_id = %s
                """,
                (claimed["source_candidate_id"],),
            )
            conn.commit()
        reclaimed = self.store.claim_source_registry_candidate(
            reviewer_id="admin-final", lease_seconds=60
        )
        self.assertEqual(reclaimed["claim_attempts"], 3)
        detail = self.store.source_registry_candidate_detail(
            claimed["source_candidate_id"]
        )
        self.assertEqual(
            detail["parent_snapshot_hash"], snapshot["snapshot_hash"]
        )
        decision = self.store.record_source_registry_candidate_decision(
            source_candidate_id=claimed["source_candidate_id"],
            reviewer_id="admin-final",
            decision="approve_for_registry",
            rationale="official host and immutable parent snapshot verified",
        )
        self.assertEqual(decision["review_status"], "approved_for_registry")
        self.assertFalse(decision["registry_activation"])
        approved_ids = {
            item["source_candidate_id"]
            for item in self.store.approved_source_registry_candidates()
        }
        self.assertIn(claimed["source_candidate_id"], approved_ids)
        with self.store.connection() as conn:
            actions = {
                row["action"]
                for row in conn.execute(
                    """
                    SELECT action FROM review_audit_events
                    WHERE entity_id = %s
                    """,
                    (claimed["source_candidate_id"],),
                ).fetchall()
            }
        self.assertTrue(
            {
                "source_claimed",
                "source_claim_renew",
                "source_claim_release",
                "source_claim_expired",
                "source_registry_review",
            }.issubset(actions)
        )

    def test_source_review_is_superseded_by_newer_different_parent_bytes(self) -> None:
        registry = load_source_registry(WORKDIR)
        self.store.sync_registry(registry)
        source = registry["sources"][0]
        first_raw = (
            f"<html><body><a href='/official/v1'>"
            f"{source['program']} version one rule</a></body></html>"
        ).encode("utf-8")
        first = build_source_snapshot(
            source,
            first_raw,
            retrieved_at="2026-08-06T12:00:00Z",
            mime_type="text/html",
        )
        first_retrieval_id = self.store.save_snapshot(first)
        links = [
            asdict(link)
            for link in discover_official_links(
                first_raw,
                mime_type="text/html",
                source_url=source["canonical_url"],
            )
        ]
        self.store.save_source_discovery(
            retrieval={
                "retrieval_id": first_retrieval_id,
                "snapshot_hash": first["snapshot_hash"],
                "parent_source_id": source["source_id"],
                "program": source["program"],
            },
            parser_version=SOURCE_DISCOVERY_PARSER_VERSION,
            links=links,
        )
        self.store.preflight_source_registry_candidates()
        claimed = self.store.claim_source_registry_candidate(
            reviewer_id="admin-lineage", lease_seconds=60
        )
        self.store.record_source_registry_candidate_decision(
            source_candidate_id=claimed["source_candidate_id"],
            reviewer_id="admin-lineage",
            decision="approve_for_registry",
            rationale="exact first snapshot reviewed",
        )
        self.assertEqual(len(self.store.approved_source_registry_candidates()), 1)

        same_bytes = build_source_snapshot(
            source,
            first_raw,
            retrieved_at="2026-08-06T13:00:00Z",
            mime_type="text/html",
        )
        self.store.save_snapshot(same_bytes)
        self.assertEqual(len(self.store.approved_source_registry_candidates()), 1)

        second = build_source_snapshot(
            source,
            b"<html><body>materially changed source bytes</body></html>",
            retrieved_at="2026-08-07T12:00:00Z",
            mime_type="text/html",
        )
        self.store.save_snapshot(second)

        self.assertEqual(self.store.approved_source_registry_candidates(), [])
        detail = self.store.source_registry_candidate_detail(
            claimed["source_candidate_id"]
        )
        self.assertEqual(detail["review_status"], "superseded")
        self.assertEqual(
            detail["supersession_reason"],
            "newer parent source bytes were captured",
        )
        self.assertIsNone(
            self.store.claim_source_registry_candidate(
                reviewer_id="admin-next", lease_seconds=60
            )
        )
        with self.store.connection() as conn:
            audit = conn.execute(
                """
                SELECT payload FROM review_audit_events
                WHERE entity_id = %s
                  AND action = 'source_candidate_superseded_lineage'
                """,
                (claimed["source_candidate_id"],),
            ).fetchone()
        self.assertIsNotNone(audit)
        self.assertFalse(audit["payload"]["registry_activation"])

    def test_source_preflight_blocker_prevents_registry_approval(self) -> None:
        registry = load_source_registry(WORKDIR)
        self.store.sync_registry(registry)
        source = registry["sources"][0]
        raw = b"<html><body><a href='/privacy'>Privacy</a></body></html>"
        snapshot = build_source_snapshot(
            source,
            raw,
            retrieved_at="2026-08-06T12:00:00Z",
            mime_type="text/html",
        )
        retrieval_id = self.store.save_snapshot(snapshot)
        links = [
            asdict(link)
            for link in discover_official_links(
                raw,
                mime_type="text/html",
                source_url=source["canonical_url"],
            )
        ]
        self.store.save_source_discovery(
            retrieval={
                "retrieval_id": retrieval_id,
                "snapshot_hash": snapshot["snapshot_hash"],
                "parent_source_id": source["source_id"],
                "program": source["program"],
            },
            parser_version=SOURCE_DISCOVERY_PARSER_VERSION,
            links=links,
        )
        report = self.store.preflight_source_registry_candidates()
        self.assertEqual(report["blocked_candidate_count"], 1)
        self.assertEqual(
            report["blocker_counts"]["navigation_or_boilerplate"], 1
        )
        claimed = self.store.claim_source_registry_candidate(
            reviewer_id="admin-blocked", lease_seconds=60
        )
        self.assertIsNotNone(claimed)
        with self.assertRaisesRegex(
            CorpusDatabaseError, "unresolved deterministic preflight blockers"
        ):
            self.store.record_source_registry_candidate_decision(
                source_candidate_id=claimed["source_candidate_id"],
                reviewer_id="admin-blocked",
                decision="approve_for_registry",
                rationale="attempted approval",
            )
        rejected = self.store.record_source_registry_candidate_decision(
            source_candidate_id=claimed["source_candidate_id"],
            reviewer_id="admin-blocked",
            decision="reject",
            rationale="navigation page is not a rules source",
        )
        self.assertEqual(rejected["review_status"], "rejected")
        self.assertEqual(self.store.approved_source_registry_candidates(), [])

    def test_shadow_export_includes_candidate_id_and_excludes_open_conflicts(self) -> None:
        from psycopg.types.json import Jsonb

        suffix = uuid.uuid4().hex
        snapshot_hash = suffix.ljust(64, "0")
        source_id = f"source_{suffix}"
        retrieval_id = f"retrieval_{suffix}"
        section_id = f"section_{suffix}"
        inference_job_id = f"inference_{suffix}"

        with self.store.connection() as conn:
            conn.execute(
                """
                INSERT INTO official_sources (
                    source_id, registry_version, canonical_url, program, jurisdiction,
                    issuer, source_type, required, official
                ) VALUES (%s, 'test-v1', %s, 'medicaid', %s, 'CMS', 'html', true, true)
                """,
                (source_id, f"https://example.gov/{suffix}", Jsonb({"country": "US"})),
            )
            conn.execute(
                """
                INSERT INTO source_snapshots (
                    snapshot_hash, mime_type, compression, compressed_bytes,
                    uncompressed_size, text_layer_kind
                ) VALUES (%s, 'text/plain', 'zlib', %s, 1, 'native')
                """,
                (snapshot_hash, b"x"),
            )
            conn.execute(
                """
                INSERT INTO source_snapshot_retrievals (
                    retrieval_id, snapshot_hash, source_id, canonical_url,
                    retrieved_at, http_status, issuer
                ) VALUES (%s, %s, %s, %s, now(), 200, 'CMS')
                """,
                (retrieval_id, snapshot_hash, source_id, f"https://example.gov/{suffix}"),
            )
            conn.execute(
                """
                INSERT INTO source_sections (
                    section_id, snapshot_hash, retrieval_id, ordinal, hierarchy_path,
                    normalized_text, normalized_text_hash, parser_name, parser_version
                ) VALUES (%s, %s, %s, 0, '[]'::jsonb, 'x', %s, 'fixture', '1')
                """,
                (section_id, snapshot_hash, retrieval_id, snapshot_hash),
            )
            conn.execute(
                """
                INSERT INTO inference_jobs (
                    inference_job_id, section_id, pass, prompt_version, model_version,
                    schema_version, idempotency_key, status, request_payload
                ) VALUES (
                    %s, %s, 1, 'fixture', 'fixture', 'fixture', %s, 'completed', '{}'::jsonb
                )
                """,
                (inference_job_id, section_id, snapshot_hash),
            )

            draft_ids: list[str] = []
            candidate_ids: list[str] = []
            for label in ("eligible", "conflicted", "superseded"):
                candidate_id = f"candidate_{label}_{suffix}"
                draft_id = f"draft_{label}_{suffix}"
                candidate_ids.append(candidate_id)
                draft_ids.append(draft_id)
                conn.execute(
                    """
                    INSERT INTO grounded_candidates (
                        candidate_id, primary_program, section_id, snapshot_hash,
                        evidence_char_start, evidence_char_end, evidence_byte_start,
                        evidence_byte_end, evidence_quote, evidence_hash,
                        extraction_job_id, extraction_contract_key,
                        critique_contract_key, candidate_payload, grounding_status
                    ) VALUES (
                        %s, 'medicaid', %s, %s, 0, 1, 0, 1, 'x', %s,
                        %s, %s, %s, %s, 'accepted'
                    )
                    """,
                    (
                        candidate_id,
                        section_id,
                        snapshot_hash,
                        snapshot_hash,
                        inference_job_id,
                        CURRENT_EXTRACTION_CONTRACT_KEY,
                        CURRENT_CRITIQUE_CONTRACT_KEY,
                        Jsonb({"candidate_id": candidate_id}),
                    ),
                )
                conn.execute(
                    """
                    INSERT INTO typed_rule_drafts (
                        draft_id, candidate_id, draft_version, canonical_rule,
                        canonical_hash, semantic_fingerprint, scope_fingerprint,
                        outcome_hash, frozen, runtime_eligibility_status
                    ) VALUES (%s, %s, 1, %s, %s, %s, %s, %s, true, 'shadow_only')
                    """,
                    (
                        draft_id,
                        candidate_id,
                        Jsonb({"candidate_id": candidate_id}),
                        snapshot_hash,
                        snapshot_hash,
                        snapshot_hash,
                        snapshot_hash,
                    ),
                )
                for task_type, role in (
                    ("policy_review", "policy_reviewer"),
                    ("legal_verification", "legal_verifier"),
                ):
                    task_id = f"task_{task_type}_{label}_{suffix}"
                    conn.execute(
                        """
                        INSERT INTO reviewer_tasks (task_id, draft_id, task_type, status)
                        VALUES (%s, %s, %s, 'completed')
                        """,
                        (task_id, draft_id, task_type),
                    )
                    conn.execute(
                        """
                        INSERT INTO reviewer_decisions (
                            decision_id, task_id, draft_id, reviewer_id,
                            reviewer_role, decision, draft_hash, rationale
                        ) VALUES (%s, %s, %s, %s, %s, 'approve', %s, 'fixture approval')
                        """,
                        (
                            f"decision_{task_type}_{label}_{suffix}",
                            task_id,
                            draft_id,
                            f"reviewer_{role}_{label}_{suffix}",
                            role,
                            snapshot_hash,
                        ),
                    )

            superseded_rule = {"candidate_id": candidate_ids[2], "version": 2}
            conn.execute(
                """
                INSERT INTO typed_rule_drafts (
                    draft_id, candidate_id, draft_version, canonical_rule,
                    canonical_hash, semantic_fingerprint, scope_fingerprint,
                    outcome_hash, validation_errors, frozen,
                    runtime_eligibility_status
                ) VALUES (%s, %s, 2, %s, %s, %s, %s, %s, %s, false, 'shadow_only')
                """,
                (
                    f"draft_superseded_v2_{suffix}",
                    candidate_ids[2],
                    Jsonb(superseded_rule),
                    canonical_sha256(superseded_rule),
                    snapshot_hash,
                    snapshot_hash,
                    snapshot_hash,
                    Jsonb(["fixture invalid replacement"]),
                ),
            )

            cluster_id = f"cluster_{suffix}"
            conn.execute(
                """
                INSERT INTO duplicate_conflict_clusters (
                    cluster_id, cluster_kind, status, fingerprint
                ) VALUES (%s, 'conflicting_outcome', 'open', %s)
                """,
                (cluster_id, snapshot_hash),
            )
            conn.execute(
                """
                INSERT INTO duplicate_conflict_members (cluster_id, draft_id)
                VALUES (%s, %s)
                """,
                (cluster_id, draft_ids[1]),
            )
            release_id = f"release_{suffix}"
            cohort_hash = canonical_sha256([candidate_ids[0]])
            conn.execute(
                """
                INSERT INTO corpus_release_cohorts (
                    release_id, corpus_target_count, candidate_id, selection_hash,
                    draft_id, draft_hash, snapshot_hash, section_id,
                    source_registry_version, extraction_pipeline_version,
                    extraction_contract_key, critique_contract_key
                ) VALUES (
                    %s, 5100, %s, %s, %s, %s, %s, %s,
                    'test-v1', 'legacy-v1', %s, %s
                )
                """,
                (
                    release_id,
                    candidate_ids[0],
                    cohort_hash,
                    draft_ids[0],
                    snapshot_hash,
                    snapshot_hash,
                    section_id,
                    CURRENT_EXTRACTION_CONTRACT_KEY,
                    CURRENT_CRITIQUE_CONTRACT_KEY,
                ),
            )
            conn.commit()

        exported = self.store.legally_verified_shadow_rules()
        exported_by_id = {item["candidate_id"]: item for item in exported}
        self.assertIn(candidate_ids[0], exported_by_id)
        self.assertNotIn(candidate_ids[1], exported_by_id)
        self.assertNotIn(candidate_ids[2], exported_by_id)
        releasable_ids = {
            item["candidate_id"] for item in self.store.release_candidates()
        }
        self.assertIn(candidate_ids[0], releasable_ids)
        self.assertNotIn(candidate_ids[1], releasable_ids)
        self.assertNotIn(candidate_ids[2], releasable_ids)
        self.assertEqual(
            exported_by_id[candidate_ids[0]]["canonical_rule"]["candidate_id"],
            candidate_ids[0],
        )
        scoped = self.store.legally_verified_shadow_rules(release_id=release_id)
        self.assertEqual([item["candidate_id"] for item in scoped], [candidate_ids[0]])
        cohort = self.store.release_cohort_summary(release_id)
        self.assertEqual(cohort["selection_hash"], cohort_hash)
        self.assertEqual(cohort["candidate_count"], 1)
        self.assertEqual(
            [item["candidate_id"] for item in self.store.release_cohort_candidates(release_id)],
            [candidate_ids[0]],
        )
        self.assertEqual(
            self.store.release_cohort_registry_versions(release_id),
            {"test-v1": 1},
        )
        self.assertEqual(
            self.store.quality_measurements(release_id=release_id)["candidate_count"],
            1,
        )
        self.assertEqual(
            self.store.review_export(release_id=release_id)["release_id"],
            release_id,
        )
        unscoped_review = self.store.review_export()
        self.assertIsNone(unscoped_review["release_id"])
        self.assertFalse(unscoped_review["runtime_activation"])
        self.assertFalse(unscoped_review["proof_binding"])


if __name__ == "__main__":
    unittest.main()
