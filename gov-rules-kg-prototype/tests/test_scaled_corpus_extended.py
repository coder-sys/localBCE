from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import tempfile
import threading
import time
import unittest
from contextlib import nullcontext, redirect_stdout
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import httpx

from gov_rules_kg import main as rules_main
from gov_rules_kg.canonical_rules import canonical_sha256
from gov_rules_kg.claude_inference import (
    CLAUDE_RESPONSE_TOOL_NAME,
    ClaudeGroundedClient,
    ClaudeInferenceError,
    ClaudeUsage,
    _post_with_hard_deadline,
    retry_delay_seconds,
)
from gov_rules_kg.quality_sampling import (
    QUALITY_REVIEW_SCHEMA,
    build_quality_sample_plan,
    merge_quality_review_submissions,
    validate_quality_review_submission,
)
from gov_rules_kg.postgres_corpus import CorpusDatabaseError
from gov_rules_kg.scale_commands import (
    _ecfr_api_url,
    _fetch_official_source,
    _run_job,
    _run_section_extraction_job,
    _run_source_fetch_job,
    _validated_official_source_url,
    claude_infer,
    corpus_progress,
    inference_recover,
    ocr_artifact_ingest,
    sections_extract,
    sources_sync,
    validate_source_preflight_artifact,
)
from gov_rules_kg.scaled_corpus import (
    CLAUDE_MODEL,
    INFERENCE_RESPONSE_CONTRACT_VERSION,
    INFERENCE_SCHEMA,
    RELEVANCE_CLASSIFIER_VERSION,
    SOURCE_CANDIDATE_PREFLIGHT_VERSION,
    all_programs,
    assess_section_relevance,
    assess_source_candidate_preflight,
    assess_source_candidate_preflight_batch,
    build_evidence_span,
    build_inference_launch_plan,
    build_inference_request,
    build_ocr_artifact,
    build_source_registry_release,
    build_source_snapshot,
    build_typed_rule_draft,
    candidate_id,
    load_source_registry,
    prioritize_inference_sections,
    program_quotas,
    restore_ocr_artifact_bytes,
    restore_snapshot_bytes,
    segment_structured_blocks,
    segment_text,
    select_balanced_release_candidates,
    validate_inference_candidates,
    validate_inference_launch_plan,
    validate_source_candidate_preflight_report,
    validate_typed_rule_draft,
)
from gov_rules_kg.source_adapters import discover_official_links, extract_source_text


WORKDIR = Path(__file__).resolve().parents[1]


class _FixtureHttpHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802 - stdlib callback name
        if self.path == "/slow":
            time.sleep(0.5)
        body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass

    def log_message(self, _format: str, *_args: object) -> None:
        return

class ExtendedScaledCorpusTests(unittest.TestCase):
    def source_candidate_preflight_report(self) -> dict:
        candidates = [
            {
                "source_candidate_id": "source-candidate_11111111111111111111111111111111",
                "program": "driver_licenses",
                "candidate_url": "https://dmv.example.gov/driver-licenses",
                "link_text": "Driver licenses",
                "preflight_score": 70,
                "preflight_hash": "a" * 64,
                "scope_mode": "direct_candidate_evidence",
                "review_status": "pending_review",
                "decision_required": "approve_for_registry_or_reject",
                "approval_effect": "inactive_registry_candidate_only",
                "legal_verification": False,
                "runtime_activation": False,
                "proof_binding": False,
            },
            {
                "source_candidate_id": "source-candidate_22222222222222222222222222222222",
                "program": "building_permits",
                "candidate_url": "https://buildings.example.gov/permits",
                "link_text": "Building permits",
                "preflight_score": 60,
                "preflight_hash": "b" * 64,
                "scope_mode": "direct_candidate_evidence",
                "review_status": "claimed_review",
                "decision_required": "approve_for_registry_or_reject",
                "approval_effect": "inactive_registry_candidate_only",
                "legal_verification": False,
                "runtime_activation": False,
                "proof_binding": False,
            },
        ]
        return {
            "schema_version": "localbce-source-candidate-preflight-report-v1",
            "preflight_version": SOURCE_CANDIDATE_PREFLIGHT_VERSION,
            "assessed_candidate_count": 4,
            "unique_program_url_count": 3,
            "duplicate_source_candidate_count": 1,
            "duplicate_source_candidate_group_count": 1,
            "unassessed_candidate_count": 0,
            "eligible_for_human_review_count": 2,
            "blocked_candidate_count": 2,
            "source_review_milestone_target": 5_100,
            "programs_without_program_context_quota_capacity": [
                "driver_licenses",
                "building_permits",
            ],
            "source_capacity_evidence_is_necessary_not_sufficient": True,
            "eligible_program_counts": {
                "building_permits": 1,
                "driver_licenses": 1,
            },
            "eligible_scope_mode_counts": {"direct_candidate_evidence": 2},
            "capacity_blocker_review_candidate_count": len(candidates),
            "capacity_blocker_review_candidates": candidates,
            "capacity_blocker_review_candidates_sha256": canonical_sha256(
                candidates
            ),
            "human_review_required": True,
            "automatic_registry_activation": False,
            "runtime_activation": False,
            "proof_binding": False,
        }

    def section(self, text: str | None = None) -> dict:
        return segment_text(
            "a" * 64,
            text
            or "Section 1\nA person is eligible when income is at or below 100 percent.",
            parser_name="fixture",
            parser_version="2",
            extraction_pipeline_version="fixture-pipeline-v1",
        )[0]

    def candidate(self, section: dict | None = None) -> dict:
        selected = section or self.section()
        start = selected["normalized_text"].index("A person")
        evidence = build_evidence_span(
            selected, start, len(selected["normalized_text"])
        )
        return {
            "program": "medicaid",
            "authority": {"issuer": "CMS", "citation": "42 CFR 435"},
            "rule_type": "eligibility_rule",
            "conditions": {
                "op": "compare",
                "fact": "income",
                "fact_type": "decimal",
                "operator": "lte",
                "value": {"type": "decimal", "value": "100"},
            },
            "outcome": {"kind": "decision", "code": "eligible"},
            "effective_from": "2026-01-01",
            "effective_through": None,
            "exceptions": [],
            "evidence": evidence,
        }

    def anthropic_response(
        self, result: dict, *, stop_reason: str = "tool_use"
    ) -> tuple[dict, dict[str, str]]:
        return (
            {
                "model": CLAUDE_MODEL,
                "stop_reason": stop_reason,
                "usage": {"input_tokens": 11, "output_tokens": 7},
                "content": [
                    {
                        "type": "tool_use",
                        "name": CLAUDE_RESPONSE_TOOL_NAME,
                        "input": result,
                    }
                ],
            },
            {"request-id": "request-fixture"},
        )

    def test_claude_infer_cli_preserves_bounded_run_options(self) -> None:
        argv = [
            "gov-rules-kg",
            "--workdir",
            str(WORKDIR),
            "claude-infer",
            "--limit",
            "4096",
            "--concurrency",
            "8",
            "--batch-size",
            "512",
            "--result-detail-limit",
            "64",
            "--drain-existing",
            "--timeout-seconds",
            "240",
        ]
        with (
            patch("sys.argv", argv),
            patch.object(rules_main, "PostgresCorpusStore", return_value=object()),
            patch.object(
                rules_main, "claude_infer", return_value={"status": "ok"}
            ) as infer,
            redirect_stdout(io.StringIO()),
        ):
            rules_main.main()
        infer.assert_called_once_with(
            WORKDIR.resolve(),
            unittest.mock.ANY,
            limit=4096,
            concurrency=8,
            batch_size=512,
            result_detail_limit=64,
            retry_failed=False,
            retry_limit=0,
            drain_existing=True,
            timeout_seconds=240.0,
        )

    def test_inference_recover_cli_is_credential_free_and_explicit(self) -> None:
        argv = [
            "gov-rules-kg",
            "--workdir",
            str(WORKDIR),
            "inference-recover",
            "--retry-failed",
            "--retry-limit",
            "11",
            "--batch-size",
            "128",
        ]
        with (
            patch("sys.argv", argv),
            patch.object(rules_main, "PostgresCorpusStore", return_value=object()),
            patch.object(
                rules_main,
                "inference_recover",
                return_value={"runtime_activation": False},
            ) as recover,
            redirect_stdout(io.StringIO()),
        ):
            rules_main.main()
        recover.assert_called_once_with(
            WORKDIR.resolve(),
            unittest.mock.ANY,
            retry_failed=True,
            retry_limit=11,
            batch_size=128,
        )

    def test_sections_extract_cli_passes_only_section_worker_options(self) -> None:
        argv = [
            "gov-rules-kg",
            "--workdir",
            str(WORKDIR),
            "sections-extract",
            "--limit",
            "17",
            "--concurrency",
            "3",
            "--retry-failed",
            "--retry-limit",
            "2",
        ]
        with (
            patch("sys.argv", argv),
            patch.object(rules_main, "PostgresCorpusStore", return_value=object()),
            patch.object(
                rules_main, "sections_extract", return_value={"status": "ok"}
            ) as extract,
            redirect_stdout(io.StringIO()),
        ):
            rules_main.main()
        extract.assert_called_once_with(
            WORKDIR.resolve(),
            unittest.mock.ANY,
            limit=17,
            concurrency=3,
            retry_failed=True,
            retry_limit=2,
        )

    def test_source_sync_rejects_ambiguous_capture_and_retry_options(self) -> None:
        with self.assertRaisesRegex(ValueError, "require --fetch"):
            sources_sync(
                WORKDIR,
                object(),
                fetch=False,
                limit=0,
                timeout_seconds=10,
                capture_id="fixture",
            )
        with self.assertRaisesRegex(ValueError, "positive"):
            sources_sync(
                WORKDIR,
                object(),
                fetch=True,
                limit=0,
                timeout_seconds=10,
                retry_failed=True,
                retry_limit=0,
            )

    def test_sections_extract_rejects_ambiguous_retry_options(self) -> None:
        with self.assertRaisesRegex(ValueError, "positive"):
            sections_extract(
                WORKDIR,
                object(),
                limit=0,
                retry_failed=True,
                retry_limit=0,
            )
        with self.assertRaisesRegex(ValueError, "requires"):
            sections_extract(
                WORKDIR,
                object(),
                limit=0,
                retry_failed=False,
                retry_limit=1,
            )

    def test_claude_infer_pages_large_runs_and_caps_result_details(self) -> None:
        sections = [
            {
                **segment_text(
                    f"{index:064x}",
                    f"Applicants must file official application {index}.",
                    parser_name="fixture",
                    extraction_pipeline_version="fixture-pipeline-v1",
                )[0],
                "program": "medicaid",
                "relevance_decision_id": f"relevance-{index}",
                "relevant": True,
            }
            for index in range(5)
        ]

        class FakeStore:
            def inference_run_lock(self):
                return nullcontext()

            def __init__(self) -> None:
                self.sections = {item["section_id"]: item for item in sections}
                self.remaining = list(sections)
                self.jobs: list[dict] = []
                self.page_sizes: list[int] = []

            def retry_failed_inference_jobs(self, **_kwargs):
                return 0

            def uninferred_sections(self, *, limit):
                self.page_sizes.append(limit)
                page = self.remaining[:limit]
                self.remaining = self.remaining[limit:]
                return page

            def save_relevance_decision(self, _decision):
                raise AssertionError("fixture relevance is already persisted")

            def enqueue_inference(self, request):
                self.jobs.append(
                    {
                        "inference_job_id": "job-" + request["section"]["section_id"],
                        "request_payload": request,
                        "attempts": 1,
                        "attempt_limit": 5,
                    }
                )

            def claim_inference_jobs(self, _worker_id, *, limit, lease_seconds):
                self.lease_seconds = lease_seconds
                jobs = self.jobs[:limit]
                self.jobs = self.jobs[limit:]
                return jobs

            def section(self, section_id):
                return self.sections[section_id]

            def commit_inference_result(self, *_args, **_kwargs):
                return 0

            def fail_inference_job(self, *_args, **_kwargs):
                raise AssertionError("successful fixture must not fail")

            def renew_inference_lease(self, *_args, **_kwargs):
                return None

            def pending_critique_sections(self, *, limit):
                return []

            def materialize_review_drafts(self, *, limit):
                return {
                    "candidates_processed": 0,
                    "drafts_created": 0,
                    "drafts_blocked": 0,
                    "policy_tasks_created": 0,
                    "clusters_created": 0,
                }

            def inference_queue_summary(self):
                return {
                    "schema_version": "localbce-inference-queue-summary-v1",
                    "groups": [],
                    "job_count": 0,
                    "pending_or_leased": 0,
                    "failed": 0,
                    "completed": 5,
                    "runtime_activation": False,
                    "proof_binding": False,
                }

        class FakeClient:
            model = CLAUDE_MODEL

            def __init__(self, **_kwargs):
                pass

            def infer(self, *_args, **_kwargs):
                return (
                    {"candidates": []},
                    SimpleNamespace(
                        input_tokens=2,
                        output_tokens=3,
                        model=CLAUDE_MODEL,
                        request_id="request-fixture",
                    ),
                )

        store = FakeStore()
        with tempfile.TemporaryDirectory() as directory, patch(
            "gov_rules_kg.scale_commands.ClaudeGroundedClient", FakeClient
        ):
            report = claude_infer(
                Path(directory),
                store,
                limit=5,
                concurrency=2,
                batch_size=2,
                result_detail_limit=2,
            )
        self.assertEqual(store.page_sizes, [2, 2, 1])
        self.assertEqual(report["sections_considered"], 5)
        self.assertEqual(report["claimed_job_attempts"], 5)
        self.assertEqual(report["result_count"], 5)
        self.assertEqual(len(report["results"]), 2)
        self.assertEqual(report["result_details_truncated"], 3)
        self.assertEqual(report["usage"]["input_tokens"], 10)
        self.assertFalse(report["runtime_activation"])

    def test_claude_infer_can_drain_existing_jobs_without_discovery(self) -> None:
        section = self.section()
        request = build_inference_request(section, "medicaid", pass_number=1)

        class FakeStore:
            def inference_run_lock(self):
                return nullcontext()

            def __init__(self) -> None:
                self.jobs = [
                    {
                        "inference_job_id": "job-existing",
                        "request_payload": request,
                        "attempts": 1,
                        "attempt_limit": 5,
                    }
                ]

            def retry_failed_inference_jobs(self, **_kwargs):
                return 0

            def uninferred_sections(self, **_kwargs):
                raise AssertionError("drain mode must not discover sections")

            def claim_inference_jobs(self, _worker_id, *, limit, lease_seconds):
                jobs = self.jobs[:limit]
                self.jobs = self.jobs[limit:]
                return jobs

            def section(self, _section_id):
                return section

            def renew_inference_lease(self, *_args, **_kwargs):
                return None

            def commit_inference_result(self, *_args, **_kwargs):
                return 0

            def fail_inference_job(self, *_args, **_kwargs):
                raise AssertionError("successful fixture must not fail")

            def pending_critique_sections(self, *, limit):
                return []

            def materialize_review_drafts(self, *, limit):
                return {
                    "candidates_processed": 0,
                    "drafts_created": 0,
                    "drafts_blocked": 0,
                    "policy_tasks_created": 0,
                    "clusters_created": 0,
                }

            def inference_queue_summary(self):
                return {"groups": [], "job_count": 1, "pending_or_leased": 0}

        class FakeClient:
            model = CLAUDE_MODEL

            def __init__(self, **_kwargs):
                pass

            def infer(self, *_args, **_kwargs):
                return (
                    {"candidates": []},
                    ClaudeUsage(2, 3, CLAUDE_MODEL, "request-existing"),
                )

        with tempfile.TemporaryDirectory() as directory, patch(
            "gov_rules_kg.scale_commands.ClaudeGroundedClient", FakeClient
        ):
            report = claude_infer(
                Path(directory),
                FakeStore(),
                limit=1,
                concurrency=1,
                batch_size=1,
                drain_existing=True,
            )
        self.assertTrue(report["drain_existing"])
        self.assertEqual(report["sections_considered"], 0)
        self.assertEqual(report["claimed_job_attempts"], 1)
        self.assertEqual(report["timeout_seconds"], 300.0)

    def test_claude_infer_drain_enqueues_critique_without_spending_attempt(self) -> None:
        section = self.section()
        request = build_inference_request(section, "medicaid", pass_number=1)
        proposed_candidate = self.candidate(section)

        class FakeStore:
            def inference_run_lock(self):
                return nullcontext()

            def __init__(self) -> None:
                self.jobs = [
                    {
                        "inference_job_id": "job-existing-extraction",
                        "request_payload": request,
                        "attempts": 1,
                        "attempt_limit": 5,
                    }
                ]
                self.extraction_completed = False
                self.critique_enqueued = False
                self.enqueued_requests: list[dict] = []

            def retry_failed_inference_jobs(self, **_kwargs):
                return 0

            def uninferred_sections(self, **_kwargs):
                raise AssertionError("drain mode must not discover sections")

            def claim_inference_jobs(self, _worker_id, *, limit, lease_seconds):
                jobs = self.jobs[:limit]
                self.jobs = self.jobs[limit:]
                return jobs

            def section(self, _section_id):
                return section

            def renew_inference_lease(self, *_args, **_kwargs):
                return None

            def commit_inference_result(self, *_args, **_kwargs):
                self.extraction_completed = True
                return 1

            def fail_inference_job(self, *_args, **_kwargs):
                raise AssertionError("successful fixture must not fail")

            def pending_critique_sections(self, *, limit):
                if (
                    self.extraction_completed
                    and not self.critique_enqueued
                    and limit > 0
                ):
                    return [
                        {
                            **section,
                            "program": "medicaid",
                            "proposed_candidates": [proposed_candidate],
                        }
                    ]
                return []

            def enqueue_inference(self, critique_request):
                self.critique_enqueued = True
                self.enqueued_requests.append(critique_request)

            def materialize_review_drafts(self, *, limit):
                return {
                    "candidates_processed": 0,
                    "drafts_created": 0,
                    "drafts_blocked": 0,
                    "policy_tasks_created": 0,
                    "clusters_created": 0,
                }

            def inference_queue_summary(self):
                return {"groups": [], "job_count": 2, "pending_or_leased": 1}

        class FakeClient:
            model = CLAUDE_MODEL

            def __init__(self, **_kwargs):
                pass

            def infer(self, *_args, **_kwargs):
                return (
                    {"candidates": [proposed_candidate]},
                    ClaudeUsage(2, 3, CLAUDE_MODEL, "request-existing"),
                )

        store = FakeStore()
        with tempfile.TemporaryDirectory() as directory, patch(
            "gov_rules_kg.scale_commands.ClaudeGroundedClient", FakeClient
        ):
            report = claude_infer(
                Path(directory),
                store,
                limit=1,
                concurrency=1,
                batch_size=1,
                drain_existing=True,
            )

        self.assertEqual(report["claimed_job_attempts"], 1)
        self.assertEqual(report["critique_enqueued"], 1)
        self.assertEqual(len(store.enqueued_requests), 1)
        self.assertEqual(store.enqueued_requests[0]["pass"], 2)

    def test_inference_recover_enqueues_pending_critiques_without_credentials(self) -> None:
        section = self.section()
        proposed_candidate = self.candidate(section)

        class FakeStore:
            def __init__(self) -> None:
                self.enqueued_requests: list[dict] = []

            def recover_expired_inference_leases(self):
                return {
                    "requeued": 0,
                    "failed_at_attempt_limit": 0,
                    "remaining_expired_leases": 0,
                }

            def pending_critique_sections(self, *, limit):
                if self.enqueued_requests or limit <= 0:
                    return []
                return [
                    {
                        **section,
                        "program": "medicaid",
                        "proposed_candidates": [proposed_candidate],
                    }
                ]

            def enqueue_inference(self, critique_request):
                self.enqueued_requests.append(critique_request)

            def materialize_review_drafts(self, *, limit):
                return {
                    "candidates_processed": 0,
                    "drafts_created": 0,
                    "drafts_blocked": 0,
                    "policy_tasks_created": 0,
                    "clusters_created": 0,
                }

            def inference_failure_report(self, *, limit):
                return {
                    "failed": 0,
                    "rejected": 0,
                    "current_retryable_failed": 0,
                }

            def inference_queue_summary(self):
                return {"groups": [], "job_count": 1, "pending_or_leased": 1}

        store = FakeStore()
        with tempfile.TemporaryDirectory() as directory:
            report = inference_recover(Path(directory), store, batch_size=32)

        self.assertEqual(report["critique_enqueued"], 1)
        self.assertEqual(len(store.enqueued_requests), 1)
        self.assertEqual(store.enqueued_requests[0]["pass"], 2)
        self.assertFalse(report["runtime_activation"])
        self.assertFalse(report["proof_binding"])

    def test_claude_infer_replenishes_completed_worker_slots(self) -> None:
        section = self.section()
        request = build_inference_request(section, "medicaid", pass_number=1)

        class FakeStore:
            def inference_run_lock(self):
                return nullcontext()

            def __init__(self) -> None:
                self.jobs = [
                    {
                        "inference_job_id": job_id,
                        "request_payload": request,
                        "attempts": 1,
                        "attempt_limit": 5,
                    }
                    for job_id in ("job-slow", "job-fast", "job-replacement")
                ]
                self.lock = threading.Lock()
                self.replacement_claimed = threading.Event()

            def retry_failed_inference_jobs(self, **_kwargs):
                return 0

            def claim_inference_jobs(self, _worker_id, *, limit, lease_seconds):
                with self.lock:
                    jobs = self.jobs[:limit]
                    self.jobs = self.jobs[limit:]
                if any(
                    job["inference_job_id"] == "job-replacement" for job in jobs
                ):
                    self.replacement_claimed.set()
                return jobs

            def pending_critique_sections(self, *, limit):
                return []

            def materialize_review_drafts(self, *, limit):
                return {
                    "candidates_processed": 0,
                    "drafts_created": 0,
                    "drafts_blocked": 0,
                    "policy_tasks_created": 0,
                    "clusters_created": 0,
                }

            def inference_queue_summary(self):
                return {"groups": [], "job_count": 3, "pending_or_leased": 0}

        class FakeClient:
            model = CLAUDE_MODEL

            def __init__(self, **_kwargs):
                pass

        store = FakeStore()

        def run_job(_store, _client, _worker_id, job):
            if job["inference_job_id"] == "job-slow":
                if not store.replacement_claimed.wait(timeout=2):
                    raise AssertionError(
                        "a completed worker slot was not replenished while another job ran"
                    )
            return {
                "job_id": job["inference_job_id"],
                "status": "completed",
                "attempt": 1,
                "input_tokens": 0,
                "output_tokens": 0,
            }

        with tempfile.TemporaryDirectory() as directory, patch(
            "gov_rules_kg.scale_commands.ClaudeGroundedClient", FakeClient
        ), patch("gov_rules_kg.scale_commands._run_job", run_job):
            report = claude_infer(
                Path(directory),
                store,
                limit=3,
                concurrency=2,
                batch_size=3,
                drain_existing=True,
            )

        self.assertTrue(store.replacement_claimed.is_set())
        self.assertEqual(report["claimed_job_attempts"], 3)
        self.assertEqual(report["completed"], 3)

    def test_claude_infer_drain_limit_counts_retryable_failed_attempts(self) -> None:
        section = self.section()
        request = build_inference_request(section, "medicaid", pass_number=1)

        class FakeStore:
            def inference_run_lock(self):
                return nullcontext()

            def __init__(self) -> None:
                self.claim_calls = 0
                self.failure_calls = 0
                self.job = {
                    "inference_job_id": "job-retryable",
                    "request_payload": request,
                    "attempts": 1,
                    "attempt_limit": 5,
                }

            def retry_failed_inference_jobs(self, **_kwargs):
                return 0

            def claim_inference_jobs(self, _worker_id, *, limit, lease_seconds):
                self.claim_calls += 1
                return [self.job][:limit]

            def section(self, _section_id):
                return section

            def renew_inference_lease(self, *_args, **_kwargs):
                return None

            def fail_inference_job(self, *_args, **_kwargs):
                self.failure_calls += 1

            def pending_critique_sections(self, *, limit):
                return []

            def materialize_review_drafts(self, *, limit):
                return {
                    "candidates_processed": 0,
                    "drafts_created": 0,
                    "drafts_blocked": 0,
                    "policy_tasks_created": 0,
                    "clusters_created": 0,
                }

            def inference_queue_summary(self):
                return {"groups": [], "job_count": 1, "pending_or_leased": 1}

        class FailingClient:
            model = CLAUDE_MODEL

            def __init__(self, **_kwargs):
                pass

            def infer(self, *_args, **_kwargs):
                raise ClaudeInferenceError("fixture timeout", retryable=True)

        store = FakeStore()
        with tempfile.TemporaryDirectory() as directory, patch(
            "gov_rules_kg.scale_commands.ClaudeGroundedClient", FailingClient
        ):
            report = claude_infer(
                Path(directory),
                store,
                limit=1,
                concurrency=1,
                batch_size=1,
                drain_existing=True,
            )
        self.assertEqual(store.claim_calls, 1)
        self.assertEqual(store.failure_calls, 1)
        self.assertEqual(report["claimed_job_attempts"], 1)
        self.assertTrue(report["results"][0]["retry_scheduled"])

    def test_claude_infer_rejects_ambiguous_scale_options(self) -> None:
        for options, message in (
            ({"limit": 0}, "limit"),
            ({"concurrency": 0}, "concurrency"),
            ({"batch_size": 0}, "batch size"),
            ({"result_detail_limit": -1}, "detail limit"),
            ({"retry_failed": True, "retry_limit": 0}, "positive"),
            ({"retry_failed": False, "retry_limit": 1}, "requires"),
            ({"timeout_seconds": 0}, "timeout"),
            ({"timeout_seconds": 901}, "timeout"),
        ):
            arguments = {
                "limit": 8,
                "concurrency": 8,
                "batch_size": 256,
                "result_detail_limit": 1000,
                "retry_failed": False,
                "retry_limit": 0,
                **options,
            }
            with self.subTest(arguments=arguments):
                with self.assertRaisesRegex(ValueError, message):
                    claude_infer(WORKDIR, object(), **arguments)

    def test_claude_usage_and_request_id_are_accounted(self) -> None:
        section = self.section()
        candidate = self.candidate(section)
        response = {
            "schema_version": INFERENCE_SCHEMA,
            "pass": 1,
            "candidates": [candidate],
        }
        client = ClaudeGroundedClient(
            api_key="fixture", transport=lambda _body: self.anthropic_response(response)
        )
        result, usage = client.infer(section, "medicaid", pass_number=1)
        self.assertEqual(result["candidates"][0]["program"], "medicaid")
        self.assertEqual(usage.input_tokens, 11)
        self.assertEqual(usage.output_tokens, 7)
        self.assertEqual(usage.request_id, "request-fixture")

    def test_claude_filters_invalid_extraction_candidate_with_audit_reason(self) -> None:
        section = self.section()
        valid = self.candidate(section)
        invalid = copy.deepcopy(valid)
        invalid["rule_type"] = "invented_rule_type"
        response = {
            "schema_version": INFERENCE_SCHEMA,
            "pass": 1,
            "candidates": [valid, invalid],
        }
        client = ClaudeGroundedClient(
            api_key="fixture", transport=lambda _body: self.anthropic_response(response)
        )
        result, _usage = client.infer(section, "medicaid", pass_number=1)
        self.assertEqual(result["candidates"], [valid])
        self.assertEqual(len(result["local_rejections"]), 1)
        self.assertEqual(
            result["local_rejections"][0]["candidate_index"],
            1,
        )
        self.assertTrue(
            any(
                "rule_type is unsupported" in error
                for error in result["local_rejections"][0]["errors"]
            )
        )

    def test_claude_rejects_unusable_repairs_without_discarding_sibling_critique(self) -> None:
        section = self.section()
        first = self.candidate(section)
        second = copy.deepcopy(first)
        second["outcome"]["code"] = "conditionally_eligible"
        third = copy.deepcopy(first)
        third["outcome"]["code"] = "ineligible"
        proposed = []
        for candidate in (first, second, third):
            proposed.append(
                {**candidate, "candidate_id": candidate_id(section, candidate)}
            )
        response = {
            "schema_version": INFERENCE_SCHEMA,
            "pass": 2,
            "candidates": [
                {
                    "candidate_id": proposed[0]["candidate_id"],
                    "critique": {
                        "result": "repair",
                        "findings": ["claimed repair"],
                        "repaired_candidate": copy.deepcopy(first),
                    },
                },
                {
                    "candidate_id": proposed[1]["candidate_id"],
                    "critique": {"result": "accept", "findings": []},
                },
                {
                    "candidate_id": proposed[2]["candidate_id"],
                    "critique": {
                        "result": "repair",
                        "findings": ["repair omitted"],
                    },
                },
            ],
        }
        client = ClaudeGroundedClient(
            api_key="fixture", transport=lambda _body: self.anthropic_response(response)
        )
        result, _usage = client.infer(
            section,
            "medicaid",
            pass_number=2,
            proposed_candidates=proposed,
        )
        self.assertEqual(result["candidates"][0]["critique"]["result"], "reject")
        self.assertEqual(result["candidates"][1]["critique"]["result"], "accept")
        self.assertEqual(result["candidates"][2]["critique"]["result"], "reject")
        self.assertIn(
            "local_validation:no_op_repair",
            result["candidates"][0]["critique"]["findings"],
        )
        self.assertNotIn(
            "repaired_candidate", result["candidates"][0]["critique"]
        )
        self.assertIn(
            "local_validation:missing_repaired_candidate",
            result["candidates"][2]["critique"]["findings"],
        )

    def test_claude_recovers_unique_exact_quote_and_rejects_truncation(self) -> None:
        section = self.section()
        candidate = self.candidate(section)
        candidate["evidence"] = {
            "char_start": 0,
            "char_end": 1,
            "quote": candidate["evidence"]["quote"],
        }
        response = {
            "schema_version": INFERENCE_SCHEMA,
            "pass": 1,
            "candidates": [candidate],
        }
        client = ClaudeGroundedClient(
            api_key="fixture", transport=lambda _body: self.anthropic_response(response)
        )
        result, _usage = client.infer(section, "medicaid", pass_number=1)
        evidence = result["candidates"][0]["evidence"]
        self.assertEqual(evidence["quote"], self.candidate(section)["evidence"]["quote"])
        self.assertGreater(evidence["char_start"], 0)

        truncated = ClaudeGroundedClient(
            api_key="fixture",
            transport=lambda _body: self.anthropic_response(
                response, stop_reason="max_tokens"
            ),
        )
        with self.assertRaisesRegex(ClaudeInferenceError, "tool_use"):
            truncated.infer(section, "medicaid", pass_number=1)

    def test_claude_request_has_hard_wall_clock_timeout(self) -> None:
        client = ClaudeGroundedClient(
            api_key="fixture", timeout_seconds=0.01, max_retries=5
        )
        started = time.monotonic()
        with patch(
            "gov_rules_kg.claude_inference._post_with_hard_deadline",
            side_effect=TimeoutError("fixture deadline"),
        ) as post:
            with self.assertRaises(ClaudeInferenceError) as raised:
                client._send({})
        self.assertTrue(raised.exception.retryable)
        post.assert_called_once()
        self.assertLess(time.monotonic() - started, 0.5)

        server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHttpHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with self.assertRaises(TimeoutError):
                _post_with_hard_deadline(
                    f"http://127.0.0.1:{server.server_port}/slow",
                    headers={},
                    body={},
                    timeout_seconds=0.05,
                )
            response = _post_with_hard_deadline(
                f"http://127.0.0.1:{server.server_port}/ok",
                headers={},
                body={},
                timeout_seconds=15,
            )
            self.assertEqual(response["status_code"], 200)
        finally:
            server.shutdown()
            thread.join()
            server.server_close()

    def test_retry_after_supports_seconds_and_http_dates(self) -> None:
        now = datetime(2026, 8, 6, 12, 0, tzinfo=timezone.utc)
        self.assertEqual(retry_delay_seconds("7.5", attempt=1, now=now), 7.5)
        future = now + timedelta(seconds=30)
        self.assertEqual(
            retry_delay_seconds(
                future.strftime("%a, %d %b %Y %H:%M:%S GMT"),
                attempt=1,
                now=now,
            ),
            30.0,
        )
        self.assertEqual(retry_delay_seconds("invalid", attempt=3, now=now), 8.0)

    def test_inference_worker_accounts_rejected_usage_without_retrying(self) -> None:
        section = self.section()
        job = {
            "inference_job_id": "job-rejected",
            "request_payload": build_inference_request(
                section, "medicaid", pass_number=1
            ),
            "attempts": 1,
            "attempt_limit": 5,
        }

        class Client:
            def infer(self, *_args, **_kwargs):
                raise ClaudeInferenceError(
                    "deterministic rejection",
                    response_rejected=True,
                    usage=ClaudeUsage(11, 7, CLAUDE_MODEL, "request-rejected"),
                )

        class Store:
            def __init__(self) -> None:
                self.failure_kwargs = None

            def section(self, _section_id):
                return section

            def renew_inference_lease(self, *_args, **_kwargs):
                return None

            def fail_inference_job(self, *_args, **kwargs):
                self.failure_kwargs = kwargs

        store = Store()
        result = _run_job(store, Client(), "worker", job)
        self.assertEqual(result["status"], "rejected")
        self.assertFalse(result["retry_scheduled"])
        self.assertEqual(store.failure_kwargs["input_tokens"], 11)
        self.assertTrue(store.failure_kwargs["rejected"])

    def test_inference_worker_renews_lease_and_fails_closed_on_lease_loss(self) -> None:
        section = self.section()
        job = {
            "inference_job_id": "job-lease",
            "request_payload": build_inference_request(
                section, "medicaid", pass_number=1
            ),
            "attempts": 1,
            "attempt_limit": 5,
        }

        class Client:
            def infer(self, *_args, **_kwargs):
                time.sleep(0.03)
                return (
                    {"schema_version": INFERENCE_SCHEMA, "pass": 1, "candidates": []},
                    ClaudeUsage(1, 1, CLAUDE_MODEL, "request-lease"),
                )

        class Store:
            def __init__(self, lose: bool) -> None:
                self.lose = lose
                self.renewals = 0
                self.committed = False
                self.failed = False

            def section(self, _section_id):
                return section

            def renew_inference_lease(self, *_args, **_kwargs):
                self.renewals += 1
                if self.lose:
                    raise CorpusDatabaseError("fixture lease lost")

            def commit_inference_result(self, *_args, **_kwargs):
                self.committed = True
                return 0

            def fail_inference_job(self, *_args, **_kwargs):
                self.failed = True

        with patch("gov_rules_kg.scale_commands.INFERENCE_HEARTBEAT_SECONDS", 0.01):
            healthy = Store(False)
            completed = _run_job(healthy, Client(), "worker", job)
            lost = Store(True)
            failed = _run_job(lost, Client(), "worker", job)
        self.assertEqual(completed["status"], "completed")
        self.assertTrue(healthy.committed)
        self.assertGreaterEqual(healthy.renewals, 1)
        self.assertEqual(failed["status"], "failed")
        self.assertFalse(lost.committed)
        self.assertTrue(lost.failed)

    def test_corpus_progress_writes_nonbinding_milestone_report(self) -> None:
        class Store:
            def corpus_scale_progress(self, target_count):
                return {
                    "schema_version": "localbce-rules-corpus-progress-v1",
                    "target_count": target_count,
                    "program_count": 51,
                    "accepted_grounded_candidates": 0,
                    "deterministic_candidates": 0,
                    "milestone_candidate_ready": False,
                    "runtime_activation": False,
                    "proof_binding": False,
                    "production_usable": False,
                }

        with tempfile.TemporaryDirectory() as directory:
            report = corpus_progress(Path(directory), Store(), target_count=5_100)
            self.assertTrue(Path(report["report"]).is_file())
        self.assertFalse(report["runtime_activation"])
        self.assertFalse(report["proof_binding"])

    def test_inference_launch_plan_is_hash_pinned_and_fail_closed(self) -> None:
        registry = load_source_registry(WORKDIR)
        programs = [
            {"program": program, "active_section_count": 1}
            for program in all_programs()
        ]
        progress = {
            "program_count": 51,
            "programs": programs,
            "programs_without_source_capture": [],
            "programs_without_active_sections": [],
            "blocking_queue_failures": {},
            "accepted_grounded_candidates": 0,
            "deterministic_candidates": 0,
            "milestone_candidate_ready": False,
        }
        preflight = {
            "preflight_version": SOURCE_CANDIDATE_PREFLIGHT_VERSION,
            "assessed_candidate_count": 1,
            "unassessed_candidate_count": 0,
            "eligible_for_human_review_count": 1,
            "blocked_candidate_count": 0,
        }
        plan = build_inference_launch_plan(
            target_count=5_100,
            registry=registry,
            progress=progress,
            preflight=preflight,
            metrics={"table_counts": {"source_snapshots": 1, "source_sections": 51}},
            credential_configured=True,
        )
        validate_inference_launch_plan(plan)
        self.assertTrue(plan["launch_ready"])
        self.assertFalse(plan["runtime_activation"])
        tampered = {**plan, "model": "unpinned"}
        with self.assertRaisesRegex(ValueError, "hash mismatch|not pinned"):
            validate_inference_launch_plan(tampered)

    def test_relevance_filter_is_deterministic_and_recall_oriented(self) -> None:
        relevant = self.section("42 CFR 1\nAn applicant must file within 30 days.")
        left = assess_section_relevance(relevant)
        self.assertEqual(left, assess_section_relevance(copy.deepcopy(relevant)))
        self.assertTrue(left["relevant"])
        self.assertEqual(left["classifier_version"], RELEVANCE_CLASSIFIER_VERSION)
        boilerplate = self.section("Skip to main content\nPrivacy policy\nFollow us on social media")
        self.assertFalse(assess_section_relevance(boilerplate)["relevant"])

    def test_inference_rejects_program_without_source_lineage(self) -> None:
        section = {**self.section(), "programs": ["medicaid"]}
        candidate = self.candidate(section)
        candidate["program"] = "snap"
        errors = validate_inference_candidates(
            section,
            {"schema_version": INFERENCE_SCHEMA, "pass": 1, "candidates": [candidate]},
            expected_pass=1,
        )
        self.assertTrue(any("not linked" in error for error in errors))

    def test_inference_response_rejects_more_than_twenty_five_candidates(self) -> None:
        response = {
            "schema_version": INFERENCE_SCHEMA,
            "pass": 1,
            "candidates": [self.candidate() for _ in range(26)],
        }
        self.assertIn(
            "inference response exceeds the 25-candidate limit",
            validate_inference_candidates(self.section(), response, expected_pass=1),
        )

    def test_inference_response_rejects_noncanonical_typed_mapping(self) -> None:
        candidate = self.candidate()
        candidate["conditions"] = {"op": "free_text", "text": "must qualify"}
        candidate["outcome"] = {"action": "approve"}
        errors = validate_inference_candidates(
            self.section(),
            {"schema_version": INFERENCE_SCHEMA, "pass": 1, "candidates": [candidate]},
            expected_pass=1,
        )
        self.assertTrue(any("conditions.op is unsupported" in error for error in errors))
        self.assertTrue(any("outcome.kind is unsupported" in error for error in errors))

    def test_inference_preserves_missing_date_as_blocked_discovery_data(self) -> None:
        section = self.section()
        candidate = self.candidate(section)
        candidate["effective_from"] = None
        candidate["effective_through"] = "2027-12-31"
        response = {
            "schema_version": INFERENCE_SCHEMA,
            "pass": 1,
            "candidates": [candidate],
        }
        self.assertEqual(validate_inference_candidates(section, response, expected_pass=1), [])
        record = {
            "candidate_id": candidate_id(section, candidate),
            "primary_program": "medicaid",
            "section_id": section["section_id"],
            "snapshot_hash": section["snapshot_hash"],
            "evidence_char_start": candidate["evidence"]["char_start"],
            "evidence_char_end": candidate["evidence"]["char_end"],
            "evidence_byte_start": candidate["evidence"]["byte_start"],
            "evidence_byte_end": candidate["evidence"]["byte_end"],
            "evidence_quote": candidate["evidence"]["quote"],
            "evidence_hash": candidate["evidence"]["evidence_hash"],
            "candidate_payload": candidate,
            "canonical_url": "https://www.ecfr.gov/current/title-42",
        }
        self.assertIn(
            "effective_from is required",
            validate_typed_rule_draft(build_typed_rule_draft(record)),
        )

    def test_critique_response_validates_without_pass_one_fields(self) -> None:
        candidate = self.candidate()
        identifier = candidate_id(self.section(), candidate)
        critique = {
            "schema_version": INFERENCE_SCHEMA,
            "pass": 2,
            "candidates": [
                {
                    "candidate_id": identifier,
                    "critique": {"result": "accept", "findings": []},
                }
            ],
        }
        self.assertEqual(
            validate_inference_candidates(self.section(), critique, expected_pass=2),
            [],
        )

    def test_repair_critique_requires_a_valid_repaired_candidate(self) -> None:
        section = self.section()
        candidate = self.candidate(section)
        identifier = candidate_id(section, candidate)
        repaired = copy.deepcopy(candidate)
        repaired["outcome"]["code"] = "conditionally_eligible"
        response = {
            "schema_version": INFERENCE_SCHEMA,
            "pass": 2,
            "candidates": [
                {
                    "candidate_id": identifier,
                    "critique": {
                        "result": "repair",
                        "findings": ["outcome correction"],
                        "repaired_candidate": repaired,
                    },
                }
            ],
        }
        self.assertEqual(validate_inference_candidates(section, response, expected_pass=2), [])
        del response["candidates"][0]["critique"]["repaired_candidate"]
        self.assertTrue(
            any(
                "requires repaired_candidate" in error
                for error in validate_inference_candidates(
                    section, response, expected_pass=2
                )
            )
        )

    def test_critique_repair_of_exception_changes_candidate_semantics(self) -> None:
        section = self.section()
        candidate = self.candidate(section)
        repaired = copy.deepcopy(candidate)
        repaired["exceptions"] = ["Emergency eligibility exception applies."]
        response = {
            "schema_version": INFERENCE_SCHEMA,
            "pass": 2,
            "candidates": [
                {
                    "candidate_id": candidate_id(section, candidate),
                    "critique": {
                        "result": "repair",
                        "findings": ["missing exception"],
                        "repaired_candidate": repaired,
                    },
                }
            ],
        }
        self.assertEqual(
            validate_inference_candidates(section, response, expected_pass=2),
            [],
        )

    def test_critique_repair_must_change_candidate_semantics(self) -> None:
        section = self.section()
        candidate = self.candidate(section)
        response = {
            "schema_version": INFERENCE_SCHEMA,
            "pass": 2,
            "candidates": [
                {
                    "candidate_id": candidate_id(section, candidate),
                    "critique": {
                        "result": "repair",
                        "findings": ["no-op"],
                        "repaired_candidate": copy.deepcopy(candidate),
                    },
                }
            ],
        }
        self.assertTrue(
            any(
                "did not change candidate semantics" in error
                for error in validate_inference_candidates(
                    section, response, expected_pass=2
                )
            )
        )

    def test_inference_section_priority_targets_least_covered_linked_program(self) -> None:
        sections = [
            {
                "section_id": "section-shared",
                "programs": ["medicaid", "snap"],
            },
            {
                "section_id": "section-medicaid",
                "programs": ["medicaid"],
            },
            {
                "section_id": "section-snap",
                "programs": ["snap"],
            },
        ]
        prioritized = prioritize_inference_sections(
            sections,
            {"medicaid": 10, "snap": 0},
        )
        self.assertEqual(
            [item["section_id"] for item in prioritized],
            ["section-shared", "section-snap", "section-medicaid"],
        )
        self.assertEqual(prioritized[0]["program"], "snap")
        self.assertEqual(prioritized[0]["program_candidate_count"], 0)
        self.assertEqual(prioritized[0]["program_ordinal"], 1)
        self.assertEqual(prioritized[1]["program_ordinal"], 2)
        self.assertEqual(
            prioritize_inference_sections(
                sections,
                {"medicaid": 0, "snap": 0},
                limit=1,
            )[0]["program"],
            "medicaid",
        )
        with self.assertRaisesRegex(ValueError, "unknown program"):
            prioritize_inference_sections(
                sections,
                {"not_a_program": 0},
            )

    def test_quality_sample_plan_is_balanced_deterministic_and_nonbinding(self) -> None:
        candidates = []
        for program in all_programs():
            for index in range(20):
                digest = hashlib.sha256(f"{program}-{index}".encode()).hexdigest()
                candidates.append(
                    {
                        "candidate_id": "cand_" + digest[:32],
                        "primary_program": program,
                        "draft_id": "draft_" + digest[:32],
                        "draft_hash": digest,
                        "mandatory_reasons": ["ocr_evidence"] if index == 0 else [],
                    }
                )
        left = build_quality_sample_plan(
            release_id="federal-5100-v1", candidates=candidates
        )
        right = build_quality_sample_plan(
            release_id="federal-5100-v1", candidates=reversed(candidates)
        )
        self.assertEqual(left, right)
        self.assertEqual(left["sample_count"], 1020)
        self.assertTrue(left["minimum_20_per_program"])
        self.assertFalse(left["runtime_activation"])

    def test_quality_consensus_requires_distinct_roles_and_uses_conservative_metrics(self) -> None:
        base = {
            "schema_version": QUALITY_REVIEW_SCHEMA,
            "sample_id": "sample_fixture",
            "candidate_id": "cand_" + "a" * 32,
            "draft_hash": "b" * 64,
            "measurements": {
                "evidence_span_precise": True,
                "typed_mapping_correct": True,
                "program_classification_correct": True,
                "deterministic_rerun_match": True,
            },
            "rationale": "checked against captured source",
            "runtime_activation": False,
            "proof_binding": False,
        }
        policy = {**base, "reviewer_id": "policy-1", "reviewer_role": "policy_reviewer"}
        legal = copy.deepcopy(
            {**base, "reviewer_id": "legal-1", "reviewer_role": "legal_verifier"}
        )
        legal["measurements"]["typed_mapping_correct"] = False
        consensus = merge_quality_review_submissions(policy, legal)
        self.assertFalse(consensus["measurements"]["typed_mapping_correct"])
        legal["reviewer_id"] = "policy-1"
        with self.assertRaisesRegex(ValueError, "different people"):
            merge_quality_review_submissions(policy, legal)
        invalid = {**policy, "draft_hash": "z" * 64}
        self.assertTrue(validate_quality_review_submission(invalid))

    def test_release_cohort_selection_is_exact_stable_and_excludes_excess(self) -> None:
        candidates = []
        quotas = program_quotas(5_100)
        for program, quota in quotas.items():
            for index in range(quota + (2 if program == all_programs()[0] else 0)):
                candidates.append(
                    {
                        "candidate_id": f"cand_{program}_{index:05d}",
                        "primary_program": program,
                    }
                )
        left = select_balanced_release_candidates(candidates, 5_100)
        right = select_balanced_release_candidates(reversed(candidates), 5_100)
        self.assertEqual(left, right)
        self.assertEqual(len(left["selected_candidates"]), 5_100)
        self.assertEqual(left["excluded_above_quota"], 2)
        self.assertFalse(any(left["program_deficits"].values()))

    def test_source_candidate_preflight_is_deterministic_and_review_only(self) -> None:
        candidate = {
            "source_candidate_id": "source-candidate-1",
            "candidate_url": "https://www.cms.gov/regulations/eligibility.xml",
            "parent_url": "https://www.cms.gov/medicaid",
            "program": "medicaid",
            "link_text": "Medicaid eligibility regulations",
            "source_locator": {"xpath": "/html/body/a[1]"},
        }
        left = assess_source_candidate_preflight(candidate)
        self.assertEqual(left, assess_source_candidate_preflight(copy.deepcopy(candidate)))
        self.assertEqual(left["schema_version"], SOURCE_CANDIDATE_PREFLIGHT_VERSION)
        self.assertTrue(left["eligible_for_human_review"])
        self.assertFalse(left["registry_activation"])
        self.assertFalse(left["runtime_activation"])

    def test_source_candidate_preflight_report_validator_accepts_review_packet(self) -> None:
        report = self.source_candidate_preflight_report()
        self.assertEqual(validate_source_candidate_preflight_report(report), [])

    def test_source_candidate_preflight_report_validator_rejects_tampering(self) -> None:
        mutations = (
            (
                "packet_hash",
                lambda report: report.update(
                    {"capacity_blocker_review_candidates_sha256": "0" * 64}
                ),
                "review hash mismatch",
                False,
            ),
            (
                "candidate_url",
                lambda report: report["capacity_blocker_review_candidates"][
                    0
                ].update({"candidate_url": "https://example.com/driver-licenses"}),
                "candidate URL must be canonical and official",
                True,
            ),
            (
                "packet_order",
                lambda report: report[
                    "capacity_blocker_review_candidates"
                ].reverse(),
                "review order is unstable",
                True,
            ),
            (
                "runtime_activation",
                lambda report: report.update({"runtime_activation": True}),
                "runtime_activation must be false",
                False,
            ),
            (
                "unscoped",
                lambda report: report["capacity_blocker_review_candidates"][
                    0
                ].update({"scope_mode": "unscoped"}),
                "scope mode is invalid",
                True,
            ),
            (
                "count",
                lambda report: report.update(
                    {"capacity_blocker_review_candidate_count": 1}
                ),
                "review count mismatch",
                False,
            ),
            (
                "malformed_capacity_program",
                lambda report: report.update(
                    {"programs_without_program_context_quota_capacity": [{}]}
                ),
                "capacity blocker programs are invalid",
                False,
            ),
        )
        for name, mutate, expected_error, rehash_packet in mutations:
            with self.subTest(name=name):
                report = self.source_candidate_preflight_report()
                mutate(report)
                if rehash_packet:
                    report["capacity_blocker_review_candidates_sha256"] = (
                        canonical_sha256(
                            report["capacity_blocker_review_candidates"]
                        )
                    )
                errors = validate_source_candidate_preflight_report(report)
                self.assertIn(expected_error, "; ".join(errors))

    def test_source_candidate_preflight_report_cli_is_database_independent(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "preflight.json"
            report_path.write_text(
                json.dumps(self.source_candidate_preflight_report()),
                encoding="utf-8",
            )
            args = rules_main.build_parser().parse_args(
                [
                    "--workdir",
                    temp_dir,
                    "sources-preflight-validate",
                    "--report",
                    str(report_path),
                ]
            )
            self.assertEqual(args.command, "sources-preflight-validate")
            self.assertEqual(args.report, report_path)
            payload = validate_source_preflight_artifact(report_path=args.report)
            self.assertEqual(payload["status"], "ok")
            self.assertFalse(payload["runtime_activation"])
            self.assertFalse(payload["proof_binding"])

    def test_source_candidate_preflight_requires_program_topic_evidence(self) -> None:
        base = {
            "parent_url": (
                "https://leginfo.legislature.ca.gov/faces/"
                "codesTOCSelected.xhtml?tocCode=HSC"
            ),
            "program": "building_permits",
            "source_locator": {"xpath": "/html/body/a[1]"},
        }
        relevant = assess_source_candidate_preflight(
            {
                **base,
                "source_candidate_id": "source-candidate-building",
                "candidate_url": (
                    "https://leginfo.legislature.ca.gov/faces/"
                    "codes_displayexpandedbranch.xhtml?tocCode=HSC&division=12.5"
                ),
                "link_text": "DIVISION 12.5. BUILDINGS USED BY THE PUBLIC",
            }
        )
        irrelevant = assess_source_candidate_preflight(
            {
                **base,
                "source_candidate_id": "source-candidate-adult-health",
                "candidate_url": (
                    "https://leginfo.legislature.ca.gov/faces/"
                    "codes_displayexpandedbranch.xhtml?tocCode=HSC&division=113"
                ),
                "link_text": "DIVISION 113. ADULT HEALTH COVERAGE EXPANSION",
            }
        )

        self.assertTrue(relevant["eligible_for_human_review"])
        self.assertIn("buildings", relevant["signals"]["program_relevance_terms"])
        self.assertFalse(irrelevant["eligible_for_human_review"])
        self.assertIn("weak_program_relevance", irrelevant["blockers"])

    def test_source_candidate_preflight_accepts_curated_regulation_descendant(self) -> None:
        result = assess_source_candidate_preflight(
            {
                "source_candidate_id": "source-candidate-ecfr-section",
                "candidate_url": (
                    "https://www.ecfr.gov/current/title-42/chapter-IV/"
                    "subchapter-C/part-430/subpart-A/section-430.0"
                ),
                "parent_url": (
                    "https://www.ecfr.gov/current/title-42/chapter-IV/"
                    "subchapter-C/part-430"
                ),
                "parent_source_type": "regulation",
                "program": "medicaid",
                "link_text": "Subpart A - General provisions",
                "source_locator": {"xpath": "/html/body/a[1]"},
            }
        )

        self.assertTrue(result["eligible_for_human_review"])
        self.assertTrue(result["signals"]["curated_hierarchical_program_scope"])
        self.assertNotIn("weak_program_relevance", result["blockers"])

    def test_source_candidate_preflight_rejects_hierarchical_sibling_escape(self) -> None:
        result = assess_source_candidate_preflight(
            {
                "source_candidate_id": "source-candidate-ecfr-sibling",
                "candidate_url": (
                    "https://www.ecfr.gov/current/title-42/chapter-IV/"
                    "subchapter-B/part-400/subpart-A"
                ),
                "parent_url": (
                    "https://www.ecfr.gov/current/title-42/chapter-IV/"
                    "subchapter-C/part-430"
                ),
                "parent_source_type": "regulation",
                "program": "medicaid",
                "link_text": "Subpart A - General provisions",
                "source_locator": {"xpath": "/html/body/a[2]"},
            }
        )

        self.assertFalse(result["eligible_for_human_review"])
        self.assertFalse(result["signals"]["curated_hierarchical_program_scope"])
        self.assertIn("weak_program_relevance", result["blockers"])

    def test_source_candidate_preflight_rejects_encoded_hierarchy_escape(self) -> None:
        result = assess_source_candidate_preflight(
            {
                "source_candidate_id": "source-candidate-ecfr-traversal",
                "candidate_url": (
                    "https://www.ecfr.gov/current/title-42/chapter-IV/"
                    "subchapter-C/part-430/%2e%2e/part-400"
                ),
                "parent_url": (
                    "https://www.ecfr.gov/current/title-42/chapter-IV/"
                    "subchapter-C/part-430"
                ),
                "parent_source_type": "regulation",
                "program": "medicaid",
                "link_text": "General provisions",
                "source_locator": {"xpath": "/html/body/a[3]"},
            }
        )

        self.assertFalse(result["eligible_for_human_review"])
        self.assertFalse(result["signals"]["curated_hierarchical_program_scope"])
        self.assertIn("weak_program_relevance", result["blockers"])

    def test_source_candidate_preflight_uses_program_specific_parent_aliases(self) -> None:
        result = assess_source_candidate_preflight(
            {
                "source_candidate_id": "source-candidate-driver-services",
                "candidate_url": "https://mvdmt.gov/",
                "parent_url": "https://www.usa.gov/motor-vehicle-services",
                "program": "driver_licenses",
                "link_text": "Montana (MT)",
                "source_locator": {"xpath": "/html/body/a[1]"},
            }
        )

        self.assertTrue(result["eligible_for_human_review"])
        self.assertIn("motor", result["signals"]["program_relevance_terms"])
        self.assertEqual(result["signals"]["direct_program_relevance_terms"], [])
        self.assertEqual(
            result["signals"]["inherited_parent_program_relevance_terms"],
            ["motor", "vehicle"],
        )
        self.assertTrue(result["signals"]["jurisdiction_directory_link"])

    def test_source_candidate_preflight_does_not_inherit_parent_scope_for_noise(self) -> None:
        base = {
            "parent_url": "https://www.usa.gov/motor-vehicle-services",
            "program": "driver_licenses",
            "source_locator": {"xpath": "/html/body/a[1]"},
        }
        candidates = (
            {
                **base,
                "source_candidate_id": "source-candidate-same-host-blog",
                "candidate_url": "https://www.usa.gov/blog",
                "link_text": "Read our blog",
            },
            {
                **base,
                "source_candidate_id": "source-candidate-cross-host-gsa",
                "candidate_url": "https://www.gsa.gov/",
                "link_text": "U.S. General Services Administration",
            },
        )

        for candidate in candidates:
            with self.subTest(candidate_id=candidate["source_candidate_id"]):
                result = assess_source_candidate_preflight(candidate)
                self.assertFalse(result["eligible_for_human_review"])
                self.assertIn("weak_program_relevance", result["blockers"])
                self.assertEqual(result["signals"]["program_relevance_terms"], [])
                self.assertEqual(
                    result["signals"]["inherited_parent_program_relevance_terms"],
                    [],
                )

    def test_driver_license_preflight_requires_driver_specific_evidence(self) -> None:
        base = {
            "parent_url": (
                "https://leginfo.legislature.ca.gov/faces/"
                "codesTOCSelected.xhtml?tocCode=VEH"
            ),
            "program": "driver_licenses",
            "source_locator": {"xpath": "/html/body/a[1]"},
        }
        relevant = assess_source_candidate_preflight(
            {
                **base,
                "source_candidate_id": "source-candidate-driver-licenses",
                "candidate_url": (
                    "https://leginfo.legislature.ca.gov/faces/"
                    "codes_displayexpandedbranch.xhtml?tocCode=VEH&division=6"
                ),
                "link_text": "DIVISION 6. DRIVERS' LICENSES",
            }
        )
        unrelated = assess_source_candidate_preflight(
            {
                **base,
                "source_candidate_id": "source-candidate-vehicle-equipment",
                "candidate_url": (
                    "https://leginfo.legislature.ca.gov/faces/"
                    "codes_displayexpandedbranch.xhtml?tocCode=VEH&division=12"
                ),
                "link_text": "DIVISION 12. EQUIPMENT OF VEHICLES",
            }
        )

        self.assertTrue(relevant["eligible_for_human_review"])
        self.assertEqual(
            relevant["signals"]["strong_program_relevance_terms"],
            ["drivers", "licenses"],
        )
        self.assertTrue(relevant["signals"]["program_specificity_satisfied"])
        self.assertFalse(unrelated["eligible_for_human_review"])
        self.assertIn("weak_program_relevance", unrelated["blockers"])
        self.assertEqual(
            unrelated["signals"]["strong_program_relevance_terms"], []
        )
        self.assertFalse(unrelated["signals"]["program_specificity_satisfied"])

    def test_source_candidate_preflight_recognizes_eitc_alias(self) -> None:
        result = assess_source_candidate_preflight(
            {
                "source_candidate_id": "source-candidate-eitc",
                "candidate_url": "https://www.irs.gov/credits-deductions/eitc",
                "parent_url": "https://www.irs.gov/credits-deductions",
                "program": "earned_income_tax_credit",
                "link_text": "EITC eligibility rules",
                "source_locator": {"xpath": "/html/body/a[1]"},
            }
        )

        self.assertTrue(result["eligible_for_human_review"])
        self.assertIn("eitc", result["signals"]["program_relevance_terms"])
    def test_source_candidate_preflight_does_not_use_malformed_s_stems(self) -> None:
        relevant = assess_source_candidate_preflight(
            {
                "source_candidate_id": "source-candidate-business-license",
                "candidate_url": "https://example.gov/business/licensing",
                "parent_url": "https://example.gov/services",
                "program": "business_licenses",
                "link_text": "Business licensing requirements",
                "source_locator": {"xpath": "/html/body/a[1]"},
            }
        )
        misspelled = assess_source_candidate_preflight(
            {
                "source_candidate_id": "source-candidate-busines-typo",
                "candidate_url": "https://example.gov/compliance",
                "parent_url": "https://example.gov/services",
                "program": "business_licenses",
                "link_text": "Busines compliance requirements",
                "source_locator": {"xpath": "/html/body/a[2]"},
            }
        )

        self.assertTrue(relevant["eligible_for_human_review"])
        self.assertFalse(misspelled["eligible_for_human_review"])
        self.assertIn("weak_program_relevance", misspelled["blockers"])
    def test_source_candidate_preflight_prioritizes_temporal_authority_review(self) -> None:
        result = assess_source_candidate_preflight(
            {
                "source_candidate_id": "source-candidate-federal-register",
                "candidate_url": (
                    "https://www.federalregister.gov/documents/2026/08/01/"
                    "eligibility-final-rule.html"
                ),
                "parent_url": "https://www.cms.gov/medicaid/regulations",
                "program": "medicaid",
                "link_text": "Final eligibility rule and effective date",
                "source_locator": {"xpath": "/html/body/a[2]"},
            }
        )
        self.assertTrue(result["eligible_for_human_review"])
        self.assertTrue(result["signals"]["temporal_authority_candidate"])
        self.assertEqual(
            result["signals"]["source_priority"], "primary_temporal_authority"
        )
        self.assertFalse(result["registry_activation"])

    def test_source_candidate_preflight_batch_blocks_exact_duplicate_urls(self) -> None:
        base = {
            "candidate_url": "https://www.ssa.gov/ssi/eligibility",
            "parent_url": "https://www.ssa.gov/ssi",
            "program": "ssi",
            "source_locator": {"xpath": "/html/body/a[1]"},
        }
        candidates = [
            {
                **base,
                "source_candidate_id": "source-candidate-weak",
                "link_text": "Learn more",
            },
            {
                **base,
                "source_candidate_id": "source-candidate-canonical",
                "link_text": "SSI eligibility requirements",
            },
            {
                **base,
                "source_candidate_id": "source-candidate-other-program",
                "program": "social_security",
                "link_text": "Social Security eligibility requirements",
            },
        ]
        left = assess_source_candidate_preflight_batch(candidates)
        right = assess_source_candidate_preflight_batch(reversed(candidates))
        self.assertEqual(left, right)
        by_id = {item["source_candidate_id"]: item for item in left}
        canonical = by_id["source-candidate-canonical"]
        duplicate = by_id["source-candidate-weak"]
        other_program = by_id["source-candidate-other-program"]
        self.assertTrue(canonical["eligible_for_human_review"])
        self.assertNotIn(
            "duplicate_source_candidate_url", canonical["blockers"]
        )
        self.assertEqual(
            canonical["signals"]["canonical_source_candidate_id"],
            "source-candidate-canonical",
        )
        self.assertEqual(
            canonical["signals"]["duplicate_program_url_count"], 2
        )
        self.assertFalse(duplicate["eligible_for_human_review"])
        self.assertIn(
            "duplicate_source_candidate_url", duplicate["blockers"]
        )
        self.assertEqual(
            duplicate["signals"]["canonical_source_candidate_id"],
            "source-candidate-canonical",
        )
        self.assertTrue(other_program["eligible_for_human_review"])
        self.assertEqual(
            other_program["signals"]["duplicate_program_url_count"], 1
        )

    def test_source_candidate_preflight_blocks_navigation_and_assets(self) -> None:
        result = assess_source_candidate_preflight(
            {
                "source_candidate_id": "source-candidate-asset",
                "candidate_url": "https://www.cms.gov/news/logo.png",
                "parent_url": "https://www.cms.gov/medicaid",
                "program": "medicaid",
                "link_text": "News logo",
                "source_locator": {"xpath": "/html/body/a[1]"},
            }
        )
        self.assertFalse(result["eligible_for_human_review"])
        self.assertIn("non_rule_resource", result["blockers"])
        self.assertIn("weak_rule_relevance", result["blockers"])

    def test_source_candidate_preflight_blocks_site_policy_boilerplate(self) -> None:
        for candidate_url, link_text in (
            ("https://www.ssa.gov/agency/privacy.html", "Privacy policy"),
            ("https://www.usa.gov/accessibility-policy", "Accessibility policy"),
            (
                "https://www.hhs.gov/vulnerability-disclosure-policy/index.html",
                "Vulnerability disclosure policy",
            ),
        ):
            with self.subTest(candidate_url=candidate_url):
                result = assess_source_candidate_preflight(
                    {
                        "source_candidate_id": "source-candidate-boilerplate",
                        "candidate_url": candidate_url,
                        "parent_url": "https://www.ssa.gov/ssi",
                        "program": "ssi",
                        "link_text": link_text,
                        "source_locator": {"xpath": "/html/body/a[1]"},
                    }
                )
                self.assertFalse(result["eligible_for_human_review"])
                self.assertIn(
                    "site_policy_or_security_boilerplate", result["blockers"]
                )

    def test_source_discovery_is_official_deduplicated_and_review_only(self) -> None:
        html = b"""
        <html><body>
          <a href="/rules/eligibility.xml">Eligibility rules</a>
          <a href="https://www.cms.gov/rules/eligibility.xml#part-a">duplicate</a>
          <a href="https://example.com/rules">external</a>
          <a href="/assets/logo.png">asset</a>
        </body></html>
        """
        links = discover_official_links(
            html,
            mime_type="text/html",
            source_url="https://www.cms.gov/programs/medicaid",
        )
        self.assertEqual(len(links), 1)
        self.assertEqual(
            links[0].canonical_url,
            "https://www.cms.gov/rules/eligibility.xml",
        )
        self.assertTrue(links[0].source_locator)

    def test_source_registry_release_is_hash_pinned_and_inactive(self) -> None:
        base = load_source_registry(WORKDIR)
        approved = {
            "source_candidate_id": "source-candidate-1",
            "candidate_url": "https://www.cms.gov/new-rules/eligibility.xml",
            "program": "medicaid",
            "parent_source_id": base["sources"][0]["source_id"],
            "parent_snapshot_hash": "a" * 64,
            "source_decision_id": "decision-1",
            "review_status": "approved_for_registry",
            "decision": "approve_for_registry",
            "reviewer_role": "rules_admin",
            "reviewer_id": "admin-1",
            "rationale": "official regulation source",
        }
        release = build_source_registry_release(
            release_id="federal-source-v2",
            base_registry=base,
            approved_candidates=[approved],
        )
        self.assertEqual(release["approved_addition_count"], 1)
        self.assertTrue(release["all_51_programs_covered"])
        self.assertEqual(
            len(release["canonical_release_hash"]), 64
        )
        self.assertFalse(release["runtime_activation"])
        self.assertFalse(release["proof_binding"])

    def test_registry_excludes_confirmed_dead_entrypoints(self) -> None:
        urls = {item["canonical_url"] for item in load_source_registry(WORKDIR)["sources"]}
        for old_url in (
            "https://www.ssa.gov/OP_Home/",
            "https://www.fns.usda.gov/snap/frules",
            "https://www.fns.usda.gov/wic/regulations",
            "https://www.acf.hhs.gov/ocs/programs/liheap",
            "https://www.ecfr.gov/",
        ):
            self.assertNotIn(old_url, urls)

    def test_official_source_url_rejects_credentials_and_nondefault_ports(self) -> None:
        with self.assertRaisesRegex(ValueError, "user information"):
            _validated_official_source_url(
                "https://user:password@www.cms.gov/rules"
            )
        with self.assertRaisesRegex(ValueError, "default HTTPS port"):
            _validated_official_source_url("https://www.cms.gov:444/rules")
        self.assertEqual(
            _validated_official_source_url("https://www.cms.gov/rules"),
            "https://www.cms.gov/rules",
        )

    def test_ecfr_root_and_invalid_snapshot_date_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "hierarchy"):
            _ecfr_api_url("https://www.ecfr.gov/current", "2026-08-10")
        with self.assertRaisesRegex(ValueError, "YYYY-MM-DD"):
            _ecfr_api_url(
                "https://www.ecfr.gov/current/title-42", "not-a-date"
            )

    def test_ecfr_source_fetch_uses_one_dated_xml_snapshot(self) -> None:
        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(str(request.url))
            return httpx.Response(
                200,
                headers={"content-type": "application/xml"},
                content=b"<ROOT><P>Applicants must file.</P></ROOT>",
                request=request,
            )

        with httpx.Client(
            transport=httpx.MockTransport(handler), follow_redirects=False
        ) as client:
            result = _fetch_official_source(
                client,
                "https://www.ecfr.gov/current/title-42/chapter-IV/part-400",
                ecfr_snapshot_date="2026-08-10",
            )
        self.assertEqual(len(seen), 1)
        self.assertIn("/api/versioner/v1/full/2026-08-10/title-42.xml", seen[0])
        self.assertIn("chapter=IV", seen[0])
        self.assertEqual(result["resolution_chain"], seen)

    def test_official_source_fetch_validates_each_redirect_before_requesting(self) -> None:
        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(str(request.url))
            return httpx.Response(
                302,
                headers={"location": "https://example.com/not-official"},
                request=request,
            )

        with httpx.Client(
            transport=httpx.MockTransport(handler), follow_redirects=False
        ) as client:
            with self.assertRaisesRegex(ValueError, r"\.gov host"):
                _fetch_official_source(client, "https://www.cms.gov/rules")
        self.assertEqual(len(seen), 1)

    def test_official_source_fetch_rejects_access_challenge(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={
                    "content-type": "text/html",
                    "x-amzn-waf-action": "challenge",
                },
                content=b"<html>captcha</html>",
                request=request,
            )

        with httpx.Client(
            transport=httpx.MockTransport(handler), follow_redirects=False
        ) as client:
            with self.assertRaisesRegex(ValueError, "access challenge"):
                _fetch_official_source(client, "https://www.cms.gov/rules")

    def test_source_fetch_worker_completes_immutable_snapshot(self) -> None:
        job = {
            "fetch_job_id": "fetch-1",
            "source_id": "source-1",
            "canonical_url": "https://www.cms.gov/rules.txt",
            "registry_version": "fixture-v1",
            "program": "medicaid",
            "jurisdiction": {"country": "US", "level": "federal", "state": None},
            "issuer": "CMS",
            "source_type": "regulation",
            "required": True,
            "official": True,
            "attempts": 1,
        }

        class Store:
            def __init__(self) -> None:
                self.snapshot = None

            def renew_source_fetch_lease(self, *_args, **_kwargs):
                return None

            def complete_source_fetch_job(self, *_args, snapshot, **_kwargs):
                self.snapshot = snapshot
                return "retrieval-1"

            def fail_source_fetch_job(self, *_args, **_kwargs):
                raise AssertionError("successful fetch must not fail")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"content-type": "text/plain"},
                content=b"Applicants must file.",
                request=request,
            )

        store = Store()
        with httpx.Client(
            transport=httpx.MockTransport(handler), follow_redirects=False
        ) as client:
            result = _run_source_fetch_job(store, client, "worker", job)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["retrieval_id"], "retrieval-1")
        self.assertEqual(
            restore_snapshot_bytes(store.snapshot), b"Applicants must file."
        )

    def test_source_fetch_worker_records_delayed_retry_without_snapshot(self) -> None:
        job = {
            "fetch_job_id": "fetch-fail",
            "source_id": "source-1",
            "canonical_url": "https://www.cms.gov/rules.txt",
            "attempts": 1,
        }

        class Store:
            def renew_source_fetch_lease(self, *_args, **_kwargs):
                return None

            def fail_source_fetch_job(self, *_args, **kwargs):
                self.failure = kwargs
                return "pending"

        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("fixture offline", request=request)

        store = Store()
        with httpx.Client(
            transport=httpx.MockTransport(handler), follow_redirects=False
        ) as client:
            result = _run_source_fetch_job(store, client, "worker", job)
        self.assertEqual(result["status"], "pending")
        self.assertIn("fixture offline", result["error"])
        self.assertGreater(store.failure["retry_delay_seconds"], 0)

    def test_section_extraction_worker_completes_versioned_sections(self) -> None:
        source = load_source_registry(WORKDIR)["sources"][0]
        snapshot = build_source_snapshot(
            source,
            b"Applicants must file.\nAppeals may be submitted.",
            retrieved_at="2026-08-10T12:00:00Z",
            mime_type="text/plain",
        )
        job = {
            **snapshot,
            "extraction_job_id": "extract-1",
            "retrieval_id": "retrieval-1",
            "canonical_url": source["canonical_url"],
            "pipeline_version": "fixture-pipeline-v2",
            "attempts": 1,
        }

        class Store:
            def renew_section_extraction_lease(self, *_args, **_kwargs):
                return None

            def complete_section_extraction_job(self, *_args, sections, **_kwargs):
                self.sections = sections
                return len(sections)

            def fail_section_extraction_job(self, *_args, **_kwargs):
                raise AssertionError("successful extraction must not fail")

        store = Store()
        result = _run_section_extraction_job(store, "worker", job)
        self.assertEqual(result["status"], "completed")
        self.assertGreater(result["section_count"], 0)
        self.assertTrue(
            all(
                item["extraction_pipeline_version"] == "fixture-pipeline-v2"
                for item in store.sections
            )
        )

    def test_section_extraction_worker_records_delayed_retry(self) -> None:
        job = {
            "extraction_job_id": "extract-fail",
            "retrieval_id": "retrieval-fail",
            "compressed_content_b64": "not-valid-base64",
            "compression": "zlib",
            "uncompressed_size": 1,
            "snapshot_hash": "a" * 64,
            "mime_type": "text/plain",
            "canonical_url": "https://www.cms.gov/rules.txt",
            "pipeline_version": "fixture-pipeline-v2",
            "attempts": 1,
        }

        class Store:
            def renew_section_extraction_lease(self, *_args, **_kwargs):
                return None

            def fail_section_extraction_job(self, *_args, **kwargs):
                self.failure = kwargs
                return "pending"

        store = Store()
        result = _run_section_extraction_job(store, "worker", job)
        self.assertEqual(result["status"], "pending")
        self.assertGreater(store.failure["retry_delay_seconds"], 0)

    def test_section_identity_binds_pipeline_and_parser_lineage(self) -> None:
        left = segment_text(
            "a" * 64,
            "Applicants must file.",
            parser_name="fixture",
            parser_version="1",
            extraction_pipeline_version="pipeline-a",
        )[0]
        right = segment_text(
            "a" * 64,
            "Applicants must file.",
            parser_name="fixture",
            parser_version="2",
            extraction_pipeline_version="pipeline-b",
        )[0]
        self.assertNotEqual(left["section_id"], right["section_id"])
        self.assertEqual(left["normalized_text_hash"], right["normalized_text_hash"])

    def test_ocr_artifact_preserves_exact_bytes_and_section_lineage(self) -> None:
        raw = b"Applicants must file.\r\nAppeals may be submitted.\n"
        artifact = build_ocr_artifact(
            retrieval_id="retrieval-fixture",
            snapshot_hash="a" * 64,
            artifact_bytes=raw,
            engine_name="tesseract",
            engine_version="5.4.1",
            operator_id="reviewer-17",
            generated_at="2026-08-11T12:30:00-05:00",
        )
        self.assertEqual(restore_ocr_artifact_bytes(artifact), raw)
        self.assertEqual(artifact["artifact_hash"], hashlib.sha256(raw).hexdigest())
        self.assertFalse(artifact["runtime_activation"])
        self.assertFalse(artifact["proof_binding"])
        sections = segment_text(
            artifact["snapshot_hash"],
            artifact["normalized_text"],
            parser_name="ocr:tesseract",
            parser_version="5.4.1",
            extraction_pipeline_version="ocr-artifact-v1",
            ocr_used=True,
            source_locator={
                "kind": "ocr_artifact_text",
                "ocr_artifact_id": artifact["ocr_artifact_id"],
                "ocr_artifact_hash": artifact["artifact_hash"],
            },
        )
        self.assertTrue(sections[0]["ocr_used"])
        self.assertEqual(
            sections[0]["source_locator"]["ocr_artifact_hash"],
            artifact["artifact_hash"],
        )

    def test_ocr_ingest_requires_dedicated_evidence_root(self) -> None:
        class Store:
            def __init__(self) -> None:
                self.saved = None

            def ocr_ingest_target(self, retrieval_id):
                self.retrieval_id = retrieval_id
                return {
                    "snapshot_hash": "b" * 64,
                    "canonical_url": "https://example.gov/source.pdf",
                    "program": "medicaid",
                }

            def save_ocr_artifact(self, artifact, sections):
                self.saved = (artifact, sections)
                return {
                    "ocr_artifact_id": artifact["ocr_artifact_id"],
                    "retrieval_id": artifact["retrieval_id"],
                    "snapshot_hash": artifact["snapshot_hash"],
                    "artifact_hash": artifact["artifact_hash"],
                    "section_count": len(sections),
                    "engine_name": artifact["engine_name"],
                    "engine_version": artifact["engine_version"],
                    "operator_id": artifact["operator_id"],
                    "generated_at": artifact["generated_at"],
                    "mandatory_quality_review": True,
                }

        with tempfile.TemporaryDirectory() as directory:
            workdir = Path(directory)
            evidence_root = workdir / "data" / "evidence" / "ocr"
            evidence_root.mkdir(parents=True)
            artifact_path = evidence_root / "source.txt"
            artifact_path.write_text("Applicants must file.\n", encoding="utf-8")
            store = Store()
            report = ocr_artifact_ingest(
                workdir,
                store,
                retrieval_id="retrieval-fixture",
                artifact_path=artifact_path,
                evidence_root=evidence_root,
                engine_name="tesseract",
                engine_version="5.4.1",
                operator_id="reviewer-17",
                generated_at="2026-08-11T17:30:00Z",
            )
            self.assertTrue(report["human_review_required"])
            self.assertFalse(report["ocr_text_is_official_source_bytes"])
            self.assertIsNotNone(store.saved)
            outside = workdir / "outside.txt"
            outside.write_text("outside", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "configured evidence root"):
                ocr_artifact_ingest(
                    workdir,
                    store,
                    retrieval_id="retrieval-fixture",
                    artifact_path=outside,
                    evidence_root=evidence_root,
                    engine_name="tesseract",
                    engine_version="5.4.1",
                    operator_id="reviewer-17",
                    generated_at="2026-08-11T17:30:00Z",
                )

    def test_structured_segmentation_preserves_hierarchy_and_locator(self) -> None:
        blocks = [
            {
                "text": "Applicants must file.",
                "hierarchy_path": ["Part 1", "Eligibility"],
                "heading": "Eligibility",
                "block_kind": "paragraph",
                "source_locator": {"xpath": "/ROOT/SECTION/P[1]"},
            },
            {
                "text": "Appeals may be submitted.",
                "hierarchy_path": ["Part 1", "Eligibility"],
                "heading": "Eligibility",
                "block_kind": "paragraph",
                "source_locator": {"xpath": "/ROOT/SECTION/P[2]"},
            },
        ]
        sections = segment_structured_blocks(
            "a" * 64,
            blocks,
            parser_name="ecfr_xml",
            extraction_pipeline_version="pipeline-v2",
        )
        self.assertEqual(len(sections), 1)
        self.assertEqual(sections[0]["hierarchy_path"], ["Part 1", "Eligibility"])
        self.assertEqual(len(sections[0]["source_locator"]["blocks"]), 2)

    def test_xml_content_containers_preserve_atomic_paragraphs(self) -> None:
        extracted = extract_source_text(
            b"<ROOT><TITLE>Part 1</TITLE><SECTION><P>(a) File.</P><P>(b) Appeal.</P></SECTION></ROOT>",
            mime_type="application/xml",
            source_url="https://www.ecfr.gov/api/versioner/v1/full/2026-08-10/title-42.xml",
        )
        paragraph_blocks = [
            block for block in extracted.blocks if block.block_kind == "paragraph"
        ]
        self.assertGreaterEqual(len(paragraph_blocks), 2)
        self.assertEqual(paragraph_blocks[0].text, "(a) File.")
        self.assertEqual(paragraph_blocks[1].text, "(b) Appeal.")


if __name__ == "__main__":
    unittest.main()
