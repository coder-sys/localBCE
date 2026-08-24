from __future__ import annotations

import hashlib
import json
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .canonical_rules import build_promotion_queue, canonical_sha256
from .scaled_corpus import (
    CLAUDE_MODEL,
    CORPUS_MILESTONES,
    CRITIQUE_CONTRACT_KEY,
    CRITIQUE_PROMPT_VERSION,
    EXTRACTION_CONTRACT_KEY,
    EXTRACTION_PROMPT_VERSION,
    INFERENCE_SCHEMA,
    INFERENCE_RESPONSE_CONTRACT_VERSION,
    MAX_CANDIDATES_PER_SECTION,
    RELEVANCE_CLASSIFIER_VERSION,
    SOURCE_CANDIDATE_PREFLIGHT_REPORT_SCHEMA,
    SOURCE_CANDIDATE_PREFLIGHT_VERSION,
    all_programs,
    assess_source_candidate_preflight_batch,
    program_quotas,
    prioritize_inference_sections,
    stable_id,
)


class CorpusDatabaseError(RuntimeError):
    pass


DEFAULT_REVIEW_LEASE_SECONDS = 24 * 60 * 60
SOURCE_REVIEW_MILESTONE_TARGET = 5_100


CURRENT_EXTRACTION_CONTRACT_KEY = EXTRACTION_CONTRACT_KEY
CURRENT_CRITIQUE_CONTRACT_KEY = CRITIQUE_CONTRACT_KEY
CURRENT_CANDIDATE_CONTRACT_SQL = (
    f"candidates.extraction_contract_key = '{CURRENT_EXTRACTION_CONTRACT_KEY}' "
    f"AND candidates.critique_contract_key = '{CURRENT_CRITIQUE_CONTRACT_KEY}'"
)
CURRENT_MEMBER_CANDIDATE_CONTRACT_SQL = (
    f"member_candidates.extraction_contract_key = "
    f"'{CURRENT_EXTRACTION_CONTRACT_KEY}' "
    f"AND member_candidates.critique_contract_key = "
    f"'{CURRENT_CRITIQUE_CONTRACT_KEY}'"
)


def _source_candidate_scope_mode(signals: dict[str, Any]) -> str:
    if signals.get("direct_program_relevance_terms"):
        return "direct_candidate_evidence"
    if signals.get("curated_hierarchical_program_scope") is True:
        return "curated_authority_hierarchy"
    if (
        signals.get("jurisdiction_directory_link") is True
        and signals.get("inherited_parent_program_relevance_terms")
    ):
        return "jurisdiction_directory_inheritance"
    if (
        signals.get("temporal_authority_candidate") is True
        and signals.get("inherited_parent_program_relevance_terms")
    ):
        return "temporal_authority_inheritance"
    return "unscoped"


def _quality_conflict_counts(
    conn: Any,
    *,
    release_id: str | None = None,
) -> dict[str, int]:
    if release_id is None:
        active_drafts_sql = f"""
            WITH latest_drafts AS (
                SELECT DISTINCT ON (candidate_id) candidate_id, draft_id
                FROM typed_rule_drafts
                ORDER BY candidate_id, draft_version DESC
            ), active_drafts AS MATERIALIZED (
                SELECT DISTINCT drafts.draft_id, drafts.scope_fingerprint,
                       drafts.outcome_hash, drafts.canonical_rule,
                       drafts.validation_errors
                FROM latest_drafts latest
                JOIN typed_rule_drafts drafts
                  ON drafts.draft_id = latest.draft_id
                JOIN grounded_candidates candidates
                  ON candidates.candidate_id = drafts.candidate_id
                JOIN source_sections sections
                  ON sections.section_id = candidates.section_id
                JOIN source_section_program_contexts contexts
                  ON contexts.section_id = candidates.section_id
                 AND contexts.program = candidates.primary_program
                 AND contexts.source_active
                WHERE sections.active
                  AND candidates.grounding_status = 'accepted'
                  AND {CURRENT_CANDIDATE_CONTRACT_SQL}
            )
        """
        params: tuple[Any, ...] = ()
    else:
        active_drafts_sql = """
            WITH active_drafts AS MATERIALIZED (
                SELECT DISTINCT drafts.draft_id, drafts.scope_fingerprint,
                       drafts.outcome_hash, drafts.canonical_rule,
                       drafts.validation_errors
                FROM corpus_release_cohorts cohorts
                JOIN typed_rule_drafts drafts
                  ON drafts.draft_id = cohorts.draft_id
                 AND drafts.canonical_hash = cohorts.draft_hash
                WHERE cohorts.release_id = %s
            )
        """
        params = (release_id,)
    row = conn.execute(
        active_drafts_sql
        + """
            , valid_drafts AS MATERIALIZED (
                SELECT draft_id, scope_fingerprint, outcome_hash,
                       COALESCE(
                           NULLIF(canonical_rule->>'effective_from', '')::date,
                           '-infinity'::date
                       ) AS effective_from,
                       COALESCE(
                           NULLIF(canonical_rule->>'effective_through', '')::date,
                           'infinity'::date
                       ) AS effective_through
                FROM active_drafts
                WHERE validation_errors = '[]'::jsonb
            ), conflict_pairs AS MATERIALIZED (
                SELECT left_draft.draft_id AS left_draft_id,
                       right_draft.draft_id AS right_draft_id
                FROM valid_drafts left_draft
                JOIN valid_drafts right_draft
                  ON left_draft.scope_fingerprint = right_draft.scope_fingerprint
                 AND left_draft.draft_id < right_draft.draft_id
                WHERE left_draft.outcome_hash <> right_draft.outcome_hash
                  AND left_draft.effective_from <= right_draft.effective_through
                  AND right_draft.effective_from <= left_draft.effective_through
            )
            SELECT
                (
                    SELECT count(DISTINCT clusters.cluster_id)
                    FROM duplicate_conflict_clusters clusters
                    WHERE clusters.status = 'open'
                      AND clusters.cluster_kind = 'conflicting_outcome'
                      AND EXISTS (
                          SELECT 1
                          FROM duplicate_conflict_members members
                          JOIN active_drafts drafts
                            ON drafts.draft_id = members.draft_id
                          WHERE members.cluster_id = clusters.cluster_id
                      )
                ) AS open_conflicts,
                (
                    SELECT count(*)
                    FROM conflict_pairs pairs
                    WHERE NOT EXISTS (
                        SELECT 1
                        FROM duplicate_conflict_clusters clusters
                        JOIN duplicate_conflict_members left_member
                          ON left_member.cluster_id = clusters.cluster_id
                         AND left_member.draft_id = pairs.left_draft_id
                        JOIN duplicate_conflict_members right_member
                          ON right_member.cluster_id = clusters.cluster_id
                         AND right_member.draft_id = pairs.right_draft_id
                        WHERE clusters.cluster_kind = 'conflicting_outcome'
                    )
                ) AS silently_merged_conflicts
        """,
        params,
    ).fetchone()
    return {
        "open_conflicts": int(row["open_conflicts"]),
        "silently_merged_conflicts": int(row["silently_merged_conflicts"]),
    }


def database_url(explicit: str | None = None) -> str:
    value = explicit or os.environ.get("DATABASE_URL")
    if not value:
        raise CorpusDatabaseError("DATABASE_URL is required for the PostgreSQL rules corpus")
    if not (value.startswith("postgresql://") or value.startswith("postgres://")):
        raise CorpusDatabaseError("DATABASE_URL must use PostgreSQL")
    return value


class PostgresCorpusStore:
    def __init__(self, url: str | None = None) -> None:
        self.url = database_url(url)

    @contextmanager
    def connection(self) -> Iterator[Any]:
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc:  # pragma: no cover - dependency gate
            raise CorpusDatabaseError("psycopg 3 is required for the PostgreSQL corpus") from exc
        with psycopg.connect(self.url, row_factory=dict_row) as conn:
            yield conn

    @contextmanager
    def inference_run_lock(self) -> Iterator[None]:
        """Hold the database-wide paid-inference lock for one CLI run."""
        lock_namespace = "localbce-rules"
        lock_name = "claude-inference-run-v1"
        with self.connection() as conn:
            row = conn.execute(
                """
                SELECT pg_try_advisory_lock(hashtext(%s), hashtext(%s)) AS acquired
                """,
                (lock_namespace, lock_name),
            ).fetchone()
            conn.commit()
            if not row or row["acquired"] is not True:
                raise CorpusDatabaseError(
                    "another Claude inference run already holds the PostgreSQL worker lock"
                )
            try:
                yield
            finally:
                conn.execute(
                    "SELECT pg_advisory_unlock(hashtext(%s), hashtext(%s))",
                    (lock_namespace, lock_name),
                )
                conn.commit()

    def migrate(self, migrations_dir: Path) -> list[str]:
        files = sorted(migrations_dir.glob("*.sql"))
        if not files:
            raise CorpusDatabaseError("no PostgreSQL migrations found")
        applied: list[str] = []
        with self.connection() as conn:
            for path in files:
                conn.execute(path.read_text(encoding="utf-8"))
                applied.append(path.name)
            self._refresh_candidate_contract_projection_with_connection(conn)
            conn.commit()
        return applied

    @staticmethod
    def _refresh_candidate_contract_projection_with_connection(conn: Any) -> None:
        """Recompute current-contract projection keys from immutable inference jobs."""
        conn.execute(
            """
            UPDATE grounded_candidates
            SET critique_contract_key = NULL
            WHERE critique_job_id IS NULL
            """
        )
        conn.execute(
            """
            UPDATE grounded_candidates candidates
            SET extraction_contract_key = CASE
                    WHEN jobs.inference_job_id IS NOT NULL THEN %s
                    ELSE NULL
                END
            FROM inference_jobs linked
            LEFT JOIN inference_jobs jobs
              ON jobs.inference_job_id = linked.inference_job_id
             AND jobs.status = 'completed'
             AND jobs.pass = 1
             AND jobs.prompt_version = %s
             AND jobs.model_version = %s
             AND jobs.schema_version = %s
             AND jobs.request_payload->>'response_contract_version' = %s
            WHERE linked.inference_job_id = candidates.extraction_job_id
            """,
            (
                CURRENT_EXTRACTION_CONTRACT_KEY,
                EXTRACTION_PROMPT_VERSION,
                CLAUDE_MODEL,
                INFERENCE_SCHEMA,
                INFERENCE_RESPONSE_CONTRACT_VERSION,
            ),
        )
        conn.execute(
            """
            UPDATE grounded_candidates candidates
            SET critique_contract_key = CASE
                    WHEN jobs.inference_job_id IS NOT NULL THEN %s
                    ELSE NULL
                END
            FROM inference_jobs linked
            LEFT JOIN inference_jobs jobs
              ON jobs.inference_job_id = linked.inference_job_id
             AND jobs.status = 'completed'
             AND jobs.pass = 2
             AND jobs.prompt_version = %s
             AND jobs.model_version = %s
             AND jobs.schema_version = %s
             AND jobs.request_payload->>'response_contract_version' = %s
            WHERE linked.inference_job_id = candidates.critique_job_id
            """,
            (
                CURRENT_CRITIQUE_CONTRACT_KEY,
                CRITIQUE_PROMPT_VERSION,
                CLAUDE_MODEL,
                INFERENCE_SCHEMA,
                INFERENCE_RESPONSE_CONTRACT_VERSION,
            ),
        )

    def sync_registry(self, registry: dict[str, Any]) -> int:
        from psycopg.types.json import Jsonb

        with self.connection() as conn:
            conn.execute("UPDATE official_sources SET active = false WHERE active")
            for source in registry["sources"]:
                conn.execute(
                    """
                    INSERT INTO official_sources (
                        source_id, registry_version, canonical_url, program, jurisdiction,
                        issuer, source_type, required, official, metadata
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, true, %s)
                    ON CONFLICT (source_id) DO UPDATE SET
                        active = true,
                        metadata = EXCLUDED.metadata
                    """,
                    (
                        source["source_id"],
                        source["registry_version"],
                        source["canonical_url"],
                        source["program"],
                        Jsonb(source["jurisdiction"]),
                        source["issuer"],
                        source["source_type"],
                        source["required"],
                        Jsonb(source["metadata"]),
                    ),
                )
            conn.commit()
        return len(registry["sources"])

    def sync_supplemental_registry(self, registry: dict[str, Any]) -> dict[str, int]:
        """Add an inactive source registry without superseding active base sources."""

        from psycopg.types.json import Jsonb

        if registry.get("supplemental") is not True:
            raise ValueError("supplemental source registry must set supplemental=true")
        for field in ("registry_activation", "runtime_activation", "proof_binding"):
            if registry.get(field) is not False:
                raise ValueError(f"supplemental source registry {field} must be false")
        registry_id = str(registry.get("registry_id", "")).strip()
        sources = registry.get("sources")
        if not registry_id or not isinstance(sources, list) or not sources:
            raise ValueError("supplemental source registry identity and sources are required")

        inserted = 0
        reactivated = 0
        with self.connection() as conn:
            active_before = int(
                conn.execute(
                    "SELECT count(*) AS count FROM official_sources WHERE active"
                ).fetchone()["count"]
            )
            for source in sources:
                if source.get("registry_version") != registry_id:
                    raise ValueError("supplemental source registry version mismatch")
                if source.get("official") is not True:
                    raise ValueError("supplemental source must be official")
                existing = conn.execute(
                    "SELECT * FROM official_sources WHERE source_id = %s FOR UPDATE",
                    (source["source_id"],),
                ).fetchone()
                identity = {
                    "registry_version": source["registry_version"],
                    "canonical_url": source["canonical_url"],
                    "program": source["program"],
                    "jurisdiction": source["jurisdiction"],
                    "issuer": source["issuer"],
                    "source_type": source["source_type"],
                    "required": source["required"],
                    "official": source["official"],
                    "metadata": source["metadata"],
                }
                if existing:
                    persisted = {key: existing[key] for key in identity}
                    if persisted != identity:
                        raise CorpusDatabaseError(
                            f"supplemental source identity collision: {source['source_id']}"
                        )
                    if not existing["active"]:
                        conn.execute(
                            "UPDATE official_sources SET active = true WHERE source_id = %s",
                            (source["source_id"],),
                        )
                        reactivated += 1
                    continue
                conn.execute(
                    """
                    INSERT INTO official_sources (
                        source_id, registry_version, canonical_url, program, jurisdiction,
                        issuer, source_type, required, official, active, metadata
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, true, true, %s)
                    """,
                    (
                        source["source_id"],
                        source["registry_version"],
                        source["canonical_url"],
                        source["program"],
                        Jsonb(source["jurisdiction"]),
                        source["issuer"],
                        source["source_type"],
                        source["required"],
                        Jsonb(source["metadata"]),
                    ),
                )
                inserted += 1
            active_after = int(
                conn.execute(
                    "SELECT count(*) AS count FROM official_sources WHERE active"
                ).fetchone()["count"]
            )
            conn.commit()
        return {
            "source_count": len(sources),
            "inserted": inserted,
            "reactivated": reactivated,
            "active_sources_before": active_before,
            "active_sources_after": active_after,
        }

    def supplemental_registry_summary(self, registry_id: str) -> dict[str, Any]:
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT source_id, program, jurisdiction, metadata,
                       active,
                       EXISTS (
                           SELECT 1 FROM source_snapshot_retrievals retrievals
                           WHERE retrievals.source_id = official_sources.source_id
                       ) AS has_snapshot,
                       EXISTS (
                           SELECT 1 FROM source_fetch_jobs jobs
                           WHERE jobs.source_id = official_sources.source_id
                       ) AS has_fetch_job
                FROM official_sources
                WHERE registry_version = %s
                ORDER BY source_id
                """,
                (registry_id,),
            ).fetchall()
        state_counts: dict[str, int] = {}
        family_coverage: dict[str, dict[str, int]] = {}
        adapter_blockers: list[str] = []
        for row in rows:
            state = str(row["jurisdiction"].get("state") or "")
            state_counts[state] = state_counts.get(state, 0) + 1
            family_coverage.setdefault(state, {})
            for family in row["metadata"].get("rule_families", []):
                family_coverage[state][family] = (
                    family_coverage[state].get(family, 0) + 1
                )
            if row["metadata"].get("adapter_required") is True:
                adapter_blockers.append(row["source_id"])
        return {
            "registry_id": registry_id,
            "source_count": len(rows),
            "active_source_count": sum(bool(row["active"]) for row in rows),
            "snapshot_count": sum(bool(row["has_snapshot"]) for row in rows),
            "fetch_job_count": sum(bool(row["has_fetch_job"]) for row in rows),
            "state_counts": dict(sorted(state_counts.items())),
            "rule_family_coverage": {
                state: dict(sorted(counts.items()))
                for state, counts in sorted(family_coverage.items())
            },
            "adapter_required_source_ids": sorted(adapter_blockers),
            "human_approved_source_count": sum(
                row["metadata"].get("human_approved") is True for row in rows
            ),
            "legally_verified_source_count": sum(
                row["metadata"].get("legal_verification_status") == "verified"
                for row in rows
            ),
            "captured_legal_evidence_source_count": sum(
                row["metadata"].get("captured_legal_evidence") is True
                for row in rows
            ),
            "runtime_activation": False,
            "proof_binding": False,
        }

    def list_active_sources(self, *, limit: int = 0) -> list[dict[str, Any]]:
        sql = "SELECT * FROM official_sources WHERE active ORDER BY program, canonical_url"
        params: tuple[Any, ...] = ()
        if limit > 0:
            sql += " LIMIT %s"
            params = (limit,)
        with self.connection() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    def enqueue_source_fetch_batch(
        self,
        *,
        registry_version: str,
        registry_manifest_sha256: str,
        capture_id: str,
        limit: int = 0,
    ) -> dict[str, Any]:
        from psycopg.types.json import Jsonb

        if not registry_version.strip() or not capture_id.strip():
            raise ValueError("source fetch registry version and capture ID are required")
        if (
            len(registry_manifest_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in registry_manifest_sha256
            )
        ):
            raise ValueError("source fetch registry manifest hash must be SHA-256")
        sources = [
            source
            for source in self.list_active_sources(limit=limit)
            if source["registry_version"] == registry_version
        ]
        if not sources:
            raise CorpusDatabaseError("source fetch batch has no active registry sources")
        configuration = {
            "kind": "official_source_snapshot",
            "capture_id": capture_id,
            "registry_manifest_sha256": registry_manifest_sha256,
            "source_ids": [source["source_id"] for source in sources],
            "runtime_activation": False,
            "proof_binding": False,
        }
        idempotency_key = canonical_sha256(configuration)
        batch_id = stable_id("source-fetch-batch", idempotency_key)
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO extraction_batches (
                    batch_id, schema_version, registry_version, status,
                    configuration, idempotency_key
                ) VALUES (%s, 'localbce-source-fetch-batch-v1', %s, 'pending', %s, %s)
                ON CONFLICT (idempotency_key) DO NOTHING
                """,
                (batch_id, registry_version, Jsonb(configuration), idempotency_key),
            )
            persisted = conn.execute(
                """
                SELECT batch_id, registry_version, configuration
                FROM extraction_batches WHERE idempotency_key = %s
                """,
                (idempotency_key,),
            ).fetchone()
            if (
                not persisted
                or persisted["batch_id"] != batch_id
                or persisted["registry_version"] != registry_version
                or persisted["configuration"] != configuration
            ):
                raise CorpusDatabaseError(
                    "persisted source fetch batch does not match its idempotency key"
                )
            for source in sources:
                fetch_job_id = stable_id(
                    "source-fetch", batch_id, source["source_id"]
                )
                conn.execute(
                    """
                    INSERT INTO source_fetch_jobs (
                        fetch_job_id, batch_id, source_id, canonical_url, status
                    ) VALUES (%s, %s, %s, %s, 'pending')
                    ON CONFLICT (batch_id, source_id) DO NOTHING
                    """,
                    (
                        fetch_job_id,
                        batch_id,
                        source["source_id"],
                        source["canonical_url"],
                    ),
                )
            summary = self._refresh_source_fetch_batch_status(conn, batch_id)
            conn.commit()
        return {
            **summary,
            "capture_id": capture_id,
            "registry_manifest_sha256": registry_manifest_sha256,
            "runtime_activation": False,
            "proof_binding": False,
        }

    def claim_source_fetch_jobs(
        self,
        batch_id: str,
        *,
        worker_id: str,
        limit: int,
        lease_seconds: int,
    ) -> list[dict[str, Any]]:
        if not worker_id.strip():
            raise ValueError("source fetch worker ID is required")
        if limit <= 0 or lease_seconds <= 0:
            raise ValueError("source fetch claim limit and lease must be positive")
        with self.connection() as conn:
            conn.execute(
                """
                UPDATE source_fetch_jobs
                SET status = CASE
                        WHEN attempts >= attempt_limit THEN 'failed'
                        ELSE 'pending'
                    END,
                    lease_owner = NULL,
                    lease_expires_at = NULL,
                    last_error = CASE
                        WHEN attempts >= attempt_limit
                            THEN COALESCE(last_error, 'source fetch lease expired')
                        ELSE last_error
                    END
                WHERE batch_id = %s AND status = 'leased'
                  AND (lease_expires_at IS NULL OR lease_expires_at <= now())
                """,
                (batch_id,),
            )
            rows = conn.execute(
                """
                WITH claimable AS (
                    SELECT fetch_job_id
                    FROM source_fetch_jobs
                    WHERE batch_id = %s AND status = 'pending'
                      AND attempts < attempt_limit
                      AND (next_attempt_at IS NULL OR next_attempt_at <= now())
                    ORDER BY created_at, fetch_job_id
                    FOR UPDATE SKIP LOCKED
                    LIMIT %s
                ), claimed AS (
                    UPDATE source_fetch_jobs AS jobs
                    SET status = 'leased', lease_owner = %s,
                        lease_expires_at = now() + make_interval(secs => %s),
                        next_attempt_at = NULL,
                        attempts = attempts + 1
                    FROM claimable
                    WHERE jobs.fetch_job_id = claimable.fetch_job_id
                    RETURNING jobs.*
                )
                SELECT claimed.*, sources.program, sources.jurisdiction,
                       sources.issuer, sources.source_type, sources.required
                FROM claimed JOIN official_sources sources USING (source_id)
                ORDER BY claimed.created_at, claimed.fetch_job_id
                """,
                (batch_id, limit, worker_id, lease_seconds),
            ).fetchall()
            self._refresh_source_fetch_batch_status(conn, batch_id)
            conn.commit()
        return [dict(row) for row in rows]

    def renew_source_fetch_lease(
        self,
        fetch_job_id: str,
        *,
        worker_id: str,
        lease_seconds: int,
    ) -> None:
        if not worker_id.strip() or lease_seconds <= 0:
            raise ValueError("source fetch worker and positive lease are required")
        with self.connection() as conn:
            cursor = conn.execute(
                """
                UPDATE source_fetch_jobs
                SET lease_expires_at = now() + make_interval(secs => %s),
                    lease_renewals = lease_renewals + 1
                WHERE fetch_job_id = %s AND status = 'leased'
                  AND lease_owner = %s AND lease_expires_at > now()
                """,
                (lease_seconds, fetch_job_id, worker_id),
            )
            if cursor.rowcount != 1:
                raise CorpusDatabaseError("source fetch lease is missing or expired")
            conn.commit()

    def retry_failed_source_fetch_jobs(
        self,
        batch_id: str,
        *,
        limit: int,
        additional_attempts: int = 5,
    ) -> int:
        if limit <= 0 or additional_attempts <= 0:
            raise ValueError("source fetch retry limit and attempts must be positive")
        with self.connection() as conn:
            cursor = conn.execute(
                """
                WITH retryable AS (
                    SELECT fetch_job_id FROM source_fetch_jobs
                    WHERE batch_id = %s AND status = 'failed'
                    ORDER BY created_at, fetch_job_id
                    FOR UPDATE SKIP LOCKED
                    LIMIT %s
                )
                UPDATE source_fetch_jobs AS jobs
                SET status = 'pending',
                    attempt_limit = attempt_limit + %s,
                    retry_rounds = retry_rounds + 1,
                    lease_owner = NULL, lease_expires_at = NULL,
                    next_attempt_at = NULL,
                    last_error = NULL
                FROM retryable
                WHERE jobs.fetch_job_id = retryable.fetch_job_id
                """,
                (batch_id, limit, additional_attempts),
            )
            self._refresh_source_fetch_batch_status(conn, batch_id)
            conn.commit()
        return cursor.rowcount

    def complete_source_fetch_job(
        self,
        fetch_job_id: str,
        *,
        worker_id: str,
        snapshot: dict[str, Any],
        response_headers: dict[str, str],
    ) -> str:
        with self.connection() as conn:
            job = conn.execute(
                """
                SELECT *, lease_expires_at > now() AS lease_live
                FROM source_fetch_jobs
                WHERE fetch_job_id = %s FOR UPDATE
                """,
                (fetch_job_id,),
            ).fetchone()
            if (
                not job
                or job["status"] != "leased"
                or job["lease_owner"] != worker_id
                or not job["lease_live"]
            ):
                raise CorpusDatabaseError(
                    "source fetch job is not leased by this live worker"
                )
            if snapshot.get("source_id") != job["source_id"]:
                raise CorpusDatabaseError("source fetch snapshot source ID mismatch")
            retrieval_id = self._save_snapshot_with_connection(
                conn, snapshot, response_headers=response_headers
            )
            conn.execute(
                """
                UPDATE source_fetch_jobs
                SET status = 'completed', snapshot_hash = %s, retrieval_id = %s,
                    lease_owner = NULL, lease_expires_at = NULL,
                    last_error = NULL, completed_at = now()
                WHERE fetch_job_id = %s
                """,
                (snapshot["snapshot_hash"], retrieval_id, fetch_job_id),
            )
            self._refresh_source_fetch_batch_status(conn, job["batch_id"])
            conn.commit()
        return retrieval_id

    def fail_source_fetch_job(
        self,
        fetch_job_id: str,
        *,
        worker_id: str,
        error: str,
        retry_delay_seconds: int = 30,
    ) -> str:
        if retry_delay_seconds < 0:
            raise ValueError("source fetch retry delay cannot be negative")
        with self.connection() as conn:
            job = conn.execute(
                """
                SELECT batch_id, attempts, attempt_limit
                FROM source_fetch_jobs
                WHERE fetch_job_id = %s AND status = 'leased'
                  AND lease_owner = %s AND lease_expires_at > now()
                FOR UPDATE
                """,
                (fetch_job_id, worker_id),
            ).fetchone()
            if not job:
                raise CorpusDatabaseError(
                    "source fetch lease was lost before failure recording"
                )
            status = (
                "pending"
                if int(job["attempts"]) < int(job["attempt_limit"])
                else "failed"
            )
            conn.execute(
                """
                UPDATE source_fetch_jobs
                SET status = %s, lease_owner = NULL, lease_expires_at = NULL,
                    next_attempt_at = CASE
                        WHEN %s = 'pending'
                            THEN now() + make_interval(secs => %s)
                        ELSE NULL
                    END,
                    last_error = %s
                WHERE fetch_job_id = %s
                """,
                (status, status, retry_delay_seconds, error[:4000], fetch_job_id),
            )
            self._refresh_source_fetch_batch_status(conn, job["batch_id"])
            conn.commit()
        return status

    def source_fetch_batch_summary(self, batch_id: str) -> dict[str, Any]:
        with self.connection() as conn:
            summary = self._refresh_source_fetch_batch_status(conn, batch_id)
            conn.commit()
        return {
            **summary,
            "runtime_activation": False,
            "proof_binding": False,
        }

    def _refresh_source_fetch_batch_status(
        self, conn: Any, batch_id: str
    ) -> dict[str, Any]:
        rows = conn.execute(
            """
            SELECT status, count(*) AS count
            FROM source_fetch_jobs WHERE batch_id = %s
            GROUP BY status
            """,
            (batch_id,),
        ).fetchall()
        counts = {str(row["status"]): int(row["count"]) for row in rows}
        total = sum(counts.values())
        if total == 0:
            raise CorpusDatabaseError("source fetch batch has no jobs")
        if counts.get("completed", 0) == total:
            status = "completed"
        elif counts.get("pending", 0) == 0 and counts.get("leased", 0) == 0:
            status = "failed"
        elif counts.get("leased", 0) or counts.get("completed", 0):
            status = "running"
        else:
            status = "pending"
        batch = conn.execute(
            """
            UPDATE extraction_batches
            SET status = %s,
                started_at = CASE
                    WHEN %s = 'running' THEN COALESCE(started_at, now())
                    ELSE started_at
                END,
                completed_at = CASE
                    WHEN %s IN ('completed', 'failed')
                        THEN COALESCE(completed_at, now())
                    ELSE NULL
                END
            WHERE batch_id = %s
            RETURNING batch_id, registry_version, status, configuration,
                      created_at, started_at, completed_at
            """,
            (status, status, status, batch_id),
        ).fetchone()
        if not batch:
            raise CorpusDatabaseError("source fetch batch does not exist")
        batch_payload = dict(batch)
        for field in ("created_at", "started_at", "completed_at"):
            value = batch_payload.get(field)
            if value is not None:
                batch_payload[field] = value.isoformat()
        return {
            **batch_payload,
            "job_counts": {
                name: counts.get(name, 0)
                for name in ("pending", "leased", "completed", "failed")
            },
            "job_count": total,
        }

    def save_snapshot(
        self,
        snapshot: dict[str, Any],
        *,
        response_headers: dict[str, str] | None = None,
    ) -> str:
        with self.connection() as conn:
            retrieval_id = self._save_snapshot_with_connection(
                conn, snapshot, response_headers=response_headers or {}
            )
            conn.commit()
        return retrieval_id

    def _save_snapshot_with_connection(
        self,
        conn: Any,
        snapshot: dict[str, Any],
        *,
        response_headers: dict[str, str],
    ) -> str:
        from psycopg.types.json import Jsonb

        self._lock_source_registry_lineage(conn)
        retrieval_id = stable_id(
            "ret",
            snapshot["source_id"],
            snapshot["snapshot_hash"],
            snapshot["retrieved_at"],
        )
        conn.execute(
            """
            INSERT INTO source_snapshots (
                snapshot_hash, mime_type, compression, compressed_bytes,
                uncompressed_size, text_layer_kind
            ) VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (snapshot_hash) DO NOTHING
            """,
            (
                snapshot["snapshot_hash"],
                snapshot["mime_type"],
                snapshot["compression"],
                snapshot["compressed_bytes"],
                snapshot["uncompressed_size"],
                snapshot["text_layer_kind"],
            ),
        )
        conn.execute(
            """
            INSERT INTO source_snapshot_retrievals (
                retrieval_id, snapshot_hash, source_id, canonical_url, retrieved_at,
                http_status, issuer, effective_metadata, response_headers
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (retrieval_id) DO NOTHING
            """,
            (
                retrieval_id,
                snapshot["snapshot_hash"],
                snapshot["source_id"],
                snapshot["canonical_url"],
                snapshot["retrieved_at"],
                snapshot["http_status"],
                snapshot["issuer"],
                Jsonb(snapshot["effective_metadata"]),
                Jsonb(response_headers),
            ),
        )
        return retrieval_id

    def ocr_ingest_target(self, retrieval_id: str) -> dict[str, Any]:
        if not retrieval_id.strip():
            raise ValueError("OCR retrieval_id is required")
        with self.connection() as conn:
            target = self._ocr_ingest_target_with_connection(conn, retrieval_id)
        return target

    @staticmethod
    def _ocr_ingest_target_with_connection(
        conn: Any, retrieval_id: str
    ) -> dict[str, Any]:
        target = conn.execute(
            """
            SELECT retrievals.retrieval_id, retrievals.snapshot_hash,
                   retrievals.canonical_url, sources.program,
                   snapshots.mime_type, snapshots.text_layer_kind,
                   (
                       SELECT count(*)
                       FROM source_sections sections
                       WHERE sections.snapshot_hash = retrievals.snapshot_hash
                         AND sections.active
                   ) AS active_section_count,
                   EXISTS (
                       SELECT 1 FROM section_extraction_jobs jobs
                       WHERE jobs.retrieval_id = retrievals.retrieval_id
                         AND jobs.status = 'failed'
                         AND (
                             jobs.last_error ILIKE '%%no usable text layer%%'
                             OR jobs.last_error ILIKE '%%OCR review is required%%'
                         )
                   ) AS terminal_no_text_failure,
                   EXISTS (
                       SELECT 1 FROM source_ocr_artifacts artifacts
                       WHERE artifacts.retrieval_id = retrievals.retrieval_id
                   ) AS existing_ocr_artifact
            FROM source_snapshot_retrievals retrievals
            JOIN source_snapshots snapshots USING (snapshot_hash)
            JOIN official_sources sources USING (source_id)
            WHERE retrievals.retrieval_id = %s AND sources.active
            """,
            (retrieval_id,),
        ).fetchone()
        if not target:
            raise CorpusDatabaseError(
                "OCR target retrieval does not exist or its source is inactive"
            )
        payload = dict(target)
        if payload["mime_type"] != "application/pdf":
            raise CorpusDatabaseError("OCR artifact ingestion is limited to PDF sources")
        if not (
            payload["text_layer_kind"] == "none"
            or payload["terminal_no_text_failure"]
            or payload["existing_ocr_artifact"]
        ):
            raise CorpusDatabaseError(
                "OCR artifact requires a terminal no-text extraction failure"
            )
        return payload

    def save_ocr_artifact(
        self,
        artifact: dict[str, Any],
        sections: list[dict[str, Any]],
    ) -> dict[str, Any]:
        from psycopg.types.json import Jsonb

        from .scaled_corpus import (
            OCR_ARTIFACT_SCHEMA,
            normalize_source_text,
            restore_ocr_artifact_bytes,
        )

        if artifact.get("schema_version") != OCR_ARTIFACT_SCHEMA:
            raise ValueError("unsupported OCR artifact schema")
        if artifact.get("runtime_activation") is not False:
            raise ValueError("OCR artifact runtime_activation must be false")
        if artifact.get("proof_binding") is not False:
            raise ValueError("OCR artifact proof_binding must be false")
        raw = restore_ocr_artifact_bytes(artifact)
        normalized = normalize_source_text(raw.decode("utf-8"))
        if normalized != artifact.get("normalized_text"):
            raise ValueError("OCR artifact normalized text mismatch")
        if hashlib.sha256(normalized.encode("utf-8")).hexdigest() != artifact.get(
            "normalized_text_hash"
        ):
            raise ValueError("OCR artifact normalized text hash mismatch")
        if not sections:
            raise ValueError("OCR artifact produced no sections")
        expected_locator = {
            "ocr_artifact_id": artifact["ocr_artifact_id"],
            "ocr_artifact_hash": artifact["artifact_hash"],
        }
        for section in sections:
            locator = section.get("source_locator") or {}
            if section.get("snapshot_hash") != artifact["snapshot_hash"]:
                raise ValueError("OCR section snapshot hash mismatch")
            if section.get("ocr_used") is not True:
                raise ValueError("OCR section must set ocr_used=true")
            for field, value in expected_locator.items():
                if locator.get(field) != value:
                    raise ValueError(f"OCR section source locator {field} mismatch")

        generated_at = datetime.fromisoformat(
            str(artifact["generated_at"]).replace("Z", "+00:00")
        )
        with self.connection() as conn:
            target = self._ocr_ingest_target_with_connection(
                conn, artifact["retrieval_id"]
            )
            if target["snapshot_hash"] != artifact["snapshot_hash"]:
                raise CorpusDatabaseError("OCR artifact snapshot lineage mismatch")
            existing = conn.execute(
                """
                SELECT * FROM source_ocr_artifacts
                WHERE retrieval_id = %s AND artifact_hash = %s
                  AND engine_name = %s AND engine_version = %s
                """,
                (
                    artifact["retrieval_id"],
                    artifact["artifact_hash"],
                    artifact["engine_name"],
                    artifact["engine_version"],
                ),
            ).fetchone()
            if existing:
                existing_payload = dict(existing)
                expected_existing = {
                    "ocr_artifact_id": artifact["ocr_artifact_id"],
                    "uncompressed_size": artifact["uncompressed_size"],
                    "normalized_text_hash": artifact["normalized_text_hash"],
                    "operator_id": artifact["operator_id"],
                    "generated_at": generated_at,
                    "metadata": artifact["metadata"],
                }
                for field, value in expected_existing.items():
                    if existing_payload[field] != value:
                        raise CorpusDatabaseError(
                            f"existing OCR artifact has different {field}"
                        )
                if bytes(existing_payload["compressed_bytes"]) != artifact["compressed_bytes"]:
                    raise CorpusDatabaseError(
                        "existing OCR artifact has different compressed bytes"
                    )
            elif int(target["active_section_count"]) > 0:
                raise CorpusDatabaseError(
                    "OCR artifact cannot replace existing active source sections"
                )
            else:
                conn.execute(
                    """
                    INSERT INTO source_ocr_artifacts (
                        ocr_artifact_id, retrieval_id, artifact_hash, compression,
                        compressed_bytes, uncompressed_size, normalized_text_hash,
                        engine_name, engine_version, operator_id, generated_at, metadata
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        artifact["ocr_artifact_id"],
                        artifact["retrieval_id"],
                        artifact["artifact_hash"],
                        artifact["compression"],
                        artifact["compressed_bytes"],
                        artifact["uncompressed_size"],
                        artifact["normalized_text_hash"],
                        artifact["engine_name"],
                        artifact["engine_version"],
                        artifact["operator_id"],
                        generated_at,
                        Jsonb(artifact["metadata"]),
                    ),
                )

            count = self._save_sections_with_connection(
                conn,
                artifact["retrieval_id"],
                sections,
                activate_pipeline=True,
            )
            for section in sections:
                conn.execute(
                    """
                    INSERT INTO source_ocr_artifact_sections (
                        ocr_artifact_id, section_id
                    ) VALUES (%s, %s)
                    ON CONFLICT (ocr_artifact_id, section_id) DO NOTHING
                    """,
                    (artifact["ocr_artifact_id"], section["section_id"]),
                )
            active_counts = conn.execute(
                """
                SELECT count(*) AS active_count,
                       count(links.section_id) AS linked_count
                FROM source_sections sections
                LEFT JOIN source_ocr_artifact_sections links
                  ON links.section_id = sections.section_id
                 AND links.ocr_artifact_id = %s
                WHERE sections.snapshot_hash = %s AND sections.active
                """,
                (artifact["ocr_artifact_id"], artifact["snapshot_hash"]),
            ).fetchone()
            if active_counts["active_count"] != active_counts["linked_count"]:
                raise CorpusDatabaseError(
                    "active OCR sections are not fully linked to the artifact"
                )
            conn.commit()
        return {
            "schema_version": OCR_ARTIFACT_SCHEMA,
            "ocr_artifact_id": artifact["ocr_artifact_id"],
            "retrieval_id": artifact["retrieval_id"],
            "snapshot_hash": artifact["snapshot_hash"],
            "artifact_hash": artifact["artifact_hash"],
            "section_count": count,
            "engine_name": artifact["engine_name"],
            "engine_version": artifact["engine_version"],
            "operator_id": artifact["operator_id"],
            "generated_at": artifact["generated_at"],
            "mandatory_quality_review": True,
            "runtime_activation": False,
            "proof_binding": False,
        }

    @staticmethod
    def _lock_source_registry_lineage(conn: Any) -> None:
        """Serialize short snapshot/approval commits without serializing fetches."""
        conn.execute(
            """
            SELECT pg_advisory_xact_lock(
                hashtextextended('localbce-source-registry-lineage-v1', 0)
            )
            """
        )

    def save_sections(self, retrieval_id: str, sections: list[dict[str, Any]]) -> int:
        with self.connection() as conn:
            count = self._save_sections_with_connection(
                conn, retrieval_id, sections, activate_pipeline=False
            )
            conn.commit()
        return count

    def _save_sections_with_connection(
        self,
        conn: Any,
        retrieval_id: str,
        sections: list[dict[str, Any]],
        *,
        activate_pipeline: bool,
    ) -> int:
        from psycopg.types.json import Jsonb

        if not sections:
            raise ValueError("section extraction produced no sections")
        pipeline_versions = {
            str(section.get("extraction_pipeline_version") or "legacy-v1")
            for section in sections
        }
        if len(pipeline_versions) != 1:
            raise ValueError("section extraction must use exactly one pipeline version")
        pipeline_version = next(iter(pipeline_versions))
        snapshot_hashes = {str(section["snapshot_hash"]) for section in sections}
        if len(snapshot_hashes) != 1:
            raise ValueError("section extraction must use exactly one snapshot")
        snapshot_hash = next(iter(snapshot_hashes))
        if activate_pipeline:
            conn.execute(
                """
                UPDATE source_sections SET active = false
                WHERE snapshot_hash = %s AND extraction_pipeline_version <> %s
                  AND active
                """,
                (snapshot_hash, pipeline_version),
            )
        for section in sections:
            conn.execute(
                """
                INSERT INTO source_sections (
                    section_id, snapshot_hash, retrieval_id, parent_section_id, ordinal,
                    hierarchy_path, heading, normalized_text, normalized_text_hash,
                    source_char_start, source_char_end, parser_name, parser_version,
                    extraction_pipeline_version, active, ocr_used, source_locator
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, true, %s, %s
                )
                ON CONFLICT (section_id) DO UPDATE SET active = true
                """,
                (
                    section["section_id"],
                    section["snapshot_hash"],
                    retrieval_id,
                    section.get("parent_section_id"),
                    section["ordinal"],
                    Jsonb(section["hierarchy_path"]),
                    section.get("heading"),
                    section["normalized_text"],
                    section["normalized_text_hash"],
                    section.get("source_char_start"),
                    section.get("source_char_end"),
                    section["parser_name"],
                    section["parser_version"],
                    pipeline_version,
                    section["ocr_used"],
                    Jsonb(section.get("source_locator", {})),
                ),
            )
            conn.execute(
                """
                INSERT INTO source_section_retrieval_links (
                    section_id, retrieval_id
                ) VALUES (%s, %s)
                ON CONFLICT (section_id, retrieval_id) DO NOTHING
                """,
                (section["section_id"], retrieval_id),
            )
        return len(sections)

    def unsectioned_retrievals(self, *, limit: int = 0) -> list[dict[str, Any]]:
        sql = """
            SELECT retrievals.*, snapshots.mime_type, snapshots.compression,
                   snapshots.compressed_bytes, snapshots.uncompressed_size,
                   snapshots.text_layer_kind
            FROM source_snapshot_retrievals retrievals
            JOIN source_snapshots snapshots USING (snapshot_hash)
            WHERE NOT EXISTS (
                SELECT 1 FROM source_section_retrieval_links links
                WHERE links.retrieval_id = retrievals.retrieval_id
            )
            ORDER BY retrievals.retrieved_at, retrievals.retrieval_id
        """
        params: tuple[Any, ...] = ()
        if limit > 0:
            sql += " LIMIT %s"
            params = (limit,)
        with self.connection() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    def enqueue_section_extraction_jobs(
        self,
        *,
        pipeline_version: str,
        limit: int = 0,
    ) -> dict[str, Any]:
        if not pipeline_version.strip():
            raise ValueError("section extraction pipeline version is required")
        if limit < 0:
            raise ValueError("section extraction enqueue limit cannot be negative")
        sql = """
            SELECT retrievals.retrieval_id, retrievals.snapshot_hash
            FROM source_snapshot_retrievals retrievals
            JOIN official_sources sources USING (source_id)
            WHERE sources.active
              AND NOT EXISTS (
                SELECT 1 FROM section_extraction_jobs jobs
                WHERE jobs.retrieval_id = retrievals.retrieval_id
                  AND jobs.pipeline_version = %s
            )
            ORDER BY retrievals.retrieved_at, retrievals.retrieval_id
        """
        params: list[Any] = [pipeline_version]
        if limit > 0:
            sql += " LIMIT %s"
            params.append(limit)
        inserted = 0
        with self.connection() as conn:
            retrievals = conn.execute(sql, tuple(params)).fetchall()
            for retrieval in retrievals:
                extraction_job_id = stable_id(
                    "section-extraction",
                    retrieval["retrieval_id"],
                    retrieval["snapshot_hash"],
                    pipeline_version,
                )
                cursor = conn.execute(
                    """
                    INSERT INTO section_extraction_jobs (
                        extraction_job_id, retrieval_id, snapshot_hash,
                        pipeline_version, status
                    ) VALUES (%s, %s, %s, %s, 'pending')
                    ON CONFLICT (retrieval_id, pipeline_version) DO NOTHING
                    """,
                    (
                        extraction_job_id,
                        retrieval["retrieval_id"],
                        retrieval["snapshot_hash"],
                        pipeline_version,
                    ),
                )
                inserted += cursor.rowcount
            conn.commit()
        return {
            **self.section_extraction_summary(pipeline_version),
            "jobs_inserted": inserted,
        }

    def claim_section_extraction_jobs(
        self,
        *,
        pipeline_version: str,
        worker_id: str,
        limit: int,
        lease_seconds: int,
    ) -> list[dict[str, Any]]:
        if not pipeline_version.strip() or not worker_id.strip():
            raise ValueError("section extraction pipeline and worker are required")
        if limit <= 0 or lease_seconds <= 0:
            raise ValueError("section extraction claim limit and lease must be positive")
        with self.connection() as conn:
            conn.execute(
                """
                UPDATE section_extraction_jobs jobs
                SET status = 'failed', lease_owner = NULL,
                    lease_expires_at = NULL, next_attempt_at = NULL,
                    last_error = 'source registry entry was superseded'
                FROM source_snapshot_retrievals retrievals,
                     official_sources sources
                WHERE jobs.retrieval_id = retrievals.retrieval_id
                  AND retrievals.source_id = sources.source_id
                  AND NOT sources.active
                  AND jobs.status IN ('pending', 'leased')
                """
            )
            conn.execute(
                """
                UPDATE section_extraction_jobs
                SET status = CASE
                        WHEN attempts >= attempt_limit THEN 'failed'
                        ELSE 'pending'
                    END,
                    lease_owner = NULL,
                    lease_expires_at = NULL,
                    last_error = CASE
                        WHEN attempts >= attempt_limit
                            THEN COALESCE(last_error, 'section extraction lease expired')
                        ELSE last_error
                    END
                WHERE pipeline_version = %s AND status = 'leased'
                  AND (lease_expires_at IS NULL OR lease_expires_at <= now())
                """,
                (pipeline_version,),
            )
            rows = conn.execute(
                """
                WITH claimable AS (
                    SELECT extraction_job_id
                    FROM section_extraction_jobs
                    WHERE pipeline_version = %s AND status = 'pending'
                      AND attempts < attempt_limit
                      AND (next_attempt_at IS NULL OR next_attempt_at <= now())
                    ORDER BY created_at, extraction_job_id
                    FOR UPDATE SKIP LOCKED
                    LIMIT %s
                ), claimed AS (
                    UPDATE section_extraction_jobs AS jobs
                    SET status = 'leased', lease_owner = %s,
                        lease_expires_at = now() + make_interval(secs => %s),
                        next_attempt_at = NULL,
                        attempts = attempts + 1
                    FROM claimable
                    WHERE jobs.extraction_job_id = claimable.extraction_job_id
                    RETURNING jobs.*
                )
                SELECT claimed.*, retrievals.canonical_url,
                       retrievals.retrieved_at, retrievals.http_status,
                       retrievals.issuer, retrievals.effective_metadata,
                       retrievals.response_headers, snapshots.mime_type,
                       snapshots.compression, snapshots.compressed_bytes,
                       snapshots.uncompressed_size, snapshots.text_layer_kind,
                       sources.program
                FROM claimed
                JOIN source_snapshot_retrievals retrievals
                  ON retrievals.retrieval_id = claimed.retrieval_id
                JOIN source_snapshots snapshots
                  ON snapshots.snapshot_hash = retrievals.snapshot_hash
                JOIN official_sources sources
                  ON sources.source_id = retrievals.source_id
                ORDER BY claimed.created_at, claimed.extraction_job_id
                """,
                (pipeline_version, limit, worker_id, lease_seconds),
            ).fetchall()
            conn.commit()
        return [dict(row) for row in rows]

    def renew_section_extraction_lease(
        self,
        extraction_job_id: str,
        *,
        worker_id: str,
        lease_seconds: int,
    ) -> None:
        if not worker_id.strip() or lease_seconds <= 0:
            raise ValueError("section extraction worker and lease are required")
        with self.connection() as conn:
            cursor = conn.execute(
                """
                UPDATE section_extraction_jobs
                SET lease_expires_at = now() + make_interval(secs => %s),
                    lease_renewals = lease_renewals + 1
                WHERE extraction_job_id = %s AND status = 'leased'
                  AND lease_owner = %s AND lease_expires_at > now()
                """,
                (lease_seconds, extraction_job_id, worker_id),
            )
            if cursor.rowcount != 1:
                raise CorpusDatabaseError(
                    "section extraction lease is missing or expired"
                )
            conn.commit()

    def retry_failed_section_extraction_jobs(
        self,
        *,
        pipeline_version: str,
        limit: int,
        additional_attempts: int = 5,
    ) -> int:
        if limit <= 0 or additional_attempts <= 0:
            raise ValueError(
                "section extraction retry limit and attempts must be positive"
            )
        with self.connection() as conn:
            cursor = conn.execute(
                """
                WITH retryable AS (
                    SELECT jobs.extraction_job_id
                    FROM section_extraction_jobs jobs
                    JOIN source_snapshot_retrievals retrievals USING (retrieval_id)
                    JOIN official_sources sources USING (source_id)
                    WHERE sources.active
                      AND jobs.pipeline_version = %s AND jobs.status = 'failed'
                    ORDER BY jobs.created_at, jobs.extraction_job_id
                    FOR UPDATE SKIP LOCKED
                    LIMIT %s
                )
                UPDATE section_extraction_jobs AS jobs
                SET status = 'pending',
                    attempt_limit = attempt_limit + %s,
                    retry_rounds = retry_rounds + 1,
                    lease_owner = NULL, lease_expires_at = NULL,
                    next_attempt_at = NULL, last_error = NULL
                FROM retryable
                WHERE jobs.extraction_job_id = retryable.extraction_job_id
                """,
                (pipeline_version, limit, additional_attempts),
            )
            conn.commit()
        return cursor.rowcount

    def complete_section_extraction_job(
        self,
        extraction_job_id: str,
        *,
        worker_id: str,
        sections: list[dict[str, Any]],
        warnings: list[str],
    ) -> int:
        from psycopg.types.json import Jsonb

        with self.connection() as conn:
            job = conn.execute(
                """
                SELECT jobs.*, lease_expires_at > now() AS lease_live,
                       sources.active AS source_active
                FROM section_extraction_jobs jobs
                JOIN source_snapshot_retrievals retrievals USING (retrieval_id)
                JOIN official_sources sources USING (source_id)
                WHERE extraction_job_id = %s
                FOR UPDATE OF jobs
                FOR SHARE OF sources
                """,
                (extraction_job_id,),
            ).fetchone()
            if (
                not job
                or job["status"] != "leased"
                or job["lease_owner"] != worker_id
                or not job["lease_live"]
                or not job["source_active"]
            ):
                raise CorpusDatabaseError(
                    "section extraction job lacks a live lease or active source"
                )
            if not sections:
                raise CorpusDatabaseError("section extraction produced no sections")
            if any(
                section.get("snapshot_hash") != job["snapshot_hash"]
                or section.get("extraction_pipeline_version")
                != job["pipeline_version"]
                for section in sections
            ):
                raise CorpusDatabaseError(
                    "section extraction output does not match job lineage"
                )
            parser_names = {section.get("parser_name") for section in sections}
            parser_versions = {section.get("parser_version") for section in sections}
            if (
                len(parser_names) != 1
                or len(parser_versions) != 1
                or not next(iter(parser_names))
                or not next(iter(parser_versions))
            ):
                raise CorpusDatabaseError(
                    "section extraction output has a missing or mixed parser identity"
                )
            count = self._save_sections_with_connection(
                conn,
                job["retrieval_id"],
                sections,
                activate_pipeline=True,
            )
            conn.execute(
                """
                UPDATE section_extraction_jobs
                SET status = 'completed', parser_name = %s, parser_version = %s,
                    section_count = %s, warnings = %s,
                    lease_owner = NULL, lease_expires_at = NULL,
                    next_attempt_at = NULL, last_error = NULL,
                    completed_at = now()
                WHERE extraction_job_id = %s
                """,
                (
                    next(iter(parser_names)),
                    next(iter(parser_versions)),
                    count,
                    Jsonb(warnings),
                    extraction_job_id,
                ),
            )
            conn.commit()
        return count

    def fail_section_extraction_job(
        self,
        extraction_job_id: str,
        *,
        worker_id: str,
        error: str,
        retry_delay_seconds: int = 30,
    ) -> str:
        if retry_delay_seconds < 0:
            raise ValueError("section extraction retry delay cannot be negative")
        with self.connection() as conn:
            job = conn.execute(
                """
                SELECT attempts, attempt_limit
                FROM section_extraction_jobs
                WHERE extraction_job_id = %s AND status = 'leased'
                  AND lease_owner = %s AND lease_expires_at > now()
                FOR UPDATE
                """,
                (extraction_job_id, worker_id),
            ).fetchone()
            if not job:
                raise CorpusDatabaseError(
                    "section extraction lease was lost before failure recording"
                )
            status = (
                "pending"
                if int(job["attempts"]) < int(job["attempt_limit"])
                else "failed"
            )
            conn.execute(
                """
                UPDATE section_extraction_jobs
                SET status = %s, lease_owner = NULL, lease_expires_at = NULL,
                    next_attempt_at = CASE
                        WHEN %s = 'pending'
                            THEN now() + make_interval(secs => %s)
                        ELSE NULL
                    END,
                    last_error = %s
                WHERE extraction_job_id = %s
                """,
                (
                    status,
                    status,
                    retry_delay_seconds,
                    error[:4000],
                    extraction_job_id,
                ),
            )
            conn.commit()
        return status

    def section_extraction_summary(self, pipeline_version: str) -> dict[str, Any]:
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT status, count(*) AS count,
                       coalesce(sum(section_count), 0) AS section_count,
                       coalesce(sum(attempts), 0) AS attempts,
                       coalesce(sum(lease_renewals), 0) AS lease_renewals
                FROM section_extraction_jobs
                WHERE pipeline_version = %s
                GROUP BY status
                """,
                (pipeline_version,),
            ).fetchall()
        counts = {str(row["status"]): int(row["count"]) for row in rows}
        return {
            "pipeline_version": pipeline_version,
            "job_counts": {
                name: counts.get(name, 0)
                for name in ("pending", "leased", "completed", "failed")
            },
            "job_count": sum(counts.values()),
            "sections_created": sum(int(row["section_count"]) for row in rows),
            "attempts": sum(int(row["attempts"]) for row in rows),
            "lease_renewals": sum(int(row["lease_renewals"]) for row in rows),
            "runtime_activation": False,
            "proof_binding": False,
        }

    def undiscovered_retrievals(
        self, *, parser_version: str, limit: int = 0
    ) -> list[dict[str, Any]]:
        sql = """
            SELECT retrievals.*, snapshots.mime_type, snapshots.compression,
                   snapshots.compressed_bytes, snapshots.uncompressed_size,
                   snapshots.text_layer_kind, sources.program,
                   sources.source_id AS parent_source_id
            FROM source_snapshot_retrievals retrievals
            JOIN source_snapshots snapshots USING (snapshot_hash)
            JOIN official_sources sources USING (source_id)
            WHERE sources.active
              AND NOT EXISTS (
                SELECT 1 FROM source_discovery_runs runs
                WHERE runs.retrieval_id = retrievals.retrieval_id
                  AND runs.parser_version = %s
            )
            ORDER BY retrievals.retrieved_at, retrievals.retrieval_id
        """
        params: list[Any] = [parser_version]
        if limit > 0:
            sql += " LIMIT %s"
            params.append(limit)
        with self.connection() as conn:
            rows = conn.execute(sql, tuple(params)).fetchall()
        return [dict(row) for row in rows]

    def save_source_discovery(
        self,
        *,
        retrieval: dict[str, Any],
        parser_version: str,
        links: list[dict[str, Any]],
    ) -> dict[str, Any]:
        from psycopg.types.json import Jsonb

        ordered = sorted(links, key=lambda item: item["canonical_url"])
        run_payload = {
            "retrieval_id": retrieval["retrieval_id"],
            "snapshot_hash": retrieval["snapshot_hash"],
            "parser_version": parser_version,
            "program": retrieval["program"],
            "links": ordered,
        }
        run_hash = canonical_sha256(run_payload)
        run_id = stable_id(
            "source-discovery",
            retrieval["retrieval_id"],
            parser_version,
            run_hash,
        )
        inserted = 0
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO source_discovery_runs (
                    discovery_run_id, retrieval_id, snapshot_hash, parser_version,
                    candidate_count, canonical_run_hash
                ) VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (retrieval_id, parser_version) DO NOTHING
                """,
                (
                    run_id,
                    retrieval["retrieval_id"],
                    retrieval["snapshot_hash"],
                    parser_version,
                    len(ordered),
                    run_hash,
                ),
            )
            existing = conn.execute(
                """
                SELECT discovery_run_id, candidate_count, canonical_run_hash
                FROM source_discovery_runs
                WHERE retrieval_id = %s AND parser_version = %s
                """,
                (retrieval["retrieval_id"], parser_version),
            ).fetchone()
            if (
                not existing
                or int(existing["candidate_count"]) != len(ordered)
                or existing["canonical_run_hash"] != run_hash
            ):
                raise CorpusDatabaseError(
                    "persisted source discovery does not match the immutable snapshot"
                )
            for link in ordered:
                candidate_id = stable_id(
                    "source-candidate",
                    retrieval["retrieval_id"],
                    retrieval["program"],
                    link["canonical_url"],
                )
                cursor = conn.execute(
                    """
                    INSERT INTO source_registry_candidates (
                        source_candidate_id, discovery_run_id, parent_source_id,
                        parent_retrieval_id, parent_snapshot_hash, program,
                        candidate_url, link_text, source_locator, review_status
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'pending_review')
                    ON CONFLICT (parent_retrieval_id, program, candidate_url) DO NOTHING
                    """,
                    (
                        candidate_id,
                        existing["discovery_run_id"],
                        retrieval["parent_source_id"],
                        retrieval["retrieval_id"],
                        retrieval["snapshot_hash"],
                        retrieval["program"],
                        link["canonical_url"],
                        link.get("link_text", ""),
                        Jsonb(link["source_locator"]),
                    ),
                )
                inserted += cursor.rowcount
            conn.commit()
        return {
            "discovery_run_id": str(existing["discovery_run_id"]),
            "canonical_run_hash": run_hash,
            "candidate_count": len(ordered),
            "candidates_inserted": inserted,
            "runtime_activation": False,
            "proof_binding": False,
        }

    def preflight_source_registry_candidates(
        self,
        *,
        limit: int = 0,
        target_count: int = SOURCE_REVIEW_MILESTONE_TARGET,
    ) -> dict[str, Any]:
        from psycopg.types.json import Jsonb

        sql = """
            SELECT candidates.*, retrievals.canonical_url AS parent_url,
                   sources.issuer, sources.source_type AS parent_source_type
            FROM source_registry_candidates candidates
            JOIN source_snapshot_retrievals retrievals
              ON retrievals.retrieval_id = candidates.parent_retrieval_id
            JOIN official_sources sources
              ON sources.source_id = candidates.parent_source_id
            WHERE candidates.review_status = 'pending_review'
            ORDER BY candidates.program, candidates.source_candidate_id
        """
        assessed = 0
        with self.connection() as conn:
            self._cancel_stale_source_registry_candidates_with_connection(conn)
            all_rows = conn.execute(sql).fetchall()
            stale_rows = [
                row
                for row in all_rows
                if row["preflight_version"] != SOURCE_CANDIDATE_PREFLIGHT_VERSION
            ]
            if limit > 0:
                stale_rows = stale_rows[:limit]
            selected_keys = {
                (str(row["program"]), str(row["candidate_url"]))
                for row in stale_rows
            }
            peer_rows = [
                row
                for row in all_rows
                if (str(row["program"]), str(row["candidate_url"])) in selected_keys
            ]
            assessments = assess_source_candidate_preflight_batch(
                dict(row) for row in peer_rows
            )
            for assessment in assessments:
                conn.execute(
                    """
                    UPDATE source_registry_candidates
                    SET preflight_version = %s,
                        preflight_score = %s,
                        preflight_blockers = %s,
                        preflight_signals = %s,
                        preflight_hash = %s,
                        preflight_assessed_at = now()
                    WHERE source_candidate_id = %s
                      AND review_status = 'pending_review'
                    """,
                    (
                        SOURCE_CANDIDATE_PREFLIGHT_VERSION,
                        assessment["score"],
                        Jsonb(assessment["blockers"]),
                        Jsonb(assessment["signals"]),
                        assessment["preflight_hash"],
                        assessment["source_candidate_id"],
                    ),
                )
            assessed = len(assessments)
            conn.commit()
        return {
            **self.source_registry_preflight_summary(target_count=target_count),
            "candidates_assessed_this_run": assessed,
        }

    def source_registry_preflight_summary(
        self,
        *,
        target_count: int = SOURCE_REVIEW_MILESTONE_TARGET,
    ) -> dict[str, Any]:
        if target_count not in CORPUS_MILESTONES:
            raise ValueError(
                "source preflight target must be 5100, 51000, or 600000"
            )
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT source_candidate_id, program, candidate_url, link_text,
                       review_status,
                       preflight_score, preflight_blockers, preflight_signals,
                       preflight_hash
                FROM source_registry_candidates
                WHERE review_status IN ('pending_review', 'claimed_review')
                  AND preflight_version = %s
                ORDER BY preflight_score DESC, program, source_candidate_id
                """,
                (SOURCE_CANDIDATE_PREFLIGHT_VERSION,),
            ).fetchall()
            unassessed = conn.execute(
                """
                SELECT count(*) AS count
                FROM source_registry_candidates
                WHERE review_status IN ('pending_review', 'claimed_review')
                  AND preflight_version IS DISTINCT FROM %s
                """,
                (SOURCE_CANDIDATE_PREFLIGHT_VERSION,),
            ).fetchone()
            accepted_rows = conn.execute(
                f"""
                SELECT candidates.primary_program AS program,
                       count(DISTINCT candidates.candidate_id) AS candidate_count
                FROM grounded_candidates candidates
                JOIN source_sections sections USING (section_id)
                JOIN source_section_program_contexts contexts
                  ON contexts.section_id = candidates.section_id
                 AND contexts.program = candidates.primary_program
                 AND contexts.source_active
                WHERE sections.active
                  AND candidates.grounding_status = 'accepted'
                  AND {CURRENT_CANDIDATE_CONTRACT_SQL}
                GROUP BY candidates.primary_program
                ORDER BY candidates.primary_program
                """
            ).fetchall()
            context_rows = conn.execute(
                """
                SELECT contexts.program,
                       count(DISTINCT contexts.section_id)
                           AS active_program_section_count
                FROM source_section_program_contexts contexts
                JOIN source_sections sections USING (section_id)
                WHERE contexts.source_active
                  AND sections.active
                GROUP BY contexts.program
                ORDER BY contexts.program
                """
            ).fetchall()
        programs = all_programs()
        quotas = program_quotas(target_count)
        active_program_section_counts = {
            str(row["program"]): int(row["active_program_section_count"])
            for row in context_rows
        }
        accepted_candidate_counts = {program: 0 for program in programs}
        for row in accepted_rows:
            accepted_candidate_counts[str(row["program"])] = int(
                row["candidate_count"]
            )
        blocker_counts: dict[str, int] = {}
        program_counts: dict[str, int] = {}
        program_url_counts: dict[tuple[str, str], int] = {}
        eligible_program_counts: dict[str, int] = {}
        eligible_priority_counts: dict[str, int] = {}
        eligible_scope_mode_counts: dict[str, int] = {}
        temporal_authority_program_counts: dict[str, int] = {}
        temporal_authority_eligible = 0
        score_bands = {"high_70_100": 0, "medium_40_69": 0, "low_0_39": 0}
        eligible = 0
        for row in rows:
            program = str(row["program"])
            program_counts[program] = program_counts.get(program, 0) + 1
            key = (program, str(row["candidate_url"]))
            program_url_counts[key] = program_url_counts.get(key, 0) + 1
            blockers = list(row["preflight_blockers"])
            if not blockers:
                signals = dict(row["preflight_signals"] or {})
                source_priority = str(
                    signals.get("source_priority", "general_official_source")
                )
                eligible += 1
                eligible_program_counts[program] = (
                    eligible_program_counts.get(program, 0) + 1
                )
                eligible_priority_counts[source_priority] = (
                    eligible_priority_counts.get(source_priority, 0) + 1
                )
                scope_mode = _source_candidate_scope_mode(signals)
                eligible_scope_mode_counts[scope_mode] = (
                    eligible_scope_mode_counts.get(scope_mode, 0) + 1
                )
                if signals.get("temporal_authority_candidate") is True:
                    temporal_authority_eligible += 1
                    temporal_authority_program_counts[program] = (
                        temporal_authority_program_counts.get(program, 0) + 1
                    )
            for blocker in blockers:
                blocker_counts[str(blocker)] = blocker_counts.get(str(blocker), 0) + 1
            score = int(row["preflight_score"])
            if score >= 70:
                score_bands["high_70_100"] += 1
            elif score >= 40:
                score_bands["medium_40_69"] += 1
            else:
                score_bands["low_0_39"] += 1
        unique_program_counts: dict[str, int] = {}
        for program, _ in program_url_counts:
            unique_program_counts[program] = unique_program_counts.get(program, 0) + 1
        duplicate_source_candidate_count = sum(
            count - 1 for count in program_url_counts.values()
        )
        duplicate_source_candidate_group_count = sum(
            count > 1 for count in program_url_counts.values()
        )
        program_context_capacity = {
            program: (
                active_program_section_counts.get(program, 0)
                * MAX_CANDIDATES_PER_SECTION
            )
            for program in programs
        }
        source_review_priority_programs = [
            {
                "program": program,
                "accepted_grounded_candidates": accepted_candidate_counts[program],
                "candidate_quota": quotas[program],
                "accepted_deficit": max(
                    0, quotas[program] - accepted_candidate_counts[program]
                ),
                "active_program_section_count": (
                    active_program_section_counts.get(program, 0)
                ),
                "program_context_candidate_upper_bound": (
                    program_context_capacity[program]
                ),
                "minimum_additional_program_contexts_lower_bound": (
                    max(0, quotas[program] - program_context_capacity[program])
                    + MAX_CANDIDATES_PER_SECTION
                    - 1
                )
                // MAX_CANDIDATES_PER_SECTION,
                "program_context_quota_possible": (
                    program_context_capacity[program] >= quotas[program]
                ),
                "eligible_source_candidates": eligible_program_counts.get(program, 0),
                "pending_source_candidates": program_counts.get(program, 0),
            }
            for program in programs
            if accepted_candidate_counts[program] < quotas[program]
        ]
        source_review_priority_programs.sort(
            key=lambda item: (
                item["program_context_quota_possible"],
                item["accepted_grounded_candidates"] != 0,
                -item["minimum_additional_program_contexts_lower_bound"],
                -item["accepted_deficit"],
                -item["eligible_source_candidates"],
                item["program"],
            )
        )
        programs_without_accepted_candidates = [
            program for program in programs if accepted_candidate_counts[program] == 0
        ]
        deficit_programs_without_eligible_source_candidates = [
            item["program"]
            for item in source_review_priority_programs
            if item["eligible_source_candidates"] == 0
        ]
        programs_without_program_context_quota_capacity = [
            item["program"]
            for item in source_review_priority_programs
            if not item["program_context_quota_possible"]
        ]
        zero_candidate_programs_without_eligible_source_candidates = [
            program
            for program in programs_without_accepted_candidates
            if eligible_program_counts.get(program, 0) == 0
        ]
        capacity_program_order = {
            program: index
            for index, program in enumerate(
                programs_without_program_context_quota_capacity
            )
        }
        capacity_blocker_review_candidates = [
            {
                "source_candidate_id": str(row["source_candidate_id"]),
                "program": str(row["program"]),
                "candidate_url": str(row["candidate_url"]),
                "link_text": str(row["link_text"]),
                "preflight_score": int(row["preflight_score"]),
                "preflight_hash": str(row["preflight_hash"]),
                "scope_mode": _source_candidate_scope_mode(
                    dict(row["preflight_signals"] or {})
                ),
                "review_status": str(row["review_status"]),
                "decision_required": "approve_for_registry_or_reject",
                "approval_effect": "inactive_registry_candidate_only",
                "legal_verification": False,
                "runtime_activation": False,
                "proof_binding": False,
            }
            for row in rows
            if (
                not row["preflight_blockers"]
                and str(row["program"])
                in programs_without_program_context_quota_capacity
            )
        ]
        capacity_blocker_review_candidates.sort(
            key=lambda item: (
                capacity_program_order[item["program"]],
                -item["preflight_score"],
                item["source_candidate_id"],
            )
        )
        top_candidates = [
            {
                "source_candidate_id": row["source_candidate_id"],
                "program": row["program"],
                "candidate_url": row["candidate_url"],
                "preflight_score": row["preflight_score"],
                "preflight_blockers": row["preflight_blockers"],
                "preflight_hash": row["preflight_hash"],
                "source_priority": (row["preflight_signals"] or {}).get(
                    "source_priority", "general_official_source"
                ),
                "temporal_authority_candidate": bool(
                    (row["preflight_signals"] or {}).get("temporal_authority_candidate")
                ),
            }
            for row in rows
            if not row["preflight_blockers"]
        ][:25]
        return {
            "schema_version": SOURCE_CANDIDATE_PREFLIGHT_REPORT_SCHEMA,
            "preflight_version": SOURCE_CANDIDATE_PREFLIGHT_VERSION,
            "assessed_candidate_count": len(rows),
            "unique_program_url_count": len(program_url_counts),
            "duplicate_source_candidate_count": duplicate_source_candidate_count,
            "duplicate_source_candidate_group_count": (
                duplicate_source_candidate_group_count
            ),
            "unassessed_candidate_count": int(unassessed["count"]),
            "eligible_for_human_review_count": eligible,
            "blocked_candidate_count": len(rows) - eligible,
            "score_bands": score_bands,
            "blocker_counts": dict(sorted(blocker_counts.items())),
            "source_review_milestone_target": target_count,
            "programs_without_program_context_quota_capacity": (
                programs_without_program_context_quota_capacity
            ),
            "source_capacity_evidence_is_necessary_not_sufficient": True,
            "accepted_candidate_counts": accepted_candidate_counts,
            "programs_without_accepted_candidates": (
                programs_without_accepted_candidates
            ),
            "deficit_programs_without_eligible_source_candidates": (
                deficit_programs_without_eligible_source_candidates
            ),
            "zero_candidate_programs_without_eligible_source_candidates": (
                zero_candidate_programs_without_eligible_source_candidates
            ),
            "source_review_priority_programs": source_review_priority_programs,
            "program_candidate_counts": dict(sorted(program_counts.items())),
            "unique_program_candidate_counts": dict(
                sorted(unique_program_counts.items())
            ),
            "eligible_program_counts": dict(sorted(eligible_program_counts.items())),
            "eligible_priority_counts": dict(sorted(eligible_priority_counts.items())),
            "eligible_scope_mode_counts": dict(
                sorted(eligible_scope_mode_counts.items())
            ),
            "temporal_authority_eligible_count": temporal_authority_eligible,
            "temporal_authority_program_counts": dict(
                sorted(temporal_authority_program_counts.items())
            ),
            "top_review_candidates": top_candidates,
            "capacity_blocker_review_candidate_count": len(
                capacity_blocker_review_candidates
            ),
            "capacity_blocker_review_candidates": (
                capacity_blocker_review_candidates
            ),
            "capacity_blocker_review_candidates_sha256": canonical_sha256(
                capacity_blocker_review_candidates
            ),
            "human_review_required": True,
            "automatic_registry_activation": False,
            "runtime_activation": False,
            "proof_binding": False,
        }

    def claim_source_registry_candidate(
        self,
        *,
        reviewer_id: str,
        program: str | None = None,
        lease_seconds: int = DEFAULT_REVIEW_LEASE_SECONDS,
    ) -> dict[str, Any] | None:
        from psycopg.types.json import Jsonb

        if not reviewer_id.strip():
            raise ValueError("source reviewer ID is required")
        program_filter = (program or "").strip() or None
        if program_filter is not None and program_filter not in set(all_programs()):
            raise ValueError("source review program must be a recognized program")
        if lease_seconds <= 0:
            raise ValueError("source review lease must be positive")
        with self.connection() as conn:
            self._cancel_stale_source_registry_candidates_with_connection(conn)
            expired = conn.execute(
                """
                UPDATE source_registry_candidates
                SET review_status = 'pending_review',
                    assigned_reviewer_id = NULL,
                    claimed_at = NULL,
                    claim_expires_at = NULL
                WHERE review_status = 'claimed_review'
                  AND (claim_expires_at IS NULL OR claim_expires_at <= now())
                RETURNING source_candidate_id, claim_attempts
                """
            ).fetchall()
            for item in expired:
                audit_id = stable_id(
                    "audit",
                    item["source_candidate_id"],
                    "source_claim_expired",
                    item["claim_attempts"],
                )
                conn.execute(
                    """
                    INSERT INTO review_audit_events (
                        event_id, actor_id, action, entity_type, entity_id, payload
                    ) VALUES (%s, 'rules-system', 'source_claim_expired',
                              'source_registry_candidate', %s, %s)
                    ON CONFLICT (event_id) DO NOTHING
                    """,
                    (
                        audit_id,
                        item["source_candidate_id"],
                        Jsonb({"claim_attempts": item["claim_attempts"]}),
                    ),
                )
            row = conn.execute(
                """
                WITH ranked AS MATERIALIZED (
                    SELECT source_candidate_id, program, preflight_score,
                           jsonb_array_length(preflight_blockers) AS blocker_count,
                           row_number() OVER (
                               PARTITION BY program
                               ORDER BY jsonb_array_length(preflight_blockers),
                                        preflight_score DESC,
                                        source_candidate_id
                           ) AS program_ordinal
                    FROM source_registry_candidates
                    WHERE review_status = 'pending_review'
                      AND preflight_version = %s
                      AND (%s::text IS NULL OR program = %s)
                ), claimable AS (
                    SELECT candidates.source_candidate_id
                    FROM source_registry_candidates candidates
                    JOIN ranked USING (source_candidate_id)
                    WHERE candidates.review_status = 'pending_review'
                    ORDER BY ranked.blocker_count, ranked.program_ordinal,
                             ranked.preflight_score DESC, ranked.program,
                             candidates.source_candidate_id
                    FOR UPDATE OF candidates SKIP LOCKED
                    LIMIT 1
                )
                UPDATE source_registry_candidates AS candidates
                SET review_status = 'claimed_review', assigned_reviewer_id = %s,
                    claimed_at = now(),
                    claim_expires_at = now() + make_interval(secs => %s),
                    claim_attempts = claim_attempts + 1
                FROM claimable
                WHERE candidates.source_candidate_id = claimable.source_candidate_id
                RETURNING candidates.*
                """,
                (
                    SOURCE_CANDIDATE_PREFLIGHT_VERSION,
                    program_filter,
                    program_filter,
                    reviewer_id,
                    lease_seconds,
                ),
            ).fetchone()
            if row:
                audit_id = stable_id(
                    "audit",
                    row["source_candidate_id"],
                    reviewer_id,
                    "source_claimed",
                    row["claim_attempts"],
                )
                conn.execute(
                    """
                    INSERT INTO review_audit_events (
                        event_id, actor_id, action, entity_type, entity_id, payload
                    ) VALUES (%s, %s, 'source_claimed',
                              'source_registry_candidate', %s, %s)
                    ON CONFLICT (event_id) DO NOTHING
                    """,
                    (
                        audit_id,
                        reviewer_id,
                        row["source_candidate_id"],
                        Jsonb(
                            {
                                "claim_attempts": row["claim_attempts"],
                                "requested_program": program_filter,
                                "claim_expires_at": str(row["claim_expires_at"]),
                            }
                        ),
                    ),
                )
            conn.commit()
        if not row:
            return None
        return {
            **dict(row),
            "runtime_activation": False,
            "proof_binding": False,
            "registry_activation": False,
        }

    def _cancel_stale_source_registry_candidates_with_connection(
        self,
        conn: Any,
    ) -> list[dict[str, Any]]:
        """Invalidate source reviews when their exact parent lineage is stale."""
        from psycopg.types.json import Jsonb

        rows = conn.execute(
            """
            UPDATE source_registry_candidates AS candidates
            SET review_status = 'superseded',
                assigned_reviewer_id = NULL,
                claimed_at = NULL,
                claim_expires_at = NULL,
                superseded_at = now(),
                supersession_reason = CASE
                    WHEN NOT sources.active
                        THEN 'parent source registry entry is inactive'
                    WHEN retrievals.snapshot_hash <> candidates.parent_snapshot_hash
                      OR runs.snapshot_hash <> candidates.parent_snapshot_hash
                      OR runs.retrieval_id <> candidates.parent_retrieval_id
                        THEN 'candidate lineage does not match its discovery evidence'
                    ELSE 'newer parent source bytes were captured'
                END
            FROM source_snapshot_retrievals retrievals,
                 source_discovery_runs runs,
                 official_sources sources
            WHERE candidates.parent_retrieval_id = retrievals.retrieval_id
              AND candidates.discovery_run_id = runs.discovery_run_id
              AND candidates.parent_source_id = sources.source_id
              AND candidates.review_status IN (
                  'pending_review', 'claimed_review', 'approved_for_registry'
              )
              AND (
                  NOT sources.active
                  OR retrievals.source_id <> candidates.parent_source_id
                  OR retrievals.snapshot_hash <> candidates.parent_snapshot_hash
                  OR runs.retrieval_id <> candidates.parent_retrieval_id
                  OR runs.snapshot_hash <> candidates.parent_snapshot_hash
                  OR EXISTS (
                      SELECT 1
                      FROM source_snapshot_retrievals newer
                      WHERE newer.source_id = candidates.parent_source_id
                        AND (newer.retrieved_at, newer.retrieval_id) >
                            (retrievals.retrieved_at, retrievals.retrieval_id)
                        AND newer.snapshot_hash <> candidates.parent_snapshot_hash
                  )
              )
            RETURNING candidates.source_candidate_id,
                      candidates.review_status,
                      candidates.supersession_reason,
                      candidates.claim_attempts
            """
        ).fetchall()
        superseded = [dict(row) for row in rows]
        for item in superseded:
            audit_id = stable_id(
                "audit",
                item["source_candidate_id"],
                "source_candidate_superseded_lineage",
            )
            conn.execute(
                """
                INSERT INTO review_audit_events (
                    event_id, actor_id, action, entity_type, entity_id, payload
                ) VALUES (
                    %s, 'rules-system', 'source_candidate_superseded_lineage',
                    'source_registry_candidate', %s, %s
                )
                ON CONFLICT (event_id) DO NOTHING
                """,
                (
                    audit_id,
                    item["source_candidate_id"],
                    Jsonb(
                        {
                            "reason": item["supersession_reason"],
                            "claim_attempts": item["claim_attempts"],
                            "registry_activation": False,
                        }
                    ),
                ),
            )
        return superseded

    def renew_source_registry_candidate_claim(
        self,
        source_candidate_id: str,
        *,
        reviewer_id: str,
        lease_seconds: int = DEFAULT_REVIEW_LEASE_SECONDS,
    ) -> dict[str, Any]:
        return self._update_source_registry_candidate_claim(
            source_candidate_id,
            reviewer_id=reviewer_id,
            action="renew",
            lease_seconds=lease_seconds,
        )

    def release_source_registry_candidate_claim(
        self,
        source_candidate_id: str,
        *,
        reviewer_id: str,
    ) -> dict[str, Any]:
        return self._update_source_registry_candidate_claim(
            source_candidate_id,
            reviewer_id=reviewer_id,
            action="release",
            lease_seconds=DEFAULT_REVIEW_LEASE_SECONDS,
        )

    def _update_source_registry_candidate_claim(
        self,
        source_candidate_id: str,
        *,
        reviewer_id: str,
        action: str,
        lease_seconds: int,
    ) -> dict[str, Any]:
        from psycopg.types.json import Jsonb

        if action not in {"renew", "release"}:
            raise ValueError("unsupported source review claim action")
        if not reviewer_id.strip():
            raise ValueError("source reviewer ID is required")
        if lease_seconds <= 0:
            raise ValueError("source review lease must be positive")
        if action == "renew":
            assignment = "claim_expires_at = now() + make_interval(secs => %s)"
            params: tuple[Any, ...] = (
                lease_seconds,
                source_candidate_id,
                reviewer_id,
            )
        else:
            assignment = (
                "review_status = 'pending_review', assigned_reviewer_id = NULL, "
                "claimed_at = NULL, claim_expires_at = NULL"
            )
            params = (source_candidate_id, reviewer_id)
        with self.connection() as conn:
            superseded = self._cancel_stale_source_registry_candidates_with_connection(
                conn
            )
            if any(
                item["source_candidate_id"] == source_candidate_id
                for item in superseded
            ):
                conn.commit()
                raise CorpusDatabaseError(
                    "source review candidate parent lineage is superseded"
                )
            row = conn.execute(
                f"""
                UPDATE source_registry_candidates
                SET {assignment}
                WHERE source_candidate_id = %s
                  AND review_status = 'claimed_review'
                  AND assigned_reviewer_id = %s
                  AND claim_expires_at > now()
                RETURNING source_candidate_id, review_status,
                          claim_expires_at, claim_attempts
                """,
                params,
            ).fetchone()
            if not row:
                raise CorpusDatabaseError(
                    "source review claim is missing, expired, or owned by another reviewer"
                )
            audit_id = stable_id(
                "audit",
                source_candidate_id,
                reviewer_id,
                f"source_claim_{action}",
                row["claim_attempts"],
                str(row["claim_expires_at"]),
            )
            conn.execute(
                """
                INSERT INTO review_audit_events (
                    event_id, actor_id, action, entity_type, entity_id, payload
                ) VALUES (%s, %s, %s, 'source_registry_candidate', %s, %s)
                ON CONFLICT (event_id) DO NOTHING
                """,
                (
                    audit_id,
                    reviewer_id,
                    f"source_claim_{action}",
                    source_candidate_id,
                    Jsonb(
                        {
                            "claim_attempts": row["claim_attempts"],
                            "claim_expires_at": str(row["claim_expires_at"])
                            if row["claim_expires_at"]
                            else None,
                        }
                    ),
                ),
            )
            conn.commit()
        return {
            **dict(row),
            "action": action,
            "runtime_activation": False,
            "proof_binding": False,
            "registry_activation": False,
        }

    def source_registry_candidate_detail(
        self, source_candidate_id: str
    ) -> dict[str, Any]:
        with self.connection() as conn:
            self._cancel_stale_source_registry_candidates_with_connection(conn)
            row = conn.execute(
                """
                SELECT candidates.*, retrievals.canonical_url AS parent_url,
                       retrievals.retrieved_at, sources.issuer,
                       runs.parser_version, runs.canonical_run_hash
                FROM source_registry_candidates candidates
                JOIN source_snapshot_retrievals retrievals
                  ON retrievals.retrieval_id = candidates.parent_retrieval_id
                JOIN official_sources sources
                  ON sources.source_id = candidates.parent_source_id
                JOIN source_discovery_runs runs USING (discovery_run_id)
                WHERE candidates.source_candidate_id = %s
                """,
                (source_candidate_id,),
            ).fetchone()
            conn.commit()
        if not row:
            raise CorpusDatabaseError("source registry candidate does not exist")
        return {
            **dict(row),
            "runtime_activation": False,
            "proof_binding": False,
            "registry_activation": False,
        }

    def record_source_registry_candidate_decision(
        self,
        *,
        source_candidate_id: str,
        reviewer_id: str,
        decision: str,
        rationale: str,
    ) -> dict[str, Any]:
        from psycopg.types.json import Jsonb

        if decision not in {"approve_for_registry", "reject"}:
            raise ValueError("source decision must be approve_for_registry or reject")
        if not rationale.strip():
            raise ValueError("source decision rationale is required")
        decision_id = stable_id(
            "source-decision",
            source_candidate_id,
            reviewer_id,
            decision,
        )
        next_status = (
            "approved_for_registry" if decision == "approve_for_registry" else "rejected"
        )
        with self.connection() as conn:
            self._lock_source_registry_lineage(conn)
            superseded = self._cancel_stale_source_registry_candidates_with_connection(
                conn
            )
            if any(
                item["source_candidate_id"] == source_candidate_id
                for item in superseded
            ):
                conn.commit()
                raise CorpusDatabaseError(
                    "source review candidate parent lineage is superseded"
                )
            candidate = conn.execute(
                """
                SELECT source_candidate_id, assigned_reviewer_id, review_status,
                       claim_expires_at, preflight_version, preflight_blockers,
                       preflight_hash,
                       claim_expires_at IS NOT NULL
                           AND claim_expires_at > now() AS claim_live
                FROM source_registry_candidates
                WHERE source_candidate_id = %s FOR UPDATE
                """,
                (source_candidate_id,),
            ).fetchone()
            if not candidate:
                raise CorpusDatabaseError("source registry candidate does not exist")
            if (
                candidate["review_status"] != "claimed_review"
                or candidate["assigned_reviewer_id"] != reviewer_id
                or not candidate["claim_live"]
            ):
                raise CorpusDatabaseError(
                    "source registry candidate is not claimed by this reviewer"
                )
            if candidate["preflight_version"] != SOURCE_CANDIDATE_PREFLIGHT_VERSION:
                raise CorpusDatabaseError(
                    "source registry candidate requires current deterministic preflight"
                )
            if decision == "approve_for_registry" and candidate["preflight_blockers"]:
                raise CorpusDatabaseError(
                    "source registry candidate has unresolved deterministic preflight blockers"
                )
            conn.execute(
                """
                INSERT INTO source_registry_candidate_decisions (
                    source_decision_id, source_candidate_id, reviewer_id,
                    reviewer_role, decision, rationale
                ) VALUES (%s, %s, %s, 'rules_admin', %s, %s)
                """,
                (
                    decision_id,
                    source_candidate_id,
                    reviewer_id,
                    decision,
                    rationale.strip(),
                ),
            )
            conn.execute(
                """
                UPDATE source_registry_candidates
                SET review_status = %s, reviewed_at = now(),
                    assigned_reviewer_id = NULL, claimed_at = NULL,
                    claim_expires_at = NULL
                WHERE source_candidate_id = %s
                """,
                (next_status, source_candidate_id),
            )
            audit_id = stable_id("audit", decision_id, "source_registry_review")
            conn.execute(
                """
                INSERT INTO review_audit_events (
                    event_id, actor_id, action, entity_type, entity_id, payload
                ) VALUES (%s, %s, 'source_registry_review',
                          'source_registry_candidate', %s, %s)
                """,
                (
                    audit_id,
                    reviewer_id,
                    source_candidate_id,
                    Jsonb(
                        {
                            "source_decision_id": decision_id,
                            "decision": decision,
                            "preflight_hash": candidate["preflight_hash"],
                            "registry_activation": False,
                        }
                    ),
                ),
            )
            conn.commit()
        return {
            "source_decision_id": decision_id,
            "review_status": next_status,
            "registry_activation": False,
            "runtime_activation": False,
            "proof_binding": False,
        }

    def approved_source_registry_candidates(self) -> list[dict[str, Any]]:
        with self.connection() as conn:
            self._lock_source_registry_lineage(conn)
            self._cancel_stale_source_registry_candidates_with_connection(conn)
            rows = conn.execute(
                """
                SELECT DISTINCT ON (candidates.program, candidates.candidate_url)
                       candidates.source_candidate_id, candidates.parent_source_id,
                       candidates.parent_snapshot_hash, candidates.program,
                       candidates.candidate_url, candidates.review_status,
                       decisions.source_decision_id, decisions.reviewer_id,
                       decisions.reviewer_role, decisions.decision,
                       decisions.rationale
                FROM source_registry_candidates candidates
                JOIN source_registry_candidate_decisions decisions
                  USING (source_candidate_id)
                JOIN official_sources parent_sources
                  ON parent_sources.source_id = candidates.parent_source_id
                WHERE candidates.review_status = 'approved_for_registry'
                  AND decisions.decision = 'approve_for_registry'
                  AND parent_sources.active
                  AND candidates.preflight_version = %s
                  AND jsonb_array_length(candidates.preflight_blockers) = 0
                ORDER BY candidates.program, candidates.candidate_url,
                         candidates.source_candidate_id
                """,
                (SOURCE_CANDIDATE_PREFLIGHT_VERSION,),
            ).fetchall()
            conn.commit()
        return [dict(row) for row in rows]

    def uninferred_sections(self, *, limit: int = 0) -> list[dict[str, Any]]:
        sql = """
            WITH section_programs AS (
                SELECT contexts.section_id,
                       array_agg(contexts.program ORDER BY contexts.program) AS programs
                FROM source_section_program_contexts contexts
                WHERE contexts.source_active
                GROUP BY contexts.section_id
            ), eligible AS (
                SELECT sections.*, programs.programs,
                       relevance.decision_id AS relevance_decision_id,
                       relevance.relevant
                FROM source_sections sections
                JOIN section_programs programs USING (section_id)
                LEFT JOIN section_relevance_decisions relevance
                  ON relevance.section_id = sections.section_id
                 AND relevance.classifier_version = %s
                WHERE sections.active
                  AND NOT EXISTS (
                    SELECT 1 FROM inference_jobs jobs
                    WHERE jobs.section_id = sections.section_id
                      AND jobs.pass = 1
                      AND jobs.prompt_version = %s
                      AND jobs.model_version = %s
                      AND jobs.schema_version = %s
                      AND jobs.request_payload->>'response_contract_version' = %s
                )
                  AND (relevance.decision_id IS NULL OR relevance.relevant)
            )
            SELECT * FROM eligible
            ORDER BY section_id
        """
        params: tuple[Any, ...] = (
            RELEVANCE_CLASSIFIER_VERSION,
            EXTRACTION_PROMPT_VERSION,
            CLAUDE_MODEL,
            INFERENCE_SCHEMA,
            INFERENCE_RESPONSE_CONTRACT_VERSION,
        )
        with self.connection() as conn:
            rows = conn.execute(sql, params).fetchall()
            accepted_rows = conn.execute(
                f"""
                SELECT candidates.primary_program AS program,
                       count(DISTINCT candidates.candidate_id) AS candidate_count
                FROM grounded_candidates candidates
                JOIN source_sections sections USING (section_id)
                JOIN source_section_program_contexts contexts
                  ON contexts.section_id = candidates.section_id
                 AND contexts.program = candidates.primary_program
                 AND contexts.source_active
                WHERE sections.active
                  AND candidates.grounding_status = 'accepted'
                  AND {CURRENT_CANDIDATE_CONTRACT_SQL}
                GROUP BY candidates.primary_program
                ORDER BY candidates.primary_program
                """
            ).fetchall()
        accepted_counts = {
            str(row["program"]): int(row["candidate_count"])
            for row in accepted_rows
        }
        return prioritize_inference_sections(
            [dict(row) for row in rows],
            accepted_counts,
            limit=limit,
        )

    def save_relevance_decision(self, decision: dict[str, Any]) -> str:
        from psycopg.types.json import Jsonb

        decision_id = stable_id(
            "relevance",
            decision["section_id"],
            decision["classifier_version"],
            decision["decision_hash"],
        )
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO section_relevance_decisions (
                    decision_id, section_id, classifier_version, section_hash,
                    relevant, score, reasons, decision_hash
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (section_id, classifier_version) DO NOTHING
                """,
                (
                    decision_id,
                    decision["section_id"],
                    decision["classifier_version"],
                    decision["section_hash"],
                    decision["relevant"],
                    decision["score"],
                    Jsonb(decision["reasons"]),
                    decision["decision_hash"],
                ),
            )
            row = conn.execute(
                """
                SELECT decision_id, section_hash, decision_hash
                FROM section_relevance_decisions
                WHERE section_id = %s AND classifier_version = %s
                """,
                (decision["section_id"], decision["classifier_version"]),
            ).fetchone()
            if (
                not row
                or row["section_hash"] != decision["section_hash"]
                or row["decision_hash"] != decision["decision_hash"]
            ):
                raise CorpusDatabaseError(
                    "persisted relevance decision does not match the current section"
                )
            conn.commit()
        return str(row["decision_id"])

    def section(self, section_id: str) -> dict[str, Any]:
        with self.connection() as conn:
            row = conn.execute(
                """
                SELECT sections.*, contexts.programs[1] AS program,
                       contexts.programs
                FROM source_sections sections
                JOIN LATERAL (
                    SELECT array_agg(program ORDER BY program) AS programs
                    FROM source_section_program_contexts
                    WHERE section_id = sections.section_id AND source_active
                ) contexts ON cardinality(contexts.programs) > 0
                WHERE sections.section_id = %s
                """,
                (section_id,),
            ).fetchone()
        if not row:
            raise CorpusDatabaseError("source section does not exist")
        return dict(row)

    def enqueue_inference(self, request: dict[str, Any]) -> str:
        from psycopg.types.json import Jsonb

        job_id = stable_id("job", request["idempotency_key"])
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO inference_jobs (
                    inference_job_id, section_id, pass, prompt_version, model_version,
                    schema_version, idempotency_key, status, request_payload
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, 'pending', %s)
                ON CONFLICT (idempotency_key) DO NOTHING
                """,
                (
                    job_id,
                    request["section"]["section_id"],
                    request["pass"],
                    request["prompt_version"],
                    request["model_version"],
                    request["schema_version"],
                    request["idempotency_key"],
                    Jsonb(request),
                ),
            )
            row = conn.execute(
                "SELECT inference_job_id FROM inference_jobs WHERE idempotency_key = %s",
                (request["idempotency_key"],),
            ).fetchone()
            conn.commit()
        return str(row["inference_job_id"])

    def claim_inference_jobs(
        self,
        worker_id: str,
        *,
        limit: int = 8,
        lease_seconds: int = 300,
    ) -> list[dict[str, Any]]:
        if not worker_id.strip():
            raise ValueError("inference worker ID must be present")
        if limit <= 0:
            raise ValueError("inference claim limit must be positive")
        if lease_seconds <= 0:
            raise ValueError("inference lease must be positive")
        with self.connection() as conn:
            conn.execute(
                """
                UPDATE inference_jobs
                SET status = 'rejected',
                    last_error = 'superseded by pinned structured response contract',
                    lease_owner = NULL,
                    lease_expires_at = NULL
                WHERE status IN ('pending', 'leased')
                  AND (
                      model_version <> %s
                      OR schema_version <> %s
                      OR (request_payload->>'response_contract_version')
                         IS DISTINCT FROM %s
                      OR (pass = 1 AND prompt_version <> %s)
                      OR (pass = 2 AND prompt_version <> %s)
                  )
                """,
                (
                    CLAUDE_MODEL,
                    INFERENCE_SCHEMA,
                    INFERENCE_RESPONSE_CONTRACT_VERSION,
                    EXTRACTION_PROMPT_VERSION,
                    CRITIQUE_PROMPT_VERSION,
                ),
            )
            conn.execute(
                """
                UPDATE inference_jobs jobs
                SET status = 'failed',
                    last_error = 'source or parser section was superseded',
                    lease_owner = NULL, lease_expires_at = NULL
                FROM source_sections sections
                WHERE jobs.section_id = sections.section_id
                  AND (
                      NOT sections.active
                      OR NOT EXISTS (
                          SELECT 1
                          FROM source_section_program_contexts contexts
                          WHERE contexts.section_id = sections.section_id
                            AND contexts.source_active
                      )
                  )
                  AND jobs.status IN ('pending', 'leased')
                """
            )
            conn.execute(
                """
                UPDATE inference_jobs
                SET status = 'failed',
                    last_error = coalesce(
                        last_error,
                        'worker lease expired after the configured attempt limit'
                    ),
                    lease_owner = NULL,
                    lease_expires_at = NULL
                WHERE status = 'leased'
                  AND lease_expires_at < now()
                  AND attempts >= attempt_limit
                """
            )
            rows = conn.execute(
                f"""
                WITH accepted_program_counts AS (
                    SELECT candidates.primary_program AS program,
                           count(DISTINCT candidates.candidate_id)
                               AS candidate_count
                    FROM grounded_candidates candidates
                    JOIN source_sections accepted_sections USING (section_id)
                    JOIN source_section_program_contexts accepted_contexts
                      ON accepted_contexts.section_id = candidates.section_id
                     AND accepted_contexts.program =
                         candidates.primary_program
                     AND accepted_contexts.source_active
                    WHERE accepted_sections.active
                      AND candidates.grounding_status = 'accepted'
                      AND {CURRENT_CANDIDATE_CONTRACT_SQL}
                    GROUP BY candidates.primary_program
                ),
                eligible AS (
                    SELECT jobs.inference_job_id, jobs.pass, jobs.created_at,
                           jobs.request_payload->>'program' AS program,
                           coalesce(counts.candidate_count, 0)
                               AS accepted_candidate_count,
                           row_number() OVER (
                               PARTITION BY jobs.pass,
                                            jobs.request_payload->>'program'
                               ORDER BY jobs.created_at,
                                        jobs.inference_job_id
                           ) AS program_rank
                    FROM inference_jobs jobs
                    JOIN source_sections sections USING (section_id)
                    LEFT JOIN accepted_program_counts counts
                      ON counts.program = jobs.request_payload->>'program'
                    WHERE sections.active
                      AND EXISTS (
                          SELECT 1
                          FROM source_section_program_contexts contexts
                          WHERE contexts.section_id = sections.section_id
                            AND contexts.source_active
                      )
                      AND attempts < attempt_limit
                      AND (
                          jobs.status = 'pending'
                          OR (jobs.status = 'leased' AND lease_expires_at < now())
                      )
                ),
                claimable AS (
                    SELECT jobs.inference_job_id
                    FROM inference_jobs jobs
                    JOIN eligible ranked_jobs USING (inference_job_id)
                    -- Close critique work before opening more extraction work.
                    ORDER BY ranked_jobs.pass DESC,
                             ranked_jobs.accepted_candidate_count
                                 + ranked_jobs.program_rank - 1,
                             ranked_jobs.created_at,
                             jobs.inference_job_id
                    FOR UPDATE OF jobs SKIP LOCKED
                    LIMIT %s
                )
                UPDATE inference_jobs AS jobs
                SET status = 'leased',
                    lease_owner = %s,
                    lease_expires_at = now() + make_interval(secs => %s),
                    attempts = attempts + 1
                FROM claimable
                WHERE jobs.inference_job_id = claimable.inference_job_id
                RETURNING jobs.*
                """,
                (limit, worker_id, lease_seconds),
            ).fetchall()
            conn.commit()
        return [dict(row) for row in rows]

    def recover_expired_inference_leases(self) -> dict[str, int]:
        """Return abandoned inference work to a durable, operator-visible state."""

        with self.connection() as conn:
            exhausted = conn.execute(
                """
                UPDATE inference_jobs
                SET status = 'failed',
                    last_error = coalesce(
                        last_error,
                        'worker lease expired after the configured attempt limit'
                    ),
                    lease_owner = NULL,
                    lease_expires_at = NULL
                WHERE status = 'leased'
                  AND lease_expires_at <= now()
                  AND attempts >= attempt_limit
                RETURNING inference_job_id
                """
            ).fetchall()
            requeued = conn.execute(
                """
                UPDATE inference_jobs
                SET status = 'pending',
                    last_error = coalesce(
                        last_error,
                        'worker lease expired and was returned to pending'
                    ),
                    lease_owner = NULL,
                    lease_expires_at = NULL
                WHERE status = 'leased'
                  AND lease_expires_at <= now()
                  AND attempts < attempt_limit
                RETURNING inference_job_id
                """
            ).fetchall()
            remaining_expired = int(
                conn.execute(
                    """
                    SELECT count(*) AS count
                    FROM inference_jobs
                    WHERE status = 'leased'
                      AND lease_expires_at <= now()
                    """
                ).fetchone()["count"]
            )
            conn.commit()
        return {
            "requeued": len(requeued),
            "failed_at_attempt_limit": len(exhausted),
            "remaining_expired_leases": remaining_expired,
        }

    def retry_failed_inference_jobs(
        self,
        *,
        limit: int,
        additional_attempts: int = 5,
    ) -> int:
        if limit <= 0:
            raise ValueError("failed inference retry limit must be positive")
        if additional_attempts <= 0:
            raise ValueError("additional inference attempts must be positive")
        with self.connection() as conn:
            rows = conn.execute(
                """
                WITH retryable AS (
                    SELECT jobs.inference_job_id
                    FROM inference_jobs jobs
                    JOIN source_sections sections USING (section_id)
                    WHERE sections.active
                      AND EXISTS (
                          SELECT 1
                          FROM source_section_program_contexts contexts
                          WHERE contexts.section_id = sections.section_id
                            AND contexts.source_active
                      )
                      AND jobs.status = 'failed'
                      AND jobs.model_version = %s
                      AND jobs.schema_version = %s
                      AND jobs.request_payload->>'response_contract_version' = %s
                      AND (
                          (jobs.pass = 1 AND jobs.prompt_version = %s)
                          OR (jobs.pass = 2 AND jobs.prompt_version = %s)
                      )
                    ORDER BY jobs.created_at, jobs.inference_job_id
                    FOR UPDATE SKIP LOCKED
                    LIMIT %s
                )
                UPDATE inference_jobs AS jobs
                SET status = 'pending',
                    attempt_limit = attempt_limit + %s,
                    retry_rounds = retry_rounds + 1,
                    lease_owner = NULL,
                    lease_expires_at = NULL,
                    completed_at = NULL
                FROM retryable
                WHERE jobs.inference_job_id = retryable.inference_job_id
                RETURNING jobs.inference_job_id
                """,
                (
                    CLAUDE_MODEL,
                    INFERENCE_SCHEMA,
                    INFERENCE_RESPONSE_CONTRACT_VERSION,
                    EXTRACTION_PROMPT_VERSION,
                    CRITIQUE_PROMPT_VERSION,
                    limit,
                    additional_attempts,
                ),
            ).fetchall()
            conn.commit()
        return len(rows)

    def renew_inference_lease(
        self,
        job_id: str,
        *,
        worker_id: str,
        lease_seconds: int = 300,
    ) -> None:
        if lease_seconds <= 0:
            raise ValueError("inference lease must be positive")
        with self.connection() as conn:
            cursor = conn.execute(
                """
                UPDATE inference_jobs
                SET lease_expires_at = now() + make_interval(secs => %s),
                    lease_renewals = lease_renewals + 1
                WHERE inference_job_id = %s
                  AND status = 'leased'
                  AND lease_owner = %s
                """,
                (lease_seconds, job_id, worker_id),
            )
            if cursor.rowcount != 1:
                raise CorpusDatabaseError("inference lease was lost before renewal")
            conn.commit()

    def commit_inference_result(
        self,
        job_id: str,
        *,
        worker_id: str,
        response_payload: dict[str, Any],
        input_tokens: int,
        output_tokens: int,
        usage_metadata: dict[str, Any],
    ) -> int:
        from psycopg.types.json import Jsonb

        with self.connection() as conn:
            job = conn.execute(
                """
                SELECT *
                FROM inference_jobs
                WHERE inference_job_id = %s
                FOR UPDATE
                """,
                (job_id,),
            ).fetchone()
            if (
                not job
                or job["status"] != "leased"
                or job["lease_owner"] != worker_id
            ):
                raise CorpusDatabaseError(
                    "inference result requires a live worker-owned lease"
                )
            section_row = conn.execute(
                """
                SELECT sections.*,
                       cardinality(contexts.programs) > 0 AS source_active,
                       contexts.programs
                FROM source_sections sections
                LEFT JOIN LATERAL (
                    SELECT array_agg(program ORDER BY program) AS programs
                    FROM source_section_program_contexts
                    WHERE section_id = sections.section_id AND source_active
                ) contexts ON true
                WHERE sections.section_id = %s
                FOR SHARE OF sections
                """,
                (job["section_id"],),
            ).fetchone()
            if (
                not section_row
                or not section_row["active"]
                or not section_row["source_active"]
            ):
                raise CorpusDatabaseError(
                    "inference result belongs to a superseded source or section"
                )
            section = dict(section_row)
            if int(job["pass"]) == 1:
                affected = len(
                    self._save_grounded_candidates_with_connection(
                        conn,
                        job_id=job_id,
                        section=section,
                        response_payload=response_payload,
                    )
                )
            elif int(job["pass"]) == 2:
                affected = self._apply_critique_with_connection(
                    conn,
                    job_id=job_id,
                    section=section,
                    response_payload=response_payload,
                )
            else:
                raise CorpusDatabaseError("unsupported inference pass")
            existing_metadata = (
                dict(job["usage_metadata"])
                if isinstance(job["usage_metadata"], dict)
                else {}
            )
            previous_history = existing_metadata.get("attempts", [])
            usage_history = (
                list(previous_history) if isinstance(previous_history, list) else []
            )
            attempt_metadata = {
                **usage_metadata,
                "status": "completed",
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
            }
            usage_history.append(attempt_metadata)
            combined_metadata = {
                **existing_metadata,
                **usage_metadata,
                "attempts": usage_history,
            }
            cursor = conn.execute(
                """
                UPDATE inference_jobs SET
                    status = 'completed', response_payload = %s,
                    input_tokens = input_tokens + %s,
                    output_tokens = output_tokens + %s, usage_metadata = %s,
                    completed_at = now(), lease_owner = NULL, lease_expires_at = NULL
                WHERE inference_job_id = %s AND status = 'leased'
                  AND lease_owner = %s
                """,
                (
                    Jsonb(response_payload),
                    input_tokens,
                    output_tokens,
                    Jsonb(combined_metadata),
                    job_id,
                    worker_id,
                ),
            )
            if cursor.rowcount != 1:
                raise CorpusDatabaseError("inference lease was lost before completion")
            conn.commit()
        return affected

    def _save_grounded_candidates_with_connection(
        self,
        conn: Any,
        *,
        job_id: str,
        section: dict[str, Any],
        response_payload: dict[str, Any],
    ) -> list[str]:
        from psycopg.types.json import Jsonb

        from .scaled_corpus import candidate_id

        saved: list[str] = []
        source_programs = {str(value) for value in section.get("programs", [])}
        for candidate in response_payload.get("candidates", []):
            if candidate.get("program") not in source_programs:
                raise CorpusDatabaseError(
                    "candidate program is not linked to the source section"
                )
            evidence = candidate["evidence"]
            identifier = candidate_id(section, candidate)
            stored_candidate = {**candidate, "candidate_id": identifier}
            conn.execute(
                """
                INSERT INTO grounded_candidates (
                    candidate_id, primary_program, section_id, snapshot_hash,
                    evidence_char_start, evidence_char_end, evidence_byte_start,
                    evidence_byte_end, evidence_quote, evidence_hash,
                    extraction_job_id, extraction_contract_key,
                    critique_job_id, critique_contract_key,
                    candidate_payload, grounding_status
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, NULL, NULL, %s, 'pending'
                )
                ON CONFLICT (candidate_id) DO UPDATE SET
                    primary_program = EXCLUDED.primary_program,
                    section_id = EXCLUDED.section_id,
                    snapshot_hash = EXCLUDED.snapshot_hash,
                    evidence_char_start = EXCLUDED.evidence_char_start,
                    evidence_char_end = EXCLUDED.evidence_char_end,
                    evidence_byte_start = EXCLUDED.evidence_byte_start,
                    evidence_byte_end = EXCLUDED.evidence_byte_end,
                    evidence_quote = EXCLUDED.evidence_quote,
                    evidence_hash = EXCLUDED.evidence_hash,
                    extraction_job_id = EXCLUDED.extraction_job_id,
                    extraction_contract_key = EXCLUDED.extraction_contract_key,
                    critique_job_id = NULL,
                    critique_contract_key = NULL,
                    candidate_payload = EXCLUDED.candidate_payload,
                    grounding_status = 'pending'
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
                    job_id,
                    CURRENT_EXTRACTION_CONTRACT_KEY,
                    Jsonb(stored_candidate),
                ),
            )
            lineage_id = stable_id("lineage", identifier, "extracted_from", job_id)
            conn.execute(
                """
                INSERT INTO candidate_lineage (
                    lineage_id, candidate_id, predecessor_candidate_id, relation, details
                ) VALUES (%s, %s, NULL, 'extracted_from', %s)
                ON CONFLICT (lineage_id) DO NOTHING
                """,
                (lineage_id, identifier, Jsonb({"inference_job_id": job_id})),
            )
            saved.append(identifier)
        return saved

    def pending_critique_sections(self, *, limit: int = 0) -> list[dict[str, Any]]:
        selection_limit = "LIMIT %s" if limit > 0 else ""
        sql = f"""
            WITH selected_sections AS MATERIALIZED (
                SELECT candidates.section_id
                FROM grounded_candidates candidates
                JOIN source_sections sections USING (section_id)
                JOIN inference_jobs extraction_jobs
                  ON extraction_jobs.inference_job_id = candidates.extraction_job_id
                WHERE sections.active
                  AND candidates.grounding_status = 'pending'
                  AND candidates.extraction_contract_key = %s
                  AND candidates.critique_contract_key IS NULL
                  AND extraction_jobs.status = 'completed'
                  AND extraction_jobs.pass = 1
                  AND extraction_jobs.prompt_version = %s
                  AND extraction_jobs.model_version = %s
                  AND extraction_jobs.schema_version = %s
                  AND extraction_jobs.request_payload->>'response_contract_version' = %s
                  AND EXISTS (
                      SELECT 1 FROM source_section_program_contexts contexts
                      WHERE contexts.section_id = sections.section_id
                        AND contexts.source_active
                  )
                  AND NOT EXISTS (
                      SELECT 1 FROM inference_jobs jobs
                      WHERE jobs.section_id = sections.section_id
                        AND jobs.pass = 2
                        AND jobs.prompt_version = %s
                        AND jobs.model_version = %s
                        AND jobs.schema_version = %s
                        AND jobs.request_payload->>'response_contract_version' = %s
                  )
                GROUP BY candidates.section_id
                ORDER BY candidates.section_id
                {selection_limit}
            )
            SELECT sections.*, contexts.programs[1] AS program,
                   contexts.programs,
                   jsonb_agg(candidates.candidate_payload ORDER BY candidates.candidate_id) AS proposed_candidates
            FROM selected_sections selected
            JOIN source_sections sections USING (section_id)
            JOIN LATERAL (
                SELECT array_agg(program ORDER BY program) AS programs
                FROM source_section_program_contexts
                WHERE section_id = sections.section_id AND source_active
            ) contexts ON cardinality(contexts.programs) > 0
            JOIN grounded_candidates candidates USING (section_id)
            JOIN inference_jobs extraction_jobs
              ON extraction_jobs.inference_job_id = candidates.extraction_job_id
            WHERE candidates.grounding_status = 'pending'
              AND candidates.extraction_contract_key = %s
              AND candidates.critique_contract_key IS NULL
              AND extraction_jobs.status = 'completed'
              AND extraction_jobs.pass = 1
              AND extraction_jobs.prompt_version = %s
              AND extraction_jobs.model_version = %s
              AND extraction_jobs.schema_version = %s
              AND extraction_jobs.request_payload->>'response_contract_version' = %s
            GROUP BY sections.section_id, contexts.programs
            ORDER BY sections.section_id
        """
        params: tuple[Any, ...] = (
            CURRENT_EXTRACTION_CONTRACT_KEY,
            EXTRACTION_PROMPT_VERSION,
            CLAUDE_MODEL,
            INFERENCE_SCHEMA,
            INFERENCE_RESPONSE_CONTRACT_VERSION,
            CRITIQUE_PROMPT_VERSION,
            CLAUDE_MODEL,
            INFERENCE_SCHEMA,
            INFERENCE_RESPONSE_CONTRACT_VERSION,
        )
        if limit > 0:
            params = (*params, limit)
        params = (
            *params,
            CURRENT_EXTRACTION_CONTRACT_KEY,
            EXTRACTION_PROMPT_VERSION,
            CLAUDE_MODEL,
            INFERENCE_SCHEMA,
            INFERENCE_RESPONSE_CONTRACT_VERSION,
        )
        with self.connection() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    def _apply_critique_with_connection(
        self,
        conn: Any,
        *,
        job_id: str,
        section: dict[str, Any],
        response_payload: dict[str, Any],
    ) -> int:
        from psycopg.types.json import Jsonb

        from .scaled_corpus import candidate_id

        section_id = section["section_id"]
        updated = 0
        for item in response_payload.get("candidates", []):
            if not isinstance(item, dict) or not isinstance(item.get("critique"), dict):
                continue
            identifier = str(item.get("candidate_id"))
            critique = item["critique"]
            result = str(critique.get("result"))
            if result not in {"accept", "repair", "reject"}:
                raise CorpusDatabaseError("critique result must be accept, repair, or reject")
            grounding_status = {"accept": "accepted", "repair": "repair", "reject": "rejected"}[result]
            original = conn.execute(
                """
                SELECT extraction_job_id FROM grounded_candidates
                WHERE candidate_id = %s AND section_id = %s
                  AND grounding_status = 'pending'
                  AND extraction_contract_key = %s
                  AND critique_contract_key IS NULL
                FOR UPDATE
                """,
                (identifier, section_id, CURRENT_EXTRACTION_CONTRACT_KEY),
            ).fetchone()
            if not original:
                raise CorpusDatabaseError(
                    "critique target is missing, already processed, or belongs to another section"
                )
            cursor = conn.execute(
                """
                UPDATE grounded_candidates
                SET critique_job_id = %s, critique_contract_key = %s,
                    grounding_status = %s
                WHERE candidate_id = %s AND section_id = %s
                  AND grounding_status = 'pending'
                  AND extraction_contract_key = %s
                  AND critique_contract_key IS NULL
                """,
                (
                    job_id,
                    CURRENT_CRITIQUE_CONTRACT_KEY,
                    grounding_status,
                    identifier,
                    section_id,
                    CURRENT_EXTRACTION_CONTRACT_KEY,
                ),
            )
            updated += cursor.rowcount
            if result != "repair":
                continue

            repaired = critique.get("repaired_candidate")
            if not isinstance(repaired, dict):
                raise CorpusDatabaseError(
                    "repair critique requires a locally validated repaired_candidate"
                )
            if repaired.get("program") not in {
                str(value) for value in section.get("programs", [])
            }:
                raise CorpusDatabaseError(
                    "repaired candidate program is not linked to the source section"
                )
            repaired_identifier = candidate_id(section, repaired)
            if repaired_identifier == identifier:
                raise CorpusDatabaseError("repair critique did not change candidate semantics")
            evidence = repaired["evidence"]
            stored_candidate = {**repaired, "candidate_id": repaired_identifier}
            conn.execute(
                """
                INSERT INTO grounded_candidates (
                    candidate_id, primary_program, section_id, snapshot_hash,
                    evidence_char_start, evidence_char_end, evidence_byte_start,
                    evidence_byte_end, evidence_quote, evidence_hash,
                    extraction_job_id, extraction_contract_key,
                    critique_job_id, critique_contract_key,
                    candidate_payload, grounding_status
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, 'accepted'
                )
                ON CONFLICT (candidate_id) DO UPDATE SET
                    primary_program = EXCLUDED.primary_program,
                    section_id = EXCLUDED.section_id,
                    snapshot_hash = EXCLUDED.snapshot_hash,
                    evidence_char_start = EXCLUDED.evidence_char_start,
                    evidence_char_end = EXCLUDED.evidence_char_end,
                    evidence_byte_start = EXCLUDED.evidence_byte_start,
                    evidence_byte_end = EXCLUDED.evidence_byte_end,
                    evidence_quote = EXCLUDED.evidence_quote,
                    evidence_hash = EXCLUDED.evidence_hash,
                    extraction_job_id = EXCLUDED.extraction_job_id,
                    extraction_contract_key = EXCLUDED.extraction_contract_key,
                    critique_job_id = EXCLUDED.critique_job_id,
                    critique_contract_key = EXCLUDED.critique_contract_key,
                    candidate_payload = EXCLUDED.candidate_payload,
                    grounding_status = 'accepted'
                """,
                (
                    repaired_identifier,
                    repaired["program"],
                    section_id,
                    section["snapshot_hash"],
                    evidence["char_start"],
                    evidence["char_end"],
                    evidence["byte_start"],
                    evidence["byte_end"],
                    evidence["quote"],
                    evidence["evidence_hash"],
                    original["extraction_job_id"],
                    CURRENT_EXTRACTION_CONTRACT_KEY,
                    job_id,
                    CURRENT_CRITIQUE_CONTRACT_KEY,
                    Jsonb(stored_candidate),
                ),
            )
            lineage_id = stable_id(
                "lineage", repaired_identifier, "repaired_from", identifier, job_id
            )
            conn.execute(
                """
                INSERT INTO candidate_lineage (
                    lineage_id, candidate_id, predecessor_candidate_id, relation, details
                ) VALUES (%s, %s, %s, 'repaired_from', %s)
                ON CONFLICT (candidate_id, relation, predecessor_candidate_id) DO NOTHING
                """,
                (
                    lineage_id,
                    repaired_identifier,
                    identifier,
                    Jsonb({"critique_job_id": job_id}),
                ),
            )
            updated += 1
        return updated

    def materialize_review_drafts(self, *, limit: int = 0) -> dict[str, int]:
        from psycopg.types.json import Jsonb

        from .scaled_corpus import (
            build_typed_rule_draft,
            draft_fingerprints,
            effective_periods_overlap,
            validate_typed_rule_draft,
        )

        if limit < 0:
            raise ValueError("review draft materialization limit cannot be negative")
        created = 0
        blocked = 0
        tasks_created = 0
        clusters_created = 0
        with self.connection() as conn:
            sql = f"""
                SELECT candidates.*, contexts.canonical_url
                FROM grounded_candidates candidates
                JOIN source_sections sections USING (section_id)
                JOIN source_section_program_contexts contexts
                  ON contexts.section_id = candidates.section_id
                 AND contexts.program = candidates.primary_program
                 AND contexts.source_active
                WHERE sections.active
                  AND candidates.grounding_status = 'accepted'
                  AND {CURRENT_CANDIDATE_CONTRACT_SQL}
                  AND NOT EXISTS (
                      SELECT 1 FROM typed_rule_drafts drafts
                      WHERE drafts.candidate_id = candidates.candidate_id
                )
                ORDER BY candidates.candidate_id
            """
            params: tuple[Any, ...] = ()
            if limit > 0:
                sql += " LIMIT %s"
                params = (limit,)
            candidates = conn.execute(sql, params).fetchall()
            for candidate_row in candidates:
                candidate = dict(candidate_row)
                rule = build_typed_rule_draft(candidate)
                errors = validate_typed_rule_draft(rule)
                blockers = self._draft_blockers(errors)
                canonical_hash, semantic_fingerprint, scope_fingerprint, outcome_hash = draft_fingerprints(rule)
                draft_id = stable_id("draft", candidate["candidate_id"], 1, canonical_hash)
                peers = conn.execute(
                    """
                    SELECT draft_id, semantic_fingerprint, outcome_hash, blocker_codes,
                           frozen, canonical_rule
                    FROM typed_rule_drafts
                    WHERE scope_fingerprint = %s
                    ORDER BY draft_id
                    """,
                    (scope_fingerprint,),
                ).fetchall()
                overlapping_peers = [
                    peer
                    for peer in peers
                    if not errors
                    and effective_periods_overlap(rule, peer["canonical_rule"])
                ]
                cluster_kind = None
                blocker_code = None
                if overlapping_peers:
                    same_period = all(
                        peer["semantic_fingerprint"] == semantic_fingerprint
                        for peer in overlapping_peers
                    )
                    same_outcome = all(peer["outcome_hash"] == outcome_hash for peer in overlapping_peers)
                    if not same_outcome:
                        cluster_kind = "conflicting_outcome"
                        blocker_code = "conflicting_duplicate"
                    elif same_period:
                        cluster_kind = "semantic_duplicate"
                        blocker_code = "semantic_duplicate"
                    else:
                        cluster_kind = "overlapping_effective_period"
                        blocker_code = "semantic_duplicate"
                    blockers.add(blocker_code)
                conn.execute(
                    """
                    INSERT INTO typed_rule_drafts (
                        draft_id, candidate_id, draft_version, canonical_rule,
                        canonical_hash, semantic_fingerprint, scope_fingerprint, outcome_hash,
                        validation_errors, blocker_codes, runtime_eligibility_status
                    ) VALUES (%s, %s, 1, %s, %s, %s, %s, %s, %s, %s, 'shadow_only')
                    """,
                    (
                        draft_id,
                        candidate["candidate_id"],
                        Jsonb(rule),
                        canonical_hash,
                        semantic_fingerprint,
                        scope_fingerprint,
                        outcome_hash,
                        Jsonb(errors),
                        Jsonb(sorted(blockers)),
                    ),
                )
                created += 1
                if cluster_kind:
                    for peer in overlapping_peers:
                        peer_blockers = set(peer["blocker_codes"] or [])
                        peer_blockers.add(blocker_code)
                        if not peer["frozen"]:
                            conn.execute(
                                "UPDATE typed_rule_drafts SET blocker_codes = %s WHERE draft_id = %s",
                                (Jsonb(sorted(peer_blockers)), peer["draft_id"]),
                            )
                    member_ids = sorted([draft_id, *(peer["draft_id"] for peer in overlapping_peers)])
                    cluster_id = stable_id("cluster", cluster_kind, scope_fingerprint, member_ids)
                    conn.execute(
                        """
                        INSERT INTO duplicate_conflict_clusters (
                            cluster_id, cluster_kind, status, fingerprint
                        ) VALUES (%s, %s, 'open', %s)
                        ON CONFLICT (cluster_id) DO NOTHING
                        """,
                        (cluster_id, cluster_kind, scope_fingerprint),
                    )
                    for member_id in member_ids:
                        conn.execute(
                            """
                            INSERT INTO duplicate_conflict_members (cluster_id, draft_id)
                            VALUES (%s, %s) ON CONFLICT DO NOTHING
                            """,
                            (cluster_id, member_id),
                        )
                    conflict_task_id = stable_id("task", cluster_id, "conflict_resolution")
                    conn.execute(
                        """
                        INSERT INTO reviewer_tasks (
                            task_id, draft_id, cluster_id, task_type, status
                        ) VALUES (%s, %s, %s, 'conflict_resolution', 'pending')
                        ON CONFLICT (draft_id, task_type) DO NOTHING
                        """,
                        (conflict_task_id, draft_id, cluster_id),
                    )
                    clusters_created += 1
                if errors or blockers:
                    blocked += 1
                    continue
                task_id = stable_id("task", draft_id, "policy_review")
                conn.execute(
                    """
                    INSERT INTO reviewer_tasks (task_id, draft_id, task_type, status)
                    VALUES (%s, %s, 'policy_review', 'pending')
                    ON CONFLICT (draft_id, task_type) DO NOTHING
                    """,
                    (task_id, draft_id),
                )
                tasks_created += 1
            conn.commit()
        return {
            "candidates_processed": len(candidates),
            "drafts_created": created,
            "drafts_blocked": blocked,
            "policy_tasks_created": tasks_created,
            "clusters_created": clusters_created,
        }

    @staticmethod
    def _draft_blockers(errors: list[str]) -> set[str]:
        blockers: set[str] = set()
        for error in errors:
            lowered = error.lower()
            if "operator" in lowered:
                blockers.add("unsupported_operator")
            elif "fact" in lowered or "typed" in lowered:
                blockers.add("missing_typed_fact")
            elif "effective_from is required" in lowered:
                blockers.add("missing_effective_date")
            elif "effective" in lowered or "yyyy-mm-dd" in lowered:
                blockers.add("invalid_effective_date")
            elif "source" in lowered or "authority" in lowered or "citation" in lowered:
                blockers.add("missing_provenance")
            else:
                blockers.add("schema_validation_failed")
        return blockers

    def fail_inference_job(
        self,
        job_id: str,
        *,
        worker_id: str,
        error: str,
        retry: bool,
        rejected: bool = False,
        input_tokens: int = 0,
        output_tokens: int = 0,
        usage_metadata: dict[str, Any] | None = None,
    ) -> None:
        from psycopg.types.json import Jsonb

        if input_tokens < 0 or output_tokens < 0:
            raise ValueError("inference token usage cannot be negative")
        if retry and rejected:
            raise ValueError("a rejected inference response cannot be retried")
        status = "pending" if retry else ("rejected" if rejected else "failed")
        with self.connection() as conn:
            job = conn.execute(
                """
                SELECT usage_metadata
                FROM inference_jobs
                WHERE inference_job_id = %s AND status = 'leased'
                  AND lease_owner = %s
                FOR UPDATE
                """,
                (job_id, worker_id),
            ).fetchone()
            if not job:
                raise CorpusDatabaseError(
                    "inference lease was lost before failure recording"
                )
            existing_metadata = (
                dict(job["usage_metadata"])
                if isinstance(job["usage_metadata"], dict)
                else {}
            )
            metadata = dict(usage_metadata or {})
            previous_history = existing_metadata.get("attempts", [])
            usage_history = (
                list(previous_history) if isinstance(previous_history, list) else []
            )
            if metadata or input_tokens or output_tokens:
                usage_history.append(
                    {
                        **metadata,
                        "status": (
                            "retry_scheduled"
                            if retry
                            else ("rejected" if rejected else "failed")
                        ),
                        "input_tokens": input_tokens,
                        "output_tokens": output_tokens,
                    }
                )
            combined_metadata = {
                **existing_metadata,
                **metadata,
                "attempts": usage_history,
            }
            cursor = conn.execute(
                """
                UPDATE inference_jobs SET status = %s, last_error = %s,
                    input_tokens = input_tokens + %s,
                    output_tokens = output_tokens + %s,
                    usage_metadata = %s,
                    lease_owner = NULL, lease_expires_at = NULL
                WHERE inference_job_id = %s AND status = 'leased' AND lease_owner = %s
                """,
                (
                    status,
                    error[:4000],
                    input_tokens,
                    output_tokens,
                    Jsonb(combined_metadata),
                    job_id,
                    worker_id,
                ),
            )
            if cursor.rowcount != 1:
                raise CorpusDatabaseError("inference lease was lost before failure recording")
            conn.commit()

    def import_blocked_baseline(self, workdir: Path) -> int:
        from psycopg.types.json import Jsonb

        queue = build_promotion_queue(workdir)
        with self.connection() as conn:
            for item in queue["items"]:
                payload_hash = canonical_sha256(item)
                conn.execute(
                    """
                    INSERT INTO legacy_baseline_candidates (
                        baseline_id, source_payload, source_payload_hash, program, blocker_codes
                    ) VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (source_payload_hash) DO NOTHING
                    """,
                    (
                        stable_id("base", payload_hash),
                        Jsonb(item),
                        payload_hash,
                        item["program"],
                        Jsonb(item["blockers"]),
                    ),
                )
            conn.commit()
        return len(queue["items"])

    def _cancel_stale_review_tasks_with_connection(
        self,
        conn: Any,
        *,
        task_type: str | None = None,
    ) -> list[dict[str, Any]]:
        """Cancel claimable work whose source, section, or draft is no longer current."""
        from psycopg.types.json import Jsonb

        rows = conn.execute(
            f"""
            WITH latest_drafts AS (
                SELECT DISTINCT ON (candidate_id) candidate_id, draft_id
                FROM typed_rule_drafts
                ORDER BY candidate_id, draft_version DESC, draft_id
            )
            UPDATE reviewer_tasks AS tasks
            SET status = 'cancelled', assigned_reviewer_id = NULL,
                claimed_at = NULL, claim_expires_at = NULL
            WHERE tasks.status IN ('pending', 'claimed')
              AND (%s::text IS NULL OR tasks.task_type = %s)
              AND NOT EXISTS (
                  SELECT 1
                  FROM typed_rule_drafts drafts
                  JOIN latest_drafts current
                    ON current.candidate_id = drafts.candidate_id
                   AND current.draft_id = drafts.draft_id
                  JOIN grounded_candidates candidates
                    ON candidates.candidate_id = drafts.candidate_id
                  JOIN source_sections sections
                    ON sections.section_id = candidates.section_id
                  JOIN source_section_program_contexts contexts
                    ON contexts.section_id = candidates.section_id
                   AND contexts.program = candidates.primary_program
                   AND contexts.source_active
                  WHERE drafts.draft_id = tasks.draft_id
                    AND sections.active
                    AND candidates.grounding_status = 'accepted'
                    AND {CURRENT_CANDIDATE_CONTRACT_SQL}
                    AND (
                        tasks.task_type <> 'conflict_resolution'
                        OR NOT EXISTS (
                            SELECT 1
                            FROM duplicate_conflict_members members
                            JOIN typed_rule_drafts member_drafts
                              ON member_drafts.draft_id = members.draft_id
                            LEFT JOIN latest_drafts member_current
                              ON member_current.candidate_id = member_drafts.candidate_id
                            JOIN grounded_candidates member_candidates
                              ON member_candidates.candidate_id = member_drafts.candidate_id
                            JOIN source_sections member_sections
                              ON member_sections.section_id = member_candidates.section_id
                            LEFT JOIN source_section_program_contexts member_contexts
                              ON member_contexts.section_id = member_candidates.section_id
                             AND member_contexts.program = member_candidates.primary_program
                             AND member_contexts.source_active
                            WHERE members.cluster_id = tasks.cluster_id
                              AND (
                                  member_current.draft_id IS DISTINCT FROM member_drafts.draft_id
                                  OR member_contexts.section_id IS NULL
                                  OR NOT member_sections.active
                                  OR member_candidates.grounding_status <> 'accepted'
                                  OR NOT ({CURRENT_MEMBER_CANDIDATE_CONTRACT_SQL})
                              )
                        )
                    )
              )
            RETURNING tasks.task_id, tasks.task_type, tasks.claim_attempts
            """,
            (task_type, task_type),
        ).fetchall()
        cancelled = [dict(row) for row in rows]
        for item in cancelled:
            audit_id = stable_id(
                "audit",
                item["task_id"],
                "task_cancelled_superseded_lineage",
            )
            conn.execute(
                f"""
                INSERT INTO review_audit_events (
                    event_id, actor_id, action, entity_type, entity_id, payload
                ) VALUES (%s, 'rules-system', 'task_cancelled_superseded_lineage',
                          'reviewer_task', %s, %s)
                ON CONFLICT (event_id) DO NOTHING
                """,
                (
                    audit_id,
                    item["task_id"],
                    Jsonb(
                        {
                            "task_type": item["task_type"],
                            "claim_attempts": item["claim_attempts"],
                            "reason": "source, section, candidate, conflict, or draft is no longer current",
                        }
                    ),
                ),
            )
        return cancelled

    def claim_review_task(
        self,
        reviewer_id: str,
        reviewer_role: str,
        *,
        lease_seconds: int = DEFAULT_REVIEW_LEASE_SECONDS,
    ) -> dict[str, Any] | None:
        from psycopg.types.json import Jsonb

        task_type = {
            "policy_reviewer": "policy_review",
            "legal_verifier": "legal_verification",
            "rules_admin": "conflict_resolution",
        }.get(reviewer_role)
        if not task_type:
            raise ValueError("unsupported reviewer role")
        if not reviewer_id.strip():
            raise ValueError("reviewer ID is required")
        if lease_seconds <= 0:
            raise ValueError("review task lease must be positive")
        with self.connection() as conn:
            self._cancel_stale_review_tasks_with_connection(
                conn, task_type=task_type
            )
            expired = conn.execute(
                """
                UPDATE reviewer_tasks
                SET status = 'pending', assigned_reviewer_id = NULL,
                    claimed_at = NULL, claim_expires_at = NULL
                WHERE task_type = %s AND status = 'claimed'
                  AND (claim_expires_at IS NULL OR claim_expires_at <= now())
                RETURNING task_id, claim_attempts
                """,
                (task_type,),
            ).fetchall()
            for item in expired:
                audit_id = stable_id(
                    "audit",
                    item["task_id"],
                    "task_claim_expired",
                    item["claim_attempts"],
                )
                conn.execute(
                    """
                    INSERT INTO review_audit_events (
                        event_id, actor_id, action, entity_type, entity_id, payload
                    ) VALUES (%s, 'rules-system', 'task_claim_expired',
                              'reviewer_task', %s, %s)
                    ON CONFLICT (event_id) DO NOTHING
                    """,
                    (
                        audit_id,
                        item["task_id"],
                        Jsonb({"claim_attempts": item["claim_attempts"]}),
                    ),
                )
            row = conn.execute(
                f"""
                WITH latest_drafts AS (
                    SELECT DISTINCT ON (candidate_id) candidate_id, draft_id
                    FROM typed_rule_drafts
                    ORDER BY candidate_id, draft_version DESC, draft_id
                ), claimable AS (
                    SELECT tasks.task_id
                    FROM reviewer_tasks tasks
                    JOIN typed_rule_drafts drafts USING (draft_id)
                    JOIN latest_drafts current
                      ON current.candidate_id = drafts.candidate_id
                     AND current.draft_id = drafts.draft_id
                    JOIN grounded_candidates candidates
                      ON candidates.candidate_id = drafts.candidate_id
                    JOIN source_sections sections
                      ON sections.section_id = candidates.section_id
                    JOIN source_section_program_contexts contexts
                      ON contexts.section_id = candidates.section_id
                     AND contexts.program = candidates.primary_program
                     AND contexts.source_active
                    WHERE tasks.task_type = %s AND tasks.status = 'pending'
                      AND sections.active
                      AND candidates.grounding_status = 'accepted'
                      AND {CURRENT_CANDIDATE_CONTRACT_SQL}
                    ORDER BY tasks.created_at, tasks.task_id
                    FOR UPDATE OF tasks, candidates, sections SKIP LOCKED
                    LIMIT 1
                )
                UPDATE reviewer_tasks AS tasks
                SET status = 'claimed', assigned_reviewer_id = %s,
                    claimed_at = now(),
                    claim_expires_at = now() + make_interval(secs => %s),
                    claim_attempts = claim_attempts + 1
                FROM claimable
                WHERE tasks.task_id = claimable.task_id
                RETURNING tasks.*
                """,
                (task_type, reviewer_id, lease_seconds),
            ).fetchone()
            if row:
                row = conn.execute(
                    """
                    SELECT tasks.*, drafts.candidate_id
                    FROM reviewer_tasks tasks
                    JOIN typed_rule_drafts drafts USING (draft_id)
                    WHERE tasks.task_id = %s
                    """,
                    (row["task_id"],),
                ).fetchone()
                audit_id = stable_id(
                    "audit",
                    row["task_id"],
                    reviewer_id,
                    "claimed",
                    str(row["claimed_at"]),
                )
                conn.execute(
                    """
                    INSERT INTO review_audit_events (
                        event_id, actor_id, action, entity_type, entity_id, payload
                    ) VALUES (%s, %s, 'task_claimed', 'reviewer_task', %s, %s)
                    ON CONFLICT (event_id) DO NOTHING
                    """,
                    (
                        audit_id,
                        reviewer_id,
                        row["task_id"],
                        Jsonb(
                            {
                                "reviewer_role": reviewer_role,
                                "claim_attempts": row["claim_attempts"],
                                "claim_expires_at": str(row["claim_expires_at"]),
                            }
                        ),
                    ),
                )
            conn.commit()
        return dict(row) if row else None

    def renew_review_task_claim(
        self,
        task_id: str,
        *,
        reviewer_id: str,
        reviewer_role: str,
        lease_seconds: int = DEFAULT_REVIEW_LEASE_SECONDS,
    ) -> dict[str, Any]:
        return self._update_review_task_claim(
            task_id,
            reviewer_id=reviewer_id,
            reviewer_role=reviewer_role,
            action="renew",
            lease_seconds=lease_seconds,
        )

    def release_review_task_claim(
        self,
        task_id: str,
        *,
        reviewer_id: str,
        reviewer_role: str,
    ) -> dict[str, Any]:
        return self._update_review_task_claim(
            task_id,
            reviewer_id=reviewer_id,
            reviewer_role=reviewer_role,
            action="release",
            lease_seconds=DEFAULT_REVIEW_LEASE_SECONDS,
        )

    def _update_review_task_claim(
        self,
        task_id: str,
        *,
        reviewer_id: str,
        reviewer_role: str,
        action: str,
        lease_seconds: int,
    ) -> dict[str, Any]:
        from psycopg.types.json import Jsonb

        task_type = {
            "policy_reviewer": "policy_review",
            "legal_verifier": "legal_verification",
            "rules_admin": "conflict_resolution",
        }.get(reviewer_role)
        if not task_type:
            raise ValueError("unsupported reviewer role")
        if action not in {"renew", "release"}:
            raise ValueError("unsupported review task claim action")
        if not reviewer_id.strip():
            raise ValueError("reviewer ID is required")
        if lease_seconds <= 0:
            raise ValueError("review task lease must be positive")
        if action == "renew":
            assignment = "claim_expires_at = now() + make_interval(secs => %s)"
            params: tuple[Any, ...] = (
                lease_seconds,
                task_id,
                task_type,
                reviewer_id,
            )
        else:
            assignment = (
                "status = 'pending', assigned_reviewer_id = NULL, "
                "claimed_at = NULL, claim_expires_at = NULL"
            )
            params = (task_id, task_type, reviewer_id)
        with self.connection() as conn:
            cancelled = self._cancel_stale_review_tasks_with_connection(
                conn, task_type=task_type
            )
            if any(item["task_id"] == task_id for item in cancelled):
                conn.commit()
                raise CorpusDatabaseError(
                    "review task source, section, candidate, conflict, or draft is superseded"
                )
            row = conn.execute(
                f"""
                UPDATE reviewer_tasks
                SET {assignment}
                WHERE task_id = %s AND task_type = %s
                  AND status = 'claimed'
                  AND assigned_reviewer_id = %s
                  AND claim_expires_at > now()
                RETURNING task_id, status, claim_expires_at, claim_attempts
                """,
                params,
            ).fetchone()
            if not row:
                raise CorpusDatabaseError(
                    "review task claim is missing, expired, or owned by another reviewer"
                )
            audit_id = stable_id(
                "audit",
                task_id,
                reviewer_id,
                f"task_claim_{action}",
                row["claim_attempts"],
                str(row["claim_expires_at"]),
            )
            conn.execute(
                f"""
                INSERT INTO review_audit_events (
                    event_id, actor_id, action, entity_type, entity_id, payload
                ) VALUES (%s, %s, %s, 'reviewer_task', %s, %s)
                ON CONFLICT (event_id) DO NOTHING
                """,
                (
                    audit_id,
                    reviewer_id,
                    f"task_claim_{action}",
                    task_id,
                    Jsonb(
                        {
                            "reviewer_role": reviewer_role,
                            "claim_attempts": row["claim_attempts"],
                            "claim_expires_at": str(row["claim_expires_at"])
                            if row["claim_expires_at"]
                            else None,
                        }
                    ),
                ),
            )
            conn.commit()
        return {
            **dict(row),
            "action": action,
            "runtime_activation": False,
            "proof_binding": False,
        }

    def list_review_tasks(self, reviewer_role: str, *, limit: int = 100) -> list[dict[str, Any]]:
        task_type = {
            "policy_reviewer": "policy_review",
            "legal_verifier": "legal_verification",
            "rules_admin": "conflict_resolution",
        }.get(reviewer_role)
        if not task_type:
            raise ValueError("unsupported reviewer role")
        with self.connection() as conn:
            self._cancel_stale_review_tasks_with_connection(
                conn, task_type=task_type
            )
            rows = conn.execute(
                f"""
                WITH latest_drafts AS (
                    SELECT DISTINCT ON (candidate_id) candidate_id, draft_id
                    FROM typed_rule_drafts
                    ORDER BY candidate_id, draft_version DESC, draft_id
                )
                SELECT tasks.task_id, tasks.draft_id, drafts.candidate_id,
                       tasks.task_type, tasks.status, tasks.assigned_reviewer_id,
                       tasks.claimed_at, tasks.claim_expires_at,
                       tasks.claim_attempts, tasks.completed_at, tasks.created_at
                FROM reviewer_tasks tasks
                JOIN typed_rule_drafts drafts USING (draft_id)
                JOIN latest_drafts current
                  ON current.candidate_id = drafts.candidate_id
                 AND current.draft_id = drafts.draft_id
                JOIN grounded_candidates candidates
                  ON candidates.candidate_id = drafts.candidate_id
                JOIN source_sections sections
                  ON sections.section_id = candidates.section_id
                JOIN source_section_program_contexts contexts
                  ON contexts.section_id = candidates.section_id
                 AND contexts.program = candidates.primary_program
                 AND contexts.source_active
                WHERE tasks.task_type = %s
                  AND tasks.status <> 'cancelled'
                  AND sections.active
                  AND candidates.grounding_status = 'accepted'
                  AND {CURRENT_CANDIDATE_CONTRACT_SQL}
                ORDER BY tasks.status, tasks.created_at, tasks.task_id
                LIMIT %s
                """,
                (task_type, max(1, min(limit, 500))),
            ).fetchall()
            conn.commit()
        return [dict(row) for row in rows]

    def candidate_review_detail(self, candidate_id: str) -> dict[str, Any]:
        with self.connection() as conn:
            row = conn.execute(
                f"""
                SELECT candidates.candidate_id, candidates.primary_program,
                       candidates.evidence_quote, candidates.evidence_char_start,
                       candidates.evidence_char_end, candidates.evidence_hash,
                       candidates.grounding_status, candidates.candidate_payload,
                       candidates.extraction_contract_key,
                       candidates.critique_contract_key,
                       sections.heading, sections.normalized_text,
                       sections.hierarchy_path, sections.active AS section_active,
                       sections.extraction_pipeline_version,
                       contexts.source_active,
                       contexts.canonical_url,
                       contexts.retrieved_at, snapshots.text_layer_kind
                FROM grounded_candidates candidates
                JOIN source_sections sections USING (section_id)
                JOIN source_section_program_contexts contexts
                  ON contexts.section_id = candidates.section_id
                 AND contexts.program = candidates.primary_program
                JOIN source_snapshots snapshots
                  ON snapshots.snapshot_hash = candidates.snapshot_hash
                WHERE candidates.candidate_id = %s
                """,
                (candidate_id,),
            ).fetchone()
            if not row:
                raise CorpusDatabaseError("candidate does not exist")
            drafts = conn.execute(
                """
                SELECT draft_id, draft_version, canonical_rule, canonical_hash,
                       validation_errors, blocker_codes, frozen, runtime_eligibility_status
                FROM typed_rule_drafts WHERE candidate_id = %s
                ORDER BY draft_version DESC
                """,
                (candidate_id,),
            ).fetchall()
            decisions = conn.execute(
                """
                SELECT decision_id, reviewer_id, reviewer_role, decision, draft_hash,
                       rationale, created_at
                FROM reviewer_decisions WHERE draft_id IN (
                    SELECT draft_id FROM typed_rule_drafts WHERE candidate_id = %s
                ) ORDER BY created_at
                """,
                (candidate_id,),
            ).fetchall()
        detail = dict(row)
        detail["current_inference_contract"] = (
            detail["extraction_contract_key"]
            == CURRENT_EXTRACTION_CONTRACT_KEY
            and detail["critique_contract_key"]
            == CURRENT_CRITIQUE_CONTRACT_KEY
        )
        return {
            **detail,
            "drafts": [dict(item) for item in drafts],
            "decisions": [dict(item) for item in decisions],
        }

    def record_review_decision(
        self,
        *,
        task_id: str,
        reviewer_id: str,
        reviewer_role: str,
        decision: str,
        rationale: str,
        selected_draft_id: str | None = None,
    ) -> str:
        if decision not in {"approve", "reject", "request_changes", "resolve"}:
            raise ValueError("unsupported review decision")
        if not rationale.strip():
            raise ValueError("review rationale is required")
        with self.connection() as conn:
            cancelled = self._cancel_stale_review_tasks_with_connection(conn)
            if any(item["task_id"] == task_id for item in cancelled):
                conn.commit()
                raise CorpusDatabaseError(
                    "review task source, section, candidate, conflict, or draft is superseded"
                )
            task = conn.execute(
                f"""
                WITH latest_drafts AS (
                    SELECT DISTINCT ON (candidate_id) candidate_id, draft_id
                    FROM typed_rule_drafts
                    ORDER BY candidate_id, draft_version DESC, draft_id
                )
                SELECT tasks.*, drafts.canonical_hash,
                       tasks.claim_expires_at IS NOT NULL
                           AND tasks.claim_expires_at > now() AS claim_live
                FROM reviewer_tasks tasks
                JOIN typed_rule_drafts drafts ON drafts.draft_id = tasks.draft_id
                JOIN latest_drafts current
                  ON current.candidate_id = drafts.candidate_id
                 AND current.draft_id = drafts.draft_id
                JOIN grounded_candidates candidates
                  ON candidates.candidate_id = drafts.candidate_id
                JOIN source_sections sections
                  ON sections.section_id = candidates.section_id
                JOIN source_section_program_contexts contexts
                  ON contexts.section_id = candidates.section_id
                 AND contexts.program = candidates.primary_program
                 AND contexts.source_active
                WHERE tasks.task_id = %s
                  AND sections.active
                  AND candidates.grounding_status = 'accepted'
                  AND {CURRENT_CANDIDATE_CONTRACT_SQL}
                FOR UPDATE OF tasks, candidates
                FOR SHARE OF sections
                """,
                (task_id,),
            ).fetchone()
            if (
                not task
                or task["status"] != "claimed"
                or task["assigned_reviewer_id"] != reviewer_id
                or not task["claim_live"]
            ):
                raise CorpusDatabaseError("review task is not claimed by this reviewer")
            expected_role = {
                "policy_review": "policy_reviewer",
                "legal_verification": "legal_verifier",
                "conflict_resolution": "rules_admin",
                "quality_review": reviewer_role,
            }[task["task_type"]]
            if reviewer_role != expected_role:
                raise CorpusDatabaseError("reviewer role does not match task type")
            if task["task_type"] in {"policy_review", "legal_verification"} and decision == "resolve":
                raise CorpusDatabaseError("policy and legal tasks cannot use the resolve decision")
            if task["task_type"] == "conflict_resolution":
                if decision != "resolve" or not selected_draft_id:
                    raise CorpusDatabaseError("conflict resolution requires resolve and a selected draft")
                selected = conn.execute(
                    """
                    SELECT 1 FROM duplicate_conflict_members
                    WHERE cluster_id = %s AND draft_id = %s
                    """,
                    (task["cluster_id"], selected_draft_id),
                ).fetchone()
                if not selected:
                    raise CorpusDatabaseError("selected draft is not a member of the conflict cluster")
            if task["task_type"] == "legal_verification":
                policy = conn.execute(
                    """
                    SELECT decisions.reviewer_id
                    FROM reviewer_decisions decisions
                    JOIN reviewer_tasks prior ON prior.task_id = decisions.task_id
                    WHERE decisions.draft_id = %s AND prior.task_type = 'policy_review'
                      AND decisions.decision = 'approve'
                      AND decisions.draft_hash = %s
                    ORDER BY decisions.created_at DESC LIMIT 1
                    """,
                    (task["draft_id"], task["canonical_hash"]),
                ).fetchone()
                if not policy:
                    raise CorpusDatabaseError("legal verification requires a matching policy approval")
                if policy["reviewer_id"] == reviewer_id:
                    raise CorpusDatabaseError("policy and legal reviewers must be different people")
            decision_id = stable_id(
                "decision",
                task_id,
                reviewer_id,
                reviewer_role,
                decision,
                task["canonical_hash"],
                datetime.now(timezone.utc).isoformat(),
            )
            conn.execute(
                f"""
                INSERT INTO reviewer_decisions (
                    decision_id, task_id, draft_id, reviewer_id, reviewer_role,
                    decision, draft_hash, rationale
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    decision_id,
                    task_id,
                    task["draft_id"],
                    reviewer_id,
                    reviewer_role,
                    decision,
                    task["canonical_hash"],
                    rationale.strip(),
                ),
            )
            if task["task_type"] == "policy_review" and decision == "approve":
                conn.execute(
                    "UPDATE typed_rule_drafts SET frozen = true WHERE draft_id = %s",
                    (task["draft_id"],),
                )
                legal_task_id = stable_id("task", task["draft_id"], "legal_verification")
                conn.execute(
                    """
                    INSERT INTO reviewer_tasks (task_id, draft_id, task_type, status)
                    VALUES (%s, %s, 'legal_verification', 'pending')
                    ON CONFLICT (draft_id, task_type) DO NOTHING
                    """,
                    (legal_task_id, task["draft_id"]),
                )
            if task["task_type"] == "conflict_resolution":
                from psycopg.types.json import Jsonb

                conn.execute(
                    """
                    UPDATE duplicate_conflict_clusters
                    SET status = 'resolved', resolution = %s, resolved_at = now()
                    WHERE cluster_id = %s AND status = 'open'
                    """,
                    (
                        Jsonb(
                            {
                                "selected_draft_id": selected_draft_id,
                                "reviewer_id": reviewer_id,
                                "decision_id": decision_id,
                            }
                        ),
                        task["cluster_id"],
                    ),
                )
            from psycopg.types.json import Jsonb

            audit_id = stable_id("audit", decision_id, "review_decision")
            conn.execute(
                """
                INSERT INTO review_audit_events (
                    event_id, actor_id, action, entity_type, entity_id, payload
                ) VALUES (%s, %s, 'review_decision', 'reviewer_task', %s, %s)
                """,
                (
                    audit_id,
                    reviewer_id,
                    task_id,
                    Jsonb(
                        {
                            "decision_id": decision_id,
                            "reviewer_role": reviewer_role,
                            "decision": decision,
                            "draft_hash": task["canonical_hash"],
                            "selected_draft_id": selected_draft_id,
                        }
                    ),
                ),
            )
            conn.execute(
                """
                UPDATE reviewer_tasks
                SET status = 'completed', completed_at = now(),
                    assigned_reviewer_id = NULL, claimed_at = NULL,
                    claim_expires_at = NULL
                WHERE task_id = %s
                """,
                (task_id,),
            )
            conn.commit()
        return decision_id

    def quality_sample_candidates(self) -> list[dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute(
                f"""
                WITH latest_drafts AS (
                    SELECT DISTINCT ON (candidate_id)
                           candidate_id, draft_id, canonical_hash, draft_version,
                           validation_errors
                    FROM typed_rule_drafts
                    ORDER BY candidate_id, draft_version DESC, draft_id
                )
                SELECT candidates.candidate_id, candidates.primary_program,
                       drafts.draft_id, drafts.canonical_hash AS draft_hash,
                       candidates.snapshot_hash, candidates.section_id,
                       candidates.extraction_contract_key,
                       candidates.critique_contract_key,
                       contexts.registry_version AS source_registry_version,
                       sections.extraction_pipeline_version,
                       array_remove(ARRAY[
                           CASE WHEN sections.ocr_used
                                THEN 'ocr_evidence' END,
                           CASE WHEN candidates.candidate_payload ? 'provenance_warning'
                                THEN 'provenance_warning' END,
                           CASE WHEN candidates.candidate_payload->>'confidence' ~ '^[0-9]+(?:\\.[0-9]+)?$'
                                  AND (candidates.candidate_payload->>'confidence')::numeric < 0.85
                                THEN 'low_confidence' END,
                           CASE WHEN EXISTS (
                               SELECT 1 FROM duplicate_conflict_members members
                               JOIN duplicate_conflict_clusters clusters USING (cluster_id)
                               WHERE members.draft_id = drafts.draft_id
                           ) THEN 'duplicate_or_conflict' END
                       ], NULL) AS mandatory_reasons
                FROM grounded_candidates candidates
                JOIN source_snapshots snapshots
                  ON snapshots.snapshot_hash = candidates.snapshot_hash
                JOIN source_sections sections
                  ON sections.section_id = candidates.section_id
                JOIN source_section_program_contexts contexts
                  ON contexts.section_id = candidates.section_id
                 AND contexts.program = candidates.primary_program
                 AND contexts.source_active
                JOIN latest_drafts drafts
                  ON drafts.candidate_id = candidates.candidate_id
                WHERE sections.active
                  AND candidates.grounding_status = 'accepted'
                  AND {CURRENT_CANDIDATE_CONTRACT_SQL}
                  AND drafts.validation_errors = '[]'::jsonb
                ORDER BY candidates.candidate_id
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def plan_quality_samples(
        self,
        *,
        release_id: str,
        target_count: int = 1_020,
        corpus_target_count: int = 5_100,
    ) -> dict[str, Any]:
        from .quality_sampling import build_quality_sample_plan
        from .scaled_corpus import select_balanced_release_candidates

        selection = select_balanced_release_candidates(
            self.quality_sample_candidates(), corpus_target_count
        )
        if selection["total_deficit"]:
            raise CorpusDatabaseError(
                "quality sample release cohort does not meet every program quota"
            )
        plan = build_quality_sample_plan(
            release_id=release_id,
            candidates=selection["selected_candidates"],
            target_count=target_count,
        )
        selected_candidate_ids = [
            candidate["candidate_id"] for candidate in selection["selected_candidates"]
        ]
        selected_cohort_lineage = {
            candidate["candidate_id"]: (
                candidate["draft_id"],
                candidate["draft_hash"],
                candidate["snapshot_hash"],
                candidate["section_id"],
                candidate["source_registry_version"],
                candidate["extraction_pipeline_version"],
                candidate["extraction_contract_key"],
                candidate["critique_contract_key"],
            )
            for candidate in selection["selected_candidates"]
        }
        expected = {
            sample["sample_id"]: (
                sample["candidate_id"],
                sample["draft_id"],
                sample["draft_hash"],
                sample["stratum"],
                sample["mandatory_reason"],
            )
            for sample in plan["samples"]
        }
        inserted = 0
        from psycopg.types.json import Jsonb

        with self.connection() as conn:
            cohort_rows = conn.execute(
                """
                SELECT corpus_target_count, candidate_id, selection_hash,
                       draft_id, draft_hash, snapshot_hash, section_id,
                       source_registry_version, extraction_pipeline_version,
                       extraction_contract_key, critique_contract_key
                FROM corpus_release_cohorts
                WHERE release_id = %s
                ORDER BY candidate_id
                """,
                (release_id,),
            ).fetchall()
            if cohort_rows:
                existing_ids = [row["candidate_id"] for row in cohort_rows]
                existing_targets = {
                    int(row["corpus_target_count"]) for row in cohort_rows
                }
                existing_hashes = {row["selection_hash"] for row in cohort_rows}
                existing_lineage = {
                    row["candidate_id"]: (
                        row["draft_id"],
                        row["draft_hash"],
                        row["snapshot_hash"],
                        row["section_id"],
                        row["source_registry_version"],
                        row["extraction_pipeline_version"],
                        row["extraction_contract_key"],
                        row["critique_contract_key"],
                    )
                    for row in cohort_rows
                }
                if (
                    existing_ids != selected_candidate_ids
                    or existing_targets != {corpus_target_count}
                    or existing_hashes != {selection["selection_hash"]}
                    or existing_lineage != selected_cohort_lineage
                ):
                    raise CorpusDatabaseError(
                        "release ID already has a different immutable corpus cohort"
                    )
            else:
                for start in range(0, len(selected_candidate_ids), 5_000):
                    batch_ids = selected_candidate_ids[start : start + 5_000]
                    conn.execute(
                        """
                        INSERT INTO corpus_release_cohorts (
                            release_id, corpus_target_count, candidate_id,
                            selection_hash, draft_id, draft_hash, snapshot_hash,
                            section_id, source_registry_version,
                            extraction_pipeline_version,
                            extraction_contract_key, critique_contract_key
                        )
                        SELECT %s, %s, selected.candidate_id, %s,
                               selected.draft_id, selected.draft_hash,
                               selected.snapshot_hash, selected.section_id,
                               selected.source_registry_version,
                               selected.extraction_pipeline_version,
                               selected.extraction_contract_key,
                               selected.critique_contract_key
                        FROM jsonb_to_recordset(%s) AS selected(
                            candidate_id text,
                            draft_id text,
                            draft_hash char(64),
                            snapshot_hash char(64),
                            section_id text,
                            source_registry_version text,
                            extraction_pipeline_version text,
                            extraction_contract_key char(64),
                            critique_contract_key char(64)
                        )
                        """,
                        (
                            release_id,
                            corpus_target_count,
                            selection["selection_hash"],
                            Jsonb(
                                [
                                    {
                                        "candidate_id": candidate_id,
                                        "draft_id": selected_cohort_lineage[
                                            candidate_id
                                        ][0],
                                        "draft_hash": selected_cohort_lineage[
                                            candidate_id
                                        ][1],
                                        "snapshot_hash": selected_cohort_lineage[
                                            candidate_id
                                        ][2],
                                        "section_id": selected_cohort_lineage[
                                            candidate_id
                                        ][3],
                                        "source_registry_version": selected_cohort_lineage[
                                            candidate_id
                                        ][4],
                                        "extraction_pipeline_version": selected_cohort_lineage[
                                            candidate_id
                                        ][5],
                                        "extraction_contract_key": selected_cohort_lineage[
                                            candidate_id
                                        ][6],
                                        "critique_contract_key": selected_cohort_lineage[
                                            candidate_id
                                        ][7],
                                    }
                                    for candidate_id in batch_ids
                                ]
                            ),
                        ),
                    )
            existing_rows = conn.execute(
                """
                SELECT sample_id, corpus_target_count, candidate_id, draft_id,
                       draft_hash, stratum, mandatory_reason
                FROM quality_sample_plans WHERE release_id = %s ORDER BY sample_id
                """,
                (release_id,),
            ).fetchall()
            for row in existing_rows:
                actual = (
                    int(row["corpus_target_count"]),
                    row["candidate_id"],
                    row["draft_id"],
                    row["draft_hash"],
                    row["stratum"],
                    row["mandatory_reason"],
                )
                expected_row = expected.get(row["sample_id"])
                if expected_row is not None:
                    expected_row = (corpus_target_count, *expected_row)
                if expected_row != actual:
                    raise CorpusDatabaseError(
                        "quality sample release ID already has a different deterministic plan"
                    )
            for sample in plan["samples"]:
                cursor = conn.execute(
                    """
                    INSERT INTO quality_sample_plans (
                        sample_id, release_id, corpus_target_count, candidate_id,
                        draft_id, draft_hash, stratum, mandatory_reason, status
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'pending_policy')
                    ON CONFLICT (release_id, candidate_id) DO NOTHING
                    """,
                    (
                        sample["sample_id"],
                        sample["release_id"],
                        corpus_target_count,
                        sample["candidate_id"],
                        sample["draft_id"],
                        sample["draft_hash"],
                        sample["stratum"],
                        sample["mandatory_reason"],
                    ),
                )
                inserted += cursor.rowcount
            conn.commit()
        return {
            **plan,
            "corpus_target_count": corpus_target_count,
            "corpus_selection_hash": selection["selection_hash"],
            "corpus_total_deficit": selection["total_deficit"],
            "samples_inserted": inserted,
        }

    def release_cohort_summary(self, release_id: str) -> dict[str, Any]:
        with self.connection() as conn:
            rows = conn.execute(
                """
                WITH latest_drafts AS (
                    SELECT DISTINCT ON (candidate_id) candidate_id, draft_id,
                           canonical_hash
                    FROM typed_rule_drafts
                    ORDER BY candidate_id, draft_version DESC, draft_id
                )
                SELECT cohorts.*, drafts.draft_id AS current_draft_id,
                       drafts.canonical_hash AS current_draft_hash,
                       candidates.snapshot_hash AS current_snapshot_hash,
                       candidates.section_id AS current_section_id,
                       candidates.grounding_status,
                       candidates.extraction_contract_key
                           AS current_extraction_contract_key,
                       candidates.critique_contract_key
                           AS current_critique_contract_key,
                       sections.active AS section_active,
                       sections.extraction_pipeline_version
                           AS current_extraction_pipeline_version,
                       contexts.source_active,
                       contexts.registry_version AS current_source_registry_version
                FROM corpus_release_cohorts cohorts
                JOIN grounded_candidates candidates
                  ON candidates.candidate_id = cohorts.candidate_id
                JOIN latest_drafts drafts
                  ON drafts.candidate_id = candidates.candidate_id
                JOIN source_sections sections
                  ON sections.section_id = candidates.section_id
                JOIN source_section_program_contexts contexts
                  ON contexts.section_id = candidates.section_id
                 AND contexts.program = candidates.primary_program
                WHERE cohorts.release_id = %s
                ORDER BY cohorts.candidate_id
                """,
                (release_id,),
            ).fetchall()
        if not rows:
            raise CorpusDatabaseError(
                "release cohort does not exist; create its quality sample plan first"
            )
        targets = {int(row["corpus_target_count"]) for row in rows}
        stored_hashes = {row["selection_hash"] for row in rows}
        if len(targets) != 1 or len(stored_hashes) != 1:
            raise CorpusDatabaseError("release cohort metadata is inconsistent")
        if any(
            row["draft_id"] != row["current_draft_id"]
            or row["draft_hash"] != row["current_draft_hash"]
            or row["snapshot_hash"] != row["current_snapshot_hash"]
            or row["section_id"] != row["current_section_id"]
            or row["source_registry_version"]
            != row["current_source_registry_version"]
            or row["extraction_pipeline_version"]
            != row["current_extraction_pipeline_version"]
            or row["grounding_status"] != "accepted"
            or row["extraction_contract_key"]
            != row["current_extraction_contract_key"]
            or row["critique_contract_key"]
            != row["current_critique_contract_key"]
            or row["current_extraction_contract_key"]
            != CURRENT_EXTRACTION_CONTRACT_KEY
            or row["current_critique_contract_key"]
            != CURRENT_CRITIQUE_CONTRACT_KEY
            or not row["section_active"]
            or not row["source_active"]
            for row in rows
        ):
            raise CorpusDatabaseError(
                "release cohort source, parser, candidate, or draft lineage is stale"
            )
        candidate_ids = [row["candidate_id"] for row in rows]
        selection_hash = canonical_sha256(candidate_ids)
        if stored_hashes != {selection_hash}:
            raise CorpusDatabaseError("release cohort selection hash mismatch")
        return {
            "release_id": release_id,
            "corpus_target_count": targets.pop(),
            "candidate_count": len(candidate_ids),
            "selection_hash": selection_hash,
            "candidate_ids": candidate_ids,
        }

    def release_cohort_candidates(self, release_id: str) -> list[dict[str, Any]]:
        self.release_cohort_summary(release_id)
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT candidates.candidate_id, candidates.primary_program,
                       candidates.section_id, candidates.snapshot_hash,
                       candidates.evidence_hash, candidates.grounding_status,
                       candidates.candidate_payload
                FROM corpus_release_cohorts cohorts
                JOIN grounded_candidates candidates
                  ON candidates.candidate_id = cohorts.candidate_id
                WHERE cohorts.release_id = %s
                ORDER BY candidates.candidate_id
                """,
                (release_id,),
            ).fetchall()
        if not rows:
            raise CorpusDatabaseError("release cohort does not exist")
        return [dict(row) for row in rows]

    def release_cohort_registry_versions(self, release_id: str) -> dict[str, int]:
        self.release_cohort_summary(release_id)
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT source_registry_version AS registry_version,
                       count(*) AS candidate_count
                FROM corpus_release_cohorts
                WHERE release_id = %s
                GROUP BY source_registry_version
                ORDER BY source_registry_version
                """,
                (release_id,),
            ).fetchall()
        if not rows:
            raise CorpusDatabaseError("release cohort source lineage does not exist")
        return {
            str(row["registry_version"]): int(row["candidate_count"])
            for row in rows
        }

    def _invalidate_stale_quality_samples_with_connection(
        self,
        conn: Any,
        *,
        release_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Invalidate quality work when its immutable source/draft pins go stale."""
        from psycopg.types.json import Jsonb

        rows = conn.execute(
            f"""
            WITH latest_drafts AS (
                SELECT DISTINCT ON (candidate_id) candidate_id, draft_id,
                       canonical_hash
                FROM typed_rule_drafts
                ORDER BY candidate_id, draft_version DESC, draft_id
            )
            UPDATE quality_sample_plans AS plans
            SET status = 'invalidated',
                assigned_policy_reviewer_id = NULL,
                assigned_legal_verifier_id = NULL,
                claimed_at = NULL,
                claim_expires_at = NULL,
                invalidated_at = now(),
                invalidation_reason =
                    'source, parser, candidate, release cohort, or draft lineage is stale'
            FROM typed_rule_drafts drafts
            JOIN grounded_candidates candidates
              ON candidates.candidate_id = drafts.candidate_id
            JOIN source_sections sections
              ON sections.section_id = candidates.section_id
            LEFT JOIN source_section_program_contexts contexts
              ON contexts.section_id = candidates.section_id
             AND contexts.program = candidates.primary_program
            LEFT JOIN latest_drafts current
              ON current.candidate_id = drafts.candidate_id
            JOIN corpus_release_cohorts cohorts
              ON cohorts.candidate_id = candidates.candidate_id
            WHERE plans.draft_id = drafts.draft_id
              AND cohorts.release_id = plans.release_id
              AND plans.status <> 'invalidated'
              AND (%s::text IS NULL OR plans.release_id = %s)
              AND (
                  current.draft_id IS DISTINCT FROM plans.draft_id
                  OR current.canonical_hash IS DISTINCT FROM plans.draft_hash
                  OR drafts.canonical_hash IS DISTINCT FROM plans.draft_hash
                  OR candidates.grounding_status <> 'accepted'
                  OR NOT ({CURRENT_CANDIDATE_CONTRACT_SQL})
                  OR NOT sections.active
                  OR contexts.section_id IS NULL
                  OR NOT contexts.source_active
                  OR cohorts.draft_id IS DISTINCT FROM plans.draft_id
                  OR cohorts.draft_hash IS DISTINCT FROM plans.draft_hash
                  OR cohorts.snapshot_hash IS DISTINCT FROM candidates.snapshot_hash
                  OR cohorts.section_id IS DISTINCT FROM candidates.section_id
                  OR cohorts.source_registry_version
                     IS DISTINCT FROM contexts.registry_version
                  OR cohorts.extraction_pipeline_version
                     IS DISTINCT FROM sections.extraction_pipeline_version
                  OR cohorts.extraction_contract_key
                     IS DISTINCT FROM candidates.extraction_contract_key
                  OR cohorts.critique_contract_key
                     IS DISTINCT FROM candidates.critique_contract_key
              )
            RETURNING plans.sample_id, plans.release_id, plans.claim_attempts
            """,
            (release_id, release_id),
        ).fetchall()
        invalidated = [dict(row) for row in rows]
        for item in invalidated:
            audit_id = stable_id(
                "audit",
                item["sample_id"],
                "quality_sample_invalidated_stale_lineage",
            )
            conn.execute(
                """
                INSERT INTO review_audit_events (
                    event_id, actor_id, action, entity_type, entity_id, payload
                ) VALUES (
                    %s, 'rules-system', 'quality_sample_invalidated_stale_lineage',
                    'quality_sample', %s, %s
                )
                ON CONFLICT (event_id) DO NOTHING
                """,
                (
                    audit_id,
                    item["sample_id"],
                    Jsonb(
                        {
                            "release_id": item["release_id"],
                            "claim_attempts": item["claim_attempts"],
                            "reason": "source, parser, candidate, release cohort, or draft lineage is stale",
                        }
                    ),
                ),
            )
        return invalidated

    def claim_quality_sample(
        self,
        *,
        reviewer_id: str,
        reviewer_role: str,
        release_id: str | None = None,
        lease_seconds: int = DEFAULT_REVIEW_LEASE_SECONDS,
    ) -> dict[str, Any] | None:
        from psycopg.types.json import Jsonb

        if not reviewer_id.strip():
            raise ValueError("quality reviewer ID is required")
        if lease_seconds <= 0:
            raise ValueError("quality review lease must be positive")
        if reviewer_role == "policy_reviewer":
            pending_status = "pending_policy"
            claimed_status = "claimed_policy"
            assignment_column = "assigned_policy_reviewer_id"
            separation_sql = ""
        elif reviewer_role == "legal_verifier":
            pending_status = "pending_legal"
            claimed_status = "claimed_legal"
            assignment_column = "assigned_legal_verifier_id"
            separation_sql = "AND assigned_policy_reviewer_id <> %s"
        else:
            raise ValueError("quality samples require policy_reviewer or legal_verifier")

        params: list[Any] = [pending_status]
        if reviewer_role == "legal_verifier":
            params.append(reviewer_id)
        release_sql = ""
        if release_id:
            release_sql = "AND plans.release_id = %s"
            params.append(release_id)
        params.extend([claimed_status, reviewer_id])
        with self.connection() as conn:
            self._invalidate_stale_quality_samples_with_connection(
                conn, release_id=release_id
            )
            expired = conn.execute(
                """
                UPDATE quality_sample_plans
                SET status = CASE status
                        WHEN 'claimed_policy' THEN 'pending_policy'
                        ELSE 'pending_legal'
                    END,
                    assigned_policy_reviewer_id = CASE
                        WHEN status = 'claimed_policy' THEN NULL
                        ELSE assigned_policy_reviewer_id
                    END,
                    assigned_legal_verifier_id = CASE
                        WHEN status = 'claimed_legal' THEN NULL
                        ELSE assigned_legal_verifier_id
                    END,
                    claimed_at = NULL,
                    claim_expires_at = NULL
                WHERE status IN ('claimed_policy', 'claimed_legal')
                  AND (claim_expires_at IS NULL OR claim_expires_at <= now())
                RETURNING sample_id, claim_attempts
                """
            ).fetchall()
            for item in expired:
                audit_id = stable_id(
                    "audit",
                    item["sample_id"],
                    "quality_claim_expired",
                    item["claim_attempts"],
                )
                conn.execute(
                    """
                    INSERT INTO review_audit_events (
                        event_id, actor_id, action, entity_type, entity_id, payload
                    ) VALUES (%s, 'rules-system', 'quality_claim_expired',
                              'quality_sample', %s, %s)
                    ON CONFLICT (event_id) DO NOTHING
                    """,
                    (
                        audit_id,
                        item["sample_id"],
                        Jsonb({"claim_attempts": item["claim_attempts"]}),
                    ),
                )
            row = conn.execute(
                f"""
                WITH latest_drafts AS (
                    SELECT DISTINCT ON (candidate_id) candidate_id, draft_id,
                           canonical_hash
                    FROM typed_rule_drafts
                    ORDER BY candidate_id, draft_version DESC, draft_id
                ), claimable AS (
                    SELECT plans.sample_id
                    FROM quality_sample_plans plans
                    JOIN typed_rule_drafts drafts USING (draft_id)
                    JOIN latest_drafts current
                      ON current.candidate_id = drafts.candidate_id
                     AND current.draft_id = drafts.draft_id
                     AND current.canonical_hash = plans.draft_hash
                    JOIN grounded_candidates candidates
                      ON candidates.candidate_id = drafts.candidate_id
                    JOIN source_sections sections
                      ON sections.section_id = candidates.section_id
                    JOIN source_section_program_contexts contexts
                      ON contexts.section_id = candidates.section_id
                     AND contexts.program = candidates.primary_program
                     AND contexts.source_active
                    JOIN corpus_release_cohorts cohorts
                      ON cohorts.release_id = plans.release_id
                     AND cohorts.candidate_id = plans.candidate_id
                     AND cohorts.draft_id = plans.draft_id
                     AND cohorts.draft_hash = plans.draft_hash
                     AND cohorts.snapshot_hash = candidates.snapshot_hash
                     AND cohorts.section_id = candidates.section_id
                     AND cohorts.source_registry_version = contexts.registry_version
                     AND cohorts.extraction_pipeline_version =
                         sections.extraction_pipeline_version
                    WHERE plans.status = %s
                      AND sections.active
                      AND candidates.grounding_status = 'accepted'
                      AND {CURRENT_CANDIDATE_CONTRACT_SQL}
                      {separation_sql}
                      {release_sql}
                    ORDER BY plans.release_id, plans.sample_id
                    FOR UPDATE OF plans, candidates, sections SKIP LOCKED
                    LIMIT 1
                )
                UPDATE quality_sample_plans AS plans
                SET status = %s, {assignment_column} = %s,
                    claimed_at = now(),
                    claim_expires_at = now() + make_interval(secs => %s),
                    claim_attempts = claim_attempts + 1
                FROM claimable
                WHERE plans.sample_id = claimable.sample_id
                RETURNING plans.*
                """,
                tuple([*params, lease_seconds]),
            ).fetchone()
            if row:
                audit_id = stable_id(
                    "audit",
                    row["sample_id"],
                    reviewer_id,
                    "quality_claimed",
                    row["claim_attempts"],
                )
                conn.execute(
                    """
                    INSERT INTO review_audit_events (
                        event_id, actor_id, action, entity_type, entity_id, payload
                    ) VALUES (%s, %s, 'quality_claimed',
                              'quality_sample', %s, %s)
                    ON CONFLICT (event_id) DO NOTHING
                    """,
                    (
                        audit_id,
                        reviewer_id,
                        row["sample_id"],
                        Jsonb(
                            {
                                "reviewer_role": reviewer_role,
                                "claim_attempts": row["claim_attempts"],
                                "claim_expires_at": str(row["claim_expires_at"]),
                            }
                        ),
                    ),
                )
            conn.commit()
        return dict(row) if row else None

    def renew_quality_sample_claim(
        self,
        sample_id: str,
        *,
        reviewer_id: str,
        reviewer_role: str,
        lease_seconds: int = DEFAULT_REVIEW_LEASE_SECONDS,
    ) -> dict[str, Any]:
        return self._update_quality_sample_claim(
            sample_id,
            reviewer_id=reviewer_id,
            reviewer_role=reviewer_role,
            action="renew",
            lease_seconds=lease_seconds,
        )

    def release_quality_sample_claim(
        self,
        sample_id: str,
        *,
        reviewer_id: str,
        reviewer_role: str,
    ) -> dict[str, Any]:
        return self._update_quality_sample_claim(
            sample_id,
            reviewer_id=reviewer_id,
            reviewer_role=reviewer_role,
            action="release",
            lease_seconds=DEFAULT_REVIEW_LEASE_SECONDS,
        )

    def _update_quality_sample_claim(
        self,
        sample_id: str,
        *,
        reviewer_id: str,
        reviewer_role: str,
        action: str,
        lease_seconds: int,
    ) -> dict[str, Any]:
        from psycopg.types.json import Jsonb

        role_fields = {
            "policy_reviewer": (
                "claimed_policy",
                "pending_policy",
                "assigned_policy_reviewer_id",
            ),
            "legal_verifier": (
                "claimed_legal",
                "pending_legal",
                "assigned_legal_verifier_id",
            ),
        }.get(reviewer_role)
        if not role_fields:
            raise ValueError("quality samples require policy_reviewer or legal_verifier")
        if action not in {"renew", "release"}:
            raise ValueError("unsupported quality review claim action")
        if not reviewer_id.strip():
            raise ValueError("quality reviewer ID is required")
        if lease_seconds <= 0:
            raise ValueError("quality review lease must be positive")
        claimed_status, pending_status, assignment_column = role_fields
        if action == "renew":
            assignment = "claim_expires_at = now() + make_interval(secs => %s)"
            params: tuple[Any, ...] = (
                lease_seconds,
                sample_id,
                claimed_status,
                reviewer_id,
            )
        else:
            assignment = (
                f"status = '{pending_status}', {assignment_column} = NULL, "
                "claimed_at = NULL, claim_expires_at = NULL"
            )
            params = (sample_id, claimed_status, reviewer_id)
        with self.connection() as conn:
            invalidated = self._invalidate_stale_quality_samples_with_connection(
                conn
            )
            if any(item["sample_id"] == sample_id for item in invalidated):
                conn.commit()
                raise CorpusDatabaseError(
                    "quality sample source, parser, candidate, cohort, or draft is stale"
                )
            row = conn.execute(
                f"""
                UPDATE quality_sample_plans
                SET {assignment}
                WHERE sample_id = %s AND status = %s
                  AND {assignment_column} = %s
                  AND claim_expires_at > now()
                RETURNING sample_id, release_id, status,
                          claim_expires_at, claim_attempts
                """,
                params,
            ).fetchone()
            if not row:
                raise CorpusDatabaseError(
                    "quality review claim is missing, expired, or owned by another reviewer"
                )
            audit_id = stable_id(
                "audit",
                sample_id,
                reviewer_id,
                f"quality_claim_{action}",
                row["claim_attempts"],
                str(row["claim_expires_at"]),
            )
            conn.execute(
                """
                INSERT INTO review_audit_events (
                    event_id, actor_id, action, entity_type, entity_id, payload
                ) VALUES (%s, %s, %s, 'quality_sample', %s, %s)
                ON CONFLICT (event_id) DO NOTHING
                """,
                (
                    audit_id,
                    reviewer_id,
                    f"quality_claim_{action}",
                    sample_id,
                    Jsonb(
                        {
                            "reviewer_role": reviewer_role,
                            "claim_attempts": row["claim_attempts"],
                            "claim_expires_at": str(row["claim_expires_at"])
                            if row["claim_expires_at"]
                            else None,
                        }
                    ),
                ),
            )
            conn.commit()
        return {
            **dict(row),
            "action": action,
            "runtime_activation": False,
            "proof_binding": False,
        }

    def record_quality_review(self, submission: dict[str, Any]) -> dict[str, Any]:
        from psycopg.types.json import Jsonb

        from .quality_sampling import (
            merge_quality_review_submissions,
            validate_quality_review_submission,
        )

        errors = validate_quality_review_submission(submission)
        if errors:
            raise ValueError("; ".join(errors))
        role = submission["reviewer_role"]
        expected_status = "claimed_policy" if role == "policy_reviewer" else "claimed_legal"
        assignment_column = (
            "assigned_policy_reviewer_id"
            if role == "policy_reviewer"
            else "assigned_legal_verifier_id"
        )
        submission_id = stable_id(
            "quality-review",
            submission["sample_id"],
            role,
            submission["reviewer_id"],
            submission["draft_hash"],
        )
        consensus: dict[str, Any] | None = None
        with self.connection() as conn:
            invalidated = self._invalidate_stale_quality_samples_with_connection(
                conn
            )
            if any(
                item["sample_id"] == submission["sample_id"]
                for item in invalidated
            ):
                conn.commit()
                raise CorpusDatabaseError(
                    "quality sample source, parser, candidate, cohort, or draft is stale"
                )
            plan = conn.execute(
                f"""
                WITH latest_drafts AS (
                    SELECT DISTINCT ON (candidate_id) candidate_id, draft_id,
                           canonical_hash
                    FROM typed_rule_drafts
                    ORDER BY candidate_id, draft_version DESC, draft_id
                )
                SELECT plans.*, drafts.canonical_hash AS current_draft_hash,
                       plans.claim_expires_at IS NOT NULL
                           AND plans.claim_expires_at > now() AS claim_live
                FROM quality_sample_plans plans
                JOIN typed_rule_drafts drafts USING (draft_id)
                JOIN latest_drafts current
                  ON current.candidate_id = drafts.candidate_id
                 AND current.draft_id = drafts.draft_id
                 AND current.canonical_hash = plans.draft_hash
                JOIN grounded_candidates candidates
                  ON candidates.candidate_id = drafts.candidate_id
                JOIN source_sections sections
                  ON sections.section_id = candidates.section_id
                JOIN source_section_program_contexts contexts
                  ON contexts.section_id = candidates.section_id
                 AND contexts.program = candidates.primary_program
                 AND contexts.source_active
                JOIN corpus_release_cohorts cohorts
                  ON cohorts.release_id = plans.release_id
                 AND cohorts.candidate_id = plans.candidate_id
                 AND cohorts.draft_id = plans.draft_id
                 AND cohorts.draft_hash = plans.draft_hash
                 AND cohorts.snapshot_hash = candidates.snapshot_hash
                 AND cohorts.section_id = candidates.section_id
                 AND cohorts.source_registry_version = contexts.registry_version
                 AND cohorts.extraction_pipeline_version =
                     sections.extraction_pipeline_version
                WHERE plans.sample_id = %s
                  AND sections.active
                  AND candidates.grounding_status = 'accepted'
                  AND {CURRENT_CANDIDATE_CONTRACT_SQL}
                FOR UPDATE OF plans, candidates
                FOR SHARE OF sections
                """,
                (submission["sample_id"],),
            ).fetchone()
            if not plan:
                raise CorpusDatabaseError("quality sample does not exist")
            if plan["status"] != expected_status:
                raise CorpusDatabaseError("quality sample is not claimed for this review role")
            if plan[assignment_column] != submission["reviewer_id"]:
                raise CorpusDatabaseError("quality sample is claimed by another reviewer")
            if not plan["claim_live"]:
                raise CorpusDatabaseError("quality review claim has expired")
            if (
                plan["candidate_id"] != submission["candidate_id"]
                or plan["draft_hash"] != submission["draft_hash"]
                or plan["current_draft_hash"] != submission["draft_hash"]
            ):
                raise CorpusDatabaseError(
                    "quality review is stale because the candidate or draft hash changed"
                )
            conn.execute(
                """
                INSERT INTO quality_review_submissions (
                    submission_id, sample_id, candidate_id, draft_hash,
                    reviewer_id, reviewer_role, measurements, rationale
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    submission_id,
                    submission["sample_id"],
                    submission["candidate_id"],
                    submission["draft_hash"],
                    submission["reviewer_id"],
                    role,
                    Jsonb(submission["measurements"]),
                    submission["rationale"].strip(),
                ),
            )
            if role == "policy_reviewer":
                conn.execute(
                    """
                    UPDATE quality_sample_plans
                    SET status = 'pending_legal', claimed_at = NULL,
                        claim_expires_at = NULL
                    WHERE sample_id = %s
                    """,
                    (submission["sample_id"],),
                )
            else:
                rows = conn.execute(
                    """
                    SELECT sample_id, candidate_id, draft_hash, reviewer_id,
                           reviewer_role, measurements, rationale
                    FROM quality_review_submissions
                    WHERE sample_id = %s ORDER BY reviewer_role
                    """,
                    (submission["sample_id"],),
                ).fetchall()
                by_role = {
                    row["reviewer_role"]: {
                        "schema_version": "localbce-rules-quality-review-v1",
                        **dict(row),
                        "runtime_activation": False,
                        "proof_binding": False,
                    }
                    for row in rows
                }
                if set(by_role) != {"policy_reviewer", "legal_verifier"}:
                    raise CorpusDatabaseError("quality consensus requires both reviewer roles")
                consensus = merge_quality_review_submissions(
                    by_role["policy_reviewer"], by_role["legal_verifier"]
                )
                conn.execute(
                    """
                    INSERT INTO quality_samples (
                        sample_id, release_id, candidate_id, stratum, mandatory_reason,
                        policy_reviewer_id, legal_verifier_id, measurements
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        plan["sample_id"],
                        plan["release_id"],
                        plan["candidate_id"],
                        plan["stratum"],
                        plan["mandatory_reason"],
                        consensus["policy_reviewer_id"],
                        consensus["legal_verifier_id"],
                        Jsonb(consensus["measurements"]),
                    ),
                )
                conn.execute(
                    """
                    UPDATE quality_sample_plans
                    SET status = 'completed', completed_at = now(),
                        claim_expires_at = NULL
                    WHERE sample_id = %s
                    """,
                    (submission["sample_id"],),
                )
            audit_id = stable_id("audit", submission_id, "quality_review")
            conn.execute(
                """
                INSERT INTO review_audit_events (
                    event_id, actor_id, action, entity_type, entity_id, payload
                ) VALUES (%s, %s, 'quality_review', 'quality_sample', %s, %s)
                """,
                (
                    audit_id,
                    submission["reviewer_id"],
                    submission["sample_id"],
                    Jsonb(
                        {
                            "submission_id": submission_id,
                            "reviewer_role": role,
                            "draft_hash": submission["draft_hash"],
                            "consensus_hash": consensus.get("consensus_hash")
                            if consensus
                            else None,
                        }
                    ),
                ),
            )
            conn.commit()
        return {
            "submission_id": submission_id,
            "completed": consensus is not None,
            "consensus": consensus,
            "runtime_activation": False,
            "proof_binding": False,
        }

    def rules_metrics(self) -> dict[str, Any]:
        with self.connection() as conn:
            tables = {}
            for name in (
                "official_sources",
                "source_snapshots",
                "source_sections",
                "source_section_retrieval_links",
                "section_extraction_jobs",
                "source_discovery_runs",
                "source_registry_candidates",
                "source_registry_candidate_decisions",
                "extraction_batches",
                "source_fetch_jobs",
                "section_relevance_decisions",
                "inference_jobs",
                "grounded_candidates",
                "typed_rule_drafts",
                "reviewer_tasks",
                "reviewer_decisions",
                "quality_sample_plans",
                "corpus_release_cohorts",
                "quality_review_submissions",
                "quality_samples",
                "corpus_releases",
                "legacy_baseline_candidates",
            ):
                tables[name] = int(conn.execute(f"SELECT count(*) AS count FROM {name}").fetchone()["count"])
            programs = conn.execute(
                f"""
                SELECT candidates.primary_program, count(*) AS count
                FROM grounded_candidates candidates
                JOIN source_sections sections USING (section_id)
                JOIN source_section_program_contexts contexts
                  ON contexts.section_id = candidates.section_id
                 AND contexts.program = candidates.primary_program
                 AND contexts.source_active
                WHERE sections.active
                  AND candidates.grounding_status = 'accepted'
                  AND {CURRENT_CANDIDATE_CONTRACT_SQL}
                GROUP BY candidates.primary_program
                ORDER BY candidates.primary_program
                """
            ).fetchall()
        return {
            "table_counts": tables,
            "accepted_candidates_by_program": {row["primary_program"]: row["count"] for row in programs},
            "runtime_activation": False,
            "proof_binding": False,
        }

    def corpus_scale_progress(self, target_count: int) -> dict[str, Any]:
        from .scaled_corpus import CORPUS_MILESTONES, all_programs, program_quotas

        if target_count not in CORPUS_MILESTONES:
            raise ValueError("corpus progress target must be 5100, 51000, or 600000")
        with self.connection() as conn:
            self._cancel_stale_review_tasks_with_connection(conn)
            coverage_rows = conn.execute(
                """
                SELECT sources.program,
                       count(DISTINCT sources.source_id) AS source_count,
                       count(DISTINCT retrievals.retrieval_id) AS retrieval_count,
                       count(DISTINCT sections.section_id)
                           FILTER (WHERE sections.active) AS active_section_count
                FROM official_sources sources
                LEFT JOIN source_snapshot_retrievals retrievals USING (source_id)
                LEFT JOIN source_section_retrieval_links links USING (retrieval_id)
                LEFT JOIN source_sections sections USING (section_id)
                WHERE sources.active
                GROUP BY sources.program
                ORDER BY sources.program
                """
            ).fetchall()
            context_rows = conn.execute(
                """
                SELECT contexts.program,
                       count(DISTINCT contexts.section_id)
                           AS active_program_section_count
                FROM source_section_program_contexts contexts
                JOIN source_sections sections USING (section_id)
                WHERE contexts.source_active
                  AND sections.active
                GROUP BY contexts.program
                ORDER BY contexts.program
                """
            ).fetchall()
            physical_section_row = conn.execute(
                """
                SELECT count(DISTINCT sections.section_id) AS section_count
                FROM source_sections sections
                WHERE sections.active
                  AND EXISTS (
                      SELECT 1
                      FROM source_section_program_contexts contexts
                      WHERE contexts.section_id = sections.section_id
                        AND contexts.source_active
                  )
                """
            ).fetchone()
            accepted_rows = conn.execute(
                f"""
                SELECT candidates.primary_program AS program,
                       count(DISTINCT candidates.candidate_id) AS candidate_count,
                       count(DISTINCT candidates.candidate_id) FILTER (
                           WHERE nullif(
                               candidates.candidate_payload->>'effective_from', ''
                           ) IS NOT NULL
                       ) AS effective_date_count
                FROM grounded_candidates candidates
                JOIN source_sections sections USING (section_id)
                JOIN source_section_program_contexts contexts
                  ON contexts.section_id = candidates.section_id
                 AND contexts.program = candidates.primary_program
                 AND contexts.source_active
                WHERE sections.active
                  AND candidates.grounding_status = 'accepted'
                  AND {CURRENT_CANDIDATE_CONTRACT_SQL}
                GROUP BY candidates.primary_program
                ORDER BY candidates.primary_program
                """
            ).fetchall()
            draft_quality = conn.execute(
                f"""
                WITH latest_drafts AS (
                    SELECT DISTINCT ON (candidate_id)
                           candidate_id, draft_id, validation_errors,
                           blocker_codes
                    FROM typed_rule_drafts
                    ORDER BY candidate_id, draft_version DESC, draft_id
                ), current_drafts AS (
                    SELECT candidates.candidate_id, drafts.draft_id,
                           drafts.validation_errors, drafts.blocker_codes
                    FROM grounded_candidates candidates
                    JOIN source_sections sections USING (section_id)
                    JOIN source_section_program_contexts contexts
                      ON contexts.section_id = candidates.section_id
                     AND contexts.program = candidates.primary_program
                     AND contexts.source_active
                    JOIN latest_drafts drafts
                      ON drafts.candidate_id = candidates.candidate_id
                    WHERE sections.active
                      AND candidates.grounding_status = 'accepted'
                      AND {CURRENT_CANDIDATE_CONTRACT_SQL}
                )
                SELECT count(DISTINCT candidate_id) AS draft_candidate_count,
                       count(DISTINCT candidate_id) FILTER (
                           WHERE validation_errors <> '[]'::jsonb
                              OR blocker_codes <> '[]'::jsonb
                       ) AS blocked_draft_candidate_count
                FROM current_drafts
                """
            ).fetchone()
            draft_blocker_rows = conn.execute(
                f"""
                WITH latest_drafts AS (
                    SELECT DISTINCT ON (candidate_id)
                           candidate_id, draft_id, blocker_codes
                    FROM typed_rule_drafts
                    ORDER BY candidate_id, draft_version DESC, draft_id
                )
                SELECT blockers.blocker,
                       count(DISTINCT candidates.candidate_id) AS candidate_count
                FROM grounded_candidates candidates
                JOIN source_sections sections USING (section_id)
                JOIN source_section_program_contexts contexts
                  ON contexts.section_id = candidates.section_id
                 AND contexts.program = candidates.primary_program
                 AND contexts.source_active
                JOIN latest_drafts drafts
                  ON drafts.candidate_id = candidates.candidate_id
                CROSS JOIN LATERAL jsonb_array_elements_text(
                    drafts.blocker_codes
                ) AS blockers(blocker)
                WHERE sections.active
                  AND candidates.grounding_status = 'accepted'
                  AND {CURRENT_CANDIDATE_CONTRACT_SQL}
                GROUP BY blockers.blocker
                ORDER BY blockers.blocker
                """
            ).fetchall()
            deterministic_rows = conn.execute(
                f"""
                WITH latest_drafts AS (
                    SELECT DISTINCT ON (candidate_id)
                           candidate_id, draft_id, validation_errors
                    FROM typed_rule_drafts
                    ORDER BY candidate_id, draft_version DESC, draft_id
                )
                SELECT candidates.primary_program AS program,
                       count(DISTINCT candidates.candidate_id) AS candidate_count
                FROM grounded_candidates candidates
                JOIN source_sections sections USING (section_id)
                JOIN source_section_program_contexts contexts
                  ON contexts.section_id = candidates.section_id
                 AND contexts.program = candidates.primary_program
                 AND contexts.source_active
                JOIN latest_drafts drafts
                  ON drafts.candidate_id = candidates.candidate_id
                WHERE sections.active
                  AND candidates.grounding_status = 'accepted'
                  AND {CURRENT_CANDIDATE_CONTRACT_SQL}
                  AND drafts.validation_errors = '[]'::jsonb
                  AND NOT EXISTS (
                      SELECT 1
                      FROM duplicate_conflict_members members
                      JOIN duplicate_conflict_clusters clusters USING (cluster_id)
                      WHERE members.draft_id = drafts.draft_id
                        AND (
                            clusters.status = 'open'
                            OR (clusters.resolution->>'selected_draft_id')
                               IS DISTINCT FROM drafts.draft_id
                        )
                  )
                GROUP BY candidates.primary_program
                ORDER BY candidates.primary_program
                """
            ).fetchall()

            def status_counts(table: str) -> dict[str, int]:
                rows = conn.execute(
                    f"SELECT status, count(*) AS count FROM {table} GROUP BY status"
                ).fetchall()
                return {str(row["status"]): int(row["count"]) for row in rows}

            queues = {
                "source_fetch_jobs": status_counts("source_fetch_jobs"),
                "section_extraction_jobs": status_counts(
                    "section_extraction_jobs"
                ),
                "inference_jobs": status_counts("inference_jobs"),
                "reviewer_tasks": status_counts("reviewer_tasks"),
            }
            current_inference_failures = int(
                conn.execute(
                    """
                    SELECT count(*) AS count
                    FROM inference_jobs jobs
                    JOIN source_sections sections USING (section_id)
                    WHERE jobs.status = 'failed'
                      AND sections.active
                      AND EXISTS (
                          SELECT 1
                          FROM source_section_program_contexts contexts
                          WHERE contexts.section_id = sections.section_id
                            AND contexts.source_active
                      )
                      AND jobs.model_version = %s
                      AND jobs.schema_version = %s
                      AND jobs.request_payload->>'response_contract_version' = %s
                      AND (
                          (jobs.pass = 1 AND jobs.prompt_version = %s)
                          OR (jobs.pass = 2 AND jobs.prompt_version = %s)
                      )
                    """,
                    (
                        CLAUDE_MODEL,
                        INFERENCE_SCHEMA,
                        INFERENCE_RESPONSE_CONTRACT_VERSION,
                        EXTRACTION_PROMPT_VERSION,
                        CRITIQUE_PROMPT_VERSION,
                    ),
                ).fetchone()["count"]
            )
            release_count = int(
                conn.execute(
                    "SELECT count(*) AS count FROM corpus_releases"
                ).fetchone()["count"]
            )
            conn.commit()

        coverage = {str(row["program"]): dict(row) for row in coverage_rows}
        program_section_counts = {
            str(row["program"]): int(row["active_program_section_count"])
            for row in context_rows
        }
        accepted = {
            str(row["program"]): int(row["candidate_count"])
            for row in accepted_rows
        }
        effective_dated = {
            str(row["program"]): int(row["effective_date_count"])
            for row in accepted_rows
        }
        deterministic = {
            str(row["program"]): int(row["candidate_count"])
            for row in deterministic_rows
        }
        quotas = program_quotas(target_count)
        programs: list[dict[str, Any]] = []
        for program in all_programs():
            row = coverage.get(program, {})
            accepted_count = accepted.get(program, 0)
            effective_date_count = effective_dated.get(program, 0)
            deterministic_count = deterministic.get(program, 0)
            quota = quotas[program]
            active_program_section_count = program_section_counts.get(program, 0)
            program_context_candidate_upper_bound = (
                active_program_section_count * MAX_CANDIDATES_PER_SECTION
            )
            program_context_capacity_deficit = max(
                0, quota - program_context_candidate_upper_bound
            )
            minimum_additional_program_contexts = (
                program_context_capacity_deficit
                + MAX_CANDIDATES_PER_SECTION
                - 1
            ) // MAX_CANDIDATES_PER_SECTION
            programs.append(
                {
                    "program": program,
                    "quota": quota,
                    "active_source_count": int(row.get("source_count", 0)),
                    "snapshot_retrieval_count": int(
                        row.get("retrieval_count", 0)
                    ),
                    "active_section_count": int(
                        row.get("active_section_count", 0)
                    ),
                    "active_program_section_count": (
                        active_program_section_count
                    ),
                    "program_context_candidate_upper_bound": (
                        program_context_candidate_upper_bound
                    ),
                    "program_context_capacity_deficit_lower_bound": (
                        program_context_capacity_deficit
                    ),
                    "minimum_additional_program_contexts_lower_bound": (
                        minimum_additional_program_contexts
                    ),
                    "program_context_quota_possible": (
                        program_context_candidate_upper_bound >= quota
                    ),
                    "accepted_grounded_candidates": accepted_count,
                    "accepted_candidates_with_effective_from": (
                        effective_date_count
                    ),
                    "deterministic_candidates": deterministic_count,
                    "accepted_deficit": max(0, quota - accepted_count),
                    "deterministic_deficit": max(
                        0, quota - deterministic_count
                    ),
                    "accepted_candidate_quota_met": (
                        accepted_count >= quota
                    ),
                    "deterministic_candidate_quota_met": (
                        deterministic_count >= quota
                    ),
                    # Backward-compatible alias for deterministic readiness.
                    "candidate_quota_met": deterministic_count >= quota,
                }
            )
        accepted_total = sum(item["accepted_grounded_candidates"] for item in programs)
        effective_dated_total = sum(
            item["accepted_candidates_with_effective_from"]
            for item in programs
        )
        deterministic_total = sum(item["deterministic_candidates"] for item in programs)
        active_physical_sections = int(physical_section_row["section_count"])
        physical_section_candidate_capacity = (
            active_physical_sections * MAX_CANDIDATES_PER_SECTION
        )
        minimum_additional_physical_sections = (
            max(0, target_count - physical_section_candidate_capacity)
            + MAX_CANDIDATES_PER_SECTION
            - 1
        ) // MAX_CANDIDATES_PER_SECTION
        minimum_additional_program_contexts = sum(
            item["minimum_additional_program_contexts_lower_bound"]
            for item in programs
        )
        queue_failures = {
            name: counts.get("failed", 0) for name, counts in queues.items()
        }
        blocking_queue_failures = dict(queue_failures)
        blocking_queue_failures["inference_jobs"] = current_inference_failures
        return {
            "schema_version": "localbce-rules-corpus-progress-v1",
            "target_count": target_count,
            "program_count": len(programs),
            "programs": programs,
            "accepted_grounded_candidates": accepted_total,
            "accepted_candidates_with_effective_from": effective_dated_total,
            "accepted_candidates_missing_effective_from": (
                accepted_total - effective_dated_total
            ),
            "current_draft_candidates": int(
                draft_quality["draft_candidate_count"]
            ),
            "blocked_draft_candidates": int(
                draft_quality["blocked_draft_candidate_count"]
            ),
            "draft_blocker_counts": {
                str(row["blocker"]): int(row["candidate_count"])
                for row in draft_blocker_rows
            },
            "deterministic_candidates": deterministic_total,
            "accepted_quota_completion": sum(
                min(item["accepted_grounded_candidates"], item["quota"])
                for item in programs
            ),
            "deterministic_quota_completion": sum(
                min(item["deterministic_candidates"], item["quota"])
                for item in programs
            ),
            "programs_at_accepted_candidate_quota": sum(
                item["accepted_candidate_quota_met"] for item in programs
            ),
            "programs_at_deterministic_candidate_quota": sum(
                item["deterministic_candidate_quota_met"] for item in programs
            ),
            # Backward-compatible alias for deterministic readiness.
            "programs_at_candidate_quota": sum(
                item["deterministic_candidate_quota_met"] for item in programs
            ),
            "max_candidates_per_program_section": (
                MAX_CANDIDATES_PER_SECTION
            ),
            "active_physical_sections": active_physical_sections,
            "physical_section_candidate_capacity": (
                physical_section_candidate_capacity
            ),
            "active_program_section_contexts": sum(
                item["active_program_section_count"] for item in programs
            ),
            "program_context_quota_upper_bound": sum(
                min(
                    item["program_context_candidate_upper_bound"],
                    item["quota"],
                )
                for item in programs
            ),
            "minimum_additional_physical_sections_lower_bound": (
                minimum_additional_physical_sections
            ),
            "minimum_additional_program_contexts_lower_bound": (
                minimum_additional_program_contexts
            ),
            "minimum_additional_source_sections_lower_bound": max(
                minimum_additional_physical_sections,
                minimum_additional_program_contexts,
            ),
            "programs_without_source_capture": [
                item["program"]
                for item in programs
                if item["snapshot_retrieval_count"] == 0
            ],
            "programs_without_active_sections": [
                item["program"]
                for item in programs
                if item["active_section_count"] == 0
            ],
            "programs_with_candidate_deficit": [
                item["program"]
                for item in programs
                if not item["deterministic_candidate_quota_met"]
            ],
            "programs_with_accepted_candidate_deficit": [
                item["program"]
                for item in programs
                if not item["accepted_candidate_quota_met"]
            ],
            "programs_with_deterministic_candidate_deficit": [
                item["program"]
                for item in programs
                if not item["deterministic_candidate_quota_met"]
            ],
            "programs_without_program_context_quota_capacity": [
                item["program"]
                for item in programs
                if not item["program_context_quota_possible"]
            ],
            "queues": queues,
            "queue_failures": queue_failures,
            "blocking_queue_failures": blocking_queue_failures,
            "release_count": release_count,
            "milestone_grounded_candidate_ready": all(
                item["accepted_candidate_quota_met"] for item in programs
            ),
            "milestone_deterministic_candidate_ready": all(
                item["deterministic_candidate_quota_met"] for item in programs
            ),
            # Backward-compatible alias for deterministic readiness.
            "milestone_candidate_ready": all(
                item["deterministic_candidate_quota_met"] for item in programs
            ),
            "milestone_source_capacity_ready": (
                physical_section_candidate_capacity >= target_count
                and all(
                    item["program_context_quota_possible"]
                    for item in programs
                )
            ),
            "source_capacity_evidence_is_necessary_not_sufficient": True,
            "runtime_activation": False,
            "proof_binding": False,
            "production_usable": False,
        }

    def inference_failure_report(self, *, limit: int = 100) -> dict[str, Any]:
        if limit <= 0 or limit > 10_000:
            raise ValueError("inference failure detail limit must be between 1 and 10000")
        with self.connection() as conn:
            counts = conn.execute(
                """
                SELECT count(*) FILTER (WHERE status = 'failed') AS failed,
                       count(*) FILTER (WHERE status = 'rejected') AS rejected
                FROM inference_jobs
                WHERE status IN ('failed', 'rejected')
                """
            ).fetchone()
            current_retryable = conn.execute(
                """
                SELECT count(*) AS count
                FROM inference_jobs jobs
                JOIN source_sections sections USING (section_id)
                WHERE jobs.status = 'failed'
                  AND sections.active
                  AND EXISTS (
                      SELECT 1
                      FROM source_section_program_contexts contexts
                      WHERE contexts.section_id = sections.section_id
                        AND contexts.source_active
                  )
                  AND jobs.model_version = %s
                  AND jobs.schema_version = %s
                  AND jobs.request_payload->>'response_contract_version' = %s
                  AND (
                      (jobs.pass = 1 AND jobs.prompt_version = %s)
                      OR (jobs.pass = 2 AND jobs.prompt_version = %s)
                  )
                """,
                (
                    CLAUDE_MODEL,
                    INFERENCE_SCHEMA,
                    INFERENCE_RESPONSE_CONTRACT_VERSION,
                    EXTRACTION_PROMPT_VERSION,
                    CRITIQUE_PROMPT_VERSION,
                ),
            ).fetchone()
            rows = conn.execute(
                """
                SELECT jobs.inference_job_id, jobs.section_id, jobs.pass,
                       jobs.prompt_version, jobs.model_version,
                       jobs.schema_version,
                       jobs.request_payload->>'response_contract_version'
                           AS response_contract_version,
                       jobs.status, jobs.attempts, jobs.attempt_limit,
                       jobs.retry_rounds, jobs.last_error,
                       jobs.created_at, jobs.completed_at,
                       sections.active AND EXISTS (
                           SELECT 1
                           FROM source_section_program_contexts contexts
                           WHERE contexts.section_id = sections.section_id
                             AND contexts.source_active
                       ) AS source_active
                FROM inference_jobs jobs
                JOIN source_sections sections USING (section_id)
                WHERE jobs.status IN ('failed', 'rejected')
                ORDER BY jobs.created_at, jobs.inference_job_id
                LIMIT %s
                """,
                (limit,),
            ).fetchall()

        details: list[dict[str, Any]] = []
        for raw_row in rows:
            row = dict(raw_row)
            current_contract = (
                row["model_version"] == CLAUDE_MODEL
                and row["schema_version"] == INFERENCE_SCHEMA
                and row["response_contract_version"]
                == INFERENCE_RESPONSE_CONTRACT_VERSION
                and (
                    (row["pass"] == 1 and row["prompt_version"] == EXTRACTION_PROMPT_VERSION)
                    or (row["pass"] == 2 and row["prompt_version"] == CRITIQUE_PROMPT_VERSION)
                )
            )
            error = str(row.get("last_error") or "")
            lowered = error.lower()
            if row["status"] == "rejected":
                error_class = "response_rejected"
            elif "timeout" in lowered:
                error_class = "timeout"
            elif "superseded" in lowered:
                error_class = "superseded"
            elif "lease" in lowered:
                error_class = "lease"
            else:
                error_class = "transport_or_worker_failure"
            for field in ("created_at", "completed_at"):
                value = row.get(field)
                row[field] = value.isoformat() if value is not None else None
            row["current_contract"] = current_contract
            row["operator_retryable"] = (
                row["status"] == "failed"
                and current_contract
                and row["source_active"] is True
            )
            row["error_class"] = error_class
            details.append(row)

        failed = int(counts["failed"])
        rejected = int(counts["rejected"])
        return {
            "schema_version": "localbce-inference-failure-report-v1",
            "failed": failed,
            "rejected": rejected,
            "current_retryable_failed": int(current_retryable["count"]),
            "details": details,
            "detail_limit": limit,
            "details_truncated": max(0, failed + rejected - len(details)),
            "contains_source_text": False,
            "runtime_activation": False,
            "proof_binding": False,
        }

    def inference_usage_report(self) -> dict[str, Any]:
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT pass, prompt_version, model_version, status,
                       count(*) AS job_count,
                       coalesce(sum(input_tokens), 0) AS input_tokens,
                       coalesce(sum(output_tokens), 0) AS output_tokens,
                       coalesce(sum(attempts), 0) AS attempts,
                       coalesce(sum(retry_rounds), 0) AS retry_rounds,
                       coalesce(sum(lease_renewals), 0) AS lease_renewals
                FROM inference_jobs
                GROUP BY pass, prompt_version, model_version, status
                ORDER BY pass, prompt_version, model_version, status
                """
            ).fetchall()
        groups = []
        numeric_fields = {
            "job_count",
            "input_tokens",
            "output_tokens",
            "attempts",
            "retry_rounds",
            "lease_renewals",
        }
        for row in rows:
            group = dict(row)
            for field in numeric_fields:
                group[field] = int(group[field])
            groups.append(group)
        return {
            "schema_version": "localbce-claude-usage-report-v1",
            "groups": groups,
            "job_count": sum(int(row["job_count"]) for row in groups),
            "input_tokens": sum(int(row["input_tokens"]) for row in groups),
            "output_tokens": sum(int(row["output_tokens"]) for row in groups),
            "attempts": sum(int(row["attempts"]) for row in groups),
            "retry_rounds": sum(int(row["retry_rounds"]) for row in groups),
            "lease_renewals": sum(int(row["lease_renewals"]) for row in groups),
            "runtime_activation": False,
            "proof_binding": False,
        }

    def inference_queue_summary(self) -> dict[str, Any]:
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT pass, status, count(*) AS job_count,
                       coalesce(sum(attempts), 0) AS attempts,
                       coalesce(sum(retry_rounds), 0) AS retry_rounds
                FROM inference_jobs
                GROUP BY pass, status
                ORDER BY pass, status
                """
            ).fetchall()
        groups = [dict(row) for row in rows]
        return {
            "schema_version": "localbce-inference-queue-summary-v1",
            "groups": groups,
            "job_count": sum(int(row["job_count"]) for row in groups),
            "pending_or_leased": sum(
                int(row["job_count"])
                for row in groups
                if row["status"] in {"pending", "leased"}
            ),
            "failed": sum(
                int(row["job_count"])
                for row in groups
                if row["status"] == "failed"
            ),
            "completed": sum(
                int(row["job_count"])
                for row in groups
                if row["status"] == "completed"
            ),
            "runtime_activation": False,
            "proof_binding": False,
        }

    def rules_checkpoint_state(self) -> dict[str, Any]:
        """Return compact read-only queue, lineage, review, and conflict counts."""

        with self.connection() as conn:
            grounding_rows = conn.execute(
                """
                SELECT grounding_status, count(*) AS count
                FROM grounded_candidates
                GROUP BY grounding_status
                ORDER BY grounding_status
                """
            ).fetchall()
            inference_rows = conn.execute(
                """
                SELECT pass, status, count(*) AS count,
                       count(*) FILTER (
                           WHERE status = 'leased' AND lease_expires_at <= now()
                       ) AS expired_leases
                FROM inference_jobs
                GROUP BY pass, status
                ORDER BY pass, status
                """
            ).fetchall()
            queue_counts: dict[str, dict[str, int]] = {}
            for table in (
                "source_fetch_jobs",
                "section_extraction_jobs",
                "reviewer_tasks",
            ):
                rows = conn.execute(
                    f"SELECT status, count(*) AS count FROM {table} GROUP BY status ORDER BY status"
                ).fetchall()
                queue_counts[table] = {
                    row["status"]: int(row["count"]) for row in rows
                }
            cluster_rows = conn.execute(
                """
                SELECT cluster_kind, status, count(*) AS count
                FROM duplicate_conflict_clusters
                GROUP BY cluster_kind, status
                ORDER BY cluster_kind, status
                """
            ).fetchall()
            decision_rows = conn.execute(
                """
                SELECT reviewer_role, decision, count(*) AS count
                FROM reviewer_decisions
                GROUP BY reviewer_role, decision
                ORDER BY reviewer_role, decision
                """
            ).fetchall()
            release_row = conn.execute(
                """
                SELECT count(*) AS release_count,
                       count(*) FILTER (WHERE gates_passed) AS passed_release_count,
                       count(*) FILTER (WHERE runtime_activation) AS runtime_release_count,
                       count(*) FILTER (WHERE proof_binding) AS proof_bound_release_count
                FROM corpus_releases
                """
            ).fetchone()
            provenance = conn.execute(
                f"""
                SELECT count(*) AS accepted_candidates,
                       count(*) FILTER (
                           WHERE snapshots.snapshot_hash IS NOT NULL
                       ) AS source_snapshot_covered,
                       count(*) FILTER (
                           WHERE length(candidates.evidence_quote) > 0
                             AND candidates.evidence_hash IS NOT NULL
                       ) AS citation_covered,
                       count(*) FILTER (
                           WHERE candidates.evidence_char_start >= 0
                             AND candidates.evidence_char_end
                                 > candidates.evidence_char_start
                             AND candidates.evidence_byte_start >= 0
                             AND candidates.evidence_byte_end
                                 > candidates.evidence_byte_start
                       ) AS evidence_span_present
                FROM grounded_candidates candidates
                JOIN source_sections sections USING (section_id)
                JOIN source_section_program_contexts contexts
                  ON contexts.section_id = candidates.section_id
                 AND contexts.program = candidates.primary_program
                 AND contexts.source_active
                LEFT JOIN source_snapshots snapshots
                  ON snapshots.snapshot_hash = candidates.snapshot_hash
                WHERE sections.active
                  AND candidates.grounding_status = 'accepted'
                  AND {CURRENT_CANDIDATE_CONTRACT_SQL}
                """
            ).fetchone()
            safety = conn.execute(
                """
                SELECT
                    (SELECT count(*) FROM grounded_candidates WHERE runtime_activation) AS candidate_runtime,
                    (SELECT count(*) FROM grounded_candidates WHERE proof_binding) AS candidate_proof,
                    (SELECT count(*) FROM quality_samples) AS quality_samples,
                    (SELECT count(*) FROM reviewer_decisions) AS reviewer_decisions
                """
            ).fetchone()
        return {
            "grounding_status_counts": {
                row["grounding_status"]: int(row["count"])
                for row in grounding_rows
            },
            "inference_job_states": [
                {
                    "pass": int(row["pass"]),
                    "status": row["status"],
                    "count": int(row["count"]),
                    "expired_leases": int(row["expired_leases"]),
                }
                for row in inference_rows
            ],
            "durable_queue_states": queue_counts,
            "duplicate_conflict_clusters": [
                {
                    "kind": row["cluster_kind"],
                    "status": row["status"],
                    "count": int(row["count"]),
                }
                for row in cluster_rows
            ],
            "reviewer_decisions": [
                {
                    "role": row["reviewer_role"],
                    "decision": row["decision"],
                    "count": int(row["count"]),
                }
                for row in decision_rows
            ],
            "provenance": {
                key: int(provenance[key])
                for key in (
                    "accepted_candidates",
                    "source_snapshot_covered",
                    "citation_covered",
                    "evidence_span_present",
                )
            },
            "review_quality": {
                "quality_sample_count": int(safety["quality_samples"]),
                "reviewer_decision_count": int(safety["reviewer_decisions"]),
                "release_count": int(release_row["release_count"]),
                "passed_release_count": int(release_row["passed_release_count"]),
            },
            "safety": {
                "runtime_activated_candidate_count": int(safety["candidate_runtime"]),
                "proof_bound_candidate_count": int(safety["candidate_proof"]),
                "runtime_release_count": int(release_row["runtime_release_count"]),
                "proof_bound_release_count": int(release_row["proof_bound_release_count"]),
                "runtime_activation": False,
                "proof_binding": False,
            },
        }

    def release_candidates(self) -> list[dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute(
                f"""
                WITH latest_drafts AS (
                    SELECT DISTINCT ON (candidate_id)
                           candidate_id, draft_id, validation_errors
                    FROM typed_rule_drafts
                    ORDER BY candidate_id, draft_version DESC, draft_id
                )
                SELECT candidates.candidate_id, candidates.primary_program,
                       candidates.section_id, candidates.snapshot_hash,
                       candidates.evidence_hash, candidates.grounding_status,
                       candidates.candidate_payload
                FROM grounded_candidates candidates
                JOIN source_sections sections USING (section_id)
                JOIN source_section_program_contexts contexts
                  ON contexts.section_id = candidates.section_id
                 AND contexts.program = candidates.primary_program
                 AND contexts.source_active
                JOIN latest_drafts drafts
                  ON drafts.candidate_id = candidates.candidate_id
                WHERE sections.active
                  AND candidates.grounding_status = 'accepted'
                  AND {CURRENT_CANDIDATE_CONTRACT_SQL}
                  AND drafts.validation_errors = '[]'::jsonb
                  AND NOT EXISTS (
                      SELECT 1
                      FROM duplicate_conflict_members members
                      JOIN duplicate_conflict_clusters clusters USING (cluster_id)
                      WHERE members.draft_id = drafts.draft_id
                        AND (
                            clusters.status = 'open'
                            OR (clusters.resolution->>'selected_draft_id')
                               IS DISTINCT FROM drafts.draft_id
                        )
                  )
                ORDER BY candidates.candidate_id
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def review_export(self, release_id: str | None = None) -> dict[str, Any]:
        if release_id:
            self.release_cohort_summary(release_id)
        with self.connection() as conn:
            if release_id:
                task_rows = conn.execute(
                    f"""
                    SELECT tasks.task_type, tasks.status, count(*) AS count
                    FROM reviewer_tasks tasks
                    JOIN typed_rule_drafts drafts USING (draft_id)
                    JOIN corpus_release_cohorts cohorts
                      ON cohorts.candidate_id = drafts.candidate_id
                     AND cohorts.release_id = %s
                    GROUP BY tasks.task_type, tasks.status
                    ORDER BY tasks.task_type, tasks.status
                    """,
                    (release_id,),
                ).fetchall()
                decision_rows = conn.execute(
                    """
                    SELECT decisions.reviewer_role, decisions.decision, count(*) AS count
                    FROM reviewer_decisions decisions
                    JOIN typed_rule_drafts drafts USING (draft_id)
                    JOIN corpus_release_cohorts cohorts
                      ON cohorts.candidate_id = drafts.candidate_id
                     AND cohorts.release_id = %s
                    GROUP BY decisions.reviewer_role, decisions.decision
                    ORDER BY decisions.reviewer_role, decisions.decision
                    """,
                    (release_id,),
                ).fetchall()
                cohort_join = """
                    JOIN corpus_release_cohorts cohorts
                      ON cohorts.candidate_id = drafts.candidate_id
                     AND cohorts.release_id = %s
                """
                approved_params: tuple[Any, ...] = (release_id,)
            else:
                self._cancel_stale_review_tasks_with_connection(conn)
                task_rows = conn.execute(
                    f"""
                    WITH latest_drafts AS (
                        SELECT DISTINCT ON (candidate_id) candidate_id, draft_id
                        FROM typed_rule_drafts
                        ORDER BY candidate_id, draft_version DESC, draft_id
                    )
                    SELECT tasks.task_type, tasks.status, count(*) AS count
                    FROM reviewer_tasks tasks
                    JOIN typed_rule_drafts drafts USING (draft_id)
                    JOIN latest_drafts current
                      ON current.candidate_id = drafts.candidate_id
                     AND current.draft_id = drafts.draft_id
                    JOIN grounded_candidates candidates
                      ON candidates.candidate_id = drafts.candidate_id
                    JOIN source_sections sections
                      ON sections.section_id = candidates.section_id
                    JOIN source_section_program_contexts contexts
                      ON contexts.section_id = candidates.section_id
                     AND contexts.program = candidates.primary_program
                     AND contexts.source_active
                    WHERE tasks.status <> 'cancelled'
                      AND sections.active
                      AND candidates.grounding_status = 'accepted'
                      AND {CURRENT_CANDIDATE_CONTRACT_SQL}
                    GROUP BY tasks.task_type, tasks.status
                    ORDER BY tasks.task_type, tasks.status
                    """
                ).fetchall()
                decision_rows = conn.execute(
                    f"""
                    WITH latest_drafts AS (
                        SELECT DISTINCT ON (candidate_id) candidate_id, draft_id
                        FROM typed_rule_drafts
                        ORDER BY candidate_id, draft_version DESC, draft_id
                    )
                    SELECT decisions.reviewer_role, decisions.decision,
                           count(*) AS count
                    FROM reviewer_decisions decisions
                    JOIN typed_rule_drafts drafts USING (draft_id)
                    JOIN latest_drafts current
                      ON current.candidate_id = drafts.candidate_id
                     AND current.draft_id = drafts.draft_id
                    JOIN grounded_candidates candidates
                      ON candidates.candidate_id = drafts.candidate_id
                    JOIN source_sections sections
                      ON sections.section_id = candidates.section_id
                    JOIN source_section_program_contexts contexts
                      ON contexts.section_id = candidates.section_id
                     AND contexts.program = candidates.primary_program
                     AND contexts.source_active
                    WHERE sections.active
                      AND candidates.grounding_status = 'accepted'
                      AND {CURRENT_CANDIDATE_CONTRACT_SQL}
                    GROUP BY decisions.reviewer_role, decisions.decision
                    ORDER BY decisions.reviewer_role, decisions.decision
                    """
                ).fetchall()
                cohort_join = f"""
                    JOIN grounded_candidates candidates
                      ON candidates.candidate_id = drafts.candidate_id
                    JOIN source_sections sections
                      ON sections.section_id = candidates.section_id
                     AND sections.active
                    JOIN source_section_program_contexts contexts
                      ON contexts.section_id = candidates.section_id
                     AND contexts.program = candidates.primary_program
                     AND contexts.source_active
                     AND {CURRENT_CANDIDATE_CONTRACT_SQL}
                """
                approved_params = ()
            approved = int(
                conn.execute(
                    f"""
                    WITH latest_drafts AS (
                        SELECT DISTINCT ON (candidate_id)
                               candidate_id, draft_id, canonical_hash, frozen,
                               validation_errors, runtime_eligibility_status
                        FROM typed_rule_drafts
                        ORDER BY candidate_id, draft_version DESC, draft_id
                    )
                    SELECT count(*) AS count FROM latest_drafts drafts
                    {cohort_join}
                    WHERE drafts.frozen
                      AND drafts.validation_errors = '[]'::jsonb
                      AND drafts.runtime_eligibility_status = 'shadow_only'
                      AND EXISTS (
                        SELECT 1 FROM reviewer_decisions d
                        JOIN reviewer_tasks t USING (task_id)
                        WHERE d.draft_id = drafts.draft_id AND t.task_type = 'policy_review'
                          AND d.decision = 'approve' AND d.draft_hash = drafts.canonical_hash
                    ) AND EXISTS (
                        SELECT 1 FROM reviewer_decisions d
                        JOIN reviewer_tasks t USING (task_id)
                        WHERE d.draft_id = drafts.draft_id AND t.task_type = 'legal_verification'
                          AND d.decision = 'approve' AND d.draft_hash = drafts.canonical_hash
                    )
                      AND NOT EXISTS (
                          SELECT 1 FROM duplicate_conflict_members members
                          JOIN duplicate_conflict_clusters clusters USING (cluster_id)
                          WHERE members.draft_id = drafts.draft_id
                            AND (
                                clusters.status = 'open'
                                OR (clusters.resolution->>'selected_draft_id')
                                   IS DISTINCT FROM drafts.draft_id
                            )
                      )
                    """,
                    approved_params,
                ).fetchone()["count"]
            )
        return {
            "schema_version": "localbce-rules-review-export-v1",
            "release_id": release_id,
            "tasks": [dict(row) for row in task_rows],
            "decisions": [dict(row) for row in decision_rows],
            "legally_verified_shadow": approved,
            "runtime_activation": False,
            "proof_binding": False,
        }

    def legally_verified_shadow_rules(
        self, release_id: str | None = None
    ) -> list[dict[str, Any]]:
        cohort_join = ""
        params: tuple[Any, ...] = ()
        if release_id:
            self.release_cohort_summary(release_id)
            cohort_join = """
                JOIN corpus_release_cohorts cohorts
                  ON cohorts.candidate_id = drafts.candidate_id
                 AND cohorts.release_id = %s
            """
            params = (release_id,)
        else:
            cohort_join = f"""
                JOIN grounded_candidates candidates
                  ON candidates.candidate_id = drafts.candidate_id
                JOIN source_sections sections
                  ON sections.section_id = candidates.section_id
                 AND sections.active
                JOIN source_section_program_contexts contexts
                  ON contexts.section_id = candidates.section_id
                 AND contexts.program = candidates.primary_program
                 AND contexts.source_active
                 AND {CURRENT_CANDIDATE_CONTRACT_SQL}
            """
        with self.connection() as conn:
            rows = conn.execute(
                f"""
                WITH latest_drafts AS (
                    SELECT DISTINCT ON (candidate_id)
                           candidate_id, draft_id, canonical_hash, canonical_rule,
                           frozen, validation_errors, runtime_eligibility_status
                    FROM typed_rule_drafts
                    ORDER BY candidate_id, draft_version DESC, draft_id
                )
                SELECT drafts.candidate_id, drafts.draft_id,
                       drafts.canonical_hash, drafts.canonical_rule
                FROM latest_drafts drafts
                {cohort_join}
                WHERE drafts.frozen
                  AND drafts.validation_errors = '[]'::jsonb
                  AND drafts.runtime_eligibility_status = 'shadow_only'
                  AND EXISTS (
                      SELECT 1 FROM reviewer_decisions d JOIN reviewer_tasks t USING (task_id)
                      WHERE d.draft_id = drafts.draft_id AND t.task_type = 'policy_review'
                        AND d.decision = 'approve' AND d.draft_hash = drafts.canonical_hash
                  )
                  AND EXISTS (
                      SELECT 1 FROM reviewer_decisions d JOIN reviewer_tasks t USING (task_id)
                      WHERE d.draft_id = drafts.draft_id AND t.task_type = 'legal_verification'
                        AND d.decision = 'approve' AND d.draft_hash = drafts.canonical_hash
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM duplicate_conflict_members members
                      JOIN duplicate_conflict_clusters clusters USING (cluster_id)
                      WHERE members.draft_id = drafts.draft_id
                        AND (
                            clusters.status = 'open'
                            OR (clusters.resolution->>'selected_draft_id')
                               IS DISTINCT FROM drafts.draft_id
                        )
                )
                ORDER BY drafts.draft_id
                """,
                params,
            ).fetchall()
        return [dict(row) for row in rows]

    def quality_measurements(
        self, release_id: str | None = None
    ) -> dict[str, Any]:
        if release_id is not None:
            return self._release_quality_measurements(release_id)
        with self.connection() as conn:
            self._invalidate_stale_quality_samples_with_connection(conn)
            candidate_count = int(
                conn.execute(
                    f"""
                    SELECT count(*) AS count
                    FROM grounded_candidates candidates
                    JOIN source_sections sections USING (section_id)
                    JOIN source_section_program_contexts contexts
                      ON contexts.section_id = candidates.section_id
                     AND contexts.program = candidates.primary_program
                     AND contexts.source_active
                    WHERE sections.active
                      AND candidates.grounding_status = 'accepted'
                      AND {CURRENT_CANDIDATE_CONTRACT_SQL}
                    """
                ).fetchone()["count"]
            )
            sample_rows = conn.execute(
                """
                SELECT candidates.primary_program, samples.measurements
                FROM quality_samples samples
                JOIN quality_sample_plans plans
                  ON plans.sample_id = samples.sample_id
                 AND plans.candidate_id = samples.candidate_id
                JOIN grounded_candidates candidates
                  ON candidates.candidate_id = samples.candidate_id
                JOIN source_sections sections USING (section_id)
                JOIN source_section_program_contexts contexts
                  ON contexts.section_id = candidates.section_id
                 AND contexts.program = candidates.primary_program
                 AND contexts.source_active
                WHERE sections.active
                  AND plans.status = 'completed'
                ORDER BY samples.sample_id
                """
            ).fetchall()
            conflict_counts = _quality_conflict_counts(conn)
            coverage = conn.execute(
                f"""
                SELECT
                    avg(CASE WHEN snapshots.snapshot_hash IS NOT NULL THEN 1.0 ELSE 0.0 END) AS source_coverage,
                    avg(CASE WHEN length(candidates.evidence_quote) > 0 THEN 1.0 ELSE 0.0 END) AS citation_coverage
                FROM grounded_candidates candidates
                JOIN source_sections sections USING (section_id)
                JOIN source_section_program_contexts contexts
                  ON contexts.section_id = candidates.section_id
                 AND contexts.program = candidates.primary_program
                 AND contexts.source_active
                LEFT JOIN source_snapshots snapshots
                  ON snapshots.snapshot_hash = candidates.snapshot_hash
                WHERE sections.active
                  AND candidates.grounding_status = 'accepted'
                  AND {CURRENT_CANDIDATE_CONTRACT_SQL}
                """
            ).fetchone()
            two_role_sample_count = int(
                conn.execute(
                    """
                    SELECT count(*) AS count
                    FROM quality_samples samples
                    JOIN quality_sample_plans plans
                      ON plans.sample_id = samples.sample_id
                     AND plans.candidate_id = samples.candidate_id
                    JOIN grounded_candidates candidates
                      ON candidates.candidate_id = samples.candidate_id
                    JOIN source_sections sections USING (section_id)
                    JOIN source_section_program_contexts contexts
                      ON contexts.section_id = candidates.section_id
                     AND contexts.program = candidates.primary_program
                     AND contexts.source_active
                    WHERE sections.active
                      AND plans.status = 'completed'
                      AND policy_reviewer_id IS NOT NULL
                      AND legal_verifier_id IS NOT NULL
                      AND policy_reviewer_id <> legal_verifier_id
                    """
                ).fetchone()["count"]
            )
            mandatory_unsampled = int(
                conn.execute(
                    f"""
                    SELECT count(DISTINCT candidates.candidate_id) AS count
                    FROM grounded_candidates candidates
                    JOIN source_snapshots snapshots
                      ON snapshots.snapshot_hash = candidates.snapshot_hash
                    JOIN source_sections sections
                      ON sections.section_id = candidates.section_id
                    JOIN source_section_program_contexts contexts
                      ON contexts.section_id = candidates.section_id
                     AND contexts.program = candidates.primary_program
                     AND contexts.source_active
                    WHERE sections.active
                      AND candidates.grounding_status = 'accepted'
                      AND {CURRENT_CANDIDATE_CONTRACT_SQL}
                      AND (
                          sections.ocr_used
                          OR candidates.candidate_payload ? 'provenance_warning'
                          OR (
                              candidates.candidate_payload->>'confidence' ~ '^[0-9]+(?:\\.[0-9]+)?$'
                              AND (candidates.candidate_payload->>'confidence')::numeric < 0.85
                          )
                          OR EXISTS (
                              SELECT 1 FROM typed_rule_drafts drafts
                              JOIN duplicate_conflict_members members USING (draft_id)
                              JOIN duplicate_conflict_clusters clusters USING (cluster_id)
                              WHERE drafts.candidate_id = candidates.candidate_id
                          )
                      )
                      AND NOT EXISTS (
                          SELECT 1
                          FROM quality_samples samples
                          JOIN quality_sample_plans plans
                            ON plans.sample_id = samples.sample_id
                           AND plans.candidate_id = samples.candidate_id
                          WHERE samples.candidate_id = candidates.candidate_id
                            AND plans.status = 'completed'
                      )
                    """
                ).fetchone()["count"]
            )
            conn.commit()
        program_values: dict[str, list[float]] = {}
        evidence_values: list[float] = []
        mapping_values: list[float] = []
        classification_values: list[float] = []
        rerun_values: list[bool] = []
        for row in sample_rows:
            measurements = row["measurements"] or {}
            evidence_values.append(float(measurements.get("evidence_span_precise", 0)))
            mapping_values.append(float(measurements.get("typed_mapping_correct", 0)))
            classification = float(measurements.get("program_classification_correct", 0))
            classification_values.append(classification)
            program_values.setdefault(row["primary_program"], []).append(classification)
            rerun_values.append(bool(measurements.get("deterministic_rerun_match", False)))
        average = lambda values: sum(values) / len(values) if values else 0.0
        return {
            "candidate_count": candidate_count,
            "sample_count": len(sample_rows),
            "program_metrics": {
                program: {"classification_accuracy": average(values), "sample_count": len(values)}
                for program, values in program_values.items()
            },
            "source_snapshot_coverage": float(coverage["source_coverage"] or 0),
            "citation_coverage": float(coverage["citation_coverage"] or 0),
            "evidence_span_precision": average(evidence_values),
            "typed_mapping_precision": average(mapping_values),
            "program_classification_accuracy": average(classification_values),
            **conflict_counts,
            "deterministic_rerun_match": bool(rerun_values) and all(rerun_values),
            "mandatory_unsampled": mandatory_unsampled,
            "two_role_sample_count": two_role_sample_count,
        }

    def _release_quality_measurements(self, release_id: str) -> dict[str, Any]:
        self.release_cohort_summary(release_id)
        with self.connection() as conn:
            self._invalidate_stale_quality_samples_with_connection(
                conn, release_id=release_id
            )
            candidate_count = int(
                conn.execute(
                    """
                    SELECT count(*) AS count FROM corpus_release_cohorts
                    WHERE release_id = %s
                    """,
                    (release_id,),
                ).fetchone()["count"]
            )
            if candidate_count == 0:
                raise CorpusDatabaseError("release cohort does not exist")
            sample_rows = conn.execute(
                """
                SELECT candidates.primary_program, samples.measurements
                FROM quality_samples samples
                JOIN quality_sample_plans plans
                  ON plans.sample_id = samples.sample_id
                 AND plans.candidate_id = samples.candidate_id
                JOIN grounded_candidates candidates
                  ON candidates.candidate_id = samples.candidate_id
                JOIN corpus_release_cohorts cohorts
                  ON cohorts.candidate_id = candidates.candidate_id
                 AND cohorts.release_id = %s
                WHERE samples.release_id = %s
                  AND plans.status = 'completed'
                ORDER BY samples.sample_id
                """,
                (release_id, release_id),
            ).fetchall()
            conflict_counts = _quality_conflict_counts(
                conn,
                release_id=release_id,
            )
            coverage = conn.execute(
                """
                SELECT
                    avg(CASE WHEN snapshots.snapshot_hash IS NOT NULL THEN 1.0 ELSE 0.0 END) AS source_coverage,
                    avg(CASE WHEN length(candidates.evidence_quote) > 0 THEN 1.0 ELSE 0.0 END) AS citation_coverage
                FROM corpus_release_cohorts cohorts
                JOIN grounded_candidates candidates
                  ON candidates.candidate_id = cohorts.candidate_id
                LEFT JOIN source_snapshots snapshots
                  ON snapshots.snapshot_hash = candidates.snapshot_hash
                WHERE cohorts.release_id = %s
                """,
                (release_id,),
            ).fetchone()
            two_role_sample_count = int(
                conn.execute(
                    """
                    SELECT count(*) AS count
                    FROM quality_samples samples
                    JOIN quality_sample_plans plans
                      ON plans.sample_id = samples.sample_id
                     AND plans.candidate_id = samples.candidate_id
                    WHERE samples.release_id = %s
                      AND plans.status = 'completed'
                      AND samples.policy_reviewer_id IS NOT NULL
                      AND samples.legal_verifier_id IS NOT NULL
                      AND samples.policy_reviewer_id <>
                          samples.legal_verifier_id
                    """,
                    (release_id,),
                ).fetchone()["count"]
            )
            mandatory_unsampled = int(
                conn.execute(
                    """
                    SELECT count(DISTINCT candidates.candidate_id) AS count
                    FROM corpus_release_cohorts cohorts
                    JOIN grounded_candidates candidates
                      ON candidates.candidate_id = cohorts.candidate_id
                    JOIN source_snapshots snapshots
                      ON snapshots.snapshot_hash = candidates.snapshot_hash
                    WHERE cohorts.release_id = %s
                      AND (
                          snapshots.text_layer_kind = 'ocr'
                          OR candidates.candidate_payload ? 'provenance_warning'
                          OR (
                              candidates.candidate_payload->>'confidence' ~ '^[0-9]+(?:\\.[0-9]+)?$'
                              AND (candidates.candidate_payload->>'confidence')::numeric < 0.85
                          )
                          OR EXISTS (
                              SELECT 1 FROM typed_rule_drafts drafts
                              JOIN duplicate_conflict_members members USING (draft_id)
                              JOIN duplicate_conflict_clusters clusters USING (cluster_id)
                              WHERE drafts.candidate_id = candidates.candidate_id
                          )
                      )
                      AND NOT EXISTS (
                          SELECT 1
                          FROM quality_samples samples
                          JOIN quality_sample_plans plans
                            ON plans.sample_id = samples.sample_id
                           AND plans.candidate_id = samples.candidate_id
                          WHERE samples.candidate_id = candidates.candidate_id
                            AND samples.release_id = %s
                            AND plans.status = 'completed'
                      )
                    """,
                    (release_id, release_id),
                ).fetchone()["count"]
            )
            conn.commit()
        program_values: dict[str, list[float]] = {}
        evidence_values: list[float] = []
        mapping_values: list[float] = []
        classification_values: list[float] = []
        rerun_values: list[bool] = []
        for row in sample_rows:
            measurements = row["measurements"] or {}
            evidence_values.append(float(measurements.get("evidence_span_precise", 0)))
            mapping_values.append(float(measurements.get("typed_mapping_correct", 0)))
            classification = float(
                measurements.get("program_classification_correct", 0)
            )
            classification_values.append(classification)
            program_values.setdefault(row["primary_program"], []).append(classification)
            rerun_values.append(
                bool(measurements.get("deterministic_rerun_match", False))
            )

        def average(values: list[float]) -> float:
            return sum(values) / len(values) if values else 0.0

        return {
            "candidate_count": candidate_count,
            "sample_count": len(sample_rows),
            "program_metrics": {
                program: {
                    "classification_accuracy": average(values),
                    "sample_count": len(values),
                }
                for program, values in program_values.items()
            },
            "source_snapshot_coverage": float(coverage["source_coverage"] or 0),
            "citation_coverage": float(coverage["citation_coverage"] or 0),
            "evidence_span_precision": average(evidence_values),
            "typed_mapping_precision": average(mapping_values),
            "program_classification_accuracy": average(classification_values),
            **conflict_counts,
            "deterministic_rerun_match": bool(rerun_values) and all(rerun_values),
            "mandatory_unsampled": mandatory_unsampled,
            "two_role_sample_count": two_role_sample_count,
        }

    def blocker_counts(self, release_id: str | None = None) -> dict[str, int]:
        cohort_join = ""
        params: tuple[Any, ...] = ()
        if release_id:
            self.release_cohort_summary(release_id)
            cohort_join = """
                JOIN corpus_release_cohorts cohorts
                  ON cohorts.candidate_id = drafts.candidate_id
                 AND cohorts.release_id = %s
            """
            params = (release_id,)
        else:
            cohort_join = f"""
                JOIN grounded_candidates candidates
                  ON candidates.candidate_id = drafts.candidate_id
                 AND candidates.grounding_status = 'accepted'
                 AND {CURRENT_CANDIDATE_CONTRACT_SQL}
                JOIN source_sections sections
                  ON sections.section_id = candidates.section_id
                 AND sections.active
                JOIN source_section_program_contexts contexts
                  ON contexts.section_id = candidates.section_id
                 AND contexts.program = candidates.primary_program
                 AND contexts.source_active
            """
        with self.connection() as conn:
            rows = conn.execute(
                f"""
                WITH latest_drafts AS (
                    SELECT DISTINCT ON (candidate_id)
                           candidate_id, blocker_codes
                    FROM typed_rule_drafts
                    ORDER BY candidate_id, draft_version DESC, draft_id
                )
                SELECT blockers.value AS blocker, count(*) AS count
                FROM latest_drafts drafts
                {cohort_join}
                CROSS JOIN LATERAL
                    jsonb_array_elements_text(drafts.blocker_codes) blockers(value)
                GROUP BY blockers.value ORDER BY blockers.value
                """,
                params,
            ).fetchall()
        return {str(row["blocker"]): int(row["count"]) for row in rows}

    def save_release(self, manifest: dict[str, Any]) -> None:
        from psycopg.types.json import Jsonb

        with self.connection() as conn:
            existing = conn.execute(
                "SELECT canonical_release_hash FROM corpus_releases WHERE release_id = %s",
                (manifest["release_id"],),
            ).fetchone()
            if existing:
                if existing["canonical_release_hash"] != manifest["canonical_release_hash"]:
                    raise CorpusDatabaseError("release ID already exists with a different canonical hash")
                return
            conn.execute(
                """
                INSERT INTO corpus_releases (
                    release_id, schema_version, target_count, candidate_count,
                    source_manifest_hash, prompt_versions, model_versions,
                    program_coverage, blocker_counts, quality_metrics,
                    reviewer_evidence, manifest, canonical_release_hash, gates_passed
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    manifest["release_id"],
                    manifest["schema_version"],
                    manifest["target_count"],
                    manifest["candidate_count"],
                    manifest["source_manifest_hash"],
                    Jsonb(manifest["prompt_versions"]),
                    Jsonb(manifest["model_versions"]),
                    Jsonb(manifest["program_coverage"]),
                    Jsonb(manifest["blocker_counts"]),
                    Jsonb(manifest["quality"]),
                    Jsonb(manifest["reviewer_evidence"]),
                    Jsonb(manifest),
                    manifest["canonical_release_hash"],
                    manifest["gates_passed"],
                ),
            )
            conn.commit()
