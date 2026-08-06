from __future__ import annotations

import json
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .canonical_rules import build_promotion_queue, canonical_sha256
from .scaled_corpus import stable_id


class CorpusDatabaseError(RuntimeError):
    pass


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

    def migrate(self, migrations_dir: Path) -> list[str]:
        files = sorted(migrations_dir.glob("*.sql"))
        if not files:
            raise CorpusDatabaseError("no PostgreSQL migrations found")
        applied: list[str] = []
        with self.connection() as conn:
            for path in files:
                conn.execute(path.read_text(encoding="utf-8"))
                applied.append(path.name)
            conn.commit()
        return applied

    def sync_registry(self, registry: dict[str, Any]) -> int:
        from psycopg.types.json import Jsonb

        with self.connection() as conn:
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

    def list_active_sources(self, *, limit: int = 0) -> list[dict[str, Any]]:
        sql = "SELECT * FROM official_sources WHERE active ORDER BY program, canonical_url"
        params: tuple[Any, ...] = ()
        if limit > 0:
            sql += " LIMIT %s"
            params = (limit,)
        with self.connection() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    def save_snapshot(
        self,
        snapshot: dict[str, Any],
        *,
        response_headers: dict[str, str] | None = None,
    ) -> str:
        from psycopg.types.json import Jsonb

        retrieval_id = stable_id(
            "ret",
            snapshot["source_id"],
            snapshot["snapshot_hash"],
            snapshot["retrieved_at"],
        )
        with self.connection() as conn:
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
                    Jsonb(response_headers or {}),
                ),
            )
            conn.commit()
        return retrieval_id

    def save_sections(self, retrieval_id: str, sections: list[dict[str, Any]]) -> int:
        from psycopg.types.json import Jsonb

        with self.connection() as conn:
            for section in sections:
                conn.execute(
                    """
                    INSERT INTO source_sections (
                        section_id, snapshot_hash, retrieval_id, parent_section_id, ordinal,
                        hierarchy_path, heading, normalized_text, normalized_text_hash,
                        source_char_start, source_char_end, parser_name, parser_version, ocr_used
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (section_id) DO NOTHING
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
                        section["ocr_used"],
                    ),
                )
            conn.commit()
        return len(sections)

    def unsectioned_retrievals(self, *, limit: int = 0) -> list[dict[str, Any]]:
        sql = """
            SELECT retrievals.*, snapshots.mime_type, snapshots.compression,
                   snapshots.compressed_bytes, snapshots.uncompressed_size,
                   snapshots.text_layer_kind
            FROM source_snapshot_retrievals retrievals
            JOIN source_snapshots snapshots USING (snapshot_hash)
            WHERE NOT EXISTS (
                SELECT 1 FROM source_sections sections
                WHERE sections.retrieval_id = retrievals.retrieval_id
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

    def uninferred_sections(self, *, limit: int = 0) -> list[dict[str, Any]]:
        sql = """
            SELECT sections.*, sources.program
            FROM source_sections sections
            JOIN source_snapshot_retrievals retrievals USING (retrieval_id)
            JOIN official_sources sources USING (source_id)
            WHERE NOT EXISTS (
                SELECT 1 FROM inference_jobs jobs
                WHERE jobs.section_id = sections.section_id AND jobs.pass = 1
            )
            ORDER BY sources.program, sections.section_id
        """
        params: tuple[Any, ...] = ()
        if limit > 0:
            sql += " LIMIT %s"
            params = (limit,)
        with self.connection() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    def section(self, section_id: str) -> dict[str, Any]:
        with self.connection() as conn:
            row = conn.execute(
                """
                SELECT sections.*, sources.program
                FROM source_sections sections
                JOIN source_snapshot_retrievals retrievals USING (retrieval_id)
                JOIN official_sources sources USING (source_id)
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

    def claim_inference_jobs(self, worker_id: str, *, limit: int = 8, lease_seconds: int = 300) -> list[dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute(
                """
                WITH claimable AS (
                    SELECT inference_job_id
                    FROM inference_jobs
                    WHERE status = 'pending'
                       OR (status = 'leased' AND lease_expires_at < now())
                    ORDER BY pass, created_at, inference_job_id
                    FOR UPDATE SKIP LOCKED
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

    def complete_inference_job(
        self,
        job_id: str,
        *,
        worker_id: str,
        response_payload: dict[str, Any],
        input_tokens: int,
        output_tokens: int,
        usage_metadata: dict[str, Any],
    ) -> None:
        from psycopg.types.json import Jsonb

        with self.connection() as conn:
            cursor = conn.execute(
                """
                UPDATE inference_jobs SET
                    status = 'completed', response_payload = %s,
                    input_tokens = %s, output_tokens = %s, usage_metadata = %s,
                    completed_at = now(), lease_owner = NULL, lease_expires_at = NULL
                WHERE inference_job_id = %s AND status = 'leased' AND lease_owner = %s
                """,
                (
                    Jsonb(response_payload),
                    input_tokens,
                    output_tokens,
                    Jsonb(usage_metadata),
                    job_id,
                    worker_id,
                ),
            )
            if cursor.rowcount != 1:
                raise CorpusDatabaseError("inference lease was lost before completion")
            conn.commit()

    def save_grounded_candidates(
        self,
        *,
        job_id: str,
        section: dict[str, Any],
        response_payload: dict[str, Any],
    ) -> list[str]:
        from psycopg.types.json import Jsonb

        from .scaled_corpus import candidate_id

        saved: list[str] = []
        with self.connection() as conn:
            for candidate in response_payload.get("candidates", []):
                evidence = candidate["evidence"]
                identifier = candidate_id(section, candidate)
                stored_candidate = {**candidate, "candidate_id": identifier}
                conn.execute(
                    """
                    INSERT INTO grounded_candidates (
                        candidate_id, primary_program, section_id, snapshot_hash,
                        evidence_char_start, evidence_char_end, evidence_byte_start,
                        evidence_byte_end, evidence_quote, evidence_hash,
                        extraction_job_id, candidate_payload, grounding_status
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'pending')
                    ON CONFLICT (candidate_id) DO NOTHING
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
            conn.commit()
        return saved

    def pending_critique_sections(self, *, limit: int = 0) -> list[dict[str, Any]]:
        sql = """
            SELECT sections.*, sources.program,
                   jsonb_agg(candidates.candidate_payload ORDER BY candidates.candidate_id) AS proposed_candidates
            FROM source_sections sections
            JOIN source_snapshot_retrievals retrievals USING (retrieval_id)
            JOIN official_sources sources USING (source_id)
            JOIN grounded_candidates candidates USING (section_id)
            WHERE candidates.grounding_status = 'pending'
              AND NOT EXISTS (
                  SELECT 1 FROM inference_jobs jobs
                  WHERE jobs.section_id = sections.section_id AND jobs.pass = 2
              )
            GROUP BY sections.section_id, sources.program
            ORDER BY sections.section_id
        """
        params: tuple[Any, ...] = ()
        if limit > 0:
            sql += " LIMIT %s"
            params = (limit,)
        with self.connection() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    def apply_critique(self, *, job_id: str, section_id: str, response_payload: dict[str, Any]) -> int:
        statuses = {
            str(item.get("candidate_id")): str(item.get("critique", {}).get("result"))
            for item in response_payload.get("candidates", [])
            if isinstance(item, dict) and isinstance(item.get("critique"), dict)
        }
        updated = 0
        with self.connection() as conn:
            for identifier, result in statuses.items():
                if result not in {"accept", "repair", "reject"}:
                    raise CorpusDatabaseError("critique result must be accept, repair, or reject")
                grounding_status = {"accept": "accepted", "repair": "repair", "reject": "rejected"}[result]
                cursor = conn.execute(
                    """
                    UPDATE grounded_candidates
                    SET critique_job_id = %s, grounding_status = %s
                    WHERE candidate_id = %s AND section_id = %s AND grounding_status = 'pending'
                    """,
                    (job_id, grounding_status, identifier, section_id),
                )
                updated += cursor.rowcount
            conn.commit()
        return updated

    def materialize_review_drafts(self) -> dict[str, int]:
        from psycopg.types.json import Jsonb

        from .scaled_corpus import (
            build_typed_rule_draft,
            draft_fingerprints,
            effective_periods_overlap,
            validate_typed_rule_draft,
        )

        created = 0
        blocked = 0
        tasks_created = 0
        clusters_created = 0
        with self.connection() as conn:
            candidates = conn.execute(
                """
                SELECT candidates.*, retrievals.canonical_url
                FROM grounded_candidates candidates
                JOIN source_sections sections USING (section_id)
                JOIN source_snapshot_retrievals retrievals USING (retrieval_id)
                WHERE candidates.grounding_status = 'accepted'
                  AND NOT EXISTS (
                      SELECT 1 FROM typed_rule_drafts drafts
                      WHERE drafts.candidate_id = candidates.candidate_id
                  )
                ORDER BY candidates.candidate_id
                """
            ).fetchall()
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
            elif "effective" in lowered or "yyyy-mm-dd" in lowered:
                blockers.add("invalid_effective_date")
            elif "source" in lowered or "authority" in lowered or "citation" in lowered:
                blockers.add("missing_provenance")
            else:
                blockers.add("schema_validation_failed")
        return blockers

    def fail_inference_job(self, job_id: str, *, worker_id: str, error: str, retry: bool) -> None:
        status = "pending" if retry else "failed"
        with self.connection() as conn:
            cursor = conn.execute(
                """
                UPDATE inference_jobs SET status = %s, last_error = %s,
                    lease_owner = NULL, lease_expires_at = NULL
                WHERE inference_job_id = %s AND status = 'leased' AND lease_owner = %s
                """,
                (status, error[:4000], job_id, worker_id),
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

    def claim_review_task(self, reviewer_id: str, reviewer_role: str) -> dict[str, Any] | None:
        task_type = {
            "policy_reviewer": "policy_review",
            "legal_verifier": "legal_verification",
            "rules_admin": "conflict_resolution",
        }.get(reviewer_role)
        if not task_type:
            raise ValueError("unsupported reviewer role")
        with self.connection() as conn:
            row = conn.execute(
                """
                WITH claimable AS (
                    SELECT task_id FROM reviewer_tasks
                    WHERE task_type = %s AND status = 'pending'
                    ORDER BY created_at, task_id
                    FOR UPDATE SKIP LOCKED
                    LIMIT 1
                )
                UPDATE reviewer_tasks AS tasks
                SET status = 'claimed', assigned_reviewer_id = %s, claimed_at = now()
                FROM claimable
                WHERE tasks.task_id = claimable.task_id
                RETURNING tasks.*
                """,
                (task_type, reviewer_id),
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
                audit_id = stable_id("audit", row["task_id"], reviewer_id, "claimed", str(row["claimed_at"]))
                from psycopg.types.json import Jsonb

                conn.execute(
                    """
                    INSERT INTO review_audit_events (
                        event_id, actor_id, action, entity_type, entity_id, payload
                    ) VALUES (%s, %s, 'task_claimed', 'reviewer_task', %s, %s)
                    ON CONFLICT (event_id) DO NOTHING
                    """,
                    (audit_id, reviewer_id, row["task_id"], Jsonb({"reviewer_role": reviewer_role})),
                )
            conn.commit()
        return dict(row) if row else None

    def list_review_tasks(self, reviewer_role: str, *, limit: int = 100) -> list[dict[str, Any]]:
        task_type = {
            "policy_reviewer": "policy_review",
            "legal_verifier": "legal_verification",
            "rules_admin": "conflict_resolution",
        }.get(reviewer_role)
        if not task_type:
            raise ValueError("unsupported reviewer role")
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT tasks.task_id, tasks.draft_id, drafts.candidate_id,
                       tasks.task_type, tasks.status, tasks.assigned_reviewer_id,
                       tasks.claimed_at, tasks.completed_at, tasks.created_at
                FROM reviewer_tasks tasks
                JOIN typed_rule_drafts drafts USING (draft_id)
                WHERE tasks.task_type = %s
                ORDER BY tasks.status, tasks.created_at, tasks.task_id
                LIMIT %s
                """,
                (task_type, max(1, min(limit, 500))),
            ).fetchall()
        return [dict(row) for row in rows]

    def candidate_review_detail(self, candidate_id: str) -> dict[str, Any]:
        with self.connection() as conn:
            row = conn.execute(
                """
                SELECT candidates.candidate_id, candidates.primary_program,
                       candidates.evidence_quote, candidates.evidence_char_start,
                       candidates.evidence_char_end, candidates.evidence_hash,
                       candidates.grounding_status, candidates.candidate_payload,
                       sections.heading, sections.normalized_text,
                       sections.hierarchy_path, retrievals.canonical_url,
                       retrievals.retrieved_at, snapshots.text_layer_kind
                FROM grounded_candidates candidates
                JOIN source_sections sections USING (section_id)
                JOIN source_snapshot_retrievals retrievals USING (retrieval_id)
                JOIN source_snapshots snapshots USING (snapshot_hash)
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
        return {**dict(row), "drafts": [dict(item) for item in drafts], "decisions": [dict(item) for item in decisions]}

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
            task = conn.execute(
                """
                SELECT tasks.*, drafts.canonical_hash
                FROM reviewer_tasks tasks
                JOIN typed_rule_drafts drafts ON drafts.draft_id = tasks.draft_id
                WHERE tasks.task_id = %s FOR UPDATE
                """,
                (task_id,),
            ).fetchone()
            if not task or task["status"] != "claimed" or task["assigned_reviewer_id"] != reviewer_id:
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
                """
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
                "UPDATE reviewer_tasks SET status = 'completed', completed_at = now() WHERE task_id = %s",
                (task_id,),
            )
            conn.commit()
        return decision_id

    def rules_metrics(self) -> dict[str, Any]:
        with self.connection() as conn:
            tables = {}
            for name in (
                "official_sources",
                "source_snapshots",
                "source_sections",
                "inference_jobs",
                "grounded_candidates",
                "typed_rule_drafts",
                "reviewer_tasks",
                "reviewer_decisions",
                "corpus_releases",
                "legacy_baseline_candidates",
            ):
                tables[name] = int(conn.execute(f"SELECT count(*) AS count FROM {name}").fetchone()["count"])
            programs = conn.execute(
                """
                SELECT primary_program, count(*) AS count
                FROM grounded_candidates
                WHERE grounding_status = 'accepted'
                GROUP BY primary_program ORDER BY primary_program
                """
            ).fetchall()
        return {
            "table_counts": tables,
            "accepted_candidates_by_program": {row["primary_program"]: row["count"] for row in programs},
            "runtime_activation": False,
            "proof_binding": False,
        }

    def release_candidates(self) -> list[dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT candidate_id, primary_program, section_id, snapshot_hash,
                       evidence_hash, grounding_status, candidate_payload
                FROM grounded_candidates
                WHERE grounding_status = 'accepted'
                  AND EXISTS (
                      SELECT 1 FROM typed_rule_drafts drafts
                      WHERE drafts.candidate_id = grounded_candidates.candidate_id
                        AND drafts.validation_errors = '[]'::jsonb
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM typed_rule_drafts drafts
                      JOIN duplicate_conflict_members members USING (draft_id)
                      JOIN duplicate_conflict_clusters clusters USING (cluster_id)
                      WHERE drafts.candidate_id = grounded_candidates.candidate_id
                        AND (
                            clusters.status = 'open'
                            OR clusters.resolution->>'selected_draft_id' <> drafts.draft_id
                        )
                  )
                ORDER BY candidate_id
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def review_export(self) -> dict[str, Any]:
        with self.connection() as conn:
            task_rows = conn.execute(
                "SELECT task_type, status, count(*) AS count FROM reviewer_tasks GROUP BY task_type, status"
            ).fetchall()
            decision_rows = conn.execute(
                "SELECT reviewer_role, decision, count(*) AS count FROM reviewer_decisions GROUP BY reviewer_role, decision"
            ).fetchall()
            approved = int(
                conn.execute(
                    """
                    SELECT count(*) AS count FROM typed_rule_drafts drafts
                    WHERE EXISTS (
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
                    """
                ).fetchone()["count"]
            )
        return {
            "schema_version": "localbce-rules-review-export-v1",
            "tasks": [dict(row) for row in task_rows],
            "decisions": [dict(row) for row in decision_rows],
            "legally_verified_shadow": approved,
            "runtime_activation": False,
            "proof_binding": False,
        }

    def legally_verified_shadow_rules(self) -> list[dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT drafts.draft_id, drafts.canonical_hash, drafts.canonical_rule
                FROM typed_rule_drafts drafts
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
                ORDER BY drafts.draft_id
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def quality_measurements(self) -> dict[str, Any]:
        with self.connection() as conn:
            candidate_count = int(
                conn.execute("SELECT count(*) AS count FROM grounded_candidates WHERE grounding_status = 'accepted'").fetchone()["count"]
            )
            sample_rows = conn.execute(
                """
                SELECT candidates.primary_program, samples.measurements
                FROM quality_samples samples
                JOIN grounded_candidates candidates USING (candidate_id)
                ORDER BY samples.sample_id
                """
            ).fetchall()
            conflicts = int(
                conn.execute(
                    "SELECT count(*) AS count FROM duplicate_conflict_clusters WHERE status = 'open' AND cluster_kind = 'conflicting_outcome'"
                ).fetchone()["count"]
            )
            coverage = conn.execute(
                """
                SELECT
                    avg(CASE WHEN snapshots.snapshot_hash IS NOT NULL THEN 1.0 ELSE 0.0 END) AS source_coverage,
                    avg(CASE WHEN length(candidates.evidence_quote) > 0 THEN 1.0 ELSE 0.0 END) AS citation_coverage
                FROM grounded_candidates candidates
                LEFT JOIN source_snapshots snapshots USING (snapshot_hash)
                WHERE candidates.grounding_status = 'accepted'
                """
            ).fetchone()
            two_role_sample_count = int(
                conn.execute(
                    """
                    SELECT count(*) AS count FROM quality_samples
                    WHERE policy_reviewer_id IS NOT NULL
                      AND legal_verifier_id IS NOT NULL
                      AND policy_reviewer_id <> legal_verifier_id
                    """
                ).fetchone()["count"]
            )
            mandatory_unsampled = int(
                conn.execute(
                    """
                    SELECT count(DISTINCT candidates.candidate_id) AS count
                    FROM grounded_candidates candidates
                    JOIN source_snapshots snapshots USING (snapshot_hash)
                    WHERE candidates.grounding_status = 'accepted'
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
                          SELECT 1 FROM quality_samples samples
                          WHERE samples.candidate_id = candidates.candidate_id
                      )
                    """
                ).fetchone()["count"]
            )
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
            "silently_merged_conflicts": conflicts,
            "deterministic_rerun_match": bool(rerun_values) and all(rerun_values),
            "mandatory_unsampled": mandatory_unsampled,
            "two_role_sample_count": two_role_sample_count,
        }

    def blocker_counts(self) -> dict[str, int]:
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT blocker, count(*) AS count
                FROM typed_rule_drafts drafts,
                     LATERAL jsonb_array_elements_text(drafts.blocker_codes) blocker
                GROUP BY blocker ORDER BY blocker
                """
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
