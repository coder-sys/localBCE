from __future__ import annotations

import json
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from .claude_inference import ClaudeGroundedClient, ClaudeInferenceError
from .postgres_corpus import PostgresCorpusStore
from .scaled_corpus import (
    build_inference_request,
    build_release_manifest,
    build_shadow_bundle,
    build_source_snapshot,
    load_source_registry,
    quality_gate_report,
    restore_snapshot_bytes,
    segment_text,
)
from .source_adapters import extract_source_text


MAX_SOURCE_BYTES = 50 * 1024 * 1024


def _write_report(workdir: Path, name: str, payload: dict[str, Any]) -> Path:
    path = workdir / "reports" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def migrate_corpus(workdir: Path, store: PostgresCorpusStore) -> dict[str, Any]:
    applied = store.migrate(workdir / "migrations")
    return {"database": "postgresql", "migrations": applied, "status": "ok"}


def sources_sync(
    workdir: Path,
    store: PostgresCorpusStore,
    *,
    fetch: bool,
    limit: int,
    timeout_seconds: float,
) -> dict[str, Any]:
    registry = load_source_registry(workdir)
    synced = store.sync_registry(registry)
    baseline = store.import_blocked_baseline(workdir)
    fetched = 0
    failures: list[dict[str, str]] = []
    if fetch:
        client = httpx.Client(
            timeout=timeout_seconds,
            follow_redirects=True,
            headers={"user-agent": "localBCE-grounded-rules/1.0 (+source-snapshot)"},
        )
        try:
            for source in store.list_active_sources(limit=limit):
                try:
                    response = client.get(source["canonical_url"])
                    response.raise_for_status()
                    raw = response.content
                    if not raw or len(raw) > MAX_SOURCE_BYTES:
                        raise ValueError("source response is empty or exceeds 50 MiB")
                    final_url = str(response.url)
                    if not final_url.startswith("https://"):
                        raise ValueError("source redirected away from https")
                    final_host = response.url.host.lower() if response.url.host else ""
                    if not (final_host.endswith(".gov") or final_host == "gov"):
                        raise ValueError("source redirected outside an official .gov host")
                    payload_source = {**source, "canonical_url": final_url}
                    snapshot = build_source_snapshot(
                        payload_source,
                        raw,
                        retrieved_at=datetime.now(timezone.utc).isoformat(),
                        mime_type=response.headers.get("content-type", "application/octet-stream"),
                        http_status=response.status_code,
                        effective_metadata={
                            "etag": response.headers.get("etag"),
                            "last_modified": response.headers.get("last-modified"),
                        },
                    )
                    safe_headers = {
                        key.lower(): value
                        for key, value in response.headers.items()
                        if key.lower() in {"content-type", "content-length", "etag", "last-modified", "date"}
                    }
                    store.save_snapshot(snapshot, response_headers=safe_headers)
                    fetched += 1
                except (httpx.HTTPError, ValueError) as exc:
                    failures.append({"source_id": source["source_id"], "error": str(exc)})
        finally:
            client.close()
    report = {
        "schema_version": "localbce-sources-sync-report-v1",
        "registry_id": registry["registry_id"],
        "registered_sources": synced,
        "covered_programs": len(registry["program_quotas"]),
        "target_candidates": registry["target_unique_grounded_candidates"],
        "baseline_candidates_imported": baseline,
        "snapshots_fetched": fetched,
        "failures": failures,
        "fetch_enabled": fetch,
        "runtime_activation": False,
        "proof_binding": False,
    }
    report["report"] = str(_write_report(workdir, "rules_sources_sync_v1.json", report))
    return report


def sections_extract(workdir: Path, store: PostgresCorpusStore, *, limit: int) -> dict[str, Any]:
    retrievals = store.unsectioned_retrievals(limit=limit)
    section_count = 0
    warnings: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    for retrieval in retrievals:
        try:
            raw = restore_snapshot_bytes(retrieval)
            extracted = extract_source_text(
                raw,
                mime_type=retrieval["mime_type"],
                source_url=retrieval["canonical_url"],
            )
            sections = segment_text(
                retrieval["snapshot_hash"],
                extracted.text,
                parser_name=extracted.parser_name,
                parser_version=extracted.parser_version,
                ocr_used=extracted.text_layer_kind == "ocr",
            )
            section_count += store.save_sections(retrieval["retrieval_id"], sections)
            if extracted.warnings:
                warnings.append({"retrieval_id": retrieval["retrieval_id"], "warnings": extracted.warnings})
        except (RuntimeError, ValueError) as exc:
            failures.append({"retrieval_id": retrieval["retrieval_id"], "error": str(exc)})
    report = {
        "schema_version": "localbce-sections-extract-report-v1",
        "retrievals_processed": len(retrievals),
        "sections_created": section_count,
        "warnings": warnings,
        "failures": failures,
        "runtime_activation": False,
        "proof_binding": False,
    }
    report["report"] = str(_write_report(workdir, "rules_sections_extract_v1.json", report))
    return report


def _run_job(store: PostgresCorpusStore, client: ClaudeGroundedClient, worker_id: str, job: dict[str, Any]) -> dict[str, Any]:
    request = job["request_payload"]
    section = store.section(request["section"]["section_id"])
    proposed = request.get("proposed_candidates")
    try:
        response, usage = client.infer(
            section,
            request["program"],
            pass_number=int(request["pass"]),
            proposed_candidates=proposed,
        )
        if int(request["pass"]) == 1:
            affected = len(store.save_grounded_candidates(job_id=job["inference_job_id"], section=section, response_payload=response))
        else:
            affected = store.apply_critique(
                job_id=job["inference_job_id"], section_id=section["section_id"], response_payload=response
            )
        store.complete_inference_job(
            job["inference_job_id"],
            worker_id=worker_id,
            response_payload=response,
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            usage_metadata={"model": usage.model, "request_id": usage.request_id},
        )
        return {"job_id": job["inference_job_id"], "pass": request["pass"], "affected": affected, "status": "completed"}
    except ClaudeInferenceError as exc:
        store.fail_inference_job(
            job["inference_job_id"],
            worker_id=worker_id,
            error=str(exc),
            retry=int(job["attempts"]) < 5,
        )
        return {"job_id": job["inference_job_id"], "pass": request["pass"], "status": "failed", "error": str(exc)}


def claude_infer(
    workdir: Path,
    store: PostgresCorpusStore,
    *,
    limit: int,
    concurrency: int = 8,
) -> dict[str, Any]:
    if limit <= 0:
        raise ValueError("claude inference limit must be positive")
    if concurrency <= 0 or concurrency > 32:
        raise ValueError("claude concurrency must be between 1 and 32")
    for section in store.uninferred_sections(limit=limit):
        store.enqueue_inference(build_inference_request(section, section["program"], pass_number=1))
    client = ClaudeGroundedClient()
    worker_id = f"{socket.gethostname()}-{os_getpid()}"
    results: list[dict[str, Any]] = []

    def drain(maximum: int) -> None:
        processed = 0
        while processed < maximum:
            batch_size = min(concurrency, maximum - processed)
            jobs = store.claim_inference_jobs(worker_id, limit=batch_size)
            if not jobs:
                return
            with ThreadPoolExecutor(max_workers=concurrency) as executor:
                futures = [executor.submit(_run_job, store, client, worker_id, job) for job in jobs]
                results.extend(future.result() for future in as_completed(futures))
            processed += len(jobs)

    drain(limit)
    for section in store.pending_critique_sections(limit=limit):
        store.enqueue_inference(
            build_inference_request(
                section,
                section["program"],
                pass_number=2,
                proposed_candidates=section["proposed_candidates"],
            )
        )
    drain(limit)
    review_materialization = store.materialize_review_drafts()
    report = {
        "schema_version": "localbce-claude-inference-run-v1",
        "model": client.model,
        "concurrency": concurrency,
        "results": sorted(results, key=lambda item: item["job_id"]),
        "completed": sum(item["status"] == "completed" for item in results),
        "failed": sum(item["status"] == "failed" for item in results),
        "review_materialization": review_materialization,
        "runtime_activation": False,
        "proof_binding": False,
    }
    report["report"] = str(_write_report(workdir, "rules_claude_inference_v1.json", report))
    return report


def os_getpid() -> int:
    import os

    return os.getpid()


def quality_evaluate(workdir: Path, store: PostgresCorpusStore) -> dict[str, Any]:
    report = quality_gate_report(**store.quality_measurements())
    report["report"] = str(_write_report(workdir, "rules_scale_quality_v1.json", report))
    return report


def review_export(workdir: Path, store: PostgresCorpusStore) -> dict[str, Any]:
    report = store.review_export()
    report["report"] = str(_write_report(workdir, "rules_review_export_v1.json", report))
    return report


def shadow_bundle_export(workdir: Path, store: PostgresCorpusStore, *, release_manifest: Path) -> dict[str, Any]:
    release = json.loads(release_manifest.read_text(encoding="utf-8"))
    if release.get("gates_passed") is not True:
        raise ValueError("shadow export requires a release that passed every corpus gate")
    rules = store.legally_verified_shadow_rules()
    bundle = build_shadow_bundle(release, rules)
    path = _write_report(workdir, "grounded_rules_shadow_bundle_v1.json", bundle)
    return {"output": str(path), "rule_count": len(rules), "rules_sha256": bundle["rules_sha256"], "runtime_activation": False, "proof_binding": False}


def corpus_release(workdir: Path, store: PostgresCorpusStore, *, release_id: str, target_count: int) -> dict[str, Any]:
    registry = load_source_registry(workdir)
    quality = quality_gate_report(**store.quality_measurements())
    candidates = store.release_candidates()
    reviewer = store.review_export()
    manifest = build_release_manifest(
        release_id=release_id,
        target_count=target_count,
        candidates=candidates,
        source_manifest_hash=registry["source_pack_sha256"],
        quality_report=quality,
        blocker_counts=store.blocker_counts(),
        reviewer_evidence=reviewer,
    )
    path = _write_report(workdir, f"corpus_release_{release_id}.json", manifest)
    if manifest["gates_passed"]:
        store.save_release(manifest)
        status = "released"
    else:
        status = "blocked_incomplete_milestone"
    return {**manifest, "status": status, "report": str(path)}
