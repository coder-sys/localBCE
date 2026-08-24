from __future__ import annotations

import json
import os
import re
import socket
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, as_completed, wait
from datetime import datetime, timezone
from pathlib import Path
from threading import Event, Thread
from typing import Any
from urllib.parse import urlencode, urljoin, urlparse

import httpx

from .canonical_rules import canonical_sha256
from .claude_inference import ClaudeGroundedClient, ClaudeInferenceError
from .postgres_corpus import CorpusDatabaseError, PostgresCorpusStore
from .scaled_corpus import (
    assess_section_relevance,
    build_inference_launch_plan,
    build_ocr_artifact,
    build_inference_request,
    build_release_manifest,
    build_shadow_bundle,
    build_source_registry_release,
    build_source_snapshot,
    load_source_registry,
    quality_gate_report,
    restore_snapshot_bytes,
    segment_structured_blocks,
    segment_text,
    validate_release_manifest,
    validate_inference_launch_plan,
    validate_source_candidate_preflight_report,
)
from .source_adapters import (
    SOURCE_DISCOVERY_PARSER_VERSION,
    discover_official_links,
    extract_source_text,
)
from .state_medicaid_core import (
    build_postgres_supplemental_registry,
    load_state_medicaid_preflight,
    load_state_medicaid_registry,
)


MAX_SOURCE_BYTES = 50 * 1024 * 1024
MAX_SOURCE_REDIRECTS = 5
INFERENCE_LEASE_SECONDS = 900
INFERENCE_HEARTBEAT_SECONDS = 30
SOURCE_FETCH_LEASE_SECONDS = 300
SOURCE_FETCH_HEARTBEAT_SECONDS = 60
SOURCE_FETCH_RETRY_DELAY_SECONDS = 30
SECTION_EXTRACTION_PIPELINE_VERSION = "section-extraction-v1"
SECTION_EXTRACTION_LEASE_SECONDS = 300
SECTION_EXTRACTION_HEARTBEAT_SECONDS = 60
SECTION_EXTRACTION_RETRY_DELAY_SECONDS = 30
OCR_INGEST_PIPELINE_VERSION = "ocr-artifact-v1"
_RELEASE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ECFR_CURRENT_PATH_PATTERN = re.compile(r"^/current/title-(\d+)(?:/(.*))?$")
_ECFR_HIERARCHY_KEYS = {
    "appendix",
    "chapter",
    "part",
    "section",
    "subchapter",
    "subpart",
    "subtitle",
}
_ECFR_TITLES_API_URL = "https://www.ecfr.gov/api/versioner/v1/titles.json"


def _validated_release_id(release_id: str) -> str:
    if not _RELEASE_ID_PATTERN.fullmatch(release_id):
        raise ValueError("release ID must be a simple 1-128 character identifier")
    return release_id


def _validated_official_source_url(value: str) -> str:
    parsed = urlparse(value)
    host = (parsed.hostname or "").lower()
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("official source URL has an invalid port") from exc
    if parsed.scheme != "https":
        raise ValueError("official source URL must use https")
    if not host.endswith(".gov"):
        raise ValueError("official source URL must use a .gov host")
    if parsed.username or parsed.password:
        raise ValueError("official source URL must not include user information")
    if port not in {None, 443}:
        raise ValueError("official source URL must use the default HTTPS port")
    return value


def _resolve_ecfr_snapshot_date(client: httpx.Client) -> str:
    response = client.get(_ECFR_TITLES_API_URL)
    response.raise_for_status()
    try:
        payload = response.json()
    except ValueError as exc:
        raise ValueError("eCFR titles API returned malformed JSON") from exc
    titles = payload.get("titles") if isinstance(payload, dict) else None
    if not isinstance(titles, list) or not titles:
        raise ValueError("eCFR titles API returned no title metadata")
    dates = {
        str(item.get("up_to_date_as_of", "")).strip()
        for item in titles
        if isinstance(item, dict)
        and item.get("reserved") is not True
        and str(item.get("up_to_date_as_of", "")).strip()
    }
    if len(dates) != 1:
        raise ValueError("eCFR titles API returned inconsistent snapshot dates")
    snapshot_date = dates.pop()
    try:
        datetime.strptime(snapshot_date, "%Y-%m-%d")
    except ValueError as exc:
        raise ValueError("eCFR titles API returned an invalid snapshot date") from exc
    return snapshot_date


def _ecfr_api_url(source_url: str, snapshot_date: str) -> str:
    parsed = urlparse(source_url)
    host = (parsed.hostname or "").lower().removeprefix("www.")
    if host != "ecfr.gov":
        return source_url
    match = _ECFR_CURRENT_PATH_PATTERN.fullmatch(parsed.path.rstrip("/"))
    if match is None:
        raise ValueError("eCFR sources must use a current title hierarchy URL")
    try:
        datetime.strptime(snapshot_date, "%Y-%m-%d")
    except ValueError as exc:
        raise ValueError("eCFR snapshot date must use YYYY-MM-DD") from exc
    title, hierarchy_path = match.groups()
    query: list[tuple[str, str]] = []
    if hierarchy_path:
        for segment in hierarchy_path.split("/"):
            key, separator, value = segment.partition("-")
            if not separator or key not in _ECFR_HIERARCHY_KEYS or not value:
                raise ValueError("unsupported eCFR hierarchy path")
            query.append((key, value))
    suffix = f"?{urlencode(query)}" if query else ""
    return (
        "https://www.ecfr.gov/api/versioner/v1/full/"
        f"{snapshot_date}/title-{title}.xml{suffix}"
    )


def _reject_access_challenge(
    final_url: str, headers: dict[str, str], raw_bytes: bytes
) -> None:
    host = (urlparse(final_url).hostname or "").lower()
    waf_action = headers.get("x-amzn-waf-action", "").strip().lower()
    if host == "unblock.federalregister.gov" or waf_action == "challenge":
        raise ValueError("official source returned an access challenge")
    mime_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if mime_type in {"text/html", "application/xhtml+xml"}:
        sample = raw_bytes[:65536].decode("utf-8", errors="ignore").lower()
        if "aggressive automated scraping" in sample and "captcha" in sample:
            raise ValueError("official source returned an access challenge")


def _fetch_official_source(
    client: httpx.Client,
    source_url: str,
    *,
    ecfr_snapshot_date: str | None = None,
) -> dict[str, Any]:
    requested_url = _validated_official_source_url(source_url)
    parsed = urlparse(requested_url)
    is_ecfr = (parsed.hostname or "").lower().removeprefix("www.") == "ecfr.gov"
    if is_ecfr:
        current_url = _validated_official_source_url(
            _ecfr_api_url(
                requested_url,
                ecfr_snapshot_date or _resolve_ecfr_snapshot_date(client),
            )
        )
        resolution_chain = [current_url]
    else:
        current_url = requested_url
        resolution_chain = []
    redirect_chain: list[str] = []
    for redirect_count in range(MAX_SOURCE_REDIRECTS + 1):
        with client.stream("GET", current_url) as response:
            if response.status_code in {301, 302, 303, 307, 308}:
                location = response.headers.get("location")
                if not location:
                    raise ValueError("source redirect is missing a location")
                if redirect_count >= MAX_SOURCE_REDIRECTS:
                    raise ValueError("source exceeded the redirect limit")
                current_url = _validated_official_source_url(
                    urljoin(str(response.url), location)
                )
                redirect_chain.append(current_url)
                continue
            response.raise_for_status()
            content_length = response.headers.get("content-length")
            if content_length:
                try:
                    declared_size = int(content_length)
                except ValueError as exc:
                    raise ValueError("source returned an invalid content-length") from exc
                if declared_size < 0 or declared_size > MAX_SOURCE_BYTES:
                    raise ValueError("source response is empty or exceeds 50 MiB")
            raw = bytearray()
            for chunk in response.iter_bytes():
                raw.extend(chunk)
                if len(raw) > MAX_SOURCE_BYTES:
                    raise ValueError("source response is empty or exceeds 50 MiB")
            if not raw:
                raise ValueError("source response is empty or exceeds 50 MiB")
            final_url = _validated_official_source_url(str(response.url))
            response_headers = {
                key.lower(): value for key, value in response.headers.items()
            }
            raw_bytes = bytes(raw)
            _reject_access_challenge(final_url, response_headers, raw_bytes)
            return {
                "content": raw_bytes,
                "final_url": final_url,
                "status_code": response.status_code,
                "headers": response_headers,
                "redirect_chain": redirect_chain,
                "resolution_chain": resolution_chain,
            }
    raise AssertionError("source redirect loop exhausted")


def _write_report(workdir: Path, name: str, payload: dict[str, Any]) -> Path:
    path = workdir / "reports" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def migrate_corpus(workdir: Path, store: PostgresCorpusStore) -> dict[str, Any]:
    applied = store.migrate(workdir / "migrations")
    return {"database": "postgresql", "migrations": applied, "status": "ok"}


def _run_source_fetch_job(
    store: PostgresCorpusStore,
    client: httpx.Client,
    worker_id: str,
    job: dict[str, Any],
    ecfr_snapshot_date: str | None = None,
) -> dict[str, Any]:
    heartbeat_stop = Event()
    heartbeat_failure: list[str] = []

    def renew_lease() -> None:
        while not heartbeat_stop.wait(SOURCE_FETCH_HEARTBEAT_SECONDS):
            try:
                store.renew_source_fetch_lease(
                    job["fetch_job_id"],
                    worker_id=worker_id,
                    lease_seconds=SOURCE_FETCH_LEASE_SECONDS,
                )
            except (CorpusDatabaseError, ValueError) as exc:
                heartbeat_failure.append(str(exc))
                return

    heartbeat = Thread(
        target=renew_lease,
        name=f"source-fetch-lease-{job['fetch_job_id']}",
        daemon=True,
    )
    heartbeat.start()
    try:
        fetched_source = _fetch_official_source(
            client,
            job["canonical_url"],
            ecfr_snapshot_date=ecfr_snapshot_date,
        )
        if heartbeat_failure:
            raise CorpusDatabaseError(heartbeat_failure[0])
        response_headers = fetched_source["headers"]
        payload_source = {
            **job,
            "canonical_url": fetched_source["final_url"],
        }
        snapshot = build_source_snapshot(
            payload_source,
            fetched_source["content"],
            retrieved_at=datetime.now(timezone.utc).isoformat(),
            mime_type=response_headers.get(
                "content-type", "application/octet-stream"
            ),
            http_status=fetched_source["status_code"],
            effective_metadata={
                "etag": response_headers.get("etag"),
                "last_modified": response_headers.get("last-modified"),
                "redirect_chain": fetched_source["redirect_chain"],
                "source_resolution": fetched_source["resolution_chain"],
            },
        )
        safe_headers = {
            key.lower(): value
            for key, value in response_headers.items()
            if key.lower()
            in {
                "content-type",
                "content-length",
                "etag",
                "last-modified",
                "date",
            }
        }
        heartbeat_stop.set()
        heartbeat.join()
        if heartbeat_failure:
            raise CorpusDatabaseError(heartbeat_failure[0])
        retrieval_id = store.complete_source_fetch_job(
            job["fetch_job_id"],
            worker_id=worker_id,
            snapshot=snapshot,
            response_headers=safe_headers,
        )
        return {
            "fetch_job_id": job["fetch_job_id"],
            "source_id": job["source_id"],
            "status": "completed",
            "attempt": int(job["attempts"]),
            "snapshot_hash": snapshot["snapshot_hash"],
            "retrieval_id": retrieval_id,
        }
    except (CorpusDatabaseError, httpx.HTTPError, KeyError, TypeError, ValueError) as exc:
        heartbeat_stop.set()
        heartbeat.join()
        failure_record_error = None
        try:
            status = store.fail_source_fetch_job(
                job["fetch_job_id"],
                worker_id=worker_id,
                error=str(exc),
                retry_delay_seconds=SOURCE_FETCH_RETRY_DELAY_SECONDS,
            )
        except (CorpusDatabaseError, ValueError) as record_exc:
            status = "lease_lost"
            failure_record_error = str(record_exc)
        return {
            "fetch_job_id": job["fetch_job_id"],
            "source_id": job["source_id"],
            "status": status,
            "attempt": int(job["attempts"]),
            "error": str(exc),
            "failure_record_error": failure_record_error,
        }


def sources_sync(
    workdir: Path,
    store: PostgresCorpusStore,
    *,
    fetch: bool,
    limit: int,
    timeout_seconds: float,
    source_registry: Path | None = None,
    concurrency: int = 4,
    capture_id: str | None = None,
    retry_failed: bool = False,
    retry_limit: int = 0,
) -> dict[str, Any]:
    if limit < 0:
        raise ValueError("source fetch limit cannot be negative")
    if timeout_seconds <= 0:
        raise ValueError("source fetch timeout must be positive")
    if concurrency <= 0 or concurrency > 16:
        raise ValueError("source fetch concurrency must be between 1 and 16")
    if retry_limit < 0:
        raise ValueError("source fetch retry limit cannot be negative")
    if retry_failed and retry_limit <= 0:
        raise ValueError("source fetch --retry-failed requires a positive --retry-limit")
    if retry_limit > 0 and not retry_failed:
        raise ValueError("source fetch --retry-limit requires --retry-failed")
    if not fetch and (capture_id is not None or retry_failed):
        raise ValueError("source capture and retry options require --fetch")
    registry = load_source_registry(workdir, source_registry)
    selected_capture_id = (
        _validated_release_id(capture_id or f"{registry['registry_id']}-bootstrap")
        if fetch
        else None
    )
    synced = store.sync_registry(registry)
    baseline = store.import_blocked_baseline(workdir)
    results: list[dict[str, Any]] = []
    batch: dict[str, Any] | None = None
    retried_failed_jobs = 0
    ecfr_snapshot_date: str | None = None
    if fetch:
        batch = store.enqueue_source_fetch_batch(
            registry_version=registry["registry_id"],
            registry_manifest_sha256=registry["registry_manifest_sha256"],
            capture_id=str(selected_capture_id),
            limit=limit,
        )
        retried_failed_jobs = (
            store.retry_failed_source_fetch_jobs(
                batch["batch_id"], limit=retry_limit
            )
            if retry_failed
            else 0
        )
        client = httpx.Client(
            timeout=timeout_seconds,
            follow_redirects=False,
            headers={
                "accept-encoding": "identity",
                "user-agent": "localBCE-grounded-rules/1.0 (+source-snapshot)",
            },
        )
        try:
            if any(
                (urlparse(source["canonical_url"]).hostname or "")
                .lower()
                .removeprefix("www.")
                == "ecfr.gov"
                for source in registry["sources"]
            ):
                ecfr_snapshot_date = _resolve_ecfr_snapshot_date(client)
            worker_id = f"{socket.gethostname()}-{os_getpid()}-source-fetch"
            maximum = limit if limit > 0 else int(batch["job_count"])
            processed = 0
            while processed < maximum:
                jobs = store.claim_source_fetch_jobs(
                    batch["batch_id"],
                    worker_id=worker_id,
                    limit=min(concurrency, maximum - processed),
                    lease_seconds=SOURCE_FETCH_LEASE_SECONDS,
                )
                if not jobs:
                    break
                with ThreadPoolExecutor(max_workers=concurrency) as executor:
                    futures = [
                        executor.submit(
                            _run_source_fetch_job,
                            store,
                            client,
                            worker_id,
                            job,
                            ecfr_snapshot_date,
                        )
                        for job in jobs
                    ]
                    results.extend(
                        future.result() for future in as_completed(futures)
                    )
                processed += len(jobs)
        finally:
            client.close()
        batch = store.source_fetch_batch_summary(batch["batch_id"])
    failures = [item for item in results if item["status"] != "completed"]
    report = {
        "schema_version": "localbce-sources-sync-report-v1",
        "registry_id": registry["registry_id"],
        "registered_sources": synced,
        "covered_programs": len(registry["program_quotas"]),
        "target_candidates": registry["target_unique_grounded_candidates"],
        "baseline_candidates_imported": baseline,
        "capture_id": (
            batch["configuration"]["capture_id"] if batch is not None else None
        ),
        "source_fetch_batch": batch,
        "source_fetch_concurrency": concurrency if fetch else 0,
        "ecfr_snapshot_date": ecfr_snapshot_date,
        "retried_failed_jobs": retried_failed_jobs,
        "snapshots_fetched": sum(
            item["status"] == "completed" for item in results
        ),
        "fetch_results": sorted(results, key=lambda item: item["fetch_job_id"]),
        "failures": failures,
        "fetch_enabled": fetch,
        "runtime_activation": False,
        "proof_binding": False,
    }
    report["report"] = str(_write_report(workdir, "rules_sources_sync_v1.json", report))
    return report


def _run_section_extraction_job(
    store: PostgresCorpusStore,
    worker_id: str,
    job: dict[str, Any],
) -> dict[str, Any]:
    heartbeat_stop = Event()
    heartbeat_failure: list[str] = []

    def renew_lease() -> None:
        while not heartbeat_stop.wait(SECTION_EXTRACTION_HEARTBEAT_SECONDS):
            try:
                store.renew_section_extraction_lease(
                    job["extraction_job_id"],
                    worker_id=worker_id,
                    lease_seconds=SECTION_EXTRACTION_LEASE_SECONDS,
                )
            except (CorpusDatabaseError, ValueError) as exc:
                heartbeat_failure.append(str(exc))
                return

    heartbeat = Thread(
        target=renew_lease,
        name=f"section-extraction-lease-{job['extraction_job_id']}",
        daemon=True,
    )
    heartbeat.start()
    try:
        raw = restore_snapshot_bytes(job)
        extracted = extract_source_text(
            raw,
            mime_type=job["mime_type"],
            source_url=job["canonical_url"],
        )
        if extracted.blocks:
            sections = segment_structured_blocks(
                job["snapshot_hash"],
                (
                    {
                        "text": block.text,
                        "hierarchy_path": block.hierarchy_path,
                        "heading": block.heading,
                        "block_kind": block.block_kind,
                        "source_locator": block.source_locator,
                    }
                    for block in extracted.blocks
                ),
                parser_name=extracted.parser_name,
                parser_version=extracted.parser_version,
                extraction_pipeline_version=job["pipeline_version"],
                ocr_used=extracted.text_layer_kind == "ocr",
            )
        else:
            sections = segment_text(
                job["snapshot_hash"],
                extracted.text,
                parser_name=extracted.parser_name,
                parser_version=extracted.parser_version,
                extraction_pipeline_version=job["pipeline_version"],
                ocr_used=extracted.text_layer_kind == "ocr",
            )
        heartbeat_stop.set()
        heartbeat.join()
        if heartbeat_failure:
            raise CorpusDatabaseError(heartbeat_failure[0])
        section_count = store.complete_section_extraction_job(
            job["extraction_job_id"],
            worker_id=worker_id,
            sections=sections,
            warnings=list(extracted.warnings),
        )
        return {
            "extraction_job_id": job["extraction_job_id"],
            "retrieval_id": job["retrieval_id"],
            "status": "completed",
            "attempt": int(job["attempts"]),
            "section_count": section_count,
            "parser_name": extracted.parser_name,
            "parser_version": extracted.parser_version,
            "warnings": list(extracted.warnings),
        }
    except (CorpusDatabaseError, KeyError, RuntimeError, TypeError, ValueError) as exc:
        heartbeat_stop.set()
        heartbeat.join()
        failure_record_error = None
        try:
            status = store.fail_section_extraction_job(
                job["extraction_job_id"],
                worker_id=worker_id,
                error=str(exc),
                retry_delay_seconds=SECTION_EXTRACTION_RETRY_DELAY_SECONDS,
            )
        except (CorpusDatabaseError, ValueError) as record_exc:
            status = "lease_lost"
            failure_record_error = str(record_exc)
        return {
            "extraction_job_id": job["extraction_job_id"],
            "retrieval_id": job["retrieval_id"],
            "status": status,
            "attempt": int(job["attempts"]),
            "error": str(exc),
            "failure_record_error": failure_record_error,
        }


def sections_extract(
    workdir: Path,
    store: PostgresCorpusStore,
    *,
    limit: int,
    concurrency: int = 4,
    retry_failed: bool = False,
    retry_limit: int = 0,
) -> dict[str, Any]:
    if limit < 0:
        raise ValueError("section extraction limit cannot be negative")
    if concurrency <= 0 or concurrency > 16:
        raise ValueError("section extraction concurrency must be between 1 and 16")
    if retry_limit < 0:
        raise ValueError("section extraction retry limit cannot be negative")
    if retry_failed and retry_limit <= 0:
        raise ValueError(
            "section extraction --retry-failed requires a positive --retry-limit"
        )
    if retry_limit > 0 and not retry_failed:
        raise ValueError("section extraction --retry-limit requires --retry-failed")
    queued = store.enqueue_section_extraction_jobs(
        pipeline_version=SECTION_EXTRACTION_PIPELINE_VERSION,
        limit=limit,
    )
    retried_failed_jobs = (
        store.retry_failed_section_extraction_jobs(
            pipeline_version=SECTION_EXTRACTION_PIPELINE_VERSION,
            limit=retry_limit,
        )
        if retry_failed
        else 0
    )
    worker_id = f"{socket.gethostname()}-{os_getpid()}-section-extraction"
    maximum = limit if limit > 0 else int(queued["job_count"])
    processed = 0
    results: list[dict[str, Any]] = []
    while processed < maximum:
        jobs = store.claim_section_extraction_jobs(
            pipeline_version=SECTION_EXTRACTION_PIPELINE_VERSION,
            worker_id=worker_id,
            limit=min(concurrency, maximum - processed),
            lease_seconds=SECTION_EXTRACTION_LEASE_SECONDS,
        )
        if not jobs:
            break
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = [
                executor.submit(
                    _run_section_extraction_job,
                    store,
                    worker_id,
                    job,
                )
                for job in jobs
            ]
            results.extend(future.result() for future in as_completed(futures))
        processed += len(jobs)
    summary = store.section_extraction_summary(
        SECTION_EXTRACTION_PIPELINE_VERSION
    )
    warnings = [
        {
            "retrieval_id": item["retrieval_id"],
            "warnings": item["warnings"],
        }
        for item in results
        if item.get("warnings")
    ]
    failures = [item for item in results if item["status"] != "completed"]
    report = {
        "schema_version": "localbce-sections-extract-report-v1",
        "pipeline_version": SECTION_EXTRACTION_PIPELINE_VERSION,
        "concurrency": concurrency,
        "jobs_inserted": queued["jobs_inserted"],
        "retried_failed_jobs": retried_failed_jobs,
        "retrievals_processed": sum(
            item["status"] == "completed" for item in results
        ),
        "sections_created": sum(
            int(item.get("section_count", 0)) for item in results
        ),
        "results": sorted(results, key=lambda item: item["extraction_job_id"]),
        "queue_summary": summary,
        "warnings": warnings,
        "failures": failures,
        "runtime_activation": False,
        "proof_binding": False,
    }
    report["report"] = str(_write_report(workdir, "rules_sections_extract_v1.json", report))
    return report


def ocr_artifact_ingest(
    workdir: Path,
    store: PostgresCorpusStore,
    *,
    retrieval_id: str,
    artifact_path: Path,
    evidence_root: Path,
    engine_name: str,
    engine_version: str,
    operator_id: str,
    generated_at: str,
) -> dict[str, Any]:
    root = evidence_root if evidence_root.is_absolute() else workdir / evidence_root
    root = root.resolve()
    selected = artifact_path if artifact_path.is_absolute() else workdir / artifact_path
    selected = selected.resolve()
    try:
        relative_path = selected.relative_to(root)
    except ValueError as exc:
        raise ValueError("OCR artifact must be beneath the configured evidence root") from exc
    if not selected.is_file():
        raise FileNotFoundError(f"OCR artifact does not exist: {selected}")
    artifact_bytes = selected.read_bytes()
    if len(artifact_bytes) > MAX_SOURCE_BYTES:
        raise ValueError("OCR artifact exceeds the 50 MiB source limit")

    target = store.ocr_ingest_target(retrieval_id)
    artifact = build_ocr_artifact(
        retrieval_id=retrieval_id,
        snapshot_hash=target["snapshot_hash"],
        artifact_bytes=artifact_bytes,
        engine_name=engine_name,
        engine_version=engine_version,
        operator_id=operator_id,
        generated_at=generated_at,
        metadata={
            "artifact_relative_path": relative_path.as_posix(),
            "source_kind": "reviewed_ocr_text",
        },
    )
    sections = segment_text(
        target["snapshot_hash"],
        artifact["normalized_text"],
        parser_name=f"ocr:{artifact['engine_name']}",
        parser_version=artifact["engine_version"],
        extraction_pipeline_version=(
            f"{OCR_INGEST_PIPELINE_VERSION}:{artifact['artifact_hash']}"
        ),
        ocr_used=True,
        source_locator={
            "kind": "ocr_artifact_text",
            "ocr_artifact_id": artifact["ocr_artifact_id"],
            "ocr_artifact_hash": artifact["artifact_hash"],
            "engine_name": artifact["engine_name"],
            "engine_version": artifact["engine_version"],
        },
    )
    stored = store.save_ocr_artifact(artifact, sections)
    report = {
        "schema_version": "localbce-ocr-artifact-ingest-report-v1",
        **stored,
        "canonical_url": target["canonical_url"],
        "program": target["program"],
        "artifact_relative_path": relative_path.as_posix(),
        "official_snapshot_preserved": True,
        "ocr_text_is_official_source_bytes": False,
        "human_review_required": True,
        "runtime_activation": False,
        "proof_binding": False,
    }
    report["report"] = str(
        _write_report(
            workdir,
            f"rules_ocr_artifact_{artifact['ocr_artifact_id']}.json",
            report,
        )
    )
    return report


def sources_discover(
    workdir: Path, store: PostgresCorpusStore, *, limit: int
) -> dict[str, Any]:
    retrievals = store.undiscovered_retrievals(
        parser_version=SOURCE_DISCOVERY_PARSER_VERSION,
        limit=limit,
    )
    runs: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    program_counts: dict[str, int] = {}
    for retrieval in retrievals:
        try:
            raw = restore_snapshot_bytes(retrieval)
            discovered = discover_official_links(
                raw,
                mime_type=retrieval["mime_type"],
                source_url=retrieval["canonical_url"],
            )
            links = [
                {
                    "canonical_url": link.canonical_url,
                    "link_text": link.link_text,
                    "source_locator": link.source_locator,
                }
                for link in discovered
            ]
            run = store.save_source_discovery(
                retrieval=retrieval,
                parser_version=SOURCE_DISCOVERY_PARSER_VERSION,
                links=links,
            )
            runs.append(run)
            program = str(retrieval["program"])
            program_counts[program] = program_counts.get(program, 0) + len(links)
        except (CorpusDatabaseError, RuntimeError, ValueError) as exc:
            failures.append(
                {"retrieval_id": retrieval["retrieval_id"], "error": str(exc)}
            )
    report = {
        "schema_version": "localbce-source-expansion-report-v1",
        "parser_version": SOURCE_DISCOVERY_PARSER_VERSION,
        "retrievals_processed": len(runs),
        "candidate_links": sum(run["candidate_count"] for run in runs),
        "candidates_inserted": sum(run["candidates_inserted"] for run in runs),
        "program_candidate_counts": dict(sorted(program_counts.items())),
        "failures": failures,
        "promotion_mode": "review_only_no_automatic_registry_activation",
        "runtime_activation": False,
        "proof_binding": False,
    }
    report["report"] = str(
        _write_report(workdir, "rules_source_expansion_v1.json", report)
    )
    return report


def sources_preflight(
    workdir: Path,
    store: PostgresCorpusStore,
    *,
    limit: int,
    target_count: int,
) -> dict[str, Any]:
    report = store.preflight_source_registry_candidates(
        limit=limit,
        target_count=target_count,
    )
    report["report"] = str(
        _write_report(workdir, "rules_source_candidate_preflight_v1.json", report)
    )
    return report


def validate_source_preflight_artifact(
    *,
    report_path: Path,
) -> dict[str, Any]:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if not isinstance(report, dict):
        raise ValueError("source candidate preflight report must be an object")
    errors = validate_source_candidate_preflight_report(report)
    if errors:
        raise ValueError("; ".join(errors))
    return {
        "schema_version": "localbce-source-candidate-preflight-validation-v1",
        "preflight_version": report["preflight_version"],
        "report": str(report_path),
        "eligible_for_human_review_count": report[
            "eligible_for_human_review_count"
        ],
        "capacity_blocker_review_candidate_count": report[
            "capacity_blocker_review_candidate_count"
        ],
        "capacity_blocker_review_candidates_sha256": report[
            "capacity_blocker_review_candidates_sha256"
        ],
        "human_review_required": True,
        "runtime_activation": False,
        "proof_binding": False,
        "status": "ok",
    }


def source_registry_release(
    workdir: Path,
    store: PostgresCorpusStore,
    *,
    release_id: str,
) -> dict[str, Any]:
    release_id = _validated_release_id(release_id)
    release = build_source_registry_release(
        release_id=release_id,
        base_registry=load_source_registry(workdir),
        approved_candidates=store.approved_source_registry_candidates(),
    )
    release["report"] = str(
        _write_report(
            workdir,
            f"source_registry_release_{release_id}.json",
            release,
        )
    )
    return release


def _run_job(store: PostgresCorpusStore, client: ClaudeGroundedClient, worker_id: str, job: dict[str, Any]) -> dict[str, Any]:
    request = job["request_payload"]
    section = store.section(request["section"]["section_id"])
    proposed = request.get("proposed_candidates")
    heartbeat_stop = Event()
    heartbeat_failure: list[str] = []
    usage = None

    def renew_lease() -> None:
        while not heartbeat_stop.wait(INFERENCE_HEARTBEAT_SECONDS):
            try:
                store.renew_inference_lease(
                    job["inference_job_id"],
                    worker_id=worker_id,
                    lease_seconds=INFERENCE_LEASE_SECONDS,
                )
            except (RuntimeError, ValueError) as exc:
                heartbeat_failure.append(str(exc))
                return

    heartbeat = Thread(
        target=renew_lease,
        name=f"inference-lease-{job['inference_job_id']}",
        daemon=True,
    )
    heartbeat.start()
    try:
        response, usage = client.infer(
            section,
            request["program"],
            pass_number=int(request["pass"]),
            proposed_candidates=proposed,
        )
        if heartbeat_failure:
            raise CorpusDatabaseError(heartbeat_failure[0])
        heartbeat_stop.set()
        heartbeat.join()
        if heartbeat_failure:
            raise CorpusDatabaseError(heartbeat_failure[0])
        affected = store.commit_inference_result(
            job["inference_job_id"],
            worker_id=worker_id,
            response_payload=response,
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            usage_metadata={"model": usage.model, "request_id": usage.request_id},
        )
        return {
            "job_id": job["inference_job_id"],
            "pass": request["pass"],
            "affected": affected,
            "status": "completed",
            "input_tokens": usage.input_tokens,
            "output_tokens": usage.output_tokens,
            "model": usage.model,
            "request_id": usage.request_id,
            "attempt": int(job["attempts"]),
        }
    except (ClaudeInferenceError, CorpusDatabaseError, KeyError, TypeError, ValueError) as exc:
        heartbeat_stop.set()
        heartbeat.join()
        if usage is None and isinstance(exc, ClaudeInferenceError):
            usage = exc.usage
        input_tokens = int(usage.input_tokens) if usage is not None else 0
        output_tokens = int(usage.output_tokens) if usage is not None else 0
        usage_metadata = (
            {"model": usage.model, "request_id": usage.request_id}
            if usage is not None
            else {}
        )
        retry = (
            isinstance(exc, ClaudeInferenceError)
            and exc.retryable
            and int(job["attempts"]) < int(job.get("attempt_limit", 5))
        )
        rejected = (
            isinstance(exc, ClaudeInferenceError)
            and exc.response_rejected
            and not retry
        )
        failure_record_error = None
        try:
            store.fail_inference_job(
                job["inference_job_id"],
                worker_id=worker_id,
                error=str(exc),
                retry=retry,
                rejected=rejected,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                usage_metadata=usage_metadata,
            )
        except CorpusDatabaseError as record_exc:
            failure_record_error = str(record_exc)
        return {
            "job_id": job["inference_job_id"],
            "pass": request["pass"],
            "status": "rejected" if rejected else "failed",
            "error": str(exc),
            "failure_record_error": failure_record_error,
            "retry_scheduled": retry,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "model": usage.model if usage is not None else None,
            "request_id": usage.request_id if usage is not None else None,
            "attempt": int(job["attempts"]),
        }
    finally:
        heartbeat_stop.set()
        if heartbeat.is_alive():
            heartbeat.join()


def _claude_infer_locked(
    workdir: Path,
    store: PostgresCorpusStore,
    *,
    limit: int,
    concurrency: int = 8,
    batch_size: int = 256,
    result_detail_limit: int = 1_000,
    retry_failed: bool = False,
    retry_limit: int = 0,
    drain_existing: bool = False,
    timeout_seconds: float = 300.0,
) -> dict[str, Any]:
    if limit <= 0:
        raise ValueError("claude inference limit must be positive")
    if concurrency <= 0 or concurrency > 32:
        raise ValueError("claude concurrency must be between 1 and 32")
    if batch_size <= 0 or batch_size > 10_000:
        raise ValueError("claude inference batch size must be between 1 and 10000")
    if result_detail_limit < 0 or result_detail_limit > 10_000:
        raise ValueError(
            "claude inference result detail limit must be between 0 and 10000"
        )
    if retry_limit < 0:
        raise ValueError("failed inference retry limit cannot be negative")
    if retry_failed and retry_limit <= 0:
        raise ValueError("--retry-failed requires a positive --retry-limit")
    if retry_limit > 0 and not retry_failed:
        raise ValueError("--retry-limit requires --retry-failed")
    if timeout_seconds <= 0 or timeout_seconds > 900:
        raise ValueError("Claude timeout must be between 0 and 900 seconds")
    retried_failed_jobs = (
        store.retry_failed_inference_jobs(limit=retry_limit)
        if retry_failed
        else 0
    )
    relevance_assessed = 0
    relevance_skipped = 0
    extraction_enqueued = 0
    sections_considered = 0
    if not drain_existing:
        while sections_considered < limit:
            sections = store.uninferred_sections(
                limit=min(batch_size, limit - sections_considered)
            )
            if not sections:
                break
            for section in sections:
                if section.get("relevance_decision_id"):
                    relevant = section.get("relevant") is True
                else:
                    decision = assess_section_relevance(section)
                    store.save_relevance_decision(decision)
                    relevance_assessed += 1
                    relevant = decision["relevant"]
                if not relevant:
                    relevance_skipped += 1
                    continue
                store.enqueue_inference(
                    build_inference_request(
                        section, section["program"], pass_number=1
                    )
                )
                extraction_enqueued += 1
            sections_considered += len(sections)
    client = ClaudeGroundedClient(timeout_seconds=timeout_seconds)
    worker_id = f"{socket.gethostname()}-{os_getpid()}"
    results: list[dict[str, Any]] = []
    failure_details: list[dict[str, Any]] = []
    result_count = 0
    completed_count = 0
    failed_count = 0
    rejected_count = 0
    input_tokens = 0
    output_tokens = 0
    attempts = 0
    claimed_job_attempts = 0

    def record_result(result: dict[str, Any]) -> None:
        nonlocal result_count, completed_count, failed_count, rejected_count
        nonlocal input_tokens, output_tokens, attempts
        result_count += 1
        completed_count += result["status"] == "completed"
        failed_count += result["status"] == "failed"
        rejected_count += result["status"] == "rejected"
        input_tokens += int(result.get("input_tokens", 0))
        output_tokens += int(result.get("output_tokens", 0))
        attempts += int(result.get("attempt", 0))
        if len(results) < result_detail_limit:
            results.append(result)
        if result["status"] == "failed" and len(failure_details) < min(
            result_detail_limit, 100
        ):
            failure_details.append(result)

    def drain(maximum: int) -> int:
        nonlocal claimed_job_attempts
        processed = 0
        claimed = 0
        queue_exhausted = False
        in_flight: dict[Any, str] = {}
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            while processed < maximum:
                claim_size = min(
                    concurrency - len(in_flight),
                    maximum - claimed,
                )
                if claim_size > 0 and not queue_exhausted:
                    jobs = store.claim_inference_jobs(
                        worker_id,
                        limit=claim_size,
                        lease_seconds=INFERENCE_LEASE_SECONDS,
                    )
                    if jobs:
                        claimed_job_attempts += len(jobs)
                        claimed += len(jobs)
                        for job in jobs:
                            future = executor.submit(
                                _run_job, store, client, worker_id, job
                            )
                            in_flight[future] = job["inference_job_id"]
                    else:
                        queue_exhausted = True

                if not in_flight:
                    break

                completed_futures, _ = wait(
                    tuple(in_flight), return_when=FIRST_COMPLETED
                )
                for future in completed_futures:
                    in_flight.pop(future)
                    record_result(future.result())
                    processed += 1
        return processed

    critique_enqueued = 0
    # In drain mode, --limit is an exact attempt budget. Outside drain mode,
    # each selected section may produce one extraction and one critique job.
    remaining_job_budget = limit if drain_existing else 2 * limit
    while remaining_job_budget > 0:
        processed = drain(min(batch_size, remaining_job_budget))
        remaining_job_budget -= processed
        # Enqueueing a critique does not consume a paid inference attempt. In
        # drain mode, keep the exact attempt budget while still making newly
        # completed extraction work visible to the critique-first scheduler.
        critique_capacity = (
            batch_size
            if drain_existing
            else min(batch_size, remaining_job_budget)
        )
        critique_sections = (
            store.pending_critique_sections(limit=critique_capacity)
            if critique_capacity > 0
            else []
        )
        for section in critique_sections:
            store.enqueue_inference(
                build_inference_request(
                    section,
                    section["program"],
                    pass_number=2,
                    proposed_candidates=section["proposed_candidates"],
                )
            )
            critique_enqueued += 1
        if processed == 0 and not critique_sections:
            break
    review_materialization = {
        "candidates_processed": 0,
        "drafts_created": 0,
        "drafts_blocked": 0,
        "policy_tasks_created": 0,
        "clusters_created": 0,
    }
    while True:
        materialized = store.materialize_review_drafts(limit=batch_size)
        for key in review_materialization:
            review_materialization[key] += int(materialized.get(key, 0))
        if int(materialized.get("candidates_processed", 0)) == 0:
            break
    queue_summary = store.inference_queue_summary()
    report = {
        "schema_version": "localbce-claude-inference-run-v1",
        "model": client.model,
        "concurrency": concurrency,
        "batch_size": batch_size,
        "drain_existing": drain_existing,
        "timeout_seconds": timeout_seconds,
        "section_limit": limit,
        "sections_considered": sections_considered,
        "relevance_assessed": relevance_assessed,
        "relevance_skipped": relevance_skipped,
        "extraction_enqueued": extraction_enqueued,
        "critique_enqueued": critique_enqueued,
        "retried_failed_jobs": retried_failed_jobs,
        "claimed_job_attempts": claimed_job_attempts,
        "results": sorted(results, key=lambda item: item["job_id"]),
        "result_count": result_count,
        "result_detail_limit": result_detail_limit,
        "result_details_truncated": max(0, result_count - len(results)),
        "failure_details": sorted(
            failure_details, key=lambda item: item["job_id"]
        ),
        "failure_details_truncated": max(0, failed_count - len(failure_details)),
        "completed": completed_count,
        "failed": failed_count,
        "rejected": rejected_count,
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "request_count": completed_count + rejected_count,
            "failed_request_count": failed_count,
            "rejected_request_count": rejected_count,
            "attempts": attempts,
        },
        "queue_summary": queue_summary,
        "review_materialization": review_materialization,
        "runtime_activation": False,
        "proof_binding": False,
    }
    report["report"] = str(
        _write_report(workdir, "rules_claude_inference_v1.json", report)
    )
    return report


def state_medicaid_sources_sync(
    workdir: Path,
    store: PostgresCorpusStore,
    *,
    registry_path: Path,
    preflight_path: Path,
) -> dict[str, Any]:
    registry, registry_validation = load_state_medicaid_registry(registry_path)
    preflight, preflight_validation = load_state_medicaid_preflight(
        preflight_path, registry
    )
    supplemental = build_postgres_supplemental_registry(registry, preflight)
    before = store.rules_metrics()["table_counts"]
    synced = store.sync_supplemental_registry(supplemental)
    after = store.rules_metrics()["table_counts"]
    protected_tables = (
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
    )
    changed_protected_tables = {
        table: {"before": before[table], "after": after[table]}
        for table in protected_tables
        if before[table] != after[table]
    }
    if changed_protected_tables:
        raise CorpusDatabaseError(
            f"Medicaid source-only sync changed protected tables: {changed_protected_tables}"
        )
    database = store.supplemental_registry_summary(registry["registry_id"])
    if database["source_count"] != registry_validation["source_count"]:
        raise CorpusDatabaseError("Medicaid source-only sync is incomplete")
    if database["snapshot_count"] or database["fetch_job_count"]:
        raise CorpusDatabaseError("Medicaid source-only sync created capture work")
    return {
        "schema_version": "localbce-state-medicaid-source-sync-v1",
        "status": "ok",
        "registry": registry_validation,
        "preflight": preflight_validation,
        "sync": synced,
        "database": database,
        "protected_table_changes": {},
        "candidates_created": 0,
        "database_jobs_created": False,
        "human_approved": False,
        "legal_verification_status": "not_verified",
        "runtime_eligibility_status": "ineligible_shadow_only",
        "runtime_activation": False,
        "proof_binding": False,
    }


def rules_checkpoint(
    workdir: Path,
    store: PostgresCorpusStore,
    *,
    registry_path: Path,
    preflight_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    registry, registry_validation = load_state_medicaid_registry(registry_path)
    preflight, preflight_validation = load_state_medicaid_preflight(
        preflight_path, registry
    )
    federal_registry = load_source_registry(workdir)
    metrics = store.rules_metrics()
    progress = store.corpus_scale_progress(600_000)
    quality = quality_gate_report(**store.quality_measurements())
    state = store.rules_checkpoint_state()
    usage = store.inference_usage_report()
    medicaid = store.supplemental_registry_summary(registry["registry_id"])
    if medicaid["source_count"] != 15:
        raise CorpusDatabaseError(
            "Medicaid Core V1 must be source-synced before checkpoint generation"
        )
    programs = [
        {
            "program": row["program"],
            "active_source_count": row["active_source_count"],
            "snapshot_retrieval_count": row["snapshot_retrieval_count"],
            "active_program_section_count": row["active_program_section_count"],
            "accepted_grounded_candidates": row["accepted_grounded_candidates"],
            "deterministic_candidates": row["deterministic_candidates"],
            "accepted_deficit": row["accepted_deficit"],
            "deterministic_deficit": row["deterministic_deficit"],
        }
        for row in progress["programs"]
    ]
    checkpoint = {
        "schema_version": "localbce-rules-corpus-checkpoint-v1",
        "checkpoint_scope": "paused_federal_scale_with_medicaid_core_v1_sources",
        "source_registries": {
            "federal_registry_id": federal_registry["registry_id"],
            "federal_registry_manifest_sha256": federal_registry[
                "registry_manifest_sha256"
            ],
            "medicaid_registry_id": registry["registry_id"],
            "medicaid_registry_canonical_sha256": registry_validation[
                "canonical_sha256"
            ],
            "medicaid_preflight_canonical_sha256": preflight_validation[
                "canonical_sha256"
            ],
        },
        "corpus": {
            "raw_grounded_candidate_count": metrics["table_counts"][
                "grounded_candidates"
            ],
            "grounding_status_counts": state["grounding_status_counts"],
            "active_accepted_candidate_count": progress[
                "accepted_grounded_candidates"
            ],
            "active_accepted_with_effective_date": progress[
                "accepted_candidates_with_effective_from"
            ],
            "active_accepted_missing_effective_date": progress[
                "accepted_candidates_missing_effective_from"
            ],
            "current_draft_candidate_count": progress["current_draft_candidates"],
            "blocked_draft_candidate_count": progress["blocked_draft_candidates"],
            "deterministic_candidate_count": progress["deterministic_candidates"],
            "program_count": progress["program_count"],
            "programs_with_accepted_candidates": sum(
                row["accepted_grounded_candidates"] > 0 for row in programs
            ),
            "programs_with_deterministic_candidates": sum(
                row["deterministic_candidates"] > 0 for row in programs
            ),
            "programs": programs,
        },
        "blockers": {
            "draft_blocker_counts": progress["draft_blocker_counts"],
            "minimum_additional_physical_sections_lower_bound": progress[
                "minimum_additional_physical_sections_lower_bound"
            ],
            "minimum_additional_program_contexts_lower_bound": progress[
                "minimum_additional_program_contexts_lower_bound"
            ],
            "remaining_medicaid_capture_blockers": medicaid[
                "adapter_required_source_ids"
            ],
        },
        "jobs": {
            "paid_inference_paused": True,
            "inference_job_states": state["inference_job_states"],
            "durable_queue_states": state["durable_queue_states"],
            "inference_usage": {
                key: usage[key]
                for key in (
                    "job_count",
                    "attempts",
                    "input_tokens",
                    "output_tokens",
                    "retry_rounds",
                    "lease_renewals",
                )
            },
        },
        "duplicates_and_conflicts": {
            "stored_clusters": state["duplicate_conflict_clusters"],
            "active_open_conflicts": quality["open_conflicts"],
            "silently_merged_conflicts": quality["silently_merged_conflicts"],
        },
        "provenance_and_citations": state["provenance"],
        "review_legal_and_quality": {
            **state["review_quality"],
            "reviewer_decisions": state["reviewer_decisions"],
            "human_approved_medicaid_sources": medicaid[
                "human_approved_source_count"
            ],
            "legally_verified_medicaid_sources": medicaid[
                "legally_verified_source_count"
            ],
            "quality_gate_passed": quality["passed"],
            "quality_sample_count": quality["sample_count"],
            "two_role_sample_count": quality["two_role_sample_count"],
            "quality_measurements": quality["measurements"],
            "quality_gates": quality["gates"],
        },
        "medicaid_core_v1": {
            **medicaid,
            "registry_source_count": registry_validation["source_count"],
            "preflight_status_counts": preflight_validation["status_counts"],
            "source_records_only": True,
            "candidates_created": 0,
            "california_shells_are_legal_evidence": False,
        },
        "safety_boundaries": {
            **state["safety"],
            "hardcoded_g1_g10_default": True,
            "rules_active_v1_unchanged_required": True,
            "candidate_rule_activation": False,
            "production_release_created": False,
            "human_or_legal_approval_implied": False,
            "legacy_sqlite_graph_used": False,
        },
    }
    checkpoint["canonical_checkpoint_sha256"] = canonical_sha256(checkpoint)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(checkpoint, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return {**checkpoint, "report": str(output_path)}


def claude_infer(
    workdir: Path,
    store: PostgresCorpusStore,
    *,
    limit: int,
    concurrency: int = 8,
    batch_size: int = 256,
    result_detail_limit: int = 1_000,
    retry_failed: bool = False,
    retry_limit: int = 0,
    drain_existing: bool = False,
    timeout_seconds: float = 300.0,
) -> dict[str, Any]:
    if limit <= 0:
        raise ValueError("claude inference limit must be positive")
    if concurrency <= 0 or concurrency > 32:
        raise ValueError("claude concurrency must be between 1 and 32")
    if batch_size <= 0 or batch_size > 10_000:
        raise ValueError("claude inference batch size must be between 1 and 10000")
    if result_detail_limit < 0 or result_detail_limit > 10_000:
        raise ValueError(
            "claude inference result detail limit must be between 0 and 10000"
        )
    if retry_limit < 0:
        raise ValueError("failed inference retry limit cannot be negative")
    if retry_failed and retry_limit <= 0:
        raise ValueError("--retry-failed requires a positive --retry-limit")
    if retry_limit > 0 and not retry_failed:
        raise ValueError("--retry-limit requires --retry-failed")
    if timeout_seconds <= 0 or timeout_seconds > 900:
        raise ValueError("Claude timeout must be between 0 and 900 seconds")
    with store.inference_run_lock():
        return _claude_infer_locked(
            workdir,
            store,
            limit=limit,
            concurrency=concurrency,
            batch_size=batch_size,
            result_detail_limit=result_detail_limit,
            retry_failed=retry_failed,
            retry_limit=retry_limit,
            drain_existing=drain_existing,
            timeout_seconds=timeout_seconds,
        )


def os_getpid() -> int:
    import os

    return os.getpid()


def quality_evaluate(
    workdir: Path,
    store: PostgresCorpusStore,
    *,
    release_id: str | None = None,
) -> dict[str, Any]:
    if release_id is not None:
        release_id = _validated_release_id(release_id)
    report = quality_gate_report(**store.quality_measurements(release_id=release_id))
    report["release_id"] = release_id
    report_name = (
        f"rules_scale_quality_{release_id}.json"
        if release_id
        else "rules_scale_quality_v1.json"
    )
    report["report"] = str(_write_report(workdir, report_name, report))
    return report


def inference_recover(
    workdir: Path,
    store: PostgresCorpusStore,
    *,
    retry_failed: bool = False,
    retry_limit: int = 0,
    batch_size: int = 256,
) -> dict[str, Any]:
    if retry_limit < 0:
        raise ValueError("failed inference retry limit cannot be negative")
    if retry_failed and retry_limit <= 0:
        raise ValueError("--retry-failed requires a positive --retry-limit")
    if retry_limit > 0 and not retry_failed:
        raise ValueError("--retry-limit requires --retry-failed")
    if batch_size <= 0 or batch_size > 10_000:
        raise ValueError("inference recovery batch size must be between 1 and 10000")

    lease_recovery = store.recover_expired_inference_leases()
    retried_failed_jobs = (
        store.retry_failed_inference_jobs(limit=retry_limit)
        if retry_failed
        else 0
    )
    critique_enqueued = 0
    while True:
        critique_sections = store.pending_critique_sections(limit=batch_size)
        if not critique_sections:
            break
        for section in critique_sections:
            store.enqueue_inference(
                build_inference_request(
                    section,
                    section["program"],
                    pass_number=2,
                    proposed_candidates=section["proposed_candidates"],
                )
            )
            critique_enqueued += 1
    materialization = {
        "candidates_processed": 0,
        "drafts_created": 0,
        "drafts_blocked": 0,
        "policy_tasks_created": 0,
        "clusters_created": 0,
    }
    while True:
        result = store.materialize_review_drafts(limit=batch_size)
        for key in materialization:
            materialization[key] += int(result.get(key, 0))
        if int(result.get("candidates_processed", 0)) == 0:
            break
    failure_summary = store.inference_failure_report(limit=1)
    report = {
        "schema_version": "localbce-inference-recovery-v1",
        "lease_recovery": lease_recovery,
        "retried_failed_jobs": retried_failed_jobs,
        "critique_enqueued": critique_enqueued,
        "review_materialization": materialization,
        "queue_summary": store.inference_queue_summary(),
        "failed": int(failure_summary["failed"]),
        "rejected": int(failure_summary["rejected"]),
        "current_retryable_failed": int(
            failure_summary["current_retryable_failed"]
        ),
        "runtime_activation": False,
        "proof_binding": False,
    }
    report["report"] = str(
        _write_report(workdir, "rules_inference_recovery_v1.json", report)
    )
    return report


def inference_failure_report(
    workdir: Path, store: PostgresCorpusStore, *, limit: int = 100
) -> dict[str, Any]:
    report = store.inference_failure_report(limit=limit)
    report["report"] = str(
        _write_report(workdir, "rules_claude_failures_v1.json", report)
    )
    return report


def inference_usage_report(
    workdir: Path, store: PostgresCorpusStore
) -> dict[str, Any]:
    report = store.inference_usage_report()
    report["report"] = str(
        _write_report(workdir, "rules_claude_usage_v1.json", report)
    )
    return report


def corpus_progress(
    workdir: Path,
    store: PostgresCorpusStore,
    *,
    target_count: int,
) -> dict[str, Any]:
    report = store.corpus_scale_progress(target_count)
    report["report"] = str(
        _write_report(
            workdir,
            f"rules_corpus_progress_{target_count}.json",
            report,
        )
    )
    return report


def inference_launch_plan(
    workdir: Path,
    store: PostgresCorpusStore,
    *,
    target_count: int,
    concurrency: int = 8,
) -> dict[str, Any]:
    plan = build_inference_launch_plan(
        target_count=target_count,
        registry=load_source_registry(workdir),
        progress=store.corpus_scale_progress(target_count),
        preflight=store.source_registry_preflight_summary(),
        metrics=store.rules_metrics(),
        credential_configured=bool(os.environ.get("ANTHROPIC_API_KEY", "").strip()),
        concurrency=concurrency,
    )
    validate_inference_launch_plan(plan)
    plan["validation_status"] = "passed"
    plan["report"] = str(
        _write_report(
            workdir,
            f"rules_inference_launch_plan_{target_count}.json",
            plan,
        )
    )
    return plan


def quality_sample_plan(
    workdir: Path,
    store: PostgresCorpusStore,
    *,
    release_id: str,
    target_count: int = 1_020,
    corpus_target_count: int = 5_100,
) -> dict[str, Any]:
    release_id = _validated_release_id(release_id)
    report = store.plan_quality_samples(
        release_id=release_id,
        target_count=target_count,
        corpus_target_count=corpus_target_count,
    )
    report["report"] = str(
        _write_report(workdir, f"quality_sample_plan_{release_id}.json", report)
    )
    return report


def review_export(workdir: Path, store: PostgresCorpusStore) -> dict[str, Any]:
    report = store.review_export()
    report["report"] = str(_write_report(workdir, "rules_review_export_v1.json", report))
    return report


def shadow_bundle_export(workdir: Path, store: PostgresCorpusStore, *, release_manifest: Path) -> dict[str, Any]:
    release = json.loads(release_manifest.read_text(encoding="utf-8"))
    if release.get("gates_passed") is not True:
        raise ValueError("shadow export requires a release that passed every corpus gate")
    release_id = _validated_release_id(str(release.get("release_id", "")))
    rules = store.legally_verified_shadow_rules(release_id=release_id)
    bundle = build_shadow_bundle(release, rules)
    path = _write_report(workdir, "grounded_rules_shadow_bundle_v1.json", bundle)
    return {"output": str(path), "rule_count": len(rules), "rules_sha256": bundle["rules_sha256"], "runtime_activation": False, "proof_binding": False}


def corpus_release(
    workdir: Path,
    store: PostgresCorpusStore,
    *,
    release_id: str,
    target_count: int,
    source_registry: Path | None = None,
) -> dict[str, Any]:
    release_id = _validated_release_id(release_id)
    registry = load_source_registry(workdir, source_registry)
    cohort = store.release_cohort_summary(release_id)
    if cohort["corpus_target_count"] != target_count:
        raise CorpusDatabaseError(
            "release target does not match the immutable quality cohort"
        )
    if cohort["candidate_count"] != target_count:
        raise CorpusDatabaseError("release cohort candidate count is incomplete")
    quality = quality_gate_report(
        **store.quality_measurements(release_id=release_id)
    )
    candidates = store.release_cohort_candidates(release_id)
    registry_versions = store.release_cohort_registry_versions(release_id)
    if registry_versions != {registry["registry_id"]: target_count}:
        raise CorpusDatabaseError(
            "release cohort source registry lineage is mixed or does not match "
            "the selected source registry"
        )
    reviewer = store.review_export(release_id=release_id)
    manifest = build_release_manifest(
        release_id=release_id,
        target_count=target_count,
        candidates=candidates,
        source_registry_id=registry["registry_id"],
        source_manifest_hash=registry["registry_manifest_sha256"],
        quality_report=quality,
        blocker_counts=store.blocker_counts(release_id=release_id),
        reviewer_evidence=reviewer,
    )
    if manifest["candidate_ids_sha256"] != cohort["selection_hash"]:
        raise CorpusDatabaseError("release manifest does not match its immutable cohort")
    path = _write_report(workdir, f"corpus_release_{release_id}.json", manifest)
    if manifest["gates_passed"]:
        store.save_release(manifest)
        status = "released"
    else:
        status = "blocked_incomplete_milestone"
    return {**manifest, "status": status, "report": str(path)}


def validate_corpus_release_artifact(
    workdir: Path,
    *,
    release_manifest: Path,
    source_registry: Path | None = None,
) -> dict[str, Any]:
    manifest = json.loads(release_manifest.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError("corpus release manifest must be an object")
    errors = validate_release_manifest(manifest)
    registry = load_source_registry(workdir, source_registry)
    if manifest.get("source_registry_id") != registry["registry_id"]:
        errors.append("corpus release source registry ID mismatch")
    if manifest.get("source_manifest_hash") != registry["registry_manifest_sha256"]:
        errors.append("corpus release source registry hash mismatch")
    if errors:
        raise ValueError("; ".join(errors))
    return {
        "schema_version": "localbce-rules-corpus-release-validation-v1",
        "release_id": manifest["release_id"],
        "canonical_release_hash": manifest["canonical_release_hash"],
        "source_registry_id": registry["registry_id"],
        "source_manifest_hash": registry["registry_manifest_sha256"],
        "candidate_count": manifest["candidate_count"],
        "target_count": manifest["target_count"],
        "gates_passed": manifest["gates_passed"],
        "runtime_activation": False,
        "proof_binding": False,
        "status": "ok",
    }
