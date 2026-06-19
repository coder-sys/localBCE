from __future__ import annotations

import importlib.metadata
import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

import httpx

from .config import RunConfig, Source


CORE_PACKAGES = ["pypdf", "PyMuPDF", "networkx"]
OPTIONAL_PACKAGES = ["requests", "httpx", "playwright", "bs4", "lxml", "whoosh"]


@dataclass
class DependencyReport:
    package: str
    version: str | None
    required: bool
    ok: bool


@dataclass
class AccessVerdict:
    source: str
    url: str
    reachable: bool
    status_code: int | None
    content_type: str | None
    bytes_read: int
    body_excerpt: str
    block_signature: str | None
    error: str | None


def package_version(package: str) -> str | None:
    lookup = {"PyMuPDF": "PyMuPDF", "bs4": "beautifulsoup4"}
    try:
        return importlib.metadata.version(lookup.get(package, package))
    except importlib.metadata.PackageNotFoundError:
        return None


def dependency_report() -> list[DependencyReport]:
    reports: list[DependencyReport] = []
    for package in CORE_PACKAGES:
        version = package_version(package)
        reports.append(DependencyReport(package, version, True, version is not None))
    for package in OPTIONAL_PACKAGES:
        version = package_version(package)
        reports.append(DependencyReport(package, version, False, version is not None))
    return reports


def assert_core_dependencies() -> None:
    missing = [r.package for r in dependency_report() if r.required and not r.ok]
    if missing:
        raise RuntimeError(f"missing core dependencies: {', '.join(missing)}")


def detect_block_signature(status_code: int | None, body: bytes) -> str | None:
    sample = body[:262_144].lower()
    if status_code in {401, 403, 429}:
        return f"http_{status_code}"
    marker_labels = {
        b"access denied": "access_denied",
        b"access has been denied": "access_denied",
        b"are you a human": "bot_challenge",
        b"bot detection": "bot_challenge",
        b"captcha": "captcha",
        b"challenge-platform": "bot_challenge",
        b"cloudflare": "cloudflare",
        b"ddos-guard": "ddos_guard",
        b"incapsula": "incapsula",
        b"_incapsula_resource": "incapsula",
        b"javascript is required": "javascript_required",
        b"noindex,nofollow": "noindex_nofollow",
        b"request unsuccessful": "request_unsuccessful",
        b"too many requests": "too_many_requests",
        b"unusual traffic": "bot_challenge",
        b"verify you are human": "bot_challenge",
    }
    for marker, label in marker_labels.items():
        if marker in sample:
            return label
    return None


def check_source(client: httpx.Client, source: Source) -> AccessVerdict:
    try:
        response = client.get(source.url)
        body = response.content[:8192]
        block_signature = detect_block_signature(response.status_code, body)
        content_type = response.headers.get("content-type")
        reachable = 200 <= response.status_code < 400 and block_signature is None
        return AccessVerdict(
            source=source.name,
            url=source.url,
            reachable=reachable,
            status_code=response.status_code,
            content_type=content_type,
            bytes_read=len(response.content),
            body_excerpt=response.text[:500],
            block_signature=block_signature,
            error=None,
        )
    except Exception as exc:  # network edge; report, do not hide
        return AccessVerdict(
            source=source.name,
            url=source.url,
            reachable=False,
            status_code=None,
            content_type=None,
            bytes_read=0,
            body_excerpt="",
            block_signature=None,
            error=str(exc),
        )


def phase0_access_check(config: RunConfig, sources: Iterable[Source] | None = None) -> dict:
    assert_core_dependencies()
    selected_sources = list(sources or config.seeds)
    headers = {"user-agent": config.user_agent}
    results: list[AccessVerdict] = []

    with httpx.Client(headers=headers, timeout=config.timeout_seconds, follow_redirects=False) as client:
        for source in selected_sources:
            verdict = check_source(client, source)
            results.append(verdict)
            time.sleep(config.polite_delay_seconds)

    required_blocked = [
        verdict.source
        for verdict, source in zip(results, selected_sources)
        if source.required and not verdict.reachable
    ]

    report = {
        "working_dir": str(config.workdir),
        "dependency_report": [asdict(item) for item in dependency_report()],
        "source_verdicts": [asdict(item) for item in results],
        "egress_ip": None,
        "egress_ip_collection": "disabled_by_default",
        "overall": "REACHABLE" if not required_blocked else "BLOCKED",
        "blocked_required_sources": required_blocked,
    }
    write_json(config.reports_dir / "phase0_access.json", report)
    return report


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
