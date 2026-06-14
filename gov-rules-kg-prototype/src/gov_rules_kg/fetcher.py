from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urldefrag

import httpx

from .access import detect_block_signature
from .config import RunConfig


@dataclass
class FetchResult:
    url: str
    canonical_url: str
    status: str
    status_code: int | None
    content_type: str | None
    body: bytes
    content_hash: str | None
    detail: str
    attempts: int = 1


def canonicalize_url(url: str) -> str:
    return urldefrag(url.strip())[0]


class PoliteFetcher:
    RETRYABLE_STATUS_CODES = {408, 429, 500, 502, 503, 504}

    def __init__(self, config: RunConfig, progress_callback: Callable[[dict], None] | None = None) -> None:
        self.config = config
        self.progress_callback = progress_callback
        self.client = httpx.Client(
            headers={"user-agent": config.user_agent},
            timeout=config.timeout_seconds,
            follow_redirects=True,
        )

    def close(self) -> None:
        self.client.close()

    def fetch(self, url: str) -> FetchResult:
        canonical_url = canonicalize_url(url)
        max_attempts = max(1, self.config.fetch_retries + 1)
        last_result: FetchResult | None = None
        for attempt in range(1, max_attempts + 1):
            time.sleep(self.config.polite_delay_seconds)
            try:
                response = self.client.get(canonical_url)
                body = response.content
                block_signature = detect_block_signature(response.status_code, body)
                content_type = response.headers.get("content-type")
                if block_signature:
                    return FetchResult(
                        url=url,
                        canonical_url=canonical_url,
                        status="NEEDS_MANUAL",
                        status_code=response.status_code,
                        content_type=content_type,
                        body=b"",
                        content_hash=None,
                        detail=f"blocked or guarded: {block_signature}",
                        attempts=attempt,
                    )
                if 200 <= response.status_code < 400:
                    return FetchResult(
                        url=url,
                        canonical_url=canonical_url,
                        status="FETCHED",
                        status_code=response.status_code,
                        content_type=content_type,
                        body=body,
                        content_hash=hashlib.sha256(body).hexdigest(),
                        detail="ok",
                        attempts=attempt,
                    )
                last_result = FetchResult(
                    url=url,
                    canonical_url=canonical_url,
                    status="FAILED",
                    status_code=response.status_code,
                    content_type=content_type,
                    body=b"",
                    content_hash=None,
                    detail=f"http status {response.status_code}",
                    attempts=attempt,
                )
                should_retry = response.status_code in self.RETRYABLE_STATUS_CODES
            except httpx.TimeoutException as exc:
                last_result = FetchResult(
                    url=url,
                    canonical_url=canonical_url,
                    status="FAILED",
                    status_code=None,
                    content_type=None,
                    body=b"",
                    content_hash=None,
                    detail=str(exc) or exc.__class__.__name__,
                    attempts=attempt,
                )
                should_retry = True
            except Exception as exc:
                last_result = FetchResult(
                    url=url,
                    canonical_url=canonical_url,
                    status="FAILED",
                    status_code=None,
                    content_type=None,
                    body=b"",
                    content_hash=None,
                    detail=str(exc),
                    attempts=attempt,
                )
                should_retry = False

            if should_retry and attempt < max_attempts:
                delay = self.config.fetch_retry_backoff_seconds * (2 ** (attempt - 1))
                self.log_retry(canonical_url, attempt, max_attempts, delay, last_result)
                time.sleep(delay)
                continue
            return last_result

        return last_result or FetchResult(
            url=url,
            canonical_url=canonical_url,
            status="FAILED",
            status_code=None,
            content_type=None,
            body=b"",
            content_hash=None,
            detail="fetch failed before first attempt",
        )

    def log_retry(
        self,
        canonical_url: str,
        attempt: int,
        max_attempts: int,
        delay_seconds: float,
        result: FetchResult,
    ) -> None:
        if not self.progress_callback:
            return
        self.progress_callback(
            {
                "event": "fetch_retry_scheduled",
                "url": canonical_url,
                "attempt": attempt,
                "max_attempts": max_attempts,
                "next_attempt": attempt + 1,
                "delay_seconds": delay_seconds,
                "status_code": result.status_code,
                "detail": result.detail,
            }
        )
