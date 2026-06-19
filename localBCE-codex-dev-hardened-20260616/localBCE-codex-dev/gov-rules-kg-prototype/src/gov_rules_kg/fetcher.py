from __future__ import annotations

import hashlib
import ipaddress
import time
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urljoin, urlparse, urldefrag

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
    final_url: str | None = None


def canonicalize_url(url: str) -> str:
    return urldefrag(url.strip())[0]


class PoliteFetcher:
    RETRYABLE_STATUS_CODES = {408, 429, 500, 502, 503, 504}

    def __init__(self, config: RunConfig, progress_callback: Callable[[dict], None] | None = None) -> None:
        self.config = config
        self.progress_callback = progress_callback
        self.host_failures: dict[str, int] = {}
        self.client = httpx.Client(
            headers={"user-agent": config.user_agent, "accept-encoding": "identity"},
            timeout=config.timeout_seconds,
            follow_redirects=False,
        )

    def close(self) -> None:
        self.client.close()

    def fetch(self, url: str) -> FetchResult:
        canonical_url = canonicalize_url(url)
        url_error = self.validate_url(canonical_url)
        if url_error:
            return FetchResult(url, canonical_url, "FAILED", None, None, b"", None, url_error)
        max_attempts = max(1, self.config.fetch_retries + 1)
        last_result: FetchResult | None = None
        for attempt in range(1, max_attempts + 1):
            time.sleep(self.config.polite_delay_seconds)
            try:
                response, body, final_url = self.get_with_redirects(canonical_url)
                final_error = self.validate_url(final_url)
                if final_error:
                    return FetchResult(
                        url=url,
                        canonical_url=canonical_url,
                        status="FAILED",
                        status_code=response.status_code,
                        content_type=response.headers.get("content-type"),
                        body=b"",
                        content_hash=None,
                        detail=f"redirect blocked: {final_error}",
                        attempts=attempt,
                        final_url=final_url,
                    )
                block_signature = detect_block_signature(response.status_code, body)
                content_type = response.headers.get("content-type")
                if block_signature:
                    self.record_failure(canonical_url)
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
                    expected_hash = self.expected_hash_for(canonical_url)
                    observed_hash = hashlib.sha256(body).hexdigest()
                    if expected_hash and expected_hash.lower() != observed_hash:
                        self.record_failure(canonical_url)
                        return FetchResult(
                            url=url,
                            canonical_url=canonical_url,
                            status="FAILED",
                            status_code=response.status_code,
                            content_type=content_type,
                            body=b"",
                        content_hash=observed_hash,
                        detail="content hash mismatch",
                        attempts=attempt,
                        final_url=final_url,
                    )
                    return FetchResult(
                        url=url,
                        canonical_url=canonical_url,
                        status="FETCHED",
                        status_code=response.status_code,
                        content_type=content_type,
                        body=body,
                        content_hash=observed_hash,
                        detail="ok" if final_url == canonical_url else f"ok redirected_to={final_url}",
                        attempts=attempt,
                        final_url=final_url,
                    )
                self.record_failure(canonical_url)
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
                    final_url=final_url,
                )
                should_retry = response.status_code in self.RETRYABLE_STATUS_CODES
            except httpx.TimeoutException as exc:
                self.record_failure(canonical_url)
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
                self.record_failure(canonical_url)
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

    def validate_url(self, url: str) -> str | None:
        parsed = urlparse(url)
        if parsed.scheme not in {"https", "http"}:
            return f"unsupported URL scheme: {parsed.scheme or 'missing'}"
        if not parsed.hostname:
            return "missing URL host"
        host = parsed.hostname.lower()
        if self.config.allowed_hosts and host not in {item.lower() for item in self.config.allowed_hosts}:
            return f"host not allowed: {host}"
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                return f"private or non-routable host blocked: {host}"
        except ValueError:
            blocked = {"localhost", "metadata.google.internal"}
            if host in blocked or host.endswith(".local"):
                return f"private or local host blocked: {host}"
        if self.host_failures.get(host, 0) >= self.config.per_host_failure_cap:
            return f"per-host failure cap reached: {host}"
        return None

    def expected_hash_for(self, canonical_url: str) -> str | None:
        for source in self.config.seeds:
            if canonicalize_url(source.url) == canonical_url and source.expected_sha256:
                return source.expected_sha256
        return None

    def record_failure(self, url: str) -> None:
        host = urlparse(url).hostname
        if host:
            normalized = host.lower()
            self.host_failures[normalized] = self.host_failures.get(normalized, 0) + 1

    def get_with_redirects(self, url: str) -> tuple[httpx.Response, bytes, str]:
        current_url = url
        for _ in range(6):
            response, body = self.get_limited(current_url)
            if response.status_code not in {301, 302, 303, 307, 308}:
                return response, body, current_url
            location = response.headers.get("location")
            if not location:
                return response, body, current_url
            next_url = canonicalize_url(urljoin(current_url, location))
            redirect_error = self.validate_url(next_url)
            if redirect_error:
                return response, b"", next_url
            current_url = next_url
        raise ValueError("redirect limit exceeded")

    def get_limited(self, url: str) -> tuple[httpx.Response, bytes]:
        if hasattr(self.client, "stream"):
            with self.client.stream("GET", url) as response:
                content_encoding = response.headers.get("content-encoding", "").strip().lower()
                if content_encoding and content_encoding != "identity":
                    raise ValueError("compressed response bodies are not accepted")
                content_length = response.headers.get("content-length")
                if self.config.require_content_length and not content_length:
                    raise ValueError("missing content-length")
                if content_length:
                    try:
                        if int(content_length) > self.config.max_response_bytes:
                            raise ValueError("response too large")
                    except ValueError as exc:
                        if str(exc) == "response too large":
                            raise
                        raise ValueError("invalid content-length") from exc
                chunks: list[bytes] = []
                total = 0
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > self.config.max_response_bytes:
                        raise ValueError("response too large")
                    chunks.append(chunk)
                return response, b"".join(chunks)
        response = self.client.get(url)
        body = response.content
        if len(body) > self.config.max_response_bytes:
            raise ValueError("response too large")
        return response, body

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
