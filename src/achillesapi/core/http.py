"""Conservative HTTP execution primitives with explicit target scoping.

Day 4 deliberately supports GET only. No endpoint is contacted unless the
caller opts in with ``execute=True`` and supplies an exact host allowlist.
Redirects are disabled so a request cannot silently leave the approved host.
"""

from __future__ import annotations

import time
from urllib.parse import urlsplit

import httpx

from achillesapi.models.evidence import (
    ExecutionEvidence,
    RequestEvidence,
    ResponseEvidence,
)

_ALLOWED_METHODS = {"GET"}
_SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "proxy-authorization"}


class ScopeError(ValueError):
    """Raised when a request falls outside the explicitly authorized scope."""


class RequestBudgetExceeded(RuntimeError):
    """Raised when the configured request budget is exhausted."""


class SafeHTTPClient:
    def __init__(
        self,
        *,
        allowed_hosts: set[str],
        timeout: float = 10.0,
        max_requests: int = 10,
        requests_per_second: float = 1.0,
        max_body_bytes: int = 65_536,
        verify_tls: bool = True,
    ) -> None:
        if not allowed_hosts:
            raise ValueError("At least one explicitly allowed host is required.")
        if timeout <= 0 or max_requests < 1 or requests_per_second <= 0 or max_body_bytes < 1:
            raise ValueError("Timeout, request budget, rate and body limit must be positive.")
        self.allowed_hosts = {host.lower().strip().rstrip(".") for host in allowed_hosts}
        self.timeout = timeout
        self.max_requests = max_requests
        self.interval = 1.0 / requests_per_second
        self.max_body_bytes = max_body_bytes
        self.verify_tls = verify_tls
        self._requests_made = 0
        self._last_request_at: float | None = None

    def _validate_target(self, method: str, url: str) -> None:
        if method.upper() not in _ALLOWED_METHODS:
            raise ScopeError("Only GET requests are enabled in this milestone.")
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ScopeError("Target must be an absolute HTTP(S) URL.")
        if parts.username or parts.password:
            raise ScopeError("Credentials embedded in URLs are not allowed.")
        if parts.hostname.lower().rstrip(".") not in self.allowed_hosts:
            raise ScopeError(f"Host {parts.hostname!r} is not in the explicit allowlist.")

    @staticmethod
    def _safe_headers(headers: httpx.Headers) -> dict[str, str]:
        return {
            key: ("[REDACTED]" if key.lower() in _SENSITIVE_HEADERS else value)
            for key, value in headers.items()
        }

    def request(self, method: str, url: str, *, execute: bool = False) -> ExecutionEvidence:
        """Create a dry-run plan or perform one scoped GET request."""
        self._validate_target(method, url)
        request_evidence = RequestEvidence(method=method.upper(), url=url)
        if not execute:
            return ExecutionEvidence(
                request=request_evidence,
                executed=False,
                notes=["Dry run: no network request was sent."],
            )
        if self._requests_made >= self.max_requests:
            raise RequestBudgetExceeded("Maximum request budget reached.")
        now = time.monotonic()
        if self._last_request_at is not None:
            wait = self.interval - (now - self._last_request_at)
            if wait > 0:
                time.sleep(wait)
        self._last_request_at = time.monotonic()
        self._requests_made += 1
        started = time.monotonic()
        try:
            with httpx.Client(
                timeout=self.timeout,
                follow_redirects=False,
                verify=self.verify_tls,
                headers={"User-Agent": "AchillesAPI/0.4.0 (authorized-security-assessment)"},
            ) as client:
                with client.stream("GET", url) as response:
                    body = bytearray()
                    truncated = False
                    for chunk in response.iter_bytes():
                        remaining = self.max_body_bytes - len(body)
                        if len(chunk) > remaining:
                            body.extend(chunk[:remaining])
                            truncated = True
                            break
                        body.extend(chunk)
                    status_code = response.status_code
                    safe_headers = self._safe_headers(response.headers)
                    encoding = response.encoding or "utf-8"
            elapsed_ms = (time.monotonic() - started) * 1000
            return ExecutionEvidence(
                request=request_evidence,
                response=ResponseEvidence(
                    status_code=status_code,
                    headers=safe_headers,
                    body_preview=bytes(body).decode(encoding, errors="replace"),
                    body_truncated=truncated,
                    elapsed_ms=round(elapsed_ms, 2),
                ),
                executed=True,
                notes=["Redirects are disabled; only the allowlisted host was contacted."],
            )
        except httpx.HTTPError as exc:
            return ExecutionEvidence(
                request=request_evidence,
                error=f"{type(exc).__name__}: {exc}",
                executed=True,
                notes=["Request was attempted; inspect the error before retrying."],
            )
