"""Two-principal BOLA verification for explicitly local training targets."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import time
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, computed_field


class BolaCheckError(ValueError):
    """Raised when a BOLA check target or input is not permitted."""


class PrincipalResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status_code: int
    elapsed_ms: float
    body: str = Field(default="", exclude=True)
    body_truncated: bool = False

    @computed_field
    @property
    def body_sha256(self) -> str:
        """Fingerprint of the canonical response, without exposing its contents."""
        return hashlib.sha256(_canonical_body(self.body).encode("utf-8")).hexdigest()


class BolaCheckResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    check: str = "BOLA"
    status: str
    confirmed_vulnerability: bool = False
    executed: bool = True
    target: str
    owner_principal: PrincipalResponse
    other_principal: PrincipalResponse
    explanation: str
    recommendation: str = (
        "Enforce object-level authorization server-side for every operation that "
        "reads or modifies an object, and test with distinct principals."
    )


def _validate_local_url(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise BolaCheckError("Target must be an absolute HTTP(S) URL.")
    if parts.username or parts.password:
        raise BolaCheckError("Credentials embedded in URLs are not allowed.")
    host = parts.hostname.lower().rstrip(".")
    is_loopback_name = host == "localhost"
    try:
        is_loopback_ip = ipaddress.ip_address(host).is_loopback
    except ValueError:
        is_loopback_ip = False
    if not (is_loopback_name or is_loopback_ip):
        raise BolaCheckError(
            "The BOLA checker is restricted to localhost/loopback targets in this milestone."
        )
    return host


def _request(url: str, token: str, timeout: float) -> PrincipalResponse:
    started = time.monotonic()
    with httpx.Client(
        timeout=timeout,
        follow_redirects=False,
        verify=True,
        headers={"User-Agent": "AchillesAPI/0.4.0 (local-authorized-lab)"},
    ) as client:
        with client.stream(
            "GET", url, headers={"Authorization": f"Bearer {token}"}
        ) as response:
            body = bytearray()
            truncated = False
            for chunk in response.iter_bytes():
                remaining = 65_536 - len(body)
                if len(chunk) > remaining:
                    body.extend(chunk[:remaining])
                    truncated = True
                    break
                body.extend(chunk)
            status_code = response.status_code
            encoding = response.encoding or "utf-8"
    return PrincipalResponse(
        status_code=status_code,
        elapsed_ms=round((time.monotonic() - started) * 1000, 2),
        body=bytes(body).decode(encoding, errors="replace"),
        body_truncated=truncated,
    )


def check_bola(
    url: str,
    *,
    owner_token: str,
    other_token: str,
    timeout: float = 5.0,
) -> BolaCheckResult:
    """Compare owner and non-owner access to the same object using two GETs.

    A positive result requires the owner baseline to succeed and the second
    principal to receive the same successful object representation.
    """
    _validate_local_url(url)
    if not owner_token or not other_token:
        raise BolaCheckError("Both bearer tokens must be provided.")
    if owner_token == other_token:
        raise BolaCheckError("Owner and other-principal tokens must be different.")
    if not 0.1 <= timeout <= 30:
        raise BolaCheckError("Timeout must be between 0.1 and 30 seconds.")

    try:
        owner = _request(url, owner_token, timeout)
        other = _request(url, other_token, timeout)
    except httpx.HTTPError as exc:
        raise BolaCheckError(f"HTTP request failed: {type(exc).__name__}") from exc

    if owner.status_code != 200:
        status = "inconclusive_owner_baseline_failed"
        explanation = (
            "The owner principal could not retrieve the object (expected HTTP 200); "
            "the comparison cannot establish an object-level authorization flaw."
        )
    elif other.status_code in {401, 403, 404}:
        status = "protected_for_other_principal"
        explanation = (
            "The owner can retrieve the object, while the other principal is denied "
            "or the object is concealed. This check did not reproduce BOLA."
        )
    elif other.status_code == 200:
        if owner.body_truncated or other.body_truncated:
            status = "inconclusive_response_truncated"
            explanation = (
                "At least one response exceeded the capture limit. The full object "
                "representations were not compared; review the endpoint manually."
            )
        elif _canonical_body(owner.body) == _canonical_body(other.body):
            status = "confirmed_bola"
            explanation = (
                "Both distinct principals received HTTP 200 with the same object "
                "representation. The local test reproduced unauthorized cross-user access."
            )
        else:
            status = "possible_bola_manual_review"
            explanation = (
                "The other principal received HTTP 200, but the returned representation "
                "differs. Review the response and the endpoint's intended access policy."
            )
    else:
        status = "inconclusive_unexpected_response"
        explanation = (
            f"The other principal received HTTP {other.status_code}; inspect the response "
            "and endpoint behavior manually."
        )

    return BolaCheckResult(
        status=status,
        confirmed_vulnerability=status == "confirmed_bola",
        target=url,
        owner_principal=owner,
        other_principal=other,
        explanation=explanation,
    )


def _canonical_body(body: str) -> str:
    try:
        return json.dumps(json.loads(body), sort_keys=True, separators=(",", ":"))
    except (json.JSONDecodeError, TypeError):
        return body.strip()
