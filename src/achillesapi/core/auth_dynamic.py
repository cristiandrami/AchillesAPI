"""Scoped dynamic authentication for authorized API assessments.

Supports OAuth2 client credentials and JSON login forms. Secrets are read only
from environment variables. Token responses never leave process memory. An
explicit host allowlist is required before any authentication network request.
"""
from __future__ import annotations

import os
import re
import time
from urllib.parse import urlsplit

import httpx

from achillesapi.core.auth import AuthenticationConfigError, AuthenticationMaterial

_ENV = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _secret(name: str | None) -> str:
    """Read one configured environment variable without exposing its value."""
    if not name or not _ENV.fullmatch(name):
        raise AuthenticationConfigError("Invalid or missing credential environment variable name")
    value = os.getenv(name)
    if not value:
        raise AuthenticationConfigError(f"Required credential environment variable {name!r} is missing")
    return value


def _validate_auth_url(url: str, hosts: set[str], insecure: bool) -> None:
    """Require a concrete, in-scope token endpoint with no URL credentials."""
    try:
        parts = urlsplit(url)
        hostname = (parts.hostname or "").lower().rstrip(".")
        if parts.scheme not in {"http", "https"} or not hostname or parts.username or parts.password:
            raise ValueError()
        if parts.fragment or hostname not in {h.lower().rstrip('.') for h in hosts}:
            raise ValueError()
        if parts.scheme == "http" and not insecure:
            raise ValueError()
    except (TypeError, ValueError) as exc:
        raise AuthenticationConfigError("Authentication URL outside approved scope or insecure HTTP not approved") from exc


def _pointer(data: object, pointer: str) -> object:
    """Read a JSON Pointer from a short-lived response without logging the data."""
    if not pointer.startswith("/"):
        raise AuthenticationConfigError("Login token pointer must begin with /")
    item = data
    for raw in pointer[1:].split("/"):
        key = raw.replace("~1", "/").replace("~0", "~")
        if not isinstance(item, dict) or key not in item:
            raise AuthenticationConfigError("Login response did not contain the expected token path")
        item = item[key]
    return item


def acquire(profile, *, allowed_hosts: set[str], allow_insecure_http: bool = False,
            timeout: float = 8.0) -> tuple[AuthenticationMaterial, float]:
    """Fetch a scoped token using a single POST, returning material and expiry.

    An OAuth2 client-credentials grant sends a standard urlencoded form. A
    login_json profile sends only explicitly named username/password fields.
    The API target's response body and the issued token are never persisted.
    """
    url = profile.token_url if profile.type == "oauth2_client_credentials" else profile.login_url
    _validate_auth_url(url, allowed_hosts, allow_insecure_http)
    if profile.type == "oauth2_client_credentials":
        form = {"grant_type": "client_credentials"}
        if profile.scopes:
            form["scope"] = " ".join(profile.scopes)
        auth = (_secret(profile.client_id_env), _secret(profile.client_secret_env))
        body = None
    elif profile.type == "login_json":
        auth = None
        form = None
        body = {profile.username_field: _secret(profile.username_env),
                profile.password_field: _secret(profile.password_env)}
    else:
        raise AuthenticationConfigError("Unsupported dynamic authentication type")
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False,
                          verify=True) as client:
            response = client.post(url, data=form, json=body, auth=auth,
                                   headers={"Accept": "application/json"})
            if response.status_code != 200:
                raise AuthenticationConfigError("Authentication failed (HTTP status not 200)")
            if len(response.content) > 16384:
                raise AuthenticationConfigError("Authentication response exceeded the size limit")
            payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise AuthenticationConfigError("Authentication request failed or returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise AuthenticationConfigError("Authentication response must be a JSON object")
    token = _pointer(payload, profile.token_pointer)
    if not isinstance(token, str) or not token or len(token) > 8192:
        raise AuthenticationConfigError("Authentication response did not contain a valid token")
    expires = payload.get("expires_in", 300)
    duration = float(expires) if isinstance(expires, (int, float)) else 300.0
    duration = min(max(duration - 30, 10), 86400)
    return AuthenticationMaterial(headers={"Authorization": "Bearer " + token}), time.monotonic() + duration
