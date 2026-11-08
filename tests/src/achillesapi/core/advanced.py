"""Bounded, non-destructive API security checks for authorized local labs.

Active checks are deliberately restricted to loopback targets. JWT inspection is
offline and does not claim to verify signatures.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from typing import Any
from urllib.parse import quote, urlsplit

import httpx


class AdvancedCheckError(ValueError):
    """Invalid or out-of-scope advanced check input."""


def require_loopback(base_url: str) -> str:
    """In pratica: Blocca target non locali per proteggere i vecchi test da uso indesiderato.

    Attenzione: Non contatta direttamente l'API target.
    """
    from ipaddress import ip_address

    parts = urlsplit(base_url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise AdvancedCheckError("Target must be an absolute HTTP(S) URL.")
    if parts.username or parts.password:
        raise AdvancedCheckError("Credentials embedded in URLs are not allowed.")
    host = parts.hostname.lower().rstrip(".")
    try:
        loopback = host == "localhost" or ip_address(host).is_loopback
    except ValueError:
        loopback = host == "localhost"
    if not loopback:
        raise AdvancedCheckError("Active advanced checks are restricted to localhost/loopback.")
    return base_url.rstrip("/")


def _client(timeout: float) -> httpx.Client:
    """In pratica: Prepara un client HTTP con timeout e senza redirect automatici.

    Attenzione: Non contatta direttamente l'API target.
    """
    return httpx.Client(timeout=timeout, follow_redirects=False, verify=True,
                        headers={"User-Agent": "AchillesAPI/0.4.0 (authorized-local-assessment)"})


def _url(base: str, path: str, values: dict[str, str] | None = None) -> str:
    """In pratica: Costruisce l'URL da base e path, sostituendo i parametri indicati.

    Attenzione: Non contatta direttamente l'API target.
    """
    values = values or {}
    def replace(match: re.Match[str]) -> str:
        """In pratica: Esegue la fase 'replace' del modulo advanced.

    Attenzione: Non contatta direttamente l'API target.
    """
        name = match.group(1)
        if name not in values:
            raise AdvancedCheckError(f"Missing --path-value for {{{name}}}.")
        return quote(values[name], safe="")
    return base + re.sub(r"\{([^{}]+)\}", replace, path)


def bola_sweep(spec: dict[str, Any], base_url: str, owner_token: str,
               other_token: str, path_values: dict[str, str], timeout: float = 5.0) -> dict[str, Any]:
    """Compare two principals across every GET operation; report candidates only."""
    # IN PRATICA: Confronta l'accesso alla stessa risorsa da parte di due identità nel motore legacy.
    # SICUREZZA: Puo inviare richieste HTTP; verificare scope, identita e autorizzazioni.
    base = require_loopback(base_url)
    if not owner_token or not other_token or owner_token == other_token:
        raise AdvancedCheckError("Two distinct non-empty bearer tokens are required.")
    results = []
    with _client(timeout) as client:
        for path, item in (spec.get("paths") or {}).items():
            if not isinstance(item, dict):
                continue
            for method, operation in item.items():
                if method.lower() != "get" or not isinstance(operation, dict):
                    continue
                url = _url(base, path, path_values)
                try:
                    own = client.get(url, headers={"Authorization": f"Bearer {owner_token}"})
                    other = client.get(url, headers={"Authorization": f"Bearer {other_token}"})
                    owner_hash = hashlib.sha256(own.content[:65536]).hexdigest()
                    other_hash = hashlib.sha256(other.content[:65536]).hexdigest()
                    if own.status_code == 200 and other.status_code == 200:
                        status = "possible_bola_same_representation" if owner_hash == other_hash else "possible_bola_different_representation"
                    elif own.status_code == 200 and other.status_code in {401, 403, 404}:
                        status = "other_principal_denied"
                    else:
                        status = "inconclusive"
                    results.append({"method": "GET", "path": path, "operation_id": operation.get("operationId"),
                                    "owner_status": own.status_code, "other_status": other.status_code,
                                    "same_response_fingerprint": owner_hash == other_hash,
                                    "status": status,
                                    "note": "Fingerprint equality/difference is triage evidence only; verify object identity and intended ownership policy."})
                except httpx.HTTPError as exc:
                    results.append({"method": "GET", "path": path, "status": "request_error",
                                    "error": type(exc).__name__})
    return {"check": "BOLA_SWEEP", "executed": True, "requests": len(results) * 2, "results": results}


def bfla_sweep(spec: dict[str, Any], base_url: str, low_token: str,
               high_token: str, path_values: dict[str, str], timeout: float = 5.0) -> dict[str, Any]:
    """Compare low/high privilege responses on GET endpoints; never infer policy."""
    # IN PRATICA: Confronta l'accesso a una funzione da parte di identità diverse nel motore legacy.
    # SICUREZZA: Puo inviare richieste HTTP; verificare scope, identita e autorizzazioni.
    base = require_loopback(base_url)
    if not low_token or not high_token or low_token == high_token:
        raise AdvancedCheckError("Two distinct role tokens are required.")
    results = []
    with _client(timeout) as client:
        for path, item in (spec.get("paths") or {}).items():
            if not isinstance(item, dict):
                continue
            for method, operation in item.items():
                if method.lower() != "get" or not isinstance(operation, dict):
                    continue
                url = _url(base, path, path_values)
                try:
                    low = client.get(url, headers={"Authorization": f"Bearer {low_token}"})
                    high = client.get(url, headers={"Authorization": f"Bearer {high_token}"})
                    differs = low.status_code != high.status_code or hashlib.sha256(low.content[:65536]).digest() != hashlib.sha256(high.content[:65536]).digest()
                    results.append({"method": "GET", "path": path,
                                    "operation_id": operation.get("operationId"),
                                    "low_privilege_status": low.status_code,
                                    "high_privilege_status": high.status_code,
                                    "response_fingerprint_differs": differs,
                                    "status": "response_difference_review" if differs else "same_response_review_policy",
                                    "note": "Compare results with the documented role policy; status differences alone do not prove BFLA."})
                except httpx.HTTPError as exc:
                    results.append({"method": "GET", "path": path, "status": "request_error",
                                    "error": type(exc).__name__})
    return {"check": "BFLA_SWEEP", "executed": True, "requests": len(results) * 2, "results": results}


def sqli_probe(url: str, parameter: str, token: str | None = None,
               timeout: float = 5.0) -> dict[str, Any]:
    """Send a single quote-only canary; no timing, stacked, or destructive payloads."""
    # IN PRATICA: Invia un controllo leggero per cercare segnali di errori SQL, senza confermare SQL injection.
    # SICUREZZA: Puo inviare richieste HTTP; verificare scope, identita e autorizzazioni.
    require_loopback(url)
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    markers = ("sql syntax", "sqlite error", "mysql", "postgresql", "odbc", "sqlstate", "ora-")
    try:
        with _client(timeout) as client:
            baseline = client.get(url, params={parameter: "achillesapi_probe"}, headers=headers)
            probe = client.get(url, params={parameter: "'"}, headers=headers)
        body = probe.text[:65536].lower()
        matches = [marker for marker in markers if marker in body]
        suspicious = bool(matches) or (baseline.status_code < 500 <= probe.status_code)
        return {"check": "SQLI_SAFE_PROBE", "parameter": parameter,
                "baseline_status": baseline.status_code, "probe_status": probe.status_code,
                "potential_signal": suspicious, "error_markers": matches,
                "conclusion": "manual_review_required" if suspicious else "no_signal_from_safe_probe",
                "note": "A negative result does not rule out SQL injection; only a non-destructive quote canary was sent."}
    except httpx.HTTPError as exc:
        raise AdvancedCheckError(f"HTTP request failed: {type(exc).__name__}") from exc


def fuzz_query_parameter(url: str, parameter: str, token: str | None = None,
                         timeout: float = 5.0) -> dict[str, Any]:
    """Low-volume GET parameter robustness checks using benign boundary values."""
    # IN PRATICA: Prova alcuni valori non distruttivi per verificare la gestione dei parametri GET.
    # SICUREZZA: Puo inviare richieste HTTP; verificare scope, identita e autorizzazioni.
    require_loopback(url)
    values = ["", "a", "0", "-1", "999999999", "null", "true", " ", "A" * 128]
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    results = []
    with _client(timeout) as client:
        for value in values:
            try:
                response = client.get(url, params={parameter: value}, headers=headers)
                results.append({"value_label": "empty" if value == "" else f"len={len(value)}",
                                "status_code": response.status_code,
                                "response_bytes": len(response.content)})
            except httpx.HTTPError as exc:
                results.append({"value_label": f"len={len(value)}", "error": type(exc).__name__})
            time.sleep(0.1)
    return {"check": "PARAMETER_FUZZ", "parameter": parameter,
            "cases": len(results), "results": results,
            "note": "Benign GET-only values; inspect unusual 5xx responses and validation inconsistencies."}


def mass_assignment_check(url: str, body: dict[str, Any], token: str | None = None,
                          execute: bool = False, timeout: float = 5.0) -> dict[str, Any]:
    """Explicit local-only PATCH probe using only a caller-supplied JSON body."""
    # IN PRATICA: Prepara o invia una PATCH esplicita: la modifica dei dati richiede autorizzazione.
    # SICUREZZA: Puo inviare richieste HTTP; verificare scope, identita e autorizzazioni.
    require_loopback(url)
    if not isinstance(body, dict) or not body:
        raise AdvancedCheckError("Provide a non-empty JSON object with --body-file.")
    if not execute:
        return {"check": "MASS_ASSIGNMENT", "executed": False, "method": "PATCH",
                "target": url, "fields": sorted(body),
                "note": "Dry run: no request sent. Review the supplied fields before --execute."}
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with _client(timeout) as client:
            response = client.patch(url, json=body, headers=headers)
        return {"check": "MASS_ASSIGNMENT", "executed": True, "method": "PATCH",
                "status_code": response.status_code, "submitted_fields": sorted(body),
                "response_bytes": len(response.content),
                "note": "Inspect the resource afterwards to determine whether protected fields changed."}
    except httpx.HTTPError as exc:
        raise AdvancedCheckError(f"HTTP request failed: {type(exc).__name__}") from exc


def inspect_jwt(token: str) -> dict[str, Any]:
    """Decode JWT header/payload offline. Signature and claims are NOT verified."""
    # IN PRATICA: Legge i campi di un JWT senza verificarne firma o autenticità.
    # SICUREZZA: Non contatta direttamente l'API target.
    parts = token.split(".")
    if len(parts) != 3:
        raise AdvancedCheckError("Input is not a compact three-part JWT.")
    def decode(segment: str) -> dict[str, Any]:
        """In pratica: Decodifica una parte del JWT e verifica che sia un oggetto JSON.

    Attenzione: Non contatta direttamente l'API target.
    """
        padded = segment + "=" * (-len(segment) % 4)
        try:
            value = json.loads(base64.urlsafe_b64decode(padded.encode()).decode())
        except Exception as exc:
            raise AdvancedCheckError("JWT contains invalid base64url/JSON.") from exc
        if not isinstance(value, dict):
            raise AdvancedCheckError("JWT header and payload must be JSON objects.")
        return value
    header, claims = decode(parts[0]), decode(parts[1])
    warnings = []
    if header.get("alg", "").lower() == "none":
        warnings.append("alg=none: reject unsigned tokens.")
    if not header.get("kid"):
        warnings.append("No kid header; verify key selection is unambiguous.")
    if "exp" not in claims:
        warnings.append("No exp claim; token lifetime may be unbounded.")
    elif isinstance(claims["exp"], (int, float)):
        if claims["exp"] <= time.time():
            warnings.append("exp is in the past; token appears expired (signature not verified).")
    else:
        warnings.append("exp is not a numeric NumericDate value.")
    if "nbf" in claims and isinstance(claims["nbf"], (int, float)) and claims["nbf"] > time.time():
        warnings.append("nbf is in the future; token is not yet valid according to this unverified claim.")
    if "iss" not in claims:
        warnings.append("No iss claim; validate issuer where applicable.")
    if "aud" not in claims:
        warnings.append("No aud claim; validate audience where applicable.")
    return {"check": "JWT_OFFLINE_INSPECTION", "header": header, "claims": claims,
            "signature_verified": False, "claims_trusted": False, "warnings": warnings,
            "note": "Decoded only. Never treat these claims as authentic without cryptographic and policy validation."}
