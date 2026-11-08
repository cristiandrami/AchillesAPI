"""Multi-principal authorization comparison for explicitly authorized loopback labs.

The engine records metadata and structural differences only: response bodies and
credential material are never written to evidence. Differences are triage signals,
not vulnerability verdicts, because the intended authorization policy is external.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from urllib.parse import quote

import httpx

from achillesapi.core.advanced import AdvancedCheckError, require_loopback
from achillesapi.core.auth import AuthenticationMaterial


def _render_path(base: str, path: str, values: dict[str, str]) -> str:
    """In pratica: Sostituisce i segnaposto del percorso con i valori di test forniti.

    Attenzione: Non contatta direttamente l'API target.
    """
    def replace(match: re.Match[str]) -> str:
        """In pratica: Esegue la fase 'replace' del modulo authorization.

    Attenzione: Non contatta direttamente l'API target.
    """
        key = match.group(1)
        if key not in values:
            raise AdvancedCheckError(f"Missing --path-value for {{{key}}}.")
        return quote(values[key], safe="")
    return base + re.sub(r"\{([^{}]+)\}", replace, path)


def _field_paths(value: Any, prefix: str = "") -> set[str]:
    """In pratica: Estrae i nomi dei campi di una risposta JSON per confrontarne la visibilità.

    Attenzione: Non contatta direttamente l'API target.
    """
    fields: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            fields.add(path)
            fields.update(_field_paths(child, path))
    elif isinstance(value, list):
        array_prefix = prefix + "[]"
        fields.add(array_prefix)
        for child in value[:20]:
            fields.update(_field_paths(child, array_prefix))
    return fields


def _response_metadata(response: httpx.Response) -> dict[str, Any]:
    """In pratica: Estrae dati delle risposte utili alla matrice senza dichiarare automaticamente vulnerabilità.

    Attenzione: Non contatta direttamente l'API target.
    """
    raw = response.content[:262144]
    try:
        parsed = response.json()
        fields = sorted(_field_paths(parsed))
        is_json = True
    except (ValueError, json.JSONDecodeError):
        fields = []
        is_json = False
    return {
        "status_code": response.status_code,
        "content_type": response.headers.get("content-type", "").split(";")[0],
        "response_bytes": len(response.content),
        "response_sha256_prefix": hashlib.sha256(raw).hexdigest()[:16],
        "json": is_json,
        "field_paths": fields,
    }


def authorization_matrix(
    spec: dict[str, Any],
    base_url: str,
    profiles: dict[str, AuthenticationMaterial],
    path_values: dict[str, str],
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Compare GET response access and JSON property visibility across profiles."""
    # IN PRATICA: Confronta le risposte ottenute con identità diverse nel motore legacy.
    # SICUREZZA: Puo inviare richieste HTTP; verificare scope, identita e autorizzazioni.
    base = require_loopback(base_url)
    if len(profiles) < 2:
        raise AdvancedCheckError("At least two distinct authentication profiles are required.")
    if len(profiles) > 10:
        raise AdvancedCheckError("A maximum of 10 profiles is allowed per matrix run.")
    if any(not name.strip() for name in profiles):
        raise AdvancedCheckError("Profile names cannot be empty.")

    endpoints: list[dict[str, Any]] = []
    request_count = 0
    with httpx.Client(timeout=timeout, follow_redirects=False, verify=True,
                      headers={"User-Agent": "AchillesAPI/0.7.0 (authorized-local-assessment)"}) as client:
        for path, item in (spec.get("paths") or {}).items():
            if not isinstance(item, dict):
                continue
            for method, operation in item.items():
                if method.lower() != "get" or not isinstance(operation, dict):
                    continue
                url = _render_path(base, path, path_values)
                principals: dict[str, Any] = {}
                for name, auth in profiles.items():
                    try:
                        response = client.get(url, headers=auth.headers, params=auth.params,
                                              cookies=auth.cookies)
                        principals[name] = _response_metadata(response)
                    except httpx.HTTPError as exc:
                        principals[name] = {"request_error": type(exc).__name__}
                    request_count += 1
                successful = {
                    name: result for name, result in principals.items()
                    if "status_code" in result and result["json"]
                }
                field_sets = {name: set(result["field_paths"]) for name, result in successful.items()}
                all_fields = set().union(*field_sets.values()) if field_sets else set()
                visibility = []
                for field in sorted(all_fields):
                    visible_to = sorted(name for name, fields in field_sets.items() if field in fields)
                    if len(visible_to) != len(profiles):
                        visibility.append({"field": field, "visible_to": visible_to,
                                           "not_visible_to": sorted(set(profiles) - set(visible_to)),
                                           "status": "property_visibility_difference_review"})
                endpoints.append({
                    "method": "GET", "path": path,
                    "operation_id": operation.get("operationId"),
                    "principals": principals,
                    "property_visibility_differences": visibility,
                    "status": "response_or_property_difference_review" if visibility or
                              len({v.get("status_code") for v in principals.values()}) > 1
                              else "no_structural_difference_detected",
                })
    return {
        "check": "AUTHORIZATION_ROLE_MATRIX",
        "executed": True,
        "profiles": list(profiles),
        "requests": request_count,
        "endpoint_count": len(endpoints),
        "endpoints": endpoints,
        "limitations": [
            "GET operations only; no state-changing requests are sent.",
            "Response differences and property visibility are review signals, not confirmed BFLA/BOPLA findings.",
            "Only JSON property names and response fingerprints are retained; response values and credentials are omitted.",
            "The engine does not infer the intended role policy or object ownership.",
        ],
    }
