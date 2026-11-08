"""Deterministic passive checks over the normalized API description."""

from __future__ import annotations

import re
from typing import Any

from achillesapi.models.api import EndpointInfo, ParsedAPI
from achillesapi.models.evidence import AssessmentFinding

_SENSITIVE_NAMES = re.compile(
    r"password|passwd|secret|token|api[_-]?key|ssn|social.?security|credit.?card|"
    r"card.?number|cvv|date.?of.?birth|dob|email|phone", re.IGNORECASE
)


def _finding(
    endpoint: EndpointInfo,
    category: str,
    title: str,
    severity: str,
    confidence: str,
    evidence: list[str],
    recommendation: str,
) -> AssessmentFinding:
    """In pratica: Prepara un singolo rilievo passivo con dati e severità.

    Attenzione: Non contatta direttamente l'API target.
    """
    return AssessmentFinding(
        finding_id=f"{category}:{endpoint.method}:{endpoint.path}",
        title=title,
        category=category,
        severity=severity,
        confidence=confidence,
        endpoint=f"{endpoint.method} {endpoint.path}",
        evidence=evidence,
        recommendation=recommendation,
    )


def assess_api(parsed: ParsedAPI) -> list[AssessmentFinding]:
    """Generate hypotheses from OpenAPI metadata; no HTTP traffic is generated."""
    # IN PRATICA: Cerca indizi di possibili problemi nella specifica, senza contattare l'API.
    # SICUREZZA: Non contatta direttamente l'API target.
    findings: list[AssessmentFinding] = []
    for endpoint in parsed.endpoints:
        if endpoint.security_is_explicitly_disabled:
            findings.append(_finding(
                endpoint, "AUTH-001", "Operation explicitly disables security", "medium", "high",
                ["The operation declares security: [] in OpenAPI."],
                (
                    "Confirm that the operation is intentionally public and enforce authorization "
                    "at the service layer where required."
                ),
            ))
        elif not endpoint.security:
            findings.append(_finding(
                endpoint, "AUTH-002", "No security requirement declared", "low", "medium",
                [
                    "No operation-level or inherited security requirement was found "
                    "in the parsed specification."
                ],
                (
                    "Verify whether the endpoint is intentionally unauthenticated; "
                    "document and test the intended access policy."
                ),
            ))

        id_parameters = [
            parameter.name
            for parameter in endpoint.path_parameters
            if re.search(r"(id|uuid|key)$", parameter.name, re.I)
        ]
        if id_parameters and endpoint.method in {"GET", "PUT", "PATCH", "DELETE"}:
            findings.append(_finding(
                endpoint,
                "AUTHZ-001",
                "Object-level authorization review candidate (BOLA)",
                "medium",
                "medium",
                [f"Path contains object-identifier candidate(s): {', '.join(id_parameters)}.",
                 "The HTTP method can access or modify an individual resource."],
                (
                    "Test with two authorized principals and verify that changing the object "
                    "identifier never exposes or modifies another user's object."
                ),
            ))

        response_properties: set[str] = set()
        for response in endpoint.responses.values():
            if not isinstance(response, dict):
                continue
            content = response.get("content", {})
            if not isinstance(content, dict):
                continue
            for media in content.values():
                schema = media.get("schema", {}) if isinstance(media, dict) else {}
                properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
                if isinstance(properties, dict):
                    response_properties.update(str(name) for name in properties)
        sensitive = sorted(name for name in response_properties if _SENSITIVE_NAMES.search(name))
        if sensitive:
            findings.append(_finding(
                endpoint,
                "DATA-001",
                "Potentially sensitive response properties",
                "medium",
                "medium",
                [f"Response schema exposes property name(s): {', '.join(sensitive)}."],
                (
                    "Confirm that each property is required by the caller and apply field-level "
                    "authorization and data minimization."
                ),
            ))

        request_properties: set[str] = set()
        body = endpoint.request_body or {}
        content = body.get("content", {}) if isinstance(body, dict) else {}
        if isinstance(content, dict):
            for media in content.values():
                schema = media.get("schema", {}) if isinstance(media, dict) else {}
                properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
                if isinstance(properties, dict):
                    request_properties.update(str(name) for name in properties)
        writable_sensitive = sorted(
            name for name in request_properties if _SENSITIVE_NAMES.search(name)
        )
        if writable_sensitive:
            findings.append(_finding(
                endpoint,
                "DATA-002",
                "Sensitive writable properties need field-level review",
                "medium",
                "low",
                [
                    "Request schema accepts potentially sensitive property name(s): "
                    f"{', '.join(writable_sensitive)}."
                ],
                (
                    "Verify server-side property allowlisting; do not rely on client-side "
                    "field filtering."
                ),
            ))
    return findings


def assessment_to_dict(findings: list[AssessmentFinding]) -> dict[str, Any]:
    """In pratica: Trasforma i risultati passivi in un dizionario pronto per il JSON.

    Attenzione: Non contatta direttamente l'API target.
    """
    return {
        "status": "passive_hypotheses",
        "confirmed_vulnerabilities": 0,
        "findings": [finding.model_dump(mode="json") for finding in findings],
        "note": "Findings are specification-based hypotheses and require authorized validation.",
    }
