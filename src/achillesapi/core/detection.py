"""Deterministic, secret-conscious analysis of captured HTTP response evidence.

This module is offline: it never sends requests and never copies response bodies
or header values that may contain secrets into the resulting report.
"""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from typing import Any


class EvidenceAnalysisError(ValueError):
    """Raised when an evidence bundle does not match the supported schema."""


_ERROR_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("SQL_ERROR", r"\b(sql syntax|sqlite error|mysql_fetch|sqlstate|ora-\d{4,5}|postgresql.*error)\b", "high"),
    ("STACK_TRACE", r"(traceback \(most recent call last\)|\bat [\w.$]+\([^\n]+:\d+\)|stack trace:)", "medium"),
    ("DEBUG_DISCLOSURE", r"(debug toolbar|werkzeug debugger| django settings module|asp\.net yellow screen)", "medium"),
)


def _headers(value: Any) -> dict[str, str]:
    """In pratica: Normalizza i nomi degli header per confrontarli senza differenze di maiuscole.

    Attenzione: Non contatta direttamente l'API target.
    """
    if not isinstance(value, dict):
        return {}
    return {str(k).strip().lower(): str(v).strip() for k, v in value.items()}


def _finding(code: str, title: str, severity: str, confidence: str,
             endpoint: str, evidence: list[str], recommendation: str,
             fingerprint: str) -> dict[str, Any]:
    """In pratica: Prepara un singolo rilievo passivo con dati e severità.

    Attenzione: Non contatta direttamente l'API target.
    """
    return {"finding_id": code, "title": title, "category": code.split("-")[0],
            "severity": severity, "confidence": confidence, "status": "needs_review",
            "endpoint": endpoint, "evidence": evidence,
            "recommendation": recommendation, "fingerprint": fingerprint}


def analyze_response_evidence(bundle: dict[str, Any]) -> dict[str, Any]:
    """Analyze captured responses without network access or retaining sensitive values.

    Input format: {"responses": [{"method", "path", "status_code", "headers",
    "body_preview", "url"?}, ...]}. Bodies are inspected in memory only; reports
    contain marker names and lengths, never body excerpts or raw header values.
    """
    # IN PRATICA: Analizza evidenze HTTP già raccolte: non genera traffico.
    # SICUREZZA: Non contatta direttamente l'API target.
    if not isinstance(bundle, dict) or not isinstance(bundle.get("responses"), list):
        raise EvidenceAnalysisError("Evidence file must contain a 'responses' array.")
    if len(bundle["responses"]) > 1000:
        raise EvidenceAnalysisError("Evidence bundle exceeds the 1000-response analysis limit.")

    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    status_counts: defaultdict[str, int] = defaultdict(int)
    analyzed = 0
    for index, item in enumerate(bundle["responses"]):
        if not isinstance(item, dict):
            raise EvidenceAnalysisError(f"responses[{index}] must be an object.")
        method = str(item.get("method", "GET")).upper()
        path = str(item.get("path", item.get("url", "unknown")))[:512]
        status = item.get("status_code")
        if not isinstance(status, int) or not 100 <= status <= 599:
            raise EvidenceAnalysisError(f"responses[{index}].status_code must be an HTTP status integer.")
        headers = _headers(item.get("headers", {}))
        body = item.get("body_preview", "")
        if not isinstance(body, str):
            body = ""
        body_sample = body[:65536]
        analyzed += 1
        status_counts[str(status)] += 1
        endpoint = f"{method} {path}"
        digest = hashlib.sha256(endpoint.encode()).hexdigest()[:12]

        def add(code: str, title: str, severity: str, confidence: str,
                evidence: list[str], recommendation: str) -> None:
            """In pratica: Aggiunge un'indicazione al report di analisi delle evidenze.

    Attenzione: Questa funzione non contatta direttamente l'API target.
    """
            key = f"{code}:{digest}"
            if key in seen:
                return
            seen.add(key)
            findings.append(_finding(code, title, severity, confidence, endpoint,
                                     evidence, recommendation, key))

        allow_origin = headers.get("access-control-allow-origin", "")
        allow_credentials = headers.get("access-control-allow-credentials", "").lower()
        if allow_origin == "*" and allow_credentials == "true":
            add("CORS-001", "Wildcard CORS origin combined with credential allowance", "high", "high",
                ["Access-Control-Allow-Origin is wildcard and Access-Control-Allow-Credentials is true."],
                "Use an explicit origin allowlist; never combine wildcard origin with credentialed access.")

        if status >= 500:
            add("HTTP-001", "Server-side error response observed", "low", "high",
                [f"HTTP {status} was returned for this captured request."],
                "Review server logs and verify that errors are handled consistently without exposing internals.")

        content_type = headers.get("content-type", "").lower()
        if "text/html" in content_type:
            for header, code, title, recommendation in (
                ("content-security-policy", "HDR-001", "HTML response lacks Content-Security-Policy",
                 "Define a restrictive Content-Security-Policy appropriate to the application."),
                ("x-content-type-options", "HDR-002", "HTML response lacks X-Content-Type-Options",
                 "Set X-Content-Type-Options: nosniff."),
                ("referrer-policy", "HDR-003", "HTML response lacks Referrer-Policy",
                 "Set a deliberate Referrer-Policy, such as strict-origin-when-cross-origin."),
            ):
                if header not in headers:
                    add(code, title, "low", "medium", [f"Missing response header: {header}."], recommendation)

        if "https://" in str(item.get("url", "")).lower() and "strict-transport-security" not in headers:
            add("HDR-004", "HTTPS response lacks Strict-Transport-Security", "low", "medium",
                ["Strict-Transport-Security header was not present in captured HTTPS response."],
                "Configure HSTS after validating HTTPS coverage and subdomain readiness.")

        server = headers.get("server", "")
        powered = headers.get("x-powered-by", "")
        if server or powered:
            names = [name for name, val in (("Server", server), ("X-Powered-By", powered)) if val]
            add("DISC-001", "Technology-identifying response headers are exposed", "info", "high",
                [f"Technology disclosure header(s) present: {', '.join(names)}; values intentionally omitted."],
                "Remove unnecessary technology-identifying headers or minimize their detail.")

        body_lower = body_sample.lower()
        for marker, pattern, severity in _ERROR_PATTERNS:
            if re.search(pattern, body_lower, re.IGNORECASE):
                add(f"LEAK-{marker}", "Response body contains an internal error disclosure marker",
                    severity, "medium", [f"Detected marker: {marker}; response body was not stored."],
                    "Return generic client errors and keep stack traces, SQL errors and debug details in protected logs.")

    findings.sort(key=lambda x: ({"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x["severity"], 5), x["finding_id"], x["endpoint"]))
    return {"schema_version": "1.0", "analysis": "offline_response_evidence",
            "executed_requests": 0, "responses_analyzed": analyzed,
            "status_counts": dict(sorted(status_counts.items())),
            "summary": {"finding_count": len(findings),
                        "by_severity": {level: sum(f["severity"] == level for f in findings)
                                        for level in ("critical", "high", "medium", "low", "info")}},
            "findings": findings,
            "limitations": ["Captured evidence may be incomplete or sanitized.",
                            "Findings are indicators requiring manual validation, not confirmed vulnerabilities.",
                            "No response body or raw header values are persisted in this report."]}
