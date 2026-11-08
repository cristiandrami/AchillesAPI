"""Conservative, bounded scanner-finding bridge for offline AI and exports.

This module never replays network traffic, stores raw bodies/headers, or upgrades
scanner observations into verified vulnerabilities.
"""
from __future__ import annotations

import re
from typing import Any

from achillesapi.ai.sanitizer import redact_text

_CATEGORY = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,80}$")
_OPERATION = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) (/[\w./{}~-]{0,300})$")
_SEVERITIES = {"critical", "high", "medium", "low", "info", "informational"}
_BOOL_FLAGS = (
    "arbitrary_origin_reflected", "allow_credentials", "cache_control_public",
    "origin_reflected", "cors_credentials_allowed", "truncated", "repeated",
)
_CHECKED_LABELS = {
    "cors_credentialed_origin_reflection": "Arbitrary Origin reflection and credential allowance observed in the same response.",
    "write_only_property_returned": "A field declared writeOnly was observed in an HTTP response.",
    "AUTHORIZATION_POLICY_MISMATCH": "The response status conflicts with an operator-supplied authorization expectation.",
    "authenticated_public_cache": "An authenticated response allows public caching.",
    "technology_disclosure": "Technology-identifying response headers were present.",
    "response_contract_mismatch": "The observed response differs from the declared OpenAPI schema.",
    "error_disclosure": "An internal error signature was detected in a response.",
    "sensitive_property_review": "A sensitive-name response property warrants permission review.",
    "unauthenticated_access_review": "Access was observed without the expected authentication context.",
}


def _entry(source: dict[str, Any]) -> dict[str, Any] | None:
    category = source.get("category")
    operation = source.get("operation", source.get("endpoint"))
    if not isinstance(category, str) or not _CATEGORY.fullmatch(category):
        return None
    if not isinstance(operation, str) or not _OPERATION.fullmatch(operation):
        return None
    severity = source.get("severity", "informational")
    if severity not in _SEVERITIES:
        severity = "informational"
    evidence = source.get("evidence")
    evidence = evidence if isinstance(evidence, dict) else {}
    safe_evidence: dict[str, Any] = {}
    for name in _BOOL_FLAGS:
        if type(evidence.get(name)) is bool:
            safe_evidence[name] = evidence[name]
    for field in ("status", "observed_status", "expected_status"):
        value = evidence.get(field, source.get(field))
        if type(value) is int and 100 <= value <= 599:
            safe_evidence[field] = value
    # Property *names* can be sensitive. Only export the number, never values or names.
    if type(evidence.get("property_count")) is int and 0 <= evidence["property_count"] <= 100:
        safe_evidence["property_count"] = evidence["property_count"]
    elif isinstance(evidence.get("property_paths"), list):
        safe_evidence["property_count"] = min(len(evidence["property_paths"]), 100)
    if isinstance(evidence.get("signatures"), list):
        permitted = {"SQL_ERROR", "STACK_TRACE", "DEBUG_DISCLOSURE"}
        safe_evidence["signature_classes"] = sorted(set(evidence["signatures"]) & permitted)
    expected = source.get("expected")
    if expected in ("allow", "deny"):
        safe_evidence["expected_access"] = expected
    reason = _CHECKED_LABELS.get(category)
    if not reason:
        # Free-form descriptions are not shared: they may contain credentials or PII.
        reason = "Review the scanner observation and validate it against the intended policy."
    return {
        "category": category,
        "operation": operation,
        "severity": severity,
        "confidence": "indicator",
        "status": "requires_review",
        "reason": reason,
        "evidence": safe_evidence,
        "verified": False,
    }


def scanner_findings(document: dict[str, Any], *, max_findings: int = 200) -> list[dict[str, Any]]:
    """Preserve original scanner signals from assessments and professional exports."""
    if not isinstance(document, dict):
        return []
    lists: list[list[Any]] = []
    if document.get("report_schema") == "achillesapi.professional.2":
        if isinstance(document.get("findings"), list):
            lists.append(document["findings"])
    else:
        exec_report = document.get("execution_report")
        if isinstance(exec_report, dict) and isinstance(exec_report.get("findings"), list):
            lists.append(exec_report["findings"])
        for section in ("multi_resource_execution", "workflow_execution"):
            part = document.get(section)
            if isinstance(part, dict):
                if isinstance(part.get("findings"), list):
                    lists.append(part["findings"])
                if section == "workflow_execution" and isinstance(part.get("workflows"), list):
                    for w in part["workflows"]:
                        if isinstance(w, dict) and isinstance(w.get("findings"), list):
                            lists.append(w["findings"])
    seen: set[tuple[str, str, str]] = set()
    results: list[dict[str, Any]] = []
    for items in lists:
        for item in items:
            if not isinstance(item, dict):
                continue
            entry = _entry(item)
            if entry is None:
                continue
            key = (entry["category"], entry["operation"], str(entry["evidence"]))
            if key in seen:
                continue
            seen.add(key)
            results.append(entry)
            if len(results) >= max_findings:
                return results
    return results
