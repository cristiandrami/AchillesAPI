"""Offline coverage inventory: opportunities for tests, never fabricated findings.

v0.22 records what can reasonably be tested from a specification. It deliberately
separates *coverage opportunities* from demonstrated vulnerabilities.
"""
from __future__ import annotations

from typing import Any

from achillesapi.models.api import ParsedAPI


def security_inventory(parsed: ParsedAPI, spec: dict[str, Any]) -> dict[str, Any]:
    """Classify each operation into OWASP API Security Top 10 (2023) test areas.

    The mapping is heuristic, uses metadata only, sends no requests and never
    asserts a security defect. Missing explicit role/ownership policy is
    surfaced as a blocker rather than guessed from a resource name.
    """
    result = []
    for ep in parsed.endpoints:
        classes = []
        blockers = []
        parameter_names = {p.name.lower() for p in ep.parameters}
        is_object = bool(ep.path_parameters) or any(
            name.endswith(("id", "ref", "key")) for name in parameter_names)
        if is_object:
            classes.append("API1:2023 Broken Object Level Authorization")
            blockers.append("Known object ownership or a disposable fixture with at least two identities")
        if ep.method in {"POST", "PATCH", "PUT"}:
            classes.append("API3:2023 Broken Object Property Level Authorization")
            blockers.append("Approved test fixture, restricted field policy and cleanup")
        if ep.security and not ep.security_is_explicitly_disabled:
            classes.append("API2:2023 Broken Authentication")
            classes.append("API5:2023 Broken Function Level Authorization")
            blockers.append("Credentials for relevant roles and their expected access policy")
        if ep.method == "GET":
            classes.append("API4:2023 Unrestricted Resource Consumption")
            classes.append("API8:2023 Security Misconfiguration")
        if any(p.location == "query" for p in ep.parameters):
            classes.append("API8:2023 Security Misconfiguration")
        if ep.method in {"POST", "PUT", "PATCH", "DELETE"}:
            blockers.append("Explicit approval for non-idempotent or state-changing tests")
        result.append({"operation": f"{ep.method} {ep.path}",
                       "test_areas": list(dict.fromkeys(classes)),
                       "required_context": list(dict.fromkeys(blockers)),
                       "tested": False, "finding": False})
    areas = sorted({category for item in result for category in item["test_areas"]})
    return {"engine": "security-inventory-v0.22", "network_requests_sent": 0,
            "operations": result, "covered_test_areas": areas,
            "note": "The inventory indicates potential checks only, not verified security defects.",
            "supported_active_checks": ["GET auth contrast", "CORS", "response schema and fields",
                                         "parameter schema constraints", "controlled disposable write workflows"]}
