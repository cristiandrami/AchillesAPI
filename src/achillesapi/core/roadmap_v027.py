"""v0.25–v0.27 offline triage, dependency inventory and policy-gated follow-ups.

These functions do not issue network requests. They deliberately reject any
attempt to treat model text or arbitrary observations as executable HTTP input.
"""
from __future__ import annotations

from collections import Counter
from typing import Any
import re

from achillesapi.models.api import ParsedAPI
from achillesapi.core.orchestrator import choose_followups

_PATH_VAR = re.compile(r"\{([^{}]+)\}")


def workflow_dependency_map(parsed: ParsedAPI, spec: dict[str, Any] | None = None) -> dict[str, Any]:
    """Propose links between path placeholders and declared response properties.

    This is a *hypothesis inventory*, not runnable credentials/fixtures. Only
    explicit names already declared by OpenAPI are used; never guess real IDs.
    """
    operations = []
    providers = []
    def resolve(schema: dict[str, Any]) -> dict[str, Any]:
        """Resolve only local component references; never fetch remote schemas."""
        for _ in range(5):
            reference = schema.get("$ref")
            if not isinstance(reference, str) or not reference.startswith("#/components/schemas/") or not isinstance(spec, dict):
                break
            name = reference.rsplit("/", 1)[-1]
            schema = spec.get("components", {}).get("schemas", {}).get(name, {})
            if not isinstance(schema, dict):
                return {}
        return schema

    for endpoint in parsed.endpoints:
        op = f"{endpoint.method} {endpoint.path}"
        variables = _PATH_VAR.findall(endpoint.path)
        declared_responses = endpoint.responses if isinstance(endpoint.responses, dict) else {}
        for status, response in declared_responses.items():
            if not str(status).startswith("2") or not isinstance(response, dict):
                continue
            content = response.get("content", {})
            if not isinstance(content, dict):
                continue
            for media in content.values():
                if not isinstance(media, dict):
                    continue
                schema = media.get("schema", {})
                if not isinstance(schema, dict):
                    continue
                schema = resolve(schema)
                properties = schema.get("properties", {})
                if isinstance(properties, dict):
                    for field in properties:
                        providers.append((op, field))
        operations.append({"operation": op, "method": endpoint.method,
                           "path_inputs": variables,
                           "requires_fixture_review": endpoint.method != "GET",
                           "ready_without_ids": not variables})
    dependencies = []
    seen = set()
    for item in operations:
        for variable in item["path_inputs"]:
            for provider_op, field in providers:
                if field.lower().replace("_", "") != variable.lower().replace("_", ""):
                    continue
                if provider_op == item["operation"]:
                    continue
                key = (provider_op, item["operation"], variable)
                if key in seen:
                    continue
                seen.add(key)
                dependencies.append({"producer": provider_op, "consumer": item["operation"],
                                     "variable": variable, "response_field": field,
                                     "confidence": "name_match_only", "executable": False,
                                     "blocker": "Provide an authorized fixture or reviewed JSON Pointer."})
    return {"engine": "offline-dependency-map-v0.26", "operations": operations,
            "candidate_dependencies": dependencies[:250], "network_requests_sent": 0,
            "limitations": ["Name matches do not prove dataflow.",
                            "Cross-resource writes require explicit setup and cleanup."]}


def vulnerability_triage(assessment: dict[str, Any]) -> dict[str, Any]:
    """Classify existing observations by review needs, never synthesize findings."""
    execution = assessment.get("execution_report") or {}
    findings = [x for x in execution.get("findings", []) if isinstance(x, dict)] if isinstance(execution, dict) else []
    categories = Counter(str(x.get("category", "unknown")) for x in findings)
    review = []
    for finding in findings:
        review.append({"id": str(finding.get("id", "unknown"))[:60],
                       "category": str(finding.get("category", "unknown"))[:100],
                       "status": "manual_validation_required",
                       "recommended_validation": (
                           "Compare authorized vs unauthorized identities with a documented ownership rule."
                           if "bola" in str(finding.get("category", "")).lower() or "authorization" in str(finding.get("category", "")).lower()
                           else "Repeat with a safe negative control and inspect full evidence privately."
                       )})
    return {"engine": "evidence-triage-v0.25", "candidate_count": len(findings),
            "categories": dict(categories), "review_queue": review,
            "confirmed_vulnerabilities": 0,
            "note": "No heuristic observation is automatically a proven vulnerability."}


def policy_gated_agent(parsed: ParsedAPI, assessment: dict[str, Any], budget: int = 3) -> dict[str, Any]:
    """Select explainable repeat-GET candidates already supported by the safe engine.

    An external LLM may provide advice in another report field, but its text
    is never used as a URL, method, request body, or permission to send traffic.
    """
    if not 0 <= budget <= 20:
        raise ValueError("Agent budget must be 0..20")
    plan = assessment.get("plan")
    execution = assessment.get("execution_report")
    if not isinstance(plan, dict):
        raise ValueError("Assessment needs an OpenAPI-derived plan")
    observations = execution.get("observations", []) if isinstance(execution, dict) else []
    if not isinstance(observations, list):
        raise ValueError("Observations must be a list")
    proposals = choose_followups(parsed, plan, observations, budget=budget)
    proposals["model_permissions"] = {"may_propose": True, "may_execute": False,
                                       "may_expand_scope": False, "may_confirm_findings": False}
    proposals["vulnerability_triage"] = vulnerability_triage(assessment)
    return proposals
