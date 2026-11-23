"""RC17: multi-round *local* AI planner constrained to deterministic, read-only scanners.

LLM output chooses an allowlisted task, never an HTTP URL, payload, credential,
method, target, or approval. HTTP is performed only through existing scoped engines.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from achillesapi.core.agent_adaptive_v3 import allowed_agent_decisions
from achillesapi.core.active_scanners_rc15 import scan_bounded_get
from achillesapi.core.verification_replay import replay_readonly_indicators
from achillesapi.core.injection_engine_rc5 import injection_assessment
from achillesapi.core.openapi import load_openapi, parse_openapi

_ALLOWED = {"verification_replay", "bounded_get_security", "injection", "authorization"}


def run_adaptive_agent(specification: Path, *, base_url: str,
                       allowed_hosts: set[str], auth: Any = None,
                       path_values: dict[str, str] | None = None,
                       known_findings: list[dict[str, Any]] | None = None,
                       prior_stages: dict[str, dict[str, Any]] | None = None,
                       approved_http: bool = False, execute: bool = False,
                       remaining_requests: int = 0, max_rounds: int = 2,
                       rate: float = 2., allow_insecure_http: bool = False,
                       endpoint: str = "http://127.0.0.1:11434",
                       model: str = "achilles-local",
                       ai_analyzer: Callable[..., dict[str, Any]] | None = None) -> dict[str, Any]:
    """Reassess after each step and stop on unsupported proposals or exhausted budget.

    An injected `ai_analyzer` is for deterministic offline testing; the
    production default is loopback-only analyze_with_ollama.
    """
    if type(max_rounds) is not int or not 1 <= max_rounds <= 3:
        raise ValueError("Agent max rounds must be 1..3")
    if type(remaining_requests) is not int or not 0 <= remaining_requests <= 60:
        raise ValueError("Agent budget must be 0..60")
    if not .1 <= rate <= 5.:
        raise ValueError("Agent rate must be 0.1..5")
    report: dict[str, Any] = {
        "engine": "achilles-local-adaptive-agent-rc17", "version": "1.0.0rc17",
        "executed": False, "status": "disabled", "requests_sent": 0,
        "rounds": [], "actions": [], "findings": [], "results": [], "authorization_review": [],
        "safety": ["only_preexisting_readonly_scanners", "offline_authorization_proposals", "immutable_allowlist",
                   "no_model_generated_http", "no_mutations", "bounded_request_budget",
                   "local_model_only", "no_model_authorizations"],
    }
    if not execute or not approved_http:
        report["status"] = "not_authorized"
        return report
    if remaining_requests < 2:
        report["status"] = "insufficient_budget"
        return report
    # Scope validated before any model or network call, including HTTP policy.
    from achillesapi.core.pipeline_rc13 import _scope
    _scope(base_url, allowed_hosts, allow_insecure_http)
    spec = load_openapi(specification)
    parsed = parse_openapi(spec)
    if ai_analyzer is None:
        from achillesapi.ai.local import analyze_with_ollama
        ai_analyzer = analyze_with_ollama
    findings = list(known_findings or [])[:200]
    stages = prior_stages or {}
    attempted: set[str] = set()
    for round_index in range(max_rounds):
        budget = remaining_requests - report["requests_sent"]
        if budget < 2:
            report["status"] = "budget_exhausted"
            break
        try:
            # Strict local client + sanitizer; no secrets, raw HTTP response or auth passed.
            analysis = ai_analyzer(parsed, findings[:60], endpoint=endpoint, model=model)
            if not isinstance(analysis, dict):
                raise ValueError("Invalid local model result")
            selection = allowed_agent_decisions(analysis,
                available={name: {"available": True} for name in _ALLOWED}, executed={})
            candidate = next((item["task"] for item in selection["selected_tasks"]
                              if item["task"] in _ALLOWED and item["task"] not in attempted), None)
        except (OSError, ValueError, RuntimeError) as exc:
            report["status"] = "local_model_error"
            report["rounds"].append({"round": round_index + 1,
                                      "status": "local_model_error", "error_type": type(exc).__name__})
            break
        if candidate is None:
            report["status"] = "no_new_approved_readonly_task"
            report["rounds"].append({"round": round_index + 1, "status": "no_approved_task",
                                      "suggested_task_count": len(selection["selected_tasks"])})
            break
        attempted.add(candidate)
        quota = min(budget, 12)
        if candidate == "injection" and quota < 3:
            report["status"] = "insufficient_budget"
            break
        row: dict[str, Any] = {"round": round_index + 1, "task": candidate, "quota": quota}
        try:
            if candidate == "authorization":
                from achillesapi.core.authorization_planner_rc21 import build_authorization_plan
                review = build_authorization_plan(spec, max_cases=60)
                # Pure planning: never turn an LLM suggestion into POST/PATCH/DELETE,
                # assumed identity, ownership policy, or arbitrary HTTP.
                report["authorization_review"].append({
                    "round": round_index + 1, "workflows_found": review["workflows_found"],
                    "counts": review["counts"],
                    "unresolved_count": review["unresolved_count"],
                    "status": "requires_operator_policy_and_fixture",
                })
                outcome = {"requests_sent": 0, "findings": [], "results": []}
            elif candidate == "injection":
                outcome = injection_assessment(specification, base_url=base_url,
                    allow_hosts=allowed_hosts, path_values=path_values or {},
                    execute=True, max_requests=quota, rate=rate,
                    allow_insecure_http=allow_insecure_http)
            elif candidate == "bounded_get_security":
                outcome = scan_bounded_get(spec, base_url=base_url,
                    allowed_hosts=allowed_hosts, path_values=path_values,
                    auth=auth, execute=True, max_requests=quota, rate=rate)
            else:
                eligible = [f for f in findings if f.get("source_engine") in {
                    "injection", "agent_injection", "rc15_security"} and
                    isinstance(f.get("test_payloads"), list)]
                outcome = (replay_readonly_indicators(spec, eligible,
                    base_url=base_url, allowed_hosts=allowed_hosts,
                    auth=auth, path_values=path_values,
                    max_requests=min(4, quota), rate=rate) if eligible
                    else {"requests_sent": 0, "results": [], "findings": []})
            used = outcome.get("requests_sent", 0)
            if type(used) is not int or not 0 <= used <= quota:
                raise ValueError("Sub-engine exceeded its request quota")
            report["requests_sent"] += used
            new_findings = [{**finding, "source_engine": "agent_" + candidate,
                             "verification_status": "requires_manual_review"}
                            for finding in outcome.get("findings", []) if isinstance(finding, dict)]
            report["findings"].extend(new_findings)
            findings.extend(new_findings)
            row.update(status="planned_offline" if candidate == "authorization" else
                       "executed" if used else "no_eligible_inputs", requests_sent=used,
                       new_findings=len(new_findings))
            if candidate == "verification_replay":
                # Preserve only metadata necessary for evidence correlation.
                row["replay_results"] = [{"operation": r.get("operation"),
                    "parameter": r.get("parameter"), "status": r.get("status")}
                    for r in outcome.get("results", []) if isinstance(r, dict)]
                report["results"].extend(row["replay_results"])
        except (OSError, ValueError, RuntimeError) as exc:
            row.update(status="engine_error", error_type=type(exc).__name__, requests_sent=0)
            report["rounds"].append(row)
            report["status"] = "engine_error"
            break
        report["rounds"].append(row)
        report["actions"].append(row)
        if row["status"] == "planned_offline":
            # Authorized read-only agent round continues to other scanner
            # recommendations, but does not treat planning as HTTP execution.
            continue
        if row["status"] == "no_eligible_inputs":
            # Don't consume a second AI inference for a task that didn't run.
            report["status"] = "no_eligible_inputs"
            break
    else:
        report["status"] = "max_rounds_reached"
    report["executed"] = any(row.get("status") == "executed" for row in report["actions"])
    return report
