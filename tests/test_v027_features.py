"""Regression tests for conservative v0.24-v0.27 offline capabilities."""
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from achillesapi.cli import app
from achillesapi.core.openapi import analyze_openapi_file
from achillesapi.core.roadmap_v027 import policy_gated_agent, vulnerability_triage, workflow_dependency_map
from achillesapi.reporting.professional import summarize_assessment, write_professional_report


def assessment():
    return {
        "version": "0.27.0", "plan": {"operations": [{"method": "GET", "path": "/thing", "status": "eligible_get", "rendered_path": "/thing"}],
                                  "execution": {"requests_sent": 3}},
        "execution_report": {"observations": [], "findings": [
            {"id": "OBS-1", "category": '<img src=x onerror=alert(1)>',
             "operation": "GET /thing", "severity": "high", "confidence": "indicator",
             "status": "requires_review", "why_flagged": "Observed inconsistent response",
             "evidence": {"status": 200, "Authorization": "Bearer secret", "body": "private user data"}}
        ]},
    }


def test_sanitized_report_drops_body_and_escapes_html(tmp_path):
    src = tmp_path / "assessment.json"
    src.write_text(json.dumps(assessment()), encoding="utf8")
    files = write_professional_report(src, tmp_path / "out")
    assert len(files) == 3
    rendered = (tmp_path / "out/achilles-report.html").read_text()
    assert "&lt;img" in rendered
    assert "<img" not in rendered
    assert "Bearer secret" not in rendered
    assert "private user data" not in rendered
    structured = json.loads((tmp_path / "out/achilles-report.json").read_text())
    assert structured["findings"][0]["status"] == "requires_review"
    assert structured["findings"][0]["confidence"] == "indicator"
    assert structured["findings"][0]["evidence"] == {"status": "200"}


def test_report_refuses_invalid_and_large_data(tmp_path):
    with pytest.raises(ValueError):
        summarize_assessment({"other": {}})
    file = tmp_path / "report.json"
    file.write_text(json.dumps(assessment()))
    with pytest.raises(ValueError):
        write_professional_report(file, tmp_path / "export", ("exe",))


def test_triage_never_upgrades_status():
    result = vulnerability_triage(assessment())
    assert result["candidate_count"] == 1
    assert result["confirmed_vulnerabilities"] == 0
    assert result["review_queue"][0]["status"] == "manual_validation_required"


def test_workflow_map_is_offline():
    parsed = analyze_openapi_file(Path("labs/independent_api/openapi.json"))
    result = workflow_dependency_map(parsed)
    assert result["network_requests_sent"] == 0
    assert all(not x["executable"] for x in result["candidate_dependencies"])


def test_agent_fails_closed_on_bad_input():
    parsed = analyze_openapi_file(Path("labs/independent_api/openapi.json"))
    with pytest.raises(ValueError):
        policy_gated_agent(parsed, assessment(), budget=21)
    result = policy_gated_agent(parsed, assessment(), budget=2)
    assert result["model_permissions"]["may_execute"] is False
    assert result["network_requests_sent"] == 0


def test_cli_report_and_offline_commands(tmp_path):
    runner = CliRunner()
    input_path = tmp_path / "assessment.json"
    input_path.write_text(json.dumps(assessment()), encoding="utf8")
    out = tmp_path / "report"
    result = runner.invoke(app, ["report", str(input_path), "--output-dir", str(out)])
    assert result.exit_code == 0, result.output
    assert (out / "achilles-report.md").exists()
    result = runner.invoke(app, ["vulnerability-triage", str(input_path), "--output", str(tmp_path / "triage.json")])
    assert result.exit_code == 0, result.output
    result = runner.invoke(app, ["workflow-map", "labs/independent_api/openapi.json", "--output", str(tmp_path / "workflows.json")])
    assert result.exit_code == 0, result.output
    result = runner.invoke(app, ["ai-prioritize", "labs/independent_api/openapi.json", str(input_path), "--output", str(tmp_path / "agent.json")])
    assert result.exit_code == 0, result.output


def test_pdf_is_optional_and_generates(tmp_path):
    pytest.importorskip("reportlab")
    source = tmp_path / "assessment.json"
    source.write_text(json.dumps(assessment()), encoding="utf8")
    [pdf] = write_professional_report(source, tmp_path / "out", ("pdf",))
    assert pdf.read_bytes().startswith(b"%PDF-")


def test_workflow_map_resolves_local_response_schema():
    from achillesapi.models.api import ParsedAPI, EndpointInfo
    api = ParsedAPI(title="Independent", version="1", openapi_version="3.0.3", endpoints=[
        EndpointInfo(path="/records", method="POST", responses={"201": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Record"}}}}}),
        EndpointInfo(path="/records/{record_ref}", method="GET", responses={"200": {"description": "OK"}}),
    ])
    spec = {"components": {"schemas": {"Record": {"type": "object", "properties": {"record_ref": {"type": "string"}}}}}}
    result = workflow_dependency_map(api, spec)
    assert len(result["candidate_dependencies"]) == 1
    assert result["candidate_dependencies"][0]["producer"] == "POST /records"
    assert result["candidate_dependencies"][0]["executable"] is False
