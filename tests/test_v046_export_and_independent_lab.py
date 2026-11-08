"""Regression: all supported tool outputs export safely, plus independent fixtures."""
import json
from pathlib import Path
from fastapi.testclient import TestClient
from achillesapi.reporting.professional import write_professional_report


def test_all_job_shapes_export_html_pdf_md_json(tmp_path: Path):
    reports = [
        {"engine": "security-inventory-v0.22", "operations": [{"operation": "GET /x"}], "requests_sent": 0},
        {"engine": "deterministic-agent", "stop_reason": "no_supported_actions", "actions": []},
        {"engine": "ai-ranking", "executive_summary": "UNTRUSTED-SECRET", "actions": []},
        {"plan": {"operations": [{"path": "/x", "status": "eligible_get"}]}, "execution_report": {"requests_sent": 2}},
        {"execution_report": {"findings": [{"category": "CORS", "operation": "GET /test"}]}, "requests_sent": 1},
        {"report_schema": "achillesapi.professional.1", "summary": {"operations_in_spec": 2}},
        {"unexpected": "<script>alert(1)</script>"},
    ]
    for i, source in enumerate(reports):
        path = tmp_path / f"source-{i}.json"
        path.write_text(json.dumps(source))
        files = write_professional_report(path, tmp_path / f"out-{i}", ("json", "html", "md", "pdf"))
        assert len(files) == 4
        assert files[-1].read_bytes().startswith(b"%PDF")
        html = files[1].read_text()
        assert "<script>alert(1)</script>" not in html
        assert "UNTRUSTED-SECRET" not in html
        report = json.loads(files[0].read_text())
        assert report["source_kind"]
        assert "report_schema" in report

