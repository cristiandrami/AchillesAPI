from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from achillesapi.cli import app

runner = CliRunner()
EXAMPLES = Path(__file__).parents[1] / "examples"


def test_scan_without_ai_is_passive_and_writes_report(tmp_path: Path) -> None:
    output = tmp_path / "scan.json"
    result = runner.invoke(app, ["scan", str(EXAMPLES / "sample_api.yaml"), "--output", str(output)])
    assert result.exit_code == 0, result.output
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["scan_type"] == "passive_openapi_only"
    assert report["target_requests_sent"] == 0
    assert report["ai_analysis"] is None


def test_ai_analyze_rejects_remote_endpoint() -> None:
    result = runner.invoke(app, [
        "ai-analyze", str(EXAMPLES / "sample_api.yaml"),
        "--endpoint", "https://example.com",
    ])
    assert result.exit_code == 1
    assert "only http" in result.output
