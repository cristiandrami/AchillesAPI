import json
from pathlib import Path

from typer.testing import CliRunner

from achillesapi.cli import app

EXAMPLES = Path(__file__).parents[1] / "examples"
runner = CliRunner()


def test_map_api_cli_exports_json(tmp_path: Path) -> None:
    output = tmp_path / "graph.json"
    result = runner.invoke(
        app,
        ["map-api", str(EXAMPLES / "sample_api.yaml"), "--output", str(output)],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["nodes"]
    assert payload["edges"]


def test_http_get_cli_is_dry_run_by_default() -> None:
    result = runner.invoke(
        app,
        ["http-get", "https://api.example.test/health", "--allow-host", "api.example.test"],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["executed"] is False
    assert payload["response"] is None
