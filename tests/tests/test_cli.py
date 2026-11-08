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


def test_bola_check_cli_is_dry_run_without_credentials_or_network() -> None:
    result = runner.invoke(
        app,
        ["bola-check", "http://127.0.0.1:8000/api/orders/order-bob"],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["executed"] is False
    assert payload["planned_requests"] == 2


def test_auth_profiles_cli_lists_profiles_without_secrets(tmp_path: Path) -> None:
    config = tmp_path / "auth.yaml"
    config.write_text(
        "profiles:\n  - name: alice\n    type: bearer\n    token_env: ACHILLES_TEST_TOKEN\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["auth-profiles", "--config", str(config)])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["profiles"][0]["name"] == "alice"
    assert "ACHILLES_TEST_TOKEN" in payload["profiles"][0]["environment_variables"]
    assert "secret" not in result.stdout.lower()


def test_http_get_requires_both_auth_options() -> None:
    result = runner.invoke(
        app,
        ["http-get", "https://api.example.test/health", "--allow-host", "api.example.test",
         "--auth-profile", "alice"],
    )
    assert result.exit_code == 1
    assert "must be supplied together" in result.output


def test_bola_sweep_accepts_two_bearer_profiles(tmp_path: Path, monkeypatch) -> None:
    import achillesapi.cli as cli_module

    config = tmp_path / "auth.yaml"
    config.write_text(
        "profiles:\n"
        "  - name: owner\n    type: bearer\n    token_env: TEST_OWNER_TOKEN\n"
        "  - name: other\n    type: bearer\n    token_env: TEST_OTHER_TOKEN\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("TEST_OWNER_TOKEN", "owner-secret")
    monkeypatch.setenv("TEST_OTHER_TOKEN", "other-secret")
    captured = {}

    def fake_sweep(spec, base_url, owner_token, other_token, path_values, timeout):
        captured.update(owner=owner_token, other=other_token, path_values=path_values)
        return {"check": "BOLA_SWEEP", "executed": False, "results": []}

    monkeypatch.setattr(cli_module, "bola_sweep", fake_sweep)
    result = runner.invoke(app, [
        "bola-sweep", str(EXAMPLES / "local_bola_lab_openapi.json"),
        "--base-url", "http://127.0.0.1:8000",
        "--auth-config", str(config), "--owner-profile", "owner", "--other-profile", "other",
        "--path-value", "order_id=order-bob",
    ])
    assert result.exit_code == 0, result.output
    assert captured == {
        "owner": "owner-secret", "other": "other-secret", "path_values": {"order_id": "order-bob"}
    }


def test_bola_sweep_requires_complete_profile_selection(tmp_path: Path) -> None:
    config = tmp_path / "auth.yaml"
    config.write_text("profiles: []\n", encoding="utf-8")
    result = runner.invoke(app, [
        "bola-sweep", str(EXAMPLES / "local_bola_lab_openapi.json"),
        "--base-url", "http://127.0.0.1:8000", "--auth-config", str(config),
        "--owner-profile", "alice",
    ])
    assert result.exit_code == 1
    assert "must be supplied together" in result.output


def test_role_matrix_requires_multiple_profiles():
    result = runner.invoke(app, [
        "role-matrix", str(EXAMPLES / "local_bola_lab_openapi.json"),
        "--base-url", "http://127.0.0.1:8000", "--auth-config", str(EXAMPLES / "auth-profiles.example.yaml"),
        "--profile", "alice",
    ])
    assert result.exit_code == 1
    assert "2-10 distinct" in result.output
